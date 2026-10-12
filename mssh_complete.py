#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mssh_complete: autocomplete for multiSSH3 (mssh)
# Copyright (C) 2026 Yufei Pan <pan@zopyr.us>
# SPDX-License-Identifier: GPL-3.0-or-later
'''
Autocomplete for mssh (multiSSH3).

Shells send the command line to `mssh-complete query` (protocol MSSHC1 on stdin) and get
ranked candidates back. Answering reads a precomputed index that is decoded lazily; only
building the index (`mssh-complete rebuild`) imports multiSSH3.
'''
import math
import os
import sys
import time
from bisect import bisect_left

version = '0.1'
__version__ = version
PROTOCOL = 'MSSHC1'
MSSH_NAMES = ('mssh', 'mssh3', 'multissh', 'multissh3', 'multiSSH3')
SHELLS = ('bash', 'zsh', 'fish')

#%% ------------ Shell lexing ----------------
class Token(object):
	'''One shell word. text is the dequoted value, raw the text as typed.'''
	__slots__ = ('text', 'raw', 'quoted', 'open_quote')

	def __init__(self, text, raw, quoted=False, open_quote=''):
		self.text = text
		self.raw = raw
		self.quoted = quoted
		self.open_quote = open_quote

	def __repr__(self):
		return 'Token({!r}, raw={!r}, quoted={!r}, open_quote={!r})'.format(self.text, self.raw, self.quoted, self.open_quote)

_ANSI_C_SIMPLE = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b',
	'f': '\f', 'v': '\v', '\\': '\\', "'": "'", '"': '"', '?': '?'}

def _ansi_c_escape(line, index):
	'''Decode the escape after a backslash at line[index] inside $'...'. Returns (text, next index).'''
	char = line[index]
	if char in _ANSI_C_SIMPLE:
		return _ANSI_C_SIMPLE[char], index + 1
	if char == 'x':
		end = index + 1
		while end < len(line) and end < index + 3 and line[end] in '0123456789abcdefABCDEF':
			end += 1
		if end > index + 1:
			return chr(int(line[index + 1:end], 16)), end
		return '\\x', index + 1
	if char in '01234567':
		end = index
		while end < len(line) and end < index + 3 and line[end] in '01234567':
			end += 1
		return chr(int(line[index:end], 8)), end
	return '\\' + char, index + 1

def lex(line):
	'''
	Split a command line into words like a POSIX shell, tolerating an unterminated quote.

	Handles '...', "...", $'...' and backslash escapes. An unterminated quote takes the rest of
	the line, and the word records it in open_quote. Shell operators are not split off.

	Returns:
		list: Token objects
	'''
	tokens = []
	length = len(line)
	index = 0
	while True:
		while index < length and line[index] in ' \t\n':
			index += 1
		if index >= length:
			return tokens
		start = index
		parts = []
		quoted = False
		open_quote = ''
		while index < length and line[index] not in ' \t\n':
			char = line[index]
			if char == '\\':
				if index + 1 < length and line[index + 1] != '\n':
					parts.append(line[index + 1])
				index += 2
			elif char == "'":
				quoted = True
				end = line.find("'", index + 1)
				if end < 0:
					parts.append(line[index + 1:])
					open_quote = "'"
					index = length
				else:
					parts.append(line[index + 1:end])
					index = end + 1
			elif char == '"':
				quoted = True
				index += 1
				while index < length and line[index] != '"':
					if line[index] == '\\' and index + 1 < length and line[index + 1] in '"\\$`\n':
						if line[index + 1] != '\n':
							parts.append(line[index + 1])
						index += 2
					else:
						parts.append(line[index])
						index += 1
				if index >= length:
					open_quote = '"'
				else:
					index += 1
			elif char == '$' and index + 1 < length and line[index + 1] == "'":
				quoted = True
				index += 2
				while index < length and line[index] != "'":
					if line[index] == '\\' and index + 1 < length:
						text, index = _ansi_c_escape(line, index + 1)
						parts.append(text)
					else:
						parts.append(line[index])
						index += 1
				if index >= length:
					open_quote = "$'"
				else:
					index += 1
			else:
				parts.append(char)
				index += 1
		tokens.append(Token(''.join(parts), line[start:min(index, length)], quoted, open_quote))

# marks the cursor while lexing; a private use character that does not appear in command lines
CURSOR = '\ue000'

class Cursor(object):
	'''A command line split at the cursor: the words before it, the word it is in, the words after it.'''
	__slots__ = ('before', 'current', 'prefix', 'open_quote', 'after')

	def __init__(self, before, current, prefix, open_quote, after):
		self.before = before
		self.current = current
		self.prefix = prefix
		self.open_quote = open_quote
		self.after = after

def split_at_cursor(before, after):
	'''
	Lex a command line around the cursor.

	Returns:
		Cursor: prefix is the dequoted part of the current word before the cursor, open_quote the
			quote left open at the cursor ('' if none)
	'''
	tokens = lex(before + CURSOR + after)
	head = lex(before + CURSOR)
	open_quote = head[-1].open_quote if head and CURSOR in head[-1].text else ''
	for index, token in enumerate(tokens):
		if CURSOR in token.text:
			prefix = token.text.split(CURSOR, 1)[0]
			current = Token(token.text.replace(CURSOR, '', 1), token.raw.replace(CURSOR, '', 1), token.quoted, token.open_quote)
			return Cursor(tokens[:index], current, prefix, open_quote, tokens[index + 1:])
	# the cursor char was swallowed (e.g. by a trailing backslash): a new empty word
	return Cursor(tokens, Token('', ''), '', '', [])

#%% ------------ Option spec ----------------
PASSWORD_DESTS = frozenset(('password', 'ipmi_password'))
PATH_DESTS = frozenset(('file', 'file_sync', 'env_file', 'env_files', 'config_file', 'store_config_file', 'host_file', 'history_file'))
USER_DESTS = frozenset(('username', 'ipmi_username'))

def _one_line(text):
	'''text on one line, with NUL, tabs and newlines turned into single spaces.'''
	return ' '.join(str(text).replace('\0', ' ').split())

class OptionSpec(object):
	'''One mssh option: its dest, every string naming it and how many values it takes.'''
	__slots__ = ('dest', 'strings', 'nargs', 'repeat', 'group', 'default', 'help')

	def __init__(self, dest, strings, nargs='0', repeat=False, group='', default='', help=''):
		self.dest = dest
		self.strings = tuple(strings)
		self.nargs = nargs
		self.repeat = repeat
		self.group = group
		self.default = default
		self.help = help

	@property
	def long(self):
		'''The first --long string, or the longest string if there is none.'''
		for string in self.strings:
			if string.startswith('--'):
				return string
		return max(self.strings, key=len)

	def to_row(self):
		return [self.dest, self.nargs, '1' if self.repeat else '0', self.group, self.default, self.help] + list(self.strings)

	@classmethod
	def from_row(cls, row):
		return cls(row[0], row[6:], row[1], row[2] == '1', row[3], row[4], row[5])

class ParserSpec(object):
	'''The options of the mssh parser, looked up the way argparse matches them.'''
	def __init__(self, options):
		self.options = list(options)
		self.by_string = {}
		for option in self.options:
			for string in option.strings:
				self.by_string[string] = option
		self._long = sorted(string for string in self.by_string if string.startswith('--'))

	def lookup(self, text):
		'''
		The option a word names, and the value attached to it with "=".

		Unique abbreviations of --long options are accepted, like argparse does.

		Returns:
			tuple: (OptionSpec or None, attached value or None)
		'''
		option = self.by_string.get(text)
		if option is not None:
			return option, None
		name, sep, value = text.partition('=')
		if sep:
			option = self.by_string.get(name) or self._abbreviation(name)
			return (option, value) if option is not None else (None, None)
		return self._abbreviation(text), None

	def _abbreviation(self, name):
		if not name.startswith('--') or len(name) < 3:
			return None
		found = {}
		for string in self._long[bisect_left(self._long, name):]:
			if not string.startswith(name):
				break
			option = self.by_string[string]
			found[id(option)] = option
		return next(iter(found.values())) if len(found) == 1 else None

	def to_rows(self):
		return [option.to_row() for option in self.options]

	@classmethod
	def from_rows(cls, rows):
		return cls(OptionSpec.from_row(row) for row in rows)

def spec_from_parser(parser):
	'''Describe the options of an argparse parser (index builder side).'''
	import argparse
	groups = {}
	for number, group in enumerate(getattr(parser, '_mutually_exclusive_groups', ())):
		for action in group._group_actions:
			groups[id(action)] = str(number)
	options = []
	for action in parser._actions:
		if not action.option_strings:
			continue
		nargs = '1' if action.nargs is None else str(action.nargs)
		repeat = isinstance(action, (argparse._AppendAction, argparse._AppendConstAction, argparse._CountAction))
		default = action.default
		if isinstance(default, bool) or not isinstance(default, (int, float, str)):
			default = ''
		options.append(OptionSpec(action.dest, action.option_strings, nargs, repeat,
			groups.get(id(action), ''), _one_line(default), _one_line(action.help or '')))
	return ParserSpec(options)

#%% ------------ Context ----------------
ROLE_OPTION = 'option'
ROLE_VALUE = 'value'
ROLE_HOSTS = 'hosts'
ROLE_COMMAND = 'command'
ROLE_SEPARATOR = 'separator'

def _looks_like_option(text):
	return len(text) > 1 and text[0] == '-'

def assign_roles(words, spec, current=None):
	'''
	The role argparse gives each word of an mssh command line (program name excluded).

	words[current] is the word being completed: a dash starting it means an option name,
	except after unquoted command words, where it belongs to the remote command.

	Returns:
		list: (role, OptionSpec or None) per word
	'''
	roles = []
	pending = None
	have_hosts = False
	after_separator = False
	command_seen = False
	commands_quoted = True
	for index, token in enumerate(words):
		text = token.text
		is_current = index == current
		dashed = _looks_like_option(text) or (is_current and text.startswith('-'))
		if pending is not None:
			option = pending
			pending = None
			if not dashed:
				roles.append((ROLE_VALUE, option))
				continue
		if after_separator:
			roles.append((ROLE_COMMAND, None))
			continue
		if text == '--' and not is_current:
			roles.append((ROLE_SEPARATOR, None))
			after_separator = True
			continue
		if dashed:
			if is_current and command_seen and not commands_quoted:
				roles.append((ROLE_COMMAND, None))
				continue
			option, attached = spec.lookup(text)
			if option is None and not is_current:
				# argparse gives unknown options to the commands
				roles.append((ROLE_COMMAND, None))
				if have_hosts:
					command_seen = True
					commands_quoted = False
				continue
			roles.append((ROLE_OPTION, option))
			if option is not None and attached is None and option.nargs != '0':
				pending = option
			continue
		if not have_hosts:
			have_hosts = True
			roles.append((ROLE_HOSTS, None))
		else:
			command_seen = True
			commands_quoted = commands_quoted and token.quoted
			roles.append((ROLE_COMMAND, None))
	return roles

def split_hosts(text):
	'''Split a hosts argument into host words, on the separators mssh accepts.'''
	for separator in ',\n\r\t;|/&':
		text = text.replace(separator, ' ')
	return text.split()

def command_features(command):
	'''Features of one remote command: the command, its program and program plus first argument.'''
	command = command.strip()
	if not command:
		return []
	words = [token.text for token in lex(command)]
	features = ['c:' + command]
	if words:
		features.append('p:' + words[0])
		if len(words) > 1 and words[1] not in ('|', '||', '&&', ';'):
			features.append('s:' + words[0] + ' ' + words[1])
	return features

def _mode(dests):
	dests = set(dests)
	if 'ipmi' in dests:
		return 'ipmi'
	if 'gather_mode' in dests:
		return 'gather'
	if 'file_sync' in dests:
		return 'sync'
	if 'file' in dests:
		return 'push'
	return 'plain'

PATH_MODES = ('push', 'sync', 'gather')

def make_features(options, hosts, commands):
	'''
	The features of an invocation, used to find similar ones in history.

	Args:
		options (list): (OptionSpec, value or None) pairs; password values are never included
		hosts (str): The hosts argument as typed
		commands (list): Command strings

	Returns:
		list: Sorted feature strings, "<kind>:<text>"
	'''
	features = set()
	mode = _mode(option.dest for option, _ in options)
	for option, value in options:
		if option.dest in PASSWORD_DESTS:
			continue
		features.add('o:' + option.long)
		if value:
			features.add('v:{}={}'.format(option.dest, value))
	if hosts:
		features.add('h:' + hosts)
		for word in split_hosts(hosts):
			user, _, host = word.rpartition('@')
			if host:
				features.add('t:' + host)
			if user:
				features.add('v:username=' + user)
	for command in commands:
		if mode in PATH_MODES:
			# with -f / -fs / -G the commands are paths
			if command.strip():
				features.add('f:' + command.strip())
		else:
			features.update(command_features(command))
	features.add('m:' + mode)
	return sorted(feature for feature in features if '\0' not in feature and '\n' not in feature)

def _join_commands(commands):
	'''Commands from command words: quoted words are commands, runs of unquoted words are one command.'''
	joined = []
	run = []
	for text, quoted in commands:
		if quoted:
			if run:
				joined.append(' '.join(run))
				run = []
			joined.append(text)
		else:
			run.append(text)
	if run:
		joined.append(' '.join(run))
	return joined

def _collect(words, roles, skip=()):
	'''The options (with values), hosts and command words of a line, leaving out the words in skip.'''
	options = []
	hosts = ''
	commands = []
	for index, (token, (role, option)) in enumerate(zip(words, roles)):
		if index in skip:
			continue
		if role == ROLE_OPTION and option is not None:
			attached = None
			if '=' in token.text and token.text not in option.strings:
				attached = token.text.partition('=')[2]
			options.append([option, attached])
		elif role == ROLE_VALUE:
			if options and options[-1][0] is option and options[-1][1] is None:
				options[-1][1] = token.text
			else:
				options.append([option, token.text])
		elif role == ROLE_HOSTS:
			hosts = token.text
		elif role == ROLE_COMMAND:
			commands.append((token.text, token.quoted))
	return [(option, value) for option, value in options], hosts, commands

def line_features(words, spec):
	'''Features of a complete mssh command line (program name excluded).'''
	options, hosts, commands = _collect(words, assign_roles(words, spec))
	return make_features(options, hosts, _join_commands(commands))

SLOT_OPTION = 'option'
SLOT_VALUE = 'value'
SLOT_HOSTS = 'hosts'
SLOT_COMMAND = 'command'

class Context(object):
	'''
	What the cursor is completing.

	slot: SLOT_OPTION, SLOT_VALUE, SLOT_HOSTS or SLOT_COMMAND
	option: the OptionSpec whose value is completed (SLOT_VALUE)
	prefix: the dequoted current word up to the cursor; value_start: where the slot's value
		starts in it (after "-x=")
	open_quote / quoted: the quote open at the cursor / whether the current word has quoting
	hosts: the hosts argument (another word); options: (OptionSpec, value) of the other words
	command_words / command_word_index / command_prefix: the remote command words up to the
		cursor, the index of the current one, and the text in front of them inside a quoted word
	mode: plain, push, sync, gather or ipmi; features: features of every other slot
	'''
	__slots__ = ('slot', 'option', 'prefix', 'value_start', 'open_quote', 'quoted', 'hosts', 'options',
		'command_words', 'command_word_index', 'command_prefix', 'mode', 'features')

	def __init__(self, **values):
		for name in self.__slots__:
			setattr(self, name, values.get(name))

	@property
	def value(self):
		return self.prefix[self.value_start:]

_PIPELINE_MARKS = ('||', '&&', '|', ';', '$(', '`', '(')

def _segment_start(text):
	'''Where the last pipeline segment of a command string starts.'''
	start = 0
	for mark in _PIPELINE_MARKS:
		at = text.rfind(mark)
		if at >= 0 and at + len(mark) > start:
			start = at + len(mark)
	return start

def parse_context(before, after, spec):
	'''
	What the cursor completes in an mssh command line, with the rest of the line as features.

	Args:
		before (str): The line up to the cursor, starting with the program name
		after (str): The line after the cursor
		spec (ParserSpec): The mssh options

	Returns:
		Context, or None when the cursor is on the program name
	'''
	cursor = split_at_cursor(before, after)
	if not cursor.before:
		return None
	words = cursor.before[1:] + [cursor.current] + cursor.after
	current = len(cursor.before) - 1
	roles = assign_roles(words, spec, current)
	role, option = roles[current]
	prefix = cursor.prefix
	value_start = 0
	if role == ROLE_OPTION:
		name, sep, _ = prefix.partition('=')
		found = spec.lookup(name)[0] if sep else None
		if found is not None and found.nargs != '0':
			slot, option, value_start = SLOT_VALUE, found, len(name) + 1
		else:
			slot, option = SLOT_OPTION, None
	elif role == ROLE_VALUE:
		slot = SLOT_VALUE
	elif role == ROLE_HOSTS:
		slot = SLOT_HOSTS
	else:
		slot = SLOT_COMMAND
	skip = {current}
	command_words = command_word_index = command_prefix = None
	if slot == SLOT_COMMAND:
		if cursor.current.quoted:
			start = _segment_start(prefix)
			segment = split_at_cursor(prefix[start:], '')
			command_words = [token.text for token in segment.before] + [segment.prefix]
			command_word_index = len(segment.before)
			if prefix.endswith(segment.prefix):
				command_prefix = prefix[:len(prefix) - len(segment.prefix)]
			else:
				command_words = None
		else:
			# the unquoted command words the current word continues
			first = current
			while first > 0 and roles[first - 1][0] == ROLE_COMMAND and not words[first - 1].quoted:
				first -= 1
			last = current
			while last + 1 < len(words) and roles[last + 1][0] == ROLE_COMMAND and not words[last + 1].quoted:
				last += 1
			skip = set(range(first, last + 1))
			command_words = [token.text for token in words[first:current]] + [prefix]
			command_word_index = current - first
			command_prefix = ''
	options, hosts, commands = _collect(words, roles, skip)
	return Context(slot=slot, option=option, prefix=prefix, value_start=value_start,
		open_quote=cursor.open_quote, quoted=cursor.current.quoted, hosts=hosts, options=options,
		command_words=command_words, command_word_index=command_word_index, command_prefix=command_prefix,
		mode=_mode(option.dest for option, _ in options),
		features=make_features(options, hosts, _join_commands(commands)))

#%% ------------ History ----------------
class HistoryEntry(object):
	'''One ~/.mssh_history line: when it ran, its options, its hosts as recorded and its commands.'''
	__slots__ = ('ts', 'options', 'option_texts', 'hosts', 'commands')

	def __init__(self, ts, options, hosts, commands, option_texts=None):
		self.ts = ts
		self.options = options
		self.option_texts = option_texts if option_texts is not None else [option.strings[0] for option, _ in options]
		self.hosts = hosts
		self.commands = commands

	def features(self):
		return make_features(self.options, self.hosts, [command for command in self.commands if command.strip()])

def parse_history_line(line, spec):
	'''
	Parse a ~/.mssh_history line: <ts>\\t<program>\\t<options>\\t<hosts>\\t<commands>.

	Returns:
		HistoryEntry, or None for a line in another format
	'''
	fields = line.rstrip('\r\n').split('\t')
	if len(fields) != 5:
		return None
	try:
		ts = int(fields[0])
	except ValueError:
		return None
	options = []
	texts = []
	tokens = lex(fields[2])
	index = 0
	while index < len(tokens):
		text = tokens[index].text
		option, attached = spec.lookup(text)
		index += 1
		if option is None:
			continue
		if attached is None and option.nargs in ('1', '+') and index < len(tokens):
			attached = tokens[index].text
			index += 1
		options.append((option, attached))
		texts.append(text.partition('=')[0] if attached is not None and '=' in text else text)
	host_tokens = lex(fields[3])
	hosts = host_tokens[0].text if host_tokens else ''
	if hosts == 'EMPTY_HOSTS':
		hosts = ''
	return HistoryEntry(ts, options, hosts, [token.text for token in lex(fields[4])], texts)

#%% ------------ Index storage (NSV) ----------------
INDEX_MAGIC = 'MSSHCIDX'
INDEX_FORMAT = '1'
INDEX_NAME = 'complete-index.v1.nsv'

class IndexCorrupt(Exception):
	'''The index file is not a complete index this version can read.'''

def safe_field(text):
	'''Whether text can be stored in an NSV field (no NUL, no newline).'''
	return '\0' not in text and '\n' not in text

def write_nsv(path, header, sections):
	'''
	Write an index file atomically (a temporary file in the same directory, then os.replace).

	Row 0 holds the magic, the format, "key=value" header fields and "@section=start,count"
	entries; every other row is a section row with its fields joined by NUL.

	Args:
		path (str): Where to write, mode 0600
		header (dict): str -> str
		sections (list): (name, rows) pairs, rows a list of lists of str

	Raises:
		ValueError: a field holds NUL or a newline
	'''
	import tempfile
	body = []
	table = []
	row_number = 1
	for name, rows in sections:
		table.append('@{}={},{}'.format(name, row_number, len(rows)))
		row_number += len(rows)
		for row in rows:
			for field in row:
				if not safe_field(field):
					raise ValueError('field {!r} of section {} holds NUL or a newline'.format(field[:40], name))
			body.append('\0'.join(row))
	head = [INDEX_MAGIC, INDEX_FORMAT] + ['{}={}'.format(key, value) for key, value in sorted(header.items())] + table
	for field in head:
		if not safe_field(field):
			raise ValueError('header field {!r} holds NUL or a newline'.format(field[:40]))
	data = '\0'.join(head) + '\n' + ''.join(row + '\n' for row in body)
	fd, temporary = tempfile.mkstemp(prefix='.complete-index.', dir=os.path.dirname(path) or '.')
	try:
		with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
			f.write(data)
			f.flush()
			os.fsync(f.fileno())
		os.replace(temporary, path)
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

class NsvIndex(object):
	'''An index file split into rows; a row is only split into fields when it is read.'''
	def __init__(self, data):
		self.rows = data.split('\n')
		head = self.rows[0].split('\0')
		if len(head) < 2 or head[0] != INDEX_MAGIC:
			raise IndexCorrupt('not an mssh completion index')
		if head[1] != INDEX_FORMAT:
			raise IndexCorrupt('index format {!r}, this version reads {!r}'.format(head[1], INDEX_FORMAT))
		self.header = {}
		self.sections = {}
		total = 1
		for field in head[2:]:
			key, sep, value = field.partition('=')
			if not sep:
				raise IndexCorrupt('bad header field {!r}'.format(field[:40]))
			if key.startswith('@'):
				start, _, count = value.partition(',')
				try:
					start, count = int(start), int(count)
				except ValueError:
					raise IndexCorrupt('bad section entry {!r}'.format(field[:40])) from None
				self.sections[key[1:]] = (start, count)
				total += count
			else:
				self.header[key] = value
		# a complete file ends with a newline, leaving one empty string after the last row
		if len(self.rows) != total + 1 or self.rows[-1] != '':
			raise IndexCorrupt('truncated index')
		for start, count in self.sections.values():
			if start < 1 or start + count > total:
				raise IndexCorrupt('section outside the index')
		self._single = {}

	@classmethod
	def load(cls, path):
		with open(path, 'r', encoding='utf-8', errors='surrogateescape', newline='') as f:
			return cls(f.read())

	def count(self, name):
		return self.sections.get(name, (0, 0))[1]

	def row(self, name, index):
		start, count = self.sections[name]
		if not 0 <= index < count:
			raise IndexError('row {} of section {} ({} rows)'.format(index, name, count))
		line = self.rows[start + index]
		return line.split('\0') if line else []

	def single(self, name):
		'''A section stored as one row, split once and kept.'''
		cached = self._single.get(name)
		if cached is None:
			cached = self.row(name, 0) if self.count(name) else []
			self._single[name] = cached
		return cached

#%% ------------ Knowledge ----------------
HALF_LIFE = 7 * 24 * 3600.0
USE_FLOOR = 0.1   # what any use keeps counting however old: frequency outlives recency

def decay(age):
	'''Factor for weights age seconds old: halves every HALF_LIFE.'''
	if age <= 0:
		return 1.0
	return 0.5 ** (age / HALF_LIFE)

def use_weight(age):
	'''Weight of one use age seconds ago: USE_FLOOR plus a recency part that halves every HALF_LIFE.'''
	return USE_FLOOR + decay(age)

def _prefix_range(sorted_items, prefix):
	'''(lo, hi): sorted_items[lo:hi] are the items starting with prefix.'''
	lo = bisect_left(sorted_items, prefix)
	hi = lo
	while hi < len(sorted_items) and sorted_items[hi].startswith(prefix):
		hi += 1
	return lo, hi

class MemoryKnowledge(object):
	'''
	Records held in memory: identical invocations share one record whose weight sums their uses.

	Used for the history tail not yet in the index, the shell's history, the replay evaluation,
	and by the builder to aggregate records before writing them.
	'''
	def __init__(self):
		self.records = []
		self._by_features = {}
		self._postings = {}
		self._weights = {}
		self._sorted = None

	def add(self, features, weight):
		key = tuple(features)
		rid = self._by_features.get(key)
		if rid is None:
			rid = len(self.records)
			self._by_features[key] = rid
			self.records.append([0.0, list(features)])
			for feature in features:
				self._postings.setdefault(feature, []).append(rid)
			self._sorted = None
		self.records[rid][0] += weight
		for feature in features:
			self._weights[feature] = self._weights.get(feature, 0.0) + weight

	def add_history(self, lines, spec, now):
		'''Add ~/.mssh_history lines, each weighted by its age.'''
		for line in lines:
			entry = parse_history_line(line, spec)
			if entry is not None:
				self.add(entry.features(), use_weight(now - entry.ts))

	def record_count(self):
		return len(self.records)

	def feature_range(self, prefix):
		if self._sorted is None:
			self._sorted = sorted(self._postings)
		lo, hi = _prefix_range(self._sorted, prefix)
		return [(text, text) for text in self._sorted[lo:hi]]

	def feature_key(self, text):
		return text if text in self._postings else None

	def postings(self, key):
		return self._postings[key]

	def record(self, rid):
		weight, features = self.records[rid]
		return weight, features

	def feature_weight(self, key):
		return self._weights.get(key, 0.0)

class SnapshotKnowledge(object):
	'''The records stored in the index, read lazily, with weights decayed to now.'''
	def __init__(self, index, now):
		self.index = index
		self.features = index.single('features')
		built = float(index.header.get('built', now) or now)
		self.scale = decay(now - built)
		self._weights = None

	def record_count(self):
		return self.index.count('records')

	def feature_range(self, prefix):
		lo, hi = _prefix_range(self.features, prefix)
		return [(key, self.features[key]) for key in range(lo, hi)]

	def feature_key(self, text):
		key = bisect_left(self.features, text)
		return key if key < len(self.features) and self.features[key] == text else None

	def postings(self, key):
		return [int(rid) for rid in self.index.row('postings', key)]

	def record(self, rid):
		row = self.index.row('records', rid)
		return float(row[0]) * self.scale, [self.features[int(key)] for key in row[1:]]

	def feature_weight(self, key):
		if self._weights is None:
			self._weights = self.index.single('fweights')
		return float(self._weights[key]) * self.scale

#%% ------------ Ranking ----------------
BETA = 0.1                  # weight of plain frecency next to similarity with the line
KIND_WEIGHTS = {}           # feature kind ('h', 't', 'v', 'c', ...) -> weight, 1.0 when absent
COMMON_SHARE = 0.5          # a feature in more than this share of the records carries no context
MAX_CONTEXT_RECORDS = 20000 # records read per query for context

def score_features(knowledges, prefix, line_features, deadline=None):
	'''
	Score every feature starting with prefix (e.g. "c:sys") in the given knowledge.

	score(c) = BETA * frecency(c) + sum over records r holding c of log(1 + weight(r)) * sim(r, line),
	where sim sums idf(f) * KIND_WEIGHTS[kind of f] over the features f shared by r and the line.
	Features in more than COMMON_SHARE of the records are left out of sim; frequency counts
	logarithmically there, so matching the line beats being used often.

	Returns:
		dict: feature text -> score
	'''
	scores = {}
	for knowledge in knowledges:
		for key, text in knowledge.feature_range(prefix):
			scores[text] = scores.get(text, 0.0) + BETA * knowledge.feature_weight(key)
	if not scores or not line_features:
		return scores
	total = sum(knowledge.record_count() for knowledge in knowledges)
	similarity = [dict() for _ in knowledges]
	for feature in line_features:
		lists = []
		for knowledge in knowledges:
			key = knowledge.feature_key(feature)
			lists.append(knowledge.postings(key) if key is not None else [])
		df = sum(len(rids) for rids in lists)
		if not df or df > COMMON_SHARE * total:
			continue
		weight = math.log(1.0 + float(total) / df) * KIND_WEIGHTS.get(feature[0], 1.0)
		for sim, rids in zip(similarity, lists):
			for rid in rids:
				sim[rid] = sim.get(rid, 0.0) + weight
	touched = 0
	for knowledge, sim in zip(knowledges, similarity):
		for rid, value in sim.items():
			touched += 1
			if touched > MAX_CONTEXT_RECORDS or (deadline is not None and touched % 256 == 0 and time.monotonic() > deadline):
				return scores
			weight, features = knowledge.record(rid)
			for text in features:
				if text.startswith(prefix):
					scores[text] = scores.get(text, 0.0) + math.log1p(weight) * value
	return scores

#%% ------------ Hosts ----------------
SRC_HOSTS_FILE, SRC_SSH_CONFIG, SRC_KNOWN_HOSTS, SRC_ARP, SRC_HISTORY, SRC_ALIAS = 1, 2, 4, 8, 16, 32

class HostTable(object):
	'''Hosts, aliases and host groups from the index; empty without one.'''
	def __init__(self, index=None):
		self.index = index
		self.names = index.single('host_names') if index is not None else []
		self.alias_names = index.single('alias_names') if index is not None else []
		self.unavailable = frozenset(index.single('unavailable')) if index is not None else frozenset()
		self._groups = None

	def names_with_prefix(self, prefix):
		lo, hi = _prefix_range(self.names, prefix)
		return self.names[lo:hi]

	def aliases_with_prefix(self, prefix):
		lo, hi = _prefix_range(self.alias_names, prefix)
		return [(index, self.alias_names[index]) for index in range(lo, hi)]

	def alias_index(self, name):
		index = bisect_left(self.alias_names, name)
		return index if index < len(self.alias_names) and self.alias_names[index] == name else None

	def alias_members(self, index):
		'''Member host names of the alias at index.'''
		return [self.names[int(member)] for member in self.index.row('aliases', index)[1:]]

	def alias_size(self, index):
		return len(self.index.row('aliases', index)) - 1

	def groups(self):
		'''(range text, member names) of the host groups found when the index was built.'''
		if self._groups is None:
			self._groups = []
			if self.index is not None:
				for number in range(self.index.count('groups')):
					row = self.index.row('groups', number)
					self._groups.append((row[0], [self.names[int(member)] for member in row[1:]]))
		return self._groups

_DIGITS = '0123456789'

def _is_digits(text):
	return bool(text) and all(char in _DIGITS for char in text)

def compact_names(names):
	'''
	Compact host names into range strings: node001..node512 -> node[001-512].

	Names that differ only in their last run of digits (with the same number of digits) are
	grouped, and each run of consecutive numbers becomes one range. Digits all members of a run
	share stay in front of the range, so the range text starts with every prefix they share.

	Returns:
		list: Range strings and names that did not group, sorted
	'''
	buckets = {}
	singles = []
	for name in names:
		end = len(name)
		while end > 0 and name[end - 1] not in _DIGITS:
			end -= 1
		start = end
		while start > 0 and name[start - 1] in _DIGITS:
			start -= 1
		if start == end:
			singles.append(name)
			continue
		key = (name[:start], end - start, name[end:])
		buckets.setdefault(key, []).append(int(name[start:end]))
	out = list(singles)
	for (stem, width, tail), numbers in buckets.items():
		numbers.sort()
		low = previous = numbers[0]
		for number in numbers[1:] + [None]:
			if number is not None and number == previous + 1:
				previous = number
				continue
			out.append(_range_text(stem, width, tail, low, previous))
			if number is not None:
				low = previous = number
	return sorted(out)

def _range_text(stem, width, tail, low, high):
	low_text = '{:0{}d}'.format(low, width)
	high_text = '{:0{}d}'.format(high, width)
	if low == high:
		return stem + low_text + tail
	common = 0
	while common < width - 1 and low_text[common] == high_text[common]:
		common += 1
	return '{}{}[{}-{}]{}'.format(stem, low_text[:common], low_text[common:], high_text[common:], tail)

def expand_ranges(text, limit=100000):
	'''
	Expand [a-b] and [a,b] number ranges in a host name, the common part of mssh's range syntax.

	Text with letter or hex ranges, or that would expand to more than limit names, is returned
	as it is (in a one-item list).
	'''
	start = text.find('[')
	end = text.find(']', start + 1)
	if start < 0 or end < 0:
		return [text]
	head, body, tail = text[:start], text[start + 1:end], text[end + 1:]
	values = []
	for part in body.split(','):
		low, sep, high = part.strip().partition('-')
		if sep and _is_digits(low) and _is_digits(high):
			width = min(len(low), len(high))
			values.extend('{:0{}d}'.format(number, width) for number in range(int(low), int(high) + 1))
		elif not sep and part.strip():
			values.append(part.strip())
		else:
			return [text]
		if len(values) > limit:
			return [text]
	out = []
	for value in values:
		out.extend(expand_ranges(head + value + tail, limit))
		if len(out) > limit:
			return [text]
	return out

#%% ------------ Cache directory ----------------
def _private_dir(path, create=True):
	'''
	Whether path is a directory only we control, creating it (mode 0700) if create.

	Same rules as multiSSH3._private_dir: not a symlink, owned by us, not accessible to others.
	'''
	import stat
	if create:
		try:
			os.mkdir(path, 0o700)
		except FileExistsError:
			pass
		except OSError:
			return False
	try:
		st = os.lstat(path)
	except OSError:
		return False
	if not stat.S_ISDIR(st.st_mode):
		return False
	if not hasattr(os, 'getuid'):
		return True
	if st.st_uid != os.getuid() or st.st_mode & 0o022:
		return False
	if st.st_mode & 0o077:
		if not create:
			return False
		try:
			os.chmod(path, 0o700)
			st = os.lstat(path)
		except OSError:
			return False
	return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077

def _owned_and_not_writable_by_others(path):
	if not hasattr(os, 'getuid'):
		return True
	try:
		st = os.stat(path)
	except OSError:
		return False
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

def cache_dir(create=True):
	'''
	mssh's private cache directory, where unavailable_hosts.csv lives, or None.

	$XDG_RUNTIME_DIR/multiSSH3 when the runtime dir is ours, else <tempdir>/multiSSH3-<uid>,
	exactly as multiSSH3._unavailable_hosts_file_path picks it.
	'''
	import tempfile
	if hasattr(os, 'getuid'):
		user_id = os.getuid()
	else:
		import getpass
		user_id = getpass.getuser()
	candidates = []
	runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
	if runtime_dir and _owned_and_not_writable_by_others(runtime_dir):
		candidates.append(os.path.join(runtime_dir, 'multiSSH3'))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
		if _private_dir(directory, create):
			return directory
	return None

def _debug(message):
	'''Append a line to <cache dir>/complete.log when MSSH_COMPLETE_DEBUG=1 (kept under 256 KB).'''
	if os.environ.get('MSSH_COMPLETE_DEBUG') != '1':
		return
	directory = cache_dir()
	if directory is None:
		return
	path = os.path.join(directory, 'complete.log')
	try:
		if os.path.getsize(path) > 256 * 1024:
			with open(path, 'rb') as f:
				f.seek(-128 * 1024, os.SEEK_END)
				kept = f.read()
			with open(path, 'wb') as f:
				f.write(kept)
	except OSError:
		pass
	try:
		with os.fdopen(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), 'a') as f:
			f.write('{:.3f} {} {}\n'.format(time.time(), os.getpid(), message))
	except OSError:
		pass

#%% ------------ Index sources ----------------
def read_hosts_file(path):
	'''name -> address from a hosts file.'''
	hosts = {}
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			for line in f:
				fields = line.split('#', 1)[0].split()
				for name in fields[1:]:
					hosts.setdefault(name, fields[0])
	except OSError:
		pass
	return hosts

def read_ssh_config(path, base_dir, names, users, read):
	'''
	Add the Host names (no patterns) and User values of an ssh config file and the files it Includes.

	Args:
		path (str): The config file
		base_dir (str): Where relative Include paths start (~/.ssh or /etc/ssh)
		names (set), users (set): Filled in
		read (list): Paths read so far, appended to (also stops Include loops)
	'''
	import glob
	path = os.path.expanduser(path)
	if path in read or len(read) > 64:
		return
	try:
		f = open(path, encoding='utf-8', errors='replace')
	except OSError:
		return
	read.append(path)
	with f:
		for line in f:
			line = line.strip()
			if not line or line.startswith('#'):
				continue
			key, _, value = line.replace('=', ' ', 1).partition(' ')
			key = key.lower()
			value = value.strip()
			if key == 'host':
				for pattern in value.split():
					pattern = pattern.strip('"')
					if pattern and not any(char in pattern for char in '*?!'):
						names.add(pattern)
			elif key == 'user' and value:
				users.add(value.strip('"'))
			elif key == 'include':
				for pattern in value.split():
					pattern = os.path.expanduser(pattern.strip('"'))
					if not os.path.isabs(pattern):
						pattern = os.path.join(base_dir, pattern)
					for included in sorted(glob.glob(pattern)):
						read_ssh_config(included, base_dir, names, users, read)

def read_known_hosts(path):
	'''Host names in a known_hosts file; hashed entries and patterns are skipped.'''
	names = set()
	try:
		with open(os.path.expanduser(path), encoding='utf-8', errors='replace') as f:
			for line in f:
				fields = line.split()
				if fields and fields[0].startswith('@'):
					fields = fields[1:]
				if not fields or fields[0].startswith('#'):
					continue
				for entry in fields[0].split(','):
					if entry.startswith('|'):
						continue
					if entry.startswith('['):
						entry = entry[1:].split(']', 1)[0]
					if entry and not any(char in entry for char in '*?!'):
						names.add(entry)
	except OSError:
		pass
	return names

def read_arp():
	'''IPv4 addresses in the neighbour (ARP) table.'''
	addresses = set()
	try:
		with open('/proc/net/arp') as f:
			next(f, None)
			for line in f:
				fields = line.split()
				# IP address, HW type, Flags, HW address, ...: flags 0x0 is an incomplete entry
				if len(fields) >= 4 and fields[2] != '0x0':
					addresses.add(fields[0])
		return addresses
	except OSError:
		pass
	if sys.platform == 'darwin':
		import subprocess
		try:
			output = subprocess.run(['arp', '-an'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2).stdout
		except (OSError, subprocess.SubprocessError):
			return addresses
		for line in output.decode('utf-8', 'replace').splitlines():
			if '(' in line and ')' in line and 'incomplete' not in line:
				addresses.add(line.split('(', 1)[1].split(')', 1)[0])
	return addresses

def read_history(path, start=0):
	'''
	The complete lines of a history file from byte offset start.

	Returns:
		tuple: (lines, offset after the last complete line, inode or None)
	'''
	try:
		with open(path, 'rb') as f:
			inode = os.fstat(f.fileno()).st_ino
			f.seek(start)
			data = f.read()
	except OSError:
		return [], start, None
	cut = data.rfind(b'\n') + 1
	text = data[:cut].decode('utf-8', 'surrogateescape')
	return [line for line in text.split('\n') if line], start + cut, inode

def _is_ip(text):
	import ipaddress
	try:
		ipaddress.ip_address(text)
		return True
	except ValueError:
		return False

_ALIAS_VALUE_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-,[]@*?:$')

def collect_aliases(mssh, history_tokens, known):
	'''
	Host aliases: env file variables that look like host lists, and environment variables used as hosts.

	An env file variable counts when it was used as a host, when its value holds a "," or a
	range, or when everything it expands to is an IP address or a known host. Values with other
	characters (paths, prompts, ...) never count.

	Returns:
		dict: name -> (source, member host names)
	'''
	aliases = {}
	try:
		variables = mssh.readEnvFromFile()
	except Exception:
		variables = {}
	for name, value in variables.items():
		if not name.isidentifier() or not value or not set(value) <= _ALIAS_VALUE_CHARS:
			continue
		members = [member.split('@', 1)[-1] for member in mssh.expand_hostnames_local([name])[0]]
		if not members or members == [name]:
			continue
		if name in history_tokens or ',' in value or '[' in value or all(_is_ip(member) or member in known for member in members):
			aliases[name] = ('env_file', members)
	for name in history_tokens:
		if name in aliases or not name.isidentifier() or name not in os.environ:
			continue
		members = [member.split('@', 1)[-1] for member in mssh.expand_hostnames_local([name])[0]]
		if members and members != [name]:
			aliases[name] = ('env', members)
	return aliases

def file_signature(path):
	'''[path, inode, size, mtime_ns] of a file, or [path] if it cannot be read.'''
	try:
		st = os.stat(path)
	except OSError:
		return [path]
	return [path, str(st.st_ino), str(st.st_size), str(st.st_mtime_ns)]

def _import_mssh():
	'''Import multiSSH3, also when both files were copied somewhere by hand.'''
	here = os.path.dirname(os.path.abspath(__file__))
	if here not in sys.path:
		sys.path.insert(0, here)
	import multiSSH3
	return multiSSH3

#%% ------------ Building the index ----------------
MAX_RECORDS = 50000

def serialize_knowledge(memory):
	'''
	The features, records, postings and feature weight rows of the heaviest MAX_RECORDS records.

	Returns:
		tuple: (features, record rows, posting rows, fweights row)
	'''
	records = sorted(memory.records, key=lambda record: -record[0])[:MAX_RECORDS]
	features = sorted({feature for _, record_features in records for feature in record_features if safe_field(feature)})
	feature_id = {feature: number for number, feature in enumerate(features)}
	record_rows = []
	postings = [[] for _ in features]
	weights = [0.0] * len(features)
	for rid, (weight, record_features) in enumerate(records):
		ids = sorted(feature_id[feature] for feature in record_features if feature in feature_id)
		record_rows.append(['%.6g' % weight] + [str(number) for number in ids])
		for number in ids:
			postings[number].append(str(rid))
			weights[number] += weight
	return features, record_rows, postings, ['%.6g' % weight for weight in weights]

def build_index(directory, now=None, mssh=None):
	'''
	Read every source and write the index into directory.

	Returns:
		str: The index path
	'''
	now = time.time() if now is None else now
	mssh = mssh or _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	history_path = os.path.expanduser(mssh.DEFAULT_HISTORY_FILE)
	lines, offset, inode = read_history(history_path)
	memory = MemoryKnowledge()
	memory.add_history(lines, spec, now)
	features, record_rows, postings, fweights = serialize_knowledge(memory)
	history_tokens = {feature[2:] for feature in features if feature.startswith('t:')}
	hosts = {}
	def add(name, source, address=''):
		if not name or not safe_field(name) or any(char in name for char in ' \t,'):
			return
		entry = hosts.setdefault(name, [0, ''])
		entry[0] |= source
		if address and not entry[1]:
			entry[1] = address
	for name, address in read_hosts_file(mssh.DEFAULT_HOST_FILE).items():
		add(name, SRC_HOSTS_FILE, address)
	ssh_names, users, ssh_paths = set(), set(), []
	read_ssh_config('~/.ssh/config', os.path.expanduser('~/.ssh'), ssh_names, users, ssh_paths)
	read_ssh_config('/etc/ssh/ssh_config', '/etc/ssh', ssh_names, users, ssh_paths)
	for name in ssh_names:
		add(name, SRC_SSH_CONFIG)
	for name in read_known_hosts('~/.ssh/known_hosts'):
		add(name, SRC_KNOWN_HOSTS)
	for address in read_arp():
		add(address, SRC_ARP, address)
	aliases = collect_aliases(mssh, history_tokens, set(hosts) | history_tokens)
	for name in history_tokens:
		if name not in aliases and '[' not in name:
			add(name, SRC_HISTORY)
	for _, members in aliases.values():
		for member in members:
			add(member, SRC_ALIAS)
	names = sorted(hosts)
	host_number = {name: number for number, name in enumerate(names)}
	alias_names = sorted(aliases)
	alias_rows = [[aliases[name][0]] + [str(host_number[member]) for member in aliases[name][1] if member in host_number] for name in alias_names]
	group_rows = []
	for text in mssh.compact_hostnames_local(names):
		if '[' in text and safe_field(text):
			members = [host_number[member] for member in getattr(mssh, '__expand_hostname')(text, validate=False) if member in host_number]
			if len(members) > 1:
				group_rows.append([text] + [str(number) for number in sorted(members)])
	unavailable = []
	unavailable_path = mssh._unavailable_hosts_file_path(create=False)
	if unavailable_path:
		unavailable = sorted(name for name in mssh._read_unavailable_hosts_file(unavailable_path) if safe_field(name))
	env_files = [os.path.expanduser(os.path.expandvars(path)) for path in (mssh._env_files or mssh.DEFAULT_ENV_FILES)]
	sources = [history_path, mssh.DEFAULT_HOST_FILE, os.path.expanduser('~/.ssh/config'), '/etc/ssh/ssh_config',
		os.path.expanduser('~/.ssh/known_hosts')] + ssh_paths + env_files + [os.path.expanduser(path) for path in mssh.CONFIG_FILE_CHAIN]
	if unavailable_path:
		sources.append(unavailable_path)
	sources += [os.path.abspath(mssh.__file__), os.path.abspath(__file__)]
	seen = set()
	source_rows = []
	for path in sources:
		if path not in seen and safe_field(path):
			seen.add(path)
			source_rows.append(file_signature(path))
	header = {
		'built': repr(now),
		'arp_at': repr(now),
		'engine': version,
		'mssh_version': str(getattr(mssh, 'version', '')),
		'history': history_path,
		'history_offset': str(offset),
		'history_ino': str(inode or ''),
	}
	sections = [
		('spec', spec.to_rows()),
		('config', [['users'] + sorted(user for user in users if safe_field(user))]),
		('sources', source_rows),
		('features', [features]),
		('fweights', [fweights]),
		('postings', postings),
		('records', record_rows),
		('host_names', [names]),
		('host_meta', [[str(hosts[name][0]), hosts[name][1]] for name in names]),
		('alias_names', [alias_names]),
		('aliases', alias_rows),
		('groups', group_rows),
		('unavailable', [unavailable]),
	]
	path = os.path.join(directory, INDEX_NAME)
	write_nsv(path, header, sections)
	return path

#%% ------------ Freshness ----------------
TAIL_LIMIT_BYTES = 64 * 1024
TAIL_LIMIT_ENTRIES = 500
ARP_TTL = 300.0
LOCK_NAME = 'complete-index.lock'
LOCK_STALE = 60.0
FIRST_BUILD_BUDGET = 2.0

def check_freshness(index, now):
	'''
	Whether the index still matches its sources.

	Returns:
		tuple: ('fresh' | 'tail' | 'rebuild', history lines appended since the index was built).
			With 'tail' the appended lines are few enough to merge in memory.
	'''
	history = index.header.get('history', '')
	for number in range(index.count('sources')):
		row = index.row('sources', number)
		if row and row[0] != history and file_signature(row[0]) != row:
			return 'rebuild', []
	try:
		if now - float(index.header.get('arp_at', '0')) > ARP_TTL:
			return 'rebuild', []
	except ValueError:
		return 'rebuild', []
	try:
		offset = int(index.header.get('history_offset', '0'))
	except ValueError:
		return 'rebuild', []
	try:
		st = os.stat(history)
	except OSError:
		return ('rebuild', []) if offset else ('fresh', [])
	if str(st.st_ino) != index.header.get('history_ino', '') and offset:
		return 'rebuild', []
	if st.st_size < offset:
		return 'rebuild', []
	if st.st_size == offset:
		return 'fresh', []
	if st.st_size - offset > TAIL_LIMIT_BYTES:
		return 'rebuild', []
	lines, _, _ = read_history(history, offset)
	if len(lines) > TAIL_LIMIT_ENTRIES:
		return 'rebuild', []
	return 'tail', lines

def take_lock(path, now=None):
	'''Create the rebuild lock file, or return False if another rebuild holds it (and it is not stale).'''
	now = time.time() if now is None else now
	for _ in range(2):
		try:
			fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
		except FileExistsError:
			try:
				age = now - os.stat(path).st_mtime
			except OSError:
				continue
			if age < LOCK_STALE:
				return False
			try:
				os.unlink(path)
			except OSError:
				pass
			continue
		except OSError:
			return False
		with os.fdopen(fd, 'w') as f:
			f.write('{} {}\n'.format(os.getpid(), int(now)))
		return True
	return False

def spawn_rebuild(directory):
	'''Start a detached `rebuild` unless one is running. Returns whether one was started.'''
	lock = os.path.join(directory, LOCK_NAME)
	if not take_lock(lock):
		return False
	import subprocess
	try:
		subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), 'rebuild', '--lock', lock],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
			close_fds=True, start_new_session=True, cwd='/')
	except OSError as e:
		_debug('cannot start rebuild: {!r}'.format(e))
		try:
			os.unlink(lock)
		except OSError:
			pass
		return False
	return True

def _load_index(path):
	try:
		return NsvIndex.load(path)
	except (OSError, IndexCorrupt, ValueError) as e:
		_debug('index not usable: {!r}'.format(e))
		return None

def load_for_query(directory, now):
	'''
	The index to answer from and the history lines it is missing.

	Starts a rebuild when the index is stale, and waits up to FIRST_BUILD_BUDGET for the first one.

	Returns:
		tuple: (NsvIndex or None, history tail lines)
	'''
	path = os.path.join(directory, INDEX_NAME)
	index = _load_index(path)
	if index is None:
		spawn_rebuild(directory)
		until = time.monotonic() + FIRST_BUILD_BUDGET
		while index is None and time.monotonic() < until:
			time.sleep(0.05)
			if os.path.exists(path):
				index = _load_index(path)
		if index is None:
			return None, []
	state, tail = check_freshness(index, now)
	if state == 'rebuild':
		spawn_rebuild(directory)
	return index, tail

#%% ------------ Engine ----------------
PRIOR = 0.001              # score of a candidate that nothing in history supports
GROUP_THRESHOLD = 50       # list single hosts once a prefix matches at most this many
UNAVAILABLE_PENALTY = 0.5  # score factor for hosts mssh found unreachable
SHELL_WEIGHT = 0.25        # weight of a shell history line next to an mssh history use
MAX_CANDIDATES = 200
MAGIC_STRINGS = ('#HOST#', '#HOSTNAME#', '#USER#', '#USERNAME#', '#ID#', '#I#', '#UUID#', '#RESOLVEDNAME#', '#IP#')
COMPLETION_ACTIONS = ('bash', 'zsh', 'fish', 'install', 'uninstall')
ENCODINGS = ('utf-8', 'latin-1', 'ascii', 'utf-16', 'cp1252')
# characters bash would read specially in an unquoted word (globs are left alone: mssh takes ranges)
_BASH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()!')

class Request(object):
	'''A completion request: the shell, its capability flags, the line split at the cursor, the word to replace.'''
	__slots__ = ('shell', 'shell_version', 'flags', 'before', 'after', 'word', 'history')

	def __init__(self, shell, before, after='', word=None, shell_version='', flags=None, history=()):
		self.shell = shell
		self.shell_version = shell_version
		self.flags = dict(flags or {})
		self.before = before
		self.after = after
		self.word = word
		self.history = list(history)

class Candidate(object):
	__slots__ = ('text', 'description', 'group', 'score')

	def __init__(self, text, description='', group='', score=0.0):
		self.text = text
		self.description = description
		self.group = group
		self.score = score

	def __repr__(self):
		return 'Candidate({!r}, {!r}, {!r}, {:.4g})'.format(self.text, self.description, self.group, self.score)

class Response(object):
	'''
	The answer to a request.

	candidates are replacements for the request's word, best first. delegate is
	(word index, prefix, words) when the shell should add its own completion of a remote
	command. ghost (SP2) and diagnostics (SP3) are not filled in yet.
	'''
	__slots__ = ('context', 'candidates', 'directives', 'delegate', 'ghost', 'diagnostics')

	def __init__(self, context=None):
		self.context = context
		self.candidates = []
		self.directives = set()
		self.delegate = None
		self.ghost = None
		self.diagnostics = []

def shell_history_knowledge(lines, spec):
	'''The shell's history as weak records: mssh lines like mssh history, other lines as local commands.'''
	memory = MemoryKnowledge()
	count = len(lines)
	for position, line in enumerate(lines):
		line = line.strip()
		tokens = lex(line) if line else []
		if not tokens:
			continue
		if os.path.basename(tokens[0].text) in MSSH_NAMES:
			features = line_features(tokens[1:], spec)
		else:
			features = command_features(line)
		if features:
			memory.add(features, SHELL_WEIGHT * 0.998 ** (count - 1 - position))
	return memory

def _shell_word(request):
	'''The request's word as the engine compares it: zsh and fish send it quoted as typed.'''
	if request.word is None:
		return None
	if request.shell in ('zsh', 'fish'):
		tokens = lex(request.word)
		return tokens[0].text if len(tokens) == 1 else ('' if not tokens else request.word)
	return request.word

def _bash_escape(text):
	return ''.join('\\' + char if char in _BASH_SPECIAL else char for char in text)

class Engine(object):
	'''Answers completion requests from parsed options, history knowledge and the host table.'''
	def __init__(self, spec, knowledges=(), hosts=None, users=()):
		self.spec = spec
		self.knowledges = [knowledge for knowledge in knowledges if knowledge is not None]
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)

	def query(self, request, deadline=None):
		context = parse_context(request.before, request.after, self.spec)
		response = Response(context)
		if context is None:
			return response
		if context.slot == SLOT_OPTION:
			candidates = self._options(context, request.shell)
		elif context.slot == SLOT_VALUE:
			candidates = self._values(context, response, deadline)
		elif context.slot == SLOT_HOSTS:
			candidates = self._hosts(context.value, context, deadline)
		else:
			candidates = self._commands(context, response, deadline)
		if request.flags.get('nosort') == '1':
			response.directives.add('nosort')
		response.candidates = self._frame(candidates, context, request)
		return response

	def _frame(self, candidates, context, request):
		'''Turn slot values into replacements for the shell's word, best first, without duplicates.'''
		word = _shell_word(request)
		prefix = context.prefix
		if word is None:
			word = prefix
		if not prefix.endswith(word):
			# the shell's word is not the end of what was parsed (e.g. backslash escapes): offer nothing
			return []
		base = prefix[:len(prefix) - len(word)]
		lead = prefix[:context.value_start]
		out = []
		seen = set()
		for candidate in sorted(candidates, key=lambda candidate: (-candidate.score, candidate.text)):
			full = lead + candidate.text
			if not full.startswith(prefix) or full in seen:
				continue
			rest = full[len(prefix):]
			if request.shell == 'bash':
				if context.open_quote == '"' and any(char in rest for char in '"\\$`'):
					continue
				if context.open_quote in ("'", "$'") and "'" in rest:
					continue
				if not context.open_quote:
					rest = _bash_escape(rest)
			if '\t' in rest or '\n' in rest:
				continue
			seen.add(full)
			out.append(Candidate(full[len(base):len(prefix)] + rest, candidate.description, candidate.group, candidate.score))
			if len(out) >= MAX_CANDIDATES:
				break
		return out

	def _options(self, context, shell):
		word = context.prefix
		used = {option.dest for option, _ in context.options if not option.repeat}
		groups = {option.group for option, _ in context.options if option.group}
		scores = score_features(self.knowledges, 'o:', context.features)
		out = []
		for option in self.spec.options:
			if option.dest in used or (option.group and option.group in groups):
				continue
			score = scores.get('o:' + option.long, 0.0) + PRIOR
			if shell == 'bash' and (word in ('', '-') or word.startswith('--')):
				strings = [option.long]
			elif shell == 'bash':
				strings = [string for string in option.strings if not string.startswith('--')]
			else:
				strings = option.strings
			for string in strings:
				if string.startswith(word):
					out.append(Candidate(string, option.help, 'options', score))
		return out

	def _values(self, context, response, deadline):
		option = context.option
		dest = option.dest
		word = context.value
		if dest in PASSWORD_DESTS:
			response.directives.add('nodefault')
			return []
		lead = 'v:{}='.format(dest)
		out = [Candidate(feature[len(lead):], 'used before', 'history', score)
			for feature, score in score_features(self.knowledges, lead + word, context.features, deadline).items()]
		if dest in PATH_DESTS:
			response.directives.add('files')
		elif dest == 'identity_file':
			response.directives.add('files')
			out.extend(self._key_files(word))
		elif dest in USER_DESTS:
			users = set(self.users)
			if os.environ.get('USER'):
				users.add(os.environ['USER'])
			out.extend(Candidate(user, 'user', 'users', PRIOR) for user in users if user.startswith(word))
		elif dest == 'skip_hosts':
			out.extend(self._hosts(word, context, deadline, boost=self._members(context.hosts)))
		elif dest == 'completion':
			out.extend(Candidate(action, '', 'values', PRIOR) for action in COMPLETION_ACTIONS if action.startswith(word))
		elif dest == 'encoding':
			out.extend(Candidate(name, '', 'values', PRIOR) for name in ENCODINGS if name.startswith(word))
		if option.default and option.default.startswith(word):
			out.append(Candidate(option.default, 'default', 'defaults', PRIOR / 2))
		return out

	def _key_files(self, word):
		directory = os.path.expanduser('~/.ssh')
		try:
			entries = os.listdir(directory)
		except OSError:
			return []
		out = []
		for name in sorted(entries):
			if name.endswith('.pub') or not (name.startswith('id_') or name + '.pub' in entries):
				continue
			text = '~/.ssh/' + name
			if text.startswith(word):
				out.append(Candidate(text, 'key', 'keys', PRIOR))
		return out

	def _members(self, hosts_text):
		'''The host names a hosts argument names, as far as the index knows them (aliases, number ranges).'''
		members = set()
		for word in split_hosts(hosts_text or ''):
			word = word.rpartition('@')[2]
			alias = self.hosts.alias_index(word)
			if alias is not None:
				members.update(self.hosts.alias_members(alias))
			else:
				members.update(expand_ranges(word))
		return members

	def _hosts(self, text, context, deadline, boost=frozenset()):
		'''Candidates for a hosts argument whose text so far is text: complete its last host.'''
		head, comma, segment = text.rpartition(',')
		user, at, host_prefix = segment.rpartition('@')
		lead = head + comma + user + at
		scores = {}
		for feature, score in score_features(self.knowledges, 't:' + host_prefix, context.features, deadline).items():
			scores[feature[2:]] = score
		out = []
		if not comma and not at:
			for feature, score in score_features(self.knowledges, 'h:' + segment, context.features, deadline).items():
				if feature[2:] not in scores:
					out.append(Candidate(feature[2:], 'used before', 'history', score))
		aliases = set()
		for number, name in self.hosts.aliases_with_prefix(host_prefix):
			aliases.add(name)
			out.append(Candidate(lead + name, 'alias, {} hosts'.format(self.hosts.alias_size(number)), 'aliases', scores.get(name, 0.0) + 2 * PRIOR))
		names = set(self.hosts.names_with_prefix(host_prefix))
		names.update(name for name in scores if name.startswith(host_prefix) and '[' not in name)
		names -= aliases
		unavailable = self.hosts.unavailable
		def host_score(name):
			score = scores.get(name, 0.0) + PRIOR
			if name in boost:
				score += 1.0
			if name in unavailable:
				score *= UNAVAILABLE_PENALTY
			return score
		def single(name):
			return Candidate(lead + name, 'unreachable recently' if name in unavailable else '', 'hosts', host_score(name))
		# host groups typed before, e.g. node[1-3]
		for name, score in scores.items():
			if '[' in name and name not in aliases:
				out.append(Candidate(lead + name, 'used before', 'groups', score))
		if len(names) <= GROUP_THRESHOLD:
			out.extend(single(name) for name in names)
			return out
		covered = set()
		for group_text, members in self.hosts.groups():
			if group_text.startswith(host_prefix) and len(members) > 1 and names.issuperset(members):
				covered.update(members)
				out.append(Candidate(lead + group_text, '{} hosts'.format(len(members)), 'groups', sum(host_score(member) for member in members)))
		rest = names - covered
		if len(rest) <= GROUP_THRESHOLD:
			out.extend(single(name) for name in rest)
		else:
			for group_text in compact_names(rest):
				members = expand_ranges(group_text)
				description = '{} hosts'.format(len(members)) if len(members) > 1 else ''
				out.append(Candidate(lead + group_text, description, 'groups' if len(members) > 1 else 'hosts', sum(host_score(member) for member in members)))
			used = sorted((name for name in names if scores.get(name)), key=lambda name: -scores[name])[:20]
			out.extend(single(name) for name in used)
		return out

	def _commands(self, context, response, deadline):
		word = context.prefix
		out = []
		if context.mode in ('sync', 'gather'):
			response.directives.add('files')
		if word.count('#') % 2 == 1:
			at = word.rfind('#')
			for magic in MAGIC_STRINGS:
				if magic.startswith(word[at:]):
					out.append(Candidate(word[:at] + magic, 'replaced per host', 'magic', 1e6))
		if context.mode in PATH_MODES:
			for feature, score in score_features(self.knowledges, 'f:' + word, context.features, deadline).items():
				out.append(Candidate(feature[2:], 'used before', 'history', score))
		elif context.quoted:
			for feature, score in score_features(self.knowledges, 'c:' + word, context.features, deadline).items():
				out.append(Candidate(feature[2:], '', 'history', score))
		elif context.command_words:
			typed = context.command_words[:-1]
			partial = context.command_words[-1]
			if not typed:
				for feature, score in score_features(self.knowledges, 'p:' + partial, context.features, deadline).items():
					out.append(Candidate(feature[2:], '', 'history', score))
			else:
				following = {}
				for feature, score in score_features(self.knowledges, 'c:' + ' '.join(typed) + ' ' + partial, context.features, deadline).items():
					words = [token.text for token in lex(feature[2:])]
					if len(words) > len(typed) and words[:len(typed)] == typed and words[len(typed)].startswith(partial):
						following[words[len(typed)]] = following.get(words[len(typed)], 0.0) + score
				out.extend(Candidate(text, '', 'history', score) for text, score in following.items())
		if context.mode == 'plain' and context.command_words is not None:
			response.delegate = (context.command_word_index, context.command_prefix, list(context.command_words))
		return out

#%% ------------ Protocol ----------------
def parse_request(data):
	'''
	Parse a request: MSSHC1\\0shell\\0version\\0flags\\0before\\0after\\0word\\0 then history lines.

	Raises:
		ValueError: not a request of this protocol
	'''
	text = data.decode('utf-8', 'surrogateescape')
	parts = text.split('\0', 7)
	if len(parts) < 8 or parts[0] != PROTOCOL:
		raise ValueError('not an {} request'.format(PROTOCOL))
	flags = {}
	for flag in parts[3].split():
		key, _, value = flag.partition('=')
		flags[key] = value
	history = [line for line in parts[7].split('\n') if line.strip()]
	return Request(parts[1], parts[4], parts[5], parts[6], parts[2], flags, history)

def _clean(text):
	return ' '.join(str(text).split())

def format_response(response, nul=True):
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup), an X
	line for delegation, then E, and a NUL unless nul is False.
	'''
	lines = [PROTOCOL]
	if response.directives:
		lines.append('D ' + ' '.join(sorted(response.directives)))
	for candidate in response.candidates:
		if safe_field(candidate.text) and '\t' not in candidate.text:
			lines.append('C {}\t{}\t{}'.format(candidate.text, _clean(candidate.description), candidate.group))
	if response.delegate is not None:
		index, prefix, words = response.delegate
		fields = [str(index), prefix] + list(words)
		if all(safe_field(field) and '\t' not in field for field in fields):
			lines.append('X ' + '\t'.join(fields))
	lines.append('E')
	return ('\n'.join(lines) + '\n' + ('\0' if nul else '')).encode('utf-8', 'surrogateescape')

def answer(request, deadline=None, directory=Ellipsis, now=None):
	'''
	Answer a request from the index in directory: mssh's cache dir by default, None for no index
	(degraded: options from mssh's parser, shell history, no ranking from mssh history).
	'''
	now = time.time() if now is None else now
	if directory is Ellipsis:
		directory = cache_dir()
	index, tail = (None, []) if directory is None else load_for_query(directory, now)
	knowledges = []
	users = ()
	if index is not None:
		spec = ParserSpec.from_rows([index.row('spec', number) for number in range(index.count('spec'))])
		knowledges.append(SnapshotKnowledge(index, now))
		config = {row[0]: row[1:] for row in (index.row('config', number) for number in range(index.count('config'))) if row}
		users = config.get('users', ())
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		spec = spec_from_parser(_import_mssh().get_parser())
	if tail:
		memory = MemoryKnowledge()
		memory.add_history(tail, spec, now)
		knowledges.append(memory)
	if request.history:
		# fish lists its history newest first, the others oldest first
		history = request.history[::-1] if request.shell == 'fish' else request.history
		knowledges.append(shell_history_knowledge(history, spec))
	return Engine(spec, knowledges, HostTable(index), users).query(request, deadline)

#%% ------------ Command line ----------------
def _cmd_query():
	deadline = time.monotonic() + float(os.environ.get('MSSH_COMPLETE_SOFT_DEADLINE', '0.2'))
	data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
	try:
		request = parse_request(data)
	except ValueError as e:
		_debug('bad request: {}'.format(e))
		return 1
	try:
		response = answer(request, deadline)
	except Exception as e:
		_debug('query failed: {!r}'.format(e))
		return 1
	sys.stdout.buffer.write(format_response(response, nul=request.flags.get('nul', '1') != '0'))
	sys.stdout.buffer.flush()
	return 0

def _cmd_rebuild(args):
	lock = args[1] if len(args) == 2 and args[0] == '--lock' else None
	try:
		directory = cache_dir()
		if directory is None:
			print('mssh-complete: no private cache directory', file=sys.stderr)
			return 1
		print(build_index(directory))
		return 0
	except Exception as e:
		_debug('rebuild failed: {!r}'.format(e))
		print('mssh-complete: rebuild failed: {!r}'.format(e), file=sys.stderr)
		return 1
	finally:
		if lock:
			try:
				os.unlink(lock)
			except OSError:
				pass

def main(argv=None):
	argv = sys.argv[1:] if argv is None else argv
	command = argv[0] if argv else ''
	if command == 'query':
		return _cmd_query()
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command in ('-V', '--version'):
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | rebuild', file=sys.stderr)
	return 2

if __name__ == '__main__':
	sys.exit(main())
