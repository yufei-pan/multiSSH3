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

version = '0.2'
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
		The option a word names, and the value attached to it ("-x=value", "--long=value", "-xVALUE").

		Unique abbreviations of --long options are accepted, like argparse does.

		Returns:
			tuple: (OptionSpec or None, attached value or None)
		'''
		option = self.by_string.get(text)
		if option is not None:
			return option, None
		name, sep, value = text.partition('=')
		option = (self.by_string.get(name) or self._abbreviation(name)) if sep else self._abbreviation(text)
		if option is not None:
			return option, (value if sep else None)
		if len(text) > 2 and text[0] == '-' and text[1] != '-':
			# argparse reads -pVALUE as -p VALUE, '=' in VALUE included
			short = self.by_string.get(text[:2])
			if short is not None and short.nargs != '0':
				return short, text[2:]
		return None, None

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

def _attached(text, option):
	'''The value attached to an option word: -x=value, --long=value or -xVALUE (None if there is none).'''
	if text in option.strings or option.nargs == '0':
		return None
	if '=' in text:
		return text.partition('=')[2]
	if not text.startswith('--') and len(text) > 2:
		return text[2:]
	return None

def _collect(words, roles, skip=()):
	'''The options (with values), hosts and command words of a line, leaving out the words in skip.'''
	options = []
	hosts = ''
	commands = []
	for index, (token, (role, option)) in enumerate(zip(words, roles)):
		if index in skip:
			continue
		if role == ROLE_OPTION and option is not None:
			options.append([option, _attached(token.text, option)])
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
	if not 0 <= ts < 10 ** 11:
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
INDEX_FORMAT = '2'
INDEX_NAME = 'complete-index.v1.nsv'

class IndexCorrupt(Exception):
	'''The index file is not a complete index this version can read.'''

def _has_control(text):
	'''Whether text holds a control character (C0, DEL, C1): such text never goes on a command line or the screen.'''
	return any(ord(char) < 32 or 127 <= ord(char) < 160 for char in text)

def _printable(text):
	'''text with each control character (C0, DEL, C1) shown as ?: safe to draw.'''
	return ''.join('?' if ord(char) < 32 or 127 <= ord(char) < 160 else char for char in text)

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
		self._uses = {}
		self._sorted = None

	def add(self, features, weight, ts=0):
		'''Add one use of an invocation with these features, at unix time ts (0 if unknown).'''
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
			count, last = self._uses.get(feature, (0, 0))
			self._uses[feature] = (count + 1, max(last, ts))

	def add_history(self, lines, spec, now):
		'''Add ~/.mssh_history lines, each weighted by its age.'''
		for line in lines:
			entry = parse_history_line(line, spec)
			if entry is not None:
				self.add(entry.features(), use_weight(now - entry.ts), entry.ts)

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

	def feature_uses(self, key):
		'''(times used, last used unix time) of a feature.'''
		return self._uses.get(key, (0, 0))

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

	def feature_uses(self, key):
		'''(times used, last used unix time) of a feature.'''
		counts = self.index.single('fcounts')
		lasts = self.index.single('flast')
		try:
			return int(counts[key]), int(lasts[key])
		except (IndexError, ValueError):
			return 0, 0

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

# as in multiSSH3 (tests point them elsewhere)
_RUN_USER_ROOT = '/run/user'
_SHM_DIR = '/dev/shm'

def cache_dir(create=True):
	'''
	mssh's private runtime directory, where unavailable_hosts.csv and the index live, or None.

	Exactly as multiSSH3.runtime_dir picks it: $XDG_RUNTIME_DIR/multiSSH3 when that runtime dir
	is ours, /run/user/<uid>/multiSSH3, /dev/shm/multiSSH3-<uid>, then <tempdir>/multiSSH3-<uid>.
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
	if hasattr(os, 'getuid'):
		run_user = os.path.join(_RUN_USER_ROOT, str(user_id))
		if _owned_and_not_writable_by_others(run_user):
			candidates.append(os.path.join(run_user, 'multiSSH3'))
		if os.path.isdir(_SHM_DIR):
			candidates.append(os.path.join(_SHM_DIR, 'multiSSH3-{}'.format(user_id)))
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
RANGE_MEMBERS_LIMIT = 4096   # a range typed before adds its members as hosts up to this many

def serialize_knowledge(memory):
	'''
	The features, records, postings and feature weight rows of the heaviest MAX_RECORDS records.

	Returns:
		tuple: (features, record rows, posting rows, fweights row, fcounts row, flast row)
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
	uses = [memory.feature_uses(feature) for feature in features]
	return (features, record_rows, postings, ['%.6g' % weight for weight in weights],
		[str(count) for count, _ in uses], [str(last) for _, last in uses])

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
	features, record_rows, postings, fweights, fcounts, flast = serialize_knowledge(memory)
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
		if name in aliases:
			continue
		if '[' in name:
			# the members of a range typed before, so they complete one by one (e.g. for -X)
			members = expand_ranges(name, limit=RANGE_MEMBERS_LIMIT)
			if members != [name]:
				for member in members:
					add(member, SRC_HISTORY)
			continue
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
		('fcounts', [fcounts]),
		('flast', [flast]),
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
MAX_HOSTS_TEXT = 256       # longer host strings typed before are not offered whole
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
	'''A completion. raw is the text before bash escaping, when it differs.'''
	__slots__ = ('text', 'description', 'group', 'score', 'raw')

	def __init__(self, text, description='', group='', score=0.0, raw=None):
		self.text = text
		self.description = description
		self.group = group
		self.score = score
		self.raw = raw

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

def _mssh_start(tokens):
	'''Index of the word that runs mssh in a command line (mssh, sudo mssh, python3 multiSSH3.py, ...), or None.'''
	for index, token in enumerate(tokens):
		name = os.path.basename(token.text)
		if name.endswith('.py'):
			name = name[:-3]
		if name in MSSH_NAMES:
			return index
	return None

# tuned with `mssh-complete eval` (ghost policy): wrong suggestions under 10% of those shown on
# synthetic and real history, the most keys saved on top of TAB
T_WORD = 0.7   # confidence the top value of the current word needs before its rest is suggested
T_LINE = 0.6   # share each following slot's top value needs before the rest of the line is suggested
SUPPORT = 1.0  # confidence = share * uses / (uses + SUPPORT): a value seen once is not yet sure

class Ghost(object):
	'''
	A grey suggestion: text goes after the cursor.

	kind is 'line' when the text goes past the current word into following slots, 'word' otherwise;
	confidence is the smallest share that let it through.
	'''
	__slots__ = ('kind', 'text', 'confidence')

	def __init__(self, kind, text, confidence):
		self.kind = kind
		self.text = text
		self.confidence = confidence

	def __repr__(self):
		return 'Ghost({!r}, {!r}, {:.3f})'.format(self.kind, self.text, self.confidence)

def _top_share(scores):
	'''(top value, its share of the positive scores) of a value -> score dict, or (None, 0).'''
	best = None
	total = 0.0
	for value, score in scores.items():
		total += max(score, 0.0)
		if best is None or (score, value) > (scores[best], best):
			best = value
	if best is None or total <= 0:
		return None, 0.0
	return best, max(scores[best], 0.0) / total

def _common_prefix(texts):
	'''The longest start all texts share ('' for none).'''
	if not texts:
		return ''
	low, high = min(texts), max(texts)
	end = 0
	while end < len(low) and low[end] == high[end]:
		end += 1
	return low[:end]

def shell_history_knowledge(lines, spec):
	'''
	The shell's history as weak records: lines running mssh like mssh history (passwords dropped),
	other lines as local commands.
	'''
	memory = MemoryKnowledge()
	count = len(lines)
	for position, line in enumerate(lines):
		line = line.strip()
		tokens = lex(line) if line else []
		if not tokens:
			continue
		start = _mssh_start(tokens)
		if start is not None:
			features = line_features(tokens[start + 1:], spec)
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

# characters zsh reads specially in an unquoted word, globs included (zsh fails on a glob that matches nothing)
_ZSH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()!*?[]#~^{}')

# characters fish reads specially in an unquoted word
_FISH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()*?[]#~{}')

# in a word taken literally bash would also read # as a comment and expand ~, globs and braces
_BASH_STRICT_SPECIAL = _BASH_SPECIAL | frozenset('#~*?[]{}')

def _shell_escape(shell, text, strict=False):
	'''text escaped for an unquoted word of shell; strict: a word taken literally (bash leaves globs only in hosts).'''
	special = {'bash': _BASH_STRICT_SPECIAL if strict else _BASH_SPECIAL, 'zsh': _ZSH_SPECIAL, 'fish': _FISH_SPECIAL}.get(shell)
	if special is None:
		return text
	return ''.join('\\' + char if char in special else char for char in text)

def _literal_word(context):
	'''Whether the current word is taken literally: a word of the remote command, or a path.'''
	return context.slot == SLOT_COMMAND or (context.slot == SLOT_VALUE and context.option.dest in PATH_DESTS)

class Engine(object):
	'''Answers completion requests from parsed options, history knowledge and the host table.'''
	def __init__(self, spec, knowledges=(), hosts=None, users=()):
		self.history_path = None
		self.spec = spec
		self.knowledges = [knowledge for knowledge in knowledges if knowledge is not None]
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)

	def query(self, request, deadline=None):
		if request.flags.get('ghost') == '1':
			response = Response(parse_context(request.before, request.after, self.spec))
			response.ghost = self.suggest(request, deadline)
			return response
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
		response.candidates = self._frame(candidates, context, request, response.directives)
		return response

	def suggest(self, request, deadline=None):
		'''
		The grey suggestion for a line with the cursor at its end, or None (never one with a control character).

		The current word's most likely value (when its share of the scores reaches T_WORD), then,
		when each following positional slot's top value reaches T_LINE, those slots: the hosts and
		the first command. Options are never added. The suggestion always extends the typed text.
		'''
		ghost = self._suggest(request, deadline)
		return None if ghost is None or _has_control(ghost.text) else ghost

	def _suggest(self, request, deadline):
		if request.after.strip():
			return None
		tokens = lex(request.before)
		if not tokens or os.path.basename(tokens[0].text) not in MSSH_NAMES:
			return None
		context = parse_context(request.before, request.after, self.spec)
		if context is None or (context.slot == SLOT_VALUE and context.option.dest in PASSWORD_DESTS):
			return None
		if context.slot == SLOT_COMMAND and not context.quoted and context.mode == 'plain' and context.command_words:
			return self._suggest_command_words(context, request.shell, deadline)
		typed = context.value
		values = {}
		for candidate in self._slot_candidates(context, deadline):
			if candidate.text.startswith(typed):
				values[candidate.text] = max(values.get(candidate.text, 0.0), candidate.score)
		top, share = _top_share(values)
		if top is None:
			return None
		share *= self._support(context, top)
		if share < T_WORD:
			return self._suggest_shared_start(context, typed, values, request.shell)
		rest = top[len(typed):]
		if context.open_quote:
			closing = '"' if context.open_quote == '"' else "'"
			unsafe = '"\\$`' if closing == '"' else "'"
			if any(char in unsafe for char in rest):
				return None
			if context.slot == SLOT_COMMAND:
				rest += closing
		elif rest:
			rest = _shell_escape(request.shell, rest, _literal_word(context))
		continuation, rest_share = self._continuation(context, top, request.shell, deadline)
		if continuation and rest_share >= T_LINE:
			return Ghost('line', rest + continuation, min(share, rest_share))
		if not rest:
			return None
		return Ghost('word', rest, share)

	def _suggest_shared_start(self, context, typed, values, shell):
		'''
		When no value of the current slot is sure enough: the start all of them share, as TAB would
		insert it, once they were used often enough between them. Never closes a quote.
		'''
		common = _common_prefix(list(values))
		if len(common) <= len(typed):
			return None
		support = 1.0
		if SUPPORT > 0:
			uses = 0
			for value in values:
				uses += self.usage(context, value)[0]
				support = float(uses) / (uses + SUPPORT)
				if support >= T_WORD:
					break
		if support < T_WORD:
			return None
		rest = common[len(typed):]
		if context.open_quote:
			unsafe = '"\\$`' if context.open_quote == '"' else "'"
			if any(char in unsafe for char in rest):
				return None
		else:
			rest = _shell_escape(shell, rest, _literal_word(context))
		return Ghost('word', rest, support)

	def _suggest_command_words(self, context, shell, deadline):
		'''
		Suggestion for a command typed as unquoted words: the rest of the most likely past command
		whose words start with the typed ones, each word escaped so the remote command is the same.
		'''
		typed = context.command_words
		commands = {}
		for feature, score in score_features(self.knowledges, 'c:' + ' '.join(typed), context.features, deadline).items():
			words = [token.text for token in lex(feature[2:])]
			if len(words) >= len(typed) and words[:len(typed) - 1] == typed[:-1] and words[len(typed) - 1].startswith(typed[-1]):
				key = tuple(words)
				commands[key] = commands.get(key, 0.0) + score
		top, share = _top_share(commands)
		if top is None:
			return None
		uses = self._uses('c:' + ' '.join(top))
		share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		next_words = {}
		for words, score in commands.items():
			next_words[words[len(typed) - 1]] = next_words.get(words[len(typed) - 1], 0.0) + score
		word, word_share = _top_share(next_words)
		word_share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		rest = _shell_escape(shell, top[len(typed) - 1][len(typed[-1]):], True)
		more = ''.join(' ' + _shell_escape(shell, extra, True) for extra in top[len(typed):])
		if more and share >= T_LINE:
			return Ghost('line', rest + more, share)
		word_rest = _shell_escape(shell, word[len(typed[-1]):], True)
		if word_rest and word_share >= T_WORD:
			return Ghost('word', word_rest, word_share)
		return None

	def _uses(self, feature):
		'''How many times a feature was used, over all knowledge.'''
		count = 0
		for knowledge in self.knowledges:
			key = knowledge.feature_key(feature)
			if key is not None and hasattr(knowledge, 'feature_uses'):
				count += knowledge.feature_uses(key)[0]
		return count

	def usage(self, context, value):
		'''(times used, last used unix time) of a value of the current slot, over all knowledge.'''
		if context.slot == SLOT_HOSTS:
			segment = value.rpartition(',')[2].rpartition('@')[2]
			features = ['h:' + value, 't:' + segment]
		elif context.slot == SLOT_VALUE:
			features = ['v:{}={}'.format(context.option.dest, value)]
		elif context.slot == SLOT_OPTION:
			option = self.spec.lookup(value)[0]
			features = ['o:' + option.long] if option else []
		else:
			features = [('f:' if context.mode in PATH_MODES else 'c:') + value]
		best = (0, 0)
		for feature in features:
			count = 0
			last = 0
			for knowledge in self.knowledges:
				key = knowledge.feature_key(feature)
				if key is not None and hasattr(knowledge, 'feature_uses'):
					uses, when = knowledge.feature_uses(key)
					count += uses
					last = max(last, when)
			best = max(best, (count, last))
		return best

	def _support(self, context, value):
		'''uses / (uses + SUPPORT) for a value of the current slot: evidence behind a suggestion.'''
		if SUPPORT <= 0:
			return 1.0
		uses = self.usage(context, value)[0]
		return float(uses) / (uses + SUPPORT)

	def _slot_candidates(self, context, deadline):
		'''The slot values the providers rank for the current slot, unframed.'''
		scratch = Response(context)
		if context.slot == SLOT_OPTION:
			return self._options(context, 'zsh')
		if context.slot == SLOT_VALUE:
			return self._values(context, scratch, deadline)
		if context.slot == SLOT_HOSTS:
			return self._hosts(context.value, context, deadline)
		return self._commands(context, scratch, deadline)

	def _continuation(self, context, value, shell, deadline):
		'''
		The following positional slots nobody typed yet, as text, and the smallest share among them.

		After a hosts value: the first command. After an option value: the hosts (when not typed)
		and the first command (when not typed). Only in plain mode, never after commands.
		'''
		if context.mode != 'plain' or context.open_quote or context.slot in (SLOT_OPTION, SLOT_COMMAND):
			return '', 0.0
		features = set(context.features)
		if any(feature.startswith('c:') for feature in features):
			return '', 0.0
		text = ''
		shares = []
		if context.slot == SLOT_HOSTS:
			features.update(make_features([], value, []))
		else:
			features.add('v:{}={}'.format(context.option.dest, value))
			if not context.hosts:
				hosts, share = _top_share(self._feature_values('h:', features, deadline))
				if hosts is None:
					return '', 0.0
				text += ' ' + _shell_escape(shell, hosts)
				shares.append(share)
				features.update(make_features([], hosts, []))
		command, share = _top_share(self._feature_values('c:', features, deadline))
		quote = _quote_command(command) if command is not None else None
		if quote is None:
			return '', 0.0
		text += ' ' + quote + command + quote
		shares.append(share)
		return text, min(shares)

	def _feature_values(self, kind, features, deadline):
		'''value -> score of every feature of a kind ('h:', 'c:'), scored against features.'''
		return {feature[len(kind):]: score for feature, score in score_features(self.knowledges, kind, sorted(features), deadline).items()}

	def _frame(self, candidates, context, request, directives=()):
		'''
		Turn slot values into replacements for the shell's word, best first, without duplicates.

		For bash, and for any shell that inserts the text as it is (request flag insert=1: the picker),
		text left unquoted is escaped for that shell, except when bash's TAB quotes file names itself.
		'''
		literal = request.shell == 'bash' or request.flags.get('insert') == '1'
		# bash's own TAB quotes file names itself; what the picker inserts nobody quotes
		bash_quotes = request.shell == 'bash' and request.flags.get('insert') != '1' and bool({'files', 'dirs'} & set(directives))
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
			if literal:
				if context.open_quote == '"' and any(char in rest for char in '"\\$`'):
					continue
				if context.open_quote in ("'", "$'") and "'" in rest:
					continue
				if not context.open_quote and not bash_quotes:
					rest = _shell_escape(request.shell, rest, _literal_word(context))
			if _has_control(rest):
				continue
			seen.add(full)
			text = full[len(base):len(prefix)] + rest
			raw = full[len(base):]
			out.append(Candidate(text, candidate.description, candidate.group, candidate.score, raw if raw != text else None))
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
				if feature[2:] not in scores and len(feature) - 2 <= MAX_HOSTS_TEXT:
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
		# ranges typed before, e.g. node[1-3]: their members are not listed beside them, unless typed
		# on their own before or named by the hosts argument (-X)
		in_ranges = set()
		for name, score in scores.items():
			if '[' in name and name not in aliases:
				out.append(Candidate(lead + name, 'used before', 'groups', score))
				in_ranges.update(expand_ranges(name, limit=RANGE_MEMBERS_LIMIT))
		names -= in_ranges - set(boost) - set(scores)
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
		# the hosts the hosts argument names stay listed one by one (for -X)
		out.extend(single(name) for name in sorted(names & set(boost)))
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
	return _printable(' '.join(str(text).split()))

def format_response(response, nul=True):
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup, then
	\\traw when bash escaping changed the text), an X line for delegation, then E, and a NUL unless
	nul is False.
	'''
	lines = [PROTOCOL]
	if response.directives:
		lines.append('D ' + ' '.join(sorted(response.directives)))
	for candidate in response.candidates:
		if safe_field(candidate.text) and '\t' not in candidate.text:
			raw = '\t' + candidate.raw if candidate.raw and safe_field(candidate.raw) and '\t' not in candidate.raw else ''
			lines.append('C {}\t{}\t{}{}'.format(candidate.text, _clean(candidate.description), candidate.group, raw))
	if response.ghost is not None and safe_field(response.ghost.text) and '\t' not in response.ghost.text:
		lines.append('G {}\t{}'.format(response.ghost.kind, response.ghost.text))
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
	return engine_for(request, directory, now).query(request, deadline)

def engine_for(request, directory=Ellipsis, now=None):
	'''The engine for a request: the index in directory (as for answer), its history tail, the shell's history.'''
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
	engine = Engine(spec, knowledges, HostTable(index), users)
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	return engine

#%% ------------ Terminal ----------------
# the keys terminals send as escape sequences (xterm, VT220, rxvt, linux console)
_KEY_SEQUENCES = {
	'\x1b[A': 'up', '\x1b[B': 'down', '\x1b[C': 'right', '\x1b[D': 'left',
	'\x1bOA': 'up', '\x1bOB': 'down', '\x1bOC': 'right', '\x1bOD': 'left',
	'\x1b[H': 'home', '\x1b[F': 'end', '\x1bOH': 'home', '\x1bOF': 'end',
	'\x1b[1~': 'home', '\x1b[4~': 'end', '\x1b[7~': 'home', '\x1b[8~': 'end',
	'\x1b[2~': 'insert', '\x1b[3~': 'delete', '\x1b[5~': 'pgup', '\x1b[6~': 'pgdn',
	'\x1b[1;5C': 'ctrl-right', '\x1b[1;5D': 'ctrl-left', '\x1b[5C': 'ctrl-right', '\x1b[5D': 'ctrl-left',
	'\x1bOc': 'ctrl-right', '\x1bOd': 'ctrl-left',
	'\x1b[1;3C': 'alt-right', '\x1b[1;3D': 'alt-left', '\x1b\x1b[C': 'alt-right', '\x1b\x1b[D': 'alt-left',
}
_KEY_NAMES = {'\r': 'enter', '\n': 'enter', '\t': 'tab', '\x7f': 'backspace', '\x08': 'backspace', '\x00': 'ctrl-space'}

def decode_keys(data):
	'''
	Split bytes read from a terminal into keys.

	Returns:
		list: (name, raw bytes) pairs. name is a key name ('up', 'enter', 'ctrl-r', 'alt-f', 'esc', 'unknown')
			or, for text, the character itself.
	'''
	text = data.decode('utf-8', 'replace')
	keys = []
	index = 0
	while index < len(text):
		char = text[index]
		if char == '\x1b':
			for length in range(min(len(text) - index, 7), 1, -1):
				sequence = text[index:index + length]
				if sequence in _KEY_SEQUENCES:
					keys.append((_KEY_SEQUENCES[sequence], sequence.encode()))
					index += length
					break
			else:
				if index + 1 < len(text) and text[index + 1] in '[O':
					# an escape sequence nobody named: up to its final byte
					end = index + 2
					while end < len(text) and not '@' <= text[end] <= '~':
						end += 1
					keys.append(('unknown', text[index:end + 1].encode()))
					index = end + 1
				elif index + 1 < len(text):
					# Alt + key arrives as Esc then the key
					keys.append(('alt-' + text[index + 1], text[index:index + 2].encode('utf-8')))
					index += 2
				else:
					keys.append(('esc', b'\x1b'))
					index += 1
			continue
		if char in _KEY_NAMES:
			keys.append((_KEY_NAMES[char], char.encode()))
		elif ord(char) < 32:
			keys.append(('ctrl-' + chr(ord(char) + 96), char.encode()))
		else:
			keys.append((char, char.encode('utf-8')))
		index += 1
	return keys

def char_width(char):
	'''Columns a character takes on a terminal: 0 (combining, control), 1, or 2 (wide).'''
	import unicodedata
	if ord(char) < 32 or ord(char) == 127 or unicodedata.combining(char) or unicodedata.category(char) in ('Mn', 'Me', 'Cf'):
		return 0
	return 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1

_ESCAPES = None

def strip_escapes(text):
	'''text without terminal escape sequences and readline's \\001 / \\002 markers.'''
	global _ESCAPES
	if _ESCAPES is None:
		import re
		_ESCAPES = re.compile('\x1b\\[[0-9;?<=>]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|\x1b[()][0-9A-Za-z]|\x1b[@-Z\\\\-_]|[\x01\x02]')
	return _ESCAPES.sub('', text)

def text_width(text):
	'''Columns text takes on a terminal, escape sequences left out.'''
	return sum(char_width(char) for char in strip_escapes(text))

def fit(text, width):
	'''text cut to at most width columns (escape sequences are not counted and stay).'''
	out = []
	used = 0
	index = 0
	plain = strip_escapes(text)
	if text_width(plain) <= width:
		return text
	while index < len(text) and used < width:
		match = None
		if text[index] in '\x1b\x01\x02':
			match = _ESCAPES.match(text, index) if _ESCAPES is not None else None
		if match:
			out.append(match.group())
			index = match.end()
			continue
		size = char_width(text[index])
		if used + size > width:
			break
		out.append(text[index])
		used += size
		index += 1
	return ''.join(out)

def ghost_style(term):
	'''The escape sequence that draws grey text on terminal type term, or None where grey text is not drawn.'''
	if not term or term in ('dumb', 'unknown') or term.startswith(('vt52', 'cons25')):
		return None
	if '256color' in term or 'truecolor' in term or 'direct' in term:
		return '\x1b[38;5;244m'
	return '\x1b[2m'

class Terminal(object):
	'''The controlling terminal in raw mode, for the picker and the editor. Restores the mode on exit and on SIGTERM / SIGHUP.'''
	def __init__(self, path='/dev/tty'):
		self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
		self._saved = None
		self._handlers = {}

	def __enter__(self):
		import signal
		import termios
		import tty
		self._saved = termios.tcgetattr(self.fd)
		for number in (signal.SIGTERM, signal.SIGHUP):
			self._handlers[number] = signal.signal(number, self._interrupted)
		# TCSANOW: TCSAFLUSH (the default) would drop keys typed while the program started
		tty.setraw(self.fd, termios.TCSANOW)
		return self

	def _interrupted(self, number, frame):
		self.restore()
		raise SystemExit(128 + number)

	def restore(self):
		import termios
		if self._saved is not None:
			try:
				termios.tcsetattr(self.fd, termios.TCSADRAIN, self._saved)
			except termios.error:
				pass

	def __exit__(self, *exc):
		import signal
		self.restore()
		for number, handler in self._handlers.items():
			signal.signal(number, handler)
		os.close(self.fd)

	def size(self):
		'''(rows, columns), 24x80 when the terminal does not say.'''
		import fcntl
		import struct
		import termios
		try:
			# a whole struct winsize: the kernel writes all of it (Python 3.14+ checks)
			rows, columns, _, _ = struct.unpack('HHHH', fcntl.ioctl(self.fd, termios.TIOCGWINSZ, b'\0' * 8))
			if rows > 0 and columns > 0:
				return rows, columns
		except OSError:
			pass
		return 24, 80

	def write(self, text):
		data = text.encode('utf-8', 'replace')
		while data:
			written = os.write(self.fd, data)
			data = data[written:]

	def _byte(self, timeout):
		import select
		if not select.select([self.fd], [], [], timeout)[0]:
			return None
		return os.read(self.fd, 1) or None

	def has_input(self):
		'''Whether more typed keys are waiting.'''
		import select
		return bool(select.select([self.fd], [], [], 0)[0])

	def read_key(self, timeout=None):
		'''
		The next key typed, as (name, raw bytes) like decode_keys; None when timeout seconds pass first
		(None: wait forever). Reads that key's bytes and no more: what was typed after it stays in the
		terminal, in order, for whoever reads next (the shell, once the picker or the editor is done).
		'''
		data = self._byte(timeout)
		if data is None:
			return None
		if data == b'\x1b':
			data += self._escape()
		else:
			data += self._utf8_rest(data)
		keys = decode_keys(data)
		return keys[0] if len(keys) == 1 else ('unknown', data)

	def _utf8_rest(self, lead):
		'''The continuation bytes of a UTF-8 character that starts with lead.'''
		byte = lead[0]
		needed = 1 if byte & 0xE0 == 0xC0 else 2 if byte & 0xF0 == 0xE0 else 3 if byte & 0xF8 == 0xF0 else 0
		rest = b''
		for _ in range(needed):
			more = self._byte(0.05)
			if more is None:
				break
			rest += more
		return rest

	def _escape(self):
		'''After Esc: the rest of an escape sequence, Alt + a key, or nothing (a lone Esc).'''
		second = self._byte(0.03)
		if second is None:
			return b''
		if second == b'\x1b':
			# Esc Esc [ C: Alt + an arrow on some terminals
			return second + self._escape()
		if second == b'O':
			return second + (self._byte(0.03) or b'')
		if second != b'[':
			return second + self._utf8_rest(second)
		out = second
		while True:
			byte = self._byte(0.03)
			if byte is None:
				return out
			out += byte
			# the final byte; "[[A" (linux console F1) has one more
			if 0x40 <= byte[0] <= 0x7E and out != b'[[':
				return out

def text_layout(text, width, row=0, column=0):
	'''
	Where the cursor is after text is written from (row, column) on a terminal width columns wide,
	wrapping before a character that does not fit. column == width: the row is full and the terminal
	has not wrapped yet.
	'''
	for char in strip_escapes(text):
		size = char_width(char)
		if column + size > width:
			row, column = row + 1, 0
		column += size
	return row, column

#%% ------------ Picker ----------------
PICKER_ROWS = 10       # candidate rows the picker shows at most
HISTORY_LIMIT = 5000   # distinct past invocations the history tab offers

class PickItem(object):
	'''A picker row: text replaces the word (slot tab) or the whole line (history tab).'''
	__slots__ = ('text', 'description', 'uses', 'last')

	def __init__(self, text, description='', uses=0, last=0):
		self.text = text
		self.description = description
		self.uses = uses
		self.last = last

	def __repr__(self):
		return 'PickItem({!r})'.format(self.text)

def fuzzy_score(query, text):
	'''
	How well query matches text: its characters in order (case-insensitive), with more for
	consecutive characters and word starts. Space-separated terms must all match.

	Returns:
		float, or None when it does not match
	'''
	lower = text.lower()
	score = 0.0
	for term in query.lower().split():
		position = 0
		last = -2
		for char in term:
			found = lower.find(char, position)
			if found < 0:
				return None
			score += 1.0
			if found == last + 1:
				score += 2.0
			if found == 0 or not lower[found - 1].isalnum():
				score += 1.5
			last = found
			position = found + 1
	return score

def _age(seconds):
	'''A short age: now, 5m, 2h, 3d, 4w, 1y.'''
	for size, unit in ((365 * 86400, 'y'), (7 * 86400, 'w'), (86400, 'd'), (3600, 'h'), (60, 'm')):
		if seconds >= size:
			return '{}{}'.format(int(seconds // size), unit)
	return 'now'

def _unicode_terminal():
	import locale
	return (locale.getpreferredencoding(False) or '').lower().replace('-', '') == 'utf8'

class Picker(object):
	'''
	The Ctrl-R menu as state: a slot tab (candidates for the word at the cursor) and a history tab
	(whole past invocations), a fuzzy filter and a selection. run() draws it below the prompt line.
	'''
	def __init__(self, slot_items, history_items, slot_title='', now=None, unicode=None):
		self.items = {'slot': list(slot_items), 'history': list(history_items)}
		self.titles = {'slot': slot_title or 'candidates', 'history': 'history'}
		self.tab = 'slot' if self.items['slot'] else 'history'
		self.query = ''
		self.selected = 0
		self.offset = 0
		self.now = time.time() if now is None else now
		self.unicode = _unicode_terminal() if unicode is None else unicode

	def matches(self):
		'''The rows of the current tab that match the filter, best first.'''
		items = self.items[self.tab]
		if not self.query:
			return items
		scored = []
		for rank, item in enumerate(items):
			score = fuzzy_score(self.query, item.text)
			if score is not None:
				# the filter decides, the context rank breaks near ties
				scored.append((score - 3.0 * rank / len(items), rank, item))
		scored.sort(key=lambda entry: (-entry[0], entry[1]))
		return [item for _, _, item in scored]

	def handle(self, name):
		'''Apply one key. Returns 'choose', 'cancel' or None.'''
		count = len(self.matches())
		if name == 'enter':
			return 'choose' if count else 'cancel'
		if name in ('esc', 'ctrl-g', 'ctrl-c'):
			return 'cancel'
		if name in ('up', 'ctrl-p'):
			self.selected = max(0, self.selected - 1)
		elif name in ('down', 'ctrl-n', 'ctrl-r'):
			self.selected = min(max(count - 1, 0), self.selected + 1)
		elif name == 'pgup':
			self.selected = max(0, self.selected - PICKER_ROWS)
		elif name == 'pgdn':
			self.selected = min(max(count - 1, 0), self.selected + PICKER_ROWS)
		elif name == 'tab':
			other = 'history' if self.tab == 'slot' else 'slot'
			if self.items[other]:
				self.tab = other
				self.selected = self.offset = 0
		elif name == 'backspace':
			self.query = self.query[:-1]
			self.selected = self.offset = 0
		elif len(name) == 1 and name >= ' ':
			self.query += name
			self.selected = self.offset = 0
		return None

	def chosen(self):
		matches = self.matches()
		return matches[self.selected] if 0 <= self.selected < len(matches) else None

	def render(self, width, rows):
		'''
		The menu's lines: a title, rows candidate rows (blank when fewer match), a status line;
		each at most width columns. The selected row is in reverse video.
		'''
		matches = self.matches()
		if self.selected < self.offset:
			self.offset = self.selected
		if self.selected >= self.offset + rows:
			self.offset = self.selected - rows + 1
		horizontal, vertical, top_left, top_right, bottom_left, bottom_right = (
			('─', '│', '┌', '┐', '└', '┘') if self.unicode else ('-', '|', '+', '+', '+', '+'))
		inner = max(width - 3, 10)
		# what is drawn shows control characters as ?: option help holds config defaults, titles hosts from the line
		title = ' {} '.format(_printable(self.titles[self.tab] + (' · ' + self.query if self.query and self.unicode else (' : ' + self.query if self.query else ''))))
		counter = ' {}/{} '.format(self.selected + 1 if matches else 0, len(matches))
		fill = max(inner - text_width(title) - text_width(counter), 0)
		lines = [fit(top_left + title + horizontal * fill + counter + top_right, width)]
		for number in range(self.offset, self.offset + rows):
			if number >= len(matches):
				lines.append(vertical + ' ' * (inner) + vertical)
				continue
			item = matches[number]
			used = []
			if item.uses:
				used.append('used {}x'.format(item.uses))
			if item.last:
				age = _age(max(self.now - item.last, 0))
				used.append(age if age == 'now' else age + ' ago')
			right = '  '.join(([_printable(item.description)] if item.description else []) + ([(' · ' if self.unicode else ', ').join(used)] if used else []))
			marker = '> ' if number == self.selected else '  '
			left = fit(marker + _printable(item.text), max(inner - text_width(right) - 1, 8))
			middle = left + ' ' * max(inner - text_width(left) - text_width(right), 1) + right
			middle = fit(middle, inner)
			middle += ' ' * (inner - text_width(middle))
			if number == self.selected:
				middle = '\x1b[7m' + middle + '\x1b[27m'
			lines.append(vertical + middle + vertical)
		other = 'history' if self.tab == 'slot' else _printable(self.titles['slot'])
		status = ' type to filter · Tab: {} · Esc '.format(other) if self.unicode else ' type to filter - Tab: {} - Esc '.format(other)
		if not self.items['history' if self.tab == 'slot' else 'slot']:
			status = status.replace(' · Tab: {}'.format(other), '').replace(' - Tab: {}'.format(other), '')
		lines.append(fit(bottom_left + status + horizontal * max(inner - text_width(status), 0) + bottom_right, width))
		return lines

	def run(self, term, line=None, before=None):
		'''
		Show the menu below the line and read keys until a choice or a cancel.

		Args:
			term (Terminal): In raw mode (line feeds keep the column)
			line (str): The line to draw first when the shell cleared it (bash): the prompt's last line
				and the whole command line; the menu opens below all of it and the cursor ends at its
				start, where bash redraws it. None: the line is on screen, the menu opens below the
				cursor's row and the cursor ends where it was.
			before (str): With line: its part before the cursor

		Returns:
			str: 'choose', 'cancel', or 'unavailable' when the terminal is too small
		'''
		rows, width = term.size()
		height = min(PICKER_ROWS, rows - 4)
		if height < 1 or width < 20:
			return 'unavailable'
		up = 0
		cursor = ''
		if line is not None:
			end_row, end_column = text_layout(line, width)
			row, column = text_layout(before, width)
			if column >= width:
				row, column = row + 1, 0
			out = '\r' + line + '\x1b[J'
			if end_column >= width:
				# the terminal waits to wrap until the next character: wrap now so moves are exact
				out += '\r\n'
				end_row += 1
			term.write(out)
			up = end_row
			# while the menu is open the cursor shows where it is in the line
			cursor = ('\x1b[{}A'.format(end_row - row) if end_row > row else '') + '\r' + ('\x1b[{}C'.format(column) if column else '')
		# make room below the line (the screen may scroll), come back to the same column and save it
		lines = height + 2
		term.write('\n' * lines + '\x1b[{}A\x1b7'.format(lines))
		try:
			draw = True
			while True:
				if draw:
					menu = self.render(width - 1, height)
					term.write(''.join('\r\n' + text + '\x1b[K' for text in menu) + '\x1b8' + cursor)
				outcome = self.handle(term.read_key()[0])
				if outcome:
					return outcome
				# keys already typed are handled before the menu is drawn again
				draw = not term.has_input()
		finally:
			term.write('\x1b8\r\n\x1b[J\x1b8' + ('\x1b[{}A'.format(up) if up else '') + ('\r' if line is not None else ''))

def _sets_password(words, spec):
	'''Whether mssh words (options, hosts, commands; no program name) give a password option.'''
	return any(option is not None and option.dest in PASSWORD_DESTS for _, option in assign_roles(words, spec))

def picker_items(request, engine, history_lines, now=None):
	'''
	What the picker offers for a request.

	Returns:
		tuple: (slot items, slot title, history items, word): word is the text before the cursor the
			slot items replace (None when nothing can be framed: the slot tab is empty)
	'''
	now = time.time() if now is None else now
	context = parse_context(request.before, request.after, engine.spec)
	slot = []
	title = ''
	word = None
	if context is not None and request.before.endswith(context.prefix):
		word = context.prefix
		asked = word
		if request.shell in ('zsh', 'fish'):
			# their glues send the word as typed, quotes included: so does the picker
			tokens = lex(request.before)
			if tokens and tokens[-1].text == word and request.before.endswith(tokens[-1].raw):
				asked = tokens[-1].raw
		response = engine.query(Request(request.shell, request.before, request.after, asked, request.shell_version, dict(request.flags, insert='1')))
		for candidate in response.candidates:
			value = (candidate.raw or candidate.text)[context.value_start:]
			uses, last = engine.usage(context, value)
			slot.append(PickItem(candidate.text, candidate.description, uses, last))
		title = {SLOT_HOSTS: 'hosts', SLOT_OPTION: 'options'}.get(context.slot, '')
		if context.slot == SLOT_VALUE:
			title = context.option.long
		elif context.slot == SLOT_COMMAND:
			title = 'commands for ' + context.hosts if context.hosts else 'commands'
	name = 'mssh'
	tokens = lex(request.before)
	if tokens and os.path.basename(tokens[0].text) in MSSH_NAMES:
		name = tokens[0].raw
	features = set(context.features) if context is not None else set()
	seen = {}
	entries = []
	for line in reversed(history_lines):
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		parts = [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']
		text = ' '.join([name] + parts)
		if not safe_field(text) or _has_control(text) or _sets_password(lex(fields[2]), engine.spec):
			continue
		if text in seen:
			seen[text][1] += 1
			continue
		if len(entries) >= HISTORY_LIMIT:
			continue
		entry = parse_history_line(line, engine.spec)
		overlap = len(features & set(entry.features())) if entry is not None else 0
		ts = entry.ts if entry is not None else 0
		seen[text] = [len(entries), 1]
		entries.append([overlap, ts, text])
	shell_lines = request.history[::-1] if request.shell != 'fish' else request.history
	for line in shell_lines:
		line = line.strip()
		tokens = lex(line)
		if tokens and os.path.basename(tokens[0].text) in MSSH_NAMES and line not in seen and len(entries) < HISTORY_LIMIT and not _has_control(line) and not _sets_password(tokens[1:], engine.spec):
			seen[line] = [len(entries), 1]
			entries.append([len(features & set(line_features(tokens[1:], engine.spec))), 0, line])
	order = sorted(range(len(entries)), key=lambda number: (-entries[number][0], -entries[number][1], number))
	history = [PickItem(entries[number][2], '', seen[entries[number][2]][1], entries[number][1]) for number in order]
	return slot, title, history, word

def apply_pick(request, picker, word, context):
	'''The new line and cursor after a choice: (line, cursor).'''
	item = picker.chosen()
	if picker.tab == 'history':
		return item.text, len(item.text)
	suffix = ' '
	if context is not None and context.open_quote:
		suffix = ('"' if context.open_quote == '"' else "'") + ' '
	elif item.text.endswith('/'):
		suffix = ''
	before = request.before[:len(request.before) - len(word)] + item.text + suffix
	return before + request.after, len(before)

#%% ------------ Line editor ----------------
def _first_word(text):
	'''
	Leading spaces, then the first word of text: a backslash and the character it escapes, and a
	quote and what follows up to the next one of its kind (or the end), kept together. Inside a
	quoted command the closing quote comes last, so its words are still taken one at a time.
	'''
	position = len(text) - len(text.lstrip(' '))
	quote = ''
	while position < len(text):
		char = text[position]
		if char == '\\' and quote != "'":
			position += 2
			continue
		if quote:
			if char == quote:
				quote = ''
		elif char in '"\'':
			quote = char
		elif char == ' ':
			break
		position += 1
	return text[:position]

def _completed_word_end(before):
	'''What follows a word completed at the end of before: its closing quote and a space, nothing after a directory.'''
	tokens = lex(before)
	open_quote = tokens[-1].open_quote if tokens else ''
	if open_quote:
		return ('"' if open_quote == '"' else "'") + ' '
	return '' if before.endswith('/') else ' '

_PROMPT_ESCAPES = None

def expand_prompt(ps1, environ=None, now=None):
	'''
	PS1 expanded the way bash does for its common escapes (\\u \\h \\H \\w \\W \\$ \\[ \\] \\e \\033 \\n
	\\t \\d \\@ \\A \\T \\j \\s \\v \\V \\!), for bash 4.2 / 4.3 where ${PS1@P} does not exist.
	$(...) and variables stay as they are.
	'''
	import socket
	environ = os.environ if environ is None else environ
	now = time.localtime(time.time() if now is None else now)
	home = environ.get('HOME', '')
	cwd = environ.get('PWD') or os.getcwd()
	short = '~' + cwd[len(home):] if home and (cwd == home or cwd.startswith(home + '/')) else cwd
	host = socket.gethostname()
	user = environ.get('USER') or environ.get('LOGNAME') or ''
	if not user:
		import getpass
		try:
			user = getpass.getuser()
		except Exception:
			user = ''
	version = environ.get('BASH_VERSION', '')
	values = {
		'u': user, 'h': host.split('.')[0], 'H': host, 'w': short, 'W': os.path.basename(short) if short not in ('/', '~') else short,
		'$': '#' if hasattr(os, 'geteuid') and os.geteuid() == 0 else '$', '[': '\x01', ']': '\x02', 'e': '\x1b', 'n': '\n',
		't': time.strftime('%H:%M:%S', now), 'T': time.strftime('%I:%M:%S', now), '@': time.strftime('%I:%M %p', now),
		'A': time.strftime('%H:%M', now), 'd': time.strftime('%a %b %d', now), 'j': '0', 's': 'bash',
		'v': '.'.join(version.split('.')[:2]), 'V': version.split('(')[0], '!': '!', '\\': '\\', 'a': '\a',
	}
	out = []
	index = 0
	while index < len(ps1):
		char = ps1[index]
		if char == '\\' and index + 1 < len(ps1):
			name = ps1[index + 1]
			digits = ps1[index + 1:index + 4]
			if len(digits) == 3 and all(digit in '01234567' for digit in digits):
				out.append(chr(int(digits, 8)))
				index += 4
				continue
			if name in values:
				out.append(values[name])
				index += 2
				continue
		out.append(char)
		index += 1
	return ''.join(out)

def readline_keyseq(raw):
	'''raw key bytes written in readline's key sequence notation (for a bind macro).'''
	out = []
	for byte in bytearray(raw):
		if byte == 0x1b:
			out.append('\\e')
		elif byte == 0x5c:
			out.append('\\\\')
		elif byte == 0x22:
			out.append('\\"')
		elif byte == 0x7f:
			out.append('\\C-?')
		elif byte < 32:
			out.append('\\C-' + chr(byte + 96))
		elif byte < 127:
			out.append(chr(byte))
		else:
			out.append('\\{:03o}'.format(byte))
	return ''.join(out)

class LineEditor(object):
	'''
	The plain-bash editor for an mssh line, as state: text, cursor and the grey suggestion.

	The editor owns the text after its prefix (the line it started with, "mssh "). handle() returns
	None to keep editing or the bytes readline must replay when the editor hands the line back
	(the key that ended it; keys typed after it stay in the terminal for readline), or the action
	'abandon'.

	suggest(before) -> Ghost or None; complete(before) -> (candidate texts, word) where the texts
	replace word at the end of before; pick(text, cursor, slot_only) -> (text, cursor) or None.
	'''
	def __init__(self, text, suggest=None, complete=None, pick=None):
		self.text = text
		self.cursor = len(text)
		self.prefix = len(text)
		self.suggest = suggest
		self.complete = complete
		self.pick = pick
		self.ghost = ''
		self._ghost_for = None
		# more typed keys are waiting (set by run): no suggestion is asked for until they are handled
		self.busy = False

	def refresh(self):
		'''Keep the suggestion in step with the text: ask again unless typing followed it.'''
		if self.cursor != len(self.text) or self.suggest is None:
			self.ghost = ''
			self._ghost_for = None
			return
		if self._ghost_for == self.text:
			return
		if self.busy:
			# no stale suggestion meanwhile; the next refresh asks
			self.ghost = ''
			return
		ghost = None
		try:
			ghost = self.suggest(self.text)
		except Exception as e:
			_debug('suggestion failed: {!r}'.format(e))
		self.ghost = ghost.text if ghost is not None else ''
		self._ghost_for = self.text

	def _insert(self, text):
		at_end = self.cursor == len(self.text)
		self.text = self.text[:self.cursor] + text + self.text[self.cursor:]
		self.cursor += len(text)
		if at_end and self.ghost.startswith(text):
			# typing along the suggestion keeps the rest of it
			self.ghost = self.ghost[len(text):]
			self._ghost_for = self.text

	def _accept(self, whole):
		if self._ghost_for != self.text:
			# typed in a burst: ask now, the operator wants the suggestion
			busy, self.busy = self.busy, False
			self.refresh()
			self.busy = busy
		if not self.ghost:
			return False
		if whole:
			taken = self.ghost
		else:
			taken = _first_word(self.ghost)
		self._insert(taken)
		return True

	def _word_left(self):
		position = self.cursor
		while position > self.prefix and self.text[position - 1] == ' ':
			position -= 1
		while position > self.prefix and self.text[position - 1] != ' ':
			position -= 1
		return position

	def _word_right(self):
		position = self.cursor
		while position < len(self.text) and self.text[position] == ' ':
			position += 1
		while position < len(self.text) and self.text[position] != ' ':
			position += 1
		return position

	def handle(self, name, raw):
		'''
		Apply one key.

		Returns:
			None to keep editing; ('pass', bytes) to hand the line back with bytes for readline to
			replay; ('abandon', b'') to drop the line
		'''
		at_end = self.cursor == len(self.text)
		if name == 'enter':
			return 'pass', raw
		if name == 'ctrl-c':
			return 'abandon', b''
		if len(name) == 1 and name >= ' ':
			self._insert(name)
		elif name == 'backspace':
			if self.cursor <= self.prefix:
				# deleting into the prefix: the line is readline's again
				if self.cursor > 0:
					self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
					self.cursor -= 1
				return 'pass', b''
			self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
			self.cursor -= 1
		elif name in ('delete', 'ctrl-d'):
			if self.cursor < len(self.text):
				self.text = self.text[:self.cursor] + self.text[self.cursor + 1:]
		elif name in ('left', 'ctrl-b'):
			if self.cursor <= self.prefix:
				return 'pass', raw
			self.cursor -= 1
		elif name in ('right', 'ctrl-f'):
			if not (at_end and self._accept(True)):
				self.cursor = min(len(self.text), self.cursor + 1)
		elif name in ('end', 'ctrl-e'):
			if not (at_end and self._accept(True)):
				self.cursor = len(self.text)
		elif name in ('home', 'ctrl-a'):
			self.cursor = self.prefix
		elif name in ('alt-right', 'ctrl-right', 'alt-f'):
			if not (at_end and self._accept(False)):
				self.cursor = self._word_right()
		elif name in ('alt-left', 'ctrl-left', 'alt-b'):
			self.cursor = self._word_left()
		elif name == 'ctrl-u':
			self.text = self.text[self.cursor:]
			self.cursor = 0
			return 'pass', b''
		elif name == 'ctrl-w':
			start = self._word_left()
			if start <= self.prefix and self.cursor == self.prefix:
				return 'pass', raw
			self.text = self.text[:start] + self.text[self.cursor:]
			self.cursor = start
		elif name == 'tab':
			self._tab()
		elif name == 'ctrl-r':
			self._pick(False)
		else:
			return 'pass', raw
		self.refresh()
		return None

	def _tab(self):
		if self.complete is None:
			return
		texts, word = self.complete(self.text[:self.cursor])
		if not texts:
			return
		common = _common_prefix(texts)
		if len(common) > len(word) and common.startswith(word):
			self._insert(common[len(word):])
			if len(set(texts)) == 1 and self.cursor == len(self.text):
				self._insert(_completed_word_end(self.text))
		else:
			self._pick(True)

	def _pick(self, slot_only):
		if self.pick is None:
			return
		result = self.pick(self.text, self.cursor, slot_only)
		if result is not None:
			self.text, self.cursor = result
			self._ghost_for = None

	def layout(self, prompt, width):
		'''
		Where things go on screen: (rows used, cursor row, cursor column, column after the last
		character), rows counted from the prompt's row, wrapped at width.
		'''
		row, column = text_layout(prompt, width)
		cursor_row, cursor_column = text_layout(self.text[:self.cursor], width, row, column)
		end_row, end_column = text_layout(self.text + self.ghost, width, row, column)
		return end_row + 1, cursor_row, cursor_column, end_column

	def draw(self, term, prompt, style):
		'''Draw the prompt's last line, the text and the grey suggestion; leave the cursor at the text's cursor.'''
		width = term.size()[1]
		rows, cursor_row, cursor_column, end_column = self.layout(prompt, width)
		ghost = (style + self.ghost + '\x1b[0m') if (style and self.ghost) else ''
		out = []
		if getattr(self, '_row', 0):
			out.append('\x1b[{}A'.format(self._row))
		out.append('\r' + prompt + self.text + ghost + '\x1b[J')
		end_row = rows - 1
		if end_column == width:
			# the terminal waits to wrap until the next character: wrap now so moves are exact
			out.append('\r\n')
			end_row += 1
		if end_row > cursor_row:
			out.append('\x1b[{}A'.format(end_row - cursor_row))
		out.append('\r')
		if cursor_column:
			out.append('\x1b[{}C'.format(cursor_column))
		term.write(''.join(out))
		self._row = cursor_row

	def erase(self, term):
		'''Erase what the editor drew; the cursor ends at the start of the prompt's row.'''
		term.write(('\x1b[{}A'.format(self._row) if getattr(self, '_row', 0) else '') + '\r\x1b[J')
		self._row = 0

	def run(self, term, prompt, style=None):
		'''
		Edit until the line is handed back.

		Returns:
			tuple: ('pass', the bytes of the key readline replays) or ('abandon', b''); keys typed after
				that key were not read: readline reads them next
		'''
		self._row = 0
		self.refresh()
		self.draw(term, prompt, style)
		while True:
			name, raw = term.read_key()
			self.busy = term.has_input()
			outcome = self.handle(name, raw)
			if outcome is not None:
				self.erase(term)
				return outcome
			if not self.busy:
				self.draw(term, prompt, style)

#%% ------------ Shell glue ----------------
GLUE_MARK = 'MSSH_COMPLETE_GLUE'

BASH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ bash: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion bash`. Sourcing it only defines functions and registers them.

_mssh_complete_slice() {
	# bash 4.2 counts COMP_POINT in bytes: cut the line in the C locale (restored on return)
	local LC_ALL=C
	_mssh_complete_before=${COMP_LINE:0:COMP_POINT}
	_mssh_complete_after=${COMP_LINE:COMP_POINT}
}

_mssh_complete_split() {
	# split $1 on tabs into _mssh_complete_fields, keeping empty fields
	local text=$1
	_mssh_complete_fields=()
	while [[ $text == *$'\t'* ]]; do
		_mssh_complete_fields+=("${text%%$'\t'*}")
		text=${text#*$'\t'}
	done
	_mssh_complete_fields+=("$text")
}

_mssh_complete_delegate() {
	# $1: the word bash replaces, $2: index of the current word, $3: text put in front of every
	# result, then the remote command words. The results land in _mssh_complete_delegated.
	local word=$1 cword=$2 prefix=$3 cmd spec func item lead
	# every process substitution below ends with "|| :": bash 4.4 exits a set -e shell after one that failed
	shift 3
	local -a words=("$@") found=()
	local cur=${words[cword]-}
	cmd=${words[0]-}
	_mssh_complete_delegated=()
	if [[ $cword -eq 0 ]]; then
		while IFS= read -r item; do
			found+=("$item")
		done < <(compgen -c -- "$cur" 2>/dev/null || :)
	else
		if ! complete -p -- "$cmd" >/dev/null 2>&1; then
			if declare -F _comp_load >/dev/null 2>&1; then
				_comp_load "$cmd" >/dev/null 2>&1 || :
			elif declare -F __load_completion >/dev/null 2>&1; then
				__load_completion "$cmd" >/dev/null 2>&1 || :
			elif declare -F _completion_loader >/dev/null 2>&1; then
				_completion_loader "$cmd" >/dev/null 2>&1 || :
			fi
		fi
		spec=$(complete -p -- "$cmd" 2>/dev/null) || spec=
		if [[ $spec =~ \ -F\ ([^ ]+) ]]; then
			func=${BASH_REMATCH[1]}
			local -a COMP_WORDS=("${words[@]}")
			local COMP_CWORD=$cword COMP_LINE="${words[*]}" COMP_POINT
			COMP_POINT=${#COMP_LINE}
			local -a COMPREPLY=()
			"$func" "$cmd" "$cur" "${words[cword-1]}" >/dev/null 2>&1 || :
			found=(${COMPREPLY[@]+"${COMPREPLY[@]}"})
		else
			while IFS= read -r item; do
				found+=("$item")
			done < <(compgen -f -- "$cur" 2>/dev/null || :)
		fi
	fi
	# the results continue prefix + current word, but bash replaces only its own word, which ends
	# the same and can be shorter (it stops at ":" and "="): drop what comes before that word
	lead=$prefix$cur
	lead=${lead%"$word"}
	for item in ${found[@]+"${found[@]}"}; do
		item=$prefix$item
		[[ -n $lead && $item == "$lead"* ]] && item=${item#"$lead"}
		[[ $item == "$word"* ]] && _mssh_complete_delegated+=("$item")
	done
	return 0
}

_mssh_complete() {
	local cur=$2 resp line item flags ble=0 files=0 dirs=0 ended=0 delegate=0
	local _mssh_complete_before _mssh_complete_after
	local -a reply=() raws=() delegate_fields=() _mssh_complete_fields=() _mssh_complete_delegated=()
	local -A seen=()
	if (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3 )); then
		_mssh_complete_slice
	else
		_mssh_complete_before=${COMP_LINE:0:COMP_POINT}
		_mssh_complete_after=${COMP_LINE:COMP_POINT}
	fi
	if [[ -z ${_mssh_complete_icase-} ]]; then
		_mssh_complete_icase=0
		[[ $(bind -v 2>/dev/null) == *'completion-ignore-case on'* ]] && _mssh_complete_icase=1
	fi
	[[ -n ${BLE_VERSION-} ]] && ble=1
	flags="nosort=0 icase=$_mssh_complete_icase ble=$ble term=${TERM-}"
	if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
		flags="nosort=1 ${flags#nosort=0 }"
	fi
	IFS= read -r -d '' -t "${MSSH_COMPLETE_TIMEOUT:-0.3}" resp < <(
		{
			printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$flags" "$_mssh_complete_before" "$_mssh_complete_after" "$cur"
			fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
		} | _mssh_complete_engine query 2>/dev/null || :
	) || return 0
	[[ $resp == MSSHC1$'\n'* ]] || return 0
	while IFS= read -r line; do
		case ${line:0:1} in
			D)
				for item in ${line:2}; do
					case $item in
						nospace|filenames|nosort) compopt -o "$item" 2>/dev/null || : ;;
						nodefault) compopt +o default +o bashdefault 2>/dev/null || : ;;
						files) files=1 ;;
						dirs) dirs=1 ;;
					esac
				done
				;;
			C)
				# text, description, group, and the unescaped text when escaping changed it
				_mssh_complete_split "${line:2}"
				reply+=("${_mssh_complete_fields[0]}")
				raws+=("${_mssh_complete_fields[3]-${_mssh_complete_fields[0]}}")
				;;
			X) _mssh_complete_split "${line:2}" ; delegate_fields=("${_mssh_complete_fields[@]}") ; delegate=1 ;;
			E) ended=1 ;;
		esac
	done <<< "$resp"
	(( ended )) || return 0
	if (( delegate )) && (( ${#delegate_fields[@]} >= 3 )); then
		_mssh_complete_delegate "$cur" "${delegate_fields[@]}"
		# a delegated completion that turned on file name quoting quotes ours too: hand them over unescaped
		if [[ $(compopt 2>/dev/null) == *' -o filenames '* ]]; then
			reply=(${raws[@]+"${raws[@]}"})
		fi
		reply+=(${_mssh_complete_delegated[@]+"${_mssh_complete_delegated[@]}"})
	fi
	if (( files || dirs )); then
		compopt -o filenames 2>/dev/null || :
		while IFS= read -r item; do
			reply+=("$item")
		done < <(if (( files )); then compgen -f -- "$cur"; else compgen -d -- "$cur"; fi 2>/dev/null || :)
	fi
	COMPREPLY=()
	for item in ${reply[@]+"${reply[@]}"}; do
		[[ -n ${seen[x$item]-} ]] && continue
		seen[x$item]=1
		COMPREPLY+=("$item")
	done
	return 0
}

complete -o default -o bashdefault -F _mssh_complete mssh mssh3 multissh multissh3 multiSSH3 2>/dev/null

# ---- grey suggestions, the Ctrl-R picker and the mssh line editor (SP2) ----

_mssh_complete_engine() {
	@ENGINE@ "$@"
}

_mssh_complete_is_mssh() {
	# whether $1 is an mssh command line: an mssh name, then a space
	[[ $1 =~ ^[[:space:]]*([^[:space:]]*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)[[:space:]] ]]
}

_mssh_complete_request() {
	# print a request with flags $1 for the line $2 (before the cursor) $3 (after it), then the history tail
	printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$1 term=${TERM-}" "$2" "$3" ''
	fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
}

_mssh_complete_prompt() {
	# the prompt the picker and the editor redraw (bash clears the line before a bind -x command):
	# expanded on bash 4.4 and later, else PS1 itself for the engine to expand
	if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
		_mssh_complete_ps1=${PS1@P}
		_mssh_complete_expand=0
	else
		_mssh_complete_ps1=$PS1
		_mssh_complete_expand=1
	fi
}

_mssh_complete_cut() {
	# READLINE_LINE before and after READLINE_POINT, which readline counts in bytes before bash 5
	(( _mssh_complete_bytes )) && local LC_ALL=C
	_mssh_complete_before=${READLINE_LINE:0:READLINE_POINT}
	_mssh_complete_after=${READLINE_LINE:READLINE_POINT}
}

_mssh_complete_set() {
	# READLINE_LINE=$1 with the cursor after its first $2 characters
	local head=${1:0:$2}
	READLINE_LINE=$1
	(( _mssh_complete_bytes )) && local LC_ALL=C
	READLINE_POINT=${#head}
}

_mssh_complete_apply() {
	# apply a pick or edit response ($1): the line, the cursor, and _mssh_complete_action / _keys
	local line text= cursor=
	_mssh_complete_action=
	_mssh_complete_keys=
	[[ $1 == MSSHC1$'\n'* && $1 == *$'\n'E ]] || return 1
	while IFS= read -r line; do
		case ${line:0:2} in
			'L ') cursor=${line:2}; cursor=${cursor%%$'\t'*}; text=${line#*$'\t'} ;;
			'K ') _mssh_complete_action=${line:2}; _mssh_complete_action=${_mssh_complete_action%%$'\t'*}; _mssh_complete_keys=${line#*$'\t'} ;;
		esac
	done <<< "$1"
	[[ $cursor =~ ^[0-9]+$ ]] || return 1
	_mssh_complete_set "$text" "$cursor"
}

_mssh_complete_pick() {
	# the picker for the mssh line in READLINE_LINE; fails when it is unavailable
	local _mssh_complete_before _mssh_complete_after _mssh_complete_ps1 _mssh_complete_expand resp status
	local _mssh_complete_action _mssh_complete_keys
	_mssh_complete_cut
	_mssh_complete_prompt
	resp=$(_mssh_complete_request "pick=1 redraw=1 expand=$_mssh_complete_expand" "$_mssh_complete_before" "$_mssh_complete_after" |
		MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine pick 2>/dev/null)
	status=$?
	(( status == 0 )) && _mssh_complete_apply "$resp"
	(( status <= 1 ))
}

_mssh_complete_ctrl_r() {
	# Ctrl-R (a macro: the hook key of keymap $1, then "\C-x\C-y"): the picker on mssh lines, else
	# what Ctrl-R did before
	local keymap=$1 previous
	bind -m "$keymap" '"\C-x\C-y": ""'
	_mssh_complete_is_mssh "$READLINE_LINE" && _mssh_complete_pick && return 0
	previous=_mssh_complete_previous_${keymap//-/_}
	previous=${!previous-}
	case $previous in
		x:*) eval "${previous#x:}" ;;
		?*)
			# put the previous binding back while it runs (a reverse search repeats with Ctrl-R
			# only when Ctrl-R is bound to it); the next prompt takes Ctrl-R back
			bind -m "$keymap" "$previous"
			bind -m "$keymap" '"\C-x\C-y": "\C-r"'
			_mssh_complete_unarmed="${_mssh_complete_unarmed-} $keymap"
			[[ ${PROMPT_COMMAND-} == *_mssh_complete_rearm\;* ]] || PROMPT_COMMAND="_mssh_complete_rearm;${PROMPT_COMMAND-}"
			;;
	esac
	return 0
}

_mssh_complete_rearm() {
	# PROMPT_COMMAND, once after a Ctrl-R fallback: Ctrl-R opens the picker again
	local status=$? keymap
	for keymap in ${_mssh_complete_unarmed-}; do
		_mssh_complete_arm "$keymap"
	done
	_mssh_complete_unarmed=
	PROMPT_COMMAND=${PROMPT_COMMAND//_mssh_complete_rearm;/}
	return $status
}

_mssh_complete_arm() {
	# bind Ctrl-R in readline keymap $1 to its hook key, then "\C-x\C-y"; each keymap has its own
	# hook key: before bash 5.1 one table holds the bind -x commands of all keymaps
	if [[ $1 == emacs ]]; then
		bind -m emacs '"\C-r": "\C-x\C-o\C-x\C-y"' 2>/dev/null
	else
		bind -m vi-insert '"\C-r": "\C-x\C-q\C-x\C-y"' 2>/dev/null
	fi
}

_mssh_complete_previous() {
	# the Ctrl-R binding of readline keymap $1, as a bind argument or x:<shell command> (bind -x),
	# into _mssh_complete_found; fails when it is unbound or cannot be told (bind -x before bash 4.3)
	local line
	_mssh_complete_found=
	while IFS= read -r line; do
		[[ $line == '"\C-r": "'*'"' ]] || continue
		line=${line#'"\C-r": "'}
		line=${line%'"'}
		line=${line//'\"'/'"'}
		_mssh_complete_found=x:${line//'\\'/'\'}
		return 0
	done < <(bind -m "$1" -X 2>/dev/null || :)
	while IFS= read -r line; do
		if [[ $line == '"\C-r": '* ]]; then
			_mssh_complete_found=$line
			return 0
		fi
	done < <(bind -m "$1" -s 2>/dev/null; bind -m "$1" -p 2>/dev/null || :)
	return 1
}

_mssh_complete_space() {
	# space ("\C-x\C-t\C-x\C-y"): after an mssh name alone, the mssh line editor; else a space
	local resp _mssh_complete_ps1 _mssh_complete_expand _mssh_complete_action _mssh_complete_keys
	local _mssh_complete_before _mssh_complete_after
	local -a expand=()
	bind -m emacs '"\C-x\C-y": ""'
	case $READLINE_LINE in
		mssh|mssh3|multissh|multissh3|multiSSH3)
			if (( READLINE_POINT == ${#READLINE_LINE} )); then
				_mssh_complete_prompt
				(( _mssh_complete_expand )) && expand=(--expand)
				resp=$(fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null |
					MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine edit ${expand[@]+"${expand[@]}"} -- "$READLINE_LINE " 2>/dev/null)
				if _mssh_complete_apply "$resp"; then
					case $_mssh_complete_action in
						abandon) READLINE_LINE= READLINE_POINT=0; bind -m emacs '"\C-x\C-y": accept-line' ;;
						pass) bind -m emacs "\"\\C-x\\C-y\": \"$_mssh_complete_keys\"" ;;
					esac
					return 0
				fi
			fi
			;;
	esac
	if [[ $_mssh_complete_space_previous == magic-space ]]; then
		bind -m emacs '"\C-x\C-y": magic-space'
		return 0
	fi
	_mssh_complete_cut
	READLINE_LINE="$_mssh_complete_before $_mssh_complete_after"
	(( READLINE_POINT += 1 ))
}

if [[ -n ${BLE_VERSION-} ]]; then
	_mssh_complete_bytes=0

	_mssh_complete_ble_call() {
		# run a binding the way ble-bind -P printed it: -m KEYMAP -f|-x|-c KEY COMMAND
		case $3 in
			-f) builtin eval -- "ble/widget/$5" ;;
			-x) ble/widget/.EDIT_COMMAND "$5" ;;
			-c) ble/widget/.SHELL_COMMAND "$5" ;;
		esac
	}

	function ble/widget/mssh-complete/ctrl-r {
		# Ctrl-R: the picker on mssh lines, else the widget Ctrl-R had
		if _mssh_complete_is_mssh "$_ble_edit_str" && ble/widget/.EDIT_COMMAND _mssh_complete_pick; then
			return 0
		fi
		local previous=_mssh_complete_previous_$_ble_decode_keymap
		[[ -n ${!previous-} ]] && builtin eval -- "_mssh_complete_ble_call ${!previous}"
		return 0
	}

	_mssh_complete_ble_bind() {
		# take Ctrl-R in ble.sh keymap $1 when its binding is a widget or a command
		local line
		while IFS= read -r line; do
			case $line in
				*' -f C-r '*|*' -x C-r '*|*' -c C-r '*)
					[[ $line == *mssh-complete/ctrl-r* ]] && return 0
					printf -v "_mssh_complete_previous_$1" '%s' "${line#ble-bind }"
					ble-bind -m "$1" -f C-r mssh-complete/ctrl-r
					return 0
					;;
			esac
		done < <(ble-bind -m "$1" -P 2>/dev/null || :)
	}
	blehook/eval-after-load keymap_emacs '_mssh_complete_ble_bind emacs'
	blehook/eval-after-load keymap_vi '_mssh_complete_ble_bind vi_imap'

	_mssh_complete_ble_source() {
		# define ble.sh's mssh suggestion source and put it first
		declare -F ble/complete/auto-complete/enter >/dev/null 2>&1 || return 0
		function ble/complete/auto-complete/source:mssh {
			# grey text for mssh lines: 1 lets the next source try, 148 when typing interrupted the query
			((_ble_edit_ind == ${#_ble_edit_str})) || return 1
			_mssh_complete_is_mssh "$_ble_edit_str" || return 1
			local request=$_ble_base_run/$$.mssh-complete.request answer=$_ble_base_run/$$.mssh-complete.answer line text= status
			_mssh_complete_request 'ghost=1 ble=1 nul=0' "$_ble_edit_str" '' > "$request" 2>/dev/null || return 1
			ble/util/conditional-sync '_mssh_complete_engine query < "$request" > "$answer" 2>/dev/null' '! ble/decode/has-input' 20 "timeout=${MSSH_COMPLETE_GHOST_TIMEOUT:-300}"
			status=$?
			((status == 148)) && return 148
			((status == 0)) || return 1
			while IFS= read -r line; do
				[[ $line == 'G '* ]] && text=${line#*$'\t'}
			done < "$answer"
			[[ -n $text ]] || return 1
			ble/complete/auto-complete/enter h 0 "$text" '' "$_ble_edit_str$text"
		}
		[[ " ${_ble_complete_auto_source[*]-} " == *' mssh '* ]] || _ble_complete_auto_source=(mssh ${_ble_complete_auto_source[@]+"${_ble_complete_auto_source[@]}"})
	}
	blehook/eval-after-load complete _mssh_complete_ble_source
elif [[ $- == *i* ]]; then
	# readline counts READLINE_POINT in bytes before bash 5
	_mssh_complete_bytes=0
	(( BASH_VERSINFO[0] < 5 )) && _mssh_complete_bytes=1

	_mssh_complete_keys() {
		# PROMPT_COMMAND, once, at the first prompt: take the keys. Not while the rc file loads: there
		# stderr is often /dev/null, and readline starting then would lose its terminal setup
		local status=$? keymap previous
		PROMPT_COMMAND=${PROMPT_COMMAND//_mssh_complete_keys;/}
		[[ -o emacs || -o vi ]] || return $status
		for keymap in emacs vi-insert; do
			# take Ctrl-R only when its binding can be called back (and is not already ours)
			if _mssh_complete_previous "$keymap" && [[ $_mssh_complete_found != *'\C-x\C-y"' ]]; then
				printf -v "_mssh_complete_previous_${keymap//-/_}" '%s' "$_mssh_complete_found"
				# "$_" last: bash sets $_ to a command's last argument, so it keeps the operator's $_
				if [[ $keymap == emacs ]]; then
					bind -m emacs -x '"\C-x\C-o": _mssh_complete_ctrl_r emacs "$_"'
				else
					bind -m vi-insert -x '"\C-x\C-q": _mssh_complete_ctrl_r vi-insert "$_"'
				fi
				_mssh_complete_arm "$keymap"
			fi
		done
		# the mssh line editor, entered with a space after an mssh name; only over a plain space key and
		# from bash 4.4 on (bash 4.2 redraws a wrapped line wrongly after every bind -x command)
		if [[ ${MSSH_COMPLETE_EDITOR-} == 1 ]] && (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
			previous=$(bind -m emacs -p 2>/dev/null | grep -F '" ": ' || :)
			_mssh_complete_space_previous=${previous#'" ": '}
			case $_mssh_complete_space_previous in
				self-insert|magic-space)
					bind -m emacs -x '"\C-x\C-t": _mssh_complete_space "$_"'
					bind -m emacs '" ": "\C-x\C-t\C-x\C-y"'
					;;
			esac
		fi
		return $status
	}
	[[ ${PROMPT_COMMAND-} == *_mssh_complete_keys\;* ]] || PROMPT_COMMAND="_mssh_complete_keys;${PROMPT_COMMAND-}"
fi
'''

ZSH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ zsh: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion zsh`. Sourcing it only defines a function and registers it.

_mssh() {
	emulate -L zsh
	zmodload zsh/zselect zsh/system zsh/datetime 2>/dev/null || return 1
	local before after flags resp chunk line item fd kind rest
	local -F end
	local -i remaining files=0 delegate=0 dcword start
	local -a fields texts shown dwords
	before="${(j: :)words[1,CURRENT-1]} ${compstate[quote]}$PREFIX"
	after="$SUFFIX ${(j: :)words[CURRENT+1,-1]}"
	flags="nosort=1 icase=0 zas=$(( ${+functions[_zsh_autosuggest_start]} )) term=$TERM"
	exec {fd}< <(
		{
			print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$flags"$'\0'"$before"$'\0'"$after"$'\0'"$PREFIX"$'\0'
			fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
		} | _mssh_complete_engine query 2>/dev/null
	)
	(( end = EPOCHREALTIME + ${MSSH_COMPLETE_TIMEOUT:-0.3} ))
	resp=
	while true; do
		(( remaining = (end - EPOCHREALTIME) * 100 ))
		(( remaining > 0 )) || break
		zselect -t $remaining -r $fd || break
		sysread -i $fd chunk || break
		resp+=$chunk
		[[ $resp == *$'\0' ]] && break
	done
	exec {fd}<&-
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n'$'\0' ]] || return 1
	for line in "${(@f)${resp%$'\0'}}"; do
		kind=${line[1]}
		rest=${line[3,-1]}
		case $kind in
			(D) for item in ${=rest}; do [[ $item == (files|dirs) ]] && files=1; done ;;
			(C)
				fields=("${(@ps:\t:)rest}")
				texts+=("$fields[1]")
				if [[ -n $fields[2] ]]; then shown+=("$fields[1]  -- $fields[2]"); else shown+=("$fields[1]"); fi
				;;
			(X) fields=("${(@ps:\t:)rest}"); delegate=1; dcword=$fields[1]; dwords=("${(@)fields[3,-1]}") ;;
		esac
	done
	(( ${#texts} )) && compadd -V mssh -l -d shown -- "${texts[@]}"
	(( files )) && _files
	if (( delegate )); then
		[[ -n $compstate[quote] ]] && compset -q
		(( start = CURRENT - dcword ))
		if (( start >= 1 )); then
			words=("${(@)words[start,-1]}")
			(( CURRENT = CURRENT - start + 1 ))
			_normal
		fi
	fi
	return 0
}

(( $+functions[compdef] )) && compdef _mssh mssh mssh3 multissh multissh3 multiSSH3

# ---- grey suggestions and the Ctrl-R picker (SP2) ----

_mssh_complete_engine() {
	@ENGINE@ "$@"
}

_mssh_complete_is_mssh() {
	# whether $1 is an mssh command line: an mssh name, then a space
	emulate -L zsh
	local MATCH MBEGIN MEND
	local -a match mbegin mend
	[[ $1 =~ '^[[:space:]]*([^[:space:]]*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)[[:space:]]' ]]
}

_mssh_complete_request() {
	# print a request with flags $1 for the line $2 (before the cursor) $3 (after it), then the history tail
	print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$1 term=$TERM"$'\0'"$2"$'\0'"$3"$'\0'$'\0'
	fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
}

_mssh_complete_ctrl_r() {
	# Ctrl-R: the picker on mssh lines, else the widget Ctrl-R had
	emulate -L zsh
	local resp line text= cursor= st
	if _mssh_complete_is_mssh "$BUFFER"; then
		resp=$(_mssh_complete_request 'pick=1 nul=0' "$LBUFFER" "$RBUFFER" | _mssh_complete_engine pick 2>/dev/null)
		st=$?
		if (( st == 0 )) && [[ $resp == MSSHC1$'\n'*$'\n'E ]]; then
			for line in "${(@f)resp}"; do
				if [[ $line == 'L '* ]]; then
					cursor=${${line#L }%%$'\t'*}
					text=${line#*$'\t'}
				fi
			done
			if [[ $cursor == <-> ]]; then
				BUFFER=$text
				CURSOR=$cursor
			fi
		fi
		zle reset-prompt
		(( st <= 1 )) && return 0
	fi
	[[ -n $_mssh_complete_previous ]] && zle $_mssh_complete_previous
	return 0
}

_mssh_complete_take_ctrl_r() {
	# bind Ctrl-R to the picker, keeping the widget it had for other lines
	emulate -L zsh
	local -a binding
	binding=(${(z)"$(bindkey '^R')"})
	[[ $binding[2] == _mssh_complete_ctrl_r ]] && return 0
	[[ -n $binding[2] && $binding[2] != undefined-key ]] || return 0
	typeset -g _mssh_complete_previous=$binding[2]
	zle -N _mssh_complete_ctrl_r
	bindkey '^R' _mssh_complete_ctrl_r
	# an incremental search repeats on Ctrl-R only when Ctrl-R is bound to it
	if [[ $_mssh_complete_previous == history-incremental-*search-backward ]] && [[ $(bindkey -M isearch '^R' 2>/dev/null) != *search* ]]; then
		bindkey -M isearch '^R' $_mssh_complete_previous 2>/dev/null
	fi
}

_zsh_autosuggest_strategy_mssh() {
	# zsh-autosuggestions strategy: the engine's grey text for mssh lines, nothing for others
	emulate -L zsh
	zmodload zsh/zselect zsh/system zsh/datetime 2>/dev/null || return 0
	_mssh_complete_is_mssh "$1" || return 0
	local fd resp= chunk line limit=${MSSH_COMPLETE_TIMEOUT:-0.3}
	local -F end
	local -i remaining
	# synchronous zsh-autosuggestions waits for the strategy while the operator types
	(( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || limit=0.05
	exec {fd}< <(_mssh_complete_request 'ghost=1 zas=1 nul=0' "$1" '' | _mssh_complete_engine query 2>/dev/null)
	(( end = EPOCHREALTIME + limit ))
	while true; do
		(( remaining = (end - EPOCHREALTIME) * 100 ))
		(( remaining > 0 )) || break
		zselect -t $remaining -r $fd || break
		sysread -i $fd chunk || break
		resp+=$chunk
	done
	exec {fd}<&-
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		[[ $line == 'G '* ]] && typeset -g suggestion="$1${line#*$'\t'}"
	done
	return 0
}

_mssh_complete_ghost_clear() {
	# drop the grey text (inside a widget)
	[[ -n $_mssh_complete_shown ]] || return 0
	POSTDISPLAY=
	region_highlight=("${(@)region_highlight:#$_mssh_complete_highlight}")
	_mssh_complete_shown=
	_mssh_complete_highlight=
}

_mssh_complete_ghost_show() {
	# show $1 as grey text after the buffer (inside a widget)
	_mssh_complete_ghost_clear
	[[ -n $1 ]] || return 0
	POSTDISPLAY=$1
	_mssh_complete_shown=$1
	_mssh_complete_highlight="$#BUFFER $(( $#BUFFER + $#POSTDISPLAY )) $_mssh_complete_style"
	region_highlight+=("$_mssh_complete_highlight")
}

_mssh_complete_ghost_cancel() {
	# forget the pending query
	[[ -n $_mssh_complete_fd ]] || return 0
	zle -F $_mssh_complete_fd 2>/dev/null
	exec {_mssh_complete_fd}<&- 2>/dev/null
	_mssh_complete_fd=
}

_mssh_complete_ghost_ready() {
	# zle -F handler: the engine answered the query for the buffer in _mssh_complete_asked
	emulate -L zsh
	local fd=$1 resp= chunk line text=
	while sysread -i $fd chunk 2>/dev/null; do
		resp+=$chunk
	done
	zle -F $fd
	exec {fd}<&-
	_mssh_complete_fd=
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		[[ $line == 'G '* ]] && text=${line#*$'\t'}
	done
	[[ -n $text ]] && zle _mssh_complete_ghost_answer -- "$text"
	return 0
}

_mssh_complete_ghost_answer() {
	# widget: show the answer if the buffer is still the one asked about
	emulate -L zsh
	[[ $BUFFER == "$_mssh_complete_asked" ]] && (( CURSOR == $#BUFFER )) || return 0
	_mssh_complete_ghost_show "$1"
	zle -R
}

_mssh_complete_ghost_redraw() {
	# line-pre-redraw hook: keep the grey text in step with the buffer
	emulate -L zsh
	local last=$_mssh_complete_last full
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		# zsh-autosuggestions loaded after the first prompt (zinit turbo, zsh-defer): mssh becomes
		# its first strategy, and once it has wrapped the widgets its grey text replaces ours
		_mssh_complete_zas_strategy
		if [[ $widgets[forward-char] != user:_mssh_complete_accept ]]; then
			_mssh_complete_ghost_handover
			return 0
		fi
	fi
	if [[ $BUFFER == "$last" ]]; then
		(( CURSOR == $#BUFFER )) || _mssh_complete_ghost_clear
		return 0
	fi
	_mssh_complete_last=$BUFFER
	if [[ -n $_mssh_complete_shown ]] && (( CURSOR == $#BUFFER )); then
		full=$last$_mssh_complete_shown
		if [[ $BUFFER == "$last"?* && $full == "$BUFFER"?* ]]; then
			# typed (or took) the next characters of the grey text: show the rest without a new query
			_mssh_complete_ghost_show "${full#"$BUFFER"}"
			return 0
		fi
	fi
	_mssh_complete_ghost_clear
	_mssh_complete_ghost_cancel
	(( CURSOR == $#BUFFER )) && _mssh_complete_is_mssh "$BUFFER" || return 0
	_mssh_complete_asked=$BUFFER
	exec {_mssh_complete_fd}< <(_mssh_complete_request 'ghost=1 nul=0' "$BUFFER" '' | _mssh_complete_engine query 2>/dev/null)
	zle -F $_mssh_complete_fd _mssh_complete_ghost_ready
}

_mssh_complete_ghost_handover() {
	# stop drawing grey text: drop ours (not what zsh-autosuggestions shows) and the hooks
	add-zle-hook-widget -d line-pre-redraw _mssh_complete_ghost_redraw
	add-zle-hook-widget -d line-finish _mssh_complete_ghost_finish
	_mssh_complete_ghost_cancel
	[[ -n $_mssh_complete_shown && $POSTDISPLAY == "$_mssh_complete_shown" ]] && POSTDISPLAY=
	region_highlight=("${(@)region_highlight:#$_mssh_complete_highlight}")
	_mssh_complete_shown= _mssh_complete_highlight= _mssh_complete_last=
}

_mssh_complete_ghost_finish() {
	# line-finish hook: no grey text on a line that was accepted
	emulate -L zsh
	_mssh_complete_ghost_cancel
	_mssh_complete_ghost_clear
	_mssh_complete_last=
}

_mssh_complete_accept() {
	# forward-char, end-of-line, forward-word and their vi forms: with grey text showing at the
	# end of the line, take all of it (one word for the word widgets); else do the usual
	emulate -L zsh
	setopt extended_glob
	local take
	local -a words
	if [[ -n $_mssh_complete_shown ]] && (( CURSOR == $#BUFFER )); then
		take=$_mssh_complete_shown
		if [[ $WIDGET == *forward-word ]]; then
			# the first shell word, escapes and quotes kept with it
			words=(${(z)take})
			take=${words[1]:+${(M)take##[[:space:]]#}${words[1]}}
		fi
		BUFFER+=${take:-$_mssh_complete_shown}
		CURSOR=$#BUFFER
		return 0
	fi
	zle _mssh_complete_orig_$WIDGET -- "$@"
}

_mssh_complete_ghost_setup() {
	# grey text with own widgets (zsh 5.3 and later, a terminal with colours)
	emulate -L zsh
	autoload -Uz is-at-least add-zle-hook-widget
	is-at-least 5.3 || return 0
	[[ -n $TERM && $TERM != dumb ]] || return 0
	zmodload zsh/zleparameter zsh/system 2>/dev/null || return 0
	local widget key
	typeset -g _mssh_complete_fd= _mssh_complete_asked= _mssh_complete_last= _mssh_complete_shown= _mssh_complete_highlight=
	typeset -g _mssh_complete_style=fg=8
	[[ $TERM == *256col* ]] && _mssh_complete_style=fg=244
	zle -N _mssh_complete_ghost_answer
	zle -N _mssh_complete_ghost_redraw
	zle -N _mssh_complete_ghost_finish
	add-zle-hook-widget line-pre-redraw _mssh_complete_ghost_redraw
	add-zle-hook-widget line-finish _mssh_complete_ghost_finish
	for widget in forward-char vi-forward-char end-of-line vi-end-of-line forward-word emacs-forward-word vi-forward-word; do
		[[ -n ${widgets[$widget]} && ${widgets[$widget]} != user:_mssh_complete_accept ]] || continue
		zle -A $widget _mssh_complete_orig_$widget
		zle -N $widget _mssh_complete_accept
	done
	# Ctrl-Right and Alt-Right take a word, unless they are bound already
	for key in '^[[1;5C' '^[[1;3C'; do
		[[ $(bindkey "$key" 2>/dev/null) == *undefined-key* ]] && bindkey "$key" forward-word
	done
}

_mssh_complete_setup() {
	# precmd, once, at the first prompt (plugins loaded after the mssh block are there by then):
	# Ctrl-R, and grey text through zsh-autosuggestions when it is loaded, else with own widgets
	add-zsh-hook -d precmd _mssh_complete_setup
	_mssh_complete_take_ctrl_r
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		_mssh_complete_zas_strategy
	else
		_mssh_complete_ghost_setup
	fi
}

_mssh_complete_zas_strategy() {
	# zsh-autosuggestions asks mssh first
	(( ${${=ZSH_AUTOSUGGEST_STRATEGY}[(Ie)mssh]} )) || ZSH_AUTOSUGGEST_STRATEGY=(mssh ${=ZSH_AUTOSUGGEST_STRATEGY:-history})
}

if [[ -o interactive ]]; then
	autoload -Uz add-zsh-hook
	add-zsh-hook precmd _mssh_complete_setup
fi
'''

FISH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it only defines a function and registers it.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: register nothing
	case '*'
		function __mssh_complete
			set -l before (string join \n -- (commandline -cp))
			set -l full (string join \n -- (commandline -p))
			set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
			set -l word (commandline -ct)
			set -l keep 1000
			set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
			set -l timeout_cmd
			if command -sq timeout
				set -l limit 0.3
				set -q MSSH_COMPLETE_TIMEOUT; and set limit $MSSH_COMPLETE_TIMEOUT
				set timeout_cmd timeout $limit
			end
			set -l lines (begin
				command printf '%s\0' MSSHC1 fish $FISH_VERSION "nul=0 term=$TERM" "$before" "$after" "$word"
				history -n $keep 2>/dev/null
			end | $timeout_cmd @ENGINE@ query 2>/dev/null)
			test (count $lines) -ge 2; or return
			test "$lines[1]" = MSSHC1; or return
			test "$lines[-1]" = E; or return
			set -l files 0
			for line in $lines[2..-2]
				set -l rest (string sub -s 3 -- "$line")
				switch (string sub -l 1 -- "$line")
					case D
						for item in (string split ' ' -- "$rest")
							contains -- $item files dirs; and set files 1
						end
					case C
						set -l fields (string split \t -- "$rest")
						printf '%s\t%s\n' $fields[1] $fields[2]
					case X
						set -l fields (string split \t -- "$rest")
						set -l words $fields[3..-1]
						set -l cmdline (string join ' ' -- (string escape -- $words[1..-2]))
						if test -n "$words[-1]"
							set cmdline "$cmdline "(string escape -- $words[-1])
						else
							set cmdline "$cmdline "
						end
						for item in (complete -C (string trim -l -- "$cmdline"))
							printf '%s%s\n' $fields[2] $item
						end
				end
			end
			if test $files = 1
				__fish_complete_path (commandline -ct)
			end
		end
		for name in mssh mssh3 multissh multissh3 multiSSH3
			complete -c $name -f -a '(__mssh_complete)'
		end
end
'''

FISH_KEYS_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish keys: Ctrl-R picker for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it defines functions; Ctrl-R is taken at the first prompt.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: take nothing
	case '*'
		if not set -q __mssh_complete_keys
			set -g __mssh_complete_keys 1
			function __mssh_complete_is_mssh
				string match -qr '^\s*(\S*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)\s' -- "$argv[1]"
			end
			function __mssh_complete_ctrl_r --argument-names mode
				# Ctrl-R: the picker on mssh lines, else what Ctrl-R did before in this bind mode
				set -l full (string join \n -- (commandline))
				if __mssh_complete_is_mssh "$full"
					set -l before (string join \n -- (commandline -c))
					set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
					set -l keep 1000
					set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
					set -l lines (begin
						command printf '%s\0' MSSHC1 fish $FISH_VERSION "pick=1 nul=0 term=$TERM" "$before" "$after" ''
						history -n $keep 2>/dev/null
					end | @ENGINE@ pick 2>/dev/null)
					set -l st $status
					if test $st -eq 0; and test (count $lines) -ge 3; and test "$lines[1]" = MSSHC1; and test "$lines[-1]" = E
						for line in $lines[2..-2]
							if string match -qr '^L \d+\t' -- $line
								commandline -r -- (string replace -r '^L \d+\t' '' -- $line)
								commandline -C -- (string replace -r '^L (\d+)\t.*' '$1' -- $line)
							end
						end
					end
					commandline -f repaint
					test $st -le 1; and return
				end
				set -l previous __mssh_complete_previous_$mode
				for command in $$previous
					if contains -- $command (bind --function-names)
						commandline -f $command
					else
						eval $command
					end
				end
			end
			function __mssh_complete_take_ctrl_r --on-event fish_prompt
				# at the first prompt, when the key bindings are set up: record Ctrl-R and take it
				functions -e __mssh_complete_take_ctrl_r
				for mode in default insert
					set -l line (bind -M $mode \cr 2>/dev/null)
					test (count $line) -ge 1; or continue
					string match -q '*__mssh_complete_ctrl_r*' -- "$line[-1]"; and continue
					eval "set -g __mssh_complete_words -- $line[-1]"
					set -l words $__mssh_complete_words[2..-1]
					set -e __mssh_complete_words
					while set -q words[1]; and string match -q -- '-*' $words[1]
						contains -- $words[1] -M --mode -m --sets-mode; and set -e words[1]
						set -e words[1]
					end
					set -e words[1]
					set -q words[1]; or continue
					set -g __mssh_complete_previous_$mode $words
					bind -M $mode \cr "__mssh_complete_ctrl_r $mode"
				end
			end
		end
end
'''

_GLUES = {'bash': BASH_GLUE, 'zsh': ZSH_GLUE, 'fish': FISH_GLUE, 'fish-keys': FISH_KEYS_GLUE}

def engine_command():
	'''How the glue runs the engine: mssh-complete if it is on PATH, else this file with this python.'''
	import shutil
	if shutil.which('mssh-complete'):
		return ['mssh-complete']
	return [sys.executable, '-I', os.path.abspath(__file__)]

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"

def render_glue(shell, command=None):
	'''The glue script for shell, running the engine with command (a list of words).'''
	import shlex
	if shell not in _GLUES:
		raise ValueError('unsupported shell {!r}, use one of {}'.format(shell, ', '.join(SHELLS)))
	command = engine_command() if command is None else command
	quote = _fish_quote if shell.startswith('fish') else shlex.quote
	return _GLUES[shell].replace('@VERSION@', version).replace('@ENGINE@', ' '.join(quote(word) for word in command))

#%% ------------ Install ----------------
RC_BEGIN = '# >>> mssh completion >>>'
RC_BEGIN_CREATED = '# >>> mssh completion (created this file) >>>'
RC_END = '# <<< mssh completion <<<'

def detect_shell(environ=None):
	'''The shell that ran us (parent process), else $SHELL; None if neither is bash, zsh or fish.'''
	environ = os.environ if environ is None else environ
	name = ''
	try:
		with open('/proc/{}/comm'.format(os.getppid())) as f:
			name = f.read().strip()
	except OSError:
		pass
	name = os.path.basename(name).lstrip('-')
	if name not in SHELLS:
		name = os.path.basename(environ.get('SHELL', '')).lstrip('-')
	return name if name in SHELLS else None

def _fish_major():
	'''The major version of the fish on PATH, or None.'''
	import subprocess
	try:
		output = subprocess.run(['fish', '-c', 'echo $FISH_VERSION'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5).stdout
		return int(output.decode('ascii', 'replace').strip().split('.')[0])
	except (OSError, ValueError, subprocess.SubprocessError):
		return None

def _ours(path):
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			return GLUE_MARK in f.readline()
	except OSError:
		return False

def _write_glue(path, text, messages):
	'''Write a glue file unless another file is in the way. Returns whether path holds the glue.'''
	if os.path.lexists(path) and not _ours(path):
		messages.append('skipped {}: it exists and mssh did not write it'.format(path))
		return False
	os.makedirs(os.path.dirname(path), exist_ok=True)
	temporary = path + '.mssh-tmp'
	with open(temporary, 'w', encoding='utf-8') as f:
		f.write(text)
	os.replace(temporary, path)
	messages.append('wrote ' + path)
	return True

def _rc_block(text, begin):
	'''
	Where the block opened by begin is in text: (start, body start, body end, end), or None.

	Its markers are whole lines anywhere in the file: the first line, CRLF line ends and a closing
	marker without a final newline included.
	'''
	import re
	head = re.search(r'(?m)^' + re.escape(begin) + r'[ \t]*\r?\n', text)
	if head is None:
		return None
	tail = re.compile(r'(?m)^' + re.escape(RC_END) + r'[ \t]*(?:\r?\n|\Z)').search(text, head.end())
	if tail is None:
		return None
	return head.start(), head.end(), tail.start(), tail.end()

def _editor_on(rc):
	'''Whether the mssh block in rc turns the mssh line editor on.'''
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			text = f.read()
	except OSError:
		return False
	for begin in (RC_BEGIN, RC_BEGIN_CREATED):
		found = _rc_block(text, begin)
		if found is not None:
			return 'export MSSH_COMPLETE_EDITOR=1' in text[found[1]:found[2]].splitlines()
	return False

def _add_rc_block(rc, body, messages):
	'''Append a marked block holding body to rc; a block with other lines (editor on or off) is replaced.'''
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			text = f.read()
	except FileNotFoundError:
		text = None
	if text is not None:
		for begin in (RC_BEGIN, RC_BEGIN_CREATED):
			found = _rc_block(text, begin)
			if found is None:
				continue
			_, body_start, body_end, _ = found
			if text[body_start:body_end].replace('\r\n', '\n') == body + '\n':
				messages.append('{} already loads it'.format(rc))
				return
			text = text[:body_start] + body + '\n' + text[body_end:]
			with open(rc, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
				f.write(text)
			messages.append('updated the mssh block in ' + rc)
			return
	block = '\n{}\n{}\n{}\n'.format(RC_BEGIN if text is not None else RC_BEGIN_CREATED, body, RC_END)
	with open(rc, 'a', encoding='utf-8', errors='surrogateescape') as f:
		f.write(block)
	messages.append('added a block loading it to ' + rc)

def _remove_rc_block(rc, messages):
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			text = f.read()
	except FileNotFoundError:
		return
	for begin in (RC_BEGIN_CREATED, RC_BEGIN):
		found = _rc_block(text, begin)
		if found is None:
			continue
		start, _, _, end = found
		# the line break install put before the block goes with it
		head = text[:start]
		head = head[:-2] if head.endswith('\r\n') else head[:-1] if head.endswith('\n') else head
		text = head + text[end:]
		if begin == RC_BEGIN_CREATED and not text:
			os.unlink(rc)
			messages.append('removed ' + rc + ' (mssh had created it)')
		else:
			with open(rc, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
				f.write(text)
			messages.append('removed the mssh block from ' + rc)
		return

def _paths(shell, home, environ):
	data = environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share')
	config = environ.get('XDG_CONFIG_HOME') or os.path.join(home, '.config')
	if shell == 'fish':
		# completions load lazily; the Ctrl-R glue must load at startup: conf.d (written whole, like the rc blocks)
		return {'files': [os.path.join(config, 'fish', 'completions', name + '.fish') for name in MSSH_NAMES],
			'keys': os.path.join(config, 'fish', 'conf.d', 'mssh-complete.fish')}
	if shell == 'zsh':
		return {'files': [os.path.join(data, 'multiSSH3', 'completion.zsh')], 'rc': os.path.join(home, '.zshrc')}
	# always from ~/.bashrc: bash-completion's per-user directory only loads where bash-completion
	# runs, which an installed package does not guarantee (stock Debian root shells do not load it)
	return {'files': [os.path.join(data, 'multiSSH3', 'completion.bash')], 'rc': os.path.join(home, '.bashrc')}

def install(shell, home=None, environ=None, command=None, editor=False):
	'''
	Install the glue for shell for the current user. Never overwrites a file mssh did not write.

	Args:
		editor (bool): bash only: also turn on the mssh line editor (MSSH_COMPLETE_EDITOR=1 in the rc block);
			an rc block that already turns it on keeps it on

	Returns:
		tuple: (exit code, list of messages saying what was done)
	'''
	import shlex
	environ = os.environ if environ is None else environ
	home = home or os.path.expanduser('~')
	messages = []
	if shell == 'fish':
		major = _fish_major()
		if major is not None and major < 3:
			return 1, ['fish {} is too old for mssh autocomplete: it needs fish 3.0 or later'.format(major)]
	text = render_glue(shell, command)
	paths = _paths(shell, home, environ)
	written = [path for path in paths['files'] if _write_glue(path, text, messages)]
	if paths.get('keys') and written:
		_write_glue(paths['keys'], render_glue('fish-keys', command), messages)
	if paths.get('rc') and written:
		quoted = shlex.quote(written[0])
		# always ends with status 0: a missing or broken file must not even change $? in a new shell
		line = '[[ -r {0} ]] && source {0} 2>/dev/null || :' if shell == 'zsh' else '[ -r {0} ] && . {0} 2>/dev/null || :'
		body = line.format(quoted)
		if shell == 'bash' and not editor and _editor_on(paths['rc']):
			# installing again after an upgrade keeps what the operator turned on
			editor = True
			messages.append('kept the mssh line editor on (to turn it off: mssh --completion uninstall bash, then install bash)')
		if editor and shell == 'bash':
			body = 'export MSSH_COMPLETE_EDITOR=1\n' + body
		_add_rc_block(paths['rc'], body, messages)
	return (0 if written else 1), messages

def uninstall(shell, home=None, environ=None):
	'''Remove what install wrote for shell. Returns (exit code, messages).'''
	environ = os.environ if environ is None else environ
	home = home or os.path.expanduser('~')
	messages = []
	paths = _paths(shell, home, environ)
	for path in paths['files'] + ([paths['keys']] if paths.get('keys') else []):
		if _ours(path):
			os.unlink(path)
			messages.append('removed ' + path)
	if paths.get('rc'):
		_remove_rc_block(paths['rc'], messages)
	return 0, messages or ['nothing to remove']

def completion_command(values):
	'''`mssh --completion ...`: print the glue for a shell, or install / uninstall it.'''
	action = values[0] if values else ''
	if action in SHELLS and len(values) == 1:
		sys.stdout.write(render_glue(action) + (render_glue('fish-keys') if action == 'fish' else ''))
		return 0
	editor = action == 'install' and values[-1:] in (['editor'], ['--editor'])
	if editor:
		values = values[:-1]
	if action in ('install', 'uninstall') and len(values) <= 2:
		shell = values[1] if len(values) == 2 else detect_shell()
		if shell not in SHELLS:
			print('mssh: cannot tell which shell to set up, name it: mssh --completion {} bash|zsh|fish'.format(action), file=sys.stderr)
			return 2
		if editor and shell != 'bash':
			print('mssh: the mssh line editor is for bash only', file=sys.stderr)
			return 2
		code, messages = install(shell, editor=editor) if action == 'install' else uninstall(shell)
		for message in messages:
			print(message)
		return code
	print('usage: mssh --completion bash|zsh|fish | install [SHELL] [editor] | uninstall [SHELL]', file=sys.stderr)
	return 2

#%% ------------ Replay evaluation ----------------
def _tab(candidates, typed, policy, quoted, nospace):
	'''What one TAB inserts after typed: (text or None if it would change typed text, appended suffix).'''
	texts = [candidate.text for candidate in candidates]
	if not texts:
		return '', ''
	if policy == 'ranked' or len(set(texts)) == 1:
		choice, unique = texts[0], True
	else:
		choice, unique = _common_prefix(texts), False
	if not choice.startswith(typed):
		return None, ''
	suffix = ('"' if quoted else '') + ' ' if unique and not nospace else ''
	return choice[len(typed):], suffix

def simulate_slot(engine, before, after, intended, quoted=False, policy='bash', shell='zsh'):
	'''
	Simulate an operator typing intended after before (with after behind the cursor), using TAB.

	The operator types a character at a time and presses TAB whenever it inserts the intended
	continuation. An appended space or quote that the operator then has to delete costs one key.

	Returns:
		dict: keys, chars, rank (of intended at the start, 0 if absent), visited and divergent
			(positions where TAB would insert something unwanted), altered (candidates not
			extending what was typed: must stay 0), suffix_cost
	'''
	result = {'keys': 0, 'chars': len(intended), 'rank': 0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0}
	position = 0
	while position < len(intended):
		typed = intended[:position]
		response = engine.query(Request(shell, before + typed, after, typed))
		candidates = response.candidates
		result['visited'] += 1
		if position == 0:
			for number, candidate in enumerate(candidates):
				if candidate.text == intended:
					result['rank'] = number + 1
					break
		result['altered'] += sum(1 for candidate in candidates if not candidate.text.startswith(typed))
		inserted, suffix = _tab(candidates, typed, policy, quoted, 'nospace' in response.directives)
		remaining = intended[position:]
		if inserted and remaining.startswith(inserted):
			result['keys'] += 1
			position += len(inserted)
			if suffix and position < len(intended):
				result['keys'] += 1
				result['suffix_cost'] += 1
			continue
		if inserted:
			result['divergent'] += 1
		result['keys'] += 1
		position += 1
	return result

def _quote_command(command):
	'''(quote char, command) for typing command inside quotes, or None when that would need escapes.'''
	if not any(char in command for char in '"\\$`'):
		return '"'
	if "'" not in command:
		return "'"
	return None

def simulate_ghost(engine, before, intended, quoted=False, ahead='', shell='bash', tab=True):
	'''
	Simulate an operator typing intended after before (nothing behind the cursor) with grey suggestions.

	At each position the operator takes the suggestion when it is what they mean: all of it when the
	rest of their line starts with it (ahead is what they would type after the slot), else its first
	word when that matches; otherwise, with tab, they press TAB when bash's TAB would insert what they
	mean (as simulate_slot's bash policy), else they type a character.

	Returns:
		dict: keys, chars, visited, shown (positions with a suggestion), divergent (shown but not
			what the operator means), altered (TAB candidates not extending what was typed: must stay 0)
	'''
	result = {'keys': 0, 'chars': len(intended), 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0}
	target = intended + ('"' if quoted else '') + ahead
	position = 0
	while position < len(intended):
		ghost = engine.suggest(Request(shell, before + intended[:position], '', ''))
		result['visited'] += 1
		if ghost is not None:
			result['shown'] += 1
			remaining = target[position:]
			word = ghost.text.split(' ', 1)[0] if not ghost.text.startswith(' ') else ''
			if remaining.startswith(ghost.text):
				result['keys'] += 1
				position += len(ghost.text)
				continue
			if word and remaining.startswith(word):
				result['keys'] += 1
				position += len(word)
				continue
			result['divergent'] += 1
		if tab:
			typed = intended[:position]
			response = engine.query(Request('zsh', before + typed, '', typed))
			result['altered'] += sum(1 for candidate in response.candidates if not candidate.text.startswith(typed))
			inserted, suffix = _tab(response.candidates, typed, 'bash', quoted, 'nospace' in response.directives)
			if inserted and intended[position:].startswith(inserted):
				result['keys'] += 1
				position += len(inserted)
				if suffix and position < len(intended):
					result['keys'] += 1
				continue
		result['keys'] += 1
		position += 1
	return result

def slot_cases(entry):
	'''
	(slot, before, after, intended, quoted, ahead) cases to replay for one history entry.

	ahead is how the positional slots after this one read when nothing follows the cursor yet
	(the grey suggestions' continuation), '' when they are not suggested.
	'''
	import shlex
	options = [(option, value, name) for (option, value), name in zip(entry.options, entry.option_texts) if option.dest not in PASSWORD_DESTS]
	option_texts = [name if value is None else '{}={}'.format(name, shlex.quote(value)) for option, value, name in options]
	commands = [command for command in entry.commands if command.strip()]
	quoted_commands = []
	for command in commands:
		quote = _quote_command(command)
		if quote is None:
			commands = []
			quoted_commands = []
			break
		quoted_commands.append(quote + command + quote)
	head = ' '.join(['mssh'] + option_texts) + ' '
	tail = (' ' + ' '.join(quoted_commands)) if quoted_commands else ''
	first_command = (' ' + quoted_commands[0]) if quoted_commands else ''
	plain = not any(option.dest in ('file', 'file_sync', 'gather_mode', 'ipmi') for option, _, _ in options)
	cases = []
	if entry.hosts and not any(char in entry.hosts for char in ' \'"\\$`'):
		cases.append(('hosts', head, '', entry.hosts, False, first_command if plain else ''))
		if tail:
			cases.append(('hosts-back', head, tail, entry.hosts, False, ''))
		if commands and _quote_command(commands[0]) == '"':
			cases.append(('command', head + entry.hosts + ' "', '', commands[0], True, ''))
	for number, (_, value, name) in enumerate(options):
		others = ' '.join(['mssh'] + option_texts[:number] + option_texts[number + 1:]) + ' '
		rest = (' ' + entry.hosts + tail) if entry.hosts else ''
		cases.append(('option', others + '-', rest, name[1:], False, ''))
		if value and not any(char in value for char in ' \'"\\$`\t'):
			ahead = ((' ' + entry.hosts) if entry.hosts else '') + first_command if plain else ''
			cases.append(('value', others + name + ' ', rest, value, False, ahead))
	return cases

def evaluate(lines, spec, since=0, limit=300, policies=('bash', 'ranked', 'ghost')):
	'''
	Replay history lines in time order: each entry is typed with only the entries before it known.

	Args:
		lines (list): ~/.mssh_history lines
		spec (ParserSpec): The mssh options
		since (int): Only replay entries from this timestamp on (older ones are still learned from)
		limit (int): Replay at most this many of the newest entries

	Returns:
		dict: (policy, slot) -> totals of simulate_slot (or, for the ghost policy, simulate_ghost)
			results plus 'cases'
	'''
	entries = sorted((entry for entry in (parse_history_line(line, spec) for line in lines) if entry is not None), key=lambda entry: entry.ts)
	replay = [number for number, entry in enumerate(entries) if entry.ts >= since][-limit:] if limit else []
	first = replay[0] if replay else len(entries)
	memory = MemoryKnowledge()
	reference = entries[-1].ts if entries else 0
	for entry in entries[:first]:
		memory.add(entry.features(), use_weight(reference - entry.ts))
	totals = {}
	for number in replay:
		entry = entries[number]
		engine = Engine(spec, [memory])
		for slot, before, after, intended, quoted, ahead in slot_cases(entry):
			if not intended:
				continue
			for policy in policies:
				if policy == 'ghost':
					# suggestions need the cursor at the end of the line: replay the slot typed last
					if slot in ('hosts-back', 'option'):
						continue
					result = simulate_ghost(engine, before, intended, quoted, ahead)
					total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0})
					total['cases'] += 1
					for key in ('keys', 'chars', 'visited', 'shown', 'divergent', 'altered'):
						total[key] += result[key]
					continue
				result = simulate_slot(engine, before, after, intended, quoted, policy)
				total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'top1': 0, 'top3': 0,
					'mrr': 0.0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0})
				total['cases'] += 1
				for key in ('keys', 'chars', 'visited', 'divergent', 'altered', 'suffix_cost'):
					total[key] += result[key]
				if result['rank']:
					total['top1'] += result['rank'] == 1
					total['top3'] += result['rank'] <= 3
					total['mrr'] += 1.0 / result['rank']
		memory.add(entry.features(), use_weight(reference - entry.ts))
	return totals

def format_report(totals):
	'''The evaluation as text tables: TAB policies, then grey suggestions.'''
	ghost = {key: total for key, total in totals.items() if key[0] == 'ghost'}
	totals = {key: total for key, total in totals.items() if key[0] != 'ghost'}
	lines = ['{:7} {:10} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9} {:>8} {:>7}'.format(
		'policy', 'slot', 'cases', 'saved', 'top1', 'top3', 'mrr', 'divergent', 'altered', 'suffix')]
	for (policy, slot), total in sorted(totals.items()):
		cases = total['cases'] or 1
		lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%} {:>6.3f} {:>8.1%} {:>8} {:>7}'.format(
			policy, slot, total['cases'], 1 - float(total['keys']) / (total['chars'] or 1),
			float(total['top1']) / cases, float(total['top3']) / cases, total['mrr'] / cases,
			float(total['divergent']) / (total['visited'] or 1), total['altered'], total['suffix_cost']))
	if ghost:
		lines.append('')
		lines.append('{:7} {:10} {:>6} {:>7} {:>7} {:>7}'.format('policy', 'slot', 'cases', 'saved', 'shown', 'wrong'))
		for (policy, slot), total in sorted(ghost.items()):
			lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%}'.format(policy, slot, total['cases'],
				1 - float(total['keys']) / (total['chars'] or 1), float(total['shown']) / (total['visited'] or 1),
				float(total['divergent']) / (total['shown'] or 1)))
	return '\n'.join(lines)

def synthetic_history(seed=1, entries=1500, start=1700000000):
	'''
	A deterministic ~/.mssh_history with known structure: host groups each with their own commands,
	options and users, so ranking can be checked without anyone's real history.
	'''
	import random
	import shlex
	rng = random.Random(seed)
	profiles = [
		('gpu[01-16]', ['-u=root', '-t=30'], ['nvidia-smi', 'systemctl restart slurmd', 'nvidia-smi -q -d TEMPERATURE']),
		('storage[1-4]', ['-u=admin'], ['df -h /data', 'zpool status', 'zfs list']),
		('login[1-2]', [], ['uptime', 'who', 'free -h']),
		('us_east', ['-t=10'], ['systemctl status nginx', 'journalctl -u nginx -n 50']),
	]
	lines = []
	ts = start
	for _ in range(entries):
		ts += rng.randint(60, 7200)
		hosts, options, commands = rng.choices(profiles, [0.4, 0.25, 0.2, 0.15])[0]
		command = rng.choices(commands, [5, 3, 1][:len(commands)])[0]
		if hosts.startswith('gpu') and rng.random() < 0.15:
			hosts = 'gpu{:02d}'.format(rng.randint(1, 16))
		lines.append('{}\t/usr/bin/multiSSH3.py\t{}\t{}\t{}'.format(ts, ' '.join(['-su'] + options), shlex.quote(hosts), shlex.quote(command)))
	return lines

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

def _prompt_from_flags(flags):
	'''
	The prompt line to redraw when a request says redraw=1 (bash clears the line before running
	pick or edit), or None. The prompt is in $MSSH_COMPLETE_PROMPT: expanded, or PS1 itself with expand=1.
	'''
	if flags.get('redraw') != '1':
		return None
	prompt = os.environ.get('MSSH_COMPLETE_PROMPT', '')
	if flags.get('expand') == '1':
		prompt = expand_prompt(prompt)
	return prompt.rsplit('\n', 1)[-1].replace('\x01', '').replace('\x02', '')

def _cmd_pick():
	'''
	mssh-complete pick: the Ctrl-R picker. Reads a request on stdin, draws on /dev/tty, prints the new
	line (MSSHC1, L <cursor>\\t<line>, E; no NUL: shells read it with command substitution). Exit 0
	chosen, 1 cancelled, 2 unavailable (the shell then does what Ctrl-R did before).
	'''
	data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
	try:
		request = parse_request(data)
	except ValueError:
		return 2
	if ghost_style(os.environ.get('TERM', '')) is None:
		return 2
	now = time.time()
	try:
		engine = engine_for(request, now=now)
		history_lines = read_history(engine.history_path)[0] if engine.history_path else []
		slot, title, history, word = picker_items(request, engine, history_lines, now)
		if not slot and not history:
			return 2
		picker = Picker(slot, history, title, now)
		prompt = _prompt_from_flags(request.flags)
		line = before = None
		if prompt is not None:
			line, before = prompt + request.before + request.after, prompt + request.before
		with Terminal() as term:
			outcome = picker.run(term, line, before)
	except Exception as e:
		_debug('pick failed: {!r}'.format(e))
		return 2
	if outcome == 'unavailable':
		return 2
	if outcome != 'choose':
		return 1
	line, cursor = apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))
	sys.stdout.buffer.write('MSSHC1\nL {}\t{}\nE\n'.format(cursor, line).encode('utf-8', 'surrogateescape'))
	sys.stdout.buffer.flush()
	return 0

def editor_completions(engine, before):
	'''
	What the editor's TAB may put in place of the word ending before: (texts, word).

	Paths are listed as bash's TAB lists them: ~ expanded, names taken as they are, hidden files
	included; what is added to the word as typed is escaped (inside an open quote, names the quote
	cannot hold are left out).
	'''
	context = parse_context(before, '', engine.spec)
	if context is None:
		return [], ''
	# the word as typed (escapes and quotes included): what the candidates' rests are added to
	tokens = lex(before)
	if not context.prefix:
		word = ''
	elif tokens and tokens[-1].text == context.prefix and before.endswith(tokens[-1].raw):
		word = tokens[-1].raw
	elif before.endswith(context.prefix):
		word = context.prefix
	else:
		return [], ''
	response = engine.query(Request('bash', before, '', context.prefix, flags={'insert': '1'}))
	texts = [word + candidate.text[len(context.prefix):] for candidate in response.candidates if candidate.text.startswith(context.prefix)]
	if {'files', 'dirs'} & set(response.directives):
		directory, slash, start = context.value.rpartition('/')
		listed = os.path.expanduser(directory + slash) if slash else '.'
		try:
			names = sorted(os.listdir(listed))
		except OSError:
			names = []
		unsafe = {'"': '"\\$`', "'": "'", "$'": "'\\"}.get(context.open_quote, '')
		for name in names:
			if not name.startswith(start) or _has_control(name):
				continue
			is_dir = os.path.isdir(os.path.join(listed, name))
			if not is_dir and 'files' not in response.directives:
				continue
			rest = name[len(start):] + ('/' if is_dir else '')
			if context.open_quote:
				if any(char in unsafe for char in rest):
					continue
			else:
				rest = _shell_escape('bash', rest, True)
			if word + rest not in texts:
				texts.append(word + rest)
	return texts, word

def _cmd_edit(args):
	'''
	mssh-complete edit [--expand] TEXT: the plain-bash editor for an mssh line.

	The prompt to redraw is in $MSSH_COMPLETE_PROMPT (PS1 itself with --expand); stdin holds the
	shell's history tail. Prints MSSHC1, L <cursor>\\t<line>, K <action>\\t<keys> (pass: readline
	replays keys, written as a readline key sequence; abandon: drop the line), E. Exit 3 when the
	editor cannot start; the shell then goes on as if it had not been asked.
	'''
	import argparse
	parser = argparse.ArgumentParser(prog='mssh-complete edit')
	parser.add_argument('--expand', action='store_true')
	parser.add_argument('text')
	options = parser.parse_args(args)
	prompt = _prompt_from_flags({'redraw': '1', 'expand': '1' if options.expand else '0'}) or ''
	history = []
	if not sys.stdin.isatty():
		data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
		history = [line for line in data.decode('utf-8', 'surrogateescape').split('\n') if line.strip()]
	try:
		engine = engine_for(Request('bash', options.text, '', '', history=history))
		term = Terminal()
	except Exception as e:
		_debug('editor cannot start: {!r}'.format(e))
		return 3
	cache = {}

	def suggest(before):
		return engine.suggest(Request('bash', before, '', ''))

	def complete(before):
		return editor_completions(engine, before)

	def pick(text, cursor, slot_only):
		if 'history' not in cache:
			cache['history'] = read_history(engine.history_path)[0] if engine.history_path else []
		request = Request('bash', text[:cursor], text[cursor:], None, history=history)
		slot, title, items, word = picker_items(request, engine, cache['history'])
		if not slot and (slot_only or not items):
			return None
		picker = Picker(slot, [] if slot_only else items, title)
		editor.erase(term)
		outcome = picker.run(term, prompt + text, prompt + text[:cursor])
		if outcome != 'choose':
			return None
		return apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))

	editor = LineEditor(options.text, suggest, complete, pick)
	try:
		with term:
			action, replay = editor.run(term, prompt, ghost_style(os.environ.get('TERM', '')))
	except Exception as e:
		_debug('editor failed: {!r}'.format(e))
		action, replay = 'pass', b''
	out = 'MSSHC1\nL {}\t{}\nK {}\t{}\nE\n'.format(editor.cursor, editor.text, action, readline_keyseq(replay))
	sys.stdout.buffer.write(out.encode('utf-8', 'surrogateescape'))
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

def _cmd_eval(args):
	import argparse
	parser = argparse.ArgumentParser(prog='mssh-complete eval', description='Replay mssh history and report how much typing completion saves.')
	parser.add_argument('history_file', nargs='?', help='history to replay (default: the one mssh writes)')
	parser.add_argument('--since', type=int, default=0, help='only replay entries from this unix time on')
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	options = parser.parse_args(args)
	mssh = _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	if options.synthetic:
		lines = synthetic_history()
	else:
		lines, _, _ = read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

def main(argv=None):
	argv = sys.argv[1:] if argv is None else argv
	command = argv[0] if argv else ''
	if command == 'query':
		return _cmd_query()
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
	if command == 'pick':
		return _cmd_pick()
	if command == 'edit':
		return _cmd_edit(argv[1:])
	if command in ('glue', 'install', 'uninstall'):
		return completion_command(argv[1:] if command == 'glue' else argv)
	if command in ('-V', '--version'):
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | pick | edit TEXT | rebuild | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

if __name__ == '__main__':
	sys.exit(main())
