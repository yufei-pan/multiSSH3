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

