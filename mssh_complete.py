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

version = '0.9'
__version__ = version
PROTOCOL = 'MSSHC1'
MSSH_NAMES = ('mssh', 'mssh3', 'multissh', 'multissh3', 'multiSSH3')
SHELLS = ('bash', 'zsh', 'fish')

#%% ------------ Shell lexing ----------------
class Token(object):
	'''One shell word. text is the dequoted value, raw the text as typed, start where raw starts in the line (-1: unknown).'''
	__slots__ = ('text', 'raw', 'quoted', 'open_quote', 'start')

	def __init__(self, text, raw, quoted=False, open_quote='', start=-1):
		self.text = text
		self.raw = raw
		self.quoted = quoted
		self.open_quote = open_quote
		self.start = start

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
		tokens.append(Token(''.join(parts), line[start:min(index, length)], quoted, open_quote, start))

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
# options passing options on to another program (-ea, -ia): mssh 6.35+ takes the word after them as
# their value even when it starts with '-' (its _with_passed_on_values), except as takes_passed_on_value says
PASSED_ON_DESTS = frozenset(('extraargs', 'ipmi_args'))
# the letters of the options needing a value of their own, by where they pass them: ssh, ipmitool
PASSED_ON_BARE_VALUE_LETTERS = {
	'extraargs': frozenset('BbcDEeFIiJLlmOoPpQRSWw'),
	'ipmi_args': frozenset('AbBCdefHIklLmNoOpPRtTUyz'),
}

def takes_passed_on_value(dest, text, spec):
	'''
	Whether -ea or -ia (dest) takes text, the word after it, as its value, as mssh's _takes_passed_on_value
	reads it: not a bare option needing a value of its own (-ea -p 2222: the quotes were forgotten), nor a
	word giving mssh's password; mssh stops at those.
	'''
	if not text.startswith('-') or ' ' in text:
		return True
	if len(text) == 2 and text[1] in PASSED_ON_BARE_VALUE_LETTERS[dest]:
		return False
	if text.startswith('-ip'):
		return False
	if text[:2] == '-p' and text[2:].isdigit():
		return True
	option = spec.lookup(text)[0]
	return option is None or option.dest not in PASSWORD_DESTS
# options naming files mssh reads its hosts and env aliases from, at Enter
LOOKUP_DESTS = frozenset(('env_file', 'env_files', 'host_file', 'config_file'))
PATH_DESTS = frozenset(('file', 'file_sync', 'env_file', 'env_files', 'config_file', 'store_config_file', 'host_file', 'history_file'))
USER_DESTS = frozenset(('username', 'ipmi_username'))

def _one_line(text):
	'''text on one line, with NUL, tabs and newlines turned into single spaces.'''
	return ' '.join(str(text).replace('\0', ' ').split())

def _password_free_help(help, password):
	'''
	The help of a password option with the password taken out. Older multiSSH3 wrote the configured
	password into the help as "(default: ...)", and older indexes keep that help and the password.
	'''
	if not password:
		return help
	help = help.replace('(default: {})'.format(password), '(default: set, not shown)')
	# named some other way: the whole text goes rather than any part of the password
	return 'A password (not shown)' if password in help else help

class OptionSpec(object):
	'''
	One mssh option: its dest, every string naming it and how many values it takes.

	A password option keeps no default, and no password in its help: both reach the index, the
	descriptions zsh and fish show and the picker.
	'''
	__slots__ = ('dest', 'strings', 'nargs', 'repeat', 'group', 'default', 'help')

	def __init__(self, dest, strings, nargs='0', repeat=False, group='', default='', help=''):
		if dest in PASSWORD_DESTS:
			help = _password_free_help(help, default)
			default = ''
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
		# every option string, sorted
		self.strings = sorted(self.by_string)
		self._passwords = [option for option in self.options if option.dest in PASSWORD_DESTS]

	def names_option(self, text):
		'''
		Whether argparse reads a word starting with "-" as an option, a wrong or ambiguous one
		included: its first two characters (one dash) or its part before "=" name an option. mssh
		takes option names in full only (_MsshArgumentParser), so a word that only starts an option
		name is not one.
		'''
		return (text[1:2] != '-' and text[:2] in self.by_string) or text.partition('=')[0] in self.by_string

	def lookup(self, text):
		'''
		The option a word names, and the value attached to it ("-x=value", "--long=value", "-xVALUE").

		Names count in full only: mssh takes no abbreviations ("--user" is not --username). Words
		that give a password some other way are password options all the same (_password_spelling).

		Returns:
			tuple: (OptionSpec or None, attached value or None)
		'''
		option = self.by_string.get(text)
		if option is not None:
			return option, None
		name, sep, value = text.partition('=')
		option = self.by_string.get(name) if sep else None
		if option is not None:
			return option, value
		found = self._password_spelling(text)
		if found is not None:
			return found
		if len(text) > 2 and text[0] == '-' and text[1] != '-':
			# argparse reads -pVALUE as -p VALUE, '=' in VALUE included
			short = self.by_string.get(text[:2])
			if short is not None and short.nargs != '0':
				return short, text[2:]
		return None, None

	def _password_spelling(self, text):
		'''
		(password option, the value attached to it or None) for a word that is no option name but
		gives a password, else None; only so the password is never offered or shown. mssh up to 6.31
		took any unique abbreviation ("--pass x", "--ipmi_passw=x"), and the shell's history keeps
		those lines; short flags written together may end in -p ("-qp x", "-qpx"); and "-ipx" is -ip
		with its value (argparse reads -i px, an error).
		'''
		name, sep, value = text.partition('=')
		if name.startswith('--'):
			found = [string for string in self.by_string if string.startswith(name)] if len(name) > 2 else []
			if len(found) == 1 and self.by_string[found[0]].dest in PASSWORD_DESTS:
				return self.by_string[found[0]], (value if sep else None)
			return None
		if len(text) < 3 or text[0] != '-':
			return None
		for option in self._passwords:
			for string in option.strings:
				if not string.startswith('--') and text.startswith(string):
					return option, text[len(string):]
		for index in range(1, len(text)):
			option = self.by_string.get('-' + text[index])
			if option is None or (option.nargs != '0' and option.dest not in PASSWORD_DESTS):
				return None
			if option.nargs != '0':
				rest = text[index + 1:]
				return option, (rest[1:] if rest.startswith('=') else rest) or None
		return None

	def to_rows(self):
		return [option.to_row() for option in self.options]

	@classmethod
	def from_rows(cls, rows):
		return cls(OptionSpec.from_row(row) for row in rows)

def spec_from_parser(parser):
	'''Describe the options of an argparse parser (index builder side). mssh help is plain text with each % doubled for argparse.'''
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
			groups.get(id(action), ''), _one_line(default), _one_line((action.help or '').replace('%%', '%'))))
	return ParserSpec(options)

def flag_settings(parser):
	'''
	What the flags of an argparse parser do (index builder side): ({long string: the value it
	sets}, {dest: its default}). The defaults follow the mssh config the parser was made with.
	'''
	import argparse
	sets = {}
	defaults = {}
	for action in parser._actions:
		if action.option_strings and isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
			sets[OptionSpec(action.dest, action.option_strings).long] = bool(action.const)
			defaults[action.dest] = bool(parser.get_default(action.dest))
	return sets, defaults

def _flag_rows(sets, defaults):
	'''flag_settings as index config rows.'''
	return [['flag_sets'] + ['{}={}'.format(string, int(value)) for string, value in sorted(sets.items())],
		['flag_defaults'] + ['{}={}'.format(dest, int(value)) for dest, value in sorted(defaults.items())]]

def _flag_values(fields):
	'''The 'name=0|1' fields of an index config row as name -> bool.'''
	values = {}
	for field in fields:
		name, sep, value = field.rpartition('=')
		if sep and value in ('0', '1'):
			values[name] = value == '1'
	return values

def _negative_number(text):
	'''Whether argparse takes a word for a negative number: -5, -1.5 (from Python 3.14: any -<digit> or -.<digit> start).'''
	if text[:1] != '-':
		return False
	rest = text[1:]
	if sys.version_info >= (3, 14):
		return rest[:1].isdecimal() or (rest[:1] == '.' and rest[1:2].isdecimal())
	whole, dot, fraction = rest.partition('.')
	return whole.isdecimal() if not dot else (whole == '' or whole.isdecimal()) and fraction.isdecimal()

def _takes_abbreviations(spec):
	'''
	Whether mssh reads an abbreviation alone ("--user") as the option it abbreviates, as argparse does
	by default. The spec looks names up the way mssh does, so it is asked about a long name cut short.
	'''
	strings = spec.by_string
	for string, option in strings.items():
		short = string[:-1]
		if string.startswith('--') and len(short) > 2 and short not in strings and all(
				strings[other] is option for other in strings if other.startswith(short)):
			return spec.lookup(short)[0] is option
	return False

def read_option_word(text, spec, abbreviations=True):
	'''
	How mssh's argument parsing reads one word: argparse's _parse_optional and consume_optional, after
	process_args has read --config_file with a parser of its own.

	A word names an option in full, as "name=value", as a short option with its value attached
	("-uroot") or followed by more short flags ("-aux" is -a -u x), or as an abbreviation when
	abbreviations is true (argparse's default; see _takes_abbreviations).

	Returns:
		tuple: (verdict, readings). verdict: 'positional'; 'options' (readings: (OptionSpec, the value
			attached or None, where the option's name ends in the word) in order); 'unknown' (no such
			option: mssh stops with an error, on Python 3.6 it passes the word on to the commands);
			'error' (mssh stops with an error: ambiguous, a flag given a value); 'unsure' (Pythons
			read it differently)
	'''
	strings = spec.by_string
	if len(text) < 2 or text[0] != '-':
		return 'positional', []
	name, sep, value = text.partition('=')
	value = value if sep else None
	double = text[1] == '-'
	# the options a name abbreviates (the two-character word itself is a short option, not one of them)
	longer = [string for string in strings if string.startswith(name) and string != text[:2]]
	if abbreviations and double and text != '--':
		# process_args first reads --config_file with a parser that knows no other option: there any
		# abbreviation of it is unique ("--c", even "--=x")
		for string in longer:
			if strings[string].dest == 'config_file':
				return _read_attached(spec, abbreviations, string, value, len(name), bool(sep))
	if text in strings:
		return 'options', [(strings[text], None, len(text))]
	if sep and name in strings:
		return _read_attached(spec, abbreviations, name, value, len(name), True)
	# argparse's _get_option_tuples: a short option with the rest of the word attached, and every option
	# the word (up to "=") abbreviates. Taking full names only, abbreviations count only next to a full
	# name (as on patch/no-option-abbrev: "-pr" stays "-p r" or "-pre", ambiguous)
	short = not double and text[:2] in strings
	if not abbreviations and not short:
		longer = []
	if not double and sep and longer:
		# older Pythons abbreviate the whole word, "=" included (so nothing), newer ones the name before it
		return 'unsure', []
	if short + len(longer) > 1:
		return 'error', []
	if short:
		return _read_attached(spec, abbreviations, text[:2], text[2:], 2, False)
	if longer:
		return _read_attached(spec, abbreviations, longer[0], value, len(name), bool(sep))
	if _negative_number(text) and not any(_negative_number(string) for string in strings):
		return 'positional', []
	if ' ' in text:
		return 'positional', []
	return 'unknown', []

def _read_attached(spec, abbreviations, string, attached, end, with_sign):
	'''
	argparse's consume_optional for read_option_word: string is the option string the word matched,
	attached the text after it (with_sign: after "="), end where the name ends in the word. A short flag
	with text after it reads the next letter as another short option.
	'''
	strings = spec.by_string
	option = strings[string]
	readings = []
	while True:
		if attached is None or option.nargs != '0':
			readings.append((option, attached, end))
			return 'options', readings
		# a flag with text after it
		if string[1] == '-' or attached == '' or attached[0] == '-':
			# "--json=x", "-a-b" and "-q=" stop mssh with an error (older Pythons crash on "-q=")
			return 'error', []
		if with_sign:
			# "-q=j" is -q -j on older Pythons, an error on newer ones
			return 'unsure', []
		readings.append((option, None, end))
		string = '-' + attached[0]
		option = strings.get(string)
		if option is None:
			# older Pythons stop at once; newer ones first act on the flags read so far (help, version), and
			# some (3.11) read the rest as a word of its own ("-q x" leaves "- x", a positional)
			if any(item[0].dest in ('help', 'version') for item in readings):
				return 'unsure', []
			rest = read_option_word('-' + attached, spec, abbreviations)[0]
			return ('error' if rest in ('unknown', 'error') else 'unsure'), []
		end += 1
		attached = attached[1:] or None
		if attached is not None and attached[0] == '=':
			if option.nargs == '0':
				return 'error', []
			attached = attached[1:]

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

	The first "--" ends the options, as in argparse (Python 3.12+; 3.6's parse_known_args too):
	every later word is a positional, the hosts when none came before it, then command words,
	dash words and another "--" included.

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
			# the word after a password option is its password, whatever it looks like: argparse stops
			# at "-p -secret", but the shell's history keeps the line, and a password is never another word.
			# mssh takes the word after -ea and -ia as their value (PASSED_ON_DESTS). argparse takes a dash
			# word as the value when it holds a space and names no option (-u "-o x"); mssh's -11 makes it
			# read negative numbers as options
			# (a word being typed in an open quote will hold more: "-I lanplus")
			passed_on = option.dest in PASSED_ON_DESTS and (takes_passed_on_value(option.dest, text, spec) or (is_current and token.open_quote))
			if not dashed or option.dest in PASSWORD_DESTS or passed_on or (' ' in text and not spec.names_option(text)):
				roles.append((ROLE_VALUE, option))
				continue
		if text == '--' and not is_current and not after_separator:
			roles.append((ROLE_SEPARATOR, None))
			after_separator = True
			continue
		if dashed and not after_separator:
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

# what separates hosts in a hosts argument for mssh besides whitespace (which str.split() splits on)
_HOST_PUNCTUATION = frozenset(',;|/&')

def _host_separator(char):
	'''Whether char separates hosts for mssh: one of _HOST_PUNCTUATION, or any whitespace str.split() splits on.'''
	return char in _HOST_PUNCTUATION or char.isspace()

def split_hosts(text):
	'''Split a hosts argument into host words, as mssh does: on its punctuation, then on any whitespace.'''
	for separator in _HOST_PUNCTUATION:
		text = text.replace(separator, ' ')
	return text.split()

def _last_host_start(text):
	'''
	(cut, start) for the last host of a hosts text: where its word starts (after the last separator, as
	split_hosts splits) and where its name does (after "user@").
	'''
	cut = len(text)
	while cut and not _host_separator(text[cut - 1]):
		cut -= 1
	return cut, text.rfind('@', cut) + 1 or cut

def words_as_typed(command):
	'''
	The words of a remote command with their quotes and escapes: each as it is typed among the
	unquoted command words of an mssh line, which mssh joins as they are into the remote command.
	'''
	return [token.raw for token in lex(command)]

def command_features(command):
	'''Features of one remote command: the command, its program and program plus first argument (words as typed).'''
	command = command.strip()
	if not command:
		return []
	words = words_as_typed(command)
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
	fold_start: where in prefix matching in any case may start: the last host, after mssh's last host
		separator (_host_separator) and "user@", a path's last part, the command word being completed;
		what comes before is matched as typed
	icase: how the word is matched in any case (a CaseFold: bash's completion-ignore-case), or None
	'''
	__slots__ = ('slot', 'option', 'prefix', 'value_start', 'open_quote', 'quoted', 'hosts', 'options',
		'command_words', 'command_word_index', 'command_prefix', 'mode', 'features', 'fold_start', 'icase')

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
			# the unquoted command words the current word continues; argparse drops a "--" between them
			def joins(index):
				role = roles[index][0]
				return role == ROLE_SEPARATOR or (role == ROLE_COMMAND and not words[index].quoted)
			first = current
			while first > 0 and joins(first - 1):
				first -= 1
			last = current
			while last + 1 < len(words) and joins(last + 1):
				last += 1
			skip = set(range(first, last + 1))
			typed = [token.text for token, (role, _) in zip(words[first:current], roles[first:current]) if role != ROLE_SEPARATOR]
			command_words = typed + [prefix]
			command_word_index = len(typed)
			command_prefix = ''
	options, hosts, commands = _collect(words, roles, skip)
	mode = _mode(option.dest for option, _ in options)
	return Context(slot=slot, option=option, prefix=prefix, value_start=value_start,
		open_quote=cursor.open_quote, quoted=cursor.current.quoted, hosts=hosts, options=options,
		command_words=command_words, command_word_index=command_word_index, command_prefix=command_prefix,
		mode=mode, features=make_features(options, hosts, _join_commands(commands)),
		fold_start=_fold_start(slot, option, prefix, value_start, cursor.current.quoted, command_prefix, mode))

def _fold_start(slot, option, prefix, value_start, quoted, command_prefix, mode):
	'''
	Where in prefix matching in any case may start (Context.fold_start), as readline matches: the last
	host of a hosts list (after mssh's last host separator and "user@": _last_host_start), the last part
	of a path (readline's file names), the command word being completed; never the words, hosts or
	directories before it.
	'''
	if slot == SLOT_OPTION:
		return 0
	if slot == SLOT_HOSTS or (slot == SLOT_VALUE and option.dest == 'skip_hosts'):
		return value_start + _last_host_start(prefix[value_start:])[1]
	if slot == SLOT_VALUE:
		return value_start + _path_start(prefix[value_start:])
	if mode in PATH_MODES or not quoted:
		return _path_start(prefix)
	# a quoted command: its current word, unless where it starts is unknown
	if command_prefix is None:
		return len(prefix)
	return len(command_prefix) + _path_start(prefix[len(command_prefix):])

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

def history_options(field, spec):
	'''
	The options field of a ~/.mssh_history line.

	Returns:
		tuple: ((OptionSpec, value or None) pairs, the option strings as written)
	'''
	options = []
	texts = []
	tokens = lex(field)
	index = 0
	while index < len(tokens):
		text = tokens[index].text
		option, attached = spec.lookup(text)
		index += 1
		if option is None:
			continue
		name = text
		if attached is not None:
			# the option string without the value written into its word: -u=root and -uroot are -u
			name = text[:len(text) - len(attached)]
			if name.endswith('='):
				name = name[:-1]
		if attached is None and option.nargs in ('1', '+') and index < len(tokens):
			attached = tokens[index].text
			index += 1
		options.append((option, attached))
		texts.append(name)
	return options, texts

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
	options, texts = history_options(fields[2], spec)
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

def _is_control(char):
	'''
	Whether char is a control character: C0, DEL, C1, or a byte 0x80-0x9f that was not UTF-8
	(surrogateescape reads it as U+DC80-U+DC9F and writes the byte back: a C1 control, such as CSI,
	on a terminal that takes 8-bit controls). Other bytes that are not UTF-8 are no control.
	'''
	code = ord(char)
	return code < 32 or 127 <= code < 160 or 0xdc80 <= code < 0xdca0

def _has_control(text):
	'''Whether text holds a control character (_is_control): such text never goes on a command line or the screen.'''
	# nearly all text is printable, which one scan in C settles (the picker checks every history line)
	return not text.isprintable() and any(_is_control(char) for char in text)

def _printable(text):
	'''text with each control character (_is_control) shown as ?: safe to draw.'''
	if text.isprintable():
		return text
	return ''.join('?' if _is_control(char) else char for char in text)

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

# letters lowering to a letter whose upper and title case are others (str has no way back from k to KELVIN
# SIGN), by that lower case letter; the tests hold them against each Python's Unicode data
_CASE_EXTRAS = {'i': '\u0130', 'k': '\u212a', '\u00df': '\u1e9e', '\u00e5': '\u212b', '\u03b8': '\u03f4', '\u03c9': '\u2126'}

# str.isascii came with Python 3.7
_isascii = getattr(str, 'isascii', None) or (lambda text: not text or max(text) < '\x80')

class CaseFold(object):
	"""
	How readline's completion-ignore-case compares characters in the shell's locale: a character at a time,
	each lowered. In a UTF-8 locale by towlower: the I with a dot lowers to an i and a dot and counts as an
	i, the dotless i is no I; Turkish locales and those copying them (turkic) lower I to the dotless i and
	the I with a dot to i. In other locales by tolower on bytes, of which only ASCII letters reach the
	engine as letters (ascii); a Turkish one lowers I to a dotless i that is none, so I and i match only
	themselves there. An instance is what a query's icase holds.
	"""
	__slots__ = ('ascii', 'turkic', '_variants')

	def __init__(self, ascii=False, turkic=False):
		self.ascii = ascii
		self.turkic = turkic
		self._variants = {}   # char -> variants(char)

	def lower(self, char):
		"""The character readline compares for char."""
		if self.ascii:
			return char.lower() if 'A' <= char <= 'Z' and not (self.turkic and char == 'I') else char
		if self.turkic and (char == 'I' or char == '\u0130'):
			return '\u0131' if char == 'I' else 'i'
		return char.lower()[0]

	def variants(self, char):
		"""The characters matching char, char included, sorted in one string: those lowering as it does."""
		variants = self._variants.get(char)
		if variants is None:
			lower = self.lower(char)
			near = {char, lower, lower.upper(), lower.title()}
			near.update(_CASE_EXTRAS.get(lower, ''))
			variants = ''.join(sorted(other for other in near if len(other) == 1 and self.lower(other) == lower))
			self._variants[char] = variants
		return variants

	def same(self, text, word):
		"""Whether text and word, as long, differ only in case."""
		if not self.turkic and _isascii(text) and _isascii(word):
			# ASCII characters are each other's variants when their upper cases are one
			return text.upper() == word.upper()
		for char, typed in zip(text, word):
			if char != typed and char not in self.variants(typed):
				return False
		return True

UNICODE_CASE = CaseFold()
_CASE_KINDS = {(False, False): UNICODE_CASE}   # (ascii, turkic) -> CaseFold, sharing what each learned

def case_fold(flags):
	"""
	How a request with icase=1 is matched in any case: a CaseFold, or None for not at all.

	This glue sends utf8 and turkic, measured in the running shell (whether bash counts a two-byte
	UTF-8 character as one, whether it lowers I to another letter than i): readline compares in the
	locale bash runs in, whatever the variables name. Older glues get what their own engine did, as an
	installed glue file stays until mssh --completion install runs again: main's between 6.36 and the
	measure (never released) sent the locale's name, lc=, read through the C library (_named_locale), no
	matching in any case where it names no locale; 6.36's sent icase alone, read once per shell, and its
	engine matched in the case typed.
	"""
	if 'utf8' in flags:
		kind = (flags['utf8'] != '1', flags.get('turkic') == '1')
	elif 'lc' in flags:
		named = _named_locale(flags['lc'])
		if named is None:
			return None
		kind = (not named[0], named[1])
	else:
		return None
	fold = _CASE_KINDS.get(kind)
	if fold is None:
		fold = _CASE_KINDS[kind] = CaseFold(*kind)
	return fold

# glibc's locales copying tr_TR's case table (lowering I to the dotless i), besides tr_*
_TURKIC_LOCALES = frozenset(('az_AZ', 'crh_UA', 'ku_TR', 'tt_RU@iqtelif'))

def _named_locale(name):
	"""
	(utf8, turkic) of the locale an older glue named (lc=), as the C library has it, or None when it has
	no such locale (bash then runs in C, or, for an LC_CTYPE it refused, in LANG's, which lc= did not say).
	turkic as the name says, by glibc's Turkish case table.
	"""
	codeset = _locale_codeset(name)
	if codeset is None:
		return None
	base, _, modifier = name.partition('@')
	language = base.partition('.')[0]
	turkic = language.partition('_')[0] == 'tr' or language in _TURKIC_LOCALES or language + '@' + modifier in _TURKIC_LOCALES
	return _utf8_codeset(codeset), turkic

def _measured_utf8(request):
	"""
	Whether bash runs in a UTF-8 locale, as a request of its glue says (utf8=, or an older glue's lc=:
	ASCII where that names no locale), None where it says nothing (zsh, fish, 6.36's glue).
	"""
	if request.shell != 'bash':
		return None
	if 'utf8' in request.flags:
		return request.flags['utf8'] == '1'
	if 'lc' in request.flags:
		named = _named_locale(request.flags['lc'])
		return named is not None and named[0]
	return None

_CODESETS = {}   # locale name -> _locale_codeset(name)

def _locale_codeset(name):
	"""
	The codeset of the locale named name as the C library has it ('UTF-8', 'ISO-8859-9', ...), None when
	it has no such locale. Asked once per name (setlocale, nl_langinfo), the process's locale put back.
	C, POSIX and '' are C without asking.
	"""
	if name in ('', 'C', 'POSIX'):
		return 'ANSI_X3.4-1968'
	if name not in _CODESETS:
		codeset = None
		try:
			import _locale
			saved = _locale.setlocale(_locale.LC_CTYPE)
			try:
				_locale.setlocale(_locale.LC_CTYPE, name)
				codeset = _locale.nl_langinfo(_locale.CODESET)
			finally:
				_locale.setlocale(_locale.LC_CTYPE, saved)
		except Exception:
			# not there, or no setlocale or nl_langinfo to ask
			codeset = None
		_CODESETS[name] = codeset
	return _CODESETS[name]

def _utf8_codeset(codeset):
	return (codeset or '').lower().replace('-', '').replace('_', '') == 'utf8'

def _starts(text, prefix, icase=None, start=0):
	"""
	Whether text starts with prefix; with icase (a CaseFold) with prefix[start:] in any case, as icase
	compares.
	"""
	if text.startswith(prefix):
		return True
	if not icase or len(text) < len(prefix) or not text.startswith(prefix[:start]):
		return False
	return icase.same(text[start:len(prefix)], prefix[start:])

def _prefix_ranges(sorted_items, prefix, icase=None, start=0):
	'''
	[(lo, hi)] in order: the runs of sorted_items starting with prefix, with icase (a CaseFold) with
	prefix[start:] in any case (as _starts matches). Each spelling of it is followed one character at a time,
	and only while some item starts with it, so the spellings tried are few however long the prefix.
	'''
	if not icase or start >= len(prefix):
		return [_prefix_range(sorted_items, prefix)]
	spellings = [prefix[:start]]
	for typed in prefix[start:]:
		spellings = [spelling + char for spelling in spellings for char in icase.variants(typed) if _starts_some(sorted_items, spelling + char)]
	return sorted(_prefix_range(sorted_items, spelling) for spelling in spellings)

class MemoryKnowledge(object):
	'''
	Records held in memory: identical invocations share one record whose weight sums their uses.

	Used for the history tail not yet in the index, the shell's history, the replay evaluation,
	and by the builder to aggregate records before writing them. shell: it holds the shell's
	history, where most runs are also in mssh's.
	'''
	def __init__(self):
		self.shell = False
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

	def feature_range(self, prefix, icase=None, start=0):
		if self._sorted is None:
			self._sorted = sorted(self._postings)
		return [(text, text) for lo, hi in _prefix_ranges(self._sorted, prefix, icase, start) for text in self._sorted[lo:hi]]

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

	def feature_range(self, prefix, icase=None, start=0):
		return [(key, self.features[key]) for lo, hi in _prefix_ranges(self.features, prefix, icase, start) for key in range(lo, hi)]

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

def score_features(knowledges, prefix, line_features, deadline=None, icase=None, start=0):
	'''
	Score every feature starting with prefix (e.g. "c:sys") in the given knowledge; with icase (a CaseFold), with
	prefix[start:] in any case (the word typed, after the kind of feature and the words before it).

	score(c) = BETA * frecency(c) + sum over records r holding c of log(1 + weight(r)) * sim(r, line),
	where sim sums idf(f) * KIND_WEIGHTS[kind of f] over the features f shared by r and the line.
	Features in more than COMMON_SHARE of the records are left out of sim; frequency counts
	logarithmically there, so matching the line beats being used often.

	Returns:
		dict: feature text -> score
	'''
	scores = {}
	for knowledge in knowledges:
		for key, text in knowledge.feature_range(prefix, icase, start):
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
				# the features starting with prefix are those found above, as every feature of a record is one of
				# its knowledge's: looked up, they match as the ranges did (icase, start) for what startswith cost
				if text in scores:
					scores[text] += math.log1p(weight) * value
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

	def names_with_prefix(self, prefix, icase=None):
		return [name for lo, hi in _prefix_ranges(self.names, prefix, icase) for name in self.names[lo:hi]]

	def aliases_with_prefix(self, prefix, icase=None):
		return [(index, self.alias_names[index]) for lo, hi in _prefix_ranges(self.alias_names, prefix, icase) for index in range(lo, hi)]

	def sources(self, name):
		'''The SRC_* bits of a host name in the table, 0 for a name it does not hold.'''
		number = bisect_left(self.names, name)
		if number >= len(self.names) or self.names[number] != name or number >= self.index.count('host_meta'):
			return 0
		try:
			return int(self.index.row('host_meta', number)[0])
		except (IndexError, ValueError):
			return 0

	def alias_index(self, name):
		index = bisect_left(self.alias_names, name)
		return index if index < len(self.alias_names) and self.alias_names[index] == name else None

	def alias_members(self, index):
		'''Member host names of the alias at index.'''
		return [self.names[int(member)] for member in self.index.row('aliases', index)[1:]]

	def alias_member_users(self, index):
		'''The user each member of the alias at index is written with (user@host), '' for none.'''
		users = self.index.row('alias_users', index) if index < self.index.count('alias_users') else []
		return users + [''] * (self.alias_size(index) - len(users))

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
			if len(values) + int(high) - int(low) >= limit:
				# past the limit: given back whole without writing it out (node[1-10000000] took 1.5 s)
				return [text]
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

def range_union(texts, limit, budget):
	'''
	What expand_ranges(text, limit) gives for each of texts, as one set, writing each name once:
	the number ranges of texts with one [...] are merged first, so hundreds of overlapping wide
	ranges cost what the hosts they cover cost, not what all their members cost. Writing stops
	after budget names (no deadline: the answer must not depend on how fast the machine is);
	texts come most important first, and the merged numbers are written in the order texts
	first name them, then the texts with more [...].
	'''
	names = set()
	spans = {}   # (text before the [, text after the ], digits) -> [(low, high)] of the a-b parts
	order = []   # keys of spans, as texts first name them
	other = []   # texts with more than one [...]: expand_ranges takes them apart
	for text in texts:
		start = text.find('[')
		end = text.find(']', start + 1)
		if start < 0 or end < 0 or '[' in text[end + 1:]:
			other.append(text)
			continue
		head, tail, body = text[:start], text[end + 1:], text[start + 1:end]
		if '[' in body:
			# a value holding a [ is read again as a range
			other.append(text)
			continue
		parts = []
		count = 0
		# expand_ranges' reading of the parts: a-b with digits, or one value
		for part in body.split(','):
			low, sep, high = part.strip().partition('-')
			if sep and _is_digits(low) and _is_digits(high):
				parts.append((low, high))
				count += max(int(high) - int(low) + 1, 0)
			elif not sep and part.strip():
				parts.append((part.strip(), None))
				count += 1
			else:
				count = None
				break
		if count is None or count > limit:
			# given back whole (letters, hex, past the limit)
			names.add(text)
			continue
		for low, high in parts:
			if high is None:
				names.add(head + low + tail)
				continue
			key = (head, tail, min(len(low), len(high)))
			if key not in spans:
				spans[key] = []
				order.append(key)
			spans[key].append((int(low), int(high)))
	written = 0
	for key in order:
		head, tail, width = key
		merged = []
		for low, high in sorted(spans[key]):
			if low > high:
				continue
			if merged and low <= merged[-1][1] + 1:
				merged[-1][1] = max(merged[-1][1], high)
			else:
				merged.append([low, high])
		for low, high in merged:
			if written >= budget:
				return names
			last = min(high, low + budget - written - 1)
			names.update('{}{:0{}d}{}'.format(head, number, width, tail) for number in range(low, last + 1))
			written += last - low + 1
	for text in other:
		if written >= budget:
			break
		members = expand_ranges(text, limit)
		names.update(members)
		# a range past the limit comes back whole after about the limit's worth of names
		count = _range_count(text)
		written += max(len(members), min(count, limit) if count is not None else 0)
	return names

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

def _could_be_private_dir(path):
	'''Whether _private_dir(path, create=True) would take path, without changing anything (as multiSSH3's).'''
	import stat
	try:
		st = os.lstat(path)
	except FileNotFoundError:
		return os.access(os.path.dirname(path), os.W_OK | os.X_OK)
	except OSError:
		return False
	if not stat.S_ISDIR(st.st_mode):
		return False
	if not hasattr(os, 'getuid'):
		return True
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

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
	is ours, /run/user/<uid>/multiSSH3, /dev/shm/multiSSH3-<uid>, then <tempdir>/multiSSH3-<uid>;
	without create, the one a write would use if it is there already, else None.
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
		if create:
			if _private_dir(directory):
				return directory
		elif _could_be_private_dir(directory):
			return directory if _private_dir(directory, create=False) else None
	return None

def _traceback():
	'''The traceback of the exception being handled, for the debug log.'''
	import traceback
	return traceback.format_exc().rstrip()

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
def _ssh_config_words(line):
	'''
	The keyword (lower case) and arguments of an ssh config line, split as ssh splits them.

	The keyword ends at blanks or one "="; arguments are split at blanks, may be quoted with " or '
	and escape a quote, a backslash or (unquoted) a space with a backslash; an argument starting
	with # starts a comment. Returns ('', []) for an empty or comment line, and for a line ssh
	rejects (an unterminated quote).
	'''
	line = line.lstrip(' \t').rstrip(' \t\r\n\f')
	end = 0
	while end < len(line) and line[end] not in ' \t=':
		end += 1
	keyword = line[:end].lower()
	if not keyword or keyword.startswith('#'):
		return '', []
	# one "=" may stand between the keyword and the arguments, blanks around it or not
	rest = line[end:].lstrip(' \t')
	if rest.startswith('='):
		rest = rest[1:]
	args = []
	index = 0
	while index < len(rest):
		if rest[index] in ' \t':
			index += 1
			continue
		if rest[index] == '#':
			break
		arg = []
		quote = ''
		while index < len(rest):
			char = rest[index]
			if char == '\\' and index + 1 < len(rest) and (rest[index + 1] in '\'"\\' or (not quote and rest[index + 1] == ' ')):
				arg.append(rest[index + 1])
				index += 2
				continue
			if not quote and char in ' \t':
				break
			if not quote and char in '"\'':
				quote = char
			elif char == quote:
				quote = ''
			else:
				arg.append(char)
			index += 1
		if quote:
			return '', []
		args.append(''.join(arg))
	return keyword, args

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
			key, args = _ssh_config_words(line)
			if key == 'host':
				for pattern in args:
					if pattern and not any(char in pattern for char in '*?!'):
						names.add(pattern)
			elif key == 'user' and args and args[0]:
				users.add(args[0])
			elif key == 'include':
				for pattern in args:
					pattern = os.path.expanduser(pattern)
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

def _in_environ(name):
	'''Whether name is an environment variable. A name the locale cannot encode (Python 3.6 in the C locale) is none.'''
	try:
		return name in os.environ
	except UnicodeEncodeError:
		return False

_ALIAS_VALUE_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-,[]@*?:$')

def collect_aliases(mssh, history_tokens, known):
	'''
	Host aliases: env file variables that look like host lists, and environment variables used as hosts.

	An env file variable counts when it was used as a host, when its value holds a "," or a
	range, or when everything it expands to is an IP address or a known host. Values with other
	characters (paths, prompts, ...) never count.

	Returns:
		dict: name -> (source, member host names, the user each member is written with or '')
	'''
	def expand(name):
		'''(member host names, their users): mssh keeps a member's user@ over -u.'''
		members, users = [], []
		for member in mssh.expand_hostnames_local([name])[0]:
			user, at, host = member.partition('@')
			members.append(host if at else member)
			users.append(user if at else '')
		return members, users
	aliases = {}
	try:
		variables = mssh.readEnvFromFile()
	except Exception:
		variables = {}
	for name, value in variables.items():
		if not name.isidentifier() or not value or not set(value) <= _ALIAS_VALUE_CHARS:
			continue
		members, users = expand(name)
		if not members or members == [name]:
			continue
		if name in history_tokens or ',' in value or '[' in value or all(_is_ip(member) or member in known for member in members):
			aliases[name] = ('env_file', members, users)
	for name in history_tokens:
		if name in aliases or not name.isidentifier() or not _in_environ(name):
			continue
		members, users = expand(name)
		if members and members != [name]:
			aliases[name] = ('env', members, users)
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
RANGE_COUNT_LIMIT = 16384    # a range whose names may repeat is expanded to count its hosts up to this many names

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
	parser = mssh.get_parser()
	spec = spec_from_parser(parser)
	history_path = os.path.expanduser(mssh.DEFAULT_HISTORY_FILE)
	lines, offset, inode = read_history(history_path)
	memory = MemoryKnowledge()
	memory.add_history(lines, spec, now)
	features, record_rows, postings, fweights, fcounts, flast = serialize_knowledge(memory)
	history_tokens = {feature[2:] for feature in features if feature.startswith('t:')}
	hosts = {}
	def add(name, source, address=''):
		# mssh splits a hosts word where a separator is: a name holding one (machine/.host in
		# systemd's ssh config) is never one host
		if not name or not safe_field(name) or any(_host_separator(char) for char in name):
			return
		entry = hosts.setdefault(name, [0, ''])
		entry[0] |= source
		if address and not entry[1]:
			entry[1] = address
	# mssh's own reading, so the names marked as from the hosts file are the ones it finds there
	for name, address in mssh.read_hosts_file(mssh.DEFAULT_HOST_FILE).items():
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
	for _, members, _ in aliases.values():
		for member in members:
			add(member, SRC_ALIAS)
	names = sorted(hosts)
	host_number = {name: number for number, name in enumerate(names)}
	alias_names = sorted(aliases)
	alias_rows = []
	# the user of each member in alias_rows, '' for none; a row without any is left empty
	alias_user_rows = []
	for name in alias_names:
		source, members, member_users = aliases[name]
		kept = [(member, user) for member, user in zip(members, member_users) if member in host_number]
		alias_rows.append([source] + [str(host_number[member]) for member, _ in kept])
		alias_user_rows.append([user for _, user in kept] if any(user for _, user in kept) else [])
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
		('config', [['users'] + sorted(user for user in users if safe_field(user))] + _flag_rows(*flag_settings(parser))),
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
		('alias_users', alias_user_rows),
		('groups', group_rows),
		('unavailable', [unavailable]),
		# option combinations main() ignores: [option, kind, why, others...]
		('no_effect', [[option, kind, why] + list(others) for option, kind, others, why in getattr(mssh, 'OPTION_NO_EFFECT', ())]),
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
LOCK_FAILED = 'failed'  # the last line of a rebuild lock kept after the build failed
FIRST_BUILD_BUDGET = 2.0    # seconds the picker and the editor (no deadline) wait for the first index
FIRST_BUILD_RESERVE = 0.1   # a query stops waiting for the first index this long before its deadline

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
	'''
	Create the rebuild lock file, or return False if another rebuild holds it (and it is not stale).

	The file says who took it (pid, time and a random token), so the process the lock was taken for
	can tell later whether it still holds it (see release_lock).
	'''
	import binascii
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
			f.write('{} {} {}\n'.format(os.getpid(), int(now), binascii.hexlify(os.urandom(8)).decode('ascii')))
		return True
	return False

def read_lock(path):
	'''What the lock file at path says, or None when it cannot be read (gone, for one).'''
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			return f.read()
	except OSError:
		return None

def release_lock(path, owner):
	'''
	Remove the lock at path if it still says owner (what read_lock gave when its holder started).

	A lock older than LOCK_STALE is taken over by the next process that wants it, even when its
	holder is still running (stuck past that, or the machine was suspended): that holder must leave
	the new lock alone, or a third process would start beside the second.
	'''
	if owner is None or read_lock(path) != owner:
		return
	try:
		os.unlink(path)
	except OSError:
		pass

def keep_failed_lock(path, owner):
	'''
	After a failed run, keep the lock at path (if it still says owner) and add that it failed: the
	next run starts once the lock goes stale, LOCK_STALE from now, instead of at the next query. A
	failure that repeats (a full runtime directory, multiSSH3.py missing) would otherwise cost a
	full run on every query.
	'''
	if owner is None or read_lock(path) != owner:
		return
	try:
		with open(path, 'a') as f:
			f.write(LOCK_FAILED + '\n')
	except OSError:
		# not marked (a query without an index waits its budget out), but kept all the same
		try:
			os.utime(path, None)
		except OSError:
			pass

def rebuild_failed(directory):
	'''Whether the last rebuild failed, less than LOCK_STALE ago (see keep_failed_lock).'''
	content = read_lock(os.path.join(directory, LOCK_NAME))
	return content is not None and content.endswith('\n' + LOCK_FAILED + '\n')

def _spawn_detached(directory, lock_name, command):
	'''Start `mssh-complete <command> --lock <lock>` detached unless one is running. Returns whether one was started.'''
	lock = os.path.join(directory, lock_name)
	if not take_lock(lock):
		return False
	import subprocess
	try:
		subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), command, '--lock', lock],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
			close_fds=True, start_new_session=True, cwd='/')
	except OSError as e:
		_debug('cannot start {}: {!r}'.format(command, e))
		try:
			os.unlink(lock)
		except OSError:
			pass
		return False
	return True

def spawn_rebuild(directory):
	'''Start a detached `rebuild` unless one is running. Returns whether one was started.'''
	return _spawn_detached(directory, LOCK_NAME, 'rebuild')

def _load_index(path):
	try:
		return NsvIndex.load(path)
	except (OSError, IndexCorrupt, ValueError) as e:
		_debug('index not usable: {!r}'.format(e))
		return None

def load_for_query(directory, now, deadline=None):
	'''
	The index to answer from and the history lines it is missing.

	Starts a rebuild when the index is stale. Without an index, starts the first build and waits for
	it up to FIRST_BUILD_BUDGET; with a deadline (time.monotonic()), only until FIRST_BUILD_RESERVE
	before it: the shell stops waiting at its deadline, so the query then answers without the index
	while the build goes on. It stops waiting when that build failed (the next one starts when its
	lock goes stale).

	Returns:
		tuple: (NsvIndex or None, history tail lines)
	'''
	path = os.path.join(directory, INDEX_NAME)
	index = _load_index(path)
	if index is None:
		spawn_rebuild(directory)
		until = time.monotonic() + FIRST_BUILD_BUDGET
		if deadline is not None:
			until = min(until, deadline - FIRST_BUILD_RESERVE)
		while index is None and not rebuild_failed(directory):
			left = until - time.monotonic()
			if left <= 0:
				break
			time.sleep(min(0.02, left))
			if os.path.exists(path):
				index = _load_index(path)
		if index is None:
			return None, []
	state, tail = check_freshness(index, now)
	if state == 'rebuild':
		spawn_rebuild(directory)
	return index, tail

#%% ------------ Host state ----------------
HOST_STATE_NAME = 'host-state.tsv'
PROBE_QUEUE_NAME = 'probe-queue'
PROBE_LOCK_NAME = 'probe.lock'
VALIDITY_FRESH = 600.0  # seconds a valid / invalid answer stays fresh
UNSURE_FRESH = 60.0     # seconds an unsure answer stays fresh
PING_FRESH = 60.0       # seconds a ping result stays fresh (a host on the line is pinged again after)
ANSWER_KEEP = 86400.0   # seconds the prober keeps when a host last answered ping, at least (answer_horizon)
ANSWER_ROWS = 10000     # at most this many hosts are kept only for when they last answered, the latest (prune_host_states)

def boot_id():
	'''An identifier of the current boot, or None where the system has none.'''
	try:
		with open('/proc/sys/kernel/random/boot_id') as f:
			return f.read().strip() or None
	except OSError:
		return None

class HostState(object):
	'''
	What the prober learned about one host. Times are wall-clock seconds.

	validity: 'valid', 'invalid' or 'unsure' (multiSSH3.host_validity), '' when never checked;
	ping: 'answer', 'silent', 'none' (could not ping) or '' when never pinged;
	answered_at: when the host last answered ping (0 when never).
	'''
	__slots__ = ('validity', 'checked_at', 'ping', 'pinged_at', 'answered_at')

	def __init__(self, validity='', checked_at=0.0, ping='', pinged_at=0.0, answered_at=0.0):
		self.validity = validity
		self.checked_at = checked_at
		self.ping = ping
		self.pinged_at = pinged_at
		self.answered_at = answered_at

	def fresh_validity(self, now):
		'''The validity while it is fresh, else ''.'''
		limit = UNSURE_FRESH if self.validity == 'unsure' else VALIDITY_FRESH
		return self.validity if self.validity and now - self.checked_at <= limit else ''

	def fresh_ping(self, now):
		'''The ping result while it is fresh, else ''.'''
		return self.ping if self.ping and now - self.pinged_at <= PING_FRESH else ''

def needs_probe(state, now):
	'''Whether the prober must look at a host: its validity is not fresh, or it may be pinged and its ping is not.'''
	if state is None:
		return True
	validity = state.fresh_validity(now)
	return not validity or (validity != 'invalid' and not state.fresh_ping(now))

def prune_host_states(states, now, horizon):
	'''
	The states worth writing down (host -> HostState, the same objects): those with a fresh validity
	or ping, which queries use as they are, and of the rest the ANSWER_ROWS hosts that answered
	ping latest, within horizon seconds. The prober carries a host's last answer into its next ping,
	which is called unreachable when silent and that answer is within the ping expiry. A state left
	out is as good as none: never answered, or longer ago than any expiry the horizon allows for.
	'''
	kept = {}
	answered = []
	for host, state in states.items():
		if state.fresh_validity(now) or state.fresh_ping(now):
			kept[host] = state
		elif state.answered_at and now - state.answered_at <= horizon:
			answered.append((-state.answered_at, host))
	answered.sort()
	for _, host in answered[:ANSWER_ROWS]:
		kept[host] = states[host]
	return kept

_VALIDITIES = ('valid', 'invalid', 'unsure')
_PINGS = ('', 'answer', 'silent', 'none')

def read_host_states(directory):
	'''host -> HostState from host-state.tsv; {} for a missing, foreign or other-boot file.'''
	try:
		with open(os.path.join(directory, HOST_STATE_NAME), encoding='utf-8', errors='replace') as f:
			lines = f.read().split('\n')
	except OSError:
		return {}
	head = lines[0].split(',', 1)
	if len(head) != 2 or head[0] != '#boot_id':
		return {}
	current = boot_id()
	if current and head[1] != current:
		return {}
	states = {}
	for line in lines[1:]:
		fields = line.split('\t')
		if len(fields) != 6 or not fields[0] or fields[1] not in _VALIDITIES or fields[3] not in _PINGS:
			continue
		try:
			states[fields[0]] = HostState(fields[1], float(fields[2]), fields[3], float(fields[4]), float(fields[5]))
		except ValueError:
			continue
	return states

def write_host_states(directory, states):
	'''Replace host-state.tsv with states (host -> HostState), atomically.'''
	import tempfile
	lines = ['#boot_id,{}'.format(boot_id() or '')]
	for host in sorted(states):
		state = states[host]
		lines.append('\t'.join([host, state.validity, repr(float(state.checked_at)), state.ping,
			repr(float(state.pinged_at)), repr(float(state.answered_at))]))
	fd, temporary = tempfile.mkstemp(prefix='.host-state.', dir=directory)
	try:
		with os.fdopen(fd, 'w', encoding='utf-8') as f:
			f.write('\n'.join(lines) + '\n')
		os.replace(temporary, os.path.join(directory, HOST_STATE_NAME))
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

def read_unavailable(directory):
	'''
	The hosts mssh's unavailable_hosts.csv lists now: failed in a recent run of this boot, their
	expiry (time.monotonic() seconds) not passed.
	'''
	try:
		with open(os.path.join(directory, 'unavailable_hosts.csv'), encoding='utf-8', errors='replace') as f:
			lines = f.read().split('\n')
	except OSError:
		return frozenset()
	now = time.monotonic()
	written = None
	hosts = set()
	for line in lines:
		fields = line.strip().split(',')
		if len(fields) != 2:
			continue
		if fields[0] == '#boot_id':
			written = fields[1]
		elif fields[0] and _is_digits(fields[1]) and int(fields[1]) > now:
			hosts.add(fields[0])
	current = boot_id()
	if current and written and current != written:
		return frozenset()
	return frozenset(hosts)

def _queueable(host):
	return bool(host) and '\t' not in host and not _has_control(host)

def queue_probes(directory, hosts):
	'''
	Append hosts to the probe queue in one write (queries do this; the prober takes them).

	Hosts already waiting in the queue are left out: a query for a long range repeats on every
	keystroke.
	'''
	path = os.path.join(directory, PROBE_QUEUE_NAME)
	try:
		with open(path, encoding='utf-8', errors='surrogateescape') as f:
			waiting = set(f.read().split('\n'))
	except OSError:
		waiting = set()
	new = []
	for host in hosts:
		if _queueable(host) and host not in waiting:
			waiting.add(host)
			new.append(host)
	if not new:
		return
	data = ''.join(host + '\n' for host in new)
	fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
	try:
		os.write(fd, data.encode('utf-8', 'surrogateescape'))
	finally:
		os.close(fd)

def take_probe_queue(directory):
	'''
	Empty the probe queue and return its hosts, newest first, each once.

	The queue is renamed before it is read: a query appending meanwhile starts a new queue. A host
	lost to that race is queued again by the next query that finds it without a fresh answer.
	'''
	path = os.path.join(directory, PROBE_QUEUE_NAME)
	taken = path + '.taken'
	try:
		os.replace(path, taken)
	except OSError:
		return []
	try:
		with open(taken, encoding='utf-8', errors='surrogateescape') as f:
			lines = f.read().split('\n')
	except OSError:
		lines = []
	try:
		os.unlink(taken)
	except OSError:
		pass
	hosts = []
	for host in reversed(lines):
		if _queueable(host) and host not in hosts:
			hosts.append(host)
	return hosts

#%% ------------ Prober ----------------
PROBE_RUN_LIMIT = 120.0  # seconds one prober run may last; the next query starts another for what is left
PING_OPTIONS = ('-i0.2', '-W1', '-q')
PING_COMMAND = ('ping', '-c2') + PING_OPTIONS
PING_TIMEOUT = 10   # seconds: PING_COMMAND is done in about one, unless its own name lookup hangs
PING_LOOPBACK = '127.0.0.1'  # pinged once a run, to tell whether ping works here at all
DNS_TIMEOUT = 2.0

def _out_of_resources(error):
	'''Whether error says the system is out of descriptors or processes (a smaller batch may work).'''
	import errno
	return isinstance(error, OSError) and error.errno in (errno.EMFILE, errno.ENFILE, errno.EAGAIN)

def probe_parallelism(mssh):
	'''
	How many hosts the prober checks at once: mssh's own rule for parallel ssh sessions (the mssh
	config's DEFAULT_MAX_CONNECTIONS, default 4 x CPUs, clamped by the open-file limit), halved
	while the 1-minute load average is at or above the CPU count; never below 4.
	'''
	try:
		parallel = int(mssh._normalize_max_connections(mssh.DEFAULT_MAX_CONNECTIONS))
	except Exception:
		parallel = 4 * (os.cpu_count() or 1)
	try:
		if os.getloadavg()[0] >= (os.cpu_count() or 1):
			parallel //= 2
	except (AttributeError, OSError):
		pass
	return max(parallel, 4)

def ping_works():
	'''
	Whether ping can work here at all, from one ping of the loopback address with the prober's
	options. Without permission (no CAP_NET_RAW, a group outside net.ipv4.ping_group_range) ping
	fails for every host, yet no one host's failure tells: iputils ping exits 2 both for that and
	for a name it cannot resolve, busybox ping 1 both for that and for silence, and their messages
	are translated. The loopback address needs no name lookup, so a failure there with a message,
	or with an exit code other than 1 (silence), means ping cannot work. A loopback that is silent
	without saying why (a firewall dropping ICMP) leaves ping on, as does a check that cannot
	finish for now (out of descriptors or processes, out of time).
	'''
	import subprocess
	argv = [PING_COMMAND[0], '-c1'] + list(PING_OPTIONS) + [PING_LOOPBACK]
	try:
		result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=PING_TIMEOUT)
	except subprocess.TimeoutExpired:
		return True
	except OSError as e:
		# out of resources says nothing yet; otherwise there is no ping command, or one we may not run
		return _out_of_resources(e)
	return result.returncode == 0 or (result.returncode == 1 and not result.stderr.strip())

def ping_host(host):
	'''
	'answer' or 'silent' after two pings; 'none' when ping fails otherwise (a name it cannot
	resolve; run_probe finds out first whether ping works at all, see ping_works) or runs out of
	time (stuck on its name lookup: a slow DNS server says nothing about the host). Raises
	FileNotFoundError without a ping command, OSError when out of descriptors or processes.
	'''
	import subprocess
	argv = list(PING_COMMAND) + (['-6'] if ':' in host else []) + [host]
	try:
		code = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT).returncode
	except subprocess.TimeoutExpired:
		return 'none'
	except FileNotFoundError:
		raise
	except OSError as e:
		if _out_of_resources(e):
			raise
		return 'none'
	return {0: 'answer', 1: 'silent'}.get(code, 'none')

def answer_horizon(mssh):
	'''
	Seconds the prober keeps when a host last answered ping: the longest ping expiry it can see
	($MSSH_COMPLETE_PING_TTL, mssh's unreachable host expiry from the mssh config), and ANSWER_KEEP
	at least, for -uhe on a line, which it cannot.
	'''
	horizon = ANSWER_KEEP
	ttl = os.environ.get('MSSH_COMPLETE_PING_TTL', '')
	if _is_digits(ttl):
		horizon = max(horizon, float(ttl))
	try:
		horizon = max(horizon, float(mssh.DEFAULT_UNAVAILABLE_HOST_EXPIRY))
	except (AttributeError, TypeError, ValueError):
		pass
	return horizon

def _probe_batch(mssh, hosts, states, now, ping_available):
	'''
	Check and ping hosts at once, one thread each, updating states (host -> HostState).

	Returns:
		list: the hosts that could not be checked for lack of descriptors or processes, in order
	'''
	import threading
	retry = []
	guard = threading.Lock()

	def check(host):
		state = states.get(host) or HostState()
		try:
			if not state.fresh_validity(now()):
				state.validity, state.checked_at = mssh.host_validity(host, timeout=DNS_TIMEOUT), now()
			if state.validity != 'invalid' and not state.fresh_ping(now()):
				answer = 'none'
				if ping_available[0]:
					try:
						answer = ping_host(host)
					except FileNotFoundError:
						ping_available[0] = False
				state.ping, state.pinged_at = answer, now()
				if answer == 'answer':
					state.answered_at = state.pinged_at
		except Exception as e:
			if _out_of_resources(e):
				with guard:
					retry.append(host)
			else:
				_debug('probing {} failed: {!r}'.format(host, e))
			return
		with guard:
			states[host] = state

	threads = []
	for number, host in enumerate(hosts):
		thread = threading.Thread(target=check, args=(host,), daemon=True)
		try:
			thread.start()
		except RuntimeError:
			# no more threads: the rest waits for a smaller batch
			retry.extend(hosts[number:])
			break
		threads.append(thread)
	for thread in threads:
		thread.join()
	return sorted(retry, key=hosts.index)

def run_probe(directory, lock=None, now=time.time, limit=PROBE_RUN_LIMIT, owner=None):
	'''
	One prober run, at low CPU priority: check the queued hosts, newest first, recording what is
	learned in host-state.tsv after each batch (without what no query can use any more:
	prune_host_states), until the queue is empty or limit seconds have passed. Hosts left over go
	back into the queue. Never connects to a host itself: only DNS, ssh -G (which reads the ssh
	config, running the commands of its Match exec lines) and ping.

	With lock (the lock file this run holds; owner is what it said when the run started, read now
	when not given), the run keeps the lock fresh after each batch, and stops, leaving its hosts
	queued, once the lock says something else: another prober took it over as stale.

	Returns:
		dict: {'checked': hosts looked at, 'parallel': hosts checked at once at the end}
	'''
	if lock and owner is None:
		owner = read_lock(lock)
	try:
		os.nice(10)
	except (AttributeError, OSError):
		pass
	mssh = _import_mssh()
	parallel = probe_parallelism(mssh)
	horizon = answer_horizon(mssh)
	started = now()
	checked = 0
	ping_available = None
	while now() - started < limit:
		hosts = take_probe_queue(directory)
		if not hosts:
			break
		states = read_host_states(directory)
		moment = now()
		todo = [host for host in hosts if needs_probe(states.get(host), moment)]
		while todo:
			if now() - started >= limit:
				queue_probes(directory, todo[::-1])
				return {'checked': checked, 'parallel': parallel}
			if ping_available is None:
				# once a run, and only once there is a host to check
				ping_available = [ping_works()]
			batch, todo = todo[:parallel], todo[parallel:]
			retry = _probe_batch(mssh, batch, states, now, ping_available)
			if lock and read_lock(lock) != owner:
				# the lock was taken over (this batch ran past LOCK_STALE, or the machine was
				# suspended): the prober holding it writes host-state.tsv now, and writing ours would
				# undo its results; it takes these hosts from the queue instead
				queue_probes(directory, (batch + todo)[::-1])
				return {'checked': checked, 'parallel': parallel}
			checked += len(batch) - len(retry)
			write_host_states(directory, prune_host_states(states, now(), horizon))
			if lock:
				# a lock that keeps changing is not stale
				try:
					os.utime(lock, None)
				except OSError:
					pass
			if retry:
				if parallel == 1:
					queue_probes(directory, (retry + todo)[::-1])
					return {'checked': checked, 'parallel': parallel}
				parallel = max(parallel // 2, 1)
				todo = retry + todo
	return {'checked': checked, 'parallel': parallel}

def spawn_probe(directory):
	'''Start a detached `probe` unless one is running. Returns whether one was started.'''
	return _spawn_detached(directory, PROBE_LOCK_NAME, 'probe')

#%% ------------ Diagnostics ----------------
DIAGNOSTIC_KINDS = ('command', 'unknown', 'range', 'unreachable', 'options')  # the order warnings are shown in
MAX_MESSAGE = 160
WARNING_ASKS = (0.3, 1.0, 3.0)  # seconds after an answer with the prober still working when a frontend asks again

class Diagnostic(object):
	'''A warning about part of an mssh line: line[start:end] is marked, message says why.'''
	__slots__ = ('start', 'end', 'kind', 'message')

	def __init__(self, start, end, kind, message):
		self.start = start
		self.end = end
		self.kind = kind
		self.message = message

	def __repr__(self):
		return 'Diagnostic({}, {}, {!r}, {!r})'.format(self.start, self.end, self.kind, self.message)

def _punctuation(unicode):
	'''The dash and the ellipsis messages use: typographic on a UTF-8 terminal (unicode), ASCII elsewhere.'''
	return (' — ', '…') if unicode else (' - ', '...')

def _shell_operator(raw):
	'''
	Where a word as typed holds an unquoted shell operator, parenthesis or backtick, or starts a
	comment: the shell's, not part of the word mssh gets (-1: none).
	'''
	if raw.startswith('#'):
		return 0
	index = 0
	while index < len(raw):
		char = raw[index]
		if char == '\\':
			index += 2
		elif char == "'" or (char == '$' and raw[index + 1:index + 2] == "'"):
			# '...' ends at the next quote, $'...' at the next one not escaped
			index = raw.find("'", index + 1) if char == "'" else index + 2
			while char == '$' and 0 <= index < len(raw) and raw[index] != "'":
				index += 2 if raw[index] == '\\' else 1
			if index < 0 or index >= len(raw):
				return -1
			index += 1
		elif char == '"':
			index += 1
			while index < len(raw) and raw[index] != '"':
				index += 2 if raw[index] == '\\' else 1
			index += 1
		elif char in '|&;<>()`':
			return index
		else:
			index += 1
	return -1

def _mssh_argv(line, tokens, start):
	'''
	The words the shell gives the mssh at tokens[start]: up to the first unquoted shell operator,
	command substitution, comment or line break. A word holding an operator ("-aux|grep") keeps what
	comes before it, unless that is a redirection's descriptor ("2>/dev/null").
	'''
	argv = []
	end = tokens[start].start + len(tokens[start].raw)
	for token in tokens[start + 1:]:
		if token.start < 0 or '\n' in line[end:token.start]:
			break
		cut = _shell_operator(token.raw)
		if cut < 0:
			argv.append(token)
			end = token.start + len(token.raw)
			continue
		head = token.raw[:cut]
		if head and not (token.raw[cut] in '<>' and head.isdecimal()):
			word = lex(head)[0]
			argv.append(Token(word.text, word.raw, word.quoted, word.open_quote, token.start))
		break
	return argv

def _quoted_command(text):
	'''text in single quotes, or in double quotes when it holds single quotes and nothing double quotes expand; None otherwise.'''
	if any(char < ' ' for char in text):
		return None
	if "'" not in text:
		return "'" + text + "'"
	if not any(char in text for char in '"$`\\!'):
		return '"' + text + '"'
	return None

# words the shell may expand into other words: what mssh gets from them is not known here
_EXPANDED = frozenset('$`*?[{~')

def _host_parts(token):
	'''
	(user typed before the @ or '', host name without user@, (start, end) in the line) for each host
	of a hosts word. A quoted or escaped word is marked whole: its parts have no exact place in the line.
	'''
	text = token.text
	exact = token.raw == text and token.start >= 0
	parts = []
	position = 0
	while position < len(text):
		if _host_separator(text[position]):
			position += 1
			continue
		end = position
		while end < len(text) and not _host_separator(text[end]):
			end += 1
		user, _, name = text[position:end].rpartition('@')
		span = (token.start + position, token.start + end) if exact else (token.start, token.start + len(token.raw))
		parts.append((user, name.strip('$'), span))
		position = end
	return parts

def _run_name(host, typed_user, line_user, own_user=''):
	'''
	The name mssh gives a host in this run: what it records a failure under in unavailable_hosts.csv
	and looks up to skip the host. The user typed with the host, else -u (line_user), else none.
	own_user: the user an alias member is written with. -u does not replace it, a user typed with the
	alias does (for root@dbs with dbs=postgres@db1 mssh runs root@db1).
	'''
	user = typed_user or own_user or line_user
	return user + '@' + host if user else host

# characters that can start an expansion the shell makes before mssh sees the word
_EXPANSION_STARTS = frozenset('$`~{!(')
# what follows a $ that the shell expands: a name, a digit, ${...}, $(...), $[...], a special parameter, zsh's flags
_PARAMETER_STARTS = frozenset('_{([@*#?$!-=~^+')

def _quoting(raw):
	'''
	How each character of a word's dequoted text (lex's Token.text) was typed: (how, stretch),
	how 'u' unquoted, 'd' in "...", 'l' taken literally (in '...' or $'...', or after a backslash);
	stretch numbers the quoted and unquoted stretches of the word. Reads quotes as lex does.
	'''
	marks = []
	stretch = 0
	index = 0
	length = len(raw)
	while index < length:
		char = raw[index]
		if char == '\\':
			if index + 1 < length and raw[index + 1] != '\n':
				marks.append(('l', stretch + 1))
			index += 2
			stretch += 2
		elif char == "'":
			end = raw.find("'", index + 1)
			end = length if end < 0 else end
			marks.extend([('l', stretch + 1)] * (end - index - 1))
			index = end + 1
			stretch += 2
		elif char == '"':
			index += 1
			while index < length and raw[index] != '"':
				if raw[index] == '\\' and index + 1 < length and raw[index + 1] in '"\\$`\n':
					if raw[index + 1] != '\n':
						marks.append(('l', stretch + 1))
					index += 2
				else:
					marks.append(('d', stretch + 1))
					index += 1
			index += 1
			stretch += 2
		elif char == '$' and index + 1 < length and raw[index + 1] == "'":
			index += 2
			while index < length and raw[index] != "'":
				if raw[index] == '\\' and index + 1 < length:
					text, index = _ansi_c_escape(raw, index + 1)
					marks.extend([('l', stretch + 1)] * len(text))
				else:
					marks.append(('l', stretch + 1))
					index += 1
			index += 1
			stretch += 2
		else:
			marks.append(('u', stretch))
			index += 1
	return marks

def _shell_expansions(text, marks, shell):
	'''
	(start, end) stretches of a word's dequoted text that the shell replaces before it runs the
	command: $NAME, ${...}, $(...), $((...)), `...`, a leading ~, {a,b}, and in bash and zsh
	{1..3} and history's !$; also an unquoted (...) (fish's command substitution; a glob pattern
	or an error in bash and zsh). Globs are left alone: one matching no file reaches mssh as
	typed, and mssh takes [ ], * and ? in ranges. marks: _quoting's.
	'''
	length = len(text)

	def closing(index, how):
		'''The index after the bracket matching the one at index (nested ones skipped), or None.'''
		opening = text[index]
		close = {'{': '}', '(': ')', '[': ']'}[opening]
		depth = 0
		for end in range(index, length):
			if marks[end][0] not in how:
				continue
			if text[end] == opening:
				depth += 1
			elif text[end] == close:
				depth -= 1
				if depth == 0:
					return end + 1
		return None

	# unquoted braces: where each one closes, and whether it holds a , of its own
	braces = {}
	stack = []
	for position in range(length):
		char = text[position]
		if marks[position][0] != 'u':
			continue
		if char == '{':
			stack.append([position, False])
		elif char == '}' and stack:
			start, listed = stack.pop()
			braces[start] = (position + 1, listed)
		elif stack and char == ',':
			stack[-1][1] = True

	found = []
	index = 0
	while index < length:
		char, how = text[index], marks[index][0]
		end = None
		# the next character, typed in the same stretch: "$" and $"..." are no expansions
		following = text[index + 1] if index + 1 < length and marks[index + 1] == marks[index] else ''
		if how == 'l':
			pass
		elif char == '$' and following and (following.isalnum() or following in _PARAMETER_STARTS):
			if following in '{([':
				# unclosed: the shell asks for more or fails, mssh gets nothing of it either way
				end = closing(index + 1, 'ud') or length
			elif following.isalnum() or following == '_':
				end = index + 2
				while end < length and (text[end].isalnum() or text[end] == '_') and marks[end] == marks[index]:
					end += 1
			else:
				end = index + 2
		elif char == '`':
			end = next((position + 1 for position in range(index + 1, length) if text[position] == '`' and marks[position][0] != 'l'), length)
		elif char == '!' and shell != 'fish' and following and following not in ' \t\n=(':
			# history expansion, in "..." too: how far the event reaches is hard to tell
			end = length
		elif how != 'u':
			pass
		elif char == '~' and index == 0:
			end = text.find('/') if '/' in text else length
		elif char == '{' and index in braces:
			close, listed = braces[index]
			if listed or (all(how == 'u' for how, _ in marks[index:close]) and _brace_sequence(text[index + 1:close - 1], shell)):
				end = close
		elif char == '(':
			end = closing(index, 'u') or length
		if end is None:
			index += 1
		else:
			found.append((index, end))
			index = max(end, index + 1)
	return found

def _without_shell_expansions(token, shell, users=False):
	'''
	A hosts word with the hosts the shell rewrites before mssh sees them ($NODES, $(cat file),
	node{1,2}, ~, !$, ...) blanked out: mssh gets something else, nothing can be said about them.
	Text the shell passes as typed (in '...', after a backslash) stays: mssh reads it itself.

	users: the word with only the hosts the shell rewrites just the user of ($USER@gpu017) kept
	instead, or None when it has none: mssh gets the host as typed, under a user not known here.
	'''
	if not _EXPANSION_STARTS.intersection(token.raw):
		return None if users else token
	text = token.text
	marks = _quoting(token.raw)
	# lex read the word another way: say nothing about it
	spans = _shell_expansions(text, marks, shell) if len(marks) == len(text) else [(0, len(text))]
	if not spans:
		return None if users else token
	expanded = [False] * len(text)
	for start, end in spans:
		expanded[start:end] = [True] * (end - start)
	blanked = list(text)
	kept = False
	position = 0
	while position < len(text):
		end = position
		while end < len(text) and not _host_separator(text[end]):
			end += 1
		at = text.rfind('@', position, end)
		# the shell rewrites a piece of the host, or only of its user@
		user_only = any(expanded[position:end]) and at >= 0 and not any(expanded[at:end])
		keep = user_only if users else not any(expanded[position:end])
		if keep:
			kept = True
		else:
			blanked[position:end] = ' ' * (end - position)
		position = end + 1
	if users and not kept:
		return None
	blanked = ''.join(blanked)
	return Token(blanked, blanked if token.raw == text else token.raw, token.quoted, token.open_quote, token.start)

# a brace warning lists the hosts to write instead up to this many
BRACE_LIST_LIMIT = 16

def _is_integer(text):
	return _is_digits(text[1:] if text.startswith('-') else text)

def _brace_sequence(inside, shell):
	'''
	What the shell puts in place of a {x..y} or {x..y..step}, given what is inside the braces:
	(a range of numbers, the width the shell pads them to, 0 for none), or (a list of characters,
	0). None when the shell leaves the braces as typed (always in fish, which has no sequences).
	'''
	fields = inside.split('..')
	if shell == 'fish' or len(fields) not in (2, 3):
		return None
	first, last = fields[0], fields[1]
	step = abs(int(fields[2])) if len(fields) == 3 and _is_integer(fields[2]) else (1 if len(fields) == 2 else 0)
	if not step:
		return None
	if _is_integer(first) and _is_integer(last):
		low, high = int(first), int(last)
		# a leading zero on either end pads every number to the longer end
		padded = any(len(field.lstrip('-')) > 1 and field.lstrip('-').startswith('0') for field in (first, last))
		numbers = range(low, high + 1, step) if low <= high else range(low, high - 1, -step)
		return numbers, max(len(first), len(last)) if padded else 0
	# letters; zsh takes any two characters
	if len(first) == 1 and len(last) == 1 and (shell == 'zsh' or ((first + last).isalpha() and max(first, last) < '\x80')):
		low, high = ord(first), ord(last)
		codes = range(low, high + 1, step) if low <= high else range(low, high - 1, -step)
		return [chr(code) for code in codes], 0
	return None

def _brace_values(text, marks, start, end, shell):
	'''
	(values, width) for the braces text[start:end] the shell expands: a list for {a,b}, else
	_brace_sequence's. (None, 0) when they nest or the shell leaves them as typed.
	'''
	inner = range(start + 1, end - 1)
	if any(text[position] in '{}' and marks[position][0] == 'u' for position in inner):
		return None, 0
	cuts = [position for position in inner if text[position] == ',' and marks[position][0] == 'u']
	if cuts:
		bounds = [start] + cuts + [end - 1]
		return [text[low + 1:high] for low, high in zip(bounds, bounds[1:])], 0
	if any(marks[position][0] != 'u' for position in inner):
		return None, 0
	return _brace_sequence(text[start + 1:end - 1], shell) or (None, 0)

def _count(values):
	'''How many values a list or range holds: len() of a range stops at sys.maxsize ({1..99999999999999999999}).'''
	if isinstance(values, list):
		return len(values)
	return max(0, (values.stop - values.start - (1 if values.step > 0 else -1)) // values.step + 1)

def _closed_brackets(text):
	'''Whether every [ of text closes before another opens: mssh pairs its [ ] as typed when more are added around it.'''
	inside = False
	for char in text:
		if char == '[':
			if inside:
				return False
			inside = True
		elif char == ']':
			inside = False
	return not inside

def _brace_split(token, shell, unicode):
	'''
	The warning for a hosts word the shell makes several words of by brace expansion (node{1,2},
	gpu{01..16}): mssh takes the first as its hosts and runs the second as the command. It says
	what to write instead (a list, an mssh range) for a word typed without quotes. None for any
	other word.
	'''
	if '{' not in token.raw:
		return None
	text = token.text
	marks = _quoting(token.raw)
	if len(marks) != len(text):
		return None
	groups = []
	for start, end in _shell_expansions(text, marks, shell):
		if text[start] == '{':
			values, width = _brace_values(text, marks, start, end, shell)
			if values is None:
				return None
			groups.append((start, end, values, width))
	bounds = [0] + [edge for start, end, _, _ in groups for edge in (start, end)] + [len(text)]
	# braces the shell leaves around or between expanded ones change how it reads them: not worked out
	if any(text[position] in '{}' and marks[position][0] == 'u' for low, high in zip(bounds[::2], bounds[1::2]) for position in range(low, high)):
		return None
	pieces = [text[low:high] for low, high in zip(bounds[::2], bounds[1::2])]
	count = 1
	for _, _, values, _ in groups:
		count *= _count(values)
	# the shell drops an empty word: what it leaves is not worked out
	if count < 2 or (not ''.join(pieces) and any('' in values for _, _, values, _ in groups if isinstance(values, list))):
		return None

	def value(group, number):
		_, _, values, width = group
		return values[number] if isinstance(values, list) else '{:0{width}d}'.format(values[number], width=width)

	def mssh_range(group):
		'''A {1..16} as an mssh range, [1-16]. mssh pads to the shorter end: both ends get the shell's width.'''
		_, _, numbers, width = group
		low, high = sorted((numbers[0], numbers[-1]))
		return '[{:0{width}d}-{:0{width}d}]'.format(low, high, width=width)

	def word(number):
		'''Word number (0: the first) of those the shell makes: bash and zsh vary the last braces fastest, fish the first.'''
		chosen = {}
		for index in (range(len(groups)) if shell == 'fish' else range(len(groups) - 1, -1, -1)):
			number, chosen[index] = divmod(number, _count(groups[index][2]))
		return pieces[0] + ''.join(value(groups[index], chosen[index]) + pieces[index + 1] for index in range(len(groups)))

	dash, _ = _punctuation(unicode)
	message = '{}: the shell makes {} words of this; mssh would run {} as the command'.format(token.raw, count, word(1))
	meant = None
	if token.raw == text:
		if (all(isinstance(values, range) and abs(values.step) == 1 and min(values[0], values[-1]) >= 0 for _, _, values, _ in groups)
				and all(_closed_brackets(piece) for piece in pieces)):
			meant = pieces[0] + ''.join(mssh_range(group) + pieces[index + 1] for index, group in enumerate(groups))
		elif count <= BRACE_LIST_LIMIT:
			# hosts beside the braces once
			meant = ','.join(_unique(host for number in range(count) for host in word(number).split(',')))
	if meant is not None and len(message) + len(dash) + len(meant) + len('did you mean ?') <= MAX_MESSAGE:
		message += dash + 'did you mean {}?'.format(meant)
	return Diagnostic(token.start, token.start + len(token.raw), 'range', message)

def _is_ip_address(name):
	'''A dotted IPv4 address, or anything with a colon (IPv6: host names hold none).'''
	parts = name.split('.')
	if len(parts) == 4 and all(_is_digits(part) and int(part) <= 255 for part in parts):
		return True
	return ':' in name

def _ipv4_range(name):
	'''
	Whether name is in mssh's IPv4 range syntax (an a-b range, x, * or ? in an octet, an octet in
	[ ]) without being one address: its members are all IP addresses.
	'''
	parts = name.split('.')
	if len(parts) != 4:
		return False
	plain = True
	for part in parts:
		if part.startswith('[') and part.endswith(']'):
			part = part[1:-1]
			plain = False
		low, sep, high = part.partition('-')
		for end in ((low, high) if sep else (low,)):
			if end in ('x', '*', '?'):
				plain = False
			elif not (_is_digits(end) and int(end) <= 255):
				return False
		plain = plain and not sep
	return not plain

def _ipv4_members(name, limit=None):
	'''
	(the first limit members, how many in all) of an IPv4 range (_ipv4_range), expanded as mssh
	expands it: [ ] dropped, an a-b range per octet, x * ? for a whole octet or a range end (0 or
	255), and no .0 or .255 in the last octet. limit: RANGE_MEMBERS_LIMIT when None.
	'''
	import itertools
	wild = ('x', '*', '?')
	octets = []
	for part in name.replace('[', '').replace(']', '').strip().split('.'):
		if '-' in part:
			low, high = part.split('-', 1)
			low = 0 if not low or low in wild else int(low)
			high = 255 if not high or high in wild else int(high)
			octets.append([str(value) for value in range(low, high + 1)])
		elif part in wild:
			octets.append([str(value) for value in range(256)])
		else:
			octets.append([part])
	octets[-1] = [value for value in octets[-1] if value not in ('0', '255')]
	total = 1
	for values in octets:
		total *= len(values)
	limit = RANGE_MEMBERS_LIMIT if limit is None else limit
	return ['.'.join(address) for address in itertools.islice(itertools.product(*octets), limit)], total

def _range_size(text):
	'''
	(how many names expand_ranges makes of text, repeats included, whether a name may come more
	than once), or None when it cannot expand text (letters, hex, a [ inside [ ]).

	No name comes twice when each [ ] holds one value or one a-b range, and each range but the
	last makes values of one width or is followed by a character that is not a digit: a name then
	splits into its values one way only. node[1-16], n[1-9][1-16] and rack[1-12]-n[1-64] cannot
	repeat; n[1-11][1-11] makes n111 twice (1 then 11, 11 then 1), and [1-2,2-3] makes 2 twice.
	'''
	count = 1
	repeats = False
	# whether the value of the [ ] before may run on into the next [ ]'s
	runs_on = False
	position = 0
	while True:
		start = text.find('[', position)
		end = text.find(']', start + 1)
		if start < 0 or end < 0:
			return count, repeats
		repeats = repeats or runs_on
		parts = text[start + 1:end].split(',')
		size = 0
		widths = set()
		for part in parts:
			low, sep, high = part.strip().partition('-')
			if sep and _is_digits(low) and _is_digits(high):
				first, last = int(low), int(high)
				if last >= first:
					size += last - first + 1
					# zero padded to the shorter bound's width, longer numbers as they are
					width = min(len(low), len(high))
					widths.update((max(width, len(str(first))), max(width, len(str(last)))))
			elif not sep and part.strip() and '[' not in part:
				size += 1
				widths.add(len(part.strip()))
			else:
				return None
		count *= size
		repeats = repeats or len(parts) > 1
		following = text[end + 1:end + 2]
		runs_on = len(widths) > 1 and (following == '[' or _is_digits(following))
		position = end + 1

def _has_open_range(text):
	'''Whether a [] group of text holds a range with an end missing (node[1-], rack[-x]), as multiSSH3._has_open_range.'''
	start = text.find('[')
	while start >= 0:
		end = text.find(']', start + 1)
		if end < 0:
			return False
		for part in text[start + 1:end].split(','):
			low, sep, high = part.partition('-')
			if sep and not (low.strip() and high.strip()):
				return True
		start = text.find('[', end + 1)
	return False

def _range_count(text):
	'''
	How many hosts expand_ranges makes of text: each name once, as mssh keeps it. None when it
	cannot expand text, or when its names may repeat (_range_size) and there are more than
	RANGE_COUNT_LIMIT of them: those are counted by expanding them, any other range without.
	'''
	size = _range_size(text)
	if size is None:
		return None
	count, repeats = size
	if not repeats:
		return count
	return len(set(_range_names(text))) if count <= RANGE_COUNT_LIMIT else None

def _iter_range(text):
	'''The names expand_ranges makes of text, one at a time, each once (text must be one _range_count can count).'''
	names = _range_names(text)
	if not _range_size(text)[1]:
		return names
	seen = set()
	return (name for name in names if not (name in seen or seen.add(name)))

def _range_names(text):
	'''The names expand_ranges makes of text, one at a time, repeats included.'''
	start = text.find('[')
	end = text.find(']', start + 1)
	if start < 0 or end < 0:
		yield text
		return
	head, tail = text[:start], text[end + 1:]
	for part in text[start + 1:end].split(','):
		low, sep, high = part.strip().partition('-')
		if sep:
			width = min(len(low), len(high))
			values = ('{:0{}d}'.format(number, width) for number in range(int(low), int(high) + 1))
		else:
			values = [part.strip()]
		for value in values:
			for name in _range_names(head + value + tail):
				yield name

def _padded_range(name):
	'''node[1-16] -> node[01-16]: the one range of name with its lower bound padded to the upper's width, or None.'''
	start = name.find('[')
	end = name.find(']', start + 1)
	if start < 0 or end < 0 or '[' in name[end:]:
		return None
	low, sep, high = name[start + 1:end].partition('-')
	if not sep or not _is_digits(low) or not _is_digits(high) or low.startswith('0') or len(low) >= len(high):
		return None
	return '{}[{}-{}]{}'.format(name[:start], low.zfill(len(high)), high, name[end + 1:])

def _one_edit(typed, other):
	'''Whether other is one insertion, deletion, substitution or swap of adjacent characters away from typed.'''
	if typed == other:
		return False
	if len(typed) == len(other):
		differ = [index for index in range(len(typed)) if typed[index] != other[index]]
		if len(differ) == 1:
			return True
		return (len(differ) == 2 and differ[1] == differ[0] + 1
			and typed[differ[0]] == other[differ[1]] and typed[differ[1]] == other[differ[0]])
	if abs(len(typed) - len(other)) != 1:
		return False
	short, long_ = (typed, other) if len(typed) < len(other) else (other, typed)
	return any(long_[:index] + long_[index + 1:] == short for index in range(len(long_)))

# Did-you-mean searches the sorted host names by bisecting: with 50k hosts, stripping or comparing
# every name cost 33 ms per unknown host, and a line with a dozen of them outlasted the shells' wait.

def _holds(names, name, lo=0, hi=None):
	'''Whether the sorted list names holds name (between lo and hi).'''
	index = bisect_left(names, name, lo, len(names) if hi is None else hi)
	return index < len(names) and names[index] == name

def _starts_some(names, prefix):
	'''Whether a name of the sorted list names starts with prefix.'''
	index = bisect_left(names, prefix)
	return index < len(names) and names[index].startswith(prefix)

def _zero_variants(names, name):
	'''
	The names of the sorted list names equal to name once leading zeros are dropped from every run
	of digits (gpu017 -> gpu17; 000 -> 0), name itself included, in sorted order. They differ from
	name only in how many zeros lead each run, so they are found run by run, never stripping a name.
	'''
	runs = []   # (the text before a run of digits, the run without its leading zeros)
	text_start = index = 0
	while index < len(name):
		if name[index] not in _DIGITS:
			index += 1
			continue
		end = index
		while end < len(name) and name[end] in _DIGITS:
			end += 1
		runs.append((name[text_start:index], name[index:end].lstrip('0') or '0'))
		text_start = index = end
	tail = name[text_start:]
	prefixes = ['']
	for text, digits in runs:
		grown = []
		for prefix in prefixes:
			head = prefix + text
			zeros = ''
			while _starts_some(names, head + zeros):
				if _starts_some(names, head + zeros + digits):
					grown.append(head + zeros + digits)
				zeros += '0'
		prefixes = grown
	return sorted(prefix + tail for prefix in prefixes if _holds(names, prefix + tail))

def _one_edit_names(names, name):
	'''
	The names of the sorted list names one edit away from name (_one_edit), in sorted order. A
	changed or added character follows a part of name that some names start with: for each such
	part only the characters that follow it in names are tried, each block of names found by bisecting.
	'''
	found = set()
	for index in range(len(name) - 1):
		found.add(name[:index] + name[index + 1] + name[index] + name[index + 2:])
	for index in range(len(name)):
		found.add(name[:index] + name[index + 1:])
	found = {candidate for candidate in found if _holds(names, candidate)}
	for index in range(len(name) + 1):
		head = name[:index]
		block = bisect_left(names, head)
		if block < len(names) and names[block] == head:
			block += 1
		while block < len(names) and names[block].startswith(head):
			char = names[block][index]
			# names starting with head + char are names[block:end]
			end = bisect_left(names, head + chr(ord(char) + 1), block) if ord(char) < sys.maxunicode else len(names)
			for candidate in (head + char + name[index + 1:], head + char + name[index:]):
				if _holds(names, candidate, block, end):
					found.add(candidate)
			block = end
	return sorted(candidate for candidate in found if _one_edit(name, candidate))

def _option_name(text, attached):
	'''An option word without the value given with it: -ip=secret -> -ip, -uroot -> -u.'''
	if attached is None:
		return text
	return text[:len(text) - len(attached)].rstrip('=')

def _unique(names):
	'''names without repeats, in order.'''
	seen = set()
	return [name for name in names if not (name in seen or seen.add(name))]

#%% ------------ Engine ----------------
PRIOR = 0.001              # score of a candidate that nothing in history supports
GROUP_THRESHOLD = 50       # list single hosts once a prefix matches at most this many
HIDDEN_MEMBERS_LIMIT = 131072  # members of ranges typed before written out to hide them from a hosts TAB, at most (~25 ms)
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
	command. ghost is the grey suggestion (SP2), diagnostics the warnings about the line (SP3).
	'''
	__slots__ = ('context', 'candidates', 'directives', 'delegate', 'ghost', 'diagnostics', 'unicode')

	def __init__(self, context=None):
		self.context = context
		self.candidates = []
		self.directives = set()
		self.delegate = None
		self.ghost = None
		self.diagnostics = []
		# whether the reason line may hold Unicode; None: as the variables say
		self.unicode = None

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
	memory.shell = True
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

# what an open quote cannot hold as it is: in "..." \ $ ` and " are read, in $'...' a \ starts an escape,
# and ' ends the other two
_QUOTE_SPECIAL = {'"': '"\\$`', "'": "'", "$'": "'\\"}

# shells that expand ! inside double quotes when they read a line (history expansion, on by default in
# interactive bash and zsh); there a backslash stops it in bash only by staying in the word
_BANG_SHELLS = frozenset(('bash', 'zsh'))

def _bang_in_double_quotes(shell, open_quote, text):
	'''Whether text put inside an open double quote holds a ! that shell would expand.'''
	return open_quote == '"' and shell in _BANG_SHELLS and '!' in text

def _literal_word(context):
	'''Whether the current word is taken literally: a word of the remote command, or a path.'''
	return context.slot == SLOT_COMMAND or (context.slot == SLOT_VALUE and context.option.dest in PATH_DESTS)

def _path_start(path):
	'''Where a path's last part starts: readline's file name completion matches only that part in any case.'''
	return path.rfind('/') + 1

def _joinable(word):
	'''
	Whether a command word keeps unquoted command words one command. mssh joins its command words
	into one command only when none of them holds whitespace; else it runs each as its own command.
	'''
	return len(word.split()) == 1

class Engine(object):
	'''Answers completion requests from parsed options, history knowledge and the host table.'''
	def __init__(self, spec, knowledges=(), hosts=None, users=()):
		self.history_path = None
		self.spec = spec
		self.knowledges = [knowledge for knowledge in knowledges if knowledge is not None]
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)
		# the runtime directory: host states, the probe queue; None runs without them
		self.directory = None
		# what mssh's flags set ({long string: value}) and their defaults ({dest: value}): flag_settings
		self.flag_sets = {}
		self.flag_defaults = {}
		# OPTION_NO_EFFECT entries from mssh: (long option, 'with' | 'without', other long options, why)
		self.no_effect = []
		# whether bash runs in a UTF-8 locale, as its glue measured it (request flag utf8), None if not said
		self.shell_utf8 = None
		# _unicode_terminal(), once asked
		self._unicode = None

	@property
	def unicode(self):
		'''
		Whether to write in Unicode (messages, the picker): as bash's glue measured its locale, else as the
		variables say, which are worked out at the first use and kept.
		'''
		if self.shell_utf8 is not None:
			return self.shell_utf8
		if self._unicode is None:
			self._unicode = _unicode_terminal()
		return self._unicode

	def query(self, request, deadline=None):
		ghost = request.flags.get('ghost') == '1'
		diag = request.flags.get('diag') == '1'
		if ghost or diag:
			# grey text and warnings come without candidates
			response = Response(parse_context(request.before, request.after, self.spec))
			if ghost:
				response.ghost = self.suggest(request, deadline)
			if diag:
				response.unicode = self.unicode
				try:
					response.diagnostics, pending = self.diagnose(request)
					if pending:
						response.directives.add('pending')
				except Exception as e:
					_debug('diagnostics failed: {!r}'.format(e))
			return response
		context = parse_context(request.before, request.after, self.spec)
		response = Response(context)
		if context is None:
			return response
		# how readline compares characters ignoring case, in the shell's locale (bash's glue says which)
		context.icase = case_fold(request.flags) if request.flags.get('icase') == '1' else None
		if context.icase:
			# bash's glue then matches what it adds itself (a command's own completion, file names) in any case too
			response.directives.add('icase')
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

	def host_states(self):
		'''What the prober learned (host -> HostState), from the runtime directory.'''
		return read_host_states(self.directory) if self.directory else {}

	def diagnose(self, request, probe=True, now=None, states=None):
		'''
		Warnings for the words of the request's line (before + after) already typed, most
		important first, and whether the prober still owes answers for hosts on the line: hosts
		without fresh answers that this call left in the probe queue (never without probe, without
		self.directory, or when the queue cannot be written).

		Args:
			probe (bool): queue those hosts and start the prober (needs self.directory)
			states: what is known about hosts (anything with get(host) -> HostState or None), instead
				of what the prober wrote (the replay passes its own)

		Returns:
			tuple: (list of Diagnostic, pending)
		'''
		now = time.time() if now is None else now
		line = request.before + request.after
		tokens = lex(line)
		start = _mssh_start(tokens)
		if start is None:
			return [], False
		cursor = len(request.before)
		words = tokens[start + 1:]
		roles = assign_roles(words, self.spec)
		states = self.host_states() if states is None else states
		unavailable = read_unavailable(self.directory) if self.directory else frozenset()
		reach = (unavailable,) + self._line_settings(words, roles)
		wanted = []
		found = []
		options = []
		def typing(token):
			return token.start <= cursor <= token.start + len(token.raw)
		for number, (token, (role, option)) in enumerate(zip(words, roles)):
			if role == ROLE_OPTION and option is not None:
				_, attached = self.spec.lookup(token.text)
				value, value_done = attached, not typing(token)
				if attached is None and number + 1 < len(words) and roles[number + 1][0] == ROLE_VALUE:
					value, value_done = words[number + 1].text, not typing(words[number + 1])
				options.append((token, option, _option_name(token.text, attached), value, not typing(token), value_done))
			if typing(token):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(_without_shell_expansions(token, request.shell), states, now, wanted, reach))
				users = _without_shell_expansions(token, request.shell, users=True)
				if users is not None:
					# mssh skips unreachable hosts by the name it runs them under, user@ included: unknown here
					found.extend(item for item in self._host_diagnostics(users, states, now, wanted, reach) if item.kind != 'unreachable')
				try:
					split = _brace_split(token, request.shell, self.unicode)
				except Exception as e:
					# a word of odd braces must not cost the line its other warnings
					_debug('brace warning failed: {!r}'.format(e))
					split = None
				if split is not None:
					found.append(split)
		found.extend(self._option_diagnostics(options))
		def ends_line(token):
			# the cursor at the end of the line's last word: Enter would run the line as it stands
			return token.start + len(token.raw) == cursor and not line[cursor:].strip()
		found.extend(self._command_diagnostics(_mssh_argv(line, tokens, start), typing, ends_line))
		wanted = [host for host in _unique(wanted) if _queueable(host)]
		# pending only once the hosts wait in the queue: then a prober takes them, the one running or
		# one a later query starts (asking again is such a query)
		pending = False
		if probe and wanted and self.directory:
			try:
				queue_probes(self.directory, wanted)
				pending = True
				spawn_probe(self.directory)
			except OSError as e:
				_debug('cannot queue hosts: {!r}'.format(e))
		found.sort(key=lambda item: (DIAGNOSTIC_KINDS.index(item.kind), item.start))
		return found, pending

	def _host_diagnostics(self, token, states, now, wanted, reach):
		'''
		Unknown hosts, range surprises and unreachable hosts in a hosts word. reach is (the hosts
		in mssh's unavailable list, whether they are skipped, the ping expiry, whether the line
		names its own lookup files, the user -u gives).
		'''
		def verdict(host):
			answer = self._verdict(host, states, now, wanted)
			return 'unsure' if answer == 'invalid' and self._mssh_may_know(host, reach) else answer
		def unreachable(host, user, own_user=''):
			return self._unreachable(host, _run_name(host, user, reach[4], own_user), states.get(host), now, reach)
		found = []
		for user, name, (start, end) in _host_parts(token):
			if not name:
				continue
			members = self._host_members(name)
			if members is None:
				if verdict(name) == 'invalid':
					found.append(Diagnostic(start, end, 'unknown', self._unknown_message(name, states, now)))
				else:
					why = unreachable(name, user)
					if why:
						found.append(Diagnostic(start, end, 'unreachable', why))
			elif members:
				members, total, own_users = members
				# an alias can list a host for two users: the host counts once, each run name can be unreachable
				hosts = _unique(members)
				answers = {host: verdict(host) for host in hosts}
				item = self._range_diagnostic(name, hosts, [answers[host] for host in hosts], total, (start, end), states, now, wanted)
				if item is not None:
					found.append(item)
				down = _unique(member for member, own_user in zip(members, own_users)
					if answers[member] != 'invalid' and unreachable(member, user, own_user))
				if down:
					_, more = _punctuation(self.unicode)
					shown = ', '.join(down[:3] + ([more] if len(down) > 3 else []))
					found.append(Diagnostic(start, end, 'unreachable', '{}: {} unreachable ({})'.format(name, len(down), shown)))
		return found

	def _host_members(self, name):
		'''
		(members, how many, the user each member is written with or '') for an alias or a range, the
		members up to RANGE_MEMBERS_LIMIT; None for one host; () for a range that cannot be expanded or
		counted here (letters, hex, _range_count): nothing is said about it. The members of an IPv4 range
		are addresses: they are only pinged, never unknown. Only alias members have users (an env file's
		dbs=postgres@db1). A range makes each name once, as mssh checks it once (n[1-11][1-11] makes n111
		twice); an alias lists a host once per user it is written with (a@node1,b@node1 are two runs of
		node1), and how many counts each host once. A range with an end missing (node[1-]) is one host
		name, as mssh takes it (an invalid one).
		'''
		if _ipv4_range(name):
			members, total = _ipv4_members(name)
			return members, total, [''] * len(members)
		number = self.hosts.alias_index(name)
		if number is not None:
			members = self.hosts.alias_members(number)
			# a@node1,b@node1: two run names (each can be unreachable), one host to count; checked up to
			# the member limit, as a range is
			pairs = _unique(list(zip(members, self.hosts.alias_member_users(number))))[:RANGE_MEMBERS_LIMIT]
			return [member for member, _ in pairs], len(set(members)), [user for _, user in pairs]
		if '[' not in name or _has_open_range(name):
			return None
		total = _range_count(name)
		if total is None:
			return ()
		members = []
		for member in _iter_range(name):
			if len(members) >= RANGE_MEMBERS_LIMIT:
				break
			members.append(member)
		return (members, total, [''] * len(members)) if members != [name] else None

	def _mssh_may_know(self, name, reach):
		'''
		Whether mssh may know a name the prober found nowhere: the line names its own hosts, env or
		config files (mssh reads them at Enter, from the shell's directory), or the name is a variable
		of the shell (the prober may have started from another shell).
		'''
		return reach[3] or _in_environ(name.rsplit('@', 1)[-1].strip().strip('$'))

	def _valid_at_once(self, name):
		'''An IP address or a hosts-file name: valid without DNS.'''
		return bool(self.hosts.sources(name) & SRC_HOSTS_FILE) or _is_ip_address(name)

	def _verdict(self, name, states, now, wanted):
		'''
		What is known about one host: 'valid', 'invalid', 'unsure', or '' (the prober is asked).
		A host whose answer or ping is not fresh goes into wanted.
		'''
		state = states.get(name)
		if self._valid_at_once(name):
			# no DNS needed, only a ping
			if state is None or not state.fresh_ping(now):
				wanted.append(name)
			return 'valid'
		if needs_probe(state, now):
			wanted.append(name)
		return state.fresh_validity(now) if state is not None else ''

	def _option_diagnostics(self, options):
		'''
		Conflicting options: two of one exclusive group (the later one is marked), a value option
		given twice with different values (the earlier one), an option with no effect on this line
		(OPTION_NO_EFFECT). options: (token, OptionSpec, name, value, word typed, value typed) per
		option word, in order.
		'''
		found = []
		on_line = {option.long for _, option, _, _, word_done, _ in options if word_done}
		groups = {}
		values = {}
		for token, option, name, value, word_done, value_done in options:
			if not word_done:
				continue
			span = (token.start, token.start + len(token.raw))
			if option.group:
				first = groups.setdefault(option.group, (option, name))
				if first[0].long != option.long:
					found.append(Diagnostic(span[0], span[1], 'options', '{} cannot be used with {} (mssh stops with an error)'.format(name, first[1])))
			if option.nargs != '0' and not option.repeat and value is not None and value_done:
				earlier = values.get(option.dest)
				if earlier is not None and earlier[1] != value:
					shown = 'the last one' if option.dest in PASSWORD_DESTS else value
					found.append(Diagnostic(earlier[0].start, earlier[0].start + len(earlier[0].raw), 'options',
						'{} given twice: mssh uses {}'.format(earlier[2], shown)))
				values[option.dest] = (token, value, name)
			for entry, kind, others, why in self.no_effect:
				if entry != option.long:
					continue
				if kind == 'with':
					applies = any(other in on_line for other in others)
				else:
					applies = not any(other in on_line or self._on_by_default(other) for other in others)
				if applies:
					found.append(Diagnostic(span[0], span[1], 'options', '{} does nothing: {}'.format(name, why)))
		return found

	def _command_diagnostics(self, argv, typing, ends_line=lambda token: False):
		'''
		Words of a remote command typed unquoted that mssh reads as its own options: mssh parses its
		options among its positionals, so in `mssh web1 journalctl -u slurmd` -u is its --username, and
		a word starting with '-' that names none stops it with an error. After an unquoted command word,
		such words are the remote command's, as the completer takes them; with -f, -s or -G before them
		the command words are paths, and nothing is said. argv: mssh's words (_mssh_argv).

		A word being typed is left alone, except the line's last word when it already is an mssh
		option (ends_line): a remote command's option is often its last word (`mssh all df -h`), and
		Enter would run the line as it stands.
		'''
		abbreviations = _takes_abbreviations(self.spec)
		have_hosts = False
		run = None        # where the unquoted remote command starts in argv
		pending = None    # nargs of an option still taking the words that follow as values
		passed_on = None  # -ea's or -ia's dest: the word may be its value even when it starts with '-'
		paths = False
		read = []
		stop = len(argv)
		for index, token in enumerate(argv):
			if passed_on:
				dest, passed_on = passed_on, None
				if takes_passed_on_value(dest, token.text, self.spec):
					pending = None
					continue
			if token.text == '--':
				stop = index
				break
			if token.text.startswith('-') and any(char in _EXPANDED for char in token.raw):
				verdict, readings = 'unsure', []
			else:
				verdict, readings = read_option_word(token.text, self.spec, abbreviations)
			if verdict == 'positional':
				if pending is not None:
					pending = pending if pending == '+' else None
				elif not have_hosts:
					have_hosts = True
				elif run is None and not token.quoted:
					if paths:
						return []
					run = index
				continue
			pending = None
			if verdict == 'options':
				option, attached, _ = readings[-1]
				if attached is None and option.nargs != '0':
					pending = option.nargs
					passed_on = option.dest if option.dest in PASSED_ON_DESTS else None
				if run is None and any(option.dest in ('file', 'file_sync', 'gather_mode') for option, _, _ in readings):
					paths = True
			if run is not None:
				read.append((token, verdict, readings))
		if not read:
			return []
		# the remote command as it should have been typed; never with a password mssh would take from it
		example = _quoted_command(' '.join(token.raw for token in argv[run:stop]))
		if any(verdict == 'unsure' or any(option.dest in PASSWORD_DESTS for option, _, _ in readings) for _, verdict, readings in read):
			example = None
		dash, _ = _punctuation(self.unicode)
		found = []
		for token, verdict, readings in read:
			if typing(token) and not (verdict == 'options' and ends_line(token)):
				continue
			if verdict == 'unsure' or (verdict == 'unknown' and sys.version_info < (3, 7)):
				continue
			text = token.text
			if verdict == 'options':
				names = []
				for option, _, _ in readings:
					names.append(option.long)
					if option.dest in ('help', 'version'):
						# mssh prints it and exits: the rest of the word is never acted on
						break
				names = _unique(names)
				ends = [end for option, _, end in readings if option.dest in PASSWORD_DESTS]
				subject = text[:min(ends)] if ends else text
				if names == [subject]:
					message = '{} is an mssh option here'.format(subject)
				else:
					message = "{} is mssh's {} here".format(subject, names[0] if len(names) == 1 else '{} and {}'.format(', '.join(names[:-1]), names[-1]))
			else:
				message = '{} is not an mssh option (mssh stops with an error)'.format(text.partition('=')[0])
			message += dash + 'quote the command'
			if example and len(message) + 2 + len(example) <= MAX_MESSAGE:
				message += ': ' + example
			found.append(Diagnostic(token.start, token.start + len(token.raw), 'command', message))
		return found

	def _on_by_default(self, string):
		'''Whether a flag (by its long string) is on without being given: the mssh config turned it on.'''
		option = self.spec.lookup(string)[0]
		return option is not None and option.nargs == '0' and self.flag_sets.get(option.long) is True and self.flag_defaults.get(option.dest, False)

	def _line_settings(self, words, roles):
		'''
		(whether unreachable hosts are skipped, the ping expiry in seconds, whether the line names
		its own lookup files, the user -u gives or '') for the options of a line.

		Skipping: the last of -su / -nsu on the line, else the mssh config's default; --script
		always skips (process_args); --ipmi never does (mssh reaches the host's BMC). Ping expiry:
		$MSSH_COMPLETE_PING_TTL, else mssh's unreachable host expiry (-uhe on the line, else its
		default). Lookup files: --env_file(s), --host_file, --config_file. User: the last -u on the
		line, else the mssh config's default (_line_user).
		'''
		flags = {}
		expiry = None
		lookup = False
		user = None
		for token, (role, option) in zip(words, roles):
			if option is None:
				continue
			if role == ROLE_OPTION and option.dest in LOOKUP_DESTS:
				lookup = True
			if role == ROLE_OPTION and option.nargs == '0' and option.long in self.flag_sets:
				flags[option.dest] = self.flag_sets[option.long]
			elif option.dest == 'unavailable_host_expiry':
				value = token.text if role == ROLE_VALUE else self.spec.lookup(token.text)[1]
				if value is not None and _is_digits(value):
					expiry = int(value)
			elif option.dest == 'username':
				value = token.text if role == ROLE_VALUE else self.spec.lookup(token.text)[1]
				if value is not None:
					user = value
		def flag(dest):
			return flags.get(dest, self.flag_defaults.get(dest, False))
		skipping = (flag('script') or flag('skip_unreachable')) and not flag('ipmi')
		ttl = os.environ.get('MSSH_COMPLETE_PING_TTL', '')
		if _is_digits(ttl) and int(ttl) > 0:
			expiry = int(ttl)
		if expiry is None:
			default = next((option.default for option in self.spec.options if option.dest == 'unavailable_host_expiry'), '')
			expiry = int(default) if _is_digits(default) else 600
		return skipping, expiry, lookup, self._line_user(user)

	def _line_user(self, given):
		'''
		The user -u gives the hosts of a line: given (the last -u value on the line, None without
		one), else the mssh config's default; stripped as run_command_on_hosts strips it.
		'''
		if given is None:
			given = next((option.default for option in self.spec.options if option.dest == 'username'), '')
		return given.strip()

	def _unreachable(self, name, run_name, state, now, reach):
		'''
		Why a host looks unreachable, or None: it failed in a recent mssh run, or stopped answering
		ping. run_name: the name the host has in this run (_run_name), which mssh's list is keyed by;
		ping does not depend on the user.
		'''
		unavailable, skipping, expiry = reach[:3]
		if run_name in unavailable:
			dash, _ = _punctuation(self.unicode)
			return '{}: {}unreachable in a recent mssh run'.format(name, 'will be skipped' + dash if skipping else '')
		if (state is not None and state.fresh_ping(now) == 'silent' and state.answered_at
				and now - state.answered_at <= expiry):
			return '{}: no answer to ping (answered {} min ago)'.format(name, max(1, int((now - state.answered_at) // 60)))
		return None

	def _unknown_message(self, name, states, now):
		dash, _ = _punctuation(self.unicode)
		meant = self._did_you_mean(name, states, now)
		return '{}: unknown host'.format(name) + (dash + 'did you mean {}?'.format(meant) if meant else '')

	def _did_you_mean(self, name, states, now):
		'''
		The one known host name meant instead of name: the same once leading zeros are dropped
		(gpu017 -> gpu17), else one edit away (names of at least 4 characters); None when there is
		no such name or more than one.
		'''
		def possible(candidate):
			state = states.get(candidate)
			return candidate != name and not (state is not None and state.fresh_validity(now) == 'invalid')
		same = [candidate for candidate in _zero_variants(self.hosts.names, name) if possible(candidate)]
		if same:
			return same[0] if len(same) == 1 else None
		if len(name) < 4:
			return None
		close = [candidate for candidate in _one_edit_names(self.hosts.names, name) if possible(candidate)]
		return close[0] if len(close) == 1 else None

	def _range_diagnostic(self, name, members, verdicts, total, span, states, now, wanted):
		'''The warning for a range or an alias with members mssh would reject (verdicts: theirs, in order), or None.'''
		unknown = []
		checked = 0
		for member, verdict in zip(members, verdicts):
			if verdict:
				checked += 1
				if verdict == 'invalid':
					unknown.append(member)
		if not unknown:
			return None
		dash, more = _punctuation(self.unicode)
		if checked < total:
			message = '{}: {} of {} checked, {} unknown so far'.format(name, checked, total, len(unknown))
		else:
			shown = ', '.join(unknown[:3] + ([more] if len(unknown) > 3 else []))
			message = '{}: {} of {} hosts unknown ({})'.format(name, len(unknown), total, shown)
			padded = _padded_range(name)
			if padded is not None:
				# every member is asked about, so the suggestion can appear once the prober answers
				verdicts = [self._verdict(member, states, now, wanted) for member in _iter_range(padded)]
				if all(verdict == 'valid' for verdict in verdicts):
					message += dash + 'did you mean {}?'.format(padded)
		return Diagnostic(span[0], span[1], 'range', message)

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
			if any(char in _QUOTE_SPECIAL[context.open_quote] for char in rest) or _bang_in_double_quotes(request.shell, context.open_quote, rest):
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
			if any(char in _QUOTE_SPECIAL[context.open_quote] for char in rest) or _bang_in_double_quotes(shell, context.open_quote, rest):
				return None
		else:
			rest = _shell_escape(shell, rest, _literal_word(context))
		return Ghost('word', rest, support)

	def _suggest_command_words(self, context, shell, deadline):
		'''
		Suggestion for a command typed as unquoted words: the rest of the most likely past command
		whose words start with the typed ones, each word escaped so the remote command is the same.
		Never a word holding whitespace: mssh would run each command word as its own command.
		'''
		typed = context.command_words
		commands = {}
		features = {}
		for feature, score in score_features(self.knowledges, 'c:' + ' '.join(typed), context.features, deadline).items():
			words = words_as_typed(feature[2:])
			if len(words) >= len(typed) and words[:len(typed) - 1] == typed[:-1] and words[len(typed) - 1].startswith(typed[-1]):
				key = tuple(words)
				commands[key] = commands.get(key, 0.0) + score
				features.setdefault(key, []).append(feature)
		top, share = _top_share(commands)
		if top is None:
			return None
		uses = sum(self._uses(feature) for feature in features[top])
		share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		next_words = {}
		for words, score in commands.items():
			next_words[words[len(typed) - 1]] = next_words.get(words[len(typed) - 1], 0.0) + score
		word, word_share = _top_share(next_words)
		word_share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		rest = _shell_escape(shell, top[len(typed) - 1][len(typed[-1]):], True)
		more = ''.join(' ' + _shell_escape(shell, extra, True) for extra in top[len(typed):])
		if more and share >= T_LINE and all(_joinable(extra) for extra in top[len(typed) - 1:]):
			return Ghost('line', rest + more, share)
		word_rest = _shell_escape(shell, word[len(typed[-1]):], True)
		if word_rest and word_share >= T_WORD and _joinable(word):
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

	def usage(self, context, value, knowledges=None):
		'''(times used, last used unix time) of a value of the current slot, over all knowledge (or the given knowledges).'''
		if context.slot == SLOT_HOSTS:
			features = ['h:' + value, 't:' + value[_last_host_start(value)[1]:]]
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
			for knowledge in self.knowledges if knowledges is None else knowledges:
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
		quote = _quote_command(command, shell) if command is not None else None
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
		ble.sh (flag ble=1) quotes what it inserts itself, as zsh and fish do.
		'''
		literal = (request.shell == 'bash' and request.flags.get('ble') != '1') or request.flags.get('insert') == '1'
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
			# whatever found it: only from fold_start on may it differ from the word in case
			if not _starts(full, prefix, context.icase, context.fold_start) or full in seen:
				continue
			rest = full[len(prefix):]
			if literal:
				if context.open_quote and any(char in _QUOTE_SPECIAL[context.open_quote] for char in rest):
					continue
				if _bang_in_double_quotes(request.shell, context.open_quote, rest):
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
		# option names are matched in any case only when the word starts none as typed, used ones included:
		# readline, finding no candidate in the case typed, puts in the first one's spelling (-q -S became -s)
		icase = context.icase if not _starts_some(self.spec.strings, word) else None
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
				if _starts(string, word, icase):
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
		icase = context.icase
		# in any case from fold_start on: the last host of -X, a path's last part (values that are no paths
		# have no "/")
		start = context.fold_start - context.value_start
		out = [Candidate(feature[len(lead):], 'used before', 'history', score)
			for feature, score in score_features(self.knowledges, lead + word, context.features, deadline, icase, len(lead) + start).items()]
		if dest in PATH_DESTS:
			response.directives.add('files')
		elif dest == 'identity_file':
			response.directives.add('files')
			out.extend(self._key_files(word, icase, start))
		elif dest in USER_DESTS:
			users = set(self.users)
			if os.environ.get('USER'):
				users.add(os.environ['USER'])
			out.extend(Candidate(user, 'user', 'users', PRIOR) for user in users if _starts(user, word, icase, start))
		elif dest == 'skip_hosts':
			# the members that can complete the host being typed (after the last separator and "user@")
			prefix = word[start:]
			out.extend(self._hosts(word, context, deadline, boost=self._members(context.hosts, prefix, icase)))
		elif dest == 'completion':
			out.extend(Candidate(action, '', 'values', PRIOR) for action in COMPLETION_ACTIONS if _starts(action, word, icase, start))
		elif dest == 'encoding':
			out.extend(Candidate(name, '', 'values', PRIOR) for name in ENCODINGS if _starts(name, word, icase, start))
		if option.default and _starts(option.default, word, icase, start):
			out.append(Candidate(option.default, 'default', 'defaults', PRIOR / 2))
		return out

	def _key_files(self, word, icase=None, start=0):
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
			if _starts(text, word, icase, start):
				out.append(Candidate(text, 'key', 'keys', PRIOR))
		return out

	def _members(self, hosts_text, prefix='', icase=None):
		'''
		The host names a hosts argument names, as far as the index knows them (aliases, number
		ranges), that start with prefix (in any case with icase): the first RANGE_MEMBERS_LIMIT of
		them, as for its warnings.
		'''
		import itertools
		members = set()
		for word in split_hosts(hosts_text or ''):
			room = RANGE_MEMBERS_LIMIT - len(members)
			if room <= 0:
				break
			word = word.rpartition('@')[2]
			alias = self.hosts.alias_index(word)
			if alias is not None:
				named = self.hosts.alias_members(alias)
			else:
				# expand_ranges checks each name it makes again (_iter_range raised on a value holding a [);
				# a range past its limit names no member, and costs nothing to find out
				named = expand_ranges(word)
			members.update(itertools.islice((name for name in named if _starts(name, prefix, icase)), room))
		return members

	def _hosts(self, text, context, deadline, boost=frozenset()):
		'''Candidates for a hosts argument whose text so far is text: complete its last host.'''
		cut, start = _last_host_start(text)
		lead, host_prefix = text[:start], text[start:]
		user = text[cut:start - 1] if start > cut else ''
		icase = context.icase
		scores = {}
		for feature, score in score_features(self.knowledges, 't:' + host_prefix, context.features, deadline, icase, 2).items():
			scores[feature[2:]] = score
		out = []
		if not start:
			# one host typed: whole hosts arguments used before
			for feature, score in score_features(self.knowledges, 'h:' + text, context.features, deadline, icase, 2).items():
				if feature[2:] not in scores and len(feature) - 2 <= MAX_HOSTS_TEXT:
					out.append(Candidate(feature[2:], 'used before', 'history', score))
		# with icase only the lookups match the host typed in any case: the names found stay apart (mssh's aliases,
		# its list of unreachable hosts and -X compare them exactly)
		aliases = set()
		for number, name in self.hosts.aliases_with_prefix(host_prefix, icase):
			aliases.add(name)
			out.append(Candidate(lead + name, 'alias, {} hosts'.format(self.hosts.alias_size(number)), 'aliases', scores.get(name, 0.0) + 2 * PRIOR))
		names = set(self.hosts.names_with_prefix(host_prefix, icase))
		# the history's names, which its lookup found starting with the host typed
		names.update(name for name in scores if '[' not in name)
		names -= aliases
		# mssh's list is keyed by the name a host runs as: the user typed with it, else -u's (-X hosts get it too)
		unavailable = self.hosts.unavailable
		line_user = self._line_user(next((value for option, value in reversed(context.options or ())
			if option.dest == 'username' and value is not None), None))
		def unreachable(name):
			# most often none is: then no name needs making
			return bool(unavailable) and _run_name(name, user, line_user) in unavailable
		def host_score(name):
			score = scores.get(name, 0.0) + PRIOR
			if name in boost:
				score += 1.0
			if unreachable(name):
				score *= UNAVAILABLE_PENALTY
			return score
		def single(name):
			return Candidate(lead + name, 'unreachable recently' if unreachable(name) else '', 'hosts', host_score(name))
		# ranges typed before, e.g. node[1-3]: their members are not listed beside them, unless typed
		# on their own before or named by the hosts argument (-X). range_union writes each member
		# once (expanding hundreds of wide ranges one by one outlasted the shells' wait), up to
		# HIDDEN_MEMBERS_LIMIT members.
		ranges = []
		for name, score in scores.items():
			if '[' in name and name not in aliases:
				out.append(Candidate(lead + name, 'used before', 'groups', score))
				ranges.append((-score, name))
		in_ranges = range_union([name for _, name in sorted(ranges)], RANGE_MEMBERS_LIMIT, HIDDEN_MEMBERS_LIMIT)
		names -= in_ranges - set(boost) - set(scores)
		if len(names) <= GROUP_THRESHOLD:
			out.extend(single(name) for name in names)
			return out
		covered = set()
		for group_text, members in self.hosts.groups():
			if _starts(group_text, host_prefix, icase) and len(members) > 1 and names.issuperset(members):
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
		icase = context.icase
		out = []
		if context.mode in ('sync', 'gather'):
			response.directives.add('files')
		if word.count('#') % 2 == 1:
			at = word.rfind('#')
			for magic in MAGIC_STRINGS:
				if _starts(magic, word[at:], icase, max(0, context.fold_start - at)):
					out.append(Candidate(word[:at] + magic, 'replaced per host', 'magic', 1e6))
		# only the word being completed is matched in any case, and of a path in it only the last part
		# (fold_start): the words typed before it and the directories stay as typed
		if context.mode in PATH_MODES:
			for feature, score in score_features(self.knowledges, 'f:' + word, context.features, deadline, icase, 2 + context.fold_start).items():
				out.append(Candidate(feature[2:], 'used before', 'history', score))
		elif context.quoted:
			# whole commands, the current word last
			for feature, score in score_features(self.knowledges, 'c:' + word, context.features, deadline, icase, 2 + context.fold_start).items():
				out.append(Candidate(feature[2:], '', 'history', score))
		elif context.command_words:
			typed = context.command_words[:-1]
			partial = context.command_words[-1]
			# a word holding whitespace would make mssh run each command word as its own command; the
			# current word, unquoted, is the whole prefix
			start = context.fold_start
			if not typed:
				for feature, score in score_features(self.knowledges, 'p:' + partial, context.features, deadline, icase, 2 + start).items():
					if _joinable(feature[2:]):
						out.append(Candidate(feature[2:], '', 'history', score))
			else:
				following = {}
				lead = 'c:' + ' '.join(typed) + ' '
				for feature, score in score_features(self.knowledges, lead + partial, context.features, deadline, icase, len(lead) + start).items():
					words = words_as_typed(feature[2:])
					if len(words) > len(typed) and words[:len(typed)] == typed and _starts(words[len(typed)], partial, icase, start) and _joinable(words[len(typed)]):
						following[words[len(typed)]] = following.get(words[len(typed)], 0.0) + score
				out.extend(Candidate(text, '', 'history', score) for text, score in following.items())
		if context.mode == 'plain' and context.command_words is not None:
			response.delegate = (context.command_word_index, context.command_prefix, list(context.command_words))
		return out

#%% ------------ Protocol ----------------
def parse_flags(text):
	'''A request's flags, space-separated key=value words, as a dict (a word without "=" has the value '').'''
	flags = {}
	for flag in text.split():
		key, _, value = flag.partition('=')
		flags[key] = value
	return flags

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
	flags = parse_flags(parts[3])
	history = [line for line in parts[7].split('\n') if line.strip()]
	return Request(parts[1], parts[4], parts[5], parts[6], parts[2], flags, history)

def _clean(text):
	return _printable(' '.join(str(text).split()))

def format_response(response, nul=True):
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup, then
	\\traw when bash escaping changed the text), a G line (grey text), W lines (warnings:
	start\\tend\\tkind\\tmessage) and an R line (the reason line shown under the prompt), an X line
	for delegation, then E, and a NUL unless nul is False.
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
	for item in response.diagnostics:
		lines.append('W {}\t{}\t{}\t{}'.format(item.start, item.end, item.kind, _clean(item.message)[:MAX_MESSAGE]))
	if response.diagnostics:
		# the line shells show under the prompt, the same everywhere
		lines.append('R ' + _clean(reason_line(response.diagnostics, response.unicode)))
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
	(degraded: options from mssh's parser, shell history, no ranking from mssh history). Before the
	first index is built, the answer is degraded unless the build ends in time (see load_for_query).
	'''
	return engine_for(request, directory, now, deadline).query(request, deadline)

def engine_for(request, directory=Ellipsis, now=None, deadline=None):
	'''
	The engine for a request: the index in directory (as for answer), its history tail, the shell's
	history. deadline limits the wait for a first index (load_for_query).
	'''
	now = time.time() if now is None else now
	if directory is Ellipsis:
		directory = cache_dir()
	index, tail = (None, []) if directory is None else load_for_query(directory, now, deadline)
	knowledges = []
	users = ()
	if index is not None:
		spec = ParserSpec.from_rows([index.row('spec', number) for number in range(index.count('spec'))])
		knowledges.append(SnapshotKnowledge(index, now))
		config = {row[0]: row[1:] for row in (index.row('config', number) for number in range(index.count('config'))) if row}
		users = config.get('users', ())
		flags = (_flag_values(config.get('flag_sets', ())), _flag_values(config.get('flag_defaults', ())))
		no_effect = [(row[0], row[1], tuple(row[3:]), row[2]) for row in (index.row('no_effect', number) for number in range(index.count('no_effect'))) if len(row) >= 3]
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		mssh = _import_mssh()
		parser = mssh.get_parser()
		spec = spec_from_parser(parser)
		flags = flag_settings(parser)
		no_effect = [(option, kind, tuple(others), why) for option, kind, others, why in getattr(mssh, 'OPTION_NO_EFFECT', ())]
	if tail:
		memory = MemoryKnowledge()
		memory.add_history(tail, spec, now)
		knowledges.append(memory)
	if request.history:
		# fish lists its history newest first, the others oldest first
		history = request.history[::-1] if request.shell == 'fish' else request.history
		knowledges.append(shell_history_knowledge(history, spec))
	engine = Engine(spec, knowledges, HostTable(index), users)
	# the locale bash runs in, as its glue measured it
	engine.shell_utf8 = _measured_utf8(request)
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	engine.directory = directory
	engine.flag_sets, engine.flag_defaults = flags
	engine.no_effect = no_effect
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
	# bracketed paste (the shell turned it on): what comes between these was pasted, not typed
	'\x1b[200~': 'paste', '\x1b[201~': 'paste-end',
}
_KEY_NAMES = {'\r': 'enter', '\n': 'enter', '\t': 'tab', '\x7f': 'backspace', '\x08': 'backspace', '\x00': 'ctrl-space'}
# keys the kitty keyboard protocol numbers by the byte legacy terminals send for them, and its modifier bits
_CSI_U_KEYS = {27: '\x1b', 13: '\r', 9: '\t', 127: '\x7f'}
_SHIFT, _ALT, _CTRL, _CAPS_LOCK, _NUM_LOCK = 1, 2, 4, 64, 128

def _legacy_key(params, final):
	'''
	The bytes a terminal sends without the kitty keyboard protocol for a key it sent as CSI params
	final: the protocol's CSI code[:shifted[:base]][;modifiers[:event][;text]] u, or xterm's
	modifyOtherKeys CSI 27;modifiers;code ~. Terminals send these when a program (or a multiplexer
	in between) asked for them and did not turn them off.

	Returns:
		str, or None for any other sequence, a key with no legacy bytes (Ctrl+Enter, Super+A, a
		Shift+key whose character is not given) or a key release
	'''
	fields = params.split(';')
	if final == '~' and len(fields) == 3 and fields[0] == '27':
		fields = [fields[2], fields[1]]
	elif final != 'u' or len(fields) > 3:
		return None
	try:
		codes = [int(code) if code else 0 for code in fields[0].split(':')]
		modifier = (fields[1] if len(fields) > 1 else '').split(':')
		bits = int(modifier[0] or 1) - 1
		release = len(modifier) > 1 and modifier[1] == '3'
		text = ''.join(chr(int(code)) for code in fields[2].split(':')) if len(fields) > 2 else ''
		char = chr(codes[0])
		shifted = chr(codes[1]) if len(codes) > 1 and codes[1] else ''
	except (ValueError, OverflowError):
		return None
	# Num Lock changes none of these keys; Caps Lock only the case of a letter
	bits &= ~_NUM_LOCK
	if release or bits < 0 or bits & ~(_SHIFT | _ALT | _CTRL | _CAPS_LOCK):
		return None
	if codes[0] in _CSI_U_KEYS:
		if bits & _CTRL:
			return None
		key = '\x1b[Z' if codes[0] == 9 and bits & _SHIFT else _CSI_U_KEYS[codes[0]]
	elif bits & _CTRL:
		# the control character, as legacy terminals send Ctrl with a letter, space or @[\]^_?
		if char in (' ', '@'):
			key = '\x00'
		elif char == '?':
			key = '\x7f'
		elif 'a' <= char <= 'z' or '@' <= char <= '_':
			key = chr(ord(char.upper()) - 64)
		else:
			return None
	else:
		if text:
			key = text
		elif bits & _SHIFT and shifted:
			key = shifted
		elif char.isalpha() and char.islower():
			key = char.upper() if bool(bits & _SHIFT) != bool(bits & _CAPS_LOCK) else char
		elif bits & _SHIFT and final == 'u' and not char.isupper():
			# the kitty protocol sends the key Shift was pressed with (xterm the character it made, as
			# in ~ and with upper case letters): what Shift makes of it depends on the keyboard layout
			return None
		else:
			key = char
		# the protocol's own codes (keypad, media and modifier keys) are private-use characters
		if not key.isprintable():
			return None
	return '\x1b' + key if bits & _ALT else key

def decode_keys(data):
	'''
	Split bytes read from a terminal into keys.

	Returns:
		list: (name, raw bytes) pairs. name is a key name ('up', 'enter', 'ctrl-r', 'alt-f', 'esc', 'unknown')
			or, for text, the character itself. A key sent the kitty keyboard protocol's way or by
			modifyOtherKeys has the bytes legacy terminals send for it as raw bytes: what readline
			understands when the editor hands it the key.
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
					sequence = text[index:end + 1]
					legacy = _legacy_key(sequence[2:-1], sequence[-1]) if sequence[1] == '[' and end < len(text) else None
					found = decode_keys(legacy.encode('utf-8')) if legacy is not None else []
					keys.append(found[0] if len(found) == 1 else ('unknown', sequence.encode()))
					index = end + 1
				elif text[index + 1:index + 2] == '\x1b' and text[index + 2:index + 3] not in ('[', 'O'):
					# Esc twice (two presses that arrived together) or Alt+Esc: Esc either way
					keys.append(('esc', b'\x1b\x1b'))
					index += 2
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

# bytes of a paste kept at most: all of it is read (none may reach the shell as typed keys), the rest dropped
PASTE_KEEP = 65536

class Terminal(object):
	'''
	The controlling terminal in raw mode, for the picker and the editor. Restores the mode on exit and on
	SIGTERM / SIGHUP; a resize (SIGWINCH) ends the wait for a key (read_key returns 'resize').
	'''
	def __init__(self, path='/dev/tty'):
		self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
		self._saved = None
		self._handlers = {}
		# a pipe the SIGWINCH handler writes to, so the wait for a key ends: Python would retry an
		# interrupted select() after running the handler
		self._resized = None

	def __enter__(self):
		import signal
		import termios
		import tty
		self._saved = termios.tcgetattr(self.fd)
		for number in (signal.SIGTERM, signal.SIGHUP):
			self._handlers[number] = signal.signal(number, self._interrupted)
		if hasattr(signal, 'SIGWINCH'):
			self._resized = os.pipe()
			for end in self._resized:
				os.set_blocking(end, False)
			self._handlers[signal.SIGWINCH] = signal.signal(signal.SIGWINCH, self._resize)
		# TCSANOW: TCSAFLUSH (the default) would drop keys typed while the program started
		tty.setraw(self.fd, termios.TCSANOW)
		# line breaks as sent: raw mode before Python 3.12 keeps INLCR and IGNCR, and zsh runs its
		# widgets with INLCR on (a CR LF Enter would come as CR CR, two line breaks)
		mode = termios.tcgetattr(self.fd)
		if mode[0] & (termios.INLCR | termios.IGNCR):
			mode[0] &= ~(termios.INLCR | termios.IGNCR)
			termios.tcsetattr(self.fd, termios.TCSANOW, mode)
		return self

	def _interrupted(self, number, frame):
		self.restore()
		raise SystemExit(128 + number)

	def _resize(self, number, frame):
		try:
			os.write(self._resized[1], b'.')
		except OSError:
			# the pipe is full: a resize is waiting already
			pass

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
		# after the handler is gone, which writes to it
		for end in self._resized or ():
			os.close(end)
		self._resized = None
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

	def has_input(self, timeout=0):
		'''Whether more typed keys are waiting, or arrive within timeout seconds.'''
		import select
		return bool(select.select([self.fd], [], [], timeout)[0])

	def read_paste(self, limit=PASTE_KEEP, idle=0.5):
		'''
		After the paste key: the pasted text, read up to the mark that ends the paste and no further
		(keys typed after it stay in the terminal). All of the paste is read, so none of it reaches the
		shell as typed keys, but only its first limit bytes are kept. A paste whose end mark does not
		come within idle seconds of its last byte is taken as ended there.
		'''
		end = b'\x1b[201~'
		kept = bytearray()
		tail = b''
		while tail != end:
			byte = self._byte(idle)
			if byte is None:
				break
			tail = (tail + byte)[-len(end):]
			if len(kept) < limit + len(end):
				kept += byte
		if kept.endswith(end):
			del kept[-len(end):]
		return bytes(kept[:limit]).decode('utf-8', 'replace')

	def read_key(self, timeout=None):
		'''
		The next key typed, as (name, raw bytes) like decode_keys; ('resize', b'') when the terminal
		changed size first (keys typed meanwhile stay for the next reads); None when timeout seconds
		pass first (None: wait forever). Reads that key's bytes and no more: what was typed after it
		stays in the terminal, in order, for whoever reads next (the shell, once the picker or the
		editor is done).
		'''
		import select
		waiting = [self.fd] + ([self._resized[0]] if self._resized else [])
		ready = select.select(waiting, [], [], timeout)[0]
		if self._resized and self._resized[0] in ready:
			try:
				# one report for all the resizes so far
				while os.read(self._resized[0], 64):
					pass
			except OSError:
				pass
			return 'resize', b''
		data = os.read(self.fd, 1) if ready else b''
		if not data:
			return None
		if data == b'\x1b':
			data += self._escape()
		else:
			data += self._utf8_rest(data)
		keys = decode_keys(data)
		if len(keys) == 1:
			return keys[0]
		# Esc again, or Esc and then a key, all at once: what was read cannot go back to the terminal,
		# so it comes with the Esc (the picker closes, the editor hands all of it to readline)
		return ('esc' if keys and keys[0][0] == 'esc' else 'unknown', data)

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
			# Esc Esc [ C: Alt + an arrow on some terminals; Esc Esc alone: Esc pressed twice, or Alt+Esc
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
# characters a paste brings to the filter at most: the filter is matched against every row at every key
PICKER_FILTER_LIMIT = 1000
# seconds: keys that come closer together than this came together (a paste, not typing)
PASTE_GAP = 0.05

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
	'''
	Whether the shell runs in a UTF-8 locale, from LC_ALL, LC_CTYPE and LANG resolved as bash resolves them
	(_locale_variables_utf8): for what bash's glue has not measured (Engine.unicode). Python's own encoding
	says UTF-8 in a C or POSIX locale too: from 3.7 it sets LC_CTYPE to C.UTF-8 in os.environ there (PEP
	538), and 3.15 always runs in UTF-8 mode. The variables are read as the process was started with them
	(_exec_environ), which that change leaves alone; where they cannot be (macOS, the BSDs), an LC_CTYPE of
	C.UTF-8, C.utf8 or UTF-8 in os.environ may be Python's and draws ASCII, whatever LANG says.
	'''
	started = _exec_environ()
	if started is not None:
		return _locale_variables_utf8(started)
	return _locale_variables_utf8(os.environ, coerced=True)

def _exec_environ():
	'''
	The environment this process was started with, as Linux keeps it in /proc/self/environ (setenv,
	which Python's PEP 538 uses, does not change it); None where there is none. A variable set twice
	is its first value, as getenv, the C library's setlocale, os.environ, zsh and fish take it (bash
	takes the last, but its glue measures the locale bash runs in).
	'''
	try:
		with open('/proc/self/environ', 'rb') as f:
			data = f.read()
	except (IOError, OSError):
		return None
	environ = {}
	for item in data.split(b'\0'):
		name, sep, value = item.partition(b'=')
		if sep:
			environ.setdefault(name.decode('utf-8', 'surrogateescape'), value.decode('utf-8', 'surrogateescape'))
	return environ

# the locale categories besides LC_CTYPE: with LANG unset, bash keeps C if the C library refuses any
_OTHER_CATEGORIES = ('LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY', 'LC_MESSAGES', 'LC_PAPER', 'LC_NAME',
	'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION')

def _locale_variables_utf8(environ, coerced=False):
	'''
	Whether bash runs in a UTF-8 locale with these variables, resolved as bash does (bash 4.2, 4.4 and 5.2
	on glibc, checked): LC_ALL if set, C if the C library refuses it; else LANG if set, which it must take
	(else C), LC_CTYPE taking over if it takes that; else LC_CTYPE, C if it refuses any LC_ variable set.
	A missing locale is C: ASCII. coerced: environ may be os.environ after Python's PEP 538, which sets
	LC_CTYPE to C.UTF-8 (C.utf8, UTF-8) where it took C (C, UTF-8 or a missing locale), whatever LANG
	is: with LC_ALL unset, that cannot be told from the operator's own C.UTF-8, and draws ASCII
	(unreadable is worse than plain)
	'''
	def utf8(name):
		return _utf8_codeset(_locale_codeset(name))
	if environ.get('LC_ALL'):
		return utf8(environ['LC_ALL'])
	lang = environ.get('LANG')
	ctype = environ.get('LC_CTYPE')
	if coerced and ctype in ('C.UTF-8', 'C.utf8', 'UTF-8'):
		return False
	if lang:
		if _locale_codeset(lang) is None:
			return False
		if ctype and _locale_codeset(ctype) is not None:
			return utf8(ctype)
		return utf8(lang)
	if any(environ.get(name) and _locale_codeset(environ[name]) is None for name in _OTHER_CATEGORIES):
		return False
	return bool(ctype) and utf8(ctype)

class Picker(object):
	'''
	The Ctrl-R menu as state: a slot tab (candidates for the word at the cursor) and a history tab
	(whole past invocations), a fuzzy filter and a selection. run() draws it below the prompt line.
	'''
	def __init__(self, slot_items, history_items, slot_title='', now=None, unicode=None, warnings=()):
		self.items = {'slot': list(slot_items), 'history': list(history_items)}
		# up to three warnings about the line, shown under the title
		self.warnings = [_printable(text) for text in list(warnings)[:3]]
		self.titles = {'slot': slot_title or 'candidates', 'history': 'history'}
		self.tab = 'slot' if self.items['slot'] else 'history'
		self.query = ''
		self.selected = 0
		self.offset = 0
		self.now = time.time() if now is None else now
		self.unicode = _unicode_terminal() if unicode is None else unicode
		# text typed right behind the Enter that chose: it goes after the choice (apply_pick)
		self.typed_after = ''

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

	def paste(self, text):
		'''
		Add pasted text to the filter. Its line breaks, tabs and other control characters only part
		words (a run of them is one space); escape sequences in it are left out.
		'''
		import re
		text = re.sub('[\\s\\x00-\\x1f\\x7f]+', ' ', strip_escapes(text))
		if not self.query or self.query.endswith(' '):
			text = text.lstrip(' ')
		self.query += text[:max(PICKER_FILTER_LIMIT - len(self.query), 0)]
		self.selected = self.offset = 0

	def _enter_with_keys_behind(self, term, raw):
		'''
		Enter (raw: its bytes) with more keys right behind it: read them all, each within PASTE_GAP of
		the last. Another line break among them makes it a paste the terminal did not mark (bracketed
		paste off): all of it filters, as choosing would leave the rest to the shell, which runs it.
		Else Enter chooses, and the text typed behind it (fast typing, keys a slow link brought
		together) goes after the choice, where the shell would have put it; other keys are left out.
		An LF or NUL right after a CR is the same Enter (CR LF and CR NUL terminals).

		Returns:
			str: 'choose', 'cancel', or None (it was a paste)
		'''
		parts = []
		size = 0
		pasted = False
		first = True
		while term.has_input(PASTE_GAP):
			name, more = term.read_key()
			joined = first and raw == b'\r' and more in (b'\n', b'\x00')
			first = False
			if joined:
				continue
			if name == 'paste':
				text = term.read_paste()
				pasted = True
			elif name == 'enter':
				text = '\n'
				pasted = True
			elif name == 'tab':
				text = '\t'
			elif len(name) == 1 and name >= ' ':
				text = name
			else:
				continue
			if size < PASTE_KEEP:
				parts.append(text)
				size += len(text)
		text = ''.join(parts)
		if pasted:
			self.paste('\n' + text)
			return None
		outcome = self.handle('enter')
		if outcome == 'choose':
			self.typed_after = text.replace('\t', '')
		return outcome

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
		for warning in self.warnings:
			text = fit(' {} {}'.format('⚠' if self.unicode else '!', warning), inner)
			lines.append(vertical + text + ' ' * (inner - text_width(text)) + vertical)
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

		When the terminal changes size, the menu opens again at the new size, from the line's start
		(line given) or the cursor as they were drawn: the terminal keeps what it shows, as readline
		assumes. It closes as cancelled when it no longer fits.

		Returns:
			str: 'choose', 'cancel', or 'unavailable' when the terminal is too small
		'''
		height, width = self._size(term)
		if height < 1 or width < 20:
			return 'unavailable'
		up, row, cursor = self._open(term, line, before, height, width)
		try:
			draw = True
			# A choice in the middle of a paste leaves the rest of it to the shell, which runs it (its
			# line breaks are Enter there): what comes right behind an Enter is looked at first. Not
			# behind one typed ahead (read before the picker first waited for a key) unless text came
			# right before it: keys typed ahead after a choice are for the shell, as they come.
			live = not term.has_input()
			after_text = False
			while True:
				if draw:
					menu = self.render(width - 1, height)
					# from the saved place below the line: between draws the cursor is in the line
					term.write('\x1b8' + ''.join('\r\n' + text + '\x1b[K' for text in menu) + '\x1b8' + cursor)
				name, raw = term.read_key()
				if name == 'resize':
					if line is not None:
						# back to the line's start, as it was drawn
						term.write(('\x1b[{}A'.format(row) if row else '') + '\r')
					height, width = self._size(term)
					up, row, cursor = self._open(term, line, before, height, width)
					# clear what is left of the menu drawn at the old size
					term.write('\r\n\x1b[J')
					if height < 1 or width < 20:
						return 'cancel'
					draw = True
					continue
				if name == 'paste':
					# the terminal marks the paste: all of it filters
					self.paste(term.read_paste())
				elif name == 'enter' and (live or after_text) and term.has_input(PASTE_GAP):
					outcome = self._enter_with_keys_behind(term, raw)
					if outcome:
						return outcome
				else:
					outcome = self.handle(name)
					if outcome:
						return outcome
				after_text = len(name) == 1 and name >= ' '
				# keys already typed are handled before the menu is drawn again
				draw = not term.has_input()
				live = live or draw
		finally:
			term.write('\x1b8\r\n\x1b[J\x1b8' + ('\x1b[{}A'.format(up) if up else '') + ('\r' if line is not None else ''))

	def _size(self, term):
		'''(candidate rows, columns) the menu gets: it fits with at least 1 row and 20 columns.'''
		rows, width = term.size()
		return min(PICKER_ROWS, rows - 4 - len(self.warnings)), width

	def _open(self, term, line, before, height, width):
		'''
		Draw the line when given (see run), make room below it for the menu and save that place.

		Returns:
			tuple: rows from the saved place up to the line's start, the row of the line the cursor is
				on, and the moves from the saved place to the cursor (line given)
		'''
		up = row = 0
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
		lines = max(height, 1) + 2 + len(self.warnings)
		term.write('\n' * lines + '\x1b[{}A\x1b7'.format(lines))
		return up, row, cursor

def reason_line(diagnostics, unicode=None):
	'''The one line shown under the prompt: the first warning, and how many more there are ('' for none).'''
	if not diagnostics:
		return ''
	unicode = _unicode_terminal() if unicode is None else unicode
	more = len(diagnostics) - 1
	return '{} {}{}'.format('⚠' if unicode else '!', diagnostics[0].message, ' (+{} more)'.format(more) if more else '')

def picker_warnings(engine, request):
	'''Up to three warnings about the request's line, for the top of the picker.'''
	try:
		found, _ = engine.diagnose(Request(request.shell, request.before, request.after, ''))
	except Exception as e:
		_debug('diagnostics failed: {!r}'.format(e))
		return []
	return [item.message for item in found[:3]]

def _without_passwords(line, spec):
	'''
	An mssh line with the passwords it gives shown as ***, for the debug log: -p VALUE, -pVALUE, -p=VALUE,
	--password VALUE, the abbreviations mssh took before 6.32, -qpVALUE, the ipmi password's spellings.
	'''
	tokens = lex(line)
	start = _mssh_start(tokens)
	if start is None:
		return line
	words = tokens[start + 1:]
	parts = []
	end = 0
	for token, (role, option) in zip(words, assign_roles(words, spec)):
		if option is None or option.dest not in PASSWORD_DESTS or role not in (ROLE_OPTION, ROLE_VALUE):
			continue
		if role == ROLE_VALUE:
			shown = '***'
		else:
			attached = spec.lookup(token.text)[1]
			if attached is None:
				continue
			shown = token.text[:len(token.text) - len(attached)] + '***'
		parts.append(line[end:token.start] + shown)
		end = token.start + len(token.raw)
	return ''.join(parts) + line[end:]

def _sets_password(words, spec):
	'''Whether mssh words (options, hosts, commands; no program name) give a password option.'''
	return any(option is not None and option.dest in PASSWORD_DESTS for _, option in assign_roles(words, spec))

# the options mssh may record in another form than the line typed for the run: 6.31 and earlier left
# the script timeout (-t 50), 0 and '' values and these options out; it records -T as the timeout,
# -uk and -k DIR as the key found, -s PATH as -f PATH -fs, and (later versions) --config_file absolute
_RECORDED_AS = {'use_script_timeout': ('timeout',), 'use_key': ('identity_file',), 'file_sync': ('file',)}
_RECORDED_LOOSELY = frozenset(('timeout', 'identity_file', 'config_file', 'host_file', 'window_width', 'window_height',
	'single_window', 'no_output', 'success_hosts', 'return_zero', 'encoding', 'diff_display_threshold', 'force_truecolor',
	'debug', 'ipmi_interface_ip_prefix', 'ipmi_username', 'ipmi_args', 'ipmi_method', 'ipmi_retry_lockout_time'))

def _run_options(options, engine):
	'''
	The options of a run that change something, as sorted (dest, value) pairs, whatever their order
	and spelling: a flag by the value it leaves ('on' / 'off') when that is not the default (mssh's
	history has -su on every line), a value ('=' and the value) unless it is the default (mssh leaves
	those out), an option without one by ''.

	Args:
		options (list): (OptionSpec, value or None) pairs
		engine (Engine): Its flag_sets and flag_defaults say what the flags do
	'''
	flags = {}
	pairs = []
	for option, value in options:
		if option.nargs == '0' and option.long in engine.flag_sets:
			flags[option.dest] = engine.flag_sets[option.long]
		elif value is None:
			pairs.append((option.dest, ''))
		elif value != option.default:
			pairs.append((option.dest, '=' + value))
	pairs.extend((dest, 'on' if on else 'off') for dest, on in flags.items() if on != engine.flag_defaults.get(dest, False))
	return tuple(sorted(pairs))

# options with which mssh records a run in no history (-I, --script) or in another file (-hf)
_RECORDED_ELSEWHERE = frozenset(('no_history', 'script', 'history_file'))

def _loose_dests(pairs):
	'''The dests of a typed run's options (_run_options) whose record may differ from them.'''
	dests = set()
	for dest, value in pairs:
		if dest in _RECORDED_AS:
			dests.add(dest)
			dests.update(_RECORDED_AS[dest])
		elif dest in _RECORDED_LOOSELY or value in ('=', '=0'):
			dests.add(dest)
	return dests

def _typed_run(line, engine):
	'''
	(run key, (options, hosts, commands)) of a shell line running mssh, or None when the history tab
	cannot offer it. The run key is (hosts, commands, options as _run_options gives them).
	'''
	if 'mssh' not in line and 'multissh' not in line and 'multiSSH' not in line:
		# most lines run something else: no need to read them
		return None
	tokens = lex(line)
	if not tokens or os.path.basename(tokens[0].text) not in MSSH_NAMES or _has_control(line):
		return None
	words = tokens[1:]
	roles = assign_roles(words, engine.spec)
	if any(option is not None and option.dest in PASSWORD_DESTS for _, option in roles):
		return None
	options, hosts, commands = _collect(words, roles)
	commands = _join_commands(commands)
	return (hosts, tuple(commands), _run_options(options, engine)), (options, hosts, commands)

def _history_items(request, engine, history_lines, name, features):
	'''
	The history tab: the past invocations, those most like the line first, then the newest.

	A run is in mssh's history and, as typed, in the shell's: the shell's lines add the rows and
	the uses mssh's history does not hold (runs with -I, and those it no longer holds).
	HISTORY_LIMIT bounds the rows (lines of mssh's history past it are not read); every line the
	shell sent is. With some of mssh's history unread, a shell line matching none of the rows counts
	only when mssh records it nowhere there (-I, --script, -hf): the index counts the others.

	Returns:
		tuple: (PickItem list, MemoryKnowledge of the runs only the shell's history holds)
	'''
	entries = []   # [features shared with the line, unix time, text, uses]
	numbers = {}   # text -> its number in entries
	parsed = []    # (number in entries, hosts, commands, line) of mssh's history
	unread = False # some of mssh's history is past the rows
	for line in reversed(history_lines):
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		parts = [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']
		text = ' '.join([name] + parts)
		if text in numbers:
			# the same text passed the checks already: count it without parsing it again
			entries[numbers[text]][3] += 1
			continue
		if len(entries) >= HISTORY_LIMIT:
			unread = True
			continue
		if not safe_field(text) or _has_control(text) or _sets_password(lex(fields[2]), engine.spec):
			continue
		entry = parse_history_line(line, engine.spec)
		numbers[text] = len(entries)
		if entry is None:
			entries.append([0, 0, text, 1])
			continue
		parsed.append((len(entries), entry.hosts, tuple(entry.commands), line))
		entries.append([len(features & set(entry.features())), entry.ts, text, 1])
	unrecorded = MemoryKnowledge()
	typed = {}  # run key -> [times in the shell's history, its (options, hosts, commands), its newest line]
	runs = []   # the run keys, newest first
	keys = {}   # line -> run key (None: not offered), so a line typed often is read once
	for line in request.history[::-1] if request.shell != 'fish' else request.history:
		line = line.strip()
		if line not in keys:
			found = _typed_run(line, engine)
			keys[line] = found[0] if found is not None else None
			if found is not None and found[0] not in typed:
				typed[found[0]] = [0, found[1], line]
				runs.append(found[0])
		if keys[line] is not None:
			typed[keys[line]][0] += 1
	# the entries of mssh's history with the hosts and commands of those runs, and their options
	candidates = {}
	wanted = set(key[:2] for key in runs)
	for number, hosts, commands, line in parsed:
		if (hosts, commands) in wanted:
			options = history_options(line.rstrip('\r\n').split('\t')[2], engine.spec)[0]
			candidates.setdefault((hosts, commands), []).append((number, _run_options(options, engine)))
	pools = {}  # the entries some runs' lines count towards -> [times typed, the newest of those runs]
	for key in runs:
		count, parts, line = typed[key]
		bucket = candidates.get(key[:2], ())
		# the record of this run, else one mssh may have written in another form
		found = [number for number, pairs in bucket if pairs == key[2]]
		loose = _loose_dests(key[2]) if not found else ()
		if loose:
			kept = [pair for pair in key[2] if pair[0] not in loose]
			found = [number for number, pairs in bucket if [pair for pair in pairs if pair[0] not in loose] == kept]
		if found:
			pool = pools.setdefault(tuple(found), [0, key])
			pool[0] += count
			continue
		if unread and not any(dest in _RECORDED_ELSEWHERE and value != 'off' for dest, value in key[2]):
			# its record may be past the rows: the index counts it already
			continue
		run_features = make_features(*parts)
		if len(entries) < HISTORY_LIMIT:
			# the newest spelling of a run only the shell's history holds
			entries.append([len(features & set(run_features)), 0, line, count])
		for _ in range(count):
			unrecorded.add(run_features, 0.0)
	for found, (count, key) in pools.items():
		# mssh's history holds this many of the shell's lines; any more are runs it does not hold
		count -= sum(entries[number][3] for number in found)
		if count > 0:
			entries[found[0]][3] += count
			run_features = make_features(*typed[key][1])
			for _ in range(count):
				unrecorded.add(run_features, 0.0)
	order = sorted(range(len(entries)), key=lambda number: (-entries[number][0], -entries[number][1], number))
	return [PickItem(entries[number][2], '', entries[number][3], entries[number][1]) for number in order], unrecorded

def picker_items(request, engine, history_lines, now=None):
	'''
	What the picker offers for a request. A row's uses count runs of mssh: one in mssh's history
	and the shell's is one use, a local command none.

	Returns:
		tuple: (slot items, slot title, history items, word): word is the text before the cursor the
			slot items replace (None when nothing can be framed: the slot tab is empty)
	'''
	now = time.time() if now is None else now
	context = parse_context(request.before, request.after, engine.spec)
	name = 'mssh'
	tokens = lex(request.before)
	if tokens and os.path.basename(tokens[0].text) in MSSH_NAMES:
		name = tokens[0].raw
	features = set(context.features) if context is not None else set()
	history, unrecorded = _history_items(request, engine, history_lines, name, features)
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
		# the shell's history counts only for runs mssh's history does not hold
		counted = [knowledge for knowledge in engine.knowledges if not getattr(knowledge, 'shell', False)] + [unrecorded]
		for candidate in response.candidates:
			value = (candidate.raw or candidate.text)[context.value_start:]
			uses, last = engine.usage(context, value, counted)
			slot.append(PickItem(candidate.text, candidate.description, uses, last))
		title = {SLOT_HOSTS: 'hosts', SLOT_OPTION: 'options'}.get(context.slot, '')
		if context.slot == SLOT_VALUE:
			title = context.option.long
		elif context.slot == SLOT_COMMAND:
			title = 'commands for ' + context.hosts if context.hosts else 'commands'
	return slot, title, history, word

def _bangs_out(text, after_dollar):
	'''Double quoted text (its quotes left out) as bangs_out_of_double_quotes writes it, quotes included.'''
	pieces = ['']
	position = 0
	while position < len(text):
		char = text[position]
		if char == '\\':
			pieces[-1] += text[position:position + 2]
			position += 2
			continue
		# $! is a parameter (zsh also takes flags between: $=!, $#!)
		if char == '!' and text[position + 1:position + 2] not in (' ', '\t', '=') and not pieces[-1].rstrip('=~^#+').endswith('$'):
			pieces.append('')
		else:
			pieces[-1] += char
		position += 1
	if len(pieces) == 1:
		return '"' + text + '"'
	# no empty "" next to a ! (but the one after a $ stays: bash reads $"..." as a translated string)
	return '\\!'.join('"' + piece + '"' if piece or (number == 0 and after_dollar) else '' for number, piece in enumerate(pieces))

def bangs_out_of_double_quotes(line):
	'''
	line with each ! that bash or zsh would expand inside double quotes taken out of them, escaped:
	"a!b" -> "a"\\!"b", "done!" -> "done"\\!. The words mean what they meant. Left as they are: a ! outside
	double quotes, before a blank or =, or in $! (none of which bash expands), and the rest of the line
	from double quotes holding ${, $( or ` on, since the shell reads quotes inside those again.
	'''
	out = []
	index = 0
	while index < len(line):
		char = line[index]
		end = index + 1
		if char == '\\':
			end = index + 2
		elif char == "'" or line.startswith("$'", index):
			# nothing expands in single quotes; in $'...' a backslash escapes the quote
			end = index + (2 if char == '$' else 1)
			while end < len(line) and line[end] != "'":
				end += 2 if char == '$' and line[end] == '\\' else 1
			end += 1
		elif char == '"':
			while end < len(line) and line[end] != '"':
				end += 2 if line[end] == '\\' else 1
			text = line[index + 1:end]
			if end >= len(line) or '`' in text or '$(' in text or '${' in text:
				# where these quotes end, and so how the rest reads, is not sure
				out.append(line[index:])
				break
			out.append(_bangs_out(text, out[-1:] == ['$']))
			index = end + 1
			continue
		out.append(line[index:end])
		index = end
	return ''.join(out)

def apply_pick(request, picker, word, context):
	'''The new line and cursor after a choice: (line, cursor); text typed right behind the Enter that chose follows it.'''
	item = picker.chosen()
	if picker.tab == 'history':
		# a line recorded in double quotes (mssh 6.26 and older) may hold a ! the shell would expand
		text = bangs_out_of_double_quotes(item.text) if request.shell in _BANG_SHELLS else item.text
		return text + picker.typed_after, len(text) + len(picker.typed_after)
	suffix = ' '
	if context is not None and context.open_quote:
		suffix = ('"' if context.open_quote == '"' else "'") + ' '
	elif item.text.endswith('/'):
		suffix = ''
	before = request.before[:len(request.before) - len(word)] + item.text + suffix + picker.typed_after
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
	def __init__(self, text, suggest=None, complete=None, pick=None, diagnose=None, unicode=None):
		self.text = text
		self.cursor = len(text)
		self.prefix = len(text)
		self.suggest = suggest
		self.complete = complete
		self.pick = pick
		self.diagnose = diagnose
		self.ghost = ''
		self._ghost_for = None
		# more typed keys are waiting (set by run): no suggestion is asked for until they are handled
		self.busy = False
		# warnings: spans of the text to underline, the line shown under it, when to ask again (monotonic)
		self.marks = []
		self.reason = ''
		self._warned_for = None
		self._asks = []
		# whether the reason line may hold Unicode; None: as the variables say
		self.unicode = unicode

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
		self.refresh_warnings()
		return None

	def refresh_warnings(self, again=False):
		'''
		Ask for warnings about the line, unless more keys wait or the answer is for this line
		already. While the prober still owes answers (pending), ask again WARNING_ASKS seconds
		after the answer to a key; again: this is one of those asks (the schedule goes on).
		'''
		if self.diagnose is None or self.busy:
			return
		if not again and self._warned_for == (self.text, self.cursor):
			return
		try:
			found, pending = self.diagnose(self.text, self.cursor)
		except Exception as e:
			_debug('warnings failed: {!r}'.format(e))
			found, pending = [], False
		self.marks = [(item.start, item.end) for item in found if 0 <= item.start < item.end <= len(self.text)]
		self.reason = reason_line(found, self.unicode)
		self._warned_for = (self.text, self.cursor)
		if not pending:
			self._asks = []
		elif not again:
			now = time.monotonic()
			self._asks = [now + delay for delay in WARNING_ASKS]

	def _wait(self):
		'''Seconds until warnings are asked for again, or None (wait for a key).'''
		return max(self._asks[0] - time.monotonic(), 0.0) if self._asks else None

	def _marked_text(self):
		'''The text with the warned spans underlined (in red unless NO_COLOR is set).'''
		on = '\x1b[4m' if os.environ.get('NO_COLOR') else '\x1b[4;31m'
		out = []
		position = 0
		for start, end in sorted(self.marks):
			start = max(start, position)
			if start >= end:
				continue
			out.append(self.text[position:start] + on + self.text[start:end] + '\x1b[0m')
			position = end
		out.append(self.text[position:])
		return ''.join(out)

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
		'''
		Draw the prompt's last line, the text (warned spans underlined), the grey suggestion and the
		warning's reason on the row below; leave the cursor at the text's cursor.
		'''
		width = term.size()[1]
		rows, cursor_row, cursor_column, end_column = self.layout(prompt, width)
		ghost = (style + self.ghost + '\x1b[0m') if (style and self.ghost) else ''
		reason = fit(_printable(self.reason), width - 1) if self.reason else ''
		out = []
		if getattr(self, '_row', 0):
			out.append('\x1b[{}A'.format(self._row))
		out.append('\r' + prompt + self._marked_text() + ghost)
		end_row = rows - 1
		if end_column == width:
			# the terminal waits to wrap until the next character: wrap now so moves are exact
			out.append('\r\n' + reason)
			end_row += 1
		elif reason:
			out.append('\x1b[K\r\n' + reason)
			end_row += 1
		out.append('\x1b[J')
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

	def interrupted(self, term, prompt):
		'''
		Leave the screen as bash leaves it after Ctrl-C: the prompt and the text as typed (no grey
		suggestion, no warning), ^C, and the cursor at the start of the next row.
		'''
		term.write(('\x1b[{}A'.format(self._row) if getattr(self, '_row', 0) else '') + '\r' + prompt + self.text + '^C\x1b[J\r\n')
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
		self.refresh_warnings()
		self.draw(term, prompt, style)
		while True:
			key = term.read_key(self._wait())
			if key is None:
				# the prober may have answered by now
				self._asks.pop(0)
				self.refresh_warnings(again=True)
				self.draw(term, prompt, style)
				continue
			name, raw = key
			if name == 'resize':
				# draw again at the new width, from the prompt's row as the old width put it (the terminal
				# keeps what it shows, as readline assumes)
				self.draw(term, prompt, style)
				continue
			self.busy = term.has_input()
			outcome = self.handle(name, raw)
			if outcome is not None:
				if outcome[0] == 'abandon':
					self.interrupted(term, prompt)
				else:
					self.erase(term)
				return outcome
			if not self.busy:
				self.draw(term, prompt, style)

#%% ------------ Shell glue ----------------
# zsh and fish run the picker through this POSIX sh: sh -c START_SCRIPT sh SECONDS PICKER-COMMAND...
# The picker creates MSSH_COMPLETE_CLAIM just before it takes the terminal (_claim_terminal). It is
# given SECONDS to do so: then, or on Ctrl-C while it starts, the script creates it first and stops the
# picker, which has not touched the terminal (a hung file system can keep it from starting, deaf to
# Ctrl-C). mkdir succeeds for one of the two only. Exit status: the picker's, 124 when it was too slow,
# 130 on Ctrl-C. The picker runs in the background of this sh, in the shell's process group: it can
# read the terminal. Its answer goes through a file: a process it leaves behind when stopped cannot
# keep the shell's command substitution open. bash waits for its "ready" line instead (_mssh_complete_start).
START_SCRIPT = r"""limit=$1
shift
dir=$(mktemp -d 2>/dev/null) || exec "$@"
exec 3<&0
MSSH_COMPLETE_CLAIM=$dir/claim "$@" <&3 3<&- >"$dir/answer" &
pid=$!
exec 3<&-
stop() {
	mkdir "$dir/claim" 2>/dev/null && : > "$dir/$1" && kill -9 "$pid"
}
# the sleeper: nothing of it may keep the shell's command substitution open, and Ctrl-C is the
# trap's (bash does not make a background subshell ignore it, as dash and busybox do)
{ trap '' INT; sleep "$limit"; stop late; } </dev/null >/dev/null 2>&1 &
sleeper=$!
trap 'stop stopped' INT
while :; do
	wait "$pid"
	status=$?
	kill -0 "$pid" 2>/dev/null || break
done
kill "$sleeper" 2>/dev/null
[ -e "$dir/stopped" ] && status=130
[ -e "$dir/late" ] && status=124
cat "$dir/answer" 2>/dev/null
rm -rf "$dir"
exit "$status"
"""

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

_mssh_complete_guard() {
	# run "$@", a glue function bash, readline or ble.sh calls, with nocasematch off: the glue's own tests
	# compare exactly (with it on, complete -p's -f passed for -F, and a remote command ran here as its
	# completion function). The shell's setting comes back on every return, also after a command's
	# completion function changed it; after a Ctrl-C cut a call short (bash 5 cuts bind -x commands), at
	# the next prompt (_mssh_complete_heal), else at the next call, unless the shell changed it since.
	# _mssh_complete_operator runs the shell's own code in it. Its variables are prefixed: the shell's
	# code runs inside it. _mssh_complete_held: the shell's setting while a call runs; _mssh_complete_left:
	# the setting the glue last made, noted before the glue turns the shell's off and after it puts the
	# shell's back: a cut between the two finds the shell's setting where the note differs, which the heal keeps
	local _mssh_complete_outer=${_mssh_complete_nocase-} _mssh_complete_was=0 _mssh_complete_rc=0
	if [[ -z $_mssh_complete_outer ]]; then
		_mssh_complete_heal || :
	fi
	shopt -q nocasematch && _mssh_complete_was=1
	# the shell's setting, as the outermost call found it (one inside is called with it off, or as ble.sh set it)
	local _mssh_complete_nocase=${_mssh_complete_outer:-$_mssh_complete_was}
	[[ -n $_mssh_complete_outer ]] || _mssh_complete_held=$_mssh_complete_was
	_mssh_complete_left=0
	shopt -u nocasematch
	"$@" || _mssh_complete_rc=$?
	if (( _mssh_complete_was )); then
		shopt -s nocasematch
	else
		shopt -u nocasematch
	fi
	_mssh_complete_left=$_mssh_complete_was
	if [[ -z $_mssh_complete_outer ]]; then
		_mssh_complete_held=
		_mssh_complete_left=
	fi
	return $_mssh_complete_rc
}

_mssh_complete_read_locale() {
	# how bash, and readline with it, takes characters in the locale it runs in, as request flags: utf8=1
	# when it counts a two-byte UTF-8 character as one and two bytes that are none as two (GB18030, GBK,
	# EUC-KR, EUC-JP and Big5 count both as one), turkic=1 when it lowers I to another letter than i
	# (Turkish: a dotless i). Whatever LC_ALL, LC_CTYPE and LANG name, this is the locale bash took
	local u=$'\xc3\xa9' g=$'\xa1\xa1' i=I turkic=1
	[[ ${i,,} == i ]] && turkic=0
	_mssh_complete_locale="utf8=$(( ${#u} == 1 && ${#g} == 2 )) turkic=$turkic"
}

_mssh_complete_heal() {
	# PROMPT_COMMAND (ble.sh: PRECMD), and the next glue call: a glue call a Ctrl-C cut short left the
	# setting it had made; the shell's comes back, at the prompt before the next command line is read.
	# Where the setting is no longer what the glue left, the shell changed it since: it stays. Left
	# alike by the shell (shopt -u after a cut that left it off) it cannot be told, and comes back
	local status=$? now=0
	if [[ -n ${_mssh_complete_held-} ]]; then
		shopt -q nocasematch && now=1
		if (( now == ${_mssh_complete_left:-0} )); then
			if (( _mssh_complete_held )); then
				shopt -s nocasematch
			else
				shopt -u nocasematch
			fi
		fi
		_mssh_complete_held=
		_mssh_complete_left=
	fi
	return $status
}

_mssh_complete_operator() {
	# run "$@", the shell's own code (a command's completion function, the binding ours took over), in
	# the shell's nocasematch; the glue's comes back after
	local _mssh_complete_rc=0
	if (( ${_mssh_complete_nocase:-0} )); then
		shopt -s nocasematch
		_mssh_complete_left=1
	fi
	"$@" || _mssh_complete_rc=$?
	_mssh_complete_left=0
	shopt -u nocasematch
	return $_mssh_complete_rc
}

_mssh_complete_delegate() {
	# $1: the word bash replaces, $2: index of the current word, $3: text put in front of every
	# result, then the remote command words. The results land in _mssh_complete_delegated.
	local word=$1 cword=$2 prefix=$3 cmd spec func item lead
	# every process substitution below ends with "|| :": bash 4.4 exits a set -e shell after one that failed
	shift 3
	local -a words=("$@") found=() kept=()
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
			_mssh_complete_operator "$func" "$cmd" "$cur" "${words[cword-1]}" >/dev/null 2>&1 || :
			found=(${COMPREPLY[@]+"${COMPREPLY[@]}"})
		else
			while IFS= read -r item; do
				found+=("$item")
			done < <(compgen -f -- "$cur" 2>/dev/null || :)
		fi
	fi
	# the results continue prefix + current word, but bash replaces only its own word, which ends
	# the same and can be shorter (it stops at ":" and "="): drop what comes before that word, as typed.
	# The word itself in any case when the engine matched so (_mssh_complete_icase), as compgen and
	# readline do (stor gives Storage-File): nocasematch on for that test alone
	lead=$prefix$cur
	lead=${lead%"$word"}
	for item in ${found[@]+"${found[@]}"}; do
		item=$prefix$item
		if [[ -n $lead && $item == "$lead"* ]]; then
			item=${item:${#lead}}
		elif [[ -n $lead ]] && (( ${_mssh_complete_icase-0} )) && [[ ${item,,} == "${lead,,}"* ]]; then
			# its text before bash's word is the lead in another case: put in for bash's word, the lead would
			# come twice (Fi:fa.txt for fi:f), and readline's file names would do the same (Fi\:fa.txt)
			_mssh_complete_dropped=1
			continue
		fi
		kept+=("$item")
	done
	if (( ${_mssh_complete_icase-0} )); then
		shopt -s nocasematch
		_mssh_complete_left=1
	fi
	for item in ${kept[@]+"${kept[@]}"}; do
		[[ $item == "$word"* ]] && _mssh_complete_delegated+=("$item")
	done
	shopt -u nocasematch
	_mssh_complete_left=0
	return 0
}

_mssh_complete() {
	# TAB (complete -F)
	_mssh_complete_guard _mssh_complete_tab "$@"
}

_mssh_complete_tab() {
	local cur=$2 resp line item one flags ble=0 files=0 dirs=0 ended=0 delegate=0 _mssh_complete_locale _mssh_complete_dropped=0
	local _mssh_complete_before _mssh_complete_after _mssh_complete_icase=0
	local -a reply=() raws=() delegate_fields=() _mssh_complete_fields=() _mssh_complete_delegated=()
	local -A seen=()
	if (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3 )); then
		_mssh_complete_slice
	else
		_mssh_complete_before=${COMP_LINE:0:COMP_POINT}
		_mssh_complete_after=${COMP_LINE:COMP_POINT}
	fi
	# ble.sh quotes what it inserts, readline does not: ble=1 only while ble.sh is attached (0.4 says so)
	[[ -n ${BLE_VERSION-} && ( -n ${BLE_ATTACHED-} || -z ${BLE_ATTACHED+set} ) ]] && ble=1
	_mssh_complete_read_locale
	flags="nosort=0 ble=$ble term=${TERM-} $_mssh_complete_locale"
	if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
		flags="nosort=1 ${flags#nosort=0 }"
	fi
	# readline's completion-ignore-case is read at every TAB (a bind or a re-read ~/.inputrc changes it), in
	# the subshell writing the request: beside the engine's start, the subshell bind -v needs costs no time.
	# No comment inside: bash 4.2 reads a quote or a parenthesis in a comment in <( ) as code
	IFS= read -r -d '' -t "${MSSH_COMPLETE_TIMEOUT:-0.3}" resp < <(
		{
			local icase=0
			[[ $(bind -v 2>/dev/null) == *'completion-ignore-case on'* ]] && icase=1
			printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$flags icase=$icase" "$_mssh_complete_before" "$_mssh_complete_after" "$cur"
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
						icase) _mssh_complete_icase=1 ;;
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
	if (( ${#COMPREPLY[@]} == 0 && _mssh_complete_dropped )); then
		compopt +o default +o bashdefault 2>/dev/null || :
	fi
	# readline ignoring case cannot tell apart words differing only in case and stops at their common start:
	# when they alone are left (the engine's, a command's own and file names), the one starting with the word
	# in its case goes in, else the first. test's = compares exactly, whatever nocasematch says
	if (( _mssh_complete_icase && ${#COMPREPLY[@]} > 1 )); then
		one=${COMPREPLY[0]}
		for item in "${COMPREPLY[@]}"; do
			if [ "${item,,}" != "${one,,}" ]; then
				one=
				break
			fi
			if [ "${item:0:${#cur}}" = "$cur" ] && [ "${one:0:${#cur}}" != "$cur" ]; then
				one=$item
			fi
		done
		if [ -n "$one" ]; then
			COMPREPLY=("$one")
		fi
	fi
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
	local _mssh_complete_locale
	_mssh_complete_read_locale
	printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$1 term=${TERM-} $_mssh_complete_locale" "$2" "$3" ''
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

_mssh_complete_start() {
	# run the engine's picker or editor ("$@" prints its answer and returns its exit status): wait
	# MSSH_COMPLETE_START_TIMEOUT seconds (2) at most for it to say "ready", just before it takes the
	# terminal, then as long as the operator takes. Sets _mssh_complete_resp to its answer and
	# _mssh_complete_status to its exit status, 124 when it was not ready in time, 130 when Ctrl-C
	# came first. An engine ready too late finds nobody reading and leaves the terminal alone.
	local line= rest= got=142 waited=0 tenths=20 trapped= _mssh_complete_interrupted=0
	_mssh_complete_resp=
	_mssh_complete_status=124
	# in tenths of a second: bash counts in integers
	[[ ${MSSH_COMPLETE_START_TIMEOUT:-2} =~ ^([0-9]*)\.?([0-9]?)[0-9]*$ ]] && tenths=$(( 10#0${BASH_REMATCH[1]} * 10 + 10#0${BASH_REMATCH[2]} ))
	if [[ -z ${BLE_VERSION-} ]]; then
		# Ctrl-C while waiting comes back here (bash would drop the line, and wait for an engine that
		# does not die of it); ble.sh reads Ctrl-C as a key
		trapped=$(trap -p INT)
		trap '_mssh_complete_interrupted=1' INT
	fi
	{
		# in short reads: a trapped Ctrl-C does not end a read. A byte at a time: bash reads a pipe one byte
		# per call, and a read that times out partway through a line loses what it read of it (bash 4.2
		# drops it, later ones keep it for the next read to write over); the rest of the line, written
		# with its first byte, is there without waiting
		while (( got > 128 && !_mssh_complete_interrupted && waited++ < tenths )); do
			IFS= read -r -t 0.1 -n 1 line && got=0 || got=$?
		done
		if (( got == 0 )) && [[ -n $line ]]; then
			IFS= read -r rest || :
			line+=$rest
		fi
		(( got > 128 )) || IFS= read -r -d '' rest || :
	} < <("$@" && status=0 || status=$?; trap '' PIPE; printf 'S %s\n' "$status" 2>/dev/null || :)
	if [[ -z ${BLE_VERSION-} ]]; then
		if [[ -n $trapped ]]; then eval "$trapped"; else trap - INT; fi
	fi
	if [[ $line == ready ]]; then
		# it had the terminal: as cancelled unless it says otherwise
		_mssh_complete_status=1
	elif (( _mssh_complete_interrupted )); then
		_mssh_complete_status=130
		return 0
	elif (( got > 128 )); then
		return 0
	else
		rest=$line$'\n'$rest
	fi
	rest=${rest%$'\n'}
	line=${rest##*$'\n'}
	if [[ $line =~ ^S\ ([0-9]+)$ ]]; then
		_mssh_complete_status=${BASH_REMATCH[1]}
		rest=${rest%"$line"}
	fi
	_mssh_complete_resp=${rest%$'\n'}
	return 0
}

_mssh_complete_run_pick() {
	# the picker, for _mssh_complete_start, on _mssh_complete_pick's line
	_mssh_complete_request "pick=1 ready=1 redraw=1 expand=$_mssh_complete_expand" "$_mssh_complete_before" "$_mssh_complete_after" |
		MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine pick 2>/dev/null
	return "${PIPESTATUS[1]}"
}

_mssh_complete_pick() {
	# the picker for the mssh line in READLINE_LINE; fails when it is unavailable or too slow to start
	_mssh_complete_guard _mssh_complete_pick_now
}

_mssh_complete_pick_now() {
	local _mssh_complete_before _mssh_complete_after _mssh_complete_ps1 _mssh_complete_expand _mssh_complete_resp _mssh_complete_status
	local _mssh_complete_action _mssh_complete_keys
	_mssh_complete_cut
	_mssh_complete_prompt
	_mssh_complete_start _mssh_complete_run_pick
	(( _mssh_complete_status == 0 )) && _mssh_complete_apply "$_mssh_complete_resp"
	# cancelled, or Ctrl-C before it opened: the line stays as it is
	(( _mssh_complete_status <= 1 || _mssh_complete_status == 130 ))
}

_mssh_complete_ctrl_r() {
	# Ctrl-R (a macro: the hook key of keymap $1, then "\C-x\C-y"): the picker on mssh lines, else
	# what Ctrl-R did before
	_mssh_complete_guard _mssh_complete_ctrl_r_key "$@"
}

_mssh_complete_ctrl_r_key() {
	local keymap=$1 previous
	bind -m "$keymap" '"\C-x\C-y": ""'
	_mssh_complete_is_mssh "$READLINE_LINE" && _mssh_complete_pick && return 0
	previous=_mssh_complete_previous_${keymap//-/_}
	previous=${!previous-}
	case $previous in
		x:*) _mssh_complete_operator eval "${previous#x:}" ;;
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
	_mssh_complete_guard _mssh_complete_rearm_now "$?"
}

_mssh_complete_rearm_now() {
	local status=$1 keymap
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
		# bind -X prints '"\C-r": "command"', from bash 5.3 on '"\C-r" "command"'
		[[ $line == '"\C-r": "'*'"' || $line == '"\C-r" "'*'"' ]] || continue
		line=${line#'"\C-r"'}
		line=${line#:}
		line=${line#' "'}
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

_mssh_complete_run_edit() {
	# the editor, for _mssh_complete_start, on _mssh_complete_space's line, told the locale bash runs in
	local _mssh_complete_locale
	_mssh_complete_read_locale
	fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null |
		MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine edit --ready --flags "$_mssh_complete_locale" ${expand[@]+"${expand[@]}"} -- "$READLINE_LINE " 2>/dev/null
	return "${PIPESTATUS[1]}"
}

_mssh_complete_space() {
	# space ("\C-x\C-t\C-x\C-y"): after an mssh name alone, the mssh line editor; else a space
	_mssh_complete_guard _mssh_complete_space_key "$@"
}

_mssh_complete_space_key() {
	local shown _mssh_complete_ps1 _mssh_complete_expand _mssh_complete_action _mssh_complete_keys
	local _mssh_complete_before _mssh_complete_after _mssh_complete_resp _mssh_complete_status
	local -a expand=()
	bind -m emacs '"\C-x\C-y": ""'
	case $READLINE_LINE in
		mssh|mssh3|multissh|multissh3|multiSSH3)
			if (( READLINE_POINT == ${#READLINE_LINE} )); then
				_mssh_complete_prompt
				(( _mssh_complete_expand )) && expand=(--expand)
				_mssh_complete_start _mssh_complete_run_edit
				if (( _mssh_complete_status == 130 )); then
					# Ctrl-C before the editor opened: as in the editor, the line and ^C stay on screen
					shown=${_mssh_complete_ps1##*$'\n'}
					printf '\r%s%s ^C\e[J\r\n' "${shown//[$'\001\002']/}" "$READLINE_LINE"
					READLINE_LINE= READLINE_POINT=0
					return 0
				fi
				if (( _mssh_complete_status == 0 )) && _mssh_complete_apply "$_mssh_complete_resp"; then
					case $_mssh_complete_action in
						# the editor left the line and ^C on screen: readline draws a fresh prompt below
						abandon) READLINE_LINE= READLINE_POINT=0 ;;
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
		_mssh_complete_guard _mssh_complete_ble_ctrl_r
	}

	_mssh_complete_ble_ctrl_r() {
		if _mssh_complete_is_mssh "$_ble_edit_str" && ble/widget/.EDIT_COMMAND _mssh_complete_pick; then
			return 0
		fi
		local previous=_mssh_complete_previous_$_ble_decode_keymap
		[[ -n ${!previous-} ]] && _mssh_complete_operator builtin eval -- "_mssh_complete_ble_call ${!previous}"
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
	blehook/eval-after-load keymap_emacs '_mssh_complete_guard _mssh_complete_ble_bind emacs'
	blehook/eval-after-load keymap_vi '_mssh_complete_guard _mssh_complete_ble_bind vi_imap'

	_mssh_complete_ble_source() {
		# define ble.sh's mssh suggestion source and put it first
		declare -F ble/complete/auto-complete/enter >/dev/null 2>&1 || return 0
		function ble/complete/auto-complete/source:mssh {
			# grey text for mssh lines: 1 lets the next source try, 148 when typing interrupted the query
			_mssh_complete_guard _mssh_complete_ble_ghost
		}
		_mssh_complete_ble_ghost() {
			((_ble_edit_ind == ${#_ble_edit_str})) || return 1
			_mssh_complete_is_mssh "$_ble_edit_str" || return 1
			local request=$_ble_base_run/$$.mssh-complete.request answer=$_ble_base_run/$$.mssh-complete.answer line text= status
			# >|: the files are written again for every question, which > refuses under noclobber
			_mssh_complete_request 'ghost=1 ble=1 nul=0' "$_ble_edit_str" '' >| "$request" 2>/dev/null || return 1
			ble/util/conditional-sync '_mssh_complete_engine query < "$request" >| "$answer" 2>/dev/null' '! ble/decode/has-input' 20 "timeout=${MSSH_COMPLETE_GHOST_TIMEOUT:-300}"
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
	blehook/eval-after-load complete '_mssh_complete_guard _mssh_complete_ble_source'

	_mssh_complete_warn_ranges=()
	_mssh_complete_warn_key=
	_mssh_complete_warn_delays=()

	_mssh_complete_ble_warn_watch() {
		# the finished words of the line ($1) changed: ask for warnings when ble.sh is idle
		local before=${1::_ble_edit_ind} after=${1:_ble_edit_ind} key
		# the line without the word at the cursor, which is still being typed
		key=${before%"${before##*[[:space:]]}"}$'\1'${after#"${after%%[[:space:]]*}"}
		[[ $key == "$_mssh_complete_warn_key" ]] && return 0
		_mssh_complete_warn_key=$key
		# while the prober works, ask again 0.3, 1 and 3 seconds after this answer
		_mssh_complete_warn_delays=(300 700 2000)
		ble/util/idle.cancel _mssh_complete_ble_warn_ask
		ble/util/idle.push _mssh_complete_ble_warn_ask
	}

	_mssh_complete_ble_warn_ask() {
		# idle task: ask the engine about the line, mark the words and show the reason line
		_mssh_complete_guard _mssh_complete_ble_warn_asked
	}

	_mssh_complete_ble_warn_asked() {
		local request=$_ble_base_run/$$.mssh-complete.warn.request answer=$_ble_base_run/$$.mssh-complete.warn.answer
		local line reason= pending=0 status start
		local -a ranges=() starts=()
		if _mssh_complete_is_mssh "$_ble_edit_str"; then
			# >| for noclobber, as for the grey text
			_mssh_complete_request 'diag=1 nul=0' "${_ble_edit_str::_ble_edit_ind}" "${_ble_edit_str:_ble_edit_ind}" >| "$request" 2>/dev/null || return 0
			ble/util/conditional-sync '_mssh_complete_engine query < "$request" >| "$answer" 2>/dev/null' '! ble/decode/has-input' 20 "timeout=${MSSH_COMPLETE_GHOST_TIMEOUT:-300}"
			status=$?
			if ((status == 148)); then
				# typing interrupted: ask again at the next redraw
				_mssh_complete_warn_key=
				return 0
			fi
			((status == 0)) || return 0
			while IFS= read -r line; do
				case $line in
					'W '*)
						_mssh_complete_split "${line:2}"
						# one mark per start, in order
						starts[_mssh_complete_fields[0]]=${_mssh_complete_fields[1]} ;;
					'R '*) reason=${line:2} ;;
					'D '*) [[ " ${line:2} " == *' pending '* ]] && pending=1 ;;
				esac
			done < "$answer"
			for start in "${!starts[@]}"; do
				ranges+=("$start" "${starts[start]}")
			done
		fi
		_mssh_complete_warn_ranges=(${ranges[@]+"${ranges[@]}"})
		ble/textarea#invalidate
		_mssh_complete_ble_warn_info "$reason"
		if ((pending && ${#_mssh_complete_warn_delays[@]})); then
			ble/util/idle.push --sleep "${_mssh_complete_warn_delays[0]}" _mssh_complete_ble_warn_ask
			_mssh_complete_warn_delays=("${_mssh_complete_warn_delays[@]:1}")
		fi
	}

	_mssh_complete_ble_warn_info() {
		# the reason line under the prompt, kept as ble.sh's default info and drawn now (as
		# ble/edit/info/immediate-show does), the cursor left where it was
		local ret pos
		ble/edit/info/set-default text "$1"
		[[ $_ble_edit_info_scene == default ]] && ble/edit/info/.rendering-enabled || return 0
		ble/canvas/panel/save-position
		pos=$ret
		ble/edit/info#panel::render "$_ble_edit_info_panel"
		ble/canvas/panel/load-position "$pos"
		ble/util/buffer.flush
	}

	_mssh_complete_ble_warn_reset() {
		# a new prompt: no warnings left from the last line
		_mssh_complete_warn_ranges=()
		_mssh_complete_warn_key=
		ble/util/idle.cancel _mssh_complete_ble_warn_ask
		ble/edit/info/set-default text ''
	}

	_mssh_complete_ble_warnings() {
		# warnings for mssh lines: an mssh highlight layer marks the words, ble.sh's info line says why
		declare -F ble/highlight/layer:{selection}/declare ble/util/idle.push ble/util/idle.cancel \
			ble/edit/info/set-default ble/edit/info/.rendering-enabled ble/edit/info#panel::render \
			ble/canvas/panel/save-position ble/canvas/panel/load-position ble/util/buffer.flush \
			ble/array#insert-before ble/textarea#invalidate >/dev/null 2>&1 || return 0
		if [[ -n ${NO_COLOR-} ]]; then
			ble/color/defface mssh_warning underline
		else
			ble/color/defface mssh_warning underline,fg=red
		fi
		ble/highlight/layer:{selection}/declare mssh
		function ble/highlight/layer:mssh/update {
			_mssh_complete_guard _mssh_complete_ble_warn_watch "$1"
			local -a sel=(${_mssh_complete_warn_ranges[@]+"${_mssh_complete_warn_ranges[@]}"}) gflags=()
			local ret i
			ble/color/face2g mssh_warning
			for ((i = 0; i < ${#sel[@]} / 2; i++)); do
				gflags[i]=$ret
			done
			ble/highlight/layer:{selection}/update mssh "$@"
		}
		function ble/highlight/layer:mssh/getg {
			ble/highlight/layer:{selection}/getg mssh "$@"
		}
		[[ " ${_ble_highlight_layer_list[*]} " == *' mssh '* ]] || ble/array#insert-before _ble_highlight_layer_list region mssh
		blehook PRECMD+=_mssh_complete_ble_warn_reset
	}
	_mssh_complete_ble_warnings
	blehook PRECMD+=_mssh_complete_heal
elif [[ $- == *i* ]]; then
	# readline counts READLINE_POINT in bytes before bash 5
	_mssh_complete_bytes=0
	(( BASH_VERSINFO[0] < 5 )) && _mssh_complete_bytes=1

	_mssh_complete_keys() {
		# PROMPT_COMMAND, once, at the first prompt: take the keys. Not while the rc file loads: there
		# stderr is often /dev/null, and readline starting then would lose its terminal setup
		_mssh_complete_guard _mssh_complete_take_keys "$?"
	}

	_mssh_complete_take_keys() {
		local status=$1 keymap line previous
		PROMPT_COMMAND=${PROMPT_COMMAND//_mssh_complete_keys;/}
		[[ -o emacs || -o vi ]] || return $status
		for keymap in emacs vi-insert; do
			# take Ctrl-R only when its binding can be called back (and is not already ours)
			if _mssh_complete_previous "$keymap" && [[ $_mssh_complete_found != *'\C-x\C-y"' ]]; then
				printf -v "_mssh_complete_previous_${keymap//-/_}" '%s' "$_mssh_complete_found"
				# a Ctrl-R bound with bind -x (fzf, atuin) is unbound first: when a bind replaces a bind -x
				# key, bash 5.1 drops the command of another bind -x key (our hook key, or the operator's)
				[[ $_mssh_complete_found == x:* ]] && bind -m "$keymap" -r '\C-r'
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
			# what space does, read without grep: the operator's grep alias or function (colours, line
			# numbers) or GREP_OPTIONS would change what it prints
			previous=
			while IFS= read -r line; do
				if [[ $line == '" ": '* ]]; then
					previous=${line#'" ": '}
				fi
			done < <(bind -m emacs -p 2>/dev/null || :)
			# space is ours already when the rc file is sourced again: keep the binding it had before
			if [[ -z $previous && $(bind -m emacs -s 2>/dev/null) == *'" ": "\C-x\C-t\C-x\C-y"'* ]]; then
				previous=${_mssh_complete_space_previous:-self-insert}
			fi
			_mssh_complete_space_previous=$previous
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
	[[ ${PROMPT_COMMAND-} == *_mssh_complete_heal\;* ]] || PROMPT_COMMAND="_mssh_complete_heal;${PROMPT_COMMAND-}"
fi
'''

ZSH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ zsh: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion zsh`. Sourcing it only defines a function and registers it.

_mssh() {
	# without the modules that read the engine's answer: what zsh offers for a command it has no
	# completion for (see the end). An if, not `|| { ...; return }`: ignore_braces and ignore_close_braces
	# read a } after a command on the same line as its argument, and the whole file would not parse
	if ! zmodload zsh/zselect zsh/system zsh/datetime 2>/dev/null; then
		_default "$@"
		return
	fi
	# the options the completion system runs completion functions in, the operator's own among them
	local -A compsys_options
	compsys_options=("${(@kv)options}")
	emulate -L zsh
	local before after flags resp chunk line item name fd kind rest
	local -F end
	local -i remaining files=0 nodefault=0 delegate=0 dcword start matches=$compstate[nmatches]
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
	_mssh_complete_keep_terminal
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
	# no answer (the engine failed, was too slow, or speaks another protocol) offers nothing
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n'$'\0' ]] || resp=
	for line in "${(@f)${resp%$'\0'}}"; do
		kind=${line[1]}
		rest=${line[3,-1]}
		case $kind in
			(D)
				for item in ${=rest}; do
					[[ $item == (files|dirs) ]] && files=1
					[[ $item == nodefault ]] && nodefault=1
				done
				;;
			(C)
				fields=("${(@ps:\t:)rest}")
				texts+=("$fields[1]")
				if [[ -n $fields[2] ]]; then shown+=("$fields[1]  -- $fields[2]"); else shown+=("$fields[1]"); fi
				;;
			(X) fields=("${(@ps:\t:)rest}"); delegate=1; dcword=$fields[1]; dwords=("${(@)fields[3,-1]}") ;;
		esac
	done
	# the completion functions below run in those options again: under zsh's defaults _arguments misreads
	# its specs, and a glob in _files that matches nothing aborts the completion
	for name in ${(k)compsys_options}; do
		[[ $options[$name] == $compsys_options[$name] ]] || options[$name]=$compsys_options[$name]
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
	# nothing offered: what zsh offers for a command it has no completion for, file names (bash's
	# -o default), unless the engine said there is nothing to offer here (nodefault: a password)
	(( compstate[nmatches] > matches || nodefault )) || _default "$@"
	return 0
}

_mssh_complete_register() {
	# precmd: TAB for the mssh names without a completion, once compinit has run (it defines compdef
	# and _comps; a stand-in compdef that queues calls for later is left alone). compinit can run
	# after this file, later in the rc file or after the first prompt (zinit turbo, zsh-defer), and
	# one loading its dump file forgets what was registered before it. A completion set for an mssh
	# name by hand stays.
	emulate -L zsh
	(( $+functions[compdef] )) && [[ ${(t)_comps} == association* ]] || return 0
	local name
	for name in mssh mssh3 multissh multissh3 multiSSH3; do
		(( $+_comps[$name] )) || compdef _mssh $name
	done
}

(( $+functions[compdef] )) && compdef _mssh mssh mssh3 multissh multissh3 multiSSH3

# ---- grey suggestions and the Ctrl-R picker (SP2) ----

_mssh_complete_engine() {
	@ENGINE@ "$@"
}

typeset -g _mssh_complete_start_script=@START@

_mssh_complete_start_pick() {
	# the picker, reading the request on stdin: MSSH_COMPLETE_START_TIMEOUT seconds (2) at most to take
	# the terminal, then as long as the operator takes. 124 when too slow, 130 on Ctrl-C while it
	# starts: see START_SCRIPT in mssh_complete.py
	emulate -L zsh
	local limit=${MSSH_COMPLETE_START_TIMEOUT:-2}
	[[ $limit == (<->|<->.<->|.<->) ]] || limit=2
	command sh -c "$_mssh_complete_start_script" sh "$limit" @ENGINE@ pick
}

_mssh_complete_keep_terminal() {
	# after each `exec {fd}< <(...)`: before zsh 5.8 the process substitution takes the terminal from the
	# shell (Ctrl-C then goes to it, and the shell's next reads can fail with "error on TTY read"); a
	# command run in the foreground hands the terminal back when it ends, as zsh-autosuggestions does
	# (its issue 364)
	(( _mssh_complete_fork )) && [[ -o monitor ]] && command true
	return 0
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
		# Ctrl-C while the picker starts stops it (130), and keeps the line: without a trap of its own
		# (local: emulate -L), zsh would end the widget and drop the line
		trap : INT
		resp=$(_mssh_complete_request 'pick=1 nul=0' "$LBUFFER" "$RBUFFER" | _mssh_complete_start_pick 2>/dev/null)
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
		if (( st <= 1 )); then
			# the menu was drawn over the reason line, which zsh does not draw again: show it (the
			# redraw hook asks anew only when a finished word changed; that answer replaces it)
			[[ -n ${_mssh_complete_warn_reason-} ]] && zle -M -- "$_mssh_complete_warn_reason"
			return 0
		fi
		# Ctrl-C while it started: the line stays as it is. Too slow (124): what Ctrl-R did before
		(( st == 130 )) && return 0
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
	_mssh_complete_keep_terminal
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

_mssh_complete_ghost_unmark() {
	# drop the grey text's highlights, found by their style: zsh moves a highlight along with the text
	# typed before it, so it is no longer where it was put
	[[ -n $_mssh_complete_drawn ]] && region_highlight=("${(@)region_highlight:#<-> <-> ${(b)_mssh_complete_drawn}}")
}

_mssh_complete_ghost_clear() {
	# drop the grey text (inside a widget)
	[[ -n $_mssh_complete_shown ]] || return 0
	POSTDISPLAY=
	_mssh_complete_ghost_unmark
	_mssh_complete_shown=
}

_mssh_complete_ghost_show() {
	# show $1 as grey text after the buffer (inside a widget)
	_mssh_complete_ghost_clear
	[[ -n $1 ]] || return 0
	POSTDISPLAY=$1
	_mssh_complete_shown=$1
	region_highlight+=("$#BUFFER $(( $#BUFFER + $#POSTDISPLAY )) $_mssh_complete_style")
	# the style as zsh reports it, to find the highlight again
	_mssh_complete_drawn=${region_highlight[-1]#<-> <-> }
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
		if (( CURSOR != $#BUFFER )); then
			_mssh_complete_ghost_clear
		elif [[ -n $_mssh_complete_shown && -z ${(M)region_highlight:#<-> <-> ${(b)_mssh_complete_drawn}} ]]; then
			# zsh-syntax-highlighting emptied region_highlight after the key (see _mssh_complete_warn_redraw)
			region_highlight+=("$#BUFFER $(( $#BUFFER + $#POSTDISPLAY )) $_mssh_complete_style")
		fi
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
	_mssh_complete_keep_terminal
	zle -F $_mssh_complete_fd _mssh_complete_ghost_ready
}

_mssh_complete_ghost_handover() {
	# stop drawing grey text: drop ours (not what zsh-autosuggestions shows) and the hooks
	add-zle-hook-widget -d line-pre-redraw _mssh_complete_ghost_redraw
	add-zle-hook-widget -d line-finish _mssh_complete_ghost_finish
	_mssh_complete_ghost_cancel
	[[ -n $_mssh_complete_shown && $POSTDISPLAY == "$_mssh_complete_shown" ]] && POSTDISPLAY=
	_mssh_complete_ghost_unmark
	_mssh_complete_shown= _mssh_complete_last=
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
	# grey text with own widgets (zsh 5.3 and later, a terminal with colours). Not under the operator's
	# sh_glob: zsh's add-zle-hook-widget runs the hooks in the operator's options, and there finds none
	# of them ("No such widget" at every key; a zle-line-init or -finish widget set before stops too)
	[[ -o sh_glob ]] && return 0
	emulate -L zsh
	autoload -Uz is-at-least add-zle-hook-widget
	is-at-least 5.3 || return 0
	[[ -n $TERM && $TERM != dumb ]] || return 0
	zmodload zsh/zleparameter zsh/system 2>/dev/null || return 0
	local widget key
	typeset -g _mssh_complete_fd= _mssh_complete_asked= _mssh_complete_last= _mssh_complete_shown= _mssh_complete_drawn=
	typeset -g _mssh_complete_style=fg=8
	[[ $TERM == *256col* ]] && _mssh_complete_style=fg=244
	(( _mssh_complete_memo )) && _mssh_complete_style+=' memo=mssh-ghost'
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

_mssh_complete_warn_unmark() {
	# drop our marks, found by their style: zsh moves a mark along with the text edited before it, so
	# it is no longer where it was put (from zsh 5.9 the style holds memo=mssh-warn; before, another
	# plugin's highlight in just that style goes too)
	[[ -n $_mssh_complete_warn_drawn ]] && region_highlight=("${(@)region_highlight:#<-> <-> ${(b)_mssh_complete_warn_drawn}}")
	_mssh_complete_warn_drawn=
	_mssh_complete_warn_marks=()
}

_mssh_complete_warn_mark() {
	# draw the last answer's marks: only the word at the cursor changed since, so the marks after it
	# move with the end of the line
	local span
	local -i start end
	for span in "${_mssh_complete_warn_marks[@]}"; do
		start=${span% *} end=${span#* }
		if (( start >= _mssh_complete_warn_cursor )); then
			(( start += $#BUFFER - _mssh_complete_warn_length, end += $#BUFFER - _mssh_complete_warn_length ))
		fi
		region_highlight+=("$start $end $_mssh_complete_warn_style")
	done
	# the style as zsh reports it (fg=red,underline), to find the marks again
	(( $#_mssh_complete_warn_marks )) && _mssh_complete_warn_drawn=${region_highlight[-1]#<-> <-> }
}

_mssh_complete_warn_clear() {
	# drop our marks and the reason line (inside a widget)
	_mssh_complete_warn_unmark
	if [[ -n $_mssh_complete_warn_reason ]]; then
		_mssh_complete_warn_reason=
		zle -M ''
	fi
}

_mssh_complete_warn_cancel() {
	# forget the pending query for warnings
	[[ -n $_mssh_complete_warn_fd ]] || return 0
	zle -F $_mssh_complete_warn_fd 2>/dev/null
	exec {_mssh_complete_warn_fd}<&- 2>/dev/null
	_mssh_complete_warn_fd=
}

_mssh_complete_warn_ask() {
	# ask for warnings about the line, after $1 hundredths of a second
	_mssh_complete_warn_asked=$BUFFER$'\0'$CURSOR
	exec {_mssh_complete_warn_fd}< <(
		(( $1 > 0 )) && zselect -t $1
		_mssh_complete_request 'diag=1 nul=0' "$LBUFFER" "$RBUFFER" | _mssh_complete_engine query 2>/dev/null)
	_mssh_complete_keep_terminal
	zle -F $_mssh_complete_warn_fd _mssh_complete_warn_ready
}

_mssh_complete_warn_redraw() {
	# line-pre-redraw hook: ask for warnings when a finished word changed (zsh keeps the reason line
	# shown by itself: drawing it again here would cover zsh's completion listings)
	emulate -L zsh
	setopt extended_glob
	# the line without the word at the cursor, which is still being typed
	local key=${LBUFFER%%[^[:space:]]#}$'\0'${RBUFFER##[^[:space:]]#}
	if [[ $key == "$_mssh_complete_warn_key" ]]; then
		# zsh-syntax-highlighting empties region_highlight after each key before zsh 5.9 (and before its
		# 0.8, on any zsh): mark again
		[[ -n $_mssh_complete_warn_drawn && -z ${(M)region_highlight:#<-> <-> ${(b)_mssh_complete_warn_drawn}} ]] && _mssh_complete_warn_mark
		return 0
	fi
	_mssh_complete_warn_key=$key
	_mssh_complete_warn_cancel
	# the marks shown stay until the answer, but no longer redrawn: they were placed for other words
	_mssh_complete_warn_marks=()
	if ! _mssh_complete_is_mssh "$BUFFER"; then
		_mssh_complete_warn_clear
		return 0
	fi
	# while the prober works, ask again 0.3, 1 and 3 seconds after this answer
	_mssh_complete_warn_delays=(30 70 200)
	_mssh_complete_warn_ask 0
}

_mssh_complete_warn_ready() {
	# zle -F handler: the engine answered the query for warnings
	emulate -L zsh
	local fd=$1 resp= chunk line reason= pending=0
	local -a marks fields
	while sysread -i $fd chunk 2>/dev/null; do
		resp+=$chunk
	done
	zle -F $fd
	exec {fd}<&-
	_mssh_complete_warn_fd=
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		case $line in
			('W '*)
				fields=("${(@ps:\t:)${line#W }}")
				marks+=("${fields[1]} ${fields[2]}") ;;
			('R '*) reason=${line#R } ;;
			('D '*) [[ " ${line#D } " == *' pending '* ]] && pending=1 ;;
		esac
	done
	zle _mssh_complete_warn_answer -- "$pending" "$reason" "${marks[@]}"
	return 0
}

_mssh_complete_warn_answer() {
	# widget: show the warnings if the line is still the one asked about
	emulate -L zsh
	if [[ $BUFFER$'\0'$CURSOR != "$_mssh_complete_warn_asked" ]]; then
		# keys since the question only changed the word being typed (else the redraw hook asked
		# anew): ask about the line as it is now
		_mssh_complete_warn_ask 0
		return 0
	fi
	local pending=$1 reason=$2 style=underline,fg=red
	shift 2
	[[ -n ${NO_COLOR-} ]] && style=underline
	(( _mssh_complete_memo )) && style+=' memo=mssh-warn'
	_mssh_complete_warn_unmark
	_mssh_complete_warn_marks=("$@")
	_mssh_complete_warn_style=$style
	_mssh_complete_warn_length=$#BUFFER _mssh_complete_warn_cursor=$CURSOR
	_mssh_complete_warn_mark
	# one zle -M in a widget: after a second one zsh draws the line a row too high
	if [[ -n $reason ]]; then
		_mssh_complete_warn_reason=$reason
		zle -M -- "$reason"
	elif [[ -n $_mssh_complete_warn_reason ]]; then
		_mssh_complete_warn_reason=
		zle -M ''
	fi
	if (( pending && $#_mssh_complete_warn_delays )); then
		_mssh_complete_warn_ask $_mssh_complete_warn_delays[1]
		shift _mssh_complete_warn_delays
	fi
	zle -R
}

_mssh_complete_warn_finish() {
	# line-finish hook: no warnings left on a line that was accepted
	emulate -L zsh
	_mssh_complete_warn_cancel
	_mssh_complete_warn_clear
	_mssh_complete_warn_key=
}

_mssh_complete_warn_setup() {
	# warnings under the line (zsh 5.3 and later), with grey text from either source; not under the
	# operator's sh_glob (see _mssh_complete_ghost_setup)
	[[ -o sh_glob ]] && return 0
	emulate -L zsh
	autoload -Uz is-at-least add-zle-hook-widget
	is-at-least 5.3 || return 0
	zmodload zsh/zleparameter zsh/system zsh/zselect 2>/dev/null || return 0
	typeset -g _mssh_complete_warn_fd= _mssh_complete_warn_asked= _mssh_complete_warn_key= _mssh_complete_warn_reason= _mssh_complete_warn_drawn=
	typeset -g _mssh_complete_warn_style=
	typeset -gi _mssh_complete_warn_length=0 _mssh_complete_warn_cursor=0
	typeset -ga _mssh_complete_warn_marks _mssh_complete_warn_delays
	zle -N _mssh_complete_warn_answer
	zle -N _mssh_complete_warn_redraw
	zle -N _mssh_complete_warn_finish
	add-zle-hook-widget line-pre-redraw _mssh_complete_warn_redraw
	add-zle-hook-widget line-finish _mssh_complete_warn_finish
}

_mssh_complete_setup() {
	# precmd, once, at the first prompt (plugins loaded after the mssh block are there by then):
	# Ctrl-R, warnings, and grey text through zsh-autosuggestions when it is loaded, else with own widgets
	add-zsh-hook -d precmd _mssh_complete_setup
	autoload -Uz is-at-least
	typeset -gi _mssh_complete_fork=0 _mssh_complete_memo=0
	is-at-least 5.8 || _mssh_complete_fork=1
	# from zsh 5.9 a highlight can carry a memo: the glue's own are then told apart from other plugins'
	is-at-least 5.9 && _mssh_complete_memo=1
	_mssh_complete_take_ctrl_r
	_mssh_complete_warn_setup
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		_mssh_complete_zas_strategy
	else
		_mssh_complete_ghost_setup
	fi
}

_mssh_complete_zas_strategy() {
	# zsh-autosuggestions asks mssh first (in zsh's options: ksh_arrays would keep only its first strategy)
	emulate -L zsh
	(( ${${=ZSH_AUTOSUGGEST_STRATEGY}[(Ie)mssh]} )) || ZSH_AUTOSUGGEST_STRATEGY=(mssh ${=ZSH_AUTOSUGGEST_STRATEGY:-history})
}

if [[ -o interactive ]]; then
	autoload -Uz add-zsh-hook
	add-zsh-hook precmd _mssh_complete_register
	add-zsh-hook precmd _mssh_complete_setup
fi
'''

# Both fish glue files ask the engine through these (a file defines them again when it loads: the same text)
_FISH_QUERY = r'''function __mssh_complete_request --argument-names flags before after word
	# print a request with flags for the line before and after the cursor, then the history tail
	set -l keep 1000
	set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
	command printf '%s\0' MSSHC1 fish $FISH_VERSION "$flags term=$TERM" "$before" "$after" "$word"
	# the history builtin: the operator's history function or alias (one showing times) would change the lines
	builtin history search -n $keep 2>/dev/null
end
function __mssh_complete_query --argument-names flags before after word
	# print the records of the engine's answer, one per line; status 1, and nothing printed anywhere,
	# when there is no answer within MSSH_COMPLETE_TIMEOUT seconds
	set -l limit 0.3
	set -q MSSH_COMPLETE_TIMEOUT; and set limit $MSSH_COMPLETE_TIMEOUT
	set -l lines
	if command -sq timeout
		set lines (__mssh_complete_request "$flags" "$before" "$after" "$word" | command timeout $limit @ENGINE@ query 2>/dev/null)
	else
		# no coreutils timeout (macOS): sh keeps the time limit. It runs the engine in the background on
		# files (the request read whole first, so fish never waits to write it), and a timer; it prints
		# the answer when the engine ends, or stops it and prints nothing when the timer does. A failure
		# to start the engine is then sh's to report (fish prints its own on the terminal)
		set lines (__mssh_complete_request "$flags" "$before" "$after" "$word" | command sh -c '
			limit=$1
			shift
			cleanup() {
				kill "$engine"
				rm -f "$request" "$answer"
				exit 1
			}
			trap cleanup HUP INT TERM
			request=$(mktemp) && answer=$(mktemp) || cleanup
			(sleep "$limit"; kill "$$") >/dev/null 2>&1 &
			timer=$!
			cat >"$request"
			"$@" <"$request" >"$answer" &
			engine=$!
			wait "$engine"
			kill "$timer"
			cat "$answer"
			rm -f "$request" "$answer"
		' sh $limit @ENGINE@ query 2>/dev/null)
	end
	test (count $lines) -ge 2; and test "$lines[1]" = MSSHC1; and test "$lines[-1]" = E; or return 1
	set -q lines[3]; and printf '%s\n' $lines[2..-2]
	return 0
end'''

def _fish_nested(text, depth):
	'''text indented by depth tabs, to sit inside a glue's blocks.'''
	return '\n'.join('\t' * depth + line if line else line for line in text.split('\n'))

FISH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it only defines functions and registers one.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: register nothing
	case '*'
''' + _fish_nested(_FISH_QUERY, 2) + r'''
		function __mssh_complete
			set -l before (string join \n -- (commandline -cp))
			set -l full (string join \n -- (commandline -p))
			set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
			set -l word (commandline -ct)
			set -l lines (__mssh_complete_query nul=0 "$before" "$after" "$word")
			or begin
				# no answer (slow, failing or missing engine): file names, as bash's default completion gives
				__fish_complete_path "$word"
				return
			end
			set -l files 0
			for line in $lines
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

FISH_KEYS_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish keys: Ctrl-R picker and warnings for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it defines functions; Ctrl-R and space are taken at the first prompt.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: take nothing
	case '*'
		if not set -q __mssh_complete_keys
			set -g __mssh_complete_keys 1
''' + _fish_nested(_FISH_QUERY, 3) + r'''
			set -g __mssh_complete_start_script @START@
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
					# the history builtin: the operator's history function or alias (one showing times) would change the lines
					# MSSH_COMPLETE_START_TIMEOUT seconds (2) at most for the picker to take the terminal, then as
					# long as the operator takes: 124 when too slow, 130 on Ctrl-C while it starts (START_SCRIPT)
					set -l limit 2
					string match -qr '^(\d+|\d+\.\d*|\.\d+)$' -- "$MSSH_COMPLETE_START_TIMEOUT"; and set limit $MSSH_COMPLETE_START_TIMEOUT
					set -l lines (begin
						command printf '%s\0' MSSHC1 fish $FISH_VERSION "pick=1 nul=0 term=$TERM" "$before" "$after" ''
						builtin history search -n $keep 2>/dev/null
					end | command sh -c $__mssh_complete_start_script sh $limit @ENGINE@ pick 2>/dev/null)
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
					# Ctrl-C while it started: the line stays as it is. Too slow (124): what Ctrl-R did before
					test $st -le 1; or test $st -eq 130; and return
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
					# the words of bind's line: -- goes before the name (after it, set keeps a -- as a value)
					eval "set -g -- __mssh_complete_words $line[-1]"
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
			function __mssh_complete_echo
				# print $argv's output under the command line, then redraw the prompt (fish's __fish_echo, which fish 3.3 lacks)
				set -l line (commandline --line)
				string >&2 repeat -N \n --count=(math (commandline | count) - $line + 1)
				$argv >&2
				string >&2 repeat -N \n --count=(math (count (fish_prompt)) - 1)
				string >&2 repeat -N \n --count=(math $line - 1)
				commandline -f repaint
			end
			function __mssh_complete_check
				# after a space: the first warning about an mssh line, printed under it when it changes
				set -l full (string join \n -- (commandline))
				set -l reason
				if __mssh_complete_is_mssh "$full"
					set -l before (string join \n -- (commandline -c))
					set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
					for line in (__mssh_complete_query 'diag=1 nul=0' "$before" "$after" '')
						string match -q 'R *' -- $line; and set reason (string sub -s 3 -- $line)
					end
				end
				test "$reason" = "$__mssh_complete_reason"; and return
				set -g __mssh_complete_reason $reason
				test -n "$reason"; and __mssh_complete_echo printf '%s\n' $reason
			end
			function __mssh_complete_take_space --on-event fish_prompt
				# at the first prompt: space does what it did, then checks the line. Not on fish 3, which
				# inserts nothing for self-insert in a binding that also runs a function
				functions -e __mssh_complete_take_space
				string match -qr '^3\.' -- $FISH_VERSION; and return
				for mode in default insert
					set -l line (bind -M $mode ' ' 2>/dev/null)
					test (count $line) -ge 1; or continue
					string match -q '*__mssh_complete_check*' -- "$line[-1]"; and continue
					eval "set -g -- __mssh_complete_words $line[-1]"
					set -l words $__mssh_complete_words[2..-1]
					set -e __mssh_complete_words
					while set -q words[1]; and string match -q -- '-*' $words[1]
						contains -- $words[1] -M --mode -m --sets-mode; and set -e words[1]
						set -e words[1]
					end
					set -e words[1]
					set -q words[1]; or continue
					bind -M $mode ' ' $words __mssh_complete_check
				end
			end
			function __mssh_complete_new_line --on-event fish_prompt
				# a new prompt: the next warning is printed even if it is the last line's
				set -e __mssh_complete_reason
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

def _zsh_guard(text):
	'''
	The zsh glue as zsh must read it: after its comment lines, read by eval in zsh's own options.

	zsh parses what it sources in the options of the moment, and a .zshrc can set them before the mssh
	block: sh_glob made `(files|dirs)` a parse error, ignore_braces made `exec {fd}< <(...)` run a
	command named {fd} (the shell exited), ksh_arrays kept compdef from running, and aliases were
	expanded into the functions. emulate -L in an anonymous function gives the operator's options back
	when it returns, however loading ended (no_aliases is set apart: zsh 5.0.2 forgets -L when emulate
	is also given -o). Not `emulate zsh -c`: its sticky emulation would switch the options at every
	call of a glue function too, and _mssh must hand over to the completion functions in the options
	it was called with.
	'''
	import re
	head = re.match(r'(?:#[^\n]*\n)*', text).group(0)
	return (head + "# Read in zsh's own options whatever the .zshrc set before it; the .zshrc's options are back after it.\n"
		+ "() {\n\temulate -L zsh\n\tsetopt no_aliases\n\teval '\n" + text[len(head):].replace("'", "'\\''") + "'\n}\n")

def render_glue(shell, command=None):
	'''The glue script for shell, running the engine with command (a list of words).'''
	import shlex
	if shell not in _GLUES:
		raise ValueError('unsupported shell {!r}, use one of {}'.format(shell, ', '.join(SHELLS)))
	command = engine_command() if command is None else command
	quote = _fish_quote if shell.startswith('fish') else shlex.quote
	text = _GLUES[shell].replace('@VERSION@', version).replace('@ENGINE@', ' '.join(quote(word) for word in command))
	text = text.replace('@START@', quote(START_SCRIPT))
	return _zsh_guard(text) if shell == 'zsh' else text

#%% ------------ Printing to a reader that may go ----------------
# the status shells report for a command SIGPIPE ended (128 + 13), as for seq in `seq 100000 | head -1`
SIGPIPE_STATUS = 141

def _discard_stdout():
	'''
	Point stdout, and stderr when it is the same file (2>&1), at devnull, after a write to it failed
	(as the Python docs suggest for a reader that has gone): what is left in the buffer then goes
	nowhere, and the flush at exit does not fail again.
	'''
	try:
		stdout_fd = sys.stdout.fileno()
		fds = [stdout_fd]
		try:
			if os.path.sameopenfile(stdout_fd, sys.stderr.fileno()):
				fds.append(sys.stderr.fileno())
		except (OSError, ValueError, AttributeError):
			pass
		devnull = os.open(os.devnull, os.O_WRONLY)
		try:
			for fd in fds:
				os.dup2(devnull, fd)
		finally:
			os.close(devnull)
	except (OSError, ValueError, AttributeError):
		# not a file descriptor (a caller's own stream): nothing to redirect
		pass

def _flush_stdout():
	'''
	Flush stdout now, in the command rather than at exit, where a failure is out of reach ("Exception
	ignored" and status 120; Python 3.6 and 3.13 even exited 0 when the fish glue could not be written).
	A failure other than a reader gone (a full disk) is raised once: stdout is discarded.
	'''
	if sys.stdout is None:
		return
	try:
		sys.stdout.flush()
	except BrokenPipeError:
		raise
	except OSError:
		_discard_stdout()
		raise

def _quiet_when_stdout_is_gone(command):
	'''
	command, ending as SIGPIPE ends other tools when the reader of its output exits early
	(mssh --completion bash | head -3): no traceback, status SIGPIPE_STATUS.

	stdout is flushed before command returns, also when it exits through argparse (--help): an output
	that fits stdout's buffer would otherwise only fail in the flush at exit.
	'''
	def run(*args, **kwargs):
		try:
			try:
				code = command(*args, **kwargs)
			except SystemExit:
				_flush_stdout()
				raise
			_flush_stdout()
			return code
		except BrokenPipeError:
			_discard_stdout()
			return SIGPIPE_STATUS
	run.__name__, run.__doc__, run.__wrapped__ = command.__name__, command.__doc__, command
	return run

#%% ------------ Install ----------------
RC_BEGIN = '# >>> mssh completion >>>'
RC_BEGIN_CREATED = '# >>> mssh completion (created this file) >>>'
RC_END = '# <<< mssh completion <<<'

class InstallError(Exception):
	'''Install or uninstall stopped without changing the file it names; its args are the lines to print.'''

class NotRegularFile(InstallError):
	'''The rc file is not a regular file: /dev/null (rc files turned off), a FIFO, a device.'''

def _reason(error, path):
	'''What went wrong with path in an OSError, in a few words (naming the file it was about if another one).'''
	if not error.strerror:
		return str(error)
	return error.strerror + (': ' + error.filename if error.filename and error.filename != path else '')

def _replace_file(path, text):
	'''
	Replace the file at path with text, all at once: a write that fails part way (disk full, quota)
	leaves the old file as it was.

	The text goes to a temporary file in the same directory, which then takes the old file's place.
	A symbolic link stays a link: the file it points to is the one replaced. The new file keeps the
	old one's permissions and owner (a file whose owner we may not set is not replaced); ACLs and
	other extended attributes are not copied.

	Raises:
		OSError: nothing was changed; a file we may not write counts, as it did when files were written in place
	'''
	import errno
	import stat
	import tempfile
	target = os.path.realpath(path)
	try:
		old = os.stat(target)
	except FileNotFoundError:
		old = None
	if old is not None and not stat.S_ISREG(old.st_mode):
		# renaming over /dev/null would replace the device with a file
		raise OSError(errno.EINVAL, 'not a regular file')
	if old is not None and not os.access(target, os.W_OK):
		raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
	try:
		fd, temporary = tempfile.mkstemp(prefix='.' + os.path.basename(target).lstrip('.') + '.', suffix='.mssh-tmp', dir=os.path.dirname(target))
	except OSError as error:
		# a directory the user may not write: say so, not the temporary file's name
		raise OSError(error.errno, 'cannot make a file beside it ({})'.format(error.strerror))
	try:
		with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
			f.write(text)
			f.flush()
			if old is None:
				# what creating the file directly would have given it
				mask = os.umask(0o22)
				os.umask(mask)
				mode = 0o666 & ~mask
			else:
				mode = stat.S_IMODE(old.st_mode)
				new = os.fstat(f.fileno())
				if (new.st_uid, new.st_gid) != (old.st_uid, old.st_gid):
					try:
						os.fchown(f.fileno(), old.st_uid, old.st_gid)
					except OSError:
						# another user's file we may write (group-writable): it must stay theirs
						raise PermissionError(errno.EPERM, 'replacing it would change its owner')
			os.fchmod(f.fileno(), mode)
			os.fsync(f.fileno())
		try:
			os.replace(temporary, target)
		except OSError as error:
			# a bind-mounted file (EBUSY, EXDEV) cannot be renamed over
			raise OSError(error.errno, 'cannot replace it ({})'.format(error.strerror))
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

def _append_file(path, text):
	'''
	Append text to the regular file at path in place, as a shell's >> would: links (hard or symbolic),
	bind mounts, owner and attributes stay as they are, and the directory need not be writable.

	A write that fails part way is cut off again, which leaves the file as it was.
	'''
	import errno
	import stat
	data = memoryview(text.encode('utf-8', 'surrogateescape'))
	fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK)
	try:
		info = os.fstat(fd)
		if not stat.S_ISREG(info.st_mode):
			raise OSError(errno.EINVAL, 'not a regular file')
		try:
			while data:
				data = data[os.write(fd, data):]
			os.fsync(fd)
		except BaseException:
			try:
				os.ftruncate(fd, info.st_size)
			except OSError:
				pass
			raise
	finally:
		os.close(fd)

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
	'''
	The major version of the fish on PATH, or None.

	From `fish --version`, which reads no configuration: `fish -c` runs the operator's config.fish and
	conf.d first, which may print, be slow or do things. The line may be translated ("fish, Version
	3.7.1"), and old releases wrote it to stderr: its first number is the version.
	'''
	import re
	import subprocess
	try:
		output = subprocess.run(['fish', '--version'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5).stdout
	except (OSError, subprocess.SubprocessError):
		return None
	found = re.search(r'\b(\d+)\.\d+', output.decode('ascii', 'replace'))
	return int(found.group(1)) if found else None

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
	try:
		os.makedirs(os.path.dirname(path), exist_ok=True)
		_replace_file(path, text)
	except OSError as error:
		raise InstallError('could not write {}: {}'.format(path, _reason(error, path)))
	messages.append('wrote ' + path)
	return True

def _as_written(path):
	'''
	path as text for a file written as UTF-8 (surrogateescape), so that the file holds the bytes the
	path has on disk: under a Latin-1 locale Python decodes them as Latin-1.
	'''
	return os.fsencode(path).decode('utf-8', 'surrogateescape')

def _as_shown(text):
	'''Text written by _as_written, as printed: in the locale's encoding, the bytes on disk again.'''
	return os.fsdecode(text.encode('utf-8', 'surrogateescape'))

def _read_rc(rc):
	'''
	The text of the rc file, or None when there is none.

	Raises:
		NotRegularFile: it is /dev/null, a FIFO or a device (reading a FIFO would wait for a writer)
		InstallError: it cannot be read
	'''
	import stat
	try:
		if not stat.S_ISREG(os.stat(rc).st_mode):
			raise NotRegularFile('did not change {}: not a regular file'.format(_shown(rc)))
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			return f.read()
	except FileNotFoundError:
		return None
	except OSError as error:
		raise InstallError('could not read {}: {}'.format(rc, _reason(error, rc)))

def _shown(rc):
	'''rc as messages name it: with the file it links to, the one that changes.'''
	return '{} (a link to {})'.format(rc, os.path.realpath(rc)) if os.path.islink(rc) else rc

def _write_rc(rc, text, by_hand, append=False):
	'''
	Replace rc with text, or append text to it. by_hand: the lines that tell the operator how to make
	the change when mssh may not.
	'''
	import errno
	try:
		if append:
			_append_file(rc, text)
		else:
			try:
				links = os.stat(rc).st_nlink
			except FileNotFoundError:
				links = 0
			if links > 1:
				# the other name (a dotfiles copy) would keep the old text; writing in place risks the
				# file when the disk is full: the operator edits it (editors write hard-linked files in place)
				raise InstallError('did not change {}: it has {} hard links, which replacing it would split'.format(rc, links), *by_hand)
			_replace_file(rc, text)
	except OSError as error:
		lines = ['could not change {}: {}; it is as it was'.format(rc, _reason(error, rc))]
		# a file mssh may not change: home-manager links rc files into the read-only Nix store, managed
		# dotfiles may be read-only, a bind-mounted one cannot be replaced; a full disk is fixed by
		# freeing space and running this again
		if error.errno in (errno.EACCES, errno.EPERM, errno.EROFS, errno.EBUSY, errno.EXDEV):
			lines += by_hand
		raise InstallError(*lines)

def _rc_block(rc, text):
	'''
	Where the mssh block is in text, rc's contents: (begin marker, start, body start, body end, end), or None.

	Its marker lines are found anywhere in the file, with spaces around them, CRLF line ends, and an
	end marker without a final newline.

	Raises:
		InstallError: the markers are not one begin line followed by one end line (one was deleted,
			or the block copied): mssh can no longer tell its own lines from the user's
	'''
	markers = []
	line_start = number = 0
	while line_start < len(text):
		newline = text.find('\n', line_start)
		line_end = len(text) if newline < 0 else newline + 1
		number += 1
		line = text[line_start:line_end].strip()
		if line in (RC_BEGIN, RC_BEGIN_CREATED, RC_END):
			markers.append((line, number, line_start, line_end))
		line_start = line_end
	if not markers:
		return None
	ends = [marker == RC_END for marker, _, _, _ in markers]
	# one begin line, then one end line
	if ends != [False, True]:
		where = ['{} at line {}'.format('end' if is_end else 'begin', marker[1]) for is_end, marker in zip(ends, markers)]
		where += ['no end'] if not any(ends) else ['no begin'] if all(ends) else []
		raise InstallError('did not change {}: its mssh completion markers ({}) are not one block, so mssh cannot tell its lines from yours'.format(rc, ', '.join(where)),
			'fix them by hand (leave one block or none), then run this again')
	(begin, _, start, body_start), (_, _, body_end, end) = markers
	return begin, start, body_start, body_end, end

def _editor_on(rc):
	'''Whether the mssh block in rc turns the mssh line editor on.'''
	try:
		text = _read_rc(rc)
		found = _rc_block(rc, text) if text is not None else None
	except InstallError:
		# adding the block says what is wrong
		return False
	return found is not None and 'export MSSH_COMPLETE_EDITOR=1' in text[found[2]:found[3]].splitlines()

def _add_rc_block(rc, body, messages):
	'''Append a marked block holding body to rc; a block with other lines (editor on or off) is replaced.'''
	shown = _as_shown(body).split('\n')
	add_by_hand = ['to load it anyway, add these lines to it yourself:', RC_BEGIN] + shown + [RC_END]
	try:
		text = _read_rc(rc)
	except NotRegularFile as error:
		raise InstallError(*(error.args + tuple(add_by_hand)))
	found = _rc_block(rc, text) if text is not None else None
	if found is not None:
		begin, start, body_start, body_end, _ = found
		if text[body_start:body_end].replace('\r\n', '\n') == body + '\n':
			messages.append('{} already loads it'.format(_shown(rc)))
			return
		by_hand = ['to load it anyway, replace lines {} to {} of it (the mssh block) with these yourself:'.format(
			text.count('\n', 0, start) + 1, text.count('\n', 0, body_end) + 1), begin] + shown + [RC_END]
		_write_rc(rc, text[:body_start] + body + '\n' + text[body_end:], by_hand)
		messages.append('updated the mssh block in ' + _shown(rc))
		return
	block = '\n{}\n{}\n{}\n'.format(RC_BEGIN if text is not None else RC_BEGIN_CREATED, body, RC_END)
	# a new block is appended in place: the user's lines are never rewritten, and a write that fails
	# part way could only leave an incomplete block, which is cut off again (or refused next time)
	_write_rc(rc, block, add_by_hand, append=text is not None)
	messages.append('added a block loading it to ' + _shown(rc))

def _remove_rc_block(rc, messages):
	try:
		text = _read_rc(rc)
	except NotRegularFile:
		# nothing mssh wrote can be in it
		return
	found = _rc_block(rc, text) if text is not None else None
	if found is None:
		return
	begin, start, _, body_end, end = found
	by_hand = ['to remove it anyway, delete lines {} to {} of it (the mssh block) yourself'.format(
		text.count('\n', 0, start) + 1, text.count('\n', 0, body_end) + 1)]
	# the line break install put before the block goes with it
	head = text[:start]
	head = head[:-2] if head.endswith('\r\n') else head[:-1] if head.endswith('\n') else head
	text = head + text[end:]
	if begin == RC_BEGIN_CREATED and not text and not os.path.islink(rc):
		try:
			os.unlink(rc)
		except OSError as error:
			raise InstallError('could not remove {}: {}'.format(rc, _reason(error, rc)))
		messages.append('removed ' + rc + ' (mssh had created it)')
	else:
		_write_rc(rc, text, by_hand)
		messages.append('removed the mssh block from ' + _shown(rc))

def _login_text(path):
	'''
	The text of a login file, or None when there is none, or it is not a regular file (a FIFO
	would wait for a writer); raises OSError when it cannot be read.
	'''
	import stat
	try:
		if not stat.S_ISREG(os.stat(path).st_mode):
			return None
	except FileNotFoundError:
		return None
	with open(path, encoding='utf-8', errors='replace') as f:
		return f.read()

def _loads_bashrc(home, text):
	'''Whether a login file's text loads ~/.bashrc: itself, or through a file in home it sources (one level).'''
	import re
	if 'bashrc' in text:
		return True
	for line in text.splitlines():
		if line.lstrip().startswith('#'):
			continue
		# `. ~/.profile`, `source "$HOME/.profile"`, `. "$HOME"/.profile`, `[ -f ~/.profile ] && . ~/.profile`
		for name in re.findall(r'''(?:^|[\s;&|(])(?:\.|source)\s+["']?(?:~|\$HOME|\$\{HOME\})["']?/([^\s"';&|)]+)''', line):
			try:
				sourced = _login_text(os.path.join(home, name))
			except OSError:
				continue
			if sourced is not None and 'bashrc' in sourced:
				return True
	return False

def _bash_login_note(home, rc):
	'''
	A note for when bash login shells (ssh logins, macOS terminals) do not seem to load rc, else None.

	They read the first of ~/.bash_profile, ~/.bash_login and ~/.profile that exists and is readable,
	not ~/.bashrc; most of those load ~/.bashrc (the distributions' own do), but not all.
	'''
	line = '[ -f ~/.bashrc ] && . ~/.bashrc'
	for name in ('.bash_profile', '.bash_login', '.profile'):
		login = os.path.join(home, name)
		if not os.path.exists(login):
			continue
		try:
			text = _login_text(login)
		except PermissionError:
			# bash skips a login file it cannot read
			continue
		except OSError:
			return None
		if text is None or _loads_bashrc(home, text):
			# no telling what a FIFO holds
			return None
		return 'note: bash login shells (ssh logins, macOS terminals) read {}, which does not seem to load {}; for autocomplete there too, add this line to it: {}'.format(login, rc, line)
	return ('note: bash login shells (ssh logins, macOS terminals) read {0}/.bash_profile, .bash_login or .profile, and there is none to load {1};'
		' for autocomplete there too, create {0}/.bash_profile holding: {2}').format(home, rc, line)

def _zsh_rc(home, environ):
	'''
	The .zshrc zsh reads, the one in $ZDOTDIR when that is set (and not empty), else ~/.zshrc; and a
	note when zsh could not say which (else None).

	ZDOTDIR is often set in ~/.zshenv or /etc/zshenv, not always exported, so mssh's environment may
	not hold it: zsh is asked, running only those zshenv files, as every zsh does. Without an answer
	from zsh, the environment's ZDOTDIR is used.
	'''
	import subprocess
	import tempfile
	zdotdir = environ.get('ZDOTDIR')
	why = None
	fd, answer = tempfile.mkstemp(prefix='mssh-zdotdir.')
	os.close(fd)
	try:
		# the answer goes to a file: a zshenv may print, or start a background job that keeps zsh's
		# stdout open long after zsh is done
		process = subprocess.Popen(['zsh', '-c', 'print -r -- "${ZDOTDIR-}" >| "$1"', 'zsh', answer], env=environ,
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		try:
			status = process.wait(timeout=5)
		except subprocess.TimeoutExpired:
			process.kill()
			process.wait()
			why = 'it took over 5 s'
		else:
			with open(answer, 'rb') as f:
				said = f.read()
			if said.endswith(b'\n'):
				zdotdir = os.fsdecode(said[:-1])
			else:
				why = 'it exited with status {}'.format(status) if status else 'it gave no answer'
	except FileNotFoundError:
		why = 'zsh is not on PATH'
	except OSError as error:
		why = 'zsh could not be run: {}'.format(error.strerror or error)
	finally:
		os.unlink(answer)
	rc = os.path.join(zdotdir or home, '.zshrc')
	return rc, (None if why is None else 'note: zsh did not say whether ZDOTDIR is set ({}): using {}'.format(why, rc))

def _home_directory(home, environ):
	'''
	The home directory to install into: home when given, else $HOME, else the user database's.

	Raises:
		InstallError: there is none, or it is / (with HOME empty, expanduser('~') gives '/', and
			install wrote /.bashrc)
	'''
	where = 'HOME'
	if not home:
		home = environ.get('HOME')
	if not home:
		where = 'the user database (HOME is empty)'
		try:
			import pwd
			home = pwd.getpwuid(os.getuid()).pw_dir
		except (ImportError, KeyError):
			raise InstallError('did not change anything: HOME is empty and the user database names no home directory; set HOME and run this again')
	if not home or os.path.realpath(home) == os.path.realpath(os.sep):
		raise InstallError('did not change anything: the home directory from {} is {!r}; set HOME to your home directory and run this again'.format(where, home))
	return home

def _zsh_starts_completion(rc):
	'''Whether rc (comments left out) starts zsh's completion system, which TAB needs: compinit, or a framework that runs it.'''
	import re
	try:
		with open(rc, encoding='utf-8', errors='replace') as f:
			text = ''.join(line for line in f if not line.lstrip().startswith('#'))
	except OSError:
		return False
	return re.search(r'compinit|oh-my-zsh|prezto|zimfw|ZIM_HOME|antigen|zplug|zgen', text) is not None

def _paths(shell, home, environ):
	data = environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share')
	# fish's own configuration directory: $XDG_CONFIG_HOME/fish, else ~/.config/fish
	config = environ.get('XDG_CONFIG_HOME') or os.path.join(home, '.config')
	if shell == 'fish':
		# completions load lazily; the Ctrl-R glue must load at startup: conf.d (written whole, like the rc blocks)
		return {'files': [os.path.join(config, 'fish', 'completions', name + '.fish') for name in MSSH_NAMES],
			'keys': os.path.join(config, 'fish', 'conf.d', 'mssh-complete.fish')}
	if shell == 'zsh':
		# zsh reads .zshrc from $ZDOTDIR when that is set (often in ~/.zshenv), and never reads ~/.zshrc then
		rc, note = _zsh_rc(home, environ)
		return {'files': [os.path.join(data, 'multiSSH3', 'completion.zsh')], 'rc': rc, 'note': note}
	# always from ~/.bashrc: bash-completion's per-user directory only loads where bash-completion
	# runs, which an installed package does not guarantee (stock Debian root shells do not load it)
	return {'files': [os.path.join(data, 'multiSSH3', 'completion.bash')], 'rc': os.path.join(home, '.bashrc')}

def install(shell, home=None, environ=None, command=None, editor=False):
	'''
	Install the glue for shell for the current user. Never overwrites a file mssh did not write.

	An rc file is replaced whole or not at all, and left alone when its mssh markers are not one block.

	Args:
		editor (bool): bash only: also turn on the mssh line editor (MSSH_COMPLETE_EDITOR=1 in the rc block);
			an rc block that already turns it on keeps it on

	Returns:
		tuple: (exit code, list of messages saying what was done)
	'''
	import shlex
	environ = os.environ if environ is None else environ
	try:
		home = _home_directory(home, environ)
	except InstallError as error:
		return 1, list(error.args)
	messages = []
	if shell == 'fish':
		major = _fish_major()
		if major is not None and major < 3:
			return 1, ['fish {} is too old for mssh autocomplete: it needs fish 3.0 or later'.format(major)]
	# paths go into files written as UTF-8 as the bytes they have on disk
	command = [_as_written(word) for word in (engine_command() if command is None else command)]
	text = render_glue(shell, command)
	paths = _paths(shell, home, environ)
	if paths.get('note'):
		messages.append(paths['note'])
	try:
		written = [path for path in paths['files'] if _write_glue(path, text, messages)]
		if paths.get('keys') and written:
			_write_glue(paths['keys'], render_glue('fish-keys', command), messages)
		if paths.get('rc') and written:
			quoted = shlex.quote(_as_written(written[0]))
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
			if shell == 'zsh' and not _zsh_starts_completion(paths['rc']):
				messages.append("TAB needs zsh's completion system, which {0} does not seem to start: if TAB does not complete mssh in a new zsh, add this line to {0}: autoload -Uz compinit && compinit".format(paths['rc']))
			if shell == 'bash':
				note = _bash_login_note(home, paths['rc'])
				if note:
					messages.append(note)
	except InstallError as error:
		return 1, messages + list(error.args)
	return (0 if written else 1), messages

def uninstall(shell, home=None, environ=None):
	'''Remove what install wrote for shell. Returns (exit code, messages).'''
	environ = os.environ if environ is None else environ
	try:
		home = _home_directory(home, environ)
	except InstallError as error:
		return 1, list(error.args)
	messages = []
	paths = _paths(shell, home, environ)
	if paths.get('note'):
		messages.append(paths['note'])
	try:
		for path in paths['files'] + ([paths['keys']] if paths.get('keys') else []):
			if _ours(path):
				try:
					os.unlink(path)
				except OSError as error:
					raise InstallError('could not remove {}: {}'.format(path, _reason(error, path)))
				messages.append('removed ' + path)
		if paths.get('rc'):
			_remove_rc_block(paths['rc'], messages)
	except InstallError as error:
		return 1, messages + list(error.args)
	if len(messages) == (1 if paths.get('note') else 0):
		messages.append('nothing to remove')
	if shell == 'zsh':
		for dump in _zsh_dumps_naming_mssh(home, environ):
			messages.append("zsh's completion dump {0} still maps mssh to _mssh, which is gone: "
				"remove it (rm {0}) and zsh makes a new one".format(dump))
	return 0, messages

def _zsh_dumps_naming_mssh(home, environ):
	'''
	The zsh completion dumps (compinit's .zcompdump, oh-my-zsh's .zcompdump-HOST-VERSION) that map mssh
	to _mssh. A dump written while the glue was loaded keeps that after it is removed, and zsh then
	answers TAB with "command not found: _mssh". They are zsh's: they are named, not changed.
	'''
	candidates = [environ.get('ZSH_COMPDUMP')]
	for directory in (environ.get('ZDOTDIR'), home):
		try:
			names = sorted(os.listdir(directory)) if directory else []
		except OSError:
			names = []
		candidates.extend(os.path.join(directory, name) for name in names
			if name.startswith('.zcompdump') and not name.endswith('.zwc'))
	found = []
	for path in candidates:
		if not path or path in found:
			continue
		try:
			with open(path, encoding='utf-8', errors='replace') as dump:
				if "'_mssh'" in dump.read(4 << 20):
					found.append(path)
		except OSError:
			pass
	return found

def prepare_index():
	'''
	Build the index now, for `mssh --completion install`: the first TAB in a new shell then answers
	from it instead of starting the build. A failure does not fail the install. Returns the message.
	'''
	directory = cache_dir()
	if directory is None:
		return 'no private runtime directory for the completion index: TAB offers options and shell history only'
	try:
		return 'built the completion index ' + build_index(directory)
	except Exception as e:
		_debug('install: rebuild failed: {!r}'.format(e))
		return 'could not build the completion index now ({}): the first TAB tries again'.format(e)

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
		if shell not in SHELLS and len(values) == 2:
			print('mssh: autocomplete is for bash, zsh and fish, not {}'.format(shell), file=sys.stderr)
			return 2
		if shell not in SHELLS:
			print('mssh: cannot tell which shell to set up, name it: mssh --completion {} bash|zsh|fish'.format(action), file=sys.stderr)
			return 2
		if editor and shell != 'bash':
			print('mssh: the mssh line editor is for bash only', file=sys.stderr)
			return 2
		code, messages = install(shell, editor=editor) if action == 'install' else uninstall(shell)
		if action == 'install' and code == 0:
			messages.append(prepare_index())
		for message in messages:
			print(message)
		return code
	print('usage: mssh --completion bash|zsh|fish | install [SHELL] [editor] | uninstall [SHELL]', file=sys.stderr)
	return 2

# as main is: mssh --completion calls this directly, not through main
completion_command = _quiet_when_stdout_is_gone(completion_command)

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

def simulate_slot(engine, before, after, intended, quoted=False, policy='bash', shell='zsh', equivalents=()):
	'''
	Simulate an operator typing intended after before (with after behind the cursor), using TAB.

	The operator types a character at a time and presses TAB whenever it inserts the intended
	continuation. An appended space or quote that the operator then has to delete costs one key.
	equivalents are texts that do what intended does (the other strings of an option): a candidate
	that is one of them ranks as intended does, and a TAB toward one is taken, the operator typing
	on to its end.

	Returns:
		dict: keys, chars, rank (of intended at the start, 0 if absent), visited and divergent
			(positions where TAB would insert something unwanted), altered (candidates not
			extending what was typed: must stay 0), suffix_cost
	'''
	result = {'keys': 0, 'chars': len(intended), 'rank': 0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0}
	targets = [intended] + [text for text in equivalents if text != intended]
	target = intended
	position = 0
	while position < len(target):
		typed = target[:position]
		response = engine.query(Request(shell, before + typed, after, typed))
		candidates = response.candidates
		result['visited'] += 1
		if position == 0:
			for number, candidate in enumerate(candidates):
				if candidate.text in targets:
					result['rank'] = number + 1
					break
		result['altered'] += sum(1 for candidate in candidates if not candidate.text.startswith(typed))
		inserted, suffix = _tab(candidates, typed, policy, quoted, 'nospace' in response.directives)
		if inserted and not target.startswith(typed + inserted):
			target = next((text for text in targets if text.startswith(typed + inserted)), target)
		remaining = target[position:]
		if inserted and remaining.startswith(inserted):
			result['keys'] += 1
			position += len(inserted)
			if suffix and position < len(target):
				result['keys'] += 1
				result['suffix_cost'] += 1
			continue
		if inserted:
			result['divergent'] += 1
		result['keys'] += 1
		position += 1
	return result

def _quote_command(command, shell):
	'''The quote char for typing command inside quotes in shell, or None when that would need escapes.'''
	if not any(char in command for char in '"\\$`') and not _bang_in_double_quotes(shell, '"', command):
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
		# the replay types as an operator does in bash
		quote = _quote_command(command, 'bash')
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
		if commands and _quote_command(commands[0], 'bash') == '"':
			cases.append(('command', head + entry.hosts + ' "', '', commands[0], True, ''))
	for number, (_, value, name) in enumerate(options):
		others = ' '.join(['mssh'] + option_texts[:number] + option_texts[number + 1:]) + ' '
		rest = (' ' + entry.hosts + tail) if entry.hosts else ''
		cases.append(('option', others + '-', rest, name[1:], False, ''))
		if value and not any(char in value for char in ' \'"\\$`\t'):
			ahead = ((' ' + entry.hosts) if entry.hosts else '') + first_command if plain else ''
			cases.append(('value', others + name + ' ', rest, value, False, ahead))
	return cases

def _newest(items, limit):
	'''The last limit items (the newest of a history), none when limit is 0 or less.'''
	return items[-limit:] if limit > 0 else []

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
	replay = _newest([number for number, entry in enumerate(entries) if entry.ts >= since], limit)
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
			equivalents = ()
			if slot == 'option':
				# every string of the option typed does what it does (-u, --username): offering another
				# is no miss. Strings of one action, not of one dest: -su and -nsu share their dest
				option, _ = spec.lookup('-' + intended)
				if option is not None:
					equivalents = tuple(string[1:] for string in option.strings)
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
				result = simulate_slot(engine, before, after, intended, quoted, policy, equivalents=equivalents)
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

def diagnostics_replay(lines, spec, validity, hosts=None, now=None):
	'''
	Replay history lines through the warnings. validity(name) -> 'valid', 'invalid' or 'unsure'
	stands in for the prober (asked once per host); there is no ping and no unavailable list.

	Returns:
		dict: lines (replayed), warned (kind -> lines with such a warning), unknown (host -> {'lines':
			lines naming it, 'meant': the host suggested or None}), checked (verdict -> hosts)
	'''
	now = time.time() if now is None else now
	engine = Engine(spec, [], hosts)
	verdicts = {}

	class Answers(object):
		'''host -> HostState, as the prober would have found it: validity(name), could not ping.'''
		def get(self, name, default=None):
			if name not in verdicts:
				verdicts[name] = validity(name)
			return HostState(verdicts[name], now, 'none', now)

	answers = Answers()
	report = {'lines': 0, 'warned': {kind: 0 for kind in DIAGNOSTIC_KINDS}, 'unknown': {}, 'checked': {}}
	for line in lines:
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		text = ' '.join(['mssh'] + [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']) + ' '
		found, _ = engine.diagnose(Request('bash', text, '', ''), probe=False, now=now, states=answers)
		report['lines'] += 1
		for kind in set(item.kind for item in found):
			report['warned'][kind] += 1
		for item in found:
			if item.kind == 'unknown':
				name = item.message.split(':', 1)[0]
				entry = report['unknown'].setdefault(name, {'lines': 0, 'meant': engine._did_you_mean(name, answers, now)})
				entry['lines'] += 1
	for verdict in verdicts.values():
		report['checked'][verdict] = report['checked'].get(verdict, 0) + 1
	return report

def format_diagnostics_report(report):
	'''The diagnostics replay as text: what was checked, which lines would warn, the hosts mssh would reject.'''
	checked = report['checked']
	out = ['warnings over {} history lines (DNS, no ping)'.format(report['lines']),
		'  hosts checked: {} (valid {}, unsure {}, invalid {})'.format(sum(checked.values()), checked.get('valid', 0), checked.get('unsure', 0), checked.get('invalid', 0)),
		'  lines warned: ' + ', '.join('{} {}'.format(kind, report['warned'][kind]) for kind in DIAGNOSTIC_KINDS)]
	if report['unknown']:
		out.append('  hosts mssh would reject:')
		for name, entry in sorted(report['unknown'].items(), key=lambda item: (-item[1]['lines'], item[0])):
			meant = '  (did you mean {}?)'.format(entry['meant']) if entry['meant'] else ''
			out.append('    {}  {} line{}{}'.format(name, entry['lines'], '' if entry['lines'] == 1 else 's', meant))
	return '\n'.join(out) + '\n'

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

def _ready():
	'''
	Say "ready" on stdout, just before taking the terminal (pick with ready=1, edit --ready): the shell
	waits only so long for it. False when nobody reads any more: the shell went on without the picker
	or the editor, and the terminal must be left alone.
	'''
	try:
		os.write(1, b'ready\n')
		return True
	except OSError:
		return False

def _claim_terminal():
	'''
	Create the directory MSSH_COMPLETE_CLAIM names (zsh and fish set it), just before taking the terminal.

	The shell waits only so long (MSSH_COMPLETE_START_TIMEOUT) for the picker to take it, and creates
	that directory itself when it stops waiting (also on Ctrl-C): mkdir succeeds for one of the two
	only, so a picker slow to start never draws after the shell went on. True when the terminal is
	ours (also without MSSH_COMPLETE_CLAIM, as bash runs it).
	'''
	path = os.environ.get('MSSH_COMPLETE_CLAIM')
	if not path:
		return True
	try:
		os.mkdir(path, 0o700)
		return True
	except OSError as e:
		_debug('pick: the shell went on ({!r}): leaving the terminal alone'.format(e))
		return False

def _cmd_pick():
	'''
	mssh-complete pick: the Ctrl-R picker. Reads a request on stdin, draws on /dev/tty, prints the new
	line (MSSHC1, L <cursor>\\t<line>, E; no NUL: shells read it with command substitution). Exit 0
	chosen, 1 cancelled, 2 unavailable (the shell then does what Ctrl-R did before). With the flag
	ready=1, "ready" comes first, before the terminal is taken.
	'''
	started = time.monotonic()
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
		picker = Picker(slot, history, title, now, unicode=engine.unicode, warnings=picker_warnings(engine, request))
		prompt = _prompt_from_flags(request.flags)
		line = before = None
		if prompt is not None:
			line, before = prompt + request.before + request.after, prompt + request.before
		if not _claim_terminal() or (request.flags.get('ready') == '1' and not _ready()):
			_debug('pick: the shell went on before it was ready, {:.3f} s in: the terminal is left alone'.format(time.monotonic() - started))
			return 2
		with Terminal() as term:
			# logged once the terminal is taken: "ready" comes just before that, nothing between
			_debug('pick: ready {:.3f} s in'.format(time.monotonic() - started))
			outcome = picker.run(term, line, before)
	except Exception as e:
		_debug('pick failed: {!r}\n{}'.format(e, _traceback()))
		return 2
	_debug('pick: {}, {:.3f} s in'.format(outcome, time.monotonic() - started))
	if outcome == 'unavailable':
		return 2
	if outcome != 'choose':
		return 1
	line, cursor = apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))
	try:
		sys.stdout.buffer.write('MSSHC1\nL {}\t{}\nE\n'.format(cursor, line).encode('utf-8', 'surrogateescape'))
		sys.stdout.buffer.flush()
	except OSError as e:
		_debug('pick: the answer did not reach the shell: {!r}'.format(e))
		raise
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
		unsafe = _QUOTE_SPECIAL.get(context.open_quote, '')
		if context.open_quote == '"':
			# in "..." bash also expands ! (history expansion)
			unsafe += '!'
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
	mssh-complete edit [--expand] [--ready] [--flags FLAGS] TEXT: the plain-bash editor for an mssh line.

	The prompt to redraw is in $MSSH_COMPLETE_PROMPT (PS1 itself with --expand); stdin holds the
	shell's history tail. Prints MSSHC1, L <cursor>\\t<line>, K <action>\\t<keys> (pass: readline
	replays keys, written as a readline key sequence; abandon: drop the line), E. Exit 3 when the
	editor cannot start; the shell then goes on as if it had not been asked. With --ready, "ready"
	comes first, before the terminal is taken.
	'''
	import argparse
	parser = argparse.ArgumentParser(prog='mssh-complete edit')
	parser.add_argument('--expand', action='store_true')
	parser.add_argument('--ready', action='store_true')
	# request flags from bash's glue: the locale it measured in the shell (utf8, turkic)
	parser.add_argument('--flags', default='')
	parser.add_argument('text')
	options = parser.parse_args(args)
	flags = parse_flags(options.flags)
	started = time.monotonic()
	prompt = _prompt_from_flags({'redraw': '1', 'expand': '1' if options.expand else '0'}) or ''
	history = []
	if not sys.stdin.isatty():
		data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
		history = [line for line in data.decode('utf-8', 'surrogateescape').split('\n') if line.strip()]
	try:
		engine = engine_for(Request('bash', options.text, '', '', flags=flags, history=history))
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
		picker = Picker(slot, [] if slot_only else items, title, unicode=engine.unicode, warnings=picker_warnings(engine, request))
		editor.erase(term)
		outcome = picker.run(term, prompt + text, prompt + text[:cursor])
		if outcome != 'choose':
			return None
		return apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))

	def diagnose(text, cursor):
		return engine.diagnose(Request('bash', text[:cursor], text[cursor:], ''))

	editor = LineEditor(options.text, suggest, complete, pick, diagnose, unicode=engine.unicode)
	# the suggestion and the warnings it opens with: asked before the shell hears "ready"
	editor.refresh()
	editor.refresh_warnings()
	if options.ready and not _ready():
		_debug('edit: the shell went on before it was ready, {:.3f} s in: the terminal is left alone'.format(time.monotonic() - started))
		return 3
	try:
		with term:
			# logged once the terminal is taken, as pick does: keys typed before that are echoed by it
			_debug('edit: ready {:.3f} s in, on {!r}'.format(time.monotonic() - started, _without_passwords(options.text, engine.spec)))
			action, replay = editor.run(term, prompt, ghost_style(os.environ.get('TERM', '')))
	except Exception as e:
		_debug('editor failed: {!r}\n{}'.format(e, _traceback()))
		action, replay = 'pass', b''
	out = 'MSSHC1\nL {}\t{}\nK {}\t{}\nE\n'.format(editor.cursor, editor.text, action, readline_keyseq(replay))
	try:
		sys.stdout.buffer.write(out.encode('utf-8', 'surrogateescape'))
		sys.stdout.buffer.flush()
	except OSError as e:
		_debug('edit: the answer did not reach the shell: {!r}'.format(e))
		raise
	_debug('edit: {} {!r} at {}, {:.3f} s in'.format(action or 'done', _without_passwords(editor.text, engine.spec), editor.cursor, time.monotonic() - started))
	return 0

def _cmd_rebuild(args):
	lock = args[1] if len(args) == 2 and args[0] == '--lock' else None
	# what the query that started us wrote into the lock, read before anything else
	owner = read_lock(lock) if lock else None
	built = False
	try:
		directory = cache_dir()
		if directory is None:
			print('mssh-complete: no private cache directory', file=sys.stderr)
			return 1
		path = build_index(directory)
		built = True
		print(path)
		return 0
	except Exception as e:
		_debug('rebuild failed: {!r}'.format(e))
		print('mssh-complete: rebuild failed: {!r}'.format(e), file=sys.stderr)
		return 1
	finally:
		if lock and built:
			release_lock(lock, owner)
		elif lock:
			keep_failed_lock(lock, owner)

def _cmd_probe(args):
	lock = args[1] if len(args) == 2 and args[0] == '--lock' else None
	# what the query that started us wrote into the lock, read before anything else
	owner = read_lock(lock) if lock else None
	try:
		directory = cache_dir()
		if directory is None:
			return 1
		run_probe(directory, lock, owner=owner)
		return 0
	except Exception as e:
		_debug('probe failed: {!r}'.format(e))
		return 1
	finally:
		if lock:
			release_lock(lock, owner)

def _print_as_stdout_can(text):
	'''
	Print text that may hold host names from the history, as stdout can: characters that came from bytes
	that are not UTF-8 as those bytes, characters stdout's encoding lacks (all but ASCII in the C locale
	on Python 3.6) as backslash escapes. print() failed on either.
	'''
	import re
	buffer = getattr(sys.stdout, 'buffer', None)
	if buffer is None:
		sys.stdout.write(text)
		return
	encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
	parts = re.split('([\udc80-\udcff]+)', text)
	sys.stdout.flush()
	buffer.write(b''.join(part.encode('ascii', 'surrogateescape') if index % 2 else part.encode(encoding, 'backslashreplace')
		for index, part in enumerate(parts)))

def _cmd_eval(args):
	import argparse
	parser = argparse.ArgumentParser(prog='mssh-complete eval', description='Replay mssh history and report how much typing completion saves.')
	parser.add_argument('history_file', nargs='?', help='history to replay (default: the one mssh writes)')
	parser.add_argument('--since', type=int, default=0, help='only replay entries from this unix time on')
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	parser.add_argument('--diagnostics', action='store_true', help='replay the warnings instead, looking hosts up in DNS (no ping): lists the hosts mssh would reject')
	options = parser.parse_args(args)
	mssh = _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	if options.synthetic:
		lines = synthetic_history()
	else:
		lines, _, _ = read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	if options.diagnostics:
		lines = _newest([line for line in lines if _entry_time(line) >= options.since], options.limit)
		hosts = engine_for(Request('bash', 'mssh ', '', '')).hosts
		_print_as_stdout_can(format_diagnostics_report(diagnostics_replay(lines, spec, mssh.host_validity, hosts)))
		return 0
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

def _entry_time(line):
	'''The unix time an mssh history line starts with, 0 when it has none.'''
	head = line.split('\t', 1)[0]
	return int(head) if _is_digits(head) else 0

@_quiet_when_stdout_is_gone
def main(argv=None):
	argv = sys.argv[1:] if argv is None else argv
	command = argv[0] if argv else ''
	if command == 'query':
		return _cmd_query()
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command == 'probe':
		return _cmd_probe(argv[1:])
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
	print('usage: mssh-complete query | pick | edit TEXT | rebuild | probe | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

if __name__ == '__main__':
	sys.exit(main())
