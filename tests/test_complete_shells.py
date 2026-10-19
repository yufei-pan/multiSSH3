import errno
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, REPO, aged, bash_session, build_index, fish_complete, fish_session, make_home,
	require_shell, without_command, zsh_session)

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]


@pytest.fixture
def setup(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	return env, home


def glue_file(home, shell, command=ENGINE):
	path = home / ('glue.' + shell)
	path.write_text(mc.render_glue(shell, command))
	return path


@pytest.mark.parametrize('bash_completion', [True, False])
def test_bash_completes_in_a_real_shell(setup, bash_completion):
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion)
	try:
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h "echo #HO') == 'mssh h "echo #HOST'
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
		assert session.line_after('mssh h "date; fakecmd al') == 'mssh h "date; fakecmd alpha" '
	finally:
		session.close()


def test_bash_ignoring_case_completes_in_any_case(tmp_path):
	# completion-ignore-case on: readline takes a candidate whose case differs from the word, and puts in its spelling
	env, home = make_home(tmp_path, HISTORY)
	(home / 'hosts').write_text('10.0.0.1 Storage-East\n')
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'), extra="bind 'set completion-ignore-case on'")
	try:
		assert session.line_after('mssh storage-e') == 'mssh Storage-East '
		assert session.line_after('mssh GP') == 'mssh gpu[01-16] '
		assert session.line_after('mssh -u ROO') == 'mssh -u root '
		assert session.line_after('mssh --NO_WA') == 'mssh --no_watch '
		# -S, -W and -I start option names as typed (used here): none may become -s, -w or -i
		assert session.line_after('mssh -q -S') == 'mssh -q -S'
		assert session.line_after('mssh --scp -W') == 'mssh --scp -W'
		assert session.line_after('mssh -nh -I') == 'mssh -nh -I'
	finally:
		session.close()


def ignoring_case(tmp_path, history, hosts='', on=True, files=(), commands=(), env_lines='', options='', lang=None):
	'''
	A bash with completion-ignore-case on (off with on False), no bash-completion, in a directory holding
	only files (no other file names among the candidates), with commands found first on its PATH, and
	env_lines in ~/hosts.env (aliases), shell options (set -e), and LANG=lang if given (the index is built in
	the tests' own).
	'''
	env, home = make_home(tmp_path, history)
	(home / 'hosts').write_text(hosts, encoding='utf-8')
	(home / 'hosts.env').write_text(env_lines)
	build_index(env)
	work = tmp_path / 'work'
	work.mkdir()
	for name in files:
		(work / name).write_text('')
	found = tmp_path / 'bin'
	found.mkdir()
	for name in commands:
		(found / name).write_text('#!/bin/sh\n')
		(found / name).chmod(0o755)
	env = dict(env, PATH=str(found) + os.pathsep + env['PATH'])
	if lang is not None:
		env['LANG'] = lang
	extra = "cd '{}'; {}".format(work, options)
	if on:
		extra = "bind 'set completion-ignore-case on'; " + extra
	return bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=extra)


def set_ignore_case(session, value):
	'''Turn completion-ignore-case on or off in a running bash, as a bind or a re-read ~/.inputrc does.'''
	session.send("bind 'set completion-ignore-case {}'\r".format(value))
	session.read_until(b'@@READY@@')


def test_bash_ignoring_case_offers_one_of_the_words_differing_only_in_case(tmp_path):
	# readline cannot tell storage-east from Storage-East and would stop at their common start
	history = ['1790000000\t/x/multiSSH3.py\t-su\tstorage-east\t"uptime"']
	history += ['179000000{}\t/x/multiSSH3.py\t-su\tlogin1\t"{}"'.format(number + 1, command)
		for number, command in enumerate(('zzsvc status', 'zzsvc start', 'Zzsvc restart'))]
	session = ignoring_case(tmp_path, history, '10.0.0.1 Storage-East\n')
	try:
		assert session.line_after('mssh storage-e') == 'mssh storage-east '
		assert session.line_after('mssh Storage-E') == 'mssh Storage-East '
		assert session.line_after('mssh STORAGE-E') == 'mssh storage-east '
		assert session.line_after('mssh login1 Zz') == 'mssh login1 Zzsvc '
		assert session.line_after('mssh login1 ZZ') == 'mssh login1 zzsvc '
	finally:
		session.close()


def test_bash_ignoring_case_lists_its_words_differing_only_in_case_beside_a_file_name(tmp_path):
	# the engine kept one of storage-file and Storage-file, not knowing the glue would add storage-other
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"nosuchcmd {}"'.format(number, word)
		for number, word in enumerate(('storage-file', 'Storage-file'))]
	session = ignoring_case(tmp_path, history, files=['storage-other'])
	try:
		assert {'storage-file', 'Storage-file', 'storage-other'} <= set(listed_after(session, 'mssh h nosuchcmd storage-'))
		assert session.line_after('mssh h nosuchcmd storage-f') == 'mssh h nosuchcmd storage-file '
		assert session.line_after('mssh h nosuchcmd Storage-f') == 'mssh h nosuchcmd Storage-file '
	finally:
		session.close()


def test_bash_ignoring_case_keeps_a_host_and_an_alias_differing_only_in_case(tmp_path):
	# the host gpus beside the alias GPUs (an env variable): gpus typed in its case is the host, never the alias
	session = ignoring_case(tmp_path, [], '10.0.0.1 gpus\n10.0.0.2 Node01\n10.0.0.3 node02\n', env_lines='GPUs=Node01,node02\n')
	try:
		assert session.line_after('mssh gpus') == 'mssh gpus '
		assert session.line_after('mssh GPU') == 'mssh GPUs '
	finally:
		session.close()


def test_bash_ignoring_case_puts_in_the_more_used_of_two_aliases_differing_only_in_case(tmp_path):
	# gpus was used ten times, GPUS never: neither in the case typed, the engine's first goes in
	history = ['17900000{:02d}\t/x/multiSSH3.py\t-su\tgpus\t"uptime"'.format(number) for number in range(10)]
	session = ignoring_case(tmp_path, history, '10.0.0.1 a1\n10.0.0.2 a2\n10.0.0.3 b1\n', env_lines='gpus=a1,a2\nGPUS=b1,b1\n')
	try:
		assert session.line_after('mssh Gp') == 'mssh gpus '
	finally:
		session.close()


def listed_after(session, typed):
	'''The words readline lists for typed on a second TAB.'''
	session.send(typed + '\t\t')
	text = session.read_until(b'@@READY@@')
	session.send('\x15')
	return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', ' ', text).split()


def test_bash_ignoring_case_lists_words_differing_only_in_case_beside_others(tmp_path):
	# Admin and admin are two accounts: beside root readline lists all three, and either goes in when typed
	session = ignoring_case(tmp_path, ['179000000{}\t/x/multiSSH3.py\t-su -u={}\th\t"uptime"'.format(number, name)
		for number, name in enumerate(('Admin', 'admin', 'root'))])
	try:
		assert {'Admin', 'admin', 'root'} <= set(listed_after(session, 'mssh -u '))
		assert session.line_after('mssh -u a') == 'mssh -u admin '
		assert session.line_after('mssh -u A') == 'mssh -u Admin '
	finally:
		session.close()


@pytest.mark.parametrize('first', ['on', 'off'])
def test_bash_follows_completion_ignore_case_as_it_changes(tmp_path, first):
	# read once per shell, the setting went stale after a bind: turned off, the engine still offered Node01 and
	# NODE03 for node0, and readline, now minding case, cut the word back to their common start (mssh N);
	# turned on, words in another case stayed out
	session = ignoring_case(tmp_path, HISTORY, '10.0.0.1 Node01\n10.0.0.3 NODE03\n10.0.0.5 Storage-East\n', on=first == 'on')

	def completes(value):
		if value == 'on':
			assert session.line_after('mssh storage-e') == 'mssh Storage-East '
		else:
			assert session.line_after('mssh node0') == 'mssh node0'
			assert session.line_after('mssh storage-e') == 'mssh storage-e'
	try:
		completes(first)
		other = 'off' if first == 'on' else 'on'
		set_ignore_case(session, other)
		completes(other)
		set_ignore_case(session, first)
		completes(first)
	finally:
		session.close()


def test_bash_ignoring_case_keeps_delegated_words_in_another_case(tmp_path):
	# bash's compgen ignores case too: stor gives Storage-File, ZZT gives zztool; dropped, the history's word
	# alone went in
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(number, command)
		for number, command in enumerate(('nosuchcmd storage-x', 'zzthing'))]
	session = ignoring_case(tmp_path, history, files=['Storage-File'], commands=['zztool'])
	try:
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-'
		assert session.line_after('mssh h ZZT') == 'mssh h zzt'
		assert session.line_after('mssh h nosuchcmd Storage-F') == 'mssh h nosuchcmd Storage-File '
	finally:
		session.close()


@pytest.mark.parametrize('options', ['', 'set -e', 'set -u'])
def test_bash_ignoring_case_puts_in_one_of_its_own_and_delegated_words_differing_only_in_case(tmp_path, options):
	# the history's storage-file and the file Storage-File, both offered, kept readline from completing
	session = ignoring_case(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd storage-file"'], files=['Storage-File'], options=options)
	try:
		assert session.line_after('mssh h nosuchcmd storage-f') == 'mssh h nosuchcmd storage-file '
		assert session.line_after('mssh h nosuchcmd Storage-F') == 'mssh h nosuchcmd Storage-File '
		assert session.line_after('mssh h nosuchcmd STORAGE-F') == 'mssh h nosuchcmd storage-file '
		assert b'unbound variable' not in session.output
	finally:
		session.close()


def nocasematch(session):
	'''Whether the running bash has nocasematch on: 'on' or 'off' (None if it does not say).'''
	start = len(session.output)
	session.send('shopt -q nocasematch && echo "@@NOCASE""=on@@" || echo "@@NOCASE""=off@@"\r')
	deadline = time.monotonic() + 10
	while time.monotonic() < deadline:
		found = re.search(rb'@@NOCASE=(on|off)@@', session.output[start:])
		if found:
			return found.group(1).decode()
		session.read_until(b'@@NOCASE=', 0.1)
	return None


def test_bash_glue_gives_the_shell_back_its_nocasematch(tmp_path):
	# the glue sets nocasematch to match delegated words as the engine matched them (on while ignoring case,
	# whatever the shell had), and puts back what the shell had
	history = ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd storage-x"']
	session = ignoring_case(tmp_path, history, files=['Storage-File'])
	try:
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-'
		assert nocasematch(session) == 'off'
		set_ignore_case(session, 'off')
		session.send('shopt -s nocasematch\r')
		session.read_until(b'@@READY@@')
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-x '
		assert nocasematch(session) == 'on'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_directories_of_a_path_as_typed(tmp_path):
	# as readline's own file name completion does: /Zzdata/pro became /zzdata/project/b.txt
	session = ignoring_case(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su -f=/zzdata/project/b.txt\th\t"/zzsrv/Out"'])
	try:
		assert session.line_after('mssh -f /Zzdata/pro') == 'mssh -f /Zzdata/pro'
		assert session.line_after('mssh -f /zzdata/PRO') == 'mssh -f /zzdata/project/b.txt '
		assert session.line_after('mssh -f /x h /ZZSRV/o') == 'mssh -f /x h /ZZSRV/o'
		assert session.line_after('mssh -f /x h /zzsrv/o') == 'mssh -f /x h /zzsrv/Out '
	finally:
		session.close()


def test_bash_ignoring_case_lowers_letters_as_its_locale_does(tmp_path):
	# in the C locale readline lowers ASCII letters only: \u0130stanbul is no word for i there, and offered
	# beside Ix1 it kept readline from completing
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n', lang='C')
	try:
		assert session.line_after('mssh i') == 'mssh Ix1 '
	finally:
		session.close()


def locale_here(name):
	'''Whether the C library here has the locale named name.'''
	import locale
	saved = locale.setlocale(locale.LC_CTYPE)
	try:
		locale.setlocale(locale.LC_CTYPE, name)
		return True
	except locale.Error:
		return False
	finally:
		locale.setlocale(locale.LC_CTYPE, saved)


@pytest.mark.parametrize('lang', ['xx_YY.UTF-8', 'tr_XX.UTF-8'])
def test_bash_ignoring_case_in_a_locale_this_system_lacks_runs_as_in_c(tmp_path, lang):
	# bash runs in C in a locale the system has not, whatever its name says: \u0130stanbul is no word for i
	if locale_here(lang):
		pytest.skip('this C library takes any locale name')
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n', lang=lang)
	try:
		assert session.line_after('mssh i') == 'mssh Ix1 '
	finally:
		session.close()


@pytest.mark.parametrize('lang, typed, line', [
	('tr_TR.UTF-8', 'mssh i', 'mssh \u0130stanbul '), ('tr_TR.UTF-8', 'mssh I', 'mssh Ix1 '),
	('tr_TR.ISO-8859-9', 'mssh i', 'mssh ix2 '), ('tr_TR.ISO-8859-9', 'mssh I', 'mssh Ix1 ')])
def test_bash_ignoring_case_in_a_turkish_locale(tmp_path, lang, typed, line):
	# in UTF-8 readline lowers I to the dotless i and the I with a dot to i; in ISO-8859-9 I and i match only
	# themselves (it lowers I to a dotless i that is no ASCII letter, and the I with a dot reaches it as two bytes)
	if not locale_here(lang):
		pytest.skip('no {} locale here'.format(lang))
	if not mc._locale_traits(lang)[1]:
		pytest.skip('this C library does not lower I to the dotless i in {} (musl)'.format(lang))
	hosts = '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n' + ('10.0.0.3 ix2\n' if 'UTF-8' not in lang else '')
	session = ignoring_case(tmp_path, [], hosts, lang=lang)
	try:
		assert session.line_after(typed) == line
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_directories_of_a_command_word_as_typed(tmp_path):
	# as readline's own file name completion does: /zzsrv/data/o became /zzsrv/Data/out
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(number, command)
		for number, command in enumerate(('nosuchcmd /zzsrv/Data/out', '/Zzopt/Tool/run.sh'))]
	session = ignoring_case(tmp_path, history)
	try:
		assert session.line_after('mssh h nosuchcmd /zzsrv/data/o') == 'mssh h nosuchcmd /zzsrv/data/o'
		assert session.line_after('mssh h nosuchcmd /zzsrv/Data/O') == 'mssh h nosuchcmd /zzsrv/Data/out '
		assert session.line_after('mssh h "nosuchcmd /zzsrv/data/o') == 'mssh h "nosuchcmd /zzsrv/data/o'
		assert session.line_after('mssh h /zzopt/tool/r') == 'mssh h /zzopt/tool/r'
		assert session.line_after('mssh h /Zzopt/Tool/R') == 'mssh h /Zzopt/Tool/run.sh '
	finally:
		session.close()


def test_bash_minding_case_keeps_delegated_words_in_their_case_whatever_nocasematch_says(tmp_path):
	# with completion-ignore-case off and the shell's nocasematch on, a command's completion offering Storage-x
	# for stor must not reach readline, which, minding case, would cut the word back to their common start
	options = 'shopt -s nocasematch; _fakeci() { COMPREPLY=(Storage-x storage-y); }; complete -F _fakeci fakeci'
	session = ignoring_case(tmp_path, [], on=False, options=options)
	try:
		assert session.line_after('mssh h fakeci stor') == 'mssh h fakeci storage-y '
		assert nocasematch(session) == 'on'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_command_words_typed_before(tmp_path):
	# a quoted command is completed whole: its words typed before the current one stay as typed there too
	session = ignoring_case(tmp_path, ['179000000{}\t/x/multiSSH3.py\t-su\tlogin1\t"{}"'.format(number, command)
		for number, command in enumerate(('zzctl status nginx', 'zzctl STATUS Nginx', 'Zzctl Status sshd'))])
	try:
		assert session.line_after('mssh login1 "zzctl STATUS n') == 'mssh login1 "zzctl STATUS Nginx" '
		assert session.line_after('mssh login1 zzctl STATUS n') == 'mssh login1 zzctl STATUS Nginx '
		assert session.line_after('mssh login1 "ZZCTL STATUS n') == 'mssh login1 "ZZCTL STATUS n'
	finally:
		session.close()


def comments_in_substitutions(script):
	"""
	The line numbers of the comments inside a command or process substitution of a bash script: every $( <(
	and >( followed until it closes, wherever it opens. Quotes, ${...} and $(( )) are no comment and hide
	none; a comment outside is skipped whole (its quotes are none). A case pattern's ) inside a substitution
	would end it early: the glue has none there.
	"""
	found = []
	# [kind, in a substitution, parentheses open]: code (the script, or a substitution's), dq, sq, ansi, brace, arith
	stack = [['code', False, 0]]
	index, line = 0, 1
	while index < len(script):
		char = script[index]
		top = stack[-1]
		if char == '\n':
			line += 1
		if top[0] in ('sq', 'ansi'):
			if top[0] == 'ansi' and char == '\\':
				line += script[index + 1:index + 2] == '\n'
				index += 2
				continue
			if char == "'":
				stack.pop()
			index += 1
			continue
		if char == '\\':
			line += script[index + 1:index + 2] == '\n'
			index += 2
			continue
		if script.startswith('$((', index):
			stack.append(['arith', False, 0])
			index += 3
			continue
		if script.startswith('$(', index) or (top[0] == 'code' and script.startswith(('<(', '>('), index)):
			stack.append(['code', True, 0])
			index += 2
			continue
		if script.startswith('${', index):
			stack.append(['brace', False, 0])
			index += 2
			continue
		if top[0] == 'arith':
			if char == '(':
				top[2] += 1
			elif char == ')' and top[2]:
				top[2] -= 1
			elif char == ')':
				stack.pop()
				index += 1
			index += 1
			continue
		if char == '"':
			if top[0] == 'dq':
				stack.pop()
			else:
				stack.append(['dq', False, 0])
		elif top[0] == 'dq':
			pass
		elif top[0] == 'brace' and char == '}':
			stack.pop()
		elif script.startswith("$'", index):
			stack.append(['ansi', False, 0])
			index += 1
		elif char == "'":
			stack.append(['sq', False, 0])
		elif top[0] == 'code' and char == '#' and (index == 0 or script[index - 1] in ' \t\n;&|(<>'):
			if any(frame[1] for frame in stack):
				found.append(line)
			while index + 1 < len(script) and script[index + 1] != '\n':
				index += 1
		elif top[0] == 'code' and char == '(':
			top[2] += 1
		elif top[0] == 'code' and char == ')':
			if top[2]:
				top[2] -= 1
			elif top[1]:
				stack.pop()
		index += 1
	return found


def test_bash_glue_has_no_comment_inside_a_command_or_process_substitution():
	# bash 4.2 reads a quote or a parenthesis in a comment inside <( ) or $( ) as code: a comment saying
	# "readline's" there broke every TAB ("bad substitution: no closing `)'"), which bash 5 never shows
	assert comments_in_substitutions(mc.render_glue('bash', ENGINE)) == []
	# the scanner finds them wherever the substitution opens, and nothing else
	assert comments_in_substitutions("x=$(\n\t# readline's\n\ty)\n") == [2]
	assert comments_in_substitutions("done < <(if (( files )); then\n\t# readline's\n\tcompgen -f; fi 2>/dev/null || :)\n") == [2]
	assert comments_in_substitutions('a "$(b\n# c\nd)"\n') == [2]
	assert comments_in_substitutions("# readline's (\nx=${#y} z=$(( 10#1 + (2) )) w=$(echo '#(' \"#\" $'\\'#') v=$(a)#b\n") == []
	assert comments_in_substitutions("f() {\n\t# it's ( not inside\n\tx=$(a; b)\n}\n# (\ny=<(c\n# in\n)\n") == [7]


def test_bash_tab_inside_an_ansi_c_quote_keeps_the_command(tmp_path):
	# in $'...' a backslash starts an escape: zzfmt "%s\n" x must not be offered there as it is
	# (zzfmt: a name no local command starts with, as the first word is also completed as a command)
	env, home = make_home(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\tnode1\t\'zzfmt "%s\\n" x\'', '1790000100\t/x/multiSSH3.py\t-su\tnode1\t"zzfmt ok"'])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after("mssh node1 'zzf") == "mssh node1 'zzfmt "
		assert session.line_after("mssh node1 $'zzf") == "mssh node1 $'zzfmt ok' "
	finally:
		session.close()


def test_bash_cursor_in_the_middle_of_a_line_with_multibyte_text(setup):
	# bash 4.2 counts COMP_POINT in bytes: the glue must cut the line in bytes there
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		left = '\x1b[D' * len(' "nvidia-smi"')
		assert session.line_after('mssh -ea=é gp "nvidia-smi"', keys=left + '\t') == 'mssh -ea=é gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_bash_falls_back_to_file_names_when_the_engine_is_slow(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	(home / 'zzfile_unique').write_text('')
	session = bash_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'bash', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		assert time.monotonic() - started < 3
	finally:
		session.close()


def test_zsh_completes_in_a_real_shell(setup):
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'))
	try:
		assert session.line_after('mssh gp') == 'mssh gpu\\[01-16\\] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
	finally:
		session.close()


@pytest.mark.parametrize('engine', ['sleep 5', 'exit 1', r"printf 'MSSHC9\nE\n\0'"], ids=['slow', 'failing', 'other-protocol'])
def test_zsh_falls_back_to_file_names_without_an_answer(setup, engine):
	# no answer: what zsh offers for a command it has no completion for (file names), as bash does
	env, home = setup
	stand_in = home / 'engine'
	stand_in.write_text('#!/bin/sh\n{}\n'.format(engine))
	stand_in.chmod(0o755)
	(home / 'zzfile_unique').write_text('')
	session = zsh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'zsh', [str(stand_in)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		assert time.monotonic() - started < 3
		assert b'_mssh:' not in session.output
	finally:
		session.close()


@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_file_names_when_mssh_has_nothing_to_offer(setup, shell):
	# an answer with nothing in it: bash's -o default offers file names, and zsh does the same,
	# except for a password (nodefault)
	env, home = setup
	(home / 'zzfile_unique').write_text('')
	start = bash_session if shell == 'bash' else zsh_session
	session = start(home, env, glue_file(home, shell))
	try:
		# hosts, then a remote command, that nothing matches
		assert session.line_after('mssh zzf') == 'mssh zzfile_unique '
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		# a remote command's own completion that offers nothing
		assert session.line_after('mssh h fakecmd zz') == 'mssh h fakecmd zzfile_unique '
		assert session.line_after('mssh -p zz') == 'mssh -p zz'
		assert session.line_after('mssh h --password=zz') == 'mssh h --password=zz'
	finally:
		session.close()


# a command whose completion is built on _arguments, as most of zsh's are
ZSH_FAKEOPTS = "_fakeopts() { _arguments '--apparent-size[sizes as seen]' '--block-size=[unit]:unit:' }\ncompdef _fakeopts fakeopts"


def test_zsh_runs_delegated_completions_as_zsh_runs_them(setup):
	# the remote command's completion runs as zsh runs it: with the completion system's options
	# (_arguments misreads its specs without them) and with the operator's own (glob_dots)
	env, home = setup
	(home / 'dots').mkdir()
	(home / 'dots' / '.zzhidden').write_text('')
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=ZSH_FAKEOPTS + '\nsetopt glob_dots')
	try:
		assert session.line_after('fakeopts --appa') == 'fakeopts --apparent-size '
		assert session.line_after('mssh h fakeopts --appa') == 'mssh h fakeopts --apparent-size '
		assert session.line_after('ls dots/') == 'ls dots/.zzhidden '
		assert session.line_after('mssh h ls dots/') == 'mssh h ls dots/.zzhidden '
		assert b'_mssh:' not in session.output
	finally:
		session.close()


@pytest.mark.parametrize('option', ['ignore_braces', 'ignore_close_braces'])
def test_zsh_glue_loads_with_brace_options(tmp_path, option):
	# with either option a } closes a group only in command position: the glue must parse all the same
	zsh = require_shell('zsh')
	env, home = make_home(tmp_path)
	script = 'autoload -Uz compinit && compinit -u -D; setopt {}; source {}; print -r -- "$+functions[_mssh] $_comps[mssh]"'
	result = subprocess.run([zsh, '-f', '-c', script.format(option, glue_file(home, 'zsh'))], env=env,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert (result.stdout.decode().split(), result.stderr.decode()) == (['1', '_mssh'], '')


def test_zsh_gives_up_on_a_slow_engine(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	session = zsh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'zsh', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh gp') == 'mssh gp'
		assert time.monotonic() - started < 3
	finally:
		session.close()


@pytest.fixture
def first_build(tmp_path):
	'''No index yet, and the first build is running (its lock is taken and it never ends).'''
	env, home = make_home(tmp_path, HISTORY)
	assert mc.take_lock(str(tmp_path / 'runtime' / 'multiSSH3' / mc.LOCK_NAME))
	# more than the engine needs, less than the 2 s it used to wait for the first build
	return dict(env, MSSH_COMPLETE_TIMEOUT='1'), home


def test_bash_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
	finally:
		session.close()


def test_zsh_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	session = zsh_session(home, env, glue_file(home, 'zsh'))
	try:
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
	finally:
		session.close()


def test_fish_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	assert [text for text, _ in fish_complete(env, glue_file(home, 'fish'), 'mssh --no_wa')] == ['--no_watch']


# compinit as rc files run it, with its dump file
COMPINIT = 'autoload -Uz compinit && compinit -u'
# compinit as zinit turbo and zsh-defer run it: after the first prompt
LATE_COMPINIT = '''_mssh_test_late() { add-zsh-hook -d precmd _mssh_test_late; autoload -Uz compinit && compinit -u }
autoload -Uz add-zsh-hook; add-zsh-hook precmd _mssh_test_late'''


@pytest.mark.parametrize('before, after, prompts', [
	('', COMPINIT, 1),
	('', LATE_COMPINIT, 2),
	(COMPINIT, COMPINIT, 1),
], ids=['later-in-the-rc-file', 'after-the-first-prompt', 'again-from-its-dump'])
def test_zsh_completes_whenever_compinit_runs(setup, before, after, prompts):
	# compdef only exists once compinit ran, and a compinit that loads its dump forgets what was registered before it
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'), compinit=before, extra=after)
	try:
		for _ in range(prompts - 1):
			session.send('true\r')
			session.read_until(b'@@READY@@')
		assert session.line_after('mssh gp') == 'mssh gpu\\[01-16\\] '
	finally:
		session.close()


def test_zsh_keeps_a_completion_set_for_mssh_by_hand(setup):
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra='compdef _fakecmd mssh')
	try:
		session.send('true\r')
		session.read_until(b'@@READY@@')
		assert session.line_after('mssh al') == 'mssh alpha '
	finally:
		session.close()


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
def test_fish_completes(setup, tmp_path, timeout):
	# with coreutils' timeout(1) and without it (macOS): the glue keeps its time limit either way
	require_shell('fish')
	env, home = setup
	if timeout == 'no timeout':
		env = without_command(env, 'timeout', tmp_path / 'bin')
	glue = glue_file(home, 'fish')
	assert fish_complete(env, glue, 'mssh gp') == [('gpu[01-16]', 'used before')]
	assert fish_complete(env, glue, 'mssh gpu[01-16] "nvid')[0] == ('nvidia-smi', '')
	# fish sets $USER from the user database, and mssh-complete offers it: the name of whoever runs the
	# tests (runner, on GitHub's machines) may start with r too
	me = pwd.getpwuid(os.getuid()).pw_name
	assert [pair for pair in fish_complete(env, glue, 'mssh -u r') if pair != (me, 'user')] == [('root', 'used before')]
	assert fish_complete(env, glue, 'mssh h fakecmd al') == [('alpha', '')]
	assert fish_complete(env, glue, 'mssh h "date; fakecmd al') == [('date; fakecmd alpha', '')]


# engines that give no answer: the glue must fall back to file names, on time and quietly
NO_ANSWER = {
	'slow': '#!/bin/sh\nsleep 5\n',
	'failing': '#!/bin/sh\nexit 1\n',
	'missing': None,
	'without its interpreter': '#!/nonexistent/python3\n',
}


def no_answer_engine(home, kind):
	path = home / 'engine'
	if NO_ANSWER[kind] is not None:
		path.write_text(NO_ANSWER[kind])
		path.chmod(0o755)
	return [str(path)]


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
@pytest.mark.parametrize('engine', sorted(NO_ANSWER))
def test_fish_falls_back_to_file_names_without_an_answer(setup, tmp_path, engine, timeout):
	# as bash does (-o default): fish's own file names, within the time limit, and nothing printed
	require_shell('fish')
	env, home = setup
	env = dict(env, MSSH_COMPLETE_TIMEOUT='0.3')
	if timeout == 'no timeout':
		env = without_command(env, 'timeout', tmp_path / 'bin')
	(home / 'zzfile_unique').write_text('')
	glue = glue_file(home, 'fish', no_answer_engine(home, engine))
	started = time.monotonic()
	assert fish_complete(env, glue, 'mssh h zzf', cwd=home) == [('zzfile_unique', '')]
	assert time.monotonic() - started < 3


# what fish prints when a command fails to start or a background job ends
FISH_MESSAGES = ('job', 'signal', 'error', 'unknown command', 'expanded command', 'fish:')


@pytest.mark.parametrize('engine', ['answering', 'slow'])
def test_fish_without_timeout_shows_nothing_but_the_completion(setup, tmp_path, engine):
	# without timeout(1) the glue keeps the time limit with a timer of its own: on screen, only the
	# completion, whether the engine answers or is stopped (TAB, and on fish 4 the check at each space)
	require_shell('fish')
	env, home = setup
	env = without_command(env, 'timeout', tmp_path / 'bin')
	(home / 'zzfile_unique').write_text('')
	# more shell history than a pipe holds: the slow engine never reads it, and fish must not wait to write it
	history = home / '.local' / 'share' / 'fish'
	history.mkdir(parents=True)
	(history / 'fish_history').write_text(''.join('- cmd: echo {} {}\n  when: {}\n'.format(number, 'x' * 300, aged(1790000000 + number)) for number in range(1000)))
	if engine == 'answering':
		command, typed, expected = ENGINE, 'mssh gp', 'mssh gpu\\[01-16\\] '
	else:
		command, typed, expected = no_answer_engine(home, 'slow'), 'mssh h zzf', 'mssh h zzfile_unique '
		env['MSSH_COMPLETE_TIMEOUT'] = '0.3'
	# fish completes only commands that exist
	pre = 'function mssh; end\nsource {}'.format(glue_file(home, 'fish', command))
	session = fish_session(home, env, mc.render_glue('fish-keys', command), pre=pre)
	try:
		start = len(session.output)
		started = time.monotonic()
		assert session.line_after(typed) == expected
		if engine == 'slow':
			assert time.monotonic() - started < 3
		# fish reports ended background jobs before its next prompt
		session.send('\r')
		session.read_until(b'@@READY@@')
		session.read_until(b'@@never@@', 1.0)
		shown = session.output[start:].decode('utf-8', 'replace').lower()
		assert [message for message in FISH_MESSAGES if message in shown] == []
	finally:
		session.close()


def _interactive_output(shell, env, home):
	'''Everything a fresh interactive shell prints before its first prompt, without the prompt.'''
	argv = {'bash': [shell, '-i'], 'zsh': [shell, '-i'], 'fish': [shell, '-i']}[os.path.basename(shell)]
	result = subprocess.run(argv, input=b'exit\n', env=dict(env, PS1='', PROMPT=''), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	# bash 4.2's readline turns on xterm's meta key mode again when keys were bound at the first
	# prompt: the same invisible mode, sent twice
	return result.returncode, re.sub('(\x1b\\[\\?1034h)+', '\x1b[?1034h', result.stdout.decode('utf-8', 'replace'))


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
@pytest.mark.parametrize('damage', ['none', 'deleted', 'unreadable', 'broken', 'no engine'])
def test_new_shells_stay_silent(tmp_path, shell, damage):
	path = require_shell(shell)
	env, home = make_home(tmp_path)
	if shell == 'zsh':
		(home / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	baseline = _interactive_output(path, env, home)
	command = ['/nonexistent/engine'] if damage == 'no engine' else ENGINE
	code, messages = mc.install(shell, home=str(home), environ=env, command=command)
	assert code == 0, messages
	# fish sources its conf.d file itself, as bash and zsh source the rc block: mssh writes both whole
	glues = [line.split(' ', 1)[1] for line in messages if line.startswith('wrote ') and '/conf.d/' not in line]
	for glue in glues:
		if damage == 'deleted':
			os.unlink(glue)
		elif damage == 'unreadable':
			os.chmod(glue, 0)
		elif damage == 'broken':
			with open(glue, 'a') as f:
				f.write('\n((( broken syntax\n')
	assert _interactive_output(path, env, home) == baseline


@pytest.mark.parametrize('compinit', ['none', 'after the block'])
def test_new_zsh_stays_silent_whenever_compinit_runs(tmp_path, compinit):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	rc = home / '.zshrc'
	tail = COMPINIT + '\n' if compinit == 'after the block' else ''
	rc.write_text('setopt nobeep\n' + tail)
	baseline = _interactive_output(path, env, home)
	rc.write_text('setopt nobeep\n')
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	with rc.open('a') as f:
		f.write(tail)
	assert _interactive_output(path, env, home) == baseline


def test_new_bash_with_the_editor_stays_silent(tmp_path):
	path = require_shell('bash')
	env, home = make_home(tmp_path)
	baseline = _interactive_output(path, env, home)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)[0] == 0
	assert _interactive_output(path, env, home) == baseline


def test_install_turns_the_editor_on_and_keeps_it_on(tmp_path):
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	mc.install('bash', home=str(home), environ=env, editor=True)
	assert 'export MSSH_COMPLETE_EDITOR=1\n' in rc.read_text()
	# installing again after an upgrade, without the word, keeps it on and says how to turn it off
	code, messages = mc.install('bash', home=str(home), environ=env)
	text = rc.read_text()
	assert 'export MSSH_COMPLETE_EDITOR=1\n' in text and text.count('# >>> mssh completion >>>') == 1
	# after the glue file it wrote, before the note about login shells
	assert messages[1:3] == ['kept the mssh line editor on (to turn it off: mssh --completion uninstall bash, then install bash)', '{} already loads it'.format(rc)]
	mc.uninstall('bash', home=str(home), environ=env)
	mc.install('bash', home=str(home), environ=env)
	assert 'MSSH_COMPLETE_EDITOR' not in rc.read_text()


@pytest.mark.parametrize('change', ['no final newline', 'crlf', 'moved to the top'])
def test_install_finds_its_block_however_the_file_was_edited(tmp_path, change):
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	mc.install('bash', home=str(home), environ=env)
	text = rc.read_text()
	if change == 'no final newline':
		text = text.rstrip('\n')
	elif change == 'crlf':
		text = text.replace('\n', '\r\n')
	else:
		begin = text.index('# >>> mssh')
		text = text[begin:] + text[:begin]
	rc.write_bytes(text.encode())
	mc.install('bash', home=str(home), environ=env)
	assert rc.read_text().count('# <<< mssh completion <<<') == 1
	mc.uninstall('bash', home=str(home), environ=env)
	assert 'mssh completion' not in rc.read_text() and 'alias ll="ls -l"' in rc.read_text()


@pytest.fixture
def install_env(tmp_path, monkeypatch):
	'''HOME and XDG_RUNTIME_DIR of a test home in os.environ, and install() writing nothing.'''
	env, home = make_home(tmp_path, HISTORY)
	monkeypatch.setenv('HOME', env['HOME'])
	monkeypatch.setenv('XDG_RUNTIME_DIR', env['XDG_RUNTIME_DIR'])
	monkeypatch.setattr(mc, 'install', lambda shell, editor=False: (0, ['wrote the glue']))
	return home


def test_install_builds_the_index_right_away(install_env, capsys):
	# the first TAB in a new shell then answers from the index instead of starting its build
	assert mc.completion_command(['install', 'bash']) == 0
	path = os.path.join(mc.cache_dir(), mc.INDEX_NAME)
	assert capsys.readouterr().out.splitlines() == ['wrote the glue', 'built the completion index ' + path]
	assert 'storage1' in mc.HostTable(mc.NsvIndex.load(path)).names


def test_install_says_when_it_cannot_build_the_index(install_env, monkeypatch, capsys):
	def fail(directory):
		raise OSError(28, 'No space left on device')
	monkeypatch.setattr(mc, 'build_index', fail)
	assert mc.completion_command(['install', 'bash']) == 0
	assert capsys.readouterr().out.splitlines()[-1] == 'could not build the completion index now ([Errno 28] No space left on device): the first TAB tries again'
	monkeypatch.setattr(mc, 'cache_dir', lambda create=True: None)
	assert mc.completion_command(['install', 'bash']) == 0
	assert capsys.readouterr().out.splitlines()[-1] == 'no private runtime directory for the completion index: TAB offers options and shell history only'


def test_uninstall_builds_nothing(install_env, monkeypatch):
	monkeypatch.setattr(mc, 'uninstall', lambda shell: (0, []))
	monkeypatch.setattr(mc, 'build_index', lambda directory: pytest.fail('built an index'))
	assert mc.completion_command(['uninstall', 'bash']) == 0


def test_completion_command_takes_the_editor_word(monkeypatch):
	calls = []
	monkeypatch.setattr(mc, 'prepare_index', lambda: 'built the completion index')
	monkeypatch.setattr(mc, 'install', lambda shell, editor=False: (calls.append((shell, editor)), (0, []))[1])
	assert mc.completion_command(['install', 'bash', 'editor']) == 0
	assert mc.completion_command(['install', 'bash', '--editor']) == 0
	assert mc.completion_command(['install', 'zsh', 'editor']) == 2
	assert calls == [('bash', True), ('bash', True)]


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_uninstall_restores_rc_files(tmp_path, shell):
	env, home = make_home(tmp_path)
	(home / '.bashrc').write_text('alias ll="ls -l"')
	(home / '.zshrc').write_text('setopt nobeep\n')
	before = {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')}
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	mc.uninstall(shell, home=str(home), environ=env)
	assert {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')} == before
	left = [os.path.join(root, name) for root, _, names in os.walk(str(home)) for name in names]
	assert sorted(left) == sorted([str(home / '.bashrc'), str(home / '.zshrc'), str(home / '.mssh_history'), str(home / '.multiSSH3.config.json')])


def test_uninstall_deletes_an_rc_file_it_created(tmp_path):
	env, home = make_home(tmp_path)
	mc.install('zsh', home=str(home), environ=env)
	assert (home / '.zshrc').exists()
	mc.uninstall('zsh', home=str(home), environ=env)
	assert not (home / '.zshrc').exists()


@pytest.mark.parametrize('zshrc, noted', [
	(None, True),
	('setopt nobeep\n', True),
	('# autoload -Uz compinit && compinit\n', True),
	('autoload -Uz compinit\ncompinit -i\n', False),
	('source $ZSH/oh-my-zsh.sh\n', False),
	('zinit light zsh-users/zsh-completions\nzicompinit; zicdreplay\n', False),
], ids=['no-zshrc', 'no-compinit', 'commented-out', 'compinit', 'oh-my-zsh', 'zinit'])
def test_zsh_install_says_when_the_rc_file_does_not_start_completion(tmp_path, zshrc, noted):
	# TAB needs zsh's completion system, which zsh starts only when told to
	env, home = make_home(tmp_path)
	rc = home / '.zshrc'
	if zshrc is not None:
		rc.write_text(zshrc)
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	notes = [message for message in messages if 'compinit' in message]
	note = "TAB needs zsh's completion system, which {0} does not seem to start: if TAB does not complete mssh in a new zsh, add this line to {0}: autoload -Uz compinit && compinit".format(rc)
	assert notes == ([note] if noted else []), messages
	# installing again says it again
	assert [message for message in mc.install('zsh', home=str(home), environ=env, command=ENGINE)[1] if 'compinit' in message] == notes


def test_install_never_overwrites_foreign_files(tmp_path):
	env, home = make_home(tmp_path)
	target = home / '.config' / 'fish' / 'completions' / 'mssh.fish'
	target.parent.mkdir(parents=True)
	target.write_text('# my own\n')
	code, messages = mc.install('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'
	assert any('skipped' in message for message in messages)
	mc.uninstall('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'


def test_bash_always_loads_from_bashrc(tmp_path, monkeypatch):
	# bash-completion being installed does not mean it runs in the user's shells (stock Debian root):
	# the ~/.bashrc hook works either way
	env, home = make_home(tmp_path)
	assert mc.install('bash', home=str(home), environ=env)[0] == 0
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	assert glue.read_text().startswith('# MSSH_COMPLETE_GLUE')
	assert mc.RC_BEGIN_CREATED in (home / '.bashrc').read_text()
	assert not (home / '.local' / 'share' / 'bash-completion').exists()


# With HOME empty, expanduser('~') is '/', and install wrote /.bashrc. These tests never let it get there:
# expanduser, the user database, os.environ's HOME and the working directory all point into tmp_path,
# and the '/' cases go only to the function that names the home directory, which writes nothing.
def _no_real_home(tmp_path, monkeypatch, user_home):
	import pwd
	for name in ('expanded', 'environ', 'cwd'):
		(tmp_path / name).mkdir()
	monkeypatch.setattr(os.path, 'expanduser', lambda path: str(tmp_path / 'expanded') + path[1:] if path.startswith('~') else path)
	monkeypatch.setenv('HOME', str(tmp_path / 'environ'))
	monkeypatch.chdir(str(tmp_path / 'cwd'))
	def getpwuid(uid):
		if user_home is None:
			raise KeyError(uid)
		return pwd.struct_passwd(('u', 'x', uid, 0, '', user_home, '/bin/sh'))
	monkeypatch.setattr(pwd, 'getpwuid', getpwuid)


@pytest.mark.parametrize('environ_home, user_home, expected', [
	('/', '/', None),
	('//', '/', None),
	('', '/', None),
	('', None, None),
	('', 'USER', 'USER'),
	('ENV', '/', 'ENV'),
])
def test_the_home_directory_is_never_slash(tmp_path, monkeypatch, environ_home, user_home, expected):
	names = {'USER': str(tmp_path / 'user'), 'ENV': str(tmp_path / 'env')}
	_no_real_home(tmp_path, monkeypatch, names.get(user_home, user_home))
	environ = {'HOME': names.get(environ_home, environ_home)}
	if expected is None:
		with pytest.raises(mc.InstallError):
			mc._home_directory(None, environ)
	else:
		assert mc._home_directory(None, environ) == names[expected]


def test_install_with_an_empty_home_uses_the_user_database(tmp_path, monkeypatch):
	_no_real_home(tmp_path, monkeypatch, str(tmp_path / 'user'))
	(tmp_path / 'user').mkdir()
	environ = {'HOME': '', 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'XDG_RUNTIME_DIR': str(tmp_path)}
	assert mc.install('bash', environ=environ, command=ENGINE)[0] == 0
	assert mc.RC_BEGIN_CREATED in (tmp_path / 'user' / '.bashrc').read_text()
	assert [os.listdir(str(tmp_path / name)) for name in ('expanded', 'environ', 'cwd')] == [[], [], []]
	assert mc.uninstall('bash', environ=environ)[0] == 0
	assert os.listdir(str(tmp_path / 'user')) == ['.local']


@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_install_without_a_home_directory_changes_nothing(tmp_path, monkeypatch, action):
	_no_real_home(tmp_path, monkeypatch, None)
	environ = {'HOME': '', 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'XDG_RUNTIME_DIR': str(tmp_path)}
	code, messages = mc.install('bash', environ=environ, command=ENGINE) if action == 'install' else mc.uninstall('bash', environ=environ)
	assert (code, messages) == (1, ['did not change anything: HOME is empty and the user database names no home directory; set HOME and run this again'])
	assert [os.listdir(str(tmp_path / name)) for name in ('expanded', 'environ', 'cwd')] == [[], [], []]


def _latin1_locale():
	'''A Latin-1 (ISO 8859-1 or -15) locale this machine has, or None.'''
	try:
		names = subprocess.run(['locale', '-a'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('ascii', 'replace').split()
	except OSError:
		return None
	return next((name for name in names if 'iso88591' in name.lower().replace('-', '').replace('_', '')), None)


def test_install_under_a_latin1_locale_writes_paths_as_they_are_on_disk(tmp_path):
	# Python decodes a non-ASCII HOME as Latin-1 there: written as UTF-8, the glue path in the rc
	# block was re-encoded (c3 83 c2 a9 for c3 a9 on disk), and [ -r ... ] skipped loading it
	bash = require_shell('bash')
	locale = _latin1_locale()
	if locale is None:
		pytest.skip('no Latin-1 locale here')
	env, _ = make_home(tmp_path)
	home = os.fsencode(str(tmp_path)) + b'/h\xc3\xa9'
	os.mkdir(home)
	env = dict(env, HOME=home, LC_ALL=locale)
	script = 'import mssh_complete as mc; mc.completion_command(["install", "bash"])'
	subprocess.run([sys.executable, '-c', script], env=env, cwd=str(REPO), stdout=subprocess.DEVNULL, check=True, timeout=60)
	with open(home + b'/.bashrc', 'rb') as f:
		assert home + b'/.local/share/multiSSH3/completion.bash' in f.read()
	result = subprocess.run([bash, '-i', '-c', 'type -t _mssh_complete || :'], env=env, cwd=home,
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
	assert result.stdout.decode().strip() == 'function'


LOGIN_LINE = '[ -f ~/.bashrc ] && . ~/.bashrc'

@pytest.mark.parametrize('files, reads', [
	({}, None),
	({'.profile': 'PATH=$HOME/bin:$PATH\n'}, '.profile'),
	({'.profile': 'if [ -n "$BASH_VERSION" ]; then . "$HOME/.bashrc"; fi\n'}, ''),
	({'.bash_login': LOGIN_LINE + '\n'}, ''),
	# bash reads the first of the three that exists
	({'.bash_profile': 'export EDITOR=vi\n', '.profile': LOGIN_LINE + '\n'}, '.bash_profile'),
	# a login file that sources another one which loads ~/.bashrc (one level deep)
	({'.bash_profile': '. ~/.profile\n', '.profile': LOGIN_LINE + '\n'}, ''),
	({'.bash_profile': '[ -f "$HOME/.profile" ] && source "$HOME/.profile"\n', '.profile': 'if [ -n "$BASH_VERSION" ]; then . "$HOME/.bashrc"; fi\n'}, ''),
	({'.bash_profile': '# . ~/.profile\n', '.profile': LOGIN_LINE + '\n'}, '.bash_profile'),
	({'.bash_profile': '. ~/.profile\n', '.profile': 'PATH=$HOME/bin:$PATH\n'}, '.bash_profile'),
])
def test_bash_install_says_when_login_shells_do_not_load_bashrc(tmp_path, files, reads):
	# login shells (ssh logins, macOS terminals) read ~/.bash_profile, ~/.bash_login or ~/.profile,
	# not ~/.bashrc: most of those load ~/.bashrc, and where none does the glue never loads there
	env, home = make_home(tmp_path)
	for name, text in files.items():
		(home / name).write_text(text)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	if reads is None:
		assert messages[-1] == ('note: bash login shells (ssh logins, macOS terminals) read {0}/.bash_profile, .bash_login or .profile,'
			' and there is none to load {0}/.bashrc; for autocomplete there too, create {0}/.bash_profile holding: {1}').format(home, LOGIN_LINE)
	elif reads:
		assert messages[-1] == ('note: bash login shells (ssh logins, macOS terminals) read {}, which does not seem to load {};'
			' for autocomplete there too, add this line to it: {}').format(home / reads, home / '.bashrc', LOGIN_LINE)
	else:
		assert messages[-1] == 'added a block loading it to {}'.format(home / '.bashrc')


def test_the_line_the_login_note_suggests_loads_the_glue(tmp_path):
	path = require_shell('bash')
	env, home = make_home(tmp_path)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[1][-1].endswith(LOGIN_LINE)
	def loaded():
		result = subprocess.run([path, '-l', '-i', '-c', 'type -t _mssh_complete || :'], env=env, cwd=str(home),
			stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
		return result.stdout.decode().strip() == 'function'
	assert not loaded()
	(home / '.bash_profile').write_text(LOGIN_LINE + '\n')
	assert loaded()


# one install or uninstall in a child process, which may not write a file past a size limit (as a full
# disk or a quota would stop it part way); prints what the call returned, or what it raised
LIMITED_CALL = r'''
import json, resource, sys
import mssh_complete as mc
limit, call, arguments = int(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
if limit >= 0:
	resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
try:
	print(json.dumps(getattr(mc, call)(**arguments)))
except Exception as error:
	print(json.dumps(['raised', repr(error)]))
'''

def _with_a_file_size_limit(limit, call, **arguments):
	result = subprocess.run([sys.executable, '-c', LIMITED_CALL, str(limit), call, json.dumps(arguments)],
		cwd=str(REPO), stdout=subprocess.PIPE, timeout=60)
	return json.loads(result.stdout.decode())

def _in_a_child(call, **arguments):
	'''What the call returns in a child process, or ['hung', []] when it did not end within 10 s.'''
	try:
		result = subprocess.run([sys.executable, '-c', LIMITED_CALL, '-1', call, json.dumps(arguments)],
			cwd=str(REPO), stdout=subprocess.PIPE, timeout=10)
	except subprocess.TimeoutExpired:
		return ['hung', []]
	return json.loads(result.stdout.decode())


@pytest.mark.parametrize('kind', ['fifo', 'device'])
def test_an_rc_file_that_is_not_a_regular_file_is_left_alone(tmp_path, kind):
	# ~/.bashrc linked to /dev/null turns it off: install as root replaced /dev/null with a file
	# holding the block (the node here is the test's own, in tmp_path), and reading a FIFO waited forever
	env, home = make_home(tmp_path)
	node = tmp_path / 'node'
	if kind == 'fifo':
		os.mkfifo(str(node))
	elif os.geteuid() == 0:
		os.mknod(str(node), 0o666 | stat.S_IFCHR, os.makedev(1, 3))
	else:
		pytest.skip('only root may make a device node')
	rc = home / '.bashrc'
	os.symlink(str(node), str(rc))
	code, messages = _in_a_child('install', shell='bash', home=str(home), environ=env, command=ENGINE)
	is_node = stat.S_ISFIFO if kind == 'fifo' else stat.S_ISCHR
	assert is_node(os.stat(str(node)).st_mode)
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	assert (code, messages[1:]) == (1, ['did not change {} (a link to {}): not a regular file'.format(rc, node),
		'to load it anyway, add these lines to it yourself:', mc.RC_BEGIN, '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue), mc.RC_END])
	# nothing of mssh's can be in it
	assert _in_a_child('uninstall', shell='bash', home=str(home), environ=env) == [0, ['removed {}'.format(glue)]]
	assert is_node(os.stat(str(node)).st_mode)


@pytest.mark.parametrize('change', ['add', 'update', 'remove'])
def test_a_failed_rc_write_leaves_the_rc_file_as_it_was(tmp_path, change):
	# install after an upgrade rewrote ~/.bashrc in place: what did not fit on the disk was lost
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text(''.join('alias x{0}="echo {0}"  # user line {0}\n'.format(number) for number in range(6000)))
	if change != 'add':
		assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	before = rc.read_bytes()
	# what is beside the rc file, but the glue's directory (adding writes it first)
	names = set(os.listdir(str(home))) - {'.local'}
	arguments = dict(shell='bash', home=str(home), environ=env)
	if change == 'remove':
		code, messages = _with_a_file_size_limit(len(before) // 2, 'uninstall', **arguments)
	else:
		# adding: the old text fits under the limit, the block does not
		limit = len(before) + 20 if change == 'add' else len(before) // 2
		code, messages = _with_a_file_size_limit(limit, 'install', command=ENGINE, editor=change == 'update', **arguments)
	assert rc.read_bytes() == before
	assert code == 1
	assert messages[-1].startswith('could not change {}: '.format(rc)) and messages[-1].endswith('; it is as it was')
	# and no temporary file is left behind
	assert set(os.listdir(str(home))) - {'.local'} == names


BLOCK_LINE = '[ -r /x/completion.bash ] && . /x/completion.bash 2>/dev/null || :\n'
USER_LINES = 'export PATH=$HOME/bin:$PATH\nalias ll="ls -l"\n'
BEGIN, CREATED, END = mc.RC_BEGIN + '\n', mc.RC_BEGIN_CREATED + '\n', mc.RC_END + '\n'
BROKEN_MARKERS = {
	'end deleted': ('export A=1\n\n' + BEGIN + BLOCK_LINE + USER_LINES, '(begin at line 3, no end)'),
	'begin deleted': ('export A=1\n\n' + BLOCK_LINE + END + USER_LINES, '(end at line 4, no begin)'),
	'end before begin': (END + USER_LINES + BEGIN + BLOCK_LINE, '(end at line 1, begin at line 4)'),
	'begin twice': (BEGIN + BLOCK_LINE + USER_LINES + BEGIN + BLOCK_LINE + END, '(begin at line 1, begin at line 5, end at line 7)'),
	'block twice': (CREATED + BLOCK_LINE + END + USER_LINES + BEGIN + BLOCK_LINE + END,
		'(begin at line 1, end at line 3, begin at line 6, end at line 8)'),
}

@pytest.mark.parametrize('damage', sorted(BROKEN_MARKERS))
@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_rc_files_with_broken_markers_are_left_alone(tmp_path, action, damage):
	# with its end line deleted, install appended a second block, and the next install replaced
	# everything from the first begin line to the new end line: the user's lines in between too
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	text, markers = BROKEN_MARKERS[damage]
	rc.write_text(text)
	for _ in range(2):
		if action == 'install':
			code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
		else:
			code, messages = mc.uninstall('bash', home=str(home), environ=env)
		assert rc.read_text() == text
		assert code == 1
		assert messages[-2:] == [
			'did not change {}: its mssh completion markers {} are not one block, so mssh cannot tell its lines from yours'.format(rc, markers),
			'fix them by hand (leave one block or none), then run this again']


def test_marker_lines_are_found_however_they_were_edited(tmp_path):
	# a marker with spaces around it, or as the last line without a line end, still counts:
	# a block it opens or closes is not mistaken for no block at all
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	text = USER_LINES + '  ' + mc.RC_BEGIN + ' \n' + BLOCK_LINE + USER_LINES + mc.RC_BEGIN
	rc.write_text(text)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 1 and '(begin at line 3, begin at line 7, no end)' in messages[-2]
	assert rc.read_text() == text


@pytest.mark.parametrize('zdotdir', ['set', 'empty'])
def test_zsh_installs_where_zsh_reads_its_rc_file(tmp_path, zdotdir):
	# zsh reads $ZDOTDIR/.zshrc when ZDOTDIR is set: install wrote ~/.zshrc, which zsh never read
	env, home = make_home(tmp_path)
	directory = home / '.config' / 'zsh' if zdotdir == 'set' else home
	directory.mkdir(parents=True, exist_ok=True)
	rc = directory / '.zshrc'
	rc.write_text('setopt nobeep\n')
	env = dict(env, ZDOTDIR=str(directory) if zdotdir == 'set' else '')
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	# other notes may follow it
	assert 'added a block loading it to {}'.format(rc) in messages
	assert mc.RC_BEGIN in rc.read_text()
	assert sorted(name for name in os.listdir(str(home)) if name.startswith('.zsh')) == (['.zshrc'] if zdotdir == 'empty' else [])
	mc.uninstall('zsh', home=str(home), environ=env)
	assert rc.read_text() == 'setopt nobeep\n'


# a stand-in zsh: the answer goes to the file named by its last argument (`print ... >| "$1"`),
# and to stdout as an `mssh-zdotdir:` line (how the first version asked)
FAKE_ZSH = '''#!/bin/sh
for last; do :; done
answer() {{
	echo "mssh-zdotdir:$1"
	case $last in /*) printf '%s\n' "$1" > "$last" ;; esac
}}
{}
'''

@pytest.mark.parametrize('answer', ['zdotdir', 'chatty zshenv', 'holds stdout', 'none', 'fails'])
def test_zsh_install_asks_zsh_for_zdotdir(tmp_path, answer):
	# ZDOTDIR set in ~/.zshenv without export is not in mssh's environment: zsh itself knows it
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	(home / 'bin').mkdir()
	fake = home / 'bin' / 'zsh'
	fake.write_text(FAKE_ZSH.format({
		'zdotdir': 'answer {}'.format(zdotdir),
		'chatty zshenv': 'echo "mssh-zdotdir:/wrong"; echo hello from zshenv; answer {}'.format(zdotdir),
		# a zshenv that starts a background job without redirecting it: reading zsh's output waited for the job
		'holds stdout': '(sleep 8) & answer {}'.format(zdotdir),
		'none': 'answer ""',
		'fails': 'exit 1'}[answer]))
	fake.chmod(0o755)
	env = dict(env, PATH=str(home / 'bin') + os.pathsep + env['PATH'])
	started = time.monotonic()
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0 and time.monotonic() - started < 4
	rc = home / '.zshrc' if answer in ('none', 'fails') else zdotdir / '.zshrc'
	assert mc.RC_BEGIN_CREATED in rc.read_text()
	# when zsh does not answer, the operator is told which file was used
	note = 'note: zsh did not say whether ZDOTDIR is set (it exited with status 1): using {}'.format(rc)
	assert [message for message in messages if message.startswith('note: zsh')] == ([note] if answer == 'fails' else [])
	assert mc.uninstall('zsh', home=str(home), environ=env)[0] == 0
	assert not rc.exists()


def test_zsh_install_says_when_there_is_no_zsh_to_ask(tmp_path):
	env, home = make_home(tmp_path)
	(home / 'bin').mkdir()
	code, messages = mc.install('zsh', home=str(home), environ=dict(env, PATH=str(home / 'bin')), command=ENGINE)
	assert code == 0 and 'note: zsh did not say whether ZDOTDIR is set (zsh is not on PATH): using {}'.format(home / '.zshrc') in messages


@pytest.mark.parametrize('job', ['', '(sleep 8) &\n'])
def test_a_new_zsh_loads_the_glue_from_an_unexported_zdotdir(tmp_path, job):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	# a background job started by ~/.zshenv keeps zsh's stdout open after zsh is done
	(home / '.zshenv').write_text('ZDOTDIR=$HOME/.config/zsh\n' + job)
	(zdotdir / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	assert 'ZDOTDIR' not in env
	started = time.monotonic()
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert time.monotonic() - started < 4
	assert not (home / '.zshrc').exists()
	result = subprocess.run([path, '-i', '-c', 'print -r -- "loaded=${+functions[_mssh]}"'], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	assert 'loaded=1' in result.stdout.decode('utf-8', 'replace')


def test_a_new_zsh_loads_the_glue_from_zdotdir(tmp_path):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	(zdotdir / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	env = dict(env, ZDOTDIR=str(zdotdir))
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	result = subprocess.run([path, '-i', '-c', 'print -r -- "loaded=${+functions[_mssh]}"'], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	assert 'loaded=1' in result.stdout.decode('utf-8', 'replace')


def test_fish_installs_into_its_config_directory(tmp_path):
	# fish's configuration directory is $XDG_CONFIG_HOME/fish when that is set
	env, home = make_home(tmp_path)
	config = home / 'xdg'
	env = dict(env, XDG_CONFIG_HOME=str(config))
	code, messages = mc.install('fish', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	wrote = sorted(message.split(' ', 1)[1] for message in messages if message.startswith('wrote '))
	assert wrote == sorted([str(config / 'fish' / 'conf.d' / 'mssh-complete.fish')]
		+ [str(config / 'fish' / 'completions' / (name + '.fish')) for name in mc.MSSH_NAMES])
	assert not (home / '.config').exists()
	mc.uninstall('fish', home=str(home), environ=env)
	assert [name for _, _, names in os.walk(str(config)) for name in names] == []


def test_a_new_fish_loads_the_glue_from_xdg_config_home(setup):
	fish = require_shell('fish')
	env, home = setup
	# fish loads a command's completions only when the command exists
	(home / 'bin').mkdir()
	(home / 'bin' / 'mssh').write_text('#!/bin/sh\n')
	(home / 'bin' / 'mssh').chmod(0o755)
	env = dict(env, XDG_CONFIG_HOME=str(home / 'xdg'), PATH=str(home / 'bin') + os.pathsep + env['PATH'])
	assert mc.install('fish', home=str(home), environ=env, command=ENGINE)[0] == 0
	script = 'complete -C"mssh --no_wa"; functions -q __mssh_complete_ctrl_r; and echo keys loaded'
	result = subprocess.run([fish, '-c', script], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	output = result.stdout.decode('utf-8', 'replace')
	assert '--no_watch' in output and 'keys loaded' in output


def test_rc_files_that_are_links_stay_links(tmp_path):
	# dotfile managers link ~/.bashrc into a repository: the file in the repository is the one changed
	env, home = make_home(tmp_path)
	(home / 'dotfiles').mkdir()
	target = home / 'dotfiles' / 'bashrc'
	target.write_text('alias ll="ls -l"\n')
	target.chmod(0o640)
	rc = home / '.bashrc'
	os.symlink(os.path.join('dotfiles', 'bashrc'), str(rc))
	shown = '{} (a link to {})'.format(rc, target)
	assert 'added a block loading it to ' + shown in mc.install('bash', home=str(home), environ=env, command=ENGINE)[1]
	assert 'updated the mssh block in ' + shown in mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)[1]
	assert rc.is_symlink() and 'export MSSH_COMPLETE_EDITOR=1\n' in target.read_text()
	assert stat.S_IMODE(target.stat().st_mode) == 0o640
	assert mc.uninstall('bash', home=str(home), environ=env) == (0, [
		'removed ' + str(home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'), 'removed the mssh block from ' + shown])
	assert rc.is_symlink() and target.read_text() == 'alias ll="ls -l"\n'
	assert os.listdir(str(home / 'dotfiles')) == ['bashrc']


@pytest.mark.skipif(os.geteuid() != 0, reason='only root may give a file to another user')
def test_rc_files_keep_their_owner(tmp_path):
	# root installing with HOME set to a user's home (sudo -E): the file must stay the user's
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	os.chown(str(rc), 4321, 4322)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322) and mc.RC_BEGIN in rc.read_text()
	assert mc.uninstall('bash', home=str(home), environ=env)[0] == 0
	assert (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322) and rc.read_text() == 'alias ll="ls -l"\n'


@pytest.mark.skipif(os.geteuid() != 0, reason='only root may give a file to another user')
def test_an_rc_file_whose_owner_cannot_be_kept_is_not_replaced(tmp_path, monkeypatch):
	# a group-writable ~/.bashrc of another user: replacing it made it the installing user's
	# (fchown fails without root, here made to fail)
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	os.chown(str(rc), 4321, 4322)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	before = rc.read_text()
	def not_permitted(*args):
		raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
	monkeypatch.setattr(os, 'fchown', not_permitted)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:-4] == ['could not change {}: replacing it would change its owner; it is as it was'.format(rc),
		'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:']
	assert rc.read_text() == before and (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322)
	assert sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history', '.multiSSH3.config.json']


def test_a_created_rc_file_gets_the_usual_permissions(tmp_path):
	env, home = make_home(tmp_path)
	mask = os.umask(0o027)
	try:
		assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	finally:
		os.umask(mask)
	assert stat.S_IMODE((home / '.zshrc').stat().st_mode) == 0o640


@pytest.mark.parametrize('change', ['create', 'add', 'update', 'remove'])
def test_an_rc_file_mssh_may_not_change_gets_the_lines_to_change_by_hand(tmp_path, monkeypatch, change):
	# home-manager links ~/.bashrc into the read-only Nix store, and managed dotfiles may be read-only:
	# install ended in a traceback there; the operator needs the lines to put in by hand instead
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	if change != 'create':
		rc.write_text('alias ll="ls -l"\n')
	if change in ('update', 'remove'):
		assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	for name in ('_replace_file', '_append_file'):
		def read_only(path, text, write=getattr(mc, name)):
			if path == str(rc):
				raise OSError(errno.EROFS, os.strerror(errno.EROFS))
			write(path, text)
		monkeypatch.setattr(mc, name, read_only)
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	failed = 'could not change {}: {}; it is as it was'.format(rc, os.strerror(errno.EROFS))
	if change == 'remove':
		code, messages = mc.uninstall('bash', home=str(home), environ=env)
		advice = ['to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	else:
		code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=change == 'update')
		if change == 'update':
			advice = ['to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
				mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
		else:
			advice = ['to load it anyway, add these lines to it yourself:', mc.RC_BEGIN, load, mc.RC_END]
	assert code == 1
	assert messages[-len(advice) - 1:] == [failed] + advice


def test_hard_linked_rc_files_stay_linked(tmp_path):
	# replacing a hard-linked ~/.bashrc split it from the dotfiles copy, which kept the old text
	env, home = make_home(tmp_path)
	(home / 'dotfiles').mkdir()
	dotfile = home / 'dotfiles' / 'bashrc'
	dotfile.write_text('alias ll="ls -l"\n')
	rc = home / '.bashrc'
	os.link(str(dotfile), str(rc))
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert mc.RC_BEGIN in dotfile.read_text() and rc.stat().st_ino == dotfile.stat().st_ino
	before = rc.read_text()
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	split = 'did not change {}: it has 2 hard links, which replacing it would split'.format(rc)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:] == [split, 'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
		mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
	code, messages = mc.uninstall('bash', home=str(home), environ=env)
	assert code == 1 and messages[-2:] == [split, 'to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	assert rc.read_text() == before and rc.stat().st_ino == dotfile.stat().st_ino


@pytest.mark.parametrize('obstacle', ['bind mount', 'directory not writable'])
def test_rc_files_that_cannot_be_replaced_still_get_a_new_block(tmp_path, monkeypatch, obstacle):
	# a bind-mounted ~/.bashrc (docker -v, devcontainers, Kubernetes subPath) cannot be renamed over
	# (EBUSY), and a home directory the user may not write takes no temporary file: the first install
	# appends in place as it always did; editing an existing block says what to change by hand
	import tempfile
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	if obstacle == 'bind mount':
		replace = os.replace
		def busy(source, target):
			if target == str(rc):
				raise OSError(errno.EBUSY, os.strerror(errno.EBUSY), source, target)
			replace(source, target)
		monkeypatch.setattr(os, 'replace', busy)
		reason = 'cannot replace it ({})'.format(os.strerror(errno.EBUSY))
	else:
		mkstemp = tempfile.mkstemp
		def denied(*args, **kwargs):
			if kwargs.get('dir') == str(home):
				raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), os.path.join(str(home), '.bashrc.x.mssh-tmp'))
			return mkstemp(*args, **kwargs)
		monkeypatch.setattr(tempfile, 'mkstemp', denied)
		reason = 'cannot make a file beside it ({})'.format(os.strerror(errno.EACCES))
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 0 and 'added a block loading it to {}'.format(rc) in messages
	assert rc.read_text() == 'alias ll="ls -l"\n\n{}\n{}\n{}\n'.format(mc.RC_BEGIN, load, mc.RC_END)
	before = rc.read_text()
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:] == ['could not change {}: {}; it is as it was'.format(rc, reason),
		'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
		mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
	code, messages = mc.uninstall('bash', home=str(home), environ=env)
	assert code == 1 and messages[-2:] == ['could not change {}: {}; it is as it was'.format(rc, reason),
		'to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	# never a temporary file: not in the messages, not left behind
	assert rc.read_text() == before and sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history', '.multiSSH3.config.json']


@pytest.mark.skipif(os.geteuid() == 0, reason='root may write any file')
def test_install_leaves_a_read_only_rc_file_alone(tmp_path):
	# replacing the file would work (the directory is writable), but the user made it read-only
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	rc.chmod(0o444)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	failed = 'could not change {}: Permission denied; it is as it was'.format(rc)
	assert code == 1 and messages[messages.index(failed) + 1] == 'to load it anyway, add these lines to it yourself:'
	assert rc.read_text() == 'alias ll="ls -l"\n'


def test_bash_delegation_keeps_text_before_word_breaks(setup):
	# bash's word ($2) stops at ":" and "=", the delegated results start at the whole word
	env, home = setup
	(home / 'a:bfile').write_text('')
	(home / 'x=abc').write_text('')
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh h nosuchcmd a:b') == 'mssh h nosuchcmd a:bfile '
		assert session.line_after('mssh h nosuchcmd x=a') == 'mssh h nosuchcmd x=abc '
	finally:
		session.close()


def test_bash_history_paths_are_escaped_once(tmp_path):
	path = str(tmp_path / 'home' / 'my hist.txt')
	env, home = make_home(tmp_path, ["1790000000\t/x/multiSSH3.py\t-su -hf='{}'\th\t\"uptime\"".format(path)])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh -hf ' + path[:-len(' hist.txt')]) == 'mssh -hf ' + path.replace(' ', '\\ ') + ' '
	finally:
		session.close()


def test_bash_delegation_that_turns_on_filenames_does_not_escape_twice(tmp_path):
	env, home = make_home(tmp_path, ["1790000000\t/x/multiSSH3.py\t-su\th\t'fakefile ab;cd'"])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh h fakefile ab') == 'mssh h fakefile ab\\;cd '
	finally:
		session.close()


@pytest.mark.parametrize('option', ['set -e', 'set -u'])
def test_bash_shell_options_do_not_break_tab(setup, option):
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=option)
	try:
		assert session.line_after('mssh h nosuchcmd zzq') == 'mssh h nosuchcmd zzq'
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert b'unbound variable' not in session.output
	finally:
		session.close()


def test_bash_set_e_survives_a_missing_engine(setup):
	# bash 4.4 exits a set -e shell after a process substitution whose command failed
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash', ['/nonexistent/engine']), bash_completion=False, extra='set -e')
	try:
		assert session.line_after('mssh h zzq') == 'mssh h zzq'
	finally:
		session.close()


# as mssh records `mssh web1 "nosuchcmd status 'ssh*'"` and the same with fakefile
QUOTED_WORD_HISTORY = ['1790000000\t/x/multiSSH3.py\t-su\tweb1\t\'{} status \'"\'"\'ssh*\'"\'"\'\''.format(name) for name in ('nosuchcmd', 'fakefile')]


def words(line):
	'''The words a line means, whatever quoting the shell chose.'''
	return None if line is None else [token.text for token in mc.lex(line)]


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_command_words_are_inserted_with_their_quotes(tmp_path, shell):
	# mssh passes the quotes of 'ssh*' on to the remote shell only when the local word holds them
	env, home = make_home(tmp_path, QUOTED_WORD_HISTORY)
	build_index(env)
	# an empty working directory: the shells add its files to the words of a remote command
	empty = tmp_path / 'empty'
	empty.mkdir()
	cd = "cd '{}'".format(empty)
	typed = ['mssh web1 nosuchcmd status ']
	if shell == 'bash':
		session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=cd)
		# a delegated completion turns on file name quoting: bash quotes the word itself
		typed.append('mssh web1 fakefile status ')
	elif shell == 'zsh':
		session = zsh_session(home, env, glue_file(home, 'zsh'), extra=cd)
		typed.append("mssh web1 nosuchcmd status \\'ss")
	else:
		session = fish_session(home, env, '', pre="source '{}'; {}".format(glue_file(home, 'fish'), cd))
		typed.append("mssh web1 nosuchcmd status \\'ss")
	try:
		for line in typed:
			assert words(session.line_after(line)) == words(line)[:4] + ["'ssh*'"], line
	finally:
		session.close()


def test_bash_with_blesh_loaded_but_not_attached_gets_escaped_words(tmp_path):
	# readline completes, not ble.sh: the words must come escaped as for plain bash
	env, home = make_home(tmp_path, QUOTED_WORD_HISTORY)
	build_index(env)
	empty = tmp_path / 'empty'
	empty.mkdir()
	extra = "BLE_VERSION=0.4.0; BLE_ATTACHED=; cd '{}'".format(empty)
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=extra)
	try:
		assert words(session.line_after('mssh web1 nosuchcmd status ')) == ['mssh', 'web1', 'nosuchcmd', 'status', "'ssh*'"]
	finally:
		session.close()


DUMP_WITH_MSSH = "#files: 812\t#version: 5.9\n_comps=(\n'git' '_git'\n'mssh' '_mssh'\n'mssh3' '_mssh'\n)\n"


@pytest.mark.parametrize('dump_dir, name', [('home', '.zcompdump'), ('home', '.zcompdump-node1-5.9'),
	('zdotdir', '.zcompdump'), ('elsewhere', 'zcompdump-5.9')])
def test_uninstall_zsh_says_to_remove_a_dump_that_still_maps_mssh(tmp_path, dump_dir, name):
	# zsh's dump keeps mssh=_mssh after the glue is gone: the next TAB said "command not found: _mssh"
	env, home = make_home(tmp_path)
	zdotdir = tmp_path / 'zdot'
	zdotdir.mkdir()
	env = dict(env, ZDOTDIR=str(zdotdir))
	directory = {'home': home, 'zdotdir': zdotdir, 'elsewhere': tmp_path / 'cache'}[dump_dir]
	directory.mkdir(exist_ok=True)
	dump = directory / name
	dump.write_text(DUMP_WITH_MSSH)
	if dump_dir == 'elsewhere':
		env['ZSH_COMPDUMP'] = str(dump)
	assert mc.install('zsh', home=str(home), environ=env)[0] == 0

	status, messages = mc.uninstall('zsh', home=str(home), environ=env)

	assert status == 0
	assert messages[-1] == ("zsh's completion dump {0} still maps mssh to _mssh, which is gone: "
		"remove it (rm {0}) and zsh makes a new one".format(dump))
	# mssh leaves zsh's own file alone
	assert dump.read_text() == DUMP_WITH_MSSH


@pytest.mark.parametrize('shell, dump', [('zsh', "_comps=(\n'git' '_git'\n)\n"), ('bash', DUMP_WITH_MSSH)])
def test_uninstall_says_nothing_of_a_dump_without_mssh(tmp_path, shell, dump):
	env, home = make_home(tmp_path)
	(home / '.zcompdump').write_text(dump)
	assert mc.install(shell, home=str(home), environ=env)[0] == 0

	_, messages = mc.uninstall(shell, home=str(home), environ=env)

	assert not [message for message in messages if 'zcompdump' in message]
