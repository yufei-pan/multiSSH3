'''
SP2 in real shells: grey suggestions, the Ctrl-R picker and the plain-bash mssh line editor.

Every shell gets a private HOME holding an mssh history where one invocation clearly dominates,
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import os
import re
import select
import shlex
import subprocess
import termios
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, require_zsh_5_3, WITH_AND_WITHOUT_DEBUG_LOG, with_debug_log, aged, bash_locale, bash_session, blesh_session, build_index,
	debug_log_size, fish_session, make_home, require_shell, without_command, zsh_session)

HISTORY = ['17900000{:02d}\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"'.format(number) for number in range(6)] + [
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]
SHELL_HISTORY = 'echo aa1\necho aa2\necho bb\n'
FAKE_MSSH = 'mssh() { printf "@@RAN[%s]@@\\n" "$*"; }'
RIGHT = '\x1b[C'
LEFT = '\x1b[D'
UP = '\x1b[A'


@pytest.fixture
def home(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	(home / '.bash_history').write_text(SHELL_HISTORY)
	return env, home


def glue_file(home, shell, name=None, command=ENGINE):
	path = home / (name or 'glue.' + shell)
	path.write_text(mc.render_glue(shell, command))
	return path


def slow_engine(home, delay, deaf=False, only=None):
	'''
	The engine, delay seconds slow to start (an NFS home, a loaded machine); deaf: Ctrl-C does not stop
	it either, as when it waits on a hung file system; only: slow for that command alone (pick), not
	for the queries typing makes.
	'''
	import shlex
	path = home / 'slow-engine'
	slow = '{}sleep {}\n'.format("trap '' INT\n" if deaf else '', delay)
	if only:
		slow = 'if [ "$1" = {} ]; then\n{}fi\n'.format(only, slow)
	path.write_text('#!/bin/sh\n{}exec {} "$@"\n'.format(slow, ' '.join(shlex.quote(part) for part in ENGINE)))
	path.chmod(0o755)
	return [str(path)]


def printed(session, keys, wait=0.6):
	'''Send keys, then the print key; the command line the shell printed (None if it did not).'''
	session.send(keys)
	time.sleep(wait)
	session.send(session.print_key)
	text = session.read_until(b']@@')
	start = text.rfind('@@LINE[')
	end = text.find(']@@', start)
	return text[start + 7:end] if start >= 0 and end > start else None


def plain(text):
	'''Terminal output without escape sequences and carriage returns.'''
	return re.sub(r'\x1b(\[[0-9;?<=>]*[ -/]*[@-~]|[()][A-Z0-9]|[=>78])', '', text).replace('\r', '')


def read_until_shown(session, text, timeout=10.0):
	'''Read until text is on screen, whatever the shell drew between its characters; return what was read.'''
	start = len(session.output)
	end = time.monotonic() + timeout
	while True:
		shown = plain(session.output[start:].decode('utf-8', 'replace'))
		if text in shown or time.monotonic() >= end:
			return shown
		session.read_for(0.1)


def words(line):
	'''The words a line means, whatever quoting was chosen.'''
	return None if line is None else [token.text for token in mc.lex(line)]


PICKED = ['mssh', 'gpu[01-16]', 'nvidia-smi']


def bash_version(env):
	output = subprocess.run([require_shell('bash'), '-c', 'echo ${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}'], env=env, stdout=subprocess.PIPE)
	return int(output.stdout.decode().strip())


# ---------------------------------------------------------------- plain bash: Ctrl-R

@WITH_AND_WITHOUT_DEBUG_LOG
def test_bash_ctrl_r_opens_the_picker_on_mssh_lines(home, debug):
	env, home = home
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_bash_picker_draws_in_the_locale_bash_runs_in(home):
	# macOS's ssh sends LC_CTYPE=UTF-8, no locale on Linux: bash keeps LANG's, C.UTF-8, and the picker
	# draws in Unicode as the shell can show it (it read LC_CTYPE and drew in ASCII)
	from complete_shell_harness import bash_locale
	env, home = home
	env = dict(env, LANG='C.UTF-8', LC_CTYPE='UTF-8')
	if bash_locale(env) != (True, False):
		pytest.skip('no C.UTF-8 here, or UTF-8 is a locale')
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'type to filter \u00b7' in session.read_until('type to filter \u00b7'.encode('utf-8'))
	finally:
		session.close()


C_SHELL = 'LC_ALL=C   # not exported: bash runs in C, mssh-complete sees the exported LANG=C.UTF-8'


def test_bash_picker_draws_in_the_locale_bash_measured_not_the_exported_one(home):
	# the exported variables say UTF-8, the shell runs in C: the picker draws in ASCII
	env, home = home
	env = dict(env, LANG='C.UTF-8')
	if bash_locale(env) != (True, False):
		pytest.skip('no C.UTF-8 here')
	session = bash_session(home, env, glue_file(home, 'bash'), extra=C_SHELL)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'type to filter - ' in session.read_until(b'type to filter')
	finally:
		session.close()


def test_bash_ctrl_r_cancel_keeps_the_line(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] nv')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'commands for')
		assert printed(session, '\x1b') == 'mssh gpu[01-16] nv'
	finally:
		session.close()


@pytest.mark.parametrize('esc', ['\x1b\x1b', '\x1b[27u', '\x1b[27;1;27~'])
def test_bash_ctrl_r_cancel_takes_esc_however_the_terminal_sends_it(home, esc):
	# two at once (a double press over ssh or mosh, Alt+Esc), the kitty keyboard protocol's CSI u
	# (tmux passes it on as the terminal sent it), xterm's modifyOtherKeys
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] nv')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'commands for')
		assert printed(session, esc) == 'mssh gpu[01-16] nv'
	finally:
		session.close()


def test_bash_ctrl_r_on_other_lines_is_still_reverse_search(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		# the second Ctrl-R finds the older match, as readline's own search does
		session.send('\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n'))
		# and the next prompt opens the picker again on mssh lines
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for' in session.read_until(b'commands for')
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_bash_ctrl_r_on_other_lines_calls_a_previous_shell_command(home, where):
	env, home = home
	fzf = '_fakefzf() { READLINE_LINE=FZF; READLINE_POINT=3; }\nbind -x \'"\\C-r": _fakefzf\''
	# bound before the glue loads, or after it in the same rc file: both are there at the first prompt
	session = bash_session(home, env, glue_file(home, 'bash'), **{'pre' if where == 'before' else 'extra': fzf})
	try:
		assert printed(session, 'ls\x12') == 'FZF'
		session.send('\x15mssh gpu[01-16] \x12')
		if bash_version(env) < 43:
			# bash 4.2 cannot list bind -x bindings: Ctrl-R stays the shell command everywhere
			assert printed(session, '') == 'FZF'
		else:
			assert 'commands for' in session.read_until(b'commands for')
	finally:
		session.close()


# Ctrl-R as fzf's key-bindings.bash binds it from bash 4 on (atuin and mcfly bind it with bind -x too)
FZF_CTRL_R = r'''_fakefzf() { READLINE_LINE=FZF; READLINE_POINT=3; }
bind -m emacs-standard -x '"\C-r": _fakefzf'
bind -m vi-command -x '"\C-r": _fakefzf'
bind -m vi-insert -x '"\C-r": _fakefzf'
'''
VI_PRINT_KEY = 'set -o vi\nbind -m vi-insert -x \'"\\C-x\\C-p": printf "@@LINE[%s]@@\\n" "$READLINE_LINE"\'\n'


@pytest.mark.parametrize('mode', ['emacs', 'vi'])
def test_bash_ctrl_r_over_fzf_keeps_every_shell_command_key(home, mode):
	# bash 5.1, when a plain bind replaces a bind -x key, drops the command of another bind -x key:
	# Ctrl-R then said "cannot find keymap for command", and a key of the operator's could stop working
	env, home = home
	if bash_version(env) < 43:
		pytest.skip('bash 4.2 cannot list bind -x bindings: Ctrl-R stays the shell command')
	session = bash_session(home, env, glue_file(home, 'bash'), pre=(VI_PRINT_KEY if mode == 'vi' else '') + FZF_CTRL_R)
	try:
		assert printed(session, 'ls\x12') == 'FZF'
		session.send('\x15mssh gpu[01-16] \x12')
		assert 'commands for' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		if mode == 'vi':
			# vi command mode keeps fzf's Ctrl-R: the glue leaves that keymap alone
			session.send('\x15ls\x1b')
			time.sleep(0.3)
			assert printed(session, '\x12A') == 'FZF'
		assert b'cannot find keymap' not in session.output
	finally:
		session.close()


@pytest.mark.parametrize('separator', [': ', ' '])
def test_bash_reads_a_shell_command_binding_in_both_formats(home, separator):
	# bind -X prints "\C-r": "command" before bash 5.3, "\C-r" "command" from 5.3 on (same escapes)
	env, home = home
	script = r'''. "$1"
bind() { [[ $3 == -X ]] && printf '%s\n' '"\C-x\C-p"SEP"echo x"' '"\C-r"SEP"__fzf_history__ \"a\\b\""'; }
_mssh_complete_previous emacs && printf '%s\n' "$_mssh_complete_found"
'''.replace('SEP', separator)
	result = subprocess.run([require_shell('bash'), '-c', script, 'bash', str(glue_file(home, 'bash'))], env=env,
		stdout=subprocess.PIPE, timeout=30)
	assert result.stdout.decode() == 'x:__fzf_history__ "a\\b"\n'


def test_bash_picker_leaves_keys_typed_after_the_choice(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12\rXYZ')
		time.sleep(1)
		assert words(printed(session, '')) == PICKED + ['XYZ']
	finally:
		session.close()


def test_bash_picker_draws_again_when_the_terminal_is_resized(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'type to filter')
		session.resize(24, 50)
		session.read_until(b'type to filter')
		rows = rendered(session).lines()
		box = rows[1:13]
		# bash 4.2/4.3: no prompt beside the menu (docs/limitations.md), but 4.2 redraws its line itself on a resize: when that
		# comes after the menu's redraw, the prompt is there
		version = bash_version(env)
		lines = ['@@READY@@ mssh gpu[01-16]'] if version >= 44 else ['mssh gpu[01-16]', '@@READY@@ mssh gpu[01-16]'] if version < 43 else ['mssh gpu[01-16]']
		assert rows[0] in lines and 'commands for gpu[01-16]' in box[0] and 'type to filter' in box[-1], rows
		assert len(set(len(row) for row in box)) == 1 and len(box[0]) < 50 and rows[13:] == [''] * 11, rows
		# Esc: the line as it was, nothing left of the menu; bash knows the new width
		session.send('\x1b')
		assert printed(session, '') == 'mssh gpu[01-16] '
		session.send('\x15echo "[$COLUMNS]"\r')
		session.read_until(b'[50]')
		rows = settled(session)
		assert not [row for row in rows if 'filter' in row or '│' in row or '|' in row] and rows[-2:] == ['[50]', '@@READY@@'], rows
	finally:
		session.close()


def test_bash_ctrl_r_goes_on_without_an_engine_slow_to_start(home):
	# past MSSH_COMPLETE_START_TIMEOUT Ctrl-R does what it did before, with the keys typed meanwhile;
	# the engine, ready later, leaves the terminal alone
	env, home = home
	delay = 1.5
	session = bash_session(home, dict(env, MSSH_COMPLETE_START_TIMEOUT='0.3'), glue_file(home, 'bash', command=slow_engine(home, delay)))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		started = time.monotonic()
		session.send('\x12aa')
		read_until_shown(session, 'echo aa2', 10)
		assert reverse_search_found(session, 'echo aa2'), screen(session)
		# the engine is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		session.send('\r')
		assert re.search(r'[\r\n]aa2\r\n', session.read_until(b'aa2\r\n'))
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


def test_bash_ctrl_c_while_the_picker_starts_keeps_the_line(home):
	# at once, even when Ctrl-C does not stop the engine, which then leaves the terminal alone
	env, home = home
	delay = 1.5
	session = bash_session(home, env, glue_file(home, 'bash', command=slow_engine(home, delay, deaf=True)))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		started = time.monotonic()
		session.send('\x12')
		time.sleep(0.3)
		session.send('\x03')
		session.read_until(b'@@READY@@ mssh gpu[01-16] ', 20)
		assert time.monotonic() - started < delay
		rows = [row for row in screen(session) if row]
		assert rows == ['@@READY@@ mssh gpu[01-16]'], rows
		# the engine is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		assert printed(session, 'x') == 'mssh gpu[01-16] x'
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('option', ['set -e', 'set -u', 'set -o pipefail', 'shopt -s nocasematch'])
def test_bash_shell_options_do_not_break_ctrl_r_or_the_editor(home, option):
	env, home = home
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'), extra=FAKE_MSSH + '\n' + option)
	try:
		# a path to mssh: space is a space, Ctrl-R the picker
		session.send('/x/mssh gpu[01-16] \x12')
		session.read_until(b'type to filter')
		assert words(printed(session, '\r')) == ['/x/mssh'] + PICKED[1:]
		if bash_version(env) >= 44:
			session.send('\x15mssh gp')
			session.read_until(b'nvidia-smi')
			assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
		# never ready in time: Ctrl-R searches as before, space is a space
		session.send('\x15MSSH_COMPLETE_START_TIMEOUT=0\r/x/mssh gpu[01-16] \x12aa')
		read_until_shown(session, 'echo aa2', 10)
		assert reverse_search_found(session, 'echo aa2'), screen(session)
		session.send('\x07\x15mssh xy\r')
		assert '@@RAN[xy]@@' in session.read_until(b'@@RAN[xy]@@')
		session.send('echo "[alive]"\r')
		assert '[alive]\r\n' in session.read_until(b'[alive]\r\n')
		# the option is still the operator's
		name = {'set -e': 'errexit', 'set -u': 'nounset'}.get(option, option.split()[-1])
		start = len(session.output)
		session.send('if shopt -qo {0} 2>/dev/null || shopt -q {0} 2>/dev/null; then echo "@@OPT""=on@@"; else echo "@@OPT""=off@@"; fi\r'.format(name))
		session.read_until(b'@@OPT=o')
		session.read_until(b'@@READY@@', 20)
		assert '@@OPT=on@@' in session.output[start:].decode('utf-8', 'replace')
	finally:
		session.close()


def test_bash_ctrl_r_keeps_the_last_argument(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('true lastarg\r')
		time.sleep(0.3)
		session.send('mssh x\x12')
		session.read_until(b'type to filter')
		session.send('\x1b')
		time.sleep(0.3)
		session.send('\x15echo "[$_]"\r')
		assert '[lastarg]' in session.read_until(b'[lastarg]')
	finally:
		session.close()


# commands holding !, which bash expands inside double quotes when it reads the line (history expansion):
# one recorded by mssh 6.27 and later (single quotes), one recorded by 6.26 and older (double quotes)
BANG_HISTORY = ['17900002{:02d}\t/x/multiSSH3.py\t-su -u=ops\tweb1\t\'zzcmd !important /etc/x\''.format(number) for number in range(6)]
BANG_HISTORY += ['1790000300\t/x/multiSSH3.py\t-su\tweb2\t"yyold !legacy done!"']


@pytest.fixture
def bang_home(tmp_path):
	env, home = make_home(tmp_path, BANG_HISTORY)
	build_index(env)
	return env, home


def ran(session, keys, wait=1.0):
	'''Send keys, then Enter: what the fake mssh ran, or what bash said instead.'''
	session.send(keys)
	time.sleep(wait)
	session.send('\r')
	output = plain(session.read_until(b'@@RAN') + session.read_until(b'@@READY@@', 20))
	found = re.search(r'@@RAN\[.*?\]@@|bash: .*', output)
	return found.group(0).strip() if found else output


def test_bash_never_inserts_a_bang_bash_would_expand(bang_home):
	env, home = bang_home
	session = bash_session(home, env, glue_file(home, 'bash'), extra=FAKE_MSSH)
	try:
		# TAB inside double quotes offers no command holding !, inside single quotes it does
		assert printed(session, 'mssh -u=ops web1 "zz\t', 1.0) == 'mssh -u=ops web1 "zz'
		time.sleep(0.3)
		session.send('\x15')
		assert ran(session, "mssh -u=ops web1 'zz\t") == '@@RAN[-u=ops web1 zzcmd !important /etc/x]@@'
		# the Ctrl-R history tab takes the ! of a line recorded in double quotes out of them
		session.send('mssh web2 ')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'type to filter')
		assert ran(session, '\tlegacy\r') == '@@RAN[-su web2 yyold !legacy done!]@@'
	finally:
		session.close()


def test_editor_suggests_a_command_holding_a_bang_in_single_quotes(bang_home):
	env, home = bang_home
	session = editor_session(env, home)
	try:
		session.send('mssh -u o')
		read_until_shown(session, 'zzcmd')
		assert ran(session, RIGHT, 0.5) == '@@RAN[-u ops web1 zzcmd !important /etc/x]@@'
	finally:
		session.close()


def test_bash_vi_mode_ctrl_r(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'), pre=VI_PRINT_KEY)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n'))
	finally:
		session.close()


# ---------------------------------------------------------------- plain bash: the mssh line editor

def editor_session(env, home, command=ENGINE, **kwargs):
	if bash_version(env) < 44:
		pytest.skip('the mssh line editor needs bash 4.4 or later')
	return bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1', **kwargs), glue_file(home, 'bash', command=command), extra=FAKE_MSSH)


def test_taking_the_keys_leaves_the_operators_variables_alone(home):
	# the glue takes the keys from PROMPT_COMMAND, in the operator's shell: what it uses on the way is local
	env, home = home
	if bash_version(env) < 44:
		pytest.skip('the mssh line editor needs bash 4.4 or later')
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'),
		pre='previous=MINE line=MINE keymap=MINE status=MINE')
	try:
		session.send('printf "@@%s@@\\n" "VARS:$previous,$line,$keymap,$status"\r')
		assert '@@VARS:MINE,MINE,MINE,MINE@@' in session.read_until(b'@@\r\n')
	finally:
		session.close()


def test_editor_needs_bash_4_4(home):
	env, home = home
	if bash_version(env) >= 44:
		pytest.skip('the editor runs here')
	# bash 4.2 redraws a wrapped line wrongly after every bind -x command: space stays a plain space
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'))
	try:
		session.send('bind -p | grep -F \'" ": \'\r')
		assert '" ": self-insert' in session.read_until(b'self-insert')
	finally:
		session.close()


def test_editor_keys_after_ctrl_r_go_to_the_picker_then_the_editor(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12\rXYZ')
		time.sleep(1)
		assert words(printed(session, '')) == PICKED + ['XYZ']
		assert '@@RAN' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


def test_editor_draws_in_the_locale_bash_measured_not_the_exported_one(home):
	# the editor is told the locale bash runs in: its picker (Ctrl-R) draws in ASCII where the shell runs in
	# C, whatever the exported variables say (it drew in Unicode, from them)
	env, home = home
	env = dict(env, LANG='C.UTF-8')
	if bash_locale(env) != (True, False):
		pytest.skip('no C.UTF-8 here')
	if bash_version(env) < 44:
		pytest.skip('the mssh line editor needs bash 4.4 or later')
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'), extra=FAKE_MSSH + '\n' + C_SHELL)
	try:
		session.send('mssh ')
		time.sleep(0.5)
		session.send('gpu[01-16] \x12')
		assert 'type to filter - ' in session.read_until(b'type to filter')
	finally:
		session.close()


def test_editor_keeps_passwords_out_of_the_debug_log(home):
	# make_home turns the log on for every shell test, and a failed test's report carries it
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh -p hunter2 host1 uptime\r')
		assert '@@RAN[-p hunter2 host1 uptime]@@' in session.read_until(b'@@RAN[-p hunter2 host1 uptime]@@', 60)
	finally:
		session.close()
	path = os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3', 'complete.log')
	log = open(path, encoding='utf-8').read() if os.path.exists(path) else ''
	assert 'hunter2' not in log


def test_editor_runs_pasted_lines_in_order(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh host1 uptime\rmssh host2 uptime\r')
		output = session.read_until(b'@@RAN[host2 uptime]@@', 60)
		assert '@@RAN[host1 uptime]@@' in output and '@@RAN[host2 uptime]@@' in output
		assert output.index('@@RAN[host1 uptime]@@') < output.index('@@RAN[host2 uptime]@@')
		assert 'not found' not in output
	finally:
		session.close()


def test_editor_space_keeps_the_last_argument(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('true lastarg\r')
		time.sleep(0.5)
		session.send('echo "[$_]"\r')
		assert '[lastarg]' in session.read_until(b'[lastarg]')
	finally:
		session.close()


def test_editor_space_keeps_magic_space_when_the_glue_loads_again(home):
	env, home = home
	# magic-space from the inputrc: `source ~/.bashrc` loads the glue again but does not read the inputrc again
	(home / '.inputrc').write_text('Space: magic-space\n')
	session = editor_session(env, home)
	try:
		for _ in range(2):
			session.send('. {}\r'.format(home / 'glue.bash'))
			session.read_until(b'@@READY@@')
		session.send('echo hi\r')
		session.read_until(b'@@READY@@')
		# space after !! expands it, as magic-space does
		assert printed(session, 'echo !! ') == 'echo echo hi '
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_editor_shows_and_accepts_the_suggestion(home, debug):
	env, home = home
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		assert '\x1b[38;5;244mu[01-16] "nvidia-smi"' in session.read_until(b'nvidia-smi')
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_editor_marks_an_unknown_host_and_says_why(home):
	env, home = home
	# the prober found gpu017 does not exist
	mc.write_host_states(os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3'), {'gpu017': mc.HostState('invalid', time.time())})
	session = editor_session(env, home)
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
	finally:
		session.close()


def test_editor_marks_a_remote_command_word_mssh_reads_as_its_own_option(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh node01 journalctl -u slurmd')
		reason = "⚠ -u is mssh's --username here — quote the command: 'journalctl -u slurmd'"
		assert reason in plain(session.read_until(b'slurmd\''))
		assert underlined(session, '-u')
	finally:
		session.close()


def test_editor_marks_an_mssh_option_ending_the_line_before_enter(home):
	# the remote command's option is its last word: Enter would run the line as it stands
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh node01 df -h')
		reason = "⚠ -h is mssh's --help here — quote the command: 'df -h'"
		assert reason in plain(session.read_until(b"df -h'"))
		assert underlined(session, '-h')
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_editor_enter_runs_what_was_typed(home, debug):
	env, home = home
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.send('\r')
		assert '@@RAN[gp]@@' in session.read_until(b'@@RAN[gp]@@')
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_editor_keeps_a_burst_of_type_ahead(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] "nvidia-smi"\r')
		assert '@@RAN[gpu[01-16] nvidia-smi]@@' in session.read_until(b'@@RAN') + session.read_until(b'@@READY@@')
	finally:
		session.close()


def test_editor_hands_back_a_broken_prefix(home):
	env, home = home
	session = editor_session(env, home)
	try:
		assert printed(session, 'mssh \x7f') == 'mssh'
		session.send('\x15')
		assert printed(session, 'mssh x\x7f\x7f\x7fy') == 'mssy'
	finally:
		session.close()


def test_editor_replays_keys_it_does_not_handle(home):
	env, home = home
	session = editor_session(env, home)
	try:
		# up: readline's previous-history
		assert printed(session, 'mssh x' + UP) == 'echo bb'
	finally:
		session.close()


@pytest.mark.parametrize('esc', ['\x1b', '\x1b[27u', '\x1b[27;1;27~'])
def test_editor_hands_esc_to_readline_however_the_terminal_sends_it(home, esc):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh xy')
		time.sleep(0.5)
		session.send(esc)
		time.sleep(0.3)
		# readline has the line and the Esc: B after it is readline's backward-word
		assert printed(session, 'bZ') == 'mssh Zxy'
	finally:
		session.close()


def test_editor_enter_sent_as_csi_u_runs_the_line(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.send('\x1b[13u')
		assert '@@RAN[gp]@@' in session.read_until(b'@@RAN[gp]@@')
	finally:
		session.close()


def test_editor_ctrl_c_drops_the_line(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh x')
		time.sleep(0.5)
		session.send('\x03')
		time.sleep(0.3)
		assert printed(session, '') == ''
	finally:
		session.close()


def test_editor_ctrl_c_leaves_the_line_on_screen(home):
	# as bash does: what was typed stays, ^C after it, and one fresh prompt below (no warning left over)
	env, home = home
	known(env, gpu017='invalid')
	session = editor_session(env, home)
	try:
		session.send('mssh gpu017 upt')
		session.read_until('unknown host'.encode())
		time.sleep(0.3)
		session.send('\x03')
		rows = settled(session)
		assert rows[-2:] == ['@@READY@@ mssh gpu017 upt^C', '@@READY@@'], rows
	finally:
		session.close()


def test_editor_draws_again_when_the_terminal_is_resized(home):
	# at once, wrapped at the new width; and bash knows the new width after the editor
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.resize(24, 30)
		session.read_until(b'nvidia-smi')
		grid = rendered(session)
		assert grid.lines()[:3] == ['@@READY@@ mssh gpu[01-16] "nvi', 'dia-smi"', ''] and grid.cursor == (0, 17)
		session.send('\x03')
		session.read_until(b'^C')
		session.send('echo "[$COLUMNS]"\r')
		session.read_until(b'[30]')
		rows = settled(session)
		assert rows[-4:] == ['@@READY@@ mssh gp^C', '@@READY@@ echo "[$COLUMNS]"', '[30]', '@@READY@@'], rows
	finally:
		session.close()


def test_editor_goes_on_without_an_engine_slow_to_start(home):
	# past MSSH_COMPLETE_START_TIMEOUT the space is a space and readline reads the keys typed meanwhile;
	# the editor, ready later, leaves the terminal alone
	env, home = home
	delay = 2.0
	session = editor_session(env, home, command=slow_engine(home, delay), MSSH_COMPLETE_START_TIMEOUT='0.3')
	try:
		started = time.monotonic()
		session.send('mssh host1 uptime\r')
		assert '@@RAN[host1 uptime]@@' in session.read_until(b'@@RAN[host1 uptime]@@')
		assert time.monotonic() - started < delay - 0.5
		# the editor is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		session.send('echo "[ok]"\r')
		assert '[ok]\r\n' in session.read_until(b'[ok]\r\n')
	finally:
		session.close()


def split_ready_engine(home, command):
	"""
	The engine, its "ready" for command (edit, pick) cut in two across the shell's 0.1 s waits for it, as
	when the wait ends between two of the bytes bash reads one at a time: then "mssh split-ok" as the line.
	"""
	import shlex
	path = home / 'split-engine'
	path.write_text('#!/bin/sh\nif [ "$1" = {} ]; then\n\tcat >/dev/null\n\tprintf re; sleep 0.25; printf "ady\\n"\n'
		'\tprintf "MSSHC1\\nL 13\\tmssh split-ok\\nK \\t\\nE\\n"\n\texit 0\nfi\nexec {} "$@"\n'.format(
			command, ' '.join(shlex.quote(part) for part in ENGINE)))
	path.chmod(0o755)
	return [str(path)]


def test_editor_ready_cut_by_the_wait_still_counts(home):
	# bash 4.2 to 4.4 drop what a read that timed out had read, 5.0 and later keep it but the next read wrote over it:
	# either way the answer was lost, and the line fell back to "mssh " with what was typed after it
	env, home = home
	session = editor_session(env, home, command=split_ready_engine(home, 'edit'))
	try:
		session.send('mssh ')
		time.sleep(1)
		assert printed(session, '') == 'mssh split-ok'
	finally:
		session.close()


def test_picker_ready_cut_by_the_wait_still_counts(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash', command=split_ready_engine(home, 'pick')))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		time.sleep(1)
		assert printed(session, '') == 'mssh split-ok'
	finally:
		session.close()


READY_SWEEP = r'''
. "$1" 2>/dev/null
engine() { sleep "$delay"; printf 'ready\n'; printf 'MSSHC1\nL 4\tmssh\nE\n'; }
lost=0
for ((step = 0; step < 250; step++)); do
	delay=$(printf '0.%06d' $((99000 + step * 4)))
	_mssh_complete_start engine
	[[ $_mssh_complete_status == 0 && $_mssh_complete_resp == $'MSSHC1\nL 4\tmssh\nE' ]] || lost=$((lost + 1))
done
echo "lost=$lost"
'''

def run_glue_script(home, script):
	'''Run script in a bash that has the glue (its path is $1), as (exit status, stdout, stderr).'''
	env, home = home
	glue = glue_file(home, 'bash')
	result = subprocess.run([require_shell('bash'), '-c', script, 'bash', str(glue)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
	return result.returncode, result.stdout.decode().strip(), result.stderr.decode()


def test_ready_arriving_as_the_wait_ends_still_counts(home):
	# the shell waits for "ready" in reads of 0.1 s; a byte that comes as one ends is read all the same (bash 5
	# says the read timed out, and the next read wrote over the byte: the line was "eady", the answer dropped;
	# bash 4.2 to 4.4 dropped the byte, and 4.2 and 4.3 could be killed by the timer's SIGALRM, rc 142).
	# The engine says ready at delays around the read time, 4 microseconds apart: some meet the end of a wait
	assert run_glue_script(home, READY_SWEEP) == (0, 'lost=0', '')


def test_ready_missing_its_first_byte_still_counts(home):
	# what bash 4.2 to 4.4 leave when a read times out as the byte comes: the loop read the second byte
	script = r'''
engine() { printf 'eady\nMSSHC1\nL 4\tmssh\nE\n'; }
. "$1" 2>/dev/null
_mssh_complete_start engine
printf '%s|%s' "$_mssh_complete_status" "$_mssh_complete_resp"
'''
	assert run_glue_script(home, script) == (0, '0|MSSHC1\nL 4\tmssh\nE', '')


def test_ready_written_as_the_whole_wait_ends_is_taken(home):
	# every read of the wait times out (the stub: as when the engine's byte meets the end of each) but the engine has
	# written: the shell looks once more before it goes on without it, as the engine would otherwise take the terminal
	# with nobody reading
	script = r'''
read() { if [[ $1 == -r && $2 == -t && $3 == 0.1 ]]; then sleep 0.1; return 142; fi; builtin read "$@"; }
engine() { printf 'ready\nMSSHC1\nL 4\tmssh\nE\n'; }
. "$1" 2>/dev/null
MSSH_COMPLETE_START_TIMEOUT=0.3
_mssh_complete_start engine
printf '%s|%s' "$_mssh_complete_status" "$_mssh_complete_resp"
'''
	assert run_glue_script(home, script) == (0, '0|MSSHC1\nL 4\tmssh\nE', '')


def test_a_stray_alarm_while_the_glue_waits_ends_nothing(home):
	# bash 4.2 and 4.3 ended the shell when a read's timer went off as the read ended ("Alarm clock"): SIGALRM is ignored
	# during the wait (here sent while it waits without a timer: the shell used to be gone). Not in 4.4 and later, which
	# leave it to readline and bash (TMOUT)
	if bash_version(home[0]) >= 44:
		pytest.skip('bash 4.4 and later do not end the shell, and the glue leaves SIGALRM to them')
	script = r'''
engine() { printf 'ready\n'; sleep 0.2; kill -ALRM $$; sleep 0.1; printf 'MSSHC1\nL 4\tmssh\nE\n'; }
. "$1" 2>/dev/null
_mssh_complete_start engine
printf '%s|%s' "$_mssh_complete_status" "$_mssh_complete_resp"
'''
	assert run_glue_script(home, script) == (0, '0|MSSHC1\nL 4\tmssh\nE', '')


def test_the_operators_alarm_trap_is_back_after_the_wait(home):
	script = r'''
engine() { printf 'ready\nMSSHC1\nL 4\tmssh\nE\n'; }
. "$1" 2>/dev/null
trap 'echo mine' ALRM
_mssh_complete_start engine
trap -p ALRM
trap - ALRM
_mssh_complete_start engine
echo "[$(trap -p ALRM)]"
TMOUT=5
_mssh_complete_start engine
echo "[$(trap -p ALRM)]"
'''
	assert run_glue_script(home, script) == (0, "trap -- 'echo mine' SIGALRM\n[]\n[]", '')


def test_the_engine_does_not_inherit_an_ignored_alarm(home):
	# bash 4.2 and 4.3 ignore SIGALRM during the wait: the engine, and what it starts, must not (a child keeps what its
	# parent ignores). awk is the engine's child here: its SigIgn mask shows what it got
	script = r'''
engine() { printf 'ready\nMSSHC1\nL 4\tign=%s\nE\n' "$(( (16#$(awk '/^SigIgn/{print $2}' /proc/self/status) >> 13) & 1 ))"; }
. "$1" 2>/dev/null
_mssh_complete_start engine
printf '%s' "$_mssh_complete_resp"
'''
	assert run_glue_script(home, script) == (0, 'MSSHC1\nL 4\tign=0\nE', '')


def shell_ignores_alarm(session):
	'''Whether the shell on session ignores SIGALRM, and its trap for it: ("0", "") when it does neither.'''
	session.send('\x15')
	time.sleep(0.3)
	session.send('echo "@@D[$(( (16#$(awk \'/^SigIgn/{print $2}\' /proc/$$/status) >> 13) & 1 ))|$(trap -p ALRM)]@""@"\r')
	found = re.findall(r'@@D\[(\d)\|(.*?)\]@@', session.read_until(b']@@'))
	return found[-1] if found else None


def test_tab_then_ctrl_c_while_the_engine_answers_leaves_sigalrm_alone(home):
	# the TAB query ends at the end of its input: nothing in it ignores SIGALRM, which a Ctrl-C there would leave ignored
	env, home = home
	session = bash_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='5'), glue_file(home, 'bash', command=slow_engine(home, 3, only='query')))
	try:
		before = shell_ignores_alarm(session)
		assert before == ('0', '')
		session.send('mssh gp\t')
		time.sleep(0.8)
		session.send('\x03')
		time.sleep(3.5)
		# the prompt after the engine is done (what was typed meanwhile is the shell's, not ours to look at)
		session.send('\r')
		time.sleep(0.5)
		assert shell_ignores_alarm(session) == before
	finally:
		session.close()


def test_editor_ctrl_c_while_it_starts_drops_the_line_as_bash_does(home):
	# as Ctrl-C in the editor: the line and ^C stay on screen, a fresh prompt below
	env, home = home
	delay = 1.5
	session = editor_session(env, home, command=slow_engine(home, delay, deaf=True))
	try:
		started = time.monotonic()
		session.send('mssh ')
		time.sleep(0.3)
		session.send('\x03')
		session.read_until(b'^C', 20)
		session.read_until(b'@@READY@@', 20)
		rows = [row for row in screen(session) if row]
		assert rows == ['@@READY@@ mssh ^C', '@@READY@@'], rows
		# the editor is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		assert printed(session, 'echo x') == 'echo x'
	finally:
		session.close()


def test_editor_ctrl_r_opens_the_picker(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		session.send('\r')
		time.sleep(0.3)
		assert words(printed(session, '')) == PICKED
	finally:
		session.close()


def test_editor_without_colours_still_edits(home):
	env, home = home
	session = editor_session(env, home, TERM='dumb')
	try:
		session.send('mssh gp')
		time.sleep(0.5)
		session.send('u\r')
		output = session.read_until(b'@@RAN[gpu]@@')
		assert '@@RAN[gpu]@@' in output
		assert '\x1b[38;5;244m' not in output and '\x1b[2m' not in output
	finally:
		session.close()


def test_space_elsewhere_is_a_space(home):
	env, home = home
	session = editor_session(env, home)
	try:
		assert printed(session, 'echo a b\x02\x02 ') == 'echo a  b'
		session.send('\x05\x15')
		assert printed(session, 'é è\x02 ') == 'é  è'
	finally:
		session.close()


# ---------------------------------------------------------------- ble.sh

def test_blesh_suggests_from_the_engine(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		# only the engine knows the command: the shell history is about echo
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_blesh_grey_text_keeps_its_limit_when_ble_sh_measured_a_busy_machine(home):
	# conditional-sync's timeout= counts its sleeps, and ble.sh shortens each by a delay it measures as the shell starts: a shell
	# started on a busy machine (here: 25 ms) gave the engine a fraction of the limit for as long as it lived (3 s lasted 25 ms,
	# the grey text and the warnings never came). The glue reads the limit off the clock. (On bash 4.2 this proves nothing: the
	# glue reading the limit the old way, as conditional-sync's timeout=, passes it on the CentOS 7 image)
	env, home = home
	busy = 'function ble/util/msleep/.calibrate-loop { _ble_util_msleep_delay=25000; }'
	session = blesh_session(home, dict(env, MSSH_COMPLETE_GHOST_TIMEOUT='3000'), glue_file(home, 'bash'), extra=busy)
	try:
		session.send('mssh gp')
		assert 'nvidia-smi' in session.read_until(b'nvidia-smi', 80)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


@pytest.mark.parametrize('limit, grey', [('0.5', False), ('1e3', False), ('2s', False), ('', False), ('03000', True), ('08', False)])
def test_blesh_grey_text_goes_on_with_a_limit_that_is_no_number_of_milliseconds(home, limit, grey):
	# 0.5, 1e3 and 2s are syntax errors in $((ret + limit)), and 08 an arithmetic one (octal): each printed one at every key and
	# lost the grey text. Here: no such error is printed, and with a long limit (03000: 3 s) the grey text shows. The limits the
	# others get (300 ms; 08 is 8 ms) are checked by the test below; their grey text is not asked for, as a loaded machine misses
	# a limit that short
	env, home = home
	session = blesh_session(home, dict(env, MSSH_COMPLETE_GHOST_TIMEOUT=limit), glue_file(home, 'bash'))
	try:
		session.send('mssh gp')
		if grey:
			shown = session.read_until(b'nvidia-smi', 80)
			assert 'nvidia-smi' in shown, shown
			assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
		else:
			session.wait_idle()
			session.send('u')
			session.wait_idle()
		output = session.output.decode('utf-8', 'replace')
		assert 'syntax error' not in output and 'value too great' not in output and 'error token' not in output, output
	finally:
		session.close()


@pytest.mark.parametrize('limit, milliseconds', [
	('0.5', 300), ('1e3', 300), ('2s', 300), ('', 300), (None, 300), ('300', 300), ('03000', 3000), ('08', 8), ('00', 0),
], ids=['0.5', '1e3', '2s', 'empty', 'unset', '300', '03000', '08', '00'])
def test_blesh_grey_text_limit_is_the_clock_plus_the_milliseconds_given_or_300(limit, milliseconds):
	# no ble.sh and no load: _mssh_complete_ble_query, cut out of the glue, with the clock and conditional-sync stubbed. The clock stands
	# at 1000 until conditional-sync, which prints the time it was given, runs the condition the query gave it as ble.sh would at each
	# wake: one millisecond before the limit (it goes on), at the limit (it stops), and with a key waiting (it stops); and the query's
	# status then says past the limit, or with a key waiting that typing cut it short
	glue = mc.render_glue('bash', ENGINE).split('\n')
	start = glue.index('\t_mssh_complete_ble_query() {')
	function = '\n'.join(glue[start:glue.index('\t}', start) + 1])
	script = function + """
clock=1000 waiting=1
ble/util/clock() { ret=$clock; }
ble/decode/has-input() { return $waiting; }
ble/util/conditional-sync() {
	echo "until=$_mssh_complete_until"
	clock=$((_mssh_complete_until - 1))
	eval "$2" && echo before=goes-on || echo before=stops
	clock=$_mssh_complete_until
	eval "$2" && echo at=goes-on || echo at=stops
	clock=$((_mssh_complete_until - 1)) waiting=0
	eval "$2" && echo key=goes-on || echo key=stops
	waiting=$final
	return 148
}
final=1
_mssh_complete_ble_query
echo "status=$?"
final=0 clock=1000 waiting=1
_mssh_complete_ble_query >/dev/null
echo "typing=$?"
"""
	env = {key: value for key, value in os.environ.items() if key != 'MSSH_COMPLETE_GHOST_TIMEOUT'}
	if limit is not None:
		env['MSSH_COMPLETE_GHOST_TIMEOUT'] = limit
	done = subprocess.run([require_shell('bash'), '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
	assert done.stdout.decode().split() == ['until={}'.format(1000 + milliseconds), 'before=goes-on', 'at=stops', 'key=stops', 'status=142', 'typing=148'] and done.stderr == b'', (done.stdout, done.stderr)


STALE_ENGINE = '''#!{python}
import os, re, subprocess, sys, time
engine = {engine!r}
folder = {folder!r}
data = sys.stdin.buffer.read()
real = subprocess.run(engine + sys.argv[1:], input=data, stdout=subprocess.PIPE).stdout
ghost = b'ghost=1' in data
older = ghost and re.search(rb'mssh gp(?!u)', data)
newer = ghost and re.search(rb'mssh gpu', data)
if older:
	# the query for the line as it was before the last key: it waits for the newer one to finish, then writes
	open(folder + '/older-running', 'w').close()
	end = time.time() + 30
	while not os.path.exists(folder + '/newer-written') and time.time() < end:
		time.sleep(0.001)
os.write(1, real)
if newer:
	open(folder + '/newer-written', 'w').close()
'''


def test_blesh_a_cancelled_query_does_not_write_into_the_next_answer(home):
	# conditional-sync signals its background shell alone: the engine it started went on and wrote its answer for the old line
	# into the file the newer query's answer is read from (mssh gpuu[01-16] "nvidia-smi" for mssh gpu). The engine is that shell
	import sys
	env, home = home
	folder = home / 'stale'
	folder.mkdir()
	wrapper = home / 'stale-engine'
	wrapper.write_text(STALE_ENGINE.format(python=sys.executable, engine=list(ENGINE), folder=str(folder)))
	wrapper.chmod(0o755)
	session = blesh_session(home, dict(env, MSSH_COMPLETE_GHOST_TIMEOUT='10000'), glue_file(home, 'bash', command=[str(wrapper)]))
	try:
		session.send('mssh gp')
		end = time.monotonic() + 20
		while not (folder / 'older-running').exists() and time.monotonic() < end:
			session.read_for(0.05)
		assert (folder / 'older-running').exists()
		session.send('u')
		assert 'nvidia-smi' in session.read_until(b'nvidia-smi', 80)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_blesh_marks_an_unknown_host_and_says_why(home):
	env, home = home
	known(env, gpu017='invalid')
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 60))
		# the reason line is drawn at once, the underline when ble.sh ends its idle pass, after the grey text's queries
		end = time.monotonic() + 20
		while not underlined(session, 'gpu017') and time.monotonic() < end:
			session.read_for(0.2)
		assert underlined(session, 'gpu017')
	finally:
		session.close()


def test_blesh_asks_for_the_warnings_again_when_the_first_query_misses_its_limit(home):
	# a busy machine: the first warnings query takes four seconds, the limit is two; the glue asks again and the next answers at
	# once. (A 0.3 s limit, the default, was too short for the answering query itself on a loaded machine: no warning in 15 s)
	env, home = home
	known(env, gpu017='invalid')
	engine = home / 'once-slow-engine'
	engine.write_text('#!/bin/sh\ncat > "$0.request"\nif [ "$1" = query ] && grep -aq diag=1 "$0.request" && [ ! -e "$0.once" ]; then\n'
		': > "$0.once"; sleep 4\nfi\nexec {} "$@" < "$0.request"\n'.format(' '.join(shlex.quote(part) for part in ENGINE)))
	engine.chmod(0o755)
	session = blesh_session(home, dict(env, MSSH_COMPLETE_GHOST_TIMEOUT='2000'), glue_file(home, 'bash', command=[str(engine)]))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 60))
		# it did run into the limit first
		assert (home / 'once-slow-engine.once').exists()
	finally:
		session.close()


def test_blesh_warning_appears_when_the_prober_answers(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu099 ')
		time.sleep(0.2)
		known(env, gpu099='invalid')
		# no key pressed: the glue asks again while the prober works
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode(), 60)
	finally:
		session.close()


def test_blesh_keeps_suggesting_and_warning_with_noclobber(home):
	# the glue's request and answer files are kept per shell: with noclobber, writing them with > failed
	# from the second time on, which took the grey text and the warnings away
	env, home = home
	known(env, gpu017='invalid', gpu018='invalid')
	session = blesh_session(home, env, glue_file(home, 'bash'), extra='set -o noclobber')
	try:
		for host in ('gpu017', 'gpu018'):
			session.send('mssh gp')
			assert 'nvidia-smi' in session.read_until(b'nvidia-smi')
			session.send('\x03')
			session.read_until(b'@@READY@@')
			session.send('mssh %s ' % host)
			assert host + ': unknown host' in plain(session.read_until(b'unknown host', 60))
			session.send('\x03')
			session.read_until(b'@@READY@@')
		assert b'cannot overwrite' not in session.output
	finally:
		session.close()


@pytest.mark.parametrize('pre', ['', "ble-bind -m emacs -x C-a 'echo -f C-r zz'"])
def test_blesh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home, pre):
	# ble-bind -P quotes a command bound with -x: a " -f C-r " inside one (here of C-a, listed first) is
	# not Ctrl-R's binding
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'), pre=pre)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		# the second Ctrl-R of ble.sh's own search finds the older match
		session.send('\x15\x12aa')
		time.sleep(0.5)
		session.send('\x12')
		assert 'echo aa1' in read_until_shown(session, 'echo aa1')
		session.send('\x07')
	finally:
		session.close()


def test_blesh_ctrl_r_goes_on_without_an_engine_slow_to_start(home):
	# ble.sh reads Ctrl-C as a key: without the deadline nothing ended the wait
	env, home = home
	delay = 8.0
	session = blesh_session(home, dict(env, MSSH_COMPLETE_START_TIMEOUT='0.3'), glue_file(home, 'bash', command=slow_engine(home, delay)))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		started = time.monotonic()
		session.send('\x12aa')
		assert 'echo aa2' in read_until_shown(session, 'echo aa2', 10)
		assert time.monotonic() - started < delay - 0.5
		# the engine is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		session.send('\x07\x15')
		assert printed(session, 'echo x') == 'echo x'
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


# ---------------------------------------------------------------- zsh

ZAS = '/opt/zsh-autosuggestions/zsh-autosuggestions.zsh'
ZSH_SH = '/opt/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh'


def zsh_with(env, home, zas=False, after=False, late=False, shell_history=SHELL_HISTORY, extra='', rc_before='', rc_after='', command=ENGINE, **options):
	'''
	zsh with the glue; zsh-autosuggestions loaded before it, after it (after), or at the first prompt (late);
	rc_before and rc_after: the operator's own rc lines before and after the glue; extra runs last;
	command: the engine the glue runs.
	'''
	pre = ''
	if zas:
		import os
		if not os.path.isfile(ZAS):
			if 'zas' in env.get('MSSH_REQUIRE_SHELLS', '') or 'zas' in os.environ.get('MSSH_REQUIRE_SHELLS', ''):
				pytest.fail('zsh-autosuggestions is required here but not at ' + ZAS)
			pytest.skip('zsh-autosuggestions is not installed at ' + ZAS)
		pre = 'source ' + ZAS
		if late:
			# as plugin managers do (zinit turbo, zsh-defer): after mssh set up its own widgets
			pre, after = '_mssh_test_late() {{ add-zsh-hook -d precmd _mssh_test_late; {} }}\nadd-zsh-hook precmd _mssh_test_late'.format(pre), True
	(home / '.zsh_history').write_text(shell_history)
	history = 'HISTFILE=~/.zsh_history; SAVEHIST=100; HISTSIZE=100; fc -R'
	return zsh_session(home, dict(env, HISTFILE=str(home / '.zsh_history')), glue_file(home, 'zsh', command=command),
		pre=(history if after else pre + '\n' + history) + '\n' + rc_before,
		extra=(pre if after else '') + '\n' + rc_after + '\n' + extra, **options)


@pytest.mark.parametrize('zas, after', [(False, False), (True, False), (True, True)], ids=['own', 'zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
def test_zsh_suggests_and_right_arrow_accepts(home, zas, after):
	if not zas:
		require_zsh_5_3()
	env, home = home
	session = zsh_with(env, home, zas, after)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		# zsh escapes the glob characters
		assert words(printed(session, RIGHT)) == ['mssh', 'gpu[01-16]', 'nvidia-smi']
	finally:
		session.close()


def test_zsh_hands_grey_text_to_zsh_autosuggestions_loaded_later(home):
	# its own history suggestion (date) and mssh's grey text (nvidia-smi) must not both be drawn
	env, home = home
	session = zsh_with(env, home, zas=True, late=True, shell_history=SHELL_HISTORY + 'mssh gpu[01-16] date\n')
	try:
		# a second prompt: zsh-autosuggestions has started
		session.send('true\r')
		session.read_until(b'@@READY@@')
		session.send('mssh gp')
		drawn = session.read_until(b'nvidia-smi')
		assert 'nvidia-smi' in drawn and 'date' not in drawn
		assert words(printed(session, RIGHT)) == ['mssh', 'gpu[01-16]', 'nvidia-smi']
	finally:
		session.close()


def runtime(env):
	return os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3')


def known(env, **validities):
	"""Host states as the prober would write them (no prober runs in these tests: make_home)."""
	mc.write_host_states(runtime(env), {host: mc.HostState(validity, time.time()) for host, validity in validities.items()})


def rendered(session):
	"""The terminal after everything the session printed, resized where the test resized it."""
	from vt_grid import Grid
	grid = Grid(24, 80)
	start = 0
	for end, rows, columns in session.resizes:
		grid.feed(session.output[start:end].decode('utf-8', 'replace'))
		grid.resize(rows, columns)
		start = end
	grid.feed(session.output[start:].decode('utf-8', 'replace'))
	return grid


def screen(session):
	return rendered(session).lines()


def underlined(session, text):
	"""Whether text is on screen with every character underlined."""
	grid = rendered(session)
	for row, line in enumerate(grid.lines()):
		column = line.find(text)
		if column >= 0:
			styles = grid.styles(row)[column:column + len(text)]
			return all('4' in style.split(';') for style in styles)
	return False


@pytest.mark.parametrize('zas', [False, True], ids=['own', 'zsh-autosuggestions'])
def test_zsh_marks_an_unknown_host_and_says_why(home, zas):
	require_zsh_5_3()
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, zas)
	try:
		session.send('mssh gpu017 ')
		output = session.read_until('unknown host'.encode())
		assert '⚠ gpu017: unknown host' in plain(output)
		# the host is underlined
		assert underlined(session, 'gpu017')
	finally:
		session.close()


def test_zsh_suggests_warns_and_picks_without_compinit(home):
	require_zsh_5_3()
	# only TAB needs zsh's completion system
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, compinit='')
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		assert words(printed(session, RIGHT)) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
	finally:
		session.close()


def test_zsh_marks_a_remote_command_word_mssh_reads_as_its_own_option(home):
	require_zsh_5_3()
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh node01 df -h ')
		output = session.read_until(b'df -h\'')
		assert "⚠ -h is mssh's --help here — quote the command: 'df -h'" in plain(output)
		assert underlined(session, '-h')
	finally:
		session.close()


def test_zsh_warning_appears_when_the_prober_answers(home):
	require_zsh_5_3()
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu099 ')
		time.sleep(0.2)
		known(env, gpu099='invalid')
		# no key pressed: the glue asks again while the prober works
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode())
	finally:
		session.close()


def test_zsh_warning_goes_away_when_the_host_is_fixed(home):
	require_zsh_5_3()
	env, home = home
	known(env, gpu017='invalid', gpu17='valid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu017 ')
		assert 'unknown host' in session.read_until('unknown host'.encode())
		session.send('\x7f' * 7 + 'gpu17 ')
		session.read_until(b'gpu17 ')
		# until the shell is done: the marks and the reason stay until the answer for the line as it is now
		session.wait_idle(20, window=0.5)
		session.read_for(0.2)
		assert not [row for row in screen(session) if 'unknown host' in row]
	finally:
		session.close()


def reverse_search_found(session, line):
	'''Whether readline's reverse search shows line (readlines before 8 redraw its prompt in ways the grid does not follow).'''
	return any(row.startswith('(reverse-i-search)`') and row.endswith(': ' + line) for row in screen(session))


def line_styles(session, text):
	"""The SGR parameters of each character on the screen row holding text."""
	grid = rendered(session)
	row = next(row for row, line in enumerate(grid.lines()) if text in line)
	return grid.styles(row)


@pytest.mark.parametrize('typed, fixes, line', [
	# a typo fixed: backspace over "17 ", then "1 " (gpu01 is fine)
	('mssh gpu017 ', ['\x7f\x7f\x7f', '1 uptime'], 'mssh gpu01 uptime'),
	# fixed inside the word (delete its 0), then the word left
	('mssh gpu017 uptime', [LEFT * 9 + '\x7f', '\x05'], 'mssh gpu17 uptime'),
], ids=['typo-retyped', 'fixed-in-place'])
def test_zsh_underline_goes_away_when_the_host_is_fixed(home, typed, fixes, line):
	# zsh rewrites the style of a mark (fg=red,underline) and moves the mark along with the text the
	# operator edits: the glue still finds its marks
	env, home = home
	known(env, gpu017='invalid', gpu01='valid', gpu17='valid')
	session = zsh_with(env, home)
	try:
		session.send(typed)
		session.read_until('unknown host'.encode())
		time.sleep(0.5)
		for keys in fixes:
			session.send(keys)
			time.sleep(0.3)
		# until the shell is done: the marks stay until the answer for the line as it is now
		session.wait_idle(20, window=0.5)
		session.read_for(0.2)
		assert not [style for style in line_styles(session, line) if '4' in style.split(';')], screen(session)[:2]
	finally:
		session.close()


def test_zsh_accepted_grey_text_is_not_grey(home):
	require_zsh_5_3()
	# a character of the grey text typed first: zsh moved the grey highlight along with it
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.send('u')
		time.sleep(0.5)
		session.send(RIGHT)
		time.sleep(0.5)
		session.read_for(0.2)
		assert not [style for style in line_styles(session, 'nvidia-smi') if '244' in style.split(';')]
	finally:
		session.close()


ARRIVING_TOGETHER = [
	# the grey text shown is the answer for "mssh gp": keys arriving in one read must not take it for a line that moved on
	(RIGHT + RIGHT, 'a Right key twice'),
	('x' + RIGHT, 'a letter then Right'),
	('u' + RIGHT, 'the next letter of the grey text then Right'),
	('\x05\x05', 'Ctrl-E twice'),
	('\x7f' + RIGHT, 'Backspace then Right'),
	('\x1bf\x1bf', 'Alt-f twice'),
]


@pytest.mark.parametrize('zas, after', [(False, False), (True, False), (True, True)], ids=['own', 'zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
@pytest.mark.parametrize('keys', [keys for keys, _ in ARRIVING_TOGETHER], ids=[name for _, name in ARRIVING_TOGETHER])
def test_zsh_keys_arriving_together_do_not_take_grey_text_from_an_older_line(home, keys, zas, after):
	if zas and keys == '\x1bf\x1bf':
		pytest.skip("zsh-autosuggestions' own word accept stops inside gpu\\[01-16\\], one key at a time too, and Enter then continues the line")
	require_zsh_5_3()
	# zsh redraws once for keys read together (PENDING): the grey text then shown was asked for a shorter or other line,
	# and an accept key took it all the same (`gpu[01-16] nvidia-smiu[01-16] nvidia-smi` ran, or `gpxu[01-16] nvidia-smi`)
	env, home = home
	session = zsh_with(env, home, zas, after, extra=FAKE_MSSH)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send(keys + '\r')
		ran = re.findall(r'@@RAN\[(.*?)\]@@', plain(session.read_until(b'@@RAN[') + session.read_until(b']@@')))
		assert len(ran) == 1, ran
		line = ran[0].replace('\\', '')
		# what was typed with the text of one answer at most, never a second one on top
		assert line.count('nvidia-smi') <= 1 and line.count('gpu[01-16]') <= 1, ran
		assert line in {'gp', 'gpu[01-16] nvidia-smi', 'gpu[01-16]', 'gpx', 'gpu', 'g'}, ran
	finally:
		session.close()


@pytest.mark.parametrize('after', [False, True], ids=['zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
@pytest.mark.parametrize('line, extra', [
	('sudo mssh gp', 'sudo() { "$@"; }'), ('FOO=1 mssh gp', ''), ('m gp', 'alias m=mssh'), ('m gp', "alias m='noglob mssh'"),
	('time mssh gp', ''), ('true && mssh gp', ''),
])
def test_zsh_keys_arriving_together_do_not_take_grey_text_from_an_older_line_of_any_mssh_command(home, line, extra, after):
	require_zsh_5_3()
	# the hook asked whether the line is an mssh line by its first word: at `sudo mssh gp`, an alias of mssh or after FOO=1, the grey
	# text of the line before stayed for a Right among the keys, and gpxu[01-16] nvidia-smi ran
	env, home = home
	# (the same line in the shell's history: the plugin's own strategy has the grey text for a line that is no mssh line to the engine)
	session = zsh_with(env, home, True, after, shell_history=line + 'u[01-16] nvidia-smi\n', extra=FAKE_MSSH + '\n' + extra)
	try:
		session.send(line)
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send('x' + RIGHT + '\r')
		ran = re.findall(r'@@RAN\[(.*?)\]@@', plain(session.read_until(b'@@RAN[') + session.read_until(b']@@')))
		assert len(ran) == 1 and ran[0].replace('\\', '') == 'gpx', ran
	finally:
		session.close()


@pytest.mark.parametrize('after', [False, True], ids=['zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
def test_zsh_keys_arriving_together_leave_the_grey_text_of_other_commands_to_zsh_autosuggestions(home, after):
	require_zsh_5_3()
	# off an mssh line the plugin behaves as it does alone: the grey text of `ranme he` is still there for the Right that takes it
	env, home = home
	session = zsh_with(env, home, True, after, shell_history='ranme hello world\n', extra='ranme() { printf "@@RAN[%s]@@\\n" "$*"; }')
	try:
		session.send('ranme he')
		session.read_until(b'llo world')
		session.wait_idle(10)
		# (Left, then Right back to the end while more keys wait, then Right takes the grey text)
		session.send(LEFT + RIGHT + RIGHT + '\r')
		ran = re.findall(r'@@RAN\[(.*?)\]@@', plain(session.read_until(b'@@RAN[') + session.read_until(b']@@')))
		assert ran == ['hello world'], ran
	finally:
		session.close()


def test_zsh_own_grey_text_stays_when_keys_that_change_nothing_arrive_together(home):
	require_zsh_5_3()
	# the hook that drops zsh-autosuggestions' stale grey text is for that plugin's: our own text is kept in step by our own hook, which
	# draws nothing again for keys that leave the line as it is (Ctrl-E twice), so one dropped here stays dropped
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send('\x05\x05')
		session.wait_idle(10)
		assert words(printed(session, RIGHT)) == ['mssh', 'gpu[01-16]', 'nvidia-smi']
	finally:
		session.close()


def test_zsh_keys_arriving_together_ask_for_the_grey_text_once(home):
	require_zsh_5_3()
	# a paste or typing ahead: one engine for the last key, not one per key (13 runs for a 12 key burst without PENDING)
	env, home = home
	command, requests = recording_engine(home)
	session = zsh_with(env, home, command=command)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		before = len(recorded_flags(requests).get('ghost', []))
		session.send('\x15mssh gpu[01-16] ')
		session.wait_idle(10, window=1.0)
		asked = len(recorded_flags(requests).get('ghost', [])) - before
		assert asked <= 2, asked
	finally:
		session.close()


@pytest.mark.parametrize('keys', [RIGHT, '\x05', '\x06', '\x1bf'], ids=['Right', 'Ctrl-E', 'Ctrl-F', 'Alt-f'])
def test_zsh_an_accept_key_after_ctrl_c_takes_nothing(home, keys):
	require_zsh_5_3()
	# Ctrl-C empties POSTDISPLAY and leaves what mssh remembers as shown: the first accept key on the new line took the text of the
	# line that was dropped, and Enter ran nvidia-smi
	env, home = home
	ran = home / 'ran'
	session = zsh_with(env, home, extra='nvidia-smi() {{ : > {}; }}'.format(shlex.quote(str(ran))))
	try:
		session.send('mssh gpu[01-16] ')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send('\x03')
		session.wait_idle(10)
		session.send(keys + '\r')
		session.wait_idle(10)
		assert not ran.exists()
		assert printed(session, '') == ''
	finally:
		session.close()


@pytest.mark.parametrize('widget', ['zle forward-char; zle forward-char', 'zle end-of-line; zle forward-word', 'zle forward-word; zle forward-word'],
	ids=['forward-char-twice', 'end-of-line-forward-word', 'forward-word-twice'])
def test_zsh_a_widget_taking_the_grey_text_twice_takes_it_once(home, widget):
	require_zsh_5_3()
	# no redraw between the calls of one widget: the second took the text again (`gpu[01-16] nvidia-smiu[01-16] nvidia-smi`)
	env, home = home
	session = zsh_with(env, home, extra="_twice() {{ {}; }}\nzle -N _twice\nbindkey '^X^T' _twice".format(widget))
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send('\x18\x14')
		session.wait_idle(10)
		line = words(printed(session, ''))
		assert line in (['mssh', 'gpu[01-16]', 'nvidia-smi'], ['mssh', 'gpu[01-16]']), line
	finally:
		session.close()


@pytest.mark.parametrize('keys', ['x\x7f', '\x15mssh gp'], ids=['x-then-backspace', 'ctrl-u-and-retype'])
def test_zsh_grey_text_comes_back_when_keys_read_together_end_on_the_line_it_was_for(home, keys):
	require_zsh_5_3()
	# the redraw that waits for the last key drops the grey text and forgets the line it was for: the line the keys end on is that
	# same line, and was found "already asked", so the grey text never returned
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		session.wait_idle(10)
		session.send(keys)
		session.read_until(b'nvidia-smi')
		assert words(printed(session, RIGHT)) == ['mssh', 'gpu[01-16]', 'nvidia-smi']
	finally:
		session.close()


def settled(session, quiet=1.0):
	"""The non-empty rows of the screen once the session printed nothing more for a while."""
	time.sleep(quiet)
	session.read_for(0.5)
	return [row.rstrip() for row in screen(session) if row.strip()]


@pytest.mark.parametrize('keys, below', [
	# the next word finished, typed or completed: the line keeps its row, the reason stays under it
	('uptime ', '⚠ gpu017: unknown host'),
	('upt\t', '⚠ gpu017: unknown host'),
	# TAB lists as on any line
	('--ipmi_\t', '--ipmi_method'),
], ids=['next-word', 'tab-completes', 'tab-lists'])
def test_zsh_keys_on_a_warned_line(home, keys, below):
	if below.startswith('⚠'):
		require_zsh_5_3()
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu017 ')
		session.read_until('unknown host'.encode())
		time.sleep(0.5)
		session.send(keys)
		rows = settled(session)
		assert rows[0].startswith('@@READY@@ mssh gpu017 ') and any(below in row for row in rows[1:]), rows[:4]
	finally:
		session.close()


@pytest.mark.parametrize('known_before, delay', [(False, 0.2), (True, 0.0), (True, 0.12)], ids=['answered-while-typing', 'known-typed-at-once', 'known-typed-quickly'])
def test_zsh_warning_appears_while_the_command_is_typed(home, known_before, delay):
	require_zsh_5_3()
	# the answer comes back after the next key, which only changed the word being typed: zsh asks again
	env, home = home
	if known_before:
		known(env, gpu099='invalid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu099 ')
		if not known_before:
			time.sleep(0.2)
			known(env, gpu099='invalid')
		for char in 'uptime':
			session.send(char)
			time.sleep(delay)
		rows = screen_when(session, lambda rows: any('gpu099: unknown host' in row for row in rows[1:]))
		assert rows[0] == '@@READY@@ mssh gpu099 uptime' and any('gpu099: unknown host' in row for row in rows[1:]), rows[:4]
	finally:
		session.close()


def slow_engine_glue(seconds=1):
	"""Glue lines making every engine query take a while, so a test can look at the shell while one is asked."""
	return '_mssh_complete_engine() {{ sleep {}; {} "$@" }}'.format(seconds, ' '.join(shlex.quote(part) for part in ENGINE))


# zsh-autosuggestions fetching in the widgets (synchronous), with a strategy of the operator's after mssh's
ZAS_SYNC = """unset ZSH_AUTOSUGGEST_USE_ASYNC
ZSH_AUTOSUGGEST_STRATEGY=(slow)
_zsh_autosuggest_strategy_slow() { zmodload zsh/zselect; zselect -t 100 }"""


def times_away(session, seconds):
	'''
	How often, sampled as fast as Python can for seconds, the terminal's foreground process group was not the
	shell; what the shell draws meanwhile is read.
	'''
	away = 0
	end = time.monotonic() + seconds
	while time.monotonic() < end:
		if os.tcgetpgrp(session.fd) != session.pid:
			away += 1
		ready, _, _ = select.select([session.fd], [], [], 0)
		if ready:
			session.output += os.read(session.fd, 65536)
	return away


@pytest.mark.parametrize('zas, extra, keys', [
	(False, '', 'mssh gp'),
	(False, '', 'mssh --ipmi_\t'),
	# a host word: the warnings' query, asked again from its answer's handler
	(False, '', 'mssh gpu017 '),
	# not zsh-autosuggestions' default (async): its own process substitution takes the terminal before zsh 5.8
	(True, ZAS_SYNC, 'mssh gp'),
], ids=['grey-text', 'tab', 'warnings', 'zsh-autosuggestions-sync'])
def test_zsh_keeps_the_terminal_while_mssh_asks(home, zas, extra, keys):
	# before zsh 5.8 (zsh change 44214) the process of an `exec {fd}< <(...)` made itself the terminal's foreground
	# process group: a Ctrl-C went to the query and the line stayed, and the shell's reads failed until it took the
	# terminal back. Not for a moment: a command run in the foreground to take it back (6.41 and before) held it
	# meanwhile, and lost it to a query that took it late
	env, home = home
	session = zsh_with(env, home, zas, extra=slow_engine_glue(1) + '\n' + extra)
	try:
		session.send(keys)
		assert times_away(session, 1.5) == 0
	finally:
		session.close()


def test_zsh_ctrl_c_drops_a_line_while_its_grey_text_is_asked_for(home):
	require_zsh_5_3()
	# not lost to the query (zsh before 5.8), which goes on: before zsh 5.8 it shares the shell's process group, and
	# one the Ctrl-C ended made zsh 5.5 now and then drop the line only at the next key, and that key with it
	env, home = home
	finished = home / 'finished'
	session = zsh_with(env, home, extra='_mssh_complete_engine() {{ sleep 1; {} "$@"; print -n x >> {} }}'.format(
		' '.join(shlex.quote(part) for part in ENGINE), shlex.quote(str(finished))))
	try:
		session.send('mssh gp')
		time.sleep(0.5)
		session.send('\x03')
		assert printed(session, '') == ''
		deadline = time.monotonic() + 5
		while not finished.exists() and time.monotonic() < deadline:
			time.sleep(0.05)
		assert finished.exists()
	finally:
		session.close()


def zsh_syntax_highlighting():
	"""The line loading zsh-syntax-highlighting; skip without it, unless MSSH_REQUIRE_SHELLS lists it."""
	if not os.path.isfile(ZSH_SH):
		if 'zsh-syntax-highlighting' in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(','):
			pytest.fail('zsh-syntax-highlighting is required here but not at ' + ZSH_SH)
		pytest.skip('zsh-syntax-highlighting is not installed at ' + ZSH_SH)
	# last in the rc file, as its instructions say
	return 'source ' + ZSH_SH


def greyed(session, text):
	"""Whether text is on screen with every character in the grey text's colour (256 colours)."""
	grid = rendered(session)
	for row, line in enumerate(grid.lines()):
		column = line.find(text)
		if column >= 0:
			return all('38;5;244' in style for style in grid.styles(row)[column:column + len(text)])
	return False


@pytest.mark.parametrize('line, move, keys', [
	('mssh gpu017 ', '', 'upt'),
	# a word before the host edited: the mark moves with the host
	('mssh -u root gpu017 ', LEFT * 8, 's'),
], ids=['next-word', 'word-before-edited'])
def test_zsh_marks_stay_with_zsh_syntax_highlighting(home, line, move, keys):
	# before zsh 5.9 (and before its 0.8) zsh-syntax-highlighting empties region_highlight after every key
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, extra=zsh_syntax_highlighting())
	try:
		session.send(line)
		session.read_until('unknown host'.encode())
		session.send(move)
		time.sleep(1)
		session.send(keys)
		time.sleep(0.5)
		session.read_for(0.2)
		assert underlined(session, 'gpu017'), screen(session)[:2]
	finally:
		session.close()


def test_zsh_grey_text_stays_grey_with_zsh_syntax_highlighting(home):
	env, home = home
	session = zsh_with(env, home, extra=zsh_syntax_highlighting())
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		# Ctrl-L: a key that leaves the line as it is
		session.send('\x0c')
		# (not a fixed sleep: on a loaded machine the redraw takes longer. Quiet first, so a repaint that turns it white is seen)
		session.wait_idle(10, window=0.5)
		deadline = time.monotonic() + 10
		while not greyed(session, 'nvidia-smi') and time.monotonic() < deadline:
			session.read_for(0.2)
		assert greyed(session, 'nvidia-smi')
	finally:
		session.close()


def test_zsh_alt_f_takes_an_escaped_word_whole(tmp_path):
	require_zsh_5_3()
	env, home = make_home(tmp_path, ["17900000{:02d}\t/x/multiSSH3.py\t-su -f='my file.txt'\tnode1\t/tmp".format(number) for number in range(6)])
	build_index(env)
	session = zsh_with(env, home)
	try:
		session.send('mssh -f m')
		session.read_until(b'file.txt')
		# not 'my\\' with a dangling backslash
		assert printed(session, '\x1bf') == 'mssh -f my\\ file.txt'
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_zsh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home, debug):
	env, home = home
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n'))
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_zsh_picker_draws_again_when_the_terminal_is_resized(home):
	# zsh leaves its line on screen: the menu opens again below the cursor's row
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		session.read_until(b'type to filter')
		session.resize(24, 50)
		session.read_until(b'type to filter')
		rows = rendered(session).lines()
		box = rows[1:13]
		assert rows[0].startswith('@@READY@@ mssh gpu[01-16]') and 'commands for gpu[01-16]' in box[0] and 'type to filter' in box[-1], rows
		assert len(set(len(row) for row in box)) == 1 and len(box[0]) < 50 and rows[13:] == [''] * 11, rows
		session.send('\x1b')
		assert printed(session, '') == 'mssh gpu[01-16] '
		session.send('\x15echo "[$COLUMNS]"\r')
		session.read_until(b'[50]')
		rows = settled(session)
		assert not [row for row in rows if 'filter' in row or '│' in row or '|' in row] and rows[-2:] == ['[50]', '@@READY@@'], rows
	finally:
		session.close()


def test_zsh_picker_leaves_keys_typed_after_the_choice(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12\rXYZ')
		time.sleep(1)
		assert words(printed(session, '')) == PICKED + ['XYZ']
	finally:
		session.close()


def recording_engine(home):
	'''The engine, keeping each request it is given in a file of home/requests: (command, that directory).'''
	requests = home / 'requests'
	requests.mkdir()
	path = home / 'recording-engine'
	path.write_text('#!/bin/sh\nrequest=$(mktemp {}/request.XXXXXX)\ncat >"$request"\nexec {} "$@" <"$request"\n'.format(
		shlex.quote(str(requests)), ' '.join(shlex.quote(part) for part in ENGINE)))
	path.chmod(0o755)
	return [str(path)], requests


def recorded_flags(requests):
	'''{kind: [the flags of each request]} of what recording_engine kept: pick, ghost, diag (warnings) or tab.'''
	kinds = {}
	for path in sorted(requests.iterdir()):
		flags = mc.parse_request(path.read_bytes()).flags
		kinds.setdefault(next((kind for kind in ('pick', 'ghost', 'diag') if flags.get(kind) == '1'), 'tab'), []).append(flags)
	return kinds


@pytest.mark.parametrize('zas', [False, True], ids=['own', 'zsh-autosuggestions'])
def test_zsh_says_the_locale_it_runs_in_in_every_request(home, zas):
	require_zsh_5_3()
	# grey text, warnings, Ctrl-R and TAB: each request holds zsh's measure of its locale, here C by an
	# LC_ALL it keeps to itself (the engine sees the exported LANG), and the picker draws ASCII
	env, home = home
	command, requests = recording_engine(home)
	session = zsh_with(env, home, zas, command=command, extra='LC_ALL=C   # not exported: zsh runs in C, mssh-complete sees LANG')
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'type to filter - ' in session.read_until(b'type to filter')
		session.send('\x1b')
		assert printed(session, '') == 'mssh gpu[01-16] '
		session.send('\x15mssh gp\t')
		session.wait_idle(40, window=0.5)
	finally:
		session.close()
	kinds = recorded_flags(requests)
	assert {'ghost', 'diag', 'pick', 'tab'} <= set(kinds), kinds
	assert [flags for flags in sum(kinds.values(), []) if (flags.get('utf8'), flags.get('turkic')) != ('0', '0')] == []


# ---------------------------------------------------------------- fish

def fish_major():
	output = subprocess.run([require_shell('fish'), '--version'], stdout=subprocess.PIPE, universal_newlines=True).stdout
	return int(re.search(r'(\d+)\.', output).group(1))


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
def test_fish_says_why_a_host_is_unknown_once(home, tmp_path, timeout):
	if fish_major() < 4:
		pytest.skip('fish 3 keeps its space key (self-insert does nothing next to a function): warnings only in the picker')
	env, home = home
	known(env, gpu017='invalid')
	if timeout == 'no timeout':
		# macOS has no coreutils timeout(1)
		env = without_command(env, 'timeout', tmp_path / 'bin')
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
		# the space was typed, and the same warning is not printed again at the next one
		assert printed(session, 'uptime ') == 'mssh gpu017 uptime '
		assert plain(session.output.decode('utf-8', 'replace')).count('gpu017: unknown host') == 1
	finally:
		session.close()


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
def test_fish_space_waits_for_a_slow_engine_only_until_the_time_limit(home, tmp_path, timeout):
	if fish_major() < 4:
		pytest.skip('fish 3 keeps its space key: no check at a space')
	env, home = home
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	env = dict(env, MSSH_COMPLETE_TIMEOUT='0.3')
	if timeout == 'no timeout':
		env = without_command(env, 'timeout', tmp_path / 'bin')
	session = fish_session(home, env, mc.render_glue('fish-keys', [str(slow)]))
	try:
		start = len(session.output)
		started = time.monotonic()
		assert printed(session, 'mssh h ', wait=0) == 'mssh h '
		assert time.monotonic() - started < 3
		# and fish printed nothing of its own: no error, no report of the engine stopped in the background
		shown = plain(session.output[start:].decode('utf-8', 'replace')).lower()
		assert [message for message in ('job', 'signal', 'error', 'command', 'fish:') if message in shown] == []
	finally:
		session.close()


def test_fish_space_still_expands_abbreviations(home):
	env, home = home
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre="abbr -a gg 'git grep'")
	try:
		assert printed(session, 'gg ') == 'git grep '
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_fish_ctrl_r_opens_the_picker_and_keeps_the_previous_binding(home, debug):
	env, home = home
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	pre = "bind \\cr 'commandline -r FISHPREV'"
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=pre)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15')
		assert printed(session, 'ls\x12') == 'FISHPREV'
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_fish_names_the_locale_it_exports_in_every_request(home):
	# TAB, the check at a space (fish 4) and Ctrl-R: each request names the LC_ALL, LC_CTYPE and LANG fish
	# exports, the only ones it follows (an LC_ALL it keeps to itself changes nothing)
	env, home = home
	command, requests = recording_engine(home)
	pre = 'set -g LC_ALL C\nfunction mssh; end\nsource {}'.format(glue_file(home, 'fish', command=command))
	session = fish_session(home, env, mc.render_glue('fish-keys', command), pre=pre)
	try:
		session.send('mssh gp\t')
		session.read_for(1.0)
		session.send('x ')
		session.read_for(1.0)
		session.send('\x12')
		assert 'type to filter' in session.read_until(b'type to filter')
		session.send('\x1b')
		session.read_for(0.5)
	finally:
		session.close()
	kinds = recorded_flags(requests)
	assert {'tab', 'pick'} | ({'diag'} if fish_major() >= 4 else set()) <= set(kinds), kinds
	assert [flags for flags in sum(kinds.values(), []) if (flags.get('lc_all'), flags.get('lc_ctype'), flags.get('lang')) != ('', '', env['LANG'])] == []


def slow_start_session(shell, env, home, delay, deaf=False, **env_options):
	'''zsh or fish (Ctrl-R bound to FISHPREV before the glue) whose engine is delay seconds slow to start.'''
	env = dict(env, **env_options)
	command = slow_engine(home, delay, deaf=deaf, only='pick')
	if shell == 'zsh':
		return zsh_with(env, home, command=command)
	return fish_session(home, env, mc.render_glue('fish-keys', command), pre="bind \\cr 'commandline -r FISHPREV'")


@pytest.mark.parametrize('shell', ['zsh', 'fish'])
def test_ctrl_r_goes_on_without_an_engine_slow_to_start(home, shell):
	# zsh and fish froze until it started. Past MSSH_COMPLETE_START_TIMEOUT Ctrl-R does what it did
	# before (zsh's incremental search, with the keys typed meanwhile); the picker never draws
	env, home = home
	delay = 1.5
	session = slow_start_session(shell, env, home, delay, MSSH_COMPLETE_START_TIMEOUT='0.3')
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		started = time.monotonic()
		if shell == 'zsh':
			session.send('\x12aa\r')
			assert re.search(r'[\r\n]aa2\r\n', session.read_until(b'aa2\r\n'))
		else:
			session.send('\x12')
			assert printed(session, '') == 'FISHPREV'
		assert time.monotonic() - started < delay
		# the engine would be ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('shell', ['zsh', 'fish'])
def test_ctrl_c_while_the_picker_starts_keeps_the_line(home, shell):
	# at once, even when Ctrl-C does not stop the engine (a hung file system): it never draws
	env, home = home
	delay = 1.5
	session = slow_start_session(shell, env, home, delay, deaf=True)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		started = time.monotonic()
		session.send('\x12')
		time.sleep(0.3)
		session.send('\x03')
		assert printed(session, '', wait=0.3) == 'mssh gpu[01-16] '
		assert time.monotonic() - started < delay
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		assert printed(session, 'x') == 'mssh gpu[01-16] x'
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('shell', ['zsh', 'fish'])
def test_a_picker_quick_enough_opens_after_its_start(home, shell):
	# slower than usual but within MSSH_COMPLETE_START_TIMEOUT: the picker opens, the choice is made
	env, home = home
	session = slow_start_session(shell, env, home, 0.5, MSSH_COMPLETE_START_TIMEOUT='30')
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 160)
		assert words(printed(session, '\r')) == PICKED
	finally:
		session.close()


# ---------------------------------------------------------------- pasting into the picker

FISH_FAKE_MSSH = 'function mssh; printf "@@RAN[%s]@@\\n" "$argv"; end'
ZSH_FAKE_MSSH = 'mssh() { print -r -- "@@RAN[$*]@@" }'


def pasted(text, form):
	'''text as a terminal sends a paste of it: between bracketed paste marks, or unmarked (the mode is off) with its line breaks as Enter.'''
	if form == 'bracketed':
		return '\x1b[200~' + text + '\x1b[201~'
	return text.replace('\n', '\r')


def paste_only_filters(session, form):
	'''
	Paste two lines into the picker: they only filter (nothing runs, Esc keeps the line). Then one line
	with its line break: Enter (typed, or the pasted one when the paste is unmarked, as when typed)
	chooses what it filtered, and nothing else reaches the line.
	'''
	session.send('mssh ')
	time.sleep(0.5)
	session.send('\x12')
	session.read_until(b'type to filter')
	session.send(pasted('stor\necho INJECTED\n', form))
	assert 'stor echo INJECTED' in read_until_shown(session, 'stor echo INJECTED')
	assert printed(session, '\x1b') == 'mssh '
	session.send('\x12')
	session.read_until(b'type to filter')
	session.send(pasted('stor\n', form))
	time.sleep(0.5)
	assert printed(session, '\r' if form == 'bracketed' else '') == 'mssh storage1 '
	assert '@@RAN' not in session.output.decode('utf-8', 'replace')


@pytest.mark.parametrize('form', ['bracketed', 'unmarked'])
def test_bash_paste_into_the_picker_only_filters(home, form):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'), extra=FAKE_MSSH)
	try:
		paste_only_filters(session, form)
	finally:
		session.close()


@pytest.mark.parametrize('form', ['bracketed', 'unmarked'])
def test_editor_paste_into_the_picker_only_filters(home, form):
	env, home = home
	session = editor_session(env, home)
	try:
		paste_only_filters(session, form)
	finally:
		session.close()


def test_editor_hands_a_paste_to_readline(home):
	# outside the picker a paste is readline's, as before the editor: its line breaks run nothing
	env, home = home
	session = editor_session(env, home)
	try:
		if b'\x1b[?2004h' not in session.output:
			pytest.skip('this bash does not turn bracketed paste on')
		session.send('mssh ')
		time.sleep(0.5)
		line = printed(session, pasted('gpu01 uptime\nhost2', 'bracketed'))
		assert line is not None and line.replace('\r\n', '\n') == 'mssh gpu01 uptime\nhost2'
		assert '@@RAN' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('form', ['bracketed', 'unmarked'])
def test_zsh_paste_into_the_picker_only_filters(home, form):
	env, home = home
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=ZSH_FAKE_MSSH)
	try:
		paste_only_filters(session, form)
	finally:
		session.close()


@pytest.mark.parametrize('form', ['bracketed', 'unmarked'])
def test_fish_paste_into_the_picker_only_filters(home, form):
	# fish 4 turns bracketed paste off while the picker runs (fish 3 leaves it on)
	env, home = home
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=FISH_FAKE_MSSH)
	try:
		paste_only_filters(session, form)
	finally:
		session.close()


ENTER_FORMS = [
	# CR LF (newline mode, serial consoles set to send it) and CR NUL (telnet) are one Enter: no LF is
	# left for the shell to run the line with
	('\r\n', 'mssh storage1 '), ('\r\x00', 'mssh storage1 '),
	# keys typed right after Enter (fast typing, a slow link) follow the choice, as the shell puts them
	('\r-q', 'mssh storage1 -q'),
]


def enter_chooses(session, keys):
	'''Filter the picker, then press Enter as keys sends it; the line the shell prints after.'''
	session.send('mssh ')
	time.sleep(0.5)
	session.send('\x12')
	session.read_until(b'type to filter')
	session.send('stor')
	time.sleep(0.3)
	return printed(session, keys)


@pytest.mark.parametrize('keys, line', ENTER_FORMS, ids=['cr-lf', 'cr-nul', 'typed-after'])
def test_bash_picker_enter_however_it_comes(home, keys, line):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'), extra=FAKE_MSSH)
	try:
		assert enter_chooses(session, keys) == line
		assert '@@RAN' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('keys, line', ENTER_FORMS, ids=['cr-lf', 'cr-nul', 'typed-after'])
def test_editor_picker_enter_however_it_comes(home, keys, line):
	env, home = home
	session = editor_session(env, home)
	try:
		assert enter_chooses(session, keys) == line
		assert '@@RAN' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('keys, line', ENTER_FORMS, ids=['cr-lf', 'cr-nul', 'typed-after'])
def test_zsh_picker_enter_however_it_comes(home, keys, line):
	env, home = home
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=ZSH_FAKE_MSSH)
	try:
		assert enter_chooses(session, keys) == line
		assert '@@RAN' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


def test_blesh_paste_into_the_picker_only_filters(home):
	# ble.sh turns bracketed paste off while the picker runs: the paste comes unmarked
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'), extra=FAKE_MSSH)
	try:
		paste_only_filters(session, 'unmarked')
	finally:
		session.close()


@pytest.mark.parametrize('pre', ['', "bind \\cr 'commandline -r FISHPREV'"], ids=['fish-binding', 'own-binding'])
def test_fish_keys_taken_run_only_what_they_ran_before(home, pre):
	# the glue keeps the commands of the bindings it takes, not bind's options or the key: fish ran
	# those as commands (Unknown command: space) at every space (fish 4) and at Ctrl-R on other lines
	env, home = home
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=pre)
	try:
		session.send('echo a b')
		read_until_shown(session, 'echo a b')
		session.send('\x12')
		if pre:
			assert 'FISHPREV' in read_until_shown(session, 'FISHPREV')
		errors = [row for row in settled(session) if 'fish:' in row or "in function '__mssh" in row]
		assert errors == []
	finally:
		session.close()


# ---------------------------------------------------------------- the picker's warnings, in every shell

# an unknown host, two exclusive options, a password given twice
WARNED = 'mssh -su -nsu -p hunter2 -p swordfish gpu017 '
PASSWORDS = ('hunter2', 'swordfish')
PICKER_WARNINGS = [
	'⚠ gpu017: unknown host',
	'⚠ -nsu cannot be used with -su (mssh stops with an error)',
	'⚠ -p given twice: mssh uses the last one',
]
REASON = '⚠ gpu017: unknown host (+2 more)'


def screen_when(session, check, timeout=40.0):
	"""The screen's non-empty rows as soon as check(rows) holds (or at the timeout)."""
	end = time.monotonic() + timeout
	while True:
		rows = [row.rstrip() for row in screen(session) if row.strip()]
		if check(rows) or time.monotonic() >= end:
			return rows
		session.read_for(0.1)


def quiet(session, gap=0.3, timeout=5.0):
	"""Read until the shell has printed nothing for gap seconds."""
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		size = len(session.output)
		session.read_for(gap)
		if len(session.output) == size:
			return


def from_the_line(rows):
	"""The rows from the command line down (the picker opens below it; rows above may scroll away)."""
	starts = [number for number, row in enumerate(rows) if row.startswith('@@READY@@ ')]
	return rows[starts[-1]:] if starts else rows


def picker_shell(shell, env, home):
	"""A session of shell where Ctrl-R opens the picker, and whether it shows a reason line while typing."""
	if shell == 'bash':
		# readline cannot draw warnings while typing: the picker is where plain bash shows them
		return bash_session(home, env, glue_file(home, 'bash')), False
	if shell == 'editor':
		return editor_session(env, home), True
	if shell == 'blesh':
		return blesh_session(home, env, glue_file(home, 'bash')), True
	if shell.startswith('zsh'):
		return zsh_with(env, home, zas=shell == 'zsh-autosuggestions'), True
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE))
	# fish 3 keeps its space key: warnings only in the picker
	return session, fish_major() >= 4


def check_warned_picker(session):
	"""Open the picker on WARNED (typed already) and check the warnings at its top."""
	session.send('\x12')
	session.read_until(b'type to filter')
	grid = rendered(session)
	lines = grid.lines()
	top = [row for row, line in enumerate(lines) if line.startswith('┌ commands for gpu017 ')]
	bottom = [row for row, line in enumerate(lines) if line.startswith('└ type to filter')]
	assert len(top) == 1 and len(bottom) == 1, lines
	top, bottom = top[0], bottom[0]
	# the warnings come first under the title, in plain text, then the candidates
	for number, text in enumerate(PICKER_WARNINGS):
		row = top + 1 + number
		assert lines[row].startswith('│ ' + text + ' ') and lines[row].endswith('│'), lines[row]
		assert set(grid.styles(row)) == {''}, (lines[row], grid.styles(row))
	assert lines[top + 4].startswith('│> nvidia-smi '), lines[top + 4]
	# nothing in the menu underlined (the line's marks do not leak into it), no password in it
	menu = range(top, bottom + 1)
	assert not [lines[row] for row in menu if any('4' in style.split(';') for style in grid.styles(row))]
	assert not [lines[row] for row in menu if any(secret in lines[row] for secret in PASSWORDS)]


@pytest.mark.parametrize('shell', ['bash', 'editor', 'zsh', 'zsh-autosuggestions', 'blesh', 'fish'])
def test_picker_shows_the_warnings_about_the_line_at_its_top(home, shell):
	if shell.startswith('zsh'):
		require_zsh_5_3()
	env, home = home
	known(env, gpu017='invalid')
	session, reason = picker_shell(shell, env, home)
	try:
		session.send(WARNED)
		shown = REASON if reason else '@@READY@@ ' + WARNED.rstrip()
		assert shown in screen_when(session, lambda rows: shown in rows)
		quiet(session)
		before = from_the_line([row.rstrip() for row in screen(session) if row.strip()])
		check_warned_picker(session)
		# Esc: the menu is gone, the line and what was under it are back as they were
		session.send('\x1b')
		after = screen_when(session, lambda rows: from_the_line(rows) == before)
		assert from_the_line(after) == before
		assert not [row for row in after if row[:1] in ('┌', '│', '└')]
		# again, then Enter: the line with the chosen command, and what was under it
		check_warned_picker(session)
		session.send('\r')
		expected = ['@@READY@@ ' + WARNED + 'nvidia-smi'] + before[1:]
		after = screen_when(session, lambda rows: from_the_line(rows) == expected)
		assert from_the_line(after) == expected
		assert not [row for row in after if row[:1] in ('┌', '│', '└')]
		assert words(printed(session, '')) == words(WARNED + 'nvidia-smi')
	finally:
		session.close()


# ---------------------------------------------------------------- the operator's own aliases and functions

# What operators put in their rc files under the names of commands a glue could run, before the mssh
# block (bash and zsh expand aliases as they read a function) or after it (functions, and the aliases
# bash and zsh expand in a command substitution as it runs). GREP_OPTIONS: old greps read it. A
# function is defined as "function name": an alias of that name is there already (the one above, or
# a system rc file's grep), and would be expanded in "name() {".
OPERATOR_BASH = '\n'.join([
	"alias grep='grep --color=always' egrep='egrep --color=always' fgrep='fgrep --color=always'",
	"alias ls='ls --color=always -F' cat='cat -A' sed='sed -E' rm='rm -i' sort='sort -r' head='head -n 1' tr='tr -d x'",
	'export GREP_OPTIONS=--color=always',
	'function grep { command grep --color=always -n "$@"; }',
	'function sed { command sed -E "$@"; }',
	'function cd { builtin cd "$@" && echo "cd $PWD"; }',
	'function command_not_found_handle { echo "not found: $1"; return 127; }',
])

OPERATOR_ZSH = '\n'.join([
	"alias grep='grep --color=always' ls='ls --color=always' cat='cat -A' sed='sed -E' rm='rm -i' sort='sort -r' head='head -n 1'",
	# as oh-my-zsh and prezto define them, global aliases included
	"alias fc='noglob fc' history='fc -il 1' _='sudo ' -- -='cd -' 1='cd -1'",
	"alias -g ...='../..' G='| grep' L='| less' H='| head' T='| tail' C='| wc -l' X='| xargs' NE='2>/dev/null'",
	'function grep { command grep --color=always -n "$@" }',
	'function sed { command sed -E "$@" }',
	'function cd { builtin cd "$@" && print -r -- "cd $PWD" }',
	'function command_not_found_handler { print -r -- "not found: $1"; return 127 }',
])

# fish's aliases are functions; the history one makes fish's --show-time permanent
OPERATOR_FISH = '\n'.join([
	"alias grep 'grep --color=always'",
	"alias cat 'cat -A'",
	"alias history 'history --show-time=\"%F %T \"'",
	'function timeout; echo TIMEOUT; end',
	'function cd; builtin cd $argv; and echo "cd $PWD"; end',
	'function fish_command_not_found; echo "not found: $argv[1]"; end',
])


def operator_rc(where, lines, **rc):
	'''rc keyword arguments putting the operator's lines before or after the glue (adding to rc's).'''
	key = 'pre' if where == 'before' else 'extra'
	rc[key] = rc.get(key, '') + '\n' + lines
	return rc


@pytest.mark.parametrize('where', ['before', 'after'])
def test_bash_keys_ignore_the_operators_aliases_and_functions(home, where):
	env, home = home
	known(env, gpu017='invalid')
	editor = bash_version(env) >= 44
	rc = operator_rc(where, OPERATOR_BASH, extra=FAKE_MSSH)
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'), **rc)
	try:
		# readline's TAB and Ctrl-R (a leading space keeps the line out of the editor)
		assert session.line_after(' mssh -u r') == ' mssh -u root '
		session.send(' mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		if editor:
			# the mssh line editor: grey text, and why a word is marked
			session.send('\x15mssh gp')
			grey = '\x1b[38;5;244mu[01-16] "nvidia-smi"'
			assert grey in session.read_until(grey.encode())
			assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
			session.send('\x15mssh gpu017 ')
			assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
		output = plain(session.output.decode('utf-8', 'replace'))
		assert 'not found' not in output and 'GREP_OPTIONS' not in output
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_blesh_ignores_the_operators_aliases_and_functions(home, where):
	env, home = home
	known(env, gpu017='invalid')
	session = blesh_session(home, env, glue_file(home, 'bash'), **operator_rc(where, OPERATOR_BASH))
	try:
		assert words(session.line_after('mssh -u r')) == ['mssh', '-u', 'root']
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 60))
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_zsh_ignores_the_operators_aliases_and_functions(home, where):
	require_zsh_5_3()
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, **{'rc_' + where: OPERATOR_ZSH})
	try:
		assert session.line_after('mssh -u r') == 'mssh -u root '
		session.send('mssh gp')
		session.read_until(b'nvidia-smi')
		assert words(printed(session, RIGHT)) == PICKED
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for')
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_fish_ignores_the_operators_functions(home, where):
	env, home = home
	known(env, gpu017='invalid')
	# lines only fish's own history has: a local command, and an mssh line
	data = home / '.local' / 'share' / 'fish'
	data.mkdir(parents=True)
	(data / 'fish_history').write_text('- cmd: echo three\n  when: {}\n- cmd: mssh zzq9 fishonly\n  when: {}\n'.format(aged(1790000000), aged(1790000001)))
	config = home / '.config' / 'fish'
	(config / 'completions').mkdir(parents=True)
	(config / 'completions' / 'mssh.fish').write_text(mc.render_glue('fish', ENGINE))
	# fish loads a command's completions only when the command exists
	pre = 'function mssh; end'
	if where == 'before':
		# conf.d runs in name order: before the mssh glue
		(config / 'conf.d').mkdir()
		(config / 'conf.d' / '00-operator.fish').write_text(OPERATOR_FISH + '\n')
	else:
		pre += '\n' + OPERATOR_FISH
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=pre)
	try:
		# TAB, from mssh's history and from fish's (roo: fish offers $USER too, which may start with r)
		assert printed(session, 'mssh -u roo\t') == 'mssh -u root '
		assert words(printed(session, '\x15mssh h "echo th\t')) == ['mssh', 'h', 'echo three']
		if fish_major() >= 4:
			session.send('\x15mssh gpu017 ')
			assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode()))
	finally:
		session.close()


@pytest.mark.parametrize('delay', [0.01, 0.03])
def test_bash_ctrl_c_right_after_ctrl_r_leaves_the_terminal_in_readline_s_mode(tmp_path, delay):
	# with an engine that dies of the signal (the real one, early on): bash 4.3, 4.4 and 5.0 left the terminal cooked until the
	# next Enter, so Ctrl-U no longer cleared the line. The mode is what counts: the line stays after this Ctrl-C by design
	env, home = make_home(tmp_path, [])
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh x')
		session.read_for(0.2)
		session.send('\x12')
		time.sleep(delay)
		session.send('\x03')
		session.read_for(0.8)
		assert not termios.tcgetattr(session.fd)[3] & termios.ICANON
	finally:
		session.close()
