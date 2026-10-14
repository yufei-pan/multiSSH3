'''
SP2 in real shells: grey suggestions, the Ctrl-R picker and the plain-bash mssh line editor.

Every shell gets a private HOME holding an mssh history where one invocation clearly dominates,
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import os
import re
import shlex
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, bash_session, blesh_session, build_index, fish_session, make_home,
	require_shell, without_command, zsh_session)

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


def slow_engine(home, delay, deaf=False):
	'''
	The engine, delay seconds slow to start (an NFS home, a loaded machine); deaf: Ctrl-C does not stop
	it either, as when it waits on a hung file system.
	'''
	import shlex
	path = home / 'slow-engine'
	path.write_text('#!/bin/sh\n{}sleep {}\nexec {} "$@"\n'.format("trap '' INT\n" if deaf else '', delay, ' '.join(shlex.quote(part) for part in ENGINE)))
	path.chmod(0o755)
	return [str(path)]


def printed(session, keys, wait=0.6):
	'''Send keys, then the print key; the command line the shell printed (None if it did not).'''
	session.send(keys)
	time.sleep(wait)
	session.send(session.print_key)
	text = session.read_until(b']@@', 10)
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
		session.read_until(b'@@never@@', 0.1)


def words(line):
	'''The words a line means, whatever quoting was chosen.'''
	return None if line is None else [token.text for token in mc.lex(line)]


PICKED = ['mssh', 'gpu[01-16]', 'nvidia-smi']


def bash_version(env):
	output = subprocess.run([require_shell('bash'), '-c', 'echo ${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}'], env=env, stdout=subprocess.PIPE)
	return int(output.stdout.decode().strip())


# ---------------------------------------------------------------- plain bash: Ctrl-R

def test_bash_ctrl_r_opens_the_picker_on_mssh_lines(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
	finally:
		session.close()


def test_bash_ctrl_r_cancel_keeps_the_line(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] nv')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'commands for', 10)
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
		session.read_until(b'commands for', 10)
		assert printed(session, esc) == 'mssh gpu[01-16] nv'
	finally:
		session.close()


def test_bash_ctrl_r_on_other_lines_is_still_reverse_search(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		# the second Ctrl-R finds the older match, as readline's own search does
		session.send('\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
		# and the next prompt opens the picker again on mssh lines
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for' in session.read_until(b'commands for', 10)
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
			assert 'commands for' in session.read_until(b'commands for', 10)
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
		assert 'commands for' in session.read_until(b'commands for', 10)
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
		session.read_until(b'type to filter', 10)
		session.resize(24, 50)
		session.read_until(b'type to filter', 10)
		rows = rendered(session).lines()
		box = rows[1:13]
		assert rows[0] == '@@READY@@ mssh gpu[01-16]' and 'commands for gpu[01-16]' in box[0] and 'type to filter' in box[-1], rows
		assert len(set(len(row) for row in box)) == 1 and len(box[0]) < 50 and rows[13:] == [''] * 11, rows
		# Esc: the line as it was, nothing left of the menu; bash knows the new width
		session.send('\x1b')
		assert printed(session, '') == 'mssh gpu[01-16] '
		session.send('\x15echo "[$COLUMNS]"\r')
		session.read_until(b'[50]', 10)
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
		assert re.search(r'[\r\n]aa2\r\n', session.read_until(b'aa2\r\n', 10))
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
		session.read_until(b'@@READY@@ mssh gpu[01-16] ', 5)
		assert time.monotonic() - started < delay
		rows = [row for row in screen(session) if row]
		assert rows == ['@@READY@@ mssh gpu[01-16]'], rows
		# the engine is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		assert printed(session, 'x') == 'mssh gpu[01-16] x'
		assert 'type to filter' not in session.output.decode('utf-8', 'replace')
	finally:
		session.close()


@pytest.mark.parametrize('option', ['set -e', 'set -u', 'set -o pipefail'])
def test_bash_shell_options_do_not_break_ctrl_r_or_the_editor(home, option):
	env, home = home
	session = bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1'), glue_file(home, 'bash'), extra=FAKE_MSSH + '\n' + option)
	try:
		# a path to mssh: space is a space, Ctrl-R the picker
		session.send('/x/mssh gpu[01-16] \x12')
		session.read_until(b'type to filter', 10)
		assert words(printed(session, '\r')) == ['/x/mssh'] + PICKED[1:]
		if bash_version(env) >= 44:
			session.send('\x15mssh gp')
			session.read_until(b'nvidia-smi', 10)
			assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
		# never ready in time: Ctrl-R searches as before, space is a space
		session.send('\x15MSSH_COMPLETE_START_TIMEOUT=0\r/x/mssh gpu[01-16] \x12aa')
		read_until_shown(session, 'echo aa2', 10)
		assert reverse_search_found(session, 'echo aa2'), screen(session)
		session.send('\x07\x15mssh xy\r')
		assert '@@RAN[xy]@@' in session.read_until(b'@@RAN[xy]@@', 10)
		session.send('echo "[alive]"\r')
		assert '[alive]\r\n' in session.read_until(b'[alive]\r\n', 10)
	finally:
		session.close()


def test_bash_ctrl_r_keeps_the_last_argument(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('true lastarg\r')
		time.sleep(0.3)
		session.send('mssh x\x12')
		session.read_until(b'type to filter', 10)
		session.send('\x1b')
		time.sleep(0.3)
		session.send('\x15echo "[$_]"\r')
		assert '[lastarg]' in session.read_until(b'[lastarg]', 10)
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
	output = plain(session.read_until(b'@@RAN', 10) + session.read_until(b'@@READY@@', 5))
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
		session.read_until(b'type to filter', 10)
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
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
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
		assert '@@VARS:MINE,MINE,MINE,MINE@@' in session.read_until(b'@@\r\n', 10)
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
		assert '" ": self-insert' in session.read_until(b'self-insert', 10)
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


def test_editor_runs_pasted_lines_in_order(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh host1 uptime\rmssh host2 uptime\r')
		output = session.read_until(b'@@RAN[host2 uptime]@@', 15)
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
		assert '[lastarg]' in session.read_until(b'[lastarg]', 10)
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
			session.read_until(b'@@READY@@', 10)
		session.send('echo hi\r')
		session.read_until(b'@@READY@@', 10)
		# space after !! expands it, as magic-space does
		assert printed(session, 'echo !! ') == 'echo echo hi '
	finally:
		session.close()


def test_editor_shows_and_accepts_the_suggestion(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		assert '\x1b[38;5;244mu[01-16] "nvidia-smi"' in session.read_until(b'nvidia-smi', 10)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_editor_marks_an_unknown_host_and_says_why(home):
	env, home = home
	# the prober found gpu017 does not exist
	mc.write_host_states(os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3'), {'gpu017': mc.HostState('invalid', time.time())})
	session = editor_session(env, home)
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
	finally:
		session.close()


def test_editor_marks_a_remote_command_word_mssh_reads_as_its_own_option(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh node01 journalctl -u slurmd')
		reason = "⚠ -u is mssh's --username here — quote the command: 'journalctl -u slurmd'"
		assert reason in plain(session.read_until(b'slurmd\'', 10))
		assert underlined(session, '-u')
	finally:
		session.close()


def test_editor_enter_runs_what_was_typed(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		session.send('\r')
		assert '@@RAN[gp]@@' in session.read_until(b'@@RAN[gp]@@', 10)
	finally:
		session.close()


def test_editor_keeps_a_burst_of_type_ahead(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] "nvidia-smi"\r')
		assert '@@RAN[gpu[01-16] nvidia-smi]@@' in session.read_until(b'@@RAN', 10) + session.read_until(b'@@READY@@', 10)
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
		session.read_until(b'nvidia-smi', 10)
		session.send('\x1b[13u')
		assert '@@RAN[gp]@@' in session.read_until(b'@@RAN[gp]@@', 10)
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
		session.read_until('unknown host'.encode(), 10)
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
		session.read_until(b'nvidia-smi', 10)
		session.resize(24, 30)
		session.read_until(b'nvidia-smi', 10)
		grid = rendered(session)
		assert grid.lines()[:3] == ['@@READY@@ mssh gpu[01-16] "nvi', 'dia-smi"', ''] and grid.cursor == (0, 17)
		session.send('\x03')
		session.read_until(b'^C', 10)
		session.send('echo "[$COLUMNS]"\r')
		session.read_until(b'[30]', 10)
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
		assert '@@RAN[host1 uptime]@@' in session.read_until(b'@@RAN[host1 uptime]@@', 10)
		assert time.monotonic() - started < delay - 0.5
		# the editor is ready by now
		time.sleep(max(started + delay + 0.5 - time.monotonic(), 0))
		session.send('echo "[ok]"\r')
		assert '[ok]\r\n' in session.read_until(b'[ok]\r\n', 10)
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
		session.read_until(b'^C', 5)
		session.read_until(b'@@READY@@', 5)
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
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
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
		output = session.read_until(b'@@RAN[gpu]@@', 10)
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
		session.read_until(b'nvidia-smi', 10)
		# only the engine knows the command: the shell history is about echo
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_blesh_marks_an_unknown_host_and_says_why(home):
	env, home = home
	known(env, gpu017='invalid')
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 15))
		session.read_until(b'@@never@@', 1)
		assert underlined(session, 'gpu017')
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
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode(), 15)
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
			assert 'nvidia-smi' in session.read_until(b'nvidia-smi', 10)
			session.send('\x03')
			session.read_until(b'@@READY@@', 10)
			session.send('mssh %s ' % host)
			assert host + ': unknown host' in plain(session.read_until(b'unknown host', 15))
			session.send('\x03')
			session.read_until(b'@@READY@@', 10)
		assert b'cannot overwrite' not in session.output
	finally:
		session.close()


def test_blesh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
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
	delay = 2.0
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


def zsh_with(env, home, zas=False, after=False, late=False, shell_history=SHELL_HISTORY, extra='', rc_before='', rc_after='', **options):
	'''
	zsh with the glue; zsh-autosuggestions loaded before it, after it (after), or at the first prompt (late);
	rc_before and rc_after: the operator's own rc lines before and after the glue; extra runs last.
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
	return zsh_session(home, dict(env, HISTFILE=str(home / '.zsh_history')), glue_file(home, 'zsh'),
		pre=(history if after else pre + '\n' + history) + '\n' + rc_before,
		extra=(pre if after else '') + '\n' + rc_after + '\n' + extra, **options)


@pytest.mark.parametrize('zas, after', [(False, False), (True, False), (True, True)], ids=['own', 'zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
def test_zsh_suggests_and_right_arrow_accepts(home, zas, after):
	env, home = home
	session = zsh_with(env, home, zas, after)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
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
		session.read_until(b'@@READY@@', 10)
		session.send('mssh gp')
		drawn = session.read_until(b'nvidia-smi', 10)
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
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, zas)
	try:
		session.send('mssh gpu017 ')
		output = session.read_until('unknown host'.encode(), 10)
		assert '⚠ gpu017: unknown host' in plain(output)
		# the host is underlined
		assert underlined(session, 'gpu017')
	finally:
		session.close()


def test_zsh_suggests_warns_and_picks_without_compinit(home):
	# only TAB needs zsh's completion system
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, compinit='')
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		assert words(printed(session, RIGHT)) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
	finally:
		session.close()


def test_zsh_marks_a_remote_command_word_mssh_reads_as_its_own_option(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh node01 df -h ')
		output = session.read_until(b'df -h\'', 10)
		assert "⚠ -h is mssh's --help here — quote the command: 'df -h'" in plain(output)
		assert underlined(session, '-h')
	finally:
		session.close()


def test_zsh_warning_appears_when_the_prober_answers(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu099 ')
		time.sleep(0.2)
		known(env, gpu099='invalid')
		# no key pressed: the glue asks again while the prober works
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode(), 10)
	finally:
		session.close()


def test_zsh_warning_goes_away_when_the_host_is_fixed(home):
	env, home = home
	known(env, gpu017='invalid', gpu17='valid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu017 ')
		assert 'unknown host' in session.read_until('unknown host'.encode(), 10)
		session.send('\x7f' * 7 + 'gpu17 ')
		session.read_until(b'gpu17 ', 10)
		time.sleep(1)
		session.read_until(b'@@never@@', 0.5)
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
		session.read_until('unknown host'.encode(), 10)
		time.sleep(0.5)
		for keys in fixes:
			session.send(keys)
			time.sleep(0.3)
		time.sleep(1)
		session.read_until(b'@@never@@', 0.2)
		assert not [style for style in line_styles(session, line) if '4' in style.split(';')], screen(session)[:2]
	finally:
		session.close()


def test_zsh_accepted_grey_text_is_not_grey(home):
	# a character of the grey text typed first: zsh moved the grey highlight along with it
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		session.send('u')
		time.sleep(0.5)
		session.send(RIGHT)
		time.sleep(0.5)
		session.read_until(b'@@never@@', 0.2)
		assert not [style for style in line_styles(session, 'nvidia-smi') if '244' in style.split(';')]
	finally:
		session.close()


def settled(session, quiet=1.0):
	"""The non-empty rows of the screen once the session printed nothing more for a while."""
	time.sleep(quiet)
	session.read_until(b'@@never@@', 0.5)
	return [row.rstrip() for row in screen(session) if row.strip()]


@pytest.mark.parametrize('keys, below', [
	# the next word finished, typed or completed: the line keeps its row, the reason stays under it
	('uptime ', '⚠ gpu017: unknown host'),
	('upt\t', '⚠ gpu017: unknown host'),
	# TAB lists as on any line
	('--ipmi_\t', '--ipmi_method'),
], ids=['next-word', 'tab-completes', 'tab-lists'])
def test_zsh_keys_on_a_warned_line(home, keys, below):
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu017 ')
		session.read_until('unknown host'.encode(), 10)
		time.sleep(0.5)
		session.send(keys)
		rows = settled(session)
		assert rows[0].startswith('@@READY@@ mssh gpu017 ') and any(below in row for row in rows[1:]), rows[:4]
	finally:
		session.close()


@pytest.mark.parametrize('known_before, delay', [(False, 0.2), (True, 0.0), (True, 0.12)], ids=['answered-while-typing', 'known-typed-at-once', 'known-typed-quickly'])
def test_zsh_warning_appears_while_the_command_is_typed(home, known_before, delay):
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
		rows = settled(session, 3)
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


@pytest.mark.parametrize('zas, extra, keys', [
	(False, '', 'mssh gp'),
	(False, '', 'mssh --ipmi_\t'),
	# grey text from zsh-autosuggestions, which gives the terminal back itself: only the warnings' query is left
	(True, '', 'mssh gpu017 '),
	(True, ZAS_SYNC, 'mssh gp'),
], ids=['grey-text', 'tab', 'warnings', 'zsh-autosuggestions-sync'])
def test_zsh_keeps_the_terminal_while_mssh_asks(home, zas, extra, keys):
	# before zsh 5.8 each query's process substitution took the terminal from the shell (Ctrl-C went to the
	# query, the shell's reads failed until it took the terminal back) unless the glue gives it back
	env, home = home
	session = zsh_with(env, home, zas, extra=slow_engine_glue() + '\n' + extra)
	try:
		session.send(keys)
		time.sleep(0.5)
		assert os.tcgetpgrp(session.fd) == session.pid
	finally:
		session.close()


def test_zsh_ctrl_c_drops_a_line_while_its_grey_text_is_asked_for(home):
	# not lost to the query (zsh before 5.8)
	env, home = home
	session = zsh_with(env, home, extra=slow_engine_glue())
	try:
		session.send('mssh gp')
		time.sleep(0.5)
		session.send('\x03')
		assert printed(session, '') == ''
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
		session.read_until('unknown host'.encode(), 10)
		session.send(move)
		time.sleep(1)
		session.send(keys)
		time.sleep(0.5)
		session.read_until(b'@@never@@', 0.2)
		assert underlined(session, 'gpu017'), screen(session)[:2]
	finally:
		session.close()


def test_zsh_grey_text_stays_grey_with_zsh_syntax_highlighting(home):
	env, home = home
	session = zsh_with(env, home, extra=zsh_syntax_highlighting())
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		# Ctrl-L: a key that leaves the line as it is
		session.send('\x0c')
		time.sleep(0.5)
		session.read_until(b'@@never@@', 0.2)
		assert greyed(session, 'nvidia-smi')
	finally:
		session.close()


def test_zsh_alt_f_takes_an_escaped_word_whole(tmp_path):
	env, home = make_home(tmp_path, ["17900000{:02d}\t/x/multiSSH3.py\t-su -f='my file.txt'\tnode1\t/tmp".format(number) for number in range(6)])
	build_index(env)
	session = zsh_with(env, home)
	try:
		session.send('mssh -f m')
		session.read_until(b'file.txt', 10)
		# not 'my\\' with a dangling backslash
		assert printed(session, '\x1bf') == 'mssh -f my\\ file.txt'
	finally:
		session.close()


def test_zsh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
	finally:
		session.close()


def test_zsh_picker_draws_again_when_the_terminal_is_resized(home):
	# zsh leaves its line on screen: the menu opens again below the cursor's row
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		session.read_until(b'type to filter', 10)
		session.resize(24, 50)
		session.read_until(b'type to filter', 10)
		rows = rendered(session).lines()
		box = rows[1:13]
		assert rows[0].startswith('@@READY@@ mssh gpu[01-16]') and 'commands for gpu[01-16]' in box[0] and 'type to filter' in box[-1], rows
		assert len(set(len(row) for row in box)) == 1 and len(box[0]) < 50 and rows[13:] == [''] * 11, rows
		session.send('\x1b')
		assert printed(session, '') == 'mssh gpu[01-16] '
		session.send('\x15echo "[$COLUMNS]"\r')
		session.read_until(b'[50]', 10)
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
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
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


def test_fish_ctrl_r_opens_the_picker_and_keeps_the_previous_binding(home):
	env, home = home
	pre = "bind \\cr 'commandline -r FISHPREV'"
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=pre)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15')
		assert printed(session, 'ls\x12') == 'FISHPREV'
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
	session.read_until(b'type to filter', 10)
	session.send(pasted('stor\necho INJECTED\n', form))
	assert 'stor echo INJECTED' in read_until_shown(session, 'stor echo INJECTED')
	assert printed(session, '\x1b') == 'mssh '
	session.send('\x12')
	session.read_until(b'type to filter', 10)
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
	session.read_until(b'type to filter', 10)
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


def screen_when(session, check, timeout=10.0):
	"""The screen's non-empty rows as soon as check(rows) holds (or at the timeout)."""
	end = time.monotonic() + timeout
	while True:
		rows = [row.rstrip() for row in screen(session) if row.strip()]
		if check(rows) or time.monotonic() >= end:
			return rows
		session.read_until(b'@@never@@', 0.1)


def quiet(session, gap=0.3, timeout=5.0):
	"""Read until the shell has printed nothing for gap seconds."""
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		size = len(session.output)
		session.read_until(b'@@never@@', gap)
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
	session.read_until(b'type to filter', 10)
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
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		if editor:
			# the mssh line editor: grey text, and why a word is marked
			session.send('\x15mssh gp')
			grey = '\x1b[38;5;244mu[01-16] "nvidia-smi"'
			assert grey in session.read_until(grey.encode(), 10)
			assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
			session.send('\x15mssh gpu017 ')
			assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
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
		session.read_until(b'nvidia-smi', 10)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 15))
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_zsh_ignores_the_operators_aliases_and_functions(home, where):
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, **{'rc_' + where: OPERATOR_ZSH})
	try:
		assert session.line_after('mssh -u r') == 'mssh -u root '
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		assert words(printed(session, RIGHT)) == PICKED
		session.send('\x15mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_fish_ignores_the_operators_functions(home, where):
	env, home = home
	known(env, gpu017='invalid')
	# lines only fish's own history has: a local command, and an mssh line
	data = home / '.local' / 'share' / 'fish'
	data.mkdir(parents=True)
	(data / 'fish_history').write_text('- cmd: echo three\n  when: 1790000000\n- cmd: mssh zzq9 fishonly\n  when: 1790000001\n')
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
		# TAB, from mssh's history and from fish's
		assert printed(session, 'mssh -u r\t') == 'mssh -u root '
		assert words(printed(session, '\x15mssh h "echo th\t')) == ['mssh', 'h', 'echo three']
		# the picker's history tab holds the line fish's history has
		session.send('\x15mssh zzq9 ')
		time.sleep(0.5)
		session.send('\x12')
		session.read_until(b'commands for', 10)
		assert printed(session, '\tfishonly\r') == 'mssh zzq9 fishonly'
		if fish_major() >= 4:
			session.send('\x15mssh gpu017 ')
			assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
	finally:
		session.close()
