'''
SP2 in real shells: grey suggestions, the Ctrl-R picker and the plain-bash mssh line editor.

Every shell gets a private HOME holding an mssh history where one invocation clearly dominates,
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import os
import re
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
UP = '\x1b[A'


@pytest.fixture
def home(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	(home / '.bash_history').write_text(SHELL_HISTORY)
	return env, home


def glue_file(home, shell, name=None):
	path = home / (name or 'glue.' + shell)
	path.write_text(mc.render_glue(shell, ENGINE))
	return path


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


def test_bash_vi_mode_ctrl_r(home):
	env, home = home
	pre = 'set -o vi\nbind -m vi-insert -x \'"\\C-x\\C-p": printf "@@LINE[%s]@@\\n" "$READLINE_LINE"\''
	session = bash_session(home, env, glue_file(home, 'bash'), pre=pre)
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

def editor_session(env, home, **kwargs):
	if bash_version(env) < 44:
		pytest.skip('the mssh line editor needs bash 4.4 or later')
	return bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1', **kwargs), glue_file(home, 'bash'), extra=FAKE_MSSH)


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


# ---------------------------------------------------------------- zsh

ZAS = '/opt/zsh-autosuggestions/zsh-autosuggestions.zsh'


def zsh_with(env, home, zas=False, after=False, late=False, shell_history=SHELL_HISTORY):
	'''zsh with the glue; zsh-autosuggestions loaded before it, after it (after), or at the first prompt (late).'''
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
		pre=history if after else pre + '\n' + history, extra=pre if after else '')


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
	"""The terminal after everything the session printed."""
	from vt_grid import Grid
	grid = Grid(24, 80)
	grid.feed(session.output.decode('utf-8', 'replace'))
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
