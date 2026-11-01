'''mssh autocomplete inside ble.sh (Bash Line Editor), which replaces readline and adds suggestions.'''
import re
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, WITH_AND_WITHOUT_DEBUG_LOG, blesh_session, build_index, debug_log_size, make_home, with_debug_log

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]
ESCAPES = re.compile(r'\x1b(\[[0-9;?>]*[A-Za-z]|[78()][A-Z0-9]?)')


@pytest.fixture
def setup(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	return env, home


def glue_file(home, command=ENGINE):
	path = home / 'glue.bash'
	path.write_text(mc.render_glue('bash', command))
	return path


def words(line):
	'''The words a line means, whatever quoting ble.sh chose ('gpu[01-16]' and gpu[01-16] are the same).'''
	return None if line is None else [token.text for token in mc.lex(line)]


@pytest.mark.parametrize('typed, expected', [
	('mssh gp', ['mssh', 'gpu[01-16]']),
	('mssh gpu[01-16] "nvid', ['mssh', 'gpu[01-16]', 'nvidia-smi']),
	('mssh -u r', ['mssh', '-u', 'root']),
	('mssh --no_wa', ['mssh', '--no_watch']),
	('mssh h fakecmd al', ['mssh', 'h', 'fakecmd', 'alpha']),
	# a quoted remote command: ble.sh hands the glue the quote evaluated and closed ('fakecmd al'), the glue reads the line it keeps
	('mssh h "fakecmd al', ['mssh', 'h', 'fakecmd alpha']),
	("mssh h 'fakecmd al", ['mssh', 'h', 'fakecmd alpha']),
	('mssh h "date; fakecmd al', ['mssh', 'h', 'date; fakecmd alpha']),
])
def test_blesh_tab_completes(setup, typed, expected):
	env, home = setup
	session = blesh_session(home, env, glue_file(home))
	try:
		assert words(session.line_after(typed)) == expected
	finally:
		session.close()


def test_blesh_suggests_our_candidates_while_typing(setup):
	# ble.sh shows the rest of the line in grey from our completion; Right arrow takes it
	env, home = setup
	session = blesh_session(home, env, glue_file(home))
	try:
		for char in 'mssh gpu[01-16] "nvid':
			session.send(char)
			time.sleep(0.1)
		time.sleep(1.5)
		assert session.line_after('', keys='\x1b[C') == 'mssh gpu[01-16] "nvidia-smi" '
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_blesh_tab_completes_with_and_without_the_debug_log(setup, debug):
	env, home = setup
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = blesh_session(home, env, glue_file(home))
	try:
		assert words(session.line_after('mssh gp')) == ['mssh', 'gpu[01-16]']
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_blesh_typing_is_not_held_up_by_a_slow_engine(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	session = blesh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, [str(slow)]))
	try:
		started = time.monotonic()
		for char in 'mssh gpu[01-16] uptime':
			session.send(char)
			time.sleep(0.05)
		# the slow engine is still running: it is what is not waited for
		assert session.line_after('', keys='', settle=False) == 'mssh gpu[01-16] uptime'
		assert time.monotonic() - started < 6
	finally:
		session.close()


def test_blesh_start_shows_nothing_from_the_glue(setup):
	env, home = setup
	alone = blesh_session(home, env)
	alone.close()
	glued = blesh_session(home, env, glue_file(home, ['/nonexistent/engine']))
	glued.close()
	strip = lambda output: ESCAPES.sub('', output.decode('utf-8', 'replace'))
	assert strip(glued.output) == strip(alone.output)


def test_blesh_inserts_command_words_as_history_ran_them(tmp_path):
	# as mssh records `mssh web1 "nosuchcmd status 'ssh*'"` and `mssh web1 'othercmd $HOME/notes'`: the
	# local words must hold what mssh passes on to the remote shell, quoted once by ble.sh
	env, home = make_home(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\tweb1\t\'nosuchcmd status \'"\'"\'ssh*\'"\'"\'\'',
		"1790000000\t/x/multiSSH3.py\t-su\tweb1\t'othercmd $HOME/notes'"])
	build_index(env)
	# an empty working directory: bash adds its files to the words of a remote command
	empty = tmp_path / 'empty'
	empty.mkdir()
	session = blesh_session(home, env, glue_file(home), extra="cd '{}'".format(empty))
	try:
		assert words(session.line_after('mssh web1 nosuchcmd status ')) == ['mssh', 'web1', 'nosuchcmd', 'status', "'ssh*'"]
		assert words(session.line_after('mssh web1 othercmd ')) == ['mssh', 'web1', 'othercmd', '$HOME/notes']
	finally:
		session.close()


def blesh_line(tmp_path, typed, history=(), options='', files=(), keys='\t'):
	"""The line after typed and keys in a new ble.sh session with the glue, in a directory holding files (and no other);
	options run after the glue loads."""
	env, home = make_home(tmp_path, history)
	build_index(env)
	work = tmp_path / 'work'
	work.mkdir()
	for name in files:
		(work / name).write_text('')
	session = blesh_session(home, env, glue_file(home), extra="cd '{}'; {}".format(work, options))
	try:
		return session.line_after(typed, keys=keys)
	finally:
		session.close()


def history_of(*commands):
	return ['{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(1790000000 + number, command) for number, command in enumerate(commands)]


@pytest.mark.parametrize('typed, history, expected', [
	# mssh's own words in a quoted command, from history alone (the command has no completion)
	('mssh h "zzcmd al', ['zzcmd alpha'], ['mssh', 'h', 'zzcmd alpha']),
	("mssh h 'zzcmd al", ['zzcmd alpha'], ['mssh', 'h', 'zzcmd alpha']),
	# a ~ typed stays as typed (ble.sh expands it here before the glue sees it), the history's path completes
	('mssh h cat ~/zzn', ['cat ~/zznotes.txt'], ['mssh', 'h', 'cat', '~/zznotes.txt']),
	# a backslash or a quote in a word before the current one no longer makes the current one a command name (6.39 read
	# ble.sh's requoted 'zz a' as a quoted word and completed the command alias)
	('mssh h fakecmd zz\\ a al', [], ['mssh', 'h', 'fakecmd', 'zz a', 'alpha']),
])
def test_blesh_tab_reads_the_line_as_typed(tmp_path, typed, history, expected):
	assert words(blesh_line(tmp_path, typed, history=history_of(*history))) == expected


def test_blesh_tab_completes_a_quoted_command_that_holds_a_equals_sign(tmp_path):
	# ble.sh splits no word inside the quote, the glue sends it whole
	line = blesh_line(tmp_path, 'mssh h "zzsvc x=al', options='complete -W x=alpha zzsvc')
	assert words(line) == ['mssh', 'h', 'zzsvc x=alpha']


def test_blesh_tab_still_completes_a_local_file_name_with_a_space_in_a_remote_command(tmp_path):
	# ble.sh's own file names (6.39 did this too, through them)
	assert blesh_line(tmp_path, 'mssh h cat zzmy\\ f', files=['zzmy file']) == 'mssh h cat zzmy\\ file '
