'''mssh autocomplete inside ble.sh (Bash Line Editor), which replaces readline and adds suggestions.'''
import re
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, blesh_session, build_index, make_home

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
		assert session.line_after('', keys='') == 'mssh gpu[01-16] uptime'
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
