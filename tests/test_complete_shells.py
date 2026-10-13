import os
import re
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, bash_session, build_index, fish_complete, make_home,
	require_shell, zsh_session)

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


def test_fish_completes(setup):
	env, home = setup
	glue = glue_file(home, 'fish')
	assert fish_complete(env, glue, 'mssh gp') == [('gpu[01-16]', 'used before')]
	assert fish_complete(env, glue, 'mssh gpu[01-16] "nvid')[0] == ('nvidia-smi', '')
	assert fish_complete(env, glue, 'mssh -u r') == [('root', 'used before')]
	assert fish_complete(env, glue, 'mssh h fakecmd al') == [('alpha', '')]
	assert fish_complete(env, glue, 'mssh h "date; fakecmd al') == [('date; fakecmd alpha', '')]


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
	assert messages[-2:] == ['kept the mssh line editor on (to turn it off: mssh --completion uninstall bash, then install bash)', '{} already loads it'.format(rc)]
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


def test_completion_command_takes_the_editor_word(monkeypatch):
	calls = []
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
	assert sorted(left) == sorted([str(home / '.bashrc'), str(home / '.zshrc'), str(home / '.mssh_history')])


def test_uninstall_deletes_an_rc_file_it_created(tmp_path):
	env, home = make_home(tmp_path)
	mc.install('zsh', home=str(home), environ=env)
	assert (home / '.zshrc').exists()
	mc.uninstall('zsh', home=str(home), environ=env)
	assert not (home / '.zshrc').exists()


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
