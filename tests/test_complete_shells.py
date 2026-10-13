import os
import re
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, bash_session, build_index, fish_complete, fish_session, make_home,
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
