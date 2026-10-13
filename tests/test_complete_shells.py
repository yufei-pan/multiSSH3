import errno
import json
import os
import re
import stat
import subprocess
import sys
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, REPO, bash_session, build_index, fish_complete, make_home,
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
	assert sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history']


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
	assert rc.read_text() == before and sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history']


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
