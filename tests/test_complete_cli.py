'''The command lines of mssh-complete and mssh --completion: what they print, and how they end.'''
import os
import subprocess
import sys

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, REPO, make_home, require_shell

MSSH = [sys.executable, '-I', str(REPO / 'multiSSH3.py')]
# what a shell reports for a command SIGPIPE ended (128 + 13), as for seq or cat piped into head
SIGPIPE_STATUS = 141


def _closed_pipe():
	'''A pipe nobody reads: its write end, the read end already closed (like head that has exited).'''
	read_fd, write_fd = os.pipe()
	os.close(read_fd)
	return write_fd


def _run_into_closed_pipe(tmp_path, argv, stderr_too=False):
	env, _ = make_home(tmp_path)
	write_fd = _closed_pipe()
	try:
		return subprocess.run(argv, env=env, cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=write_fd,
			stderr=write_fd if stderr_too else subprocess.PIPE, timeout=60)
	finally:
		os.close(write_fd)


PRINTING = [
	pytest.param(ENGINE + ['glue', 'bash'], id='glue-bash'),
	pytest.param(ENGINE + ['glue', 'zsh'], id='glue-zsh'),
	# the fish glue fits in stdout's buffer: it fails in the flush at exit, not in the write
	pytest.param(ENGINE + ['glue', 'fish'], id='glue-fish'),
	pytest.param(MSSH + ['--completion', 'bash'], id='mssh-bash'),
	pytest.param(MSSH + ['--completion', 'zsh'], id='mssh-zsh'),
	pytest.param(MSSH + ['--completion', 'fish'], id='mssh-fish'),
	pytest.param(ENGINE + ['install', 'bash'], id='install'),
	pytest.param(MSSH + ['--completion', 'install', 'zsh'], id='mssh-install'),
	pytest.param(ENGINE + ['uninstall', 'bash'], id='uninstall'),
	pytest.param(ENGINE + ['-V'], id='version'),
	pytest.param(ENGINE + ['eval', '--help'], id='eval-help'),
	pytest.param(ENGINE + ['edit', '--help'], id='edit-help'),
	pytest.param(ENGINE + ['eval', '--synthetic', '--limit', '5'], id='eval-report'),
	pytest.param(ENGINE + ['rebuild'], id='rebuild'),
]


@pytest.mark.parametrize('argv', PRINTING)
def test_a_reader_that_exits_early_ends_the_command_quietly(tmp_path, argv):
	# mssh --completion bash | head -3: no traceback or "Exception ignored", and SIGPIPE's status, as other tools end
	result = _run_into_closed_pipe(tmp_path, argv)

	assert result.stderr.decode('utf-8', 'replace') == ''
	assert result.returncode == SIGPIPE_STATUS


@pytest.mark.parametrize('argv', [
	pytest.param(ENGINE + ['glue', 'bash'], id='glue-bash'),
	pytest.param(ENGINE + ['-V'], id='version'),
	pytest.param(MSSH + ['--completion', 'fish'], id='mssh-fish'),
])
def test_a_reader_of_stdout_and_stderr_that_exits_early(tmp_path, argv):
	# ... 2>&1 | head: the flush at exit must not fail on stderr either (Python would exit 120)
	assert _run_into_closed_pipe(tmp_path, argv, stderr_too=True).returncode == SIGPIPE_STATUS


@pytest.mark.parametrize('argv', [
	pytest.param(ENGINE + ['glue', 'fish'], id='glue-fish'),
	pytest.param(MSSH + ['--completion', 'fish'], id='mssh-fish'),
	pytest.param(ENGINE + ['-V'], id='version'),
])
def test_a_glue_that_could_not_be_written_fails(tmp_path, argv):
	# mssh --completion fish > file on a full disk: the glue fits stdout's buffer, and its failed
	# write in the flush at exit was lost (Python 3.6 and 3.13 exited 0, the file empty)
	if not os.path.exists('/dev/full'):
		pytest.skip('no /dev/full here')
	env, _ = make_home(tmp_path)
	with open('/dev/full', 'w') as full:
		result = subprocess.run(argv, env=env, cwd=str(tmp_path), stdout=full, stderr=subprocess.PIPE, timeout=60)

	assert result.returncode not in (0, SIGPIPE_STATUS)
	assert 'No space left on device' in result.stderr.decode('utf-8', 'replace')


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_the_glue_is_printed_whole_when_it_is_read(tmp_path, shell):
	# what eval "$(mssh --completion bash)" and sourcing it read
	env, _ = make_home(tmp_path)
	expected = (mc.render_glue(shell) + (mc.render_glue('fish-keys') if shell == 'fish' else '')).encode()
	for argv in (ENGINE + ['glue', shell], MSSH + ['--completion', shell]):
		result = subprocess.run(argv, env=env, cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

		assert (result.returncode, result.stderr.decode('utf-8', 'replace')) == (0, '')
		assert result.stdout == expected


def test_bash_evaluates_the_printed_glue(tmp_path):
	bash = require_shell('bash')
	env, _ = make_home(tmp_path)
	script = 'eval "$("$@" --completion bash)" && complete -p mssh'
	result = subprocess.run([bash, '--norc', '--noprofile', '-c', script, 'bash'] + MSSH, env=env, cwd=str(tmp_path),
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

	assert result.returncode == 0, result.stderr
	assert b'-F _mssh_complete mssh' in result.stdout


def _fake_fish(tmp_path, monkeypatch, version_line, stream='stdout'):
	'''
	A fish first on PATH: --version prints version_line on stream (old releases wrote it to stderr).
	With -c, it first loads "the operator's config", which greets and leaves a marker, as a config.fish
	may. Returns the marker's path.
	'''
	bin_dir = tmp_path / 'bin'
	bin_dir.mkdir()
	marker = tmp_path / 'config-ran'
	version = version_line.rsplit(' ', 1)[-1]
	fish = bin_dir / 'fish'
	fish.write_text('#!/bin/sh\n'
		'if [ "$1" = --version ]; then printf "%s\\n" "{line}" {redirect}; exit 0; fi\n'
		'echo "Welcome to fish, the friendly interactive shell"; : > "{marker}"\n'
		'[ "$1" = -c ] && echo "{version}"\n'.format(line=version_line, redirect='>&2' if stream == 'stderr' else '',
			marker=marker, version=version))
	fish.chmod(0o755)
	monkeypatch.setenv('PATH', str(bin_dir) + os.pathsep + os.environ.get('PATH', ''))
	return marker


def test_the_fish_version_is_read_without_the_operators_fish_config(tmp_path, monkeypatch):
	# fish -c loads config.fish and conf.d, which may print (here: a greeting before the version), be slow
	# or do things; fish --version reads no configuration
	marker = _fake_fish(tmp_path, monkeypatch, 'fish, version 3.3.1')

	assert mc._fish_major() == 3
	assert not marker.exists()


@pytest.mark.parametrize('line, stream, major', [
	('fish, version 3.3.1', 'stdout', 3),
	('fish, version 4.0.2', 'stdout', 4),
	('fish, version 3.6.0-1234-gabcdef0', 'stdout', 3),
	# fish translates the line
	('fish, Version 3.7.1', 'stdout', 3),
	# old releases wrote it to stderr
	('fish, version 2.7.1', 'stderr', 2),
	('fish: unknown option --version', 'stderr', None),
])
def test_the_fish_major_version_is_read_from_what_fish_prints(tmp_path, monkeypatch, line, stream, major):
	_fake_fish(tmp_path, monkeypatch, line, stream)

	assert mc._fish_major() == major


def test_install_refuses_fish_2(tmp_path, monkeypatch):
	_fake_fish(tmp_path, monkeypatch, 'fish, version 2.7.1', 'stderr')
	env, home = make_home(tmp_path)

	code, messages = mc.install('fish', home=str(home), environ=env)

	assert (code, messages) == (1, ['fish 2 is too old for mssh autocomplete: it needs fish 3.0 or later'])
	assert not (home / '.config').exists()


def test_a_real_fish_version_is_read_without_its_config(tmp_path, monkeypatch):
	fish = require_shell('fish')
	env, home = make_home(tmp_path)
	reference = subprocess.run([fish, '-c', 'echo $FISH_VERSION'], env=env, stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE, timeout=30).stdout.decode()
	config = home / '.config' / 'fish'
	(config / 'conf.d').mkdir(parents=True)
	(config / 'config.fish').write_text('echo config says hi\ntouch {}\n'.format(home / 'config-ran'))
	(config / 'conf.d' / 'greet.fish').write_text('touch {}\n'.format(home / 'conf.d-ran'))
	monkeypatch.setenv('HOME', str(home))
	monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)

	assert mc._fish_major() == int(reference.split('.')[0])
	assert not (home / 'config-ran').exists() and not (home / 'conf.d-ran').exists()


@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_a_shell_named_without_autocomplete_is_named_back(capsys, action):
	# not "cannot tell which shell to set up, name it": it was named
	assert mc.completion_command([action, 'tcsh']) == 2

	error = capsys.readouterr().err
	assert 'tcsh' in error and 'bash, zsh' in error and 'cannot tell' not in error


def test_a_shell_that_cannot_be_told_is_asked_for(capsys, monkeypatch):
	monkeypatch.setattr(mc, 'detect_shell', lambda: None)

	assert mc.completion_command(['install']) == 2
	assert 'cannot tell which shell to set up' in capsys.readouterr().err


# Python 3.6 in the C locale (cron, containers, ssh without LANG on CentOS 7 / RHEL 8): os.environ holds
# ASCII names only, and looking up a name with another character raised UnicodeEncodeError. Later
# Pythons behave so with -X utf8=0.
C_LOCALE_PYTHON = [sys.executable, '-I', '-X', 'utf8=0']


def _c_locale_env(env):
	env = dict(env, LC_ALL='C', LANG='C')
	encoding = subprocess.run(C_LOCALE_PYTHON + ['-c', 'import sys; print(sys.getfilesystemencoding())'], env=env,
		stdout=subprocess.PIPE, timeout=30).stdout.decode().strip()
	if encoding not in ('ascii', 'ANSI_X3.4-1968'):
		pytest.skip('the C locale here encodes file names as {}'.format(encoding))
	return env


def test_a_non_ascii_word_in_the_history_does_not_stop_the_index_build(tmp_path):
	env, _ = make_home(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\th\u00e9llo\t"uptime"'])

	result = subprocess.run(C_LOCALE_PYTHON + [str(REPO / 'mssh_complete.py'), 'rebuild'], env=_c_locale_env(env),
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

	assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')


_HOST_SCRIPT = '''
import sys, time
sys.path.insert(0, {repo!r})
import multiSSH3, mssh_complete as mc
host = 'h\\u00e9llo'
print(ascii(multiSSH3.expand_hostnames_local([host])))
# the warnings for a line naming it, once the prober has found it invalid
mc.spawn_probe = lambda directory: True
engine = mc.Engine(mc.spec_from_parser(multiSSH3.get_parser()), [])
engine.directory = {directory!r}
now = time.time()
mc.write_host_states(engine.directory, {{host: mc.HostState('invalid', now)}})
found, _ = engine.diagnose(mc.Request('bash', 'mssh ' + host + ' uptime', '', ''), now=now)
print(ascii([(item.kind, item.message) for item in found]))
'''


def test_a_host_name_the_locale_cannot_encode_is_no_variable(tmp_path):
	env, _ = make_home(tmp_path)
	directory = tmp_path / 'states'
	directory.mkdir(mode=0o700)
	script = tmp_path / 'hosts.py'
	script.write_text(_HOST_SCRIPT.format(repo=str(REPO), directory=str(directory)))

	result = subprocess.run(C_LOCALE_PYTHON + [str(script)], env=_c_locale_env(env), stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, timeout=60)

	assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')
	assert result.stdout.decode().splitlines() == ["(['h\\xe9llo'], ['h\\xe9llo'])", "[('unknown', 'h\\xe9llo: unknown host')]"]
