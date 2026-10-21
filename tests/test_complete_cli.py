'''The command lines of mssh-complete and mssh --completion: what they print, and how they end.'''
import os
import shutil
import subprocess
import sys

import pytest

import multiSSH3
import mssh_complete as mc
from complete_shell_harness import ENGINE, REPO, build_index, make_home, require_shell

# -I as the engine is run, but mssh's entry point heeds PYTHONDONTWRITEBYTECODE, which -I drops: the glue it
# prints carries -B then (module_command)
MSSH = [sys.executable, '-I'] + (['-B'] if sys.dont_write_bytecode else []) + [str(REPO / 'multiSSH3.py')]
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


_EVAL_SCRIPT = '''
import sys
sys.path.insert(0, {repo!r})
import multiSSH3, mssh_complete as mc
# no DNS: every name is one the prober would reject; nothing starts in the background
multiSSH3.host_validity = lambda name, timeout=2.0: 'invalid'
mc.spawn_probe = mc.spawn_rebuild = lambda directory: False
sys.exit(mc.main(['eval', '--diagnostics', {history!r}]))
'''


@pytest.mark.parametrize('host, printed, c_locale', [
	# a name the C locale cannot print (Python 3.6): a backslash escape
	(b'h\xc3\xa9llo', b'h\\xe9llo', True),
	# bytes that are not UTF-8, which stdout's strict UTF-8 (en_US.UTF-8) could not print: the bytes themselves
	(b'h\xffllo', b'h\xffllo', False),
])
def test_the_diagnostics_report_names_a_host_stdout_cannot_print(tmp_path, host, printed, c_locale):
	env, home = make_home(tmp_path)
	(home / '.mssh_history').write_bytes(b'1790000000\t/x/multiSSH3.py\t-su\t' + host + b'\t"uptime"\n')
	# built now: the report would wait for it
	build_index(env)
	script = tmp_path / 'eval.py'
	script.write_text(_EVAL_SCRIPT.format(repo=str(REPO), history=str(home / '.mssh_history')))

	result = subprocess.run((C_LOCALE_PYTHON if c_locale else [sys.executable, '-I']) + [str(script)],
		env=_c_locale_env(env) if c_locale else dict(env, LC_ALL='en_US.UTF-8'), stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, timeout=60)

	assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')
	assert b'    ' + printed + b'  1 line' in result.stdout


def test_the_glue_runs_mssh_complete_when_it_is_on_path(tmp_path, monkeypatch):
	monkeypatch.setenv('PATH', str(tmp_path))
	assert mc.engine_command() == mc.module_command()
	(tmp_path / 'mssh-complete').write_text('#!/bin/sh\n')
	(tmp_path / 'mssh-complete').chmod(0o755)
	assert mc.engine_command() == ['mssh-complete']


def _engine_copy(tmp_path, name):
	'''mssh_complete.py copied alone into a new directory tmp_path/name (bytes, so as to be any name). Returns its path.'''
	directory = os.path.join(os.fsencode(str(tmp_path)), name)
	os.mkdir(directory)
	path = os.path.join(directory, b'mssh_complete.py')
	shutil.copyfile(os.fsencode(str(REPO / 'mssh_complete.py')), path)
	return os.fsdecode(path)


def _module_command(monkeypatch, path, write_bytecode=True):
	'''module_command(path) made by a python that writes bytecode into __pycache__, or none.'''
	monkeypatch.setattr(sys, 'dont_write_bytecode', not write_bytecode)
	if hasattr(sys, 'pycache_prefix'):
		monkeypatch.setattr(sys, 'pycache_prefix', None)
	return mc.module_command(path)


def _version_from(command, env=None):
	'''
	Run command -V, python saying where it takes each code object from. Returns (status, what it
	printed, where mssh_complete came from each time: 'source' or 'bytecode').
	'''
	result = subprocess.run(command[:1] + ['-v'] + command[1:] + ['-V'], env=env, stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	taken = []
	for line in result.stderr.decode('utf-8', 'replace').splitlines():
		name = line.rstrip("'").rsplit('/', 1)[-1]
		if line.startswith('# code object from ') and name.startswith('mssh_complete.'):
			taken.append('bytecode' if name.endswith('.pyc') else 'source')
	return result.returncode, result.stdout.decode('utf-8', 'replace'), taken


VERSION_LINE = 'mssh-complete {} (protocol {})\n'.format(mc.version, mc.PROTOCOL)


@pytest.mark.parametrize('name, c_locale', [
	(b'lone', False),
	(b'd\xc3\xa9', False),
	# Python 3.6 in the C locale takes the name as ASCII with the other bytes escaped
	(b'd\xc3\xa9', True),
	# bytes that are no UTF-8
	(b'\xff', False),
], ids=['plain', 'non-ascii', 'non-ascii-c-locale', 'not-utf8'])
def test_the_engine_runs_from_its_bytecode_cache(tmp_path, monkeypatch, name, c_locale):
	# python compiles a script anew every time: run as one, the engine was compiled at every TAB
	command = _module_command(monkeypatch, _engine_copy(tmp_path, name))
	env = None
	if c_locale:
		env = _c_locale_env(dict(os.environ))
		command = command[:1] + ['-X', 'utf8=0'] + command[1:]

	assert _version_from(command, env) == (0, VERSION_LINE, ['source'])
	assert _version_from(command, env) == (0, VERSION_LINE, ['bytecode'])


def test_the_engine_writes_no_bytecode_when_its_python_writes_none(tmp_path, monkeypatch):
	# PYTHONDONTWRITEBYTECODE when the glue was made: -I drops it, the glue's -B keeps it
	path = _engine_copy(tmp_path, b'lone')
	command = _module_command(monkeypatch, path, write_bytecode=False)

	assert '-B' in command[:command.index('-c')]
	assert _version_from(command) == (0, VERSION_LINE, ['source'])
	assert not os.path.exists(os.path.join(os.path.dirname(path), '__pycache__'))


def test_the_engine_runs_where_its_bytecode_cannot_be_written(tmp_path, monkeypatch):
	# as in a read-only directory (the shell matrix mounts the repository so): compiled every time, as a script is
	path = _engine_copy(tmp_path, b'lone')
	(tmp_path / 'lone' / '__pycache__').write_text('')
	command = _module_command(monkeypatch, path)

	assert _version_from(command) == (0, VERSION_LINE, ['source'])
	assert _version_from(command) == (0, VERSION_LINE, ['source'])


def test_an_engine_file_that_is_gone_ends_with_status_2(tmp_path):
	# as python ends for a script it cannot open: a picker ending with more than 1 is not there, and Ctrl-R
	# does what it did before
	result = subprocess.run(mc.module_command(str(tmp_path / 'mssh_complete.py')) + ['pick'], stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

	assert (result.returncode, result.stdout) == (2, b'')
	assert b'cannot open file' in result.stderr and b'No such file or directory' in result.stderr


# loads a module from its path, as the two loaders do, so that its own directory is on no sys.path
_LOAD_BY_PATH = '''
import importlib.util, sys
def load(name, path):
	spec = importlib.util.spec_from_file_location(name, path)
	module = importlib.util.module_from_spec(spec)
	sys.modules[name] = module
	spec.loader.exec_module(module)
	return module
'''

_COMPLETION_PATH_SCRIPT = _LOAD_BY_PATH + '''
import contextlib, io, os
here = os.path.dirname(sys.argv[1])
mssh = load('multiSSH3', sys.argv[1])
before = list(sys.path)
with contextlib.redirect_stdout(io.StringIO()) as glue:
	status = mssh._completion_command(['bash'])
print(status, glue.getvalue().startswith('# MSSH_COMPLETE_GLUE '), sys.path == before, sys.modules['mssh_complete'].__file__ == os.path.join(here, 'mssh_complete.py'))
'''

def test_mssh_completion_loads_the_mssh_complete_beside_it_by_path(tmp_path):
	# mssh run where mssh_complete is not importable loads the one beside it from its path, and puts its
	# directory on no sys.path: a file beside it named as a standard module would hide that one from mssh_complete
	for name in ('mssh_complete.py', 'multiSSH3.py'):
		shutil.copyfile(str(REPO / name), str(tmp_path / name))
	result = subprocess.run([sys.executable, '-I', '-B', '-c', _COMPLETION_PATH_SCRIPT, str(tmp_path / 'multiSSH3.py')],
		cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	assert result.stdout.split() == [b'0', b'True', b'True', b'True'], result.stderr.decode('utf-8', 'replace')


_COMPLETION_ALONE_SCRIPT = _LOAD_BY_PATH + '''
mssh = load('multiSSH3', sys.argv[1])
print(mssh._completion_command(['bash']), 'mssh_complete' in sys.modules)
'''

def test_mssh_completion_without_mssh_complete_beside_it_says_so(tmp_path):
	shutil.copyfile(str(REPO / 'multiSSH3.py'), str(tmp_path / 'multiSSH3.py'))
	# -S: no site-packages, so an installed or editable multiSSH3 has no mssh_complete to import here
	result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', _COMPLETION_ALONE_SCRIPT, str(tmp_path / 'multiSSH3.py')],
		cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	assert result.stdout.split() == [b'1', b'False'], result.stderr.decode('utf-8', 'replace')
	assert b'autocomplete needs mssh_complete.py next to ' in result.stderr


_IMPORT_FAILS_SCRIPT = _LOAD_BY_PATH + '''
name, path = sys.argv[1:3]
module = load(name, path)
sys.path[:0] = sys.argv[3:]
try:
	module._completion_command(['bash']) if name == 'multiSSH3' else module._import_mssh()
except BaseException as error:
	print(type(error).__name__, error)
'''


def import_fails(tmp_path, first, other_stub, installed=False):
	"""The failure (class and text) of importing the other module when its stub raises: the stub sits beside first, or
	(installed) in a directory on sys.path with no copy beside first."""
	pair = {'multiSSH3': 'mssh_complete', 'mssh_complete': 'multiSSH3'}
	other = pair[first]
	here = tmp_path / 'here'
	here.mkdir()
	shutil.copyfile(str(REPO / (first + '.py')), str(here / (first + '.py')))
	where = tmp_path / 'installed' if installed else here
	where.mkdir(exist_ok=True)
	(where / (other + '.py')).write_text(other_stub)
	command = [sys.executable, '-I', '-S', '-B', '-c', _IMPORT_FAILS_SCRIPT, first, str(here / (first + '.py'))]
	command += [str(where)] if installed else []
	result = subprocess.run(command, cwd=str(tmp_path), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, timeout=60)
	return result.stdout.decode('utf-8', 'replace').strip(), result.stderr.decode('utf-8', 'replace')


def test_mssh_completion_reports_an_import_error_of_an_installed_mssh_complete_as_it_is(tmp_path):
	# not as the file being missing: it is there, and what it imports is not
	out, err = import_fails(tmp_path, 'multiSSH3', 'import zz_no_such_module\n', installed=True)
	assert out.startswith('ModuleNotFoundError'), (out, err)
	assert 'zz_no_such_module' in out and 'needs mssh_complete.py' not in err


def test_mssh_completion_survives_an_mssh_complete_that_took_itself_out_of_sys_modules(tmp_path):
	out, err = import_fails(tmp_path, 'multiSSH3', 'import sys\ndel sys.modules[__name__]\nraise RuntimeError("boom")\n')
	assert out == 'RuntimeError boom', (out, err)


def test_the_engine_survives_a_multissh3_that_took_itself_out_of_sys_modules(tmp_path):
	out, err = import_fails(tmp_path, 'mssh_complete', 'import sys\ndel sys.modules[__name__]\nraise RuntimeError("boom")\n')
	assert out == 'RuntimeError boom', (out, err)


def test_the_engine_reports_an_import_error_of_an_installed_multissh3_as_it_is(tmp_path):
	# already so before 6.38 (the engine's installed branch never caught it): kept beside mssh's case above
	out, err = import_fails(tmp_path, 'mssh_complete', 'import zz_no_such_module\n', installed=True)
	assert out.startswith('ModuleNotFoundError') and 'zz_no_such_module' in out, (out, err)


def test_the_engine_takes_no_module_from_elsewhere(tmp_path):
	# as isolated as a script run with -I: nothing from the current directory or PYTHONPATH, and its own
	# directory is not put on sys.path (a file there named as a standard module would hide that one,
	# also for multiSSH3's own imports: it imports ipaddress after the engine's imports are done);
	# the index is built with the multiSSH3 beside it
	env, _ = make_home(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\tnode1\t"uptime"'])
	decoys = tmp_path / 'decoys'
	engine = tmp_path / 'engine'
	decoys.mkdir()
	engine.mkdir()
	for name in ('mssh_complete', 'multiSSH3', 'bisect', 'ipaddress'):
		(decoys / (name + '.py')).write_text('raise SystemExit("the decoy {} was imported")\n'.format(name))
	for name in ('bisect', 'ipaddress'):
		shutil.copyfile(str(decoys / (name + '.py')), str(engine / (name + '.py')))
	for name in ('mssh_complete.py', 'multiSSH3.py'):
		shutil.copyfile(str(REPO / name), str(engine / name))
	command = mc.module_command(str(engine / 'mssh_complete.py'))
	env = dict(env, PYTHONPATH=str(decoys))

	built = subprocess.run(command + ['rebuild'], env=env, cwd=str(decoys), stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	answer = subprocess.run(command + ['query'], input=b'MSSHC1\0bash\x005.2\0\0mssh no\0\0no\0', env=env, cwd=str(decoys),
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

	assert built.returncode == 0, built.stderr.decode('utf-8', 'replace')
	assert mc.NsvIndex.load(built.stdout.decode().strip()).header['mssh_version'] == multiSSH3.version
	assert answer.returncode == 0, answer.stderr.decode('utf-8', 'replace')
	assert answer.stdout.startswith(b'MSSHC1\n') and b'node1' in answer.stdout
