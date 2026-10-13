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
