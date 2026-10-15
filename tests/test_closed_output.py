'''
mssh started with stdout or stderr closed (>&-, 2>&-): Python gives it None for the stream. What would
go there goes nowhere, as print does then, instead of a traceback (stdout) or into stdout (stderr).
'''
import json
import os
import subprocess
import sys

import pytest

from conftest import MULTISSH3_PY, PACKAGE_ROOT

FAKE_SSH = '#!/bin/sh\necho fake-ssh-output\n'


@pytest.fixture
def env(tmp_path):
	fake_ssh = tmp_path / 'fake-ssh'
	fake_ssh.write_text(FAKE_SSH)
	fake_ssh.chmod(0o755)
	(tmp_path / '.multiSSH3.config.json').write_text(json.dumps({'_sshPath': str(fake_ssh)}))
	runtime = tmp_path / 'run'
	runtime.mkdir(mode=0o700)
	return dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime), TERM='dumb')


def _run(env, closed, module, *args):
	'''Run module with the descriptor closed (1 or 2); what the other one gets, and the exit status.'''
	command = [sys.executable, '-I', str(module)] + list(args)
	kept = subprocess.PIPE
	process = subprocess.run(['sh', '-c', 'exec "$@" {}>&-'.format(closed), 'sh'] + command,
		stdout=kept if closed == 2 else None, stderr=kept if closed == 1 else None,
		stdin=subprocess.DEVNULL, env=env, timeout=60, cwd=str(PACKAGE_ROOT.parent))
	other = process.stderr if closed == 1 else process.stdout
	return other.decode('utf-8', 'replace'), process.returncode


@pytest.mark.parametrize('args', [['-V'], ['-h'], ['--completion', 'bash'],
	['--no_history', '-nw', '127.0.0.1', 'true'], ['--no_history', '-nw', '-j', '127.0.0.1', 'true']])
def test_mssh_with_stdout_closed(env, args):
	err, status = _run(env, 1, MULTISSH3_PY, *args)

	assert 'Traceback' not in err and status == 0, err


def test_mssh_with_stderr_closed_keeps_its_messages_out_of_stdout(env):
	out, status = _run(env, 2, MULTISSH3_PY, '--no_history', '-nw', '127.0.0.1', 'true')

	assert 'fake-ssh-output' in out
	# the echoed command line and the summary are stderr's
	assert '> ' not in out and 'Complete' not in out
	assert status == 0, out


@pytest.mark.parametrize('closed', [1, 2])
def test_mssh_complete_with_a_stream_closed(env, closed):
	text, status = _run(env, closed, PACKAGE_ROOT / 'mssh_complete.py', '-V')

	assert 'Traceback' not in text and status == 0, text
