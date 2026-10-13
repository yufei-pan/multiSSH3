'''A terminal that is very narrow or tells no size (0 columns): the results still print.'''
import json
import os
import select
import signal
import subprocess
import sys
import time

import pytest

import multiSSH3

PACKAGE_ROOT = os.path.dirname(os.path.abspath(multiSSH3.__file__))
MULTISSH3_PY = os.path.join(PACKAGE_ROOT, 'multiSSH3.py')

# a fake ssh: skips its options up to --, then the host, and runs the command here with sh
FAKE_SSH = '''#!/bin/sh
echo "$@" >> "$0.log"
while [ $# -gt 0 ]; do
	case "$1" in
		--) shift; break;;
		*) shift;;
	esac
done
shift
exec sh -c "$*"
'''


@pytest.mark.parametrize('reported, environ, expected', [
	((0, 0), {}, (120, 30)),
	((0, 0), {'COLUMNS': '100', 'LINES': '40'}, (100, 40)),
	((0, 40), {}, (120, 40)),
	((200, 0), {'LINES': '50'}, (200, 50)),
	((0, 0), {'COLUMNS': '0', 'LINES': '-3'}, (120, 30)),
	((0, 0), {'COLUMNS': 'wide', 'LINES': ''}, (120, 30)),
	# a size the terminal knows wins, as before
	((200, 40), {'COLUMNS': '100', 'LINES': '10'}, (200, 40)),
])
def test_get_terminal_size_takes_a_reported_zero_as_unknown(monkeypatch, reported, environ, expected):
	# a pty nobody set a size on (script without a terminal, some CI runners) reports 0x0
	monkeypatch.setattr(os, 'get_terminal_size', lambda *args: os.terminal_size(reported))
	monkeypatch.delenv('COLUMNS', raising=False)
	monkeypatch.delenv('LINES', raising=False)
	for name, value in environ.items():
		monkeypatch.setenv(name, value)

	assert tuple(multiSSH3.get_terminal_size()) == expected


def _sizeless_pty():
	pty = pytest.importorskip('pty')
	master, slave = pty.openpty()
	import fcntl
	import struct
	import termios
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
	return master, slave


@pytest.mark.parametrize('stdout_is_the_pty', [True, False], ids=['stdout', 'stdin'])
def test_get_terminal_size_of_a_pty_without_a_size(stdout_is_the_pty):
	# stdout the pty: os.get_terminal_size(); stdout a pipe (mssh ... | less): the TIOCGWINSZ of stdin
	master, slave = _sizeless_pty()
	env = dict(os.environ)
	env.pop('COLUMNS', None)
	env.pop('LINES', None)
	code = 'import sys, multiSSH3; sys.stderr.write(" ".join(map(str, multiSSH3.get_terminal_size()[:2])))'
	try:
		result = subprocess.run([sys.executable, '-c', code], stdin=slave, stdout=slave if stdout_is_the_pty else subprocess.PIPE,
			stderr=subprocess.PIPE, cwd=PACKAGE_ROOT, env=env, universal_newlines=True, timeout=60)
	finally:
		os.close(slave)
		os.close(master)

	assert result.stderr.split() == ['120', '30']


def _host(name, stdout, returncode=0, command='echo one two three four five six seven eight nine ten'):
	host = multiSSH3.Host(name=name, command=command)
	host.stdout = list(stdout)
	host.returncode = returncode
	return host


def _hosts():
	'''Hosts whose output merges with a difference shown, a host on its own, and one with stderr.'''
	common = ['line {} of what every host printed'.format(number) for number in range(12)]
	hosts = [_host('node{}'.format(number), common + ['node{} differs here'.format(number)]) for number in range(1, 4)]
	hosts.append(_host('a-host-with-a-rather-long-name.example', ['its own output'], returncode=1))
	hosts[-1].stderr = ['something failed']
	return hosts


def _plain(monkeypatch):
	monkeypatch.setattr(multiSSH3, 'getIP', lambda hostname, local=False: hostname)
	monkeypatch.setattr(multiSSH3, 'get_terminal_color_capability', lambda: 'None')


def _output(monkeypatch, columns, **kwargs):
	_plain(monkeypatch)
	monkeypatch.setattr(multiSSH3, 'get_terminal_size', lambda: os.terminal_size((columns, 24)))
	typed = [list('a line typed into the curses display\n'), list('one more')]
	return multiSSH3.generate_output(_hosts(), keyPressesIn=typed, **kwargs)


@pytest.mark.parametrize('columns', [0, 1, 3, 10, 19])
def test_a_terminal_narrower_than_20_columns_is_laid_out_as_20(monkeypatch, columns):
	# 0 and 1 column raised ValueError in textwrap; 3 cut host names up a character a line
	assert _output(monkeypatch, columns) == _output(monkeypatch, 20)


def _rules(output):
	return {line for line in output.split('\n') if line.startswith('─')}


def test_a_wider_terminal_still_sets_the_layout(monkeypatch):
	assert _rules(_output(monkeypatch, 20)) == {'─' * 20}
	assert _rules(_output(monkeypatch, 30)) == {'─' * 30}
	# on a wide terminal as wide as the output needs: its longest host name (38 columns) and 5
	assert _rules(_output(monkeypatch, 80)) == {'─' * 43}


@pytest.mark.parametrize('columns', [0, 1, 2, 3])
def test_get_host_raw_output_lays_out_at_least_20_columns(monkeypatch, columns):
	# the width it returns is the one mergeOutputs wraps host names at: given 2, it never returned, filling memory
	_plain(monkeypatch)
	outputs, _, _, _, line_length = multiSSH3.get_host_raw_output(_hosts(), columns)

	assert line_length == 20
	block = outputs['node1']
	command_lines = block[1:block.index('▓ STDOUT:')]
	assert command_lines == [' echo one two three', '- four five six ', '-seven eight nine ', '-ten']


@pytest.mark.parametrize('mode', ['greppable', 'usejson'])
@pytest.mark.parametrize('columns', [0, 1, 2])
def test_greppable_and_json_output_do_not_depend_on_the_terminal(monkeypatch, mode, columns):
	assert _output(monkeypatch, columns, **{mode: True}) == _output(monkeypatch, 80, **{mode: True})


def _run_in_pty(argv, rows, columns, env, deadline=60):
	'''Run argv on a pty of rows x columns (stdin, stdout and stderr): (output, exit status).'''
	pty = pytest.importorskip('pty')
	import fcntl
	import struct
	import termios
	master, slave = pty.openpty()
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
	# a regression that loops while it allocates (textwrap did at 2 columns) must not take the machine's memory
	argv = ['/bin/sh', '-c', 'ulimit -v 2097152 2>/dev/null; exec "$0" "$@"'] + list(argv)
	process = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=env['HOME'], close_fds=True)
	os.close(slave)
	output = b''
	end = time.monotonic() + deadline
	exited = False
	try:
		while time.monotonic() < end:
			ready, _, _ = select.select([master], [], [], 0.1)
			if ready:
				try:
					data = os.read(master, 65536)
				except OSError:
					# EIO: every process holding the pty has closed it
					data = b''
				if not data:
					break
				output += data
			elif exited:
				# what it wrote before it exited has been read
				break
			else:
				exited = process.poll() is not None
		else:
			process.send_signal(signal.SIGKILL)
	finally:
		os.close(master)
	return output.decode('utf-8', 'replace'), process.wait(timeout=10)


def _scratch_home(tmp_path):
	'''An environment whose HOME holds a config that makes mssh run a fake ssh, and a hosts file.'''
	fake_ssh = tmp_path / 'fake-ssh'
	fake_ssh.write_text(FAKE_SSH)
	fake_ssh.chmod(0o755)
	(tmp_path / '.multiSSH3.config.json').write_text(json.dumps({'_sshPath': str(fake_ssh)}))
	(tmp_path / 'hosts').write_text('127.0.0.1\n')
	runtime = tmp_path / 'run'
	runtime.mkdir(mode=0o700)
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime), TERM='dumb')
	env.pop('COLUMNS', None)
	env.pop('LINES', None)
	return env, str(fake_ssh) + '.log'


@pytest.mark.parametrize('rows, columns', [(0, 0), (24, 0), (24, 1), (24, 2)])
def test_mssh_prints_its_results_whatever_width_the_terminal_reports(tmp_path, rows, columns):
	# script -qc 'mssh ...' /dev/null without a terminal gives mssh a 0x0 pty: the commands ran, then printing
	# them failed (ValueError: invalid width -1). 1 column failed too, and at 2 printing never ended
	env, fake_ssh_log = _scratch_home(tmp_path)
	argv = [sys.executable, MULTISSH3_PY, '-ef', '/dev/null', '--host_file', env['HOME'] + '/hosts', '127.0.0.1', 'echo narrow-ok']

	output, status = _run_in_pty(argv, rows, columns, env)

	assert 'Traceback' not in output
	assert ' narrow-ok' in output.splitlines()
	assert status == 0
	with open(fake_ssh_log) as log:
		assert '127.0.0.1 echo narrow-ok' in log.read()
