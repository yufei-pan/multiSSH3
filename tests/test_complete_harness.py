'''The pty session the autocomplete tests drive shells with.'''
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import complete_shell_harness as harness


@pytest.fixture
def session():
	# a process that stays silent until the test ends
	session = harness.Session([sys.executable, '-c', 'import time; time.sleep(600)'], {})
	yield session
	session.close()


@pytest.fixture
def clock(monkeypatch):
	# a clock moving 0.05 s at each look, so what is measured is the wait the code asked for, not how busy the machine is
	now = [1000.0]

	def monotonic():
		now[0] += 0.05
		return now[0]
	monkeypatch.setattr(harness.time, 'monotonic', monotonic)
	return now


@pytest.mark.parametrize('read', [lambda session: session.read_until(b'never shown', 1.0), lambda session: session.read_for(1.0)], ids=['read_until', 'read_for'])
def test_a_read_waits_the_time_it_is_given_and_no_more(session, clock, read):
	started = clock[0]
	assert read(session) == ''
	assert 1.0 <= clock[0] - started <= 1.2


def test_read_until_stops_at_the_marker():
	# the marker comes once and the process stays: not stopping at it would run to the timeout
	session = harness.Session([sys.executable, '-c', 'print("first", flush=True); import time; time.sleep(600)'], {})
	try:
		started = time.monotonic()
		assert 'first' in session.read_until(b'first', 120.0)
		assert time.monotonic() - started < 120.0
	finally:
		session.close()


def _gone(pid):
	"""Whether the process is no more, or a zombie that only its parent has to reap. Where there is a /proc it says (as Session._busy reads it),
	and elsewhere (macOS) ps does. A ps that cannot tell is no answer: busybox's, on the matrix's bash images, has no -p, printed its usage and
	nothing else, and that was read as "gone", so the test passed with the leak back."""
	if os.path.isdir('/proc/self'):
		try:
			with open('/proc/{}/stat'.format(pid)) as f:
				return f.read().rsplit(')', 1)[1].split()[0] == 'Z'
		except (FileNotFoundError, ProcessLookupError):
			return True
	done = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	state = done.stdout.decode().strip()
	assert state or not done.stderr, 'ps cannot tell whether {} is there: {}'.format(pid, done.stderr.decode(errors='replace').strip())
	return not state or state[0] == 'Z'


def test_a_test_that_ends_without_closing_its_session_leaves_neither_the_shell_nor_the_terminal_reader():
	# the reader holds the terminal's master: while it ran on after its test, a test killed (the time limit, a stopped run) or ended with
	# os._exit left the reader and the shell, which gets no hangup while a master is open, running for ever. The child ends as that test does.
	# (Not python -I: the harness imports pytest, which the matrix's python 3.6 images keep in /usr/local/lib/python3.6/site-packages, a
	# directory that CentOS's python reads only with the user site on, and -I turns that off)
	script = ('import os, sys\nsys.path[:0] = sys.argv[1:]\nimport complete_shell_harness as h\n'
		"session = h.Session([sys.executable, '-c', 'import time; time.sleep(600)'], dict(os.environ))\n"
		'print(session.pid, session._screen.pid, flush=True)\nos._exit(0)\n')
	output = subprocess.run([sys.executable, '-c', script, str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parents[1])], stdout=subprocess.PIPE, timeout=60).stdout
	pids = [int(word) for word in output.split()]
	assert len(pids) == 2, output
	try:
		# (the reader looks once a second; 15 s is for a machine with no CPU to spare)
		end = time.monotonic() + 15
		while not all(_gone(pid) for pid in pids) and time.monotonic() < end:
			time.sleep(0.1)
		assert [pid for pid in pids if not _gone(pid)] == []
	finally:
		for pid in pids:
			try:
				os.kill(pid, signal.SIGKILL)
			except OSError:
				pass
