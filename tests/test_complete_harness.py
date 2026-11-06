'''The pty session the autocomplete tests drive shells with.'''
import sys
import time

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
