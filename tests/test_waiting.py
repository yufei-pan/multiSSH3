"""
While commands run, mssh waits without polling: a host's monitor wakes when the command's output ends
(and ten times a second to check -t and Ctrl C), the threads forwarding typed lines wake when a line is
typed or the command stops, and the main thread wakes when a worker ends. Polling each command a
hundred times a second cost 0.44 CPU cores per 1000 waiting hosts, 1.5 cores with the TUI.
Real processes (sleep) stand in for ssh.
"""
import io
import subprocess
import sys
import threading
import time

import pytest

import multiSSH3

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="sh and sleep")


def _real_command(monkeypatch, argv):
	"""Popen runs argv whatever mssh asks for; returns the list of poll() calls made on it."""
	real_popen = subprocess.Popen
	polls = []

	class Counted(real_popen):
		def poll(self):
			polls.append(threading.current_thread().ident)
			return super().poll()

	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "/usr/bin/ssh", "sh": "/bin/sh"})
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda command, **kwargs: Counted(argv, **kwargs))
	return polls


def test_a_running_command_is_not_polled_a_hundred_times_a_second(fake_host, monkeypatch):
	polls = _real_command(monkeypatch, ["sleep", "1"])
	host = fake_host("mock-a", command="sleep 1")
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), 0, None)

	assert host.returncode == 0
	assert time.monotonic() - started < 1.5
	# about ten checks a second (-t, Ctrl C), and a few once its output ended: it was about 130
	assert len(polls) < 40


def test_a_command_that_ends_is_noticed_at_once(fake_host, monkeypatch):
	_real_command(monkeypatch, ["sh", "-c", "sleep 0.3; echo done"])
	host = fake_host("mock-a", command="sleep 0.3")
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), 0, None)

	assert host.returncode == 0 and host.stdout == ["done"]
	assert time.monotonic() - started < 0.6


def test_a_command_that_closes_its_output_and_runs_on_is_still_waited_for(fake_host, monkeypatch):
	# its output ends long before it does: the monitor keeps checking it
	_real_command(monkeypatch, ["sh", "-c", "exec >/dev/null 2>&1; sleep 0.5"])
	host = fake_host("mock-a", command="x")
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), 0, None)

	assert host.returncode == 0
	assert 0.5 <= time.monotonic() - started < 0.9


def test_a_silent_command_still_times_out(fake_host, monkeypatch):
	_real_command(monkeypatch, ["sleep", "5"])
	host = fake_host("mock-a", command="sleep 5")
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), 1, None)

	assert host.returncode == 124
	assert time.monotonic() - started < 2


def test_ctrl_c_stops_a_running_command_promptly(fake_host, monkeypatch):
	_real_command(monkeypatch, ["sleep", "5"])
	monkeypatch.setattr(multiSSH3, "_emo", False)
	host = fake_host("mock-a", command="sleep 5")
	threading.Timer(0.3, lambda: setattr(multiSSH3, "_emo", True)).start()
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), 0, None)

	assert host.returncode == 130
	assert time.monotonic() - started < 1


class _Stream(io.BytesIO):
	def flush(self):
		pass


@pytest.fixture
def typing(monkeypatch, fake_host):
	"""A stdin writer thread for a host while the TUI runs; returns (host, stream, stop_event, thread)."""
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	host = fake_host("mock-a", command="cat")
	host.interactive_stdin = True
	stream = _Stream()
	stop_event = threading.Event()
	sleeps = []
	real_sleep = time.sleep
	writer = None

	def counted_sleep(seconds):
		if writer is not None and threading.current_thread() is writer:
			sleeps.append(seconds)
		real_sleep(seconds)
	monkeypatch.setattr(multiSSH3.time, "sleep", counted_sleep)
	writer = threading.Thread(target=multiSSH3.__handle_writing_stream, args=(stream, stop_event, host), daemon=True)
	writer.start()
	yield host, stream, stop_event, writer, sleeps
	stop_event.set()
	multiSSH3._typed_lines_changed_notify()
	writer.join(1)


def test_a_typed_line_reaches_the_command_without_polling(typing):
	host, stream, stop_event, writer, sleeps = typing
	time.sleep(0.3)
	# the TUI: Enter ends the line
	multiSSH3.__keyPressesIn[-1].extend("ls\n")
	multiSSH3.__keyPressesIn.append([])
	multiSSH3._typed_lines_changed_notify()
	deadline = time.monotonic() + 1
	while stream.getvalue() != b"ls\n" and time.monotonic() < deadline:
		time.sleep(0.005)

	assert stream.getvalue() == b"ls\n"
	assert time.monotonic() - deadline < -0.9
	assert host.stdout == ["> ls↵"]
	# it slept a hundred times a second waiting for the line
	assert sleeps == []


def test_the_typed_line_writer_ends_at_once_when_its_command_ends(typing):
	host, stream, stop_event, writer, sleeps = typing
	time.sleep(0.1)
	started = time.monotonic()
	stop_event.set()
	multiSSH3._typed_lines_changed_notify()
	writer.join(1)

	assert not writer.is_alive()
	assert time.monotonic() - started < 0.1


def test_the_main_thread_waits_for_the_hosts_without_polling(monkeypatch):
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: "/dev/null")
	_real_command(monkeypatch, ["sleep", "0.5"])
	main = threading.current_thread()
	sleeps = []
	real_sleep = time.sleep

	def counted_sleep(seconds):
		if threading.current_thread() is main:
			sleeps.append(seconds)
		real_sleep(seconds)
	monkeypatch.setattr(multiSSH3.time, "sleep", counted_sleep)
	started = time.monotonic()

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-[a-c]", commands=["sleep"], no_watch=True, quiet=True,
		no_history=True, called=True, will_update_unreachable_hosts=False)

	assert [host.returncode for host in hosts] == [0, 0, 0]
	assert time.monotonic() - started < 1
	# it slept about every 10 ms, 50 times here
	assert len(sleeps) < 5


class _CountedWake(threading.Event):
	"""A writer's wake event counting the times it woke."""
	def __init__(self):
		super().__init__()
		self.wakes = 0

	def wait(self, timeout=None):
		woke = super().wait(timeout)
		self.wakes += woke
		return woke


def test_a_command_stopping_wakes_only_its_own_typed_line_writer(monkeypatch, fake_host):
	# each command's end woke every writer waiting: thousands of hosts in the TUI then spent most of
	# their time fighting over one lock (20 to 45 s instead of 7.5 for 4000 hosts)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	writers = []
	for number in range(50):
		host = fake_host("mock-%d" % number, command="cat")
		host.interactive_stdin = True
		stop_event, wake = threading.Event(), _CountedWake()
		thread = threading.Thread(target=multiSSH3.__handle_writing_stream, args=(_Stream(), stop_event, host, wake), daemon=True)
		thread.start()
		writers.append((stop_event, wake, thread))
	time.sleep(0.2)
	stop_event, wake, thread = writers[0]

	# as the monitor stops its command
	stop_event.set()
	wake.set()
	thread.join(1)
	time.sleep(0.1)

	assert not thread.is_alive()
	assert sum(other_wake.wakes for _, other_wake, _ in writers[1:]) == 0
	# a typed line wakes them all
	multiSSH3.__keyPressesIn[-1].extend("ls\n")
	multiSSH3.__keyPressesIn.append([])
	multiSSH3._typed_lines_changed_notify()
	time.sleep(0.2)
	assert all(other_wake.wakes >= 1 for _, other_wake, _ in writers[1:])
	for stop_event, wake, thread in writers:
		stop_event.set()
		wake.set()
		thread.join(1)
