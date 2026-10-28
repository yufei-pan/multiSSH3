"""What run_command records once the command ended: its readers may still be busy, or a process
the command left in the background may hold its output pipes open."""
import io
import os
import signal
import threading
import time

import pytest

import multiSSH3


class FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
		self.returncode = returncode

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""


class PausingPipe:
	"""A command pipe whose reader stops for a while: after its first output, or before its first read."""
	def __init__(self, pipe, pause, before_first_read=False):
		self.pipe = pipe
		self.pause = pause
		self.before_first_read = before_first_read
		self.paused = False

	def read1(self, size):
		if self.before_first_read and not self.paused:
			self.paused = True
			time.sleep(self.pause)
		data = self.pipe.read1(size)
		if data and not self.paused:
			# holds output the pipe no longer has, as a reader busy with a big chunk under load does
			self.paused = True
			time.sleep(self.pause)
		return data


def watch_readers(monkeypatch, stdout_pause=None, before_first_read=False):
	"""Record when the readers of the command's pipes end; slow the stdout reader down when asked."""
	reader = multiSSH3.__handle_reading_stream
	ended = {}

	def watched(stream, target, host, buffer):
		if isinstance(stream, io.BytesIO):
			# run_command recording leftover output itself, not a reader thread
			return reader(stream, target, host, buffer)
		name = "stdout" if target is host.stdout else "stderr"
		ended[name] = threading.Event()
		if name == "stdout" and stdout_pause:
			stream = PausingPipe(stream, stdout_pause, before_first_read)
		try:
			reader(stream, target, host, buffer)
		finally:
			ended[name].set()

	monkeypatch.setattr(multiSSH3, "__handle_reading_stream", watched)
	return ended


def run_in_shell(fake_host, command):
	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", command, shell=True)
	started = time.monotonic()
	multiSSH3.run_command(host, threading.Semaphore(1), timeout=0)
	return host, time.monotonic() - started


def kill_pid_in(path):
	try:
		os.kill(int(path.read_text().strip()), signal.SIGKILL)
	except (OSError, ValueError):
		pass


def wait_for(predicate, seconds=5):
	deadline = time.monotonic() + seconds
	while not predicate() and time.monotonic() < deadline:
		time.sleep(0.02)
	return predicate()


def test_output_is_complete_when_a_reader_lags_behind_the_exit(fake_host, monkeypatch):
	ended = watch_readers(monkeypatch, stdout_pause=1.5)

	host, _elapsed = run_in_shell(fake_host, "printf 'one\\n'; sleep 0.3; printf 'two\\n'")

	assert host.stdout == ["one", "two"]  # all of it, in order, when run_command returns
	assert ended["stdout"].is_set()  # nothing is appended later
	assert host.returncode == 0


def test_the_stderr_filter_keeps_the_list_the_reader_appends_to(fake_host, monkeypatch):
	host = fake_host("mock-a", "cmd")
	stderr = host.stderr
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen",
		lambda *a, **k: FakeProc(stderr=b"Connection to mock-a closed.\nboom\n", returncode=1))

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert host.stderr is stderr  # a line a late reader appends is not lost in a list nobody looks at
	assert host.stderr == ["boom"]


def test_a_background_process_holding_the_pipes_does_not_hold_up_the_command(fake_host, monkeypatch, tmp_path):
	ended = watch_readers(monkeypatch)
	pid, go, wrote = tmp_path / "pid", tmp_path / "go", tmp_path / "wrote"
	# the background job keeps stdout and stderr open, and writes only when the test says so
	command = ("echo done; printf 'no newline'; "
		"(while [ ! -e {go} ]; do sleep 0.05; done; echo late; touch {wrote}; exec sleep 30) & "
		"echo $! > {pid}").format(go=go, wrote=wrote, pid=pid)
	try:
		host, elapsed = run_in_shell(fake_host, command)

		assert elapsed < 5
		assert host.returncode == 0
		assert host.stdout == ["done", "no newline"]  # the unfinished last line is kept too

		go.touch()
		assert wait_for(wrote.exists)
		assert ended["stdout"].wait(5)  # the reader ends once the pipe has input again

		assert host.stdout == ["done", "no newline"]  # what the background job wrote later is not recorded
		assert host.output[-1] == "Command finished with return code 0"
	finally:
		go.touch()
		kill_pid_in(pid)


def test_a_background_process_writing_without_end_does_not_hold_up_the_command(fake_host, monkeypatch, tmp_path):
	ended = watch_readers(monkeypatch)
	monkeypatch.setattr(multiSSH3, "_READER_MAX_BYTES_AFTER_EXIT", 256 * 1024)  # quicker than the real limit
	pid = tmp_path / "pid"
	try:
		host, elapsed = run_in_shell(fake_host, "echo done; yes 'background line' & echo $! > {}".format(pid))

		assert elapsed < 10
		assert host.returncode == 0
		assert host.stdout[0] == "done"
		assert ended["stdout"].is_set()  # stopped taking in what the background job writes
		lines = len(host.stdout)
		time.sleep(0.3)
		assert len(host.stdout) == lines
	finally:
		kill_pid_in(pid)


def test_a_timed_out_command_that_ignores_the_signals_still_ends_with_124(fake_host):
	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", "trap '' INT TERM; echo hi; sleep 8", shell=True)
	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=1)  # it keeps its pipes open after the timeout

	assert time.monotonic() - started < 6  # not held up until the command ends
	assert host.returncode == 124
	assert host.stdout == ["hi"]
	assert "Timeout!" in host.stderr


def test_ctrl_c_does_not_wait_for_a_stuck_reader(fake_host, monkeypatch):
	watch_readers(monkeypatch, stdout_pause=3, before_first_read=True)
	monkeypatch.setattr(multiSSH3, "_emo", True)

	host, elapsed = run_in_shell(fake_host, "sleep 5")

	assert elapsed < 2.5
	assert host.returncode is not None
