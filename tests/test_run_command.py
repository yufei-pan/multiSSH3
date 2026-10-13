import os
import io
import threading

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


class TimeoutProc(FakeProc):
	def __init__(self):
		super().__init__()
		self.returncode = None
		self.signals = []
		self.terminated = False

	def send_signal(self, sig):
		self.signals.append(sig)

	def terminate(self):
		self.terminated = True
		self.returncode = -15


def test_run_timeout_is_124_without_live_ssh(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "sleep forever")
	proc = TimeoutProc()
	ticks = iter([0.0, 2.0])
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *args, **kwargs: proc)
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=1)

	assert proc.signals == [multiSSH3.signal.SIGINT]
	assert proc.terminated is True
	assert host.returncode == 124
	assert "Timeout!" in host.stderr


@pytest.mark.live_ssh
def test_run_echo_localhost(ssh_mode, local_ssh_hosts, fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	if ssh_mode == "live":
		host = multiSSH3.Host(
			name=local_ssh_hosts[0],
			command="echo mssh-live-ok",
		)
		multiSSH3.run_command(host, sem, timeout=20)
		assert host.returncode == 0
		assert any("mssh-live-ok" in line for line in host.stdout)
		return

	host = fake_host("mock-a", "echo hi")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	popen_calls = []

	def fake_popen(argv, **kwargs):
		popen_calls.append((argv, kwargs))
		return FakeProc(stdout=b"hi\n")

	monkeypatch.setattr(
		multiSSH3.subprocess,
		"Popen",
		fake_popen,
	)

	multiSSH3.run_command(host, sem, timeout=5)

	assert host.returncode == 0
	assert any("hi" in line for line in host.stdout)
	assert len(popen_calls) == 1
	argv, _kwargs = popen_calls[0]
	assert argv[0] == "ssh"
	assert argv[-3:] == ["--", "mock-a", "echo hi"]


@pytest.mark.live_ssh
def test_run_false_returns_nonzero(
	ssh_mode,
	local_ssh_hosts,
	fake_host,
	monkeypatch,
):
	sem = threading.Semaphore(1)
	if ssh_mode == "live":
		host = multiSSH3.Host(name=local_ssh_hosts[0], command="false")
	else:
		host = fake_host("mock-a", "false")
		monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
		monkeypatch.setattr(
			multiSSH3.subprocess,
			"Popen",
			lambda *args, **kwargs: FakeProc(returncode=1),
		)

	multiSSH3.run_command(host, sem, timeout=20)

	assert host.returncode not in (0, None)


@pytest.mark.live_ssh
def test_run_timeout(ssh_mode, local_ssh_hosts):
	if ssh_mode != "live":
		pytest.skip("timeout path covered under live SSH")

	sem = threading.Semaphore(1)
	host = multiSSH3.Host(name=local_ssh_hosts[0], command="sleep 5")

	multiSSH3.run_command(host, sem, timeout=1)

	assert host.returncode == 124
	assert "Timeout!" in host.stderr


def test_run_command_expands_magic_host(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "echo #HOST#")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	popen_calls = []

	def fake_popen(argv, **kwargs):
		popen_calls.append(argv)
		return FakeProc(stdout=b"mock-a\n")

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert popen_calls
	assert "echo mock-a" in popen_calls[0][-1]


def test_run_command_extraargs_and_user(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("user@mock-b", "true", extraargs="-o Foo=bar")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	popen_calls = []

	def fake_popen(argv, **kwargs):
		popen_calls.append(argv)
		return FakeProc()

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	argv = popen_calls[0]
	joined = " ".join(str(a) for a in argv)
	assert "mock-b" in joined
	assert "Foo=bar" in joined or "-o" in argv


def test_run_command_stderr_captured(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "cmd")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(
		multiSSH3.subprocess,
		"Popen",
		lambda *a, **k: FakeProc(stdout=b"", stderr=b"boom\n", returncode=1),
	)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 1
	assert any("boom" in line for line in host.stderr)


class _Stream:
	"""A stand-in for sys.stdin that only answers isatty()."""

	def __init__(self, tty):
		self.tty = tty

	def isatty(self):
		return self.tty


def _pretend_terminal(monkeypatch, stdin_is_terminal=True):
	"""Make processRunOnHosts see a terminal on stdout (and, unless told otherwise, on stdin)."""
	monkeypatch.setattr(multiSSH3, "__curses_available", True)
	monkeypatch.setattr(multiSSH3.sys.stdout, "isatty", lambda: True)
	monkeypatch.setattr(multiSSH3.sys, "stdin", _Stream(stdin_is_terminal))
	monkeypatch.setattr(multiSSH3.os, "get_terminal_size", lambda *args: os.terminal_size((120, 40)))


def _process(hosts, **overrides):
	kwargs = dict(timeout=5, password=None, max_connections=2, hosts=hosts, return_unfinished=False, no_watch=True,
		json=False, no_output=True, greppable=False, unavailableHosts={}, will_update_unreachable_hosts=False,
		pre_merge=False)
	kwargs.update(overrides)
	multiSSH3.processRunOnHosts(**kwargs)


def test_command_reading_stdin_gets_eof_without_tui(fake_host):
	import time

	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", "cat", shell=True)
	started = time.monotonic()

	_process([host], no_watch=True)

	assert host.returncode == 0  # not 124: nobody can type, so stdin must not stay open
	assert time.monotonic() - started < 3


def test_tui_keeps_stdin_open_for_key_presses(fake_host, monkeypatch):
	import curses

	seen = []

	def fake_start(hosts, **kwargs):
		for host in hosts:
			seen.append(host.interactive_stdin)
			host.returncode = 0
		return []

	host = fake_host("mock-a", "cat")
	_pretend_terminal(monkeypatch)
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", fake_start)
	monkeypatch.setattr(curses, "wrapper", lambda *args, **kwargs: None)

	_process([host], no_watch=False)

	assert seen == [True]


def test_exit_from_the_tui_stands_when_the_terminal_hung_up(fake_host, monkeypatch):
	# SIGHUP from a closed terminal: curses' cleanup fails on it and replaces mssh's SystemExit with an
	# error, which must not start the TUI again on the dead terminal
	import curses

	tries = []

	def hung_up_wrapper(*args, **kwargs):
		tries.append(1)
		host.returncode = -9  # the handler killed the command
		try:
			raise SystemExit(129)  # the signal handler, inside the TUI
		finally:
			raise curses.error("nocbreak() returned ERR")

	host = fake_host("mock-a", "sleep 60")
	_pretend_terminal(monkeypatch)  # the TUI also needs a terminal on stdin
	finished = threading.Thread(target=lambda: None)
	finished.start()
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda hosts, **kwargs: [finished])
	monkeypatch.setattr(curses, "wrapper", hung_up_wrapper)

	with pytest.raises(SystemExit) as exc_info:
		_process([host], no_watch=False)

	assert exc_info.value.code == 129
	assert tries == [1]


@pytest.mark.parametrize("stdin", [_Stream(False), None], ids=["redirected", "closed"])
def test_no_tui_and_no_stdin_pipe_when_stdin_is_not_a_terminal(fake_host, monkeypatch, stdin):
	seen = []

	def fake_start(hosts, **kwargs):
		for host in hosts:
			seen.append(host.interactive_stdin)
			host.returncode = 0
		return []

	host = fake_host("mock-a", "cat")
	_pretend_terminal(monkeypatch)
	monkeypatch.setattr(multiSSH3.sys, "stdin", stdin)  # mssh ... < file, a pipe, or fd 0 closed
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", fake_start)

	_process([host], no_watch=False)

	assert seen == [False]  # nobody can type: commands get /dev/null, as without the TUI


def test_command_reading_stdin_ends_when_stdin_is_not_a_terminal(fake_host, monkeypatch):
	import curses
	import time

	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", "cat", shell=True)
	tui_runs = []

	def tui(*args, **kwargs):
		# the live view stays up while commands run; without a keyboard nobody can type into it
		tui_runs.append(args)
		deadline = time.monotonic() + 3
		while host.returncode is None and time.monotonic() < deadline:
			time.sleep(0.01)

	_pretend_terminal(monkeypatch, stdin_is_terminal=False)
	monkeypatch.setattr(curses, "wrapper", tui)
	started = time.monotonic()

	_process([host], no_watch=False)

	assert tui_runs == []  # curses would read stdin (a while-read loop's next lines) as key presses
	assert host.returncode == 0
	assert time.monotonic() - started < 3


def test_interface_ip_prefix_leaves_ipv6_hosts_alone(fake_host, monkeypatch):
	host = fake_host("v6-host", "true", interface_ip_prefix="10.0.0.", ip="2001:db8::5")
	commands = []
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert commands[0][-2] == "v6-host"  # [ssh, ..., '--', target, command]: not rewritten to 10.0.0.x
	assert any("ip_prefix" in line for line in host.output)


@pytest.mark.parametrize("prefix, address", [
	("172.30", "172.30.5.7"),
	("172.30.", "172.30.5.7"),  # was 172.30..7
	("192.168.9.", "192.168.9.7"),
])
def test_interface_ip_prefix_with_or_without_a_trailing_dot(fake_host, monkeypatch, prefix, address):
	host = fake_host("node7", "true", interface_ip_prefix=prefix, ip="10.0.5.7")
	commands = []
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert commands[0][-2] == address  # [ssh, ..., '--', target, command]


def test_stdin_closes_when_the_tui_exits_early(fake_host, monkeypatch):
	import curses
	import time

	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", "sleep 0.3; cat", shell=True)
	_pretend_terminal(monkeypatch)
	monkeypatch.setattr(curses, "wrapper", lambda *args, **kwargs: None)  # e.g. the user pressed ESC
	started = time.monotonic()

	_process([host], no_watch=False)

	assert host.returncode == 0  # cat got end of input once nobody could type any more
	assert time.monotonic() - started < 3


def test_hosts_started_without_process_run_get_no_stdin_pipe(fake_host):
	import time

	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	host = fake_host("localhost", "cat", shell=True)
	started = time.monotonic()

	threads = multiSSH3.start_run_on_hosts([host], timeout=5)
	multiSSH3.join_threads(threads, timeout=10)

	assert host.returncode == 0
	assert time.monotonic() - started < 3


def test_stdin_pipe_is_closed_when_the_tui_ends_during_startup(fake_host, monkeypatch):
	import time

	class RunsUntilStdinCloses(FakeProc):
		def __init__(self):
			super().__init__()
			self.pipe = self.stdin  # run_command drops proc.stdin once it is closed
			self.deadline = time.monotonic() + 2

		def poll(self):
			if self.stdin.closed or time.monotonic() > self.deadline:
				return 0
			return None

	procs = []

	def popen(cmd, **kwargs):
		host.interactive_stdin = False  # the TUI ends right as this command starts
		procs.append(RunsUntilStdinCloses())
		return procs[-1]

	host = fake_host("mock-a", "cat")
	host.interactive_stdin = True
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)

	started = time.monotonic()

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=0)

	assert procs[0].pipe.closed  # end of input, not a pipe left open forever
	assert time.monotonic() - started < 1.5  # ended by the close, not the safety deadline


def test_ip_magic_string_without_an_ip_uses_the_ssh_address(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: None)  # reachable only through the ssh config
	host = multiSSH3.Host("jump-only", "ping -c1 #IP#", ip=None)
	commands = []
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert commands[0][-1] == "ping -c1 jump-only"


def test_typed_lines_are_sent_before_stdin_closes_when_the_tui_quits(fake_host, monkeypatch):
	class RecordingPipe(io.BytesIO):
		def close(self):
			self.sent = self.getvalue()
			super().close()

	pipe = RecordingPipe()
	host = fake_host("mock-a", "read answer")
	host.interactive_stdin = False  # the TUI quit right after the user typed
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("yes\n"), []])

	multiSSH3.__handle_writing_stream(pipe, threading.Event(), host)

	assert pipe.closed
	assert pipe.sent == b"yes\n"
