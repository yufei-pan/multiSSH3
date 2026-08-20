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
