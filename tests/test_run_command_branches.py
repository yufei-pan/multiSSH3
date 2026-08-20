import io
import errno
import threading

import multiSSH3


class FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
		self.returncode = returncode
		self.signals = []

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""

	def send_signal(self, sig):
		self.signals.append(sig)

	def terminate(self):
		self.returncode = -15


def _patch_popen(monkeypatch, fake_factory):
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_factory)


def test_run_command_shell_mode(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("ignored", "echo shell", shell=True)
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"shell\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert calls and calls[0][0] == "/bin/sh"
	assert calls[0][1] == "-c"


def test_run_command_scp_files(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host(
		"mock-a",
		"/tmp/dest",
		files=["/tmp/a"],
		scp=True,
	)
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert calls[0][0] == "scp"
	assert "/tmp/a" in calls[0]


def test_run_command_rsync_files(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "/tmp/dest", files=["/tmp/a"], scp=False)
	# Prefer rsync path
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	multiSSH3._binPaths.pop("scp", None)
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert calls[0][0] == "rsync"


def test_run_command_gather_mode_scp(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host(
		"mock-a",
		"/tmp/local",
		files=["/tmp/remote"],
		scp=True,
		gatherMode=True,
	)
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	joined = " ".join(calls[0])
	assert "mock-a:/tmp/remote" in joined
	assert "/tmp/local" in joined


def test_run_command_ipmitool_local(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"Chassis Power is on\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(
		host,
		sem,
		timeout=5,
		ipmi_definitions_list=[multiSSH3.get_default_ipmi_definition()],
	)
	assert host.returncode == 0
	assert calls and "ipmitool" in " ".join(calls[0])


def test_run_command_ipmi_unsupported_method(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	defn = multiSSH3.get_default_ipmi_definition()
	defn["ipmi_method"] = "not-a-method"
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[defn])
	assert host.returncode == 1
	assert any("not supported" in line for line in host.stderr + host.output)


def test_run_command_retry_limit_exhausted(fake_host):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	multiSSH3.run_command(host, sem, timeout=5, retry_limit=-1)
	assert host.returncode == 1
	assert any("Retry limit" in line for line in host.stderr + host.output)


def test_run_command_emfile_retries_after_releasing_semaphore(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def fake_popen(*args, **kwargs):
		attempts.append(args[0])
		if len(attempts) == 1:
			raise OSError(errno.EMFILE, "too many open files")
		return FakeProc()

	def fake_sleep(seconds):
		acquired = sem.acquire(blocking=False)
		assert acquired, "EMFILE backoff ran while the semaphore was held"
		sem.release()
		delays.append(seconds)

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", fake_sleep)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 0


def test_run_command_emfile_exhausts_retry_budget(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def always_emfile(*args, **kwargs):
		attempts.append(args[0])
		raise OSError(errno.EMFILE, "too many open files")

	_patch_popen(monkeypatch, always_emfile)
	monkeypatch.setattr(multiSSH3.time, "sleep", delays.append)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 1
	assert any("Retry limit" in line for line in host.stderr)


def test_run_command_magic_user_ip_uuid(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("alice@mock-a", "echo #USER# #IP# #UUID#")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"ok\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	remote = calls[0][-1]
	assert "alice" in remote
	assert "mock-a" in remote
	assert str(host.uuid) in remote


def test_run_command_interface_ip_prefix(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", interface_ip_prefix="10.1.2.")
	# Host.ip is mock-a from fake getIP — prefix rewrite may warn; still should run
	host.ip = "192.168.1.5"
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert "10.1.2.5" in " ".join(calls[0]) or host.address.startswith("10.1.2.")


def test_run_command_extraargs_list(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", extraargs=["-o", "Foo=1"])
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert "-o" in calls[0] and "Foo=1" in calls[0]


def test_run_command_missing_file_tools(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "/dest", files=["/tmp/a"], scp=True)
	multiSSH3._binPaths.pop("scp", None)
	multiSSH3._binPaths.pop("rsync", None)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 1
