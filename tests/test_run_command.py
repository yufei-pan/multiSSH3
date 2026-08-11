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
	monkeypatch.setattr(
		multiSSH3.subprocess,
		"Popen",
		lambda *args, **kwargs: FakeProc(stdout=b"hi\n"),
	)

	multiSSH3.run_command(host, sem, timeout=5)

	assert host.returncode == 0
	assert any("hi" in line for line in host.stdout)


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

	assert host.returncode not in (0, None)
