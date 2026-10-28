import os
import pwd
import socket
import subprocess
import sys

import pytest

import multiSSH3
import mssh_complete
from conftest import (
	SESSION_HOME,
	parse_mssh_test_hosts,
	run_cli,
	ssh_hosts_works,
	ssh_localhost_works,
	tty_or_curses_ok,
)


def test_version_cli():
	r = run_cli(["-V"])
	assert r.returncode == 0
	assert "6." in (r.stdout + r.stderr)


def test_parse_hosts_default(monkeypatch):
	monkeypatch.delenv("MSSH_TEST_HOSTS", raising=False)
	hosts = parse_mssh_test_hosts()
	assert "127.0.0.1" in hosts
	assert all(h.startswith("127.") for h in hosts)


def test_ssh_probe_reports_whether_ssh_got_in(monkeypatch, tmp_path):
	calls = tmp_path / "calls"
	fake_ssh = tmp_path / "ssh"
	# gets in on 127.0.0.1 only, and records its arguments
	fake_ssh.write_text('#!/bin/sh\necho "$@" >> {}\ncase "$*" in *" 127.0.0.1 true") exit 0 ;; esac\nexit 255\n'.format(calls))
	fake_ssh.chmod(0o755)
	monkeypatch.setenv("PATH", str(tmp_path))

	assert ssh_localhost_works() is True
	assert ssh_hosts_works(["127.0.0.2"]) is False
	# never waits for a password prompt
	assert all("-o BatchMode=yes" in line for line in calls.read_text().splitlines())
	monkeypatch.setenv("PATH", str(tmp_path / "nothing"))
	assert ssh_localhost_works() is False


def test_parse_hosts_rejects_non_loopback(monkeypatch):
	monkeypatch.setenv("MSSH_TEST_HOSTS", "10.0.0.1")
	with pytest.raises(ValueError, match="127.0.0.0/8"):
		parse_mssh_test_hosts()


def test_parse_hosts_rejects_hostname(monkeypatch):
	monkeypatch.setenv("MSSH_TEST_HOSTS", "localhost")
	with pytest.raises(ValueError, match="Invalid MSSH_TEST_HOSTS"):
		parse_mssh_test_hosts()


def test_parse_hosts_accepts_loopback_override(monkeypatch):
	monkeypatch.setenv("MSSH_TEST_HOSTS", "127.0.0.5,127.0.0.6")
	assert parse_mssh_test_hosts() == ["127.0.0.5", "127.0.0.6"]


def test_ssh_hosts_works_requires_every_host(monkeypatch):
	def fake_ssh_host_works(host):
		return host == "127.0.0.1"

	monkeypatch.setattr("conftest.ssh_host_works", fake_ssh_host_works)
	assert ssh_hosts_works(["127.0.0.1"]) is True
	assert ssh_hosts_works(["127.0.0.1", "127.0.0.2"]) is False


def test_tty_or_curses_ok_uses_real_terminal(monkeypatch):
	monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
	monkeypatch.setattr("conftest._real_tty_fd", lambda: (42, None))

	setupterm_fds = []

	class FakeCurses:
		@staticmethod
		def setupterm(term=None, fd=-1):
			setupterm_fds.append(fd)

		@staticmethod
		def tigetnum(name):
			return 80

		wrapper = object()

	monkeypatch.setitem(sys.modules, "curses", FakeCurses())
	assert tty_or_curses_ok() is True
	assert setupterm_fds == [42]


def test_tty_or_curses_ok_false_without_real_tty(monkeypatch):
	monkeypatch.setattr("conftest._real_tty_fd", lambda: (None, None))
	assert tty_or_curses_ok() is False


def test_the_tests_never_use_the_real_home():
	real_home = pwd.getpwuid(os.getuid()).pw_dir
	child = subprocess.run([sys.executable, "-c", "import os; print(os.path.expanduser('~'))"],
		stdout=subprocess.PIPE, universal_newlines=True, check=True)

	assert os.path.expanduser("~") == SESSION_HOME != real_home
	# processes the tests start too: mssh run from a test writes its history there
	assert child.stdout.strip() == SESSION_HOME
	assert os.path.expanduser(multiSSH3.DEFAULT_HISTORY_FILE) == os.path.join(SESSION_HOME, ".mssh_history")


@pytest.mark.parametrize("xdg", [True, False], ids=["xdg_runtime_dir", "temp_dir"])
def test_the_tests_never_use_the_real_runtime_dir(monkeypatch, tmp_path_factory, xdg):
	if not xdg:
		# the end of the chain: <tempdir>/multiSSH3-<uid>
		monkeypatch.delenv("XDG_RUNTIME_DIR")
	base = str(tmp_path_factory.getbasetemp())

	assert multiSSH3.runtime_dir().startswith(base + os.sep)
	assert mssh_complete.cache_dir() == multiSSH3.runtime_dir()
	assert multiSSH3._unavailable_hosts_file_path().startswith(base + os.sep)


def test_mssh_started_by_a_test_never_reads_the_real_runtime_dir(tmp_path):
	# a test running mssh in a process of its own gives it a new $XDG_RUNTIME_DIR, and reading the
	# unreachable hosts fell back to /run/user/<uid>/multiSSH3: hosts this machine's own runs found
	# unreachable were skipped there. Reading sets up the directory a write would use, so it is the one
	# under the new $XDG_RUNTIME_DIR.
	runtime = tmp_path / "run"
	runtime.mkdir(mode=0o700)
	child = subprocess.run([sys.executable, "-c", "import multiSSH3; print(multiSSH3._unavailable_hosts_file_path())"],
		stdout=subprocess.PIPE, universal_newlines=True, check=True, cwd=os.path.dirname(os.path.abspath(multiSSH3.__file__)),
		env=dict(os.environ, XDG_RUNTIME_DIR=str(runtime)))

	assert child.stdout.strip() == str(runtime / "multiSSH3" / "unavailable_hosts.csv")


def test_the_tests_never_see_this_machine_s_host_names():
	# its env files (/etc/profile.d/hosts.sh) and hosts file
	assert multiSSH3.readEnvFromFile() == {}
	assert multiSSH3.getIP("localhost") == "127.0.0.1"
	# nor DNS: a search domain with a wildcard would give any short name an address
	with pytest.raises(socket.gaierror):
		socket.getaddrinfo("h", 22)
	assert multiSSH3.getIP("h") is None
	assert multiSSH3.expand_hostnames(["h", "127.0.0.1"]) == {"127.0.0.1": "127.0.0.1"}
