import sys

import pytest

from tests.conftest import (
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


def test_parse_hosts_default():
	hosts = parse_mssh_test_hosts()
	assert "127.0.0.1" in hosts
	assert all(h.startswith("127.") for h in hosts)


def test_ssh_probe_returns_bool():
	assert isinstance(ssh_localhost_works(), bool)


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

	monkeypatch.setattr("tests.conftest.ssh_host_works", fake_ssh_host_works)
	assert ssh_hosts_works(["127.0.0.1"]) is True
	assert ssh_hosts_works(["127.0.0.1", "127.0.0.2"]) is False


def test_tty_or_curses_ok_uses_real_terminal(monkeypatch):
	monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
	monkeypatch.setattr(sys.__stdout__, "isatty", lambda: True)

	class FakeCurses:
		@staticmethod
		def setupterm():
			return None

		@staticmethod
		def tigetnum(name):
			return 80

		wrapper = object()

	monkeypatch.setitem(sys.modules, "curses", FakeCurses())
	assert tty_or_curses_ok() is True


def test_tty_or_curses_ok_false_without_real_tty(monkeypatch):
	monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
	monkeypatch.setattr(sys.__stdout__, "isatty", lambda: False)
	monkeypatch.setattr("tests.conftest._real_tty_available", lambda: False)
	assert tty_or_curses_ok() is False
