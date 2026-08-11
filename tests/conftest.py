import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import multiSSH3

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MULTISSH3_PY = PACKAGE_ROOT / "multiSSH3.py"

DEFAULT_LOOPBACK_HOSTS = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def parse_mssh_test_hosts():
	raw = os.environ.get("MSSH_TEST_HOSTS", "").strip()
	if not raw:
		return list(DEFAULT_LOOPBACK_HOSTS)
	return [h.strip() for h in raw.split(",") if h.strip()]


def ssh_localhost_works():
	ssh = shutil.which("ssh")
	if not ssh:
		return False
	try:
		r = subprocess.run(
			[
				ssh,
				"-o", "BatchMode=yes",
				"-o", "ConnectTimeout=2",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"127.0.0.1",
				"true",
			],
			capture_output=True,
			timeout=5,
		)
		return r.returncode == 0
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
		return False


def tty_or_curses_ok():
	try:
		import curses
		if not sys.stdout.isatty():
			return False
		# Soft probe: import succeeds and we have a tty
		return hasattr(curses, "wrapper")
	except Exception:
		return False


def run_cli(args, timeout=30, check=False):
	return subprocess.run(
		[sys.executable, str(MULTISSH3_PY), *args],
		capture_output=True,
		text=True,
		timeout=timeout,
		check=check,
	)


def _clear_expand_caches():
	for name in (
		"__validate_expand_hostname",
		"__expandIPv4Address",
		"__expand_hostname",
		"__expand_hostnames",
	):
		fn = getattr(multiSSH3, name, None)
		if fn is not None and hasattr(fn, "cache_clear"):
			fn.cache_clear()


@pytest.fixture(autouse=True)
def restore_module_globals():
	saved = {
		"_no_env": multiSSH3._no_env,
		"__global_suppress_printout": multiSSH3.__global_suppress_printout,
		"__mainReturnCode": multiSSH3.__mainReturnCode,
		"__failedHosts": set(multiSSH3.__failedHosts),
		"_encoding": multiSSH3._encoding,
		"DEFAULT_PASSWORD": multiSSH3.DEFAULT_PASSWORD,
		"SSH_STRICT_HOST_KEY_CHECKING": multiSSH3.SSH_STRICT_HOST_KEY_CHECKING,
		"_etc_hosts": dict(getattr(multiSSH3, "_etc_hosts", {}) or {}),
	}
	_clear_expand_caches()
	yield
	for k, v in saved.items():
		setattr(multiSSH3, k, v if k != "__failedHosts" else set(v))
	multiSSH3.__failedHosts = set(saved["__failedHosts"])
	multiSSH3.join_threads(timeout=2)
	_clear_expand_caches()


@pytest.fixture
def no_hostname_validation(monkeypatch):
	monkeypatch.setattr(
		multiSSH3,
		"__validate_expand_hostname",
		lambda hostname: [hostname],
	)
	_clear_expand_caches()
	yield
	_clear_expand_caches()


@pytest.fixture(scope="session")
def _ssh_probe():
	return ssh_localhost_works()


@pytest.fixture
def ssh_mode(_ssh_probe):
	return "live" if _ssh_probe else "mock"


@pytest.fixture
def local_ssh_hosts(_ssh_probe):
	if not _ssh_probe:
		return []
	return parse_mssh_test_hosts()


@pytest.fixture
def hosts_for_run(local_ssh_hosts, ssh_mode):
	if ssh_mode == "live":
		return list(local_ssh_hosts)
	return ["mock-a", "mock-b"]


@pytest.fixture
def fake_host(monkeypatch):
	def _factory(name, command="true", **kwargs):
		# Avoid DNS for fake names
		monkeypatch.setattr(
			multiSSH3,
			"getIP",
			lambda hostname, local=False: hostname.split("@")[-1],
		)
		return multiSSH3.Host(name=name, command=command, **kwargs)
	return _factory


class StubWindow:
	def __init__(self):
		self.calls = []
		self._yx = (24, 80)

	def getmaxyx(self):
		return self._yx

	def addstr(self, *args, **kwargs):
		self.calls.append(("addstr", args, kwargs))

	def addnstr(self, *args, **kwargs):
		self.calls.append(("addnstr", args, kwargs))

	def move(self, *args, **kwargs):
		self.calls.append(("move", args, kwargs))

	def clrtoeol(self, *args, **kwargs):
		self.calls.append(("clrtoeol", args, kwargs))

	def refresh(self, *args, **kwargs):
		self.calls.append(("refresh", args, kwargs))


class CursesHarness:
	def __init__(self, mode):
		self.mode = mode
		self.window = StubWindow()
		self.keys = []

	def inject_keys(self, seq):
		self.keys.extend(seq)


@pytest.fixture
def curses_harness():
	mode = "live" if tty_or_curses_ok() else "stub"
	return CursesHarness(mode)


def pytest_configure(config):
	config.addinivalue_line("markers", "live_ssh: exercises real SSH when available")
	config.addinivalue_line("markers", "live_tui: exercises real curses/tty when available")
	config.addinivalue_line("markers", "smoke_optional: skip if optional binaries missing")
