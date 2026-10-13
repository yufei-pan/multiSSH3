import atexit
import ipaddress
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# The tests see mssh's built-in defaults and nothing of the machine they run on. multiSSH3 reads the
# config files under ~ when it is imported, and env files, history and keys under ~ later: the session,
# and every process it starts, gets an empty HOME of its own first. ssh finds ~/.ssh through the passwd
# database, not HOME, so the live localhost tests still have their keys.
_SESSION_DIR = tempfile.mkdtemp(prefix="mssh-tests-")
atexit.register(shutil.rmtree, _SESSION_DIR, True)
SESSION_HOME = os.path.join(_SESSION_DIR, "home")
os.mkdir(SESSION_HOME)
os.environ["HOME"] = SESSION_HOME

# ssh -G (how mssh validates names) without the developer's ssh config, whose aliases would decide
# which test names are valid and whose Match exec lines would run commands. Every other ssh, the live
# localhost tests' included, is the real one with the real config.
_REAL_SSH = shutil.which("ssh")
if _REAL_SSH:
	os.mkdir(os.path.join(_SESSION_DIR, "bin"))
	with open(os.path.join(_SESSION_DIR, "bin", "ssh"), "w") as _wrapper:
		_wrapper.write('#!/bin/sh\nif [ "$1" = -G ]; then exec {0} -F /dev/null "$@"; fi\nexec {0} "$@"\n'.format(shlex.quote(_REAL_SSH)))
	os.chmod(os.path.join(_SESSION_DIR, "bin", "ssh"), 0o755)
	os.environ["PATH"] = os.path.join(_SESSION_DIR, "bin") + os.pathsep + os.environ.get("PATH", "")

import multiSSH3  # noqa: E402 (after HOME and PATH)

# outside HOME: this machine's host names and aliases are not the tests'
multiSSH3.DEFAULT_HOST_FILE = os.path.join(_SESSION_DIR, "hosts")
with open(multiSSH3.DEFAULT_HOST_FILE, "w") as _hosts:
	_hosts.write("127.0.0.1\tlocalhost\n")
multiSSH3._etc_hosts.clear()
# in place: _env_files is this list until a test replaces it, and main() starts over from it
multiSSH3.DEFAULT_ENV_FILES[:] = [path for path in multiSSH3.DEFAULT_ENV_FILES if path.startswith("~")]


def pytest_configure(config):
	# a config file outside HOME (/etc/multiSSH3.config.json, /etc/multiSSH3.d/...) changes every default
	if multiSSH3.__configs_from_file:
		found = [path for path in multiSSH3.CONFIG_FILE_CHAIN if os.path.isfile(os.path.expanduser(path))]
		raise pytest.UsageError("the tests expect mssh's built-in defaults, but {} changes them: "
			"move it aside while the tests run".format(" and ".join(found)))

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MULTISSH3_PY = PACKAGE_ROOT / "multiSSH3.py"

DEFAULT_LOOPBACK_HOSTS = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
LOOPBACK_NET = ipaddress.ip_network("127.0.0.0/8")


def _validate_loopback_host(host):
	addr = ipaddress.ip_address(host.strip())
	if addr not in LOOPBACK_NET:
		raise ValueError(f"MSSH_TEST_HOSTS entry {host!r} is outside 127.0.0.0/8")
	return str(addr)


def parse_mssh_test_hosts():
	raw = os.environ.get("MSSH_TEST_HOSTS", "").strip()
	if not raw:
		return list(DEFAULT_LOOPBACK_HOSTS)
	hosts = []
	for entry in raw.split(","):
		entry = entry.strip()
		if not entry:
			continue
		try:
			hosts.append(_validate_loopback_host(entry))
		except ValueError as exc:
			raise ValueError(f"Invalid MSSH_TEST_HOSTS entry: {exc}") from exc
	return hosts


def _real_tty_fd():
	real_stdout = getattr(sys, "__stdout__", None)
	if real_stdout is not None and real_stdout.isatty():
		return real_stdout.fileno(), None
	try:
		fd = os.open("/dev/tty", os.O_RDWR)
		return fd, fd
	except OSError:
		return None, None


def tty_or_curses_ok():
	try:
		import curses
		fd, close_fd = _real_tty_fd()
		if fd is None:
			return False
		if not hasattr(curses, "wrapper"):
			return False
		try:
			curses.setupterm(fd=fd)
			return curses.tigetnum("cols") > 0
		finally:
			if close_fd is not None:
				os.close(close_fd)
	except Exception:
		return False


def ssh_host_works(host):
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
				host,
				"true",
			],
			capture_output=True,
			timeout=5,
		)
		return r.returncode == 0
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
		return False


def ssh_hosts_works(hosts):
	return bool(hosts) and all(ssh_host_works(host) for host in hosts)


def ssh_localhost_works():
	return ssh_host_works("127.0.0.1")


def run_cli(args, timeout=30, check=False):
	return subprocess.run(
		[sys.executable, str(MULTISSH3_PY), *args],
		capture_output=True,
		text=True,
		timeout=timeout,
		check=check,
	)


def _clear_expand_caches():
	# every memoized resolution / env result, so tests cannot see each other's lookups
	getattr(multiSSH3, "_dns_cache", {}).clear()
	multiSSH3.__expansion_env_state = None
	getattr(multiSSH3, "_consulted_env", {}).clear()
	getattr(multiSSH3, "_reported_invalid_hosts", set()).clear()
	for name in (
		"getIP",
		"readEnvFromFile",
		"__validate_expand_hostname",
		"__expandIPv4Address",
		"__expand_hostname",
		"__expand_hostnames",
		"_ssh_config_target",
		"_ssh_config_values",
		"get_terminal_color_capability",
		"rgb_to_ansi_color_string",
		"int_to_unique_ansi_color",
	):
		fn = getattr(multiSSH3, name, None)
		if fn is not None and hasattr(fn, "cache_clear"):
			fn.cache_clear()


_real_getaddrinfo = socket.getaddrinfo


def getaddrinfo_without_dns(host, port, family=0, type=0, proto=0, flags=0):
	"""socket.getaddrinfo for the tests: IP addresses and localhost, no other name exists (no DNS)."""
	name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
	if name is not None and name.lower().rstrip(".") == "localhost":
		host = "127.0.0.1"
	elif name is not None:
		try:
			ipaddress.ip_address(name.split("%")[0])
		except ValueError:
			raise socket.gaierror(socket.EAI_NONAME, "Name or service not known (the tests look no names up)")
	return _real_getaddrinfo(host, port, family, type, proto, flags | socket.AI_NUMERICHOST)


@pytest.fixture(autouse=True)
def no_machine_state(tmp_path_factory):
	"""
	Keep tests off this machine's state: its runtime dirs ($XDG_RUNTIME_DIR, /run/user/<uid>, /dev/shm,
	the temp dir) hold the developer's cache of unreachable hosts, and its DNS answers (or hangs) for names.
	A test patching any of these itself wins.
	"""
	import mssh_complete
	machine = tmp_path_factory.mktemp("machine")
	runtime = machine / "runtime"
	runtime.mkdir(mode=0o700)
	(machine / "tmp").mkdir()
	# a patcher of its own: a test's monkeypatch must still be undone before restore_module_globals runs
	with pytest.MonkeyPatch.context() as patch:
		for module in (multiSSH3, mssh_complete):
			patch.setattr(module, "_RUN_USER_ROOT", "/dev/null/no-run-user", raising=False)
			patch.setattr(module, "_SHM_DIR", "/dev/null/no-shm", raising=False)
		# processes the test starts inherit the variable
		patch.setenv("XDG_RUNTIME_DIR", str(runtime))
		patch.setattr(tempfile, "tempdir", str(machine / "tmp"))
		patch.setattr(socket, "getaddrinfo", getaddrinfo_without_dns)
		yield


@pytest.fixture(autouse=True)
def restore_module_globals():
	saved = {
		"_emo": multiSSH3._emo,
		"_commands_started": multiSSH3._commands_started,
		"_env_files": list(multiSSH3._env_files),
		"_explicit_env_files": set(multiSSH3._explicit_env_files),
		"__globalUnavailableHosts": dict(multiSSH3.__globalUnavailableHosts),
		"__keyPressesIn": [list(line) for line in multiSSH3.__keyPressesIn],
		"DEFAULT_IPMI_DEFINITIONS": [dict(item) for item in multiSSH3.DEFAULT_IPMI_DEFINITIONS],
		"ERRORS": list(multiSSH3.ERRORS),
		"_no_env": multiSSH3._no_env,
		"__global_suppress_printout": multiSSH3.__global_suppress_printout,
		"__mainReturnCode": multiSSH3.__mainReturnCode,
		"__failedHosts": set(multiSSH3.__failedHosts),
		"_encoding": multiSSH3._encoding,
		"DEFAULT_PASSWORD": multiSSH3.DEFAULT_PASSWORD,
		"SSH_STRICT_HOST_KEY_CHECKING": multiSSH3.SSH_STRICT_HOST_KEY_CHECKING,
		"_etc_hosts": dict(getattr(multiSSH3, "_etc_hosts", {}) or {}),
		"FORCE_TRUECOLOR": multiSSH3.FORCE_TRUECOLOR,
		"__DEBUG_MODE": getattr(multiSSH3, "__DEBUG_MODE", False),
		"__returnZero": multiSSH3.__returnZero,
		"DEFAULT_DIFF_DISPLAY_THRESHOLD": multiSSH3.DEFAULT_DIFF_DISPLAY_THRESHOLD,
		"DEFAULT_HOST_FILE": multiSSH3.DEFAULT_HOST_FILE,
		"_binPaths": dict(multiSSH3._binPaths),
	}
	_clear_expand_caches()
	yield
	for k, v in saved.items():
		if k in (
			"_env_files",
			"_explicit_env_files",
			"__globalUnavailableHosts",
			"__keyPressesIn",
			"DEFAULT_IPMI_DEFINITIONS",
			"ERRORS",
			"__failedHosts",
			"_binPaths",
		):
			continue
		setattr(multiSSH3, k, v)
	multiSSH3._env_files = list(saved["_env_files"])
	multiSSH3._explicit_env_files = set(saved["_explicit_env_files"])
	multiSSH3.__globalUnavailableHosts = dict(saved["__globalUnavailableHosts"])
	multiSSH3.__keyPressesIn = [list(line) for line in saved["__keyPressesIn"]]
	multiSSH3.DEFAULT_IPMI_DEFINITIONS = [dict(item) for item in saved["DEFAULT_IPMI_DEFINITIONS"]]
	multiSSH3.ERRORS = list(saved["ERRORS"])
	multiSSH3.__failedHosts = set(saved["__failedHosts"])
	multiSSH3._binPaths = dict(saved["_binPaths"])
	multiSSH3.join_threads(timeout=2)
	_clear_expand_caches()


@pytest.fixture
def no_hostname_validation(monkeypatch):
	monkeypatch.setattr(
		multiSSH3,
		"__validate_expand_hostname",
		lambda hostname: [hostname],
	)
	# nor the lookups that go with it: names are taken as typed, none has an address
	monkeypatch.setattr(multiSSH3, "_prefetch_ips", lambda hostnames: None)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: None)
	_clear_expand_caches()
	yield
	_clear_expand_caches()


@pytest.fixture(scope="session")
def _ssh_probe():
	return ssh_hosts_works(parse_mssh_test_hosts())


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
	def __init__(self, yx=(24, 80), keys=None):
		self.calls = []
		self._yx = yx
		self.keys = list(keys or [])

	def getmaxyx(self):
		return self._yx

	def getch(self):
		self.calls.append(("getch", (), {}))
		return self.keys.pop(0) if self.keys else -1

	def set_size(self, rows, columns):
		self._yx = (rows, columns)

	def clear(self):
		self.calls.append(("clear", (), {}))

	def nodelay(self, value):
		self.calls.append(("nodelay", (value,), {}))

	def idlok(self, value):
		self.calls.append(("idlok", (value,), {}))

	def scrollok(self, value):
		self.calls.append(("scrollok", (value,), {}))

	def leaveok(self, value):
		self.calls.append(("leaveok", (value,), {}))

	def box(self):
		self.calls.append(("box", (), {}))

	def vline(self, *args):
		self.calls.append(("vline", args, {}))

	def noutrefresh(self):
		self.calls.append(("noutrefresh", (), {}))

	def touchwin(self):
		self.calls.append(("touchwin", (), {}))

	def addstr(self, *args, **kwargs):
		self.calls.append(("addstr", args, kwargs))

	def addnstr(self, *args, **kwargs):
		self.calls.append(("addnstr", args, kwargs))

	def move(self, *args, **kwargs):
		self.calls.append(("move", args, kwargs))

	def deleteln(self, *args, **kwargs):
		self.calls.append(("deleteln", args, kwargs))

	def clrtoeol(self, *args, **kwargs):
		self.calls.append(("clrtoeol", args, kwargs))

	def refresh(self, *args, **kwargs):
		self.calls.append(("refresh", args, kwargs))


class StubPanel:
	def __init__(self, window):
		self.window = window
		self.hidden = False
		self.calls = []

	def hide(self):
		self.hidden = True
		self.calls.append("hide")

	def show(self):
		self.hidden = False
		self.calls.append("show")


class StubPanelModule:
	def __init__(self, harness):
		self.harness = harness

	def new_panel(self, window):
		panel = StubPanel(window)
		self.harness.panels.append(panel)
		return panel

	def update_panels(self):
		self.harness.panel_updates += 1


class StubCursesHarness:
	def __init__(self):
		self.window = StubWindow()
		self.windows = []
		self.panels = []
		self.panel_updates = 0
		self.screen_updates = 0

	def inject_keys(self, seq):
		self.window.keys.extend(seq)

	def newwin(self, rows, columns, y, x):
		window = StubWindow((rows, columns))
		window.calls.append(("origin", (y, x), {}))
		self.windows.append(window)
		return window


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


@pytest.fixture
def stub_curses_harness(monkeypatch):
	import curses

	harness = StubCursesHarness()
	panel_module = StubPanelModule(harness)
	monkeypatch.setattr(curses, "newwin", harness.newwin)
	monkeypatch.setattr(curses, "panel", panel_module)
	monkeypatch.setattr(curses, "doupdate", lambda: setattr(harness, "screen_updates", harness.screen_updates + 1))
	monkeypatch.setattr(curses, "ACS_VLINE", ord("|"), raising=False)
	monkeypatch.setattr(curses, "KEY_RESIZE", 410, raising=False)
	monkeypatch.setattr(curses, "KEY_REFRESH", 12, raising=False)
	monkeypatch.setattr(curses, "KEY_F5", 269, raising=False)
	monkeypatch.setattr(curses, "KEY_EXIT", 361, raising=False)
	monkeypatch.setattr(curses, "KEY_HELP", 353, raising=False)
	monkeypatch.setattr(curses, "KEY_F1", 265, raising=False)
	monkeypatch.setattr(curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(curses, "can_change_color", lambda: False)
	monkeypatch.setattr(curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(curses, "color_pair", lambda pair: pair << 8)
	monkeypatch.setattr(curses, "A_BOLD", 1 << 16, raising=False)
	monkeypatch.setattr(curses, "A_DIM", 1 << 17, raising=False)
	monkeypatch.setattr(curses, "A_UNDERLINE", 1 << 18, raising=False)
	monkeypatch.setattr(curses, "A_BLINK", 1 << 19, raising=False)
	monkeypatch.setattr(curses, "A_REVERSE", 1 << 20, raising=False)
	monkeypatch.setattr(curses, "A_INVIS", 1 << 21, raising=False)
	monkeypatch.setattr(multiSSH3, "__curses_global_color_pairs", {})
	monkeypatch.setattr(multiSSH3, "__curses_current_color_pair_index", 1)
	return harness
