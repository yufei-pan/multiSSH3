'''
Which commands may use the operator's terminal.

ssh asks for passwords, passphrases and new host keys on its controlling terminal, not on stdin. With the
TUI drawing on the terminal, or several commands asking at once, the questions are hidden or mixed, typed
keys are split between them and a typed password can echo. So only a command that runs alone without the
TUI keeps the terminal; the others start in a session of their own, where ssh has no terminal and fails at
once with its reason.
'''
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import multiSSH3

ROOT = str(Path(multiSSH3.__file__).resolve().parent)

def _can_take_a_terminal():
	if os.name != "posix":
		return False
	try:
		import pty  # noqa: F401
		import termios
	except ImportError:
		return False
	return hasattr(termios, "TIOCSCTTY")


_needs_pty = pytest.mark.skipif(not _can_take_a_terminal(), reason="needs a pseudo-terminal it can make its controlling terminal")

# how a command finds out whether it could ask the operator something: ssh opens /dev/tty
_TERMINAL_PROBE = (
	"import os\n"
	"try:\n"
	"    os.close(os.open('/dev/tty', os.O_RDWR))\n"
	"    print('terminal')\n"
	"except OSError:\n"
	"    print('no terminal')\n"
)


def _scratch_env(tmp_path):
	'''An environment keeping mssh off the machine's home, config and runtime dir.'''
	home = tmp_path / "home"
	home.mkdir(exist_ok=True)
	run = tmp_path / "run"
	run.mkdir(mode=0o700, exist_ok=True)
	return dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(run), PYTHONDONTWRITEBYTECODE="1")


def _run_on_new_terminal(code, env, keys=(), timeout=30):
	'''
	Run python code as an operator's shell runs mssh: the session leader of a new pseudo-terminal, which
	is its controlling terminal. keys are (seconds, bytes) typed on that terminal; bytes may also be a
	function returning them (or None to wait). Returns (exit code, everything shown on the terminal).
	'''
	import pty
	master, slave = pty.openpty()
	starter = "import fcntl, sys, termios; fcntl.ioctl(0, termios.TIOCSCTTY, 0); del fcntl, termios; exec(sys.argv[1])"
	proc = subprocess.Popen([sys.executable, "-c", starter, code], stdin=slave, stdout=slave, stderr=slave,
		env=env, cwd=str(Path(env["HOME"]).parent), start_new_session=True)
	os.close(slave)
	keys = sorted(keys, key=lambda key: key[0])
	output = b""
	started = time.monotonic()
	try:
		while True:
			now = time.monotonic() - started
			if keys and keys[0][0] <= now:
				data = keys[0][1]() if callable(keys[0][1]) else keys[0][1]
				if data is not None:
					os.write(master, data)
					keys.pop(0)
			if now > timeout:
				raise AssertionError("still running after {} s, shown so far: {!r}".format(timeout, output))
			ready, _, _ = select.select([master], [], [], 0.05)
			if not ready:
				continue
			try:
				data = os.read(master, 65536)
			except OSError:
				# EIO: nothing has the terminal open any more
				data = b""
			if not data:
				break
			output += data
		proc.wait(timeout=10)
	finally:
		if proc.poll() is None:
			proc.kill()
			proc.wait()
		os.close(master)
	return proc.returncode, output.decode(errors="replace")


def _probe_hosts_on_terminal(tmp_path, count, max_connections=4):
	'''Run the terminal probe on count hosts with -nw on a new terminal; what each command found.'''
	probe = "{} -c {}".format(multiSSH3.shlex.quote(sys.executable), multiSSH3.shlex.quote(_TERMINAL_PROBE))
	code = (
		"import json, sys\n"
		"sys.path.insert(0, {root!r})\n"
		"import multiSSH3\n"
		"hosts = [multiSSH3.Host('host{{}}'.format(i), {probe!r}, shell=True, ip='127.0.0.1') for i in range({count})]\n"
		"multiSSH3.processRunOnHosts(timeout=20, password=None, max_connections={max_connections}, hosts=hosts,\n"
		"    return_unfinished=False, no_watch=True, json=False, no_output=True, greppable=False,\n"
		"    unavailableHosts={{}}, will_update_unreachable_hosts=False, pre_merge=False)\n"
		"print('RESULT ' + json.dumps([host.stdout for host in hosts]))\n"
	).format(root=ROOT, probe=probe, count=count, max_connections=max_connections)
	returncode, shown = _run_on_new_terminal(code, _scratch_env(tmp_path))
	assert returncode == 0, shown
	import json
	return json.loads(shown.split("RESULT ", 1)[1].splitlines()[0])


@_needs_pty
def test_commands_of_several_hosts_cannot_use_the_terminal(tmp_path):
	# with -nw on two hosts, two ssh asked at once: typed keys went to either and a password could echo
	assert _probe_hosts_on_terminal(tmp_path, 2) == [["no terminal"], ["no terminal"]]


@_needs_pty
def test_a_lone_command_without_the_tui_keeps_the_terminal(tmp_path):
	# `mssh -nw host cmd` lets ssh ask for a password, as plain ssh does
	assert _probe_hosts_on_terminal(tmp_path, 1) == [["terminal"]]


@_needs_pty
def test_commands_run_one_at_a_time_keep_the_terminal(tmp_path):
	# -nw -m 1: one command asks at a time, as typing each host's password needs
	assert _probe_hosts_on_terminal(tmp_path, 2, max_connections=1) == [["terminal"], ["terminal"]]


def _terminal_decisions(fake_host, monkeypatch, count=1, max_connections=4, tui=False, return_unfinished=False):
	import curses
	seen = []

	def fake_start(hosts, **kwargs):
		for host in hosts:
			seen.append(host.use_terminal)
			host.returncode = 0
		return []

	hosts = [fake_host("mock-{}".format(i), "true") for i in range(count)]
	if tui:
		monkeypatch.setattr(multiSSH3, "__curses_available", True)
		monkeypatch.setattr(multiSSH3.sys.stdout, "isatty", lambda: True)
		monkeypatch.setattr(multiSSH3.sys.stdin, "isatty", lambda: True, raising=False)
		monkeypatch.setattr(multiSSH3.os, "get_terminal_size", lambda *args: os.terminal_size((120, 40)))
		monkeypatch.setattr(curses, "wrapper", lambda *args, **kwargs: None)
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", fake_start)
	multiSSH3.processRunOnHosts(timeout=5, password=None, max_connections=max_connections, hosts=hosts,
		return_unfinished=return_unfinished, no_watch=not tui, json=False, no_output=True, greppable=False,
		unavailableHosts={}, will_update_unreachable_hosts=False, pre_merge=False)
	return seen


def test_only_a_command_running_alone_without_the_tui_keeps_the_terminal(fake_host, monkeypatch):
	assert _terminal_decisions(fake_host, monkeypatch, count=1) == [True]
	assert _terminal_decisions(fake_host, monkeypatch, count=3) == [False] * 3
	assert _terminal_decisions(fake_host, monkeypatch, count=3, max_connections=1) == [True] * 3


def test_the_tui_takes_the_terminal_even_for_one_host(fake_host, monkeypatch):
	# curses draws on it and reads its keys: a password question would be hidden behind the TUI
	assert _terminal_decisions(fake_host, monkeypatch, count=1, tui=True) == [False]


def test_commands_left_running_for_the_caller_get_no_terminal(fake_host, monkeypatch):
	# return_unfinished: the caller goes on (and may start more) while the command runs
	assert _terminal_decisions(fake_host, monkeypatch, count=1, return_unfinished=True) == [False]


class _FinishedProc:
	def __init__(self):
		import io
		self.stdout = io.BytesIO()
		self.stderr = io.BytesIO()
		self.stdin = None
		self.returncode = 0

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""


@pytest.mark.parametrize("use_terminal", [False, True])
def test_a_command_without_the_terminal_starts_in_a_session_of_its_own(fake_host, monkeypatch, use_terminal):
	started = []
	host = fake_host("mock-a", "true")
	host.use_terminal = use_terminal
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: started.append(kwargs) or _FinishedProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert host.returncode == 0
	# a new session has no controlling terminal: ssh cannot open /dev/tty to ask anything (POSIX only)
	assert started[0].get("start_new_session") is (os.name == "posix" and not use_terminal)


def test_hosts_start_without_the_terminal_by_default(fake_host):
	# start_run_on_hosts / run_command used directly: nothing says the command runs alone
	assert fake_host("mock-a", "true").use_terminal is False
	host = fake_host("mock-b", "true")
	host.use_terminal = True
	assert host.copy().use_terminal is True


def _started_argv(fake_host, monkeypatch, use_terminal=False, password=None, files=None, scp=False, sshpass=True):
	started = []
	host = fake_host("mock-a", "/tmp/" if files else "true", files=files, scp=scp)
	host.use_terminal = use_terminal
	for tool in ("ssh", "scp", "rsync"):
		monkeypatch.setitem(multiSSH3._binPaths, tool, tool)
	if sshpass:
		monkeypatch.setitem(multiSSH3._binPaths, "sshpass", "sshpass")
	else:
		monkeypatch.delitem(multiSSH3._binPaths, "sshpass", raising=False)
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: started.append(argv) or _FinishedProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, passwds=password)

	return started[0]


_NO_PASSWORD_PROMPTS = "-o NumberOfPasswordPrompts=0"


@pytest.mark.skipif(os.name != "posix", reason="commands keep the console on Windows")
def test_ssh_without_a_terminal_sends_no_password_it_cannot_ask_for(fake_host, monkeypatch):
	# with no terminal ssh sent an empty password three times per host: each one a failed login in the
	# host's auth log (fail2ban), and OpenSSH 9.8+ sshd then refuses this machine for a while
	monkeypatch.delenv("SSH_ASKPASS_REQUIRE", raising=False)
	argv = _started_argv(fake_host, monkeypatch)
	assert argv[0] == "ssh" and _NO_PASSWORD_PROMPTS in argv[:argv.index("--")]
	# file copies: scp passes it to its ssh, rsync through --rsh
	assert _NO_PASSWORD_PROMPTS in _started_argv(fake_host, monkeypatch, files=["/etc/hostname"], scp=True)
	rsync = _started_argv(fake_host, monkeypatch, files=["/etc/hostname"])
	assert rsync[0] == "rsync" and _NO_PASSWORD_PROMPTS in rsync[rsync.index("--rsh") + 1]
	# no sshpass: -p cannot answer, ssh has no terminal either
	assert _NO_PASSWORD_PROMPTS in _started_argv(fake_host, monkeypatch, password="secret", sshpass=False)


@pytest.mark.parametrize("case", ["terminal", "sshpass", "askpass"])
def test_ssh_asks_for_passwords_where_something_answers(fake_host, monkeypatch, case):
	monkeypatch.delenv("SSH_ASKPASS_REQUIRE", raising=False)
	if case == "terminal":
		# -nw with one host: the operator types it, as with plain ssh
		argv = _started_argv(fake_host, monkeypatch, use_terminal=True)
	elif case == "sshpass":
		# -p: sshpass answers on its own pty
		argv = _started_argv(fake_host, monkeypatch, password="secret")
		assert argv[0] == "sshpass"
	else:
		# the user asked ssh to use the askpass program (it needs no terminal)
		monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
		argv = _started_argv(fake_host, monkeypatch)
	assert not any("NumberOfPasswordPrompts" in str(arg) for arg in argv)


def _run_and_note(fake_host, monkeypatch, capsys, stderr_by_host, password=None, use_terminal=False, no_output=False):
	'''Run hosts whose ssh printed stderr_by_host[name], with the default output; return mssh's stderr.'''
	def fake_start(hosts, **kwargs):
		for host in hosts:
			host.stderr = list(stderr_by_host[host.name])
			host.returncode = 255
			# the case under test, whatever processRunOnHosts decided for this many hosts
			host.use_terminal = use_terminal
		return []

	hosts = [fake_host(name, "hostname") for name in stderr_by_host]
	monkeypatch.setitem(multiSSH3._binPaths, "sshpass", "sshpass")
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", fake_start)
	multiSSH3.processRunOnHosts(timeout=5, password=password, max_connections=4, hosts=hosts,
		return_unfinished=False, no_watch=True, json=False, no_output=no_output, greppable=False,
		unavailableHosts={}, will_update_unreachable_hosts=False, pre_merge=True)
	return capsys.readouterr().err


def _denied(user, host, methods="publickey,password"):
	return ["Warning: Permanently added '{}' (ED25519) to the list of known hosts.".format(host),
		"{}@{}: Permission denied ({}).".format(user, host, methods)]


@pytest.mark.skipif(os.name != "posix", reason="commands keep the console on Windows")
def test_a_note_says_why_ssh_did_not_ask_for_the_password(fake_host, monkeypatch, capsys):
	err = _run_and_note(fake_host, monkeypatch, capsys, {
		"bob@node1": _denied("bob", "node1"),
		"bob@node2": _denied("bob", "node2", "publickey,keyboard-interactive"),
		"bob@node3": ["ok"],
	})
	notes = [line for line in err.splitlines() if line.startswith("Note:")]
	assert len(notes) == 1  # one line for the run, not one per host
	assert "ssh could not ask for the password (or key passphrase) of bob@node[1-2]" in notes[0]
	assert "-p" in notes[0] and "-nw -m 1" in notes[0]


@pytest.mark.parametrize("case", ["terminal", "sshpass", "publickey_only", "other_host", "no_output"])
def test_no_note_unless_ssh_wanted_a_password_it_could_not_ask_for(fake_host, monkeypatch, capsys, case):
	stderr = {"bob@node1": _denied("bob", "node1")}
	kwargs = {}
	if case == "terminal":
		kwargs["use_terminal"] = True  # it could ask: the password was wrong or not typed
	elif case == "sshpass":
		kwargs["password"] = "wrong"  # sshpass answered: the password was wrong
	elif case == "publickey_only":
		stderr = {"bob@node1": _denied("bob", "node1", "publickey")}  # no password would have helped
	elif case == "other_host":
		# an ssh run by the command (or a jump host) failed, not the one mssh started for node1
		stderr = {"bob@node1": _denied("bob", "elsewhere")}
	else:
		kwargs["no_output"] = True
	assert "Note:" not in _run_and_note(fake_host, monkeypatch, capsys, stderr, **kwargs)


def test_the_note_reads_hostile_remote_output_in_linear_time(fake_host):
	# stderr comes from the remote side: a long line of '@' made an \S+@\S+ pattern backtrack for seconds
	tail = ": Permission denied (publickey,password)."
	lines = ["@" * 100000, "a@" * 50000, "@" * 100000 + tail, "a@" * 50000 + tail, "u@h" + tail[:-1] + "@" * 100000,
		"u@h: Permission denied (" + "(" * 100000, "x" * 100000 + "@h" + tail]
	for line in lines:
		started = time.perf_counter()
		multiSSH3._SSH_PERMISSION_DENIED.fullmatch(line)
		assert time.perf_counter() - started < 0.05, line[:20]
	host = fake_host("bob@node1", "true")
	host.stderr = lines
	host.returncode = 255
	started = time.perf_counter()
	multiSSH3._note_unasked_passwords([host], None)
	assert time.perf_counter() - started < 0.1
