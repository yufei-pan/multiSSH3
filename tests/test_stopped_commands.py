"""
-t and Ctrl C stop only mssh's local ssh (or rsync, scp, ...): the remote command gets no signal and
may run on. -t fires after that many seconds without output. A host mssh stopped says so, and what
stopping it left; one stopped by Ctrl C is never a success (sshpass exits 0 when interrupted). The
command sshpass runs gets the SIGINT first, as Ctrl C at a terminal gives it: ssh-copy-id cleans up.
"""
import io
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time

import pytest

import multiSSH3


class RunningProc:
	"""A command that runs until it is terminated."""
	def __init__(self):
		# no process: none to look for below it
		self.pid = None
		self.stdout = io.BytesIO()
		self.stderr = io.BytesIO()
		self.stdin = io.BytesIO()
		self.returncode = None
		self.signals = []

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""

	def send_signal(self, sig):
		self.signals.append(sig)

	def terminate(self):
		self.returncode = -15


class EndedProc(RunningProc):
	"""A command that has already ended when mssh looks."""
	def __init__(self, returncode, stderr=b""):
		super().__init__()
		self.returncode = returncode
		self.stderr = io.BytesIO(stderr)


def _run(fake_host, monkeypatch, proc, timeout=0, passwds=None, ctrl_c=False, **host_kwargs):
	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "/usr/bin/ssh", "sshpass": "/usr/bin/sshpass", "rsync": "/usr/bin/rsync", "scp": "/usr/bin/scp"})
	monkeypatch.setattr(multiSSH3, "_emo", False)

	def start(*args, **kwargs):
		# with ctrl_c, Ctrl C comes once the command runs (one pressed before would keep it from starting)
		if ctrl_c:
			multiSSH3._emo = True
		return proc
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", start)
	host = fake_host("mock-a", **host_kwargs)
	# the command starts at 0 and is silent from then on
	ticks = iter([0.0, 2.0])
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	multiSSH3.run_command(host, threading.Semaphore(1), timeout, passwds)
	return host


def test_a_timeout_says_the_command_may_still_run_on_the_host(fake_host, monkeypatch):
	host = _run(fake_host, monkeypatch, RunningProc(), timeout=1, command="sleep 100")

	assert host.returncode == 124
	assert host.stderr == ["Timeout!", "No output for 1 s, so ssh was stopped: the command may still run on the host."]
	assert "No output for 1 s, so ssh was stopped: the command may still run on the host." in host.output


def test_a_timeout_with_a_password_names_ssh_not_sshpass(fake_host, monkeypatch):
	host = _run(fake_host, monkeypatch, RunningProc(), timeout=1, passwds="pw", command="sleep 100")

	assert host.stderr[-1] == "No output for 1 s, so ssh was stopped: the command may still run on the host."


def test_a_copy_that_timed_out_may_be_incomplete(fake_host, monkeypatch):
	# scp: a failed rsync may be tried again with scp
	host = _run(fake_host, monkeypatch, RunningProc(), timeout=1, command="/tmp/dest", files=["/tmp/a"], scp=True)

	assert host.returncode == 124
	assert host.stderr == ["Timeout!", "No output for 1 s, so scp was stopped: the copy may be incomplete."]


def test_ctrl_c_while_the_command_runs(fake_host, monkeypatch):
	proc = RunningProc()

	host = _run(fake_host, monkeypatch, proc, command="sleep 100", ctrl_c=True)

	assert proc.signals == [multiSSH3.signal.SIGINT]
	assert host.returncode == 130
	assert host.stderr == ["Ctrl C detected, Emergency Stop!", "ssh was stopped: the command may still run on the host."]


def test_ctrl_c_that_reached_ssh_first(fake_host, monkeypatch):
	# the terminal's Ctrl C reaches ssh as well as mssh: ssh ends before mssh stops it, saying only
	# "Killed by signal 2." (hidden)

	host = _run(fake_host, monkeypatch, EndedProc(255, b"Killed by signal 2.\n"), command="sleep 100", ctrl_c=True)

	assert host.returncode == 130
	assert host.stderr == ["Ctrl C detected, Emergency Stop!", "ssh was stopped: the command may still run on the host."]


def test_ctrl_c_with_sshpass_is_not_a_success(fake_host, monkeypatch):
	# sshpass exits 0 when Ctrl C stops it

	host = _run(fake_host, monkeypatch, EndedProc(0), passwds="pw", command="sleep 100", ctrl_c=True)

	assert host.returncode == 130
	assert host.stderr[-1] == "ssh was stopped: the command may still run on the host."


def test_a_command_that_ends_on_its_own_keeps_its_result(fake_host, monkeypatch):
	host = _run(fake_host, monkeypatch, EndedProc(3, b"real error\n"), timeout=1, command="false")

	assert host.returncode == 3
	assert host.stderr == ["real error"]


def test_the_timeout_help_says_it_counts_time_without_output():
	help_text = next(action.help for action in multiSSH3.get_parser()._actions if "--timeout" in action.option_strings)

	assert "without output" in help_text
	assert "Timeout for each command" not in help_text


posix_only = pytest.mark.skipif(os.name != "posix", reason="sessions and terminals are POSIX")

# sshpass 1.10 while ssh has written nothing to sshpass's terminal yet: the command runs as a session
# leader on a new terminal, and SIGINT or SIGTERM ends sshpass at once, which hangs up that terminal
FAKE_SSHPASS = """#!{python}
import os, pty, signal, sys
pid, master = pty.fork()
if pid == 0:
	os.execv(sys.argv[2], sys.argv[2:])
signal.signal(signal.SIGINT, lambda *_: os._exit(0))
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
while True:
	try:
		if not os.read(master, 1024):
			break
	except OSError:
		break
_, status = os.waitpid(pid, 0)
sys.exit(status >> 8)
"""

# ssh-copy-id's scratch directory and the trap that removes it (not on SIGHUP); sleep is ssh connecting
FAKE_SSH_COPY_ID = """#!/bin/sh
SCRATCH_DIR=$(mktemp -d ~/.ssh/ssh-copy-id.XXXXXXXXXX)
trap 'rm -rf "$SCRATCH_DIR"; echo cleaned >> ~/cleaned' EXIT TERM INT QUIT
sleep 30
"""


def _tool(path, text):
	path.write_text(text)
	path.chmod(0o755)
	return str(path)


@pytest.fixture
def copy_id_that_hangs(monkeypatch, tmp_path):
	home = tmp_path / "home"
	(home / ".ssh").mkdir(parents=True)
	monkeypatch.setenv("HOME", str(home))
	bins = tmp_path / "bin"
	bins.mkdir()
	monkeypatch.setattr(multiSSH3, "_binPaths", {
		"sh": "/bin/sh",
		"ssh": str(bins / "ssh"),
		"sshpass": _tool(bins / "sshpass", FAKE_SSHPASS.format(python=sys.executable)),
		"ssh-copy-id": _tool(bins / "ssh-copy-id", FAKE_SSH_COPY_ID),
	})
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: "127.0.0.1")
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: {"proxyjump": "none", "proxycommand": "none"})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())
	return home


@posix_only
def test_a_timed_out_ssh_copy_id_under_sshpass_cleans_up_after_itself(copy_id_that_hangs):
	# sshpass ended at once and hung up ssh-copy-id, whose trap does not cover SIGHUP: every host that
	# timed out left an empty ~/.ssh/ssh-copy-id.XXXXXXXXXX
	home = copy_id_that_hangs
	start = time.monotonic()

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a", copy_id=True, password="pw", timeout=1,
		no_watch=True, quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)

	assert [host.returncode for host in hosts] == [124]
	deadline = time.monotonic() + 5
	while not (home / "cleaned").exists() and time.monotonic() < deadline:
		time.sleep(0.05)
	assert list((home / ".ssh").glob("ssh-copy-id.*")) == []
	assert (home / "cleaned").exists()
	# stopped, not left to sleep out its 30 s
	assert time.monotonic() - start < 10


@posix_only
def test_ssh_copy_id_under_sshpass_stopped_by_ctrl_c_cleans_up_after_itself(copy_id_that_hangs, monkeypatch):
	home = copy_id_that_hangs
	monkeypatch.setattr(multiSSH3, "_emo", False)
	monkeypatch.setattr(multiSSH3, "_stopping", False)
	# the first Ctrl C, once ssh-copy-id is waiting for ssh
	threading.Timer(0.5, lambda: setattr(multiSSH3, "_emo", True)).start()

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a", copy_id=True, password="pw",
		no_watch=True, quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)

	assert [host.returncode for host in hosts] == [130]
	deadline = time.monotonic() + 5
	while not (home / "cleaned").exists() and time.monotonic() < deadline:
		time.sleep(0.05)
	assert list((home / ".ssh").glob("ssh-copy-id.*")) == []


@posix_only
@pytest.mark.skipif(not shutil.which("pgrep"), reason="pgrep is the fallback")
def test_child_processes_are_found_without_proc_children_files(monkeypatch):
	child = subprocess.Popen(["sleep", "30"])
	try:
		def no_children_file(path, *args, **kwargs):
			raise FileNotFoundError(path)
		monkeypatch.setattr(multiSSH3, "open", no_children_file, raising=False)
		assert child.pid in multiSSH3._child_pids(os.getpid())
	finally:
		child.kill()
		child.wait()


@posix_only
def test_sessions_below_a_process_are_found(tmp_path):
	# sh -> python (setsid) -> sleep: the python process leads a session, as sshpass's command does
	ready = tmp_path / "ready"
	script = 'import os, time; os.setsid(); open({!r}, "w").close(); time.sleep(30)'.format(str(ready))
	proc = subprocess.Popen(["/bin/sh", "-c", "{} -c {}; true".format(shlex.quote(sys.executable), shlex.quote(script))])
	try:
		deadline = time.monotonic() + 5
		while not ready.exists() and time.monotonic() < deadline:
			time.sleep(0.02)
		leaders = multiSSH3._sessions_below(proc.pid)
		assert len(leaders) == 1 and leaders[0] != proc.pid
		assert os.getsid(leaders[0]) == leaders[0]
	finally:
		for leader in multiSSH3._sessions_below(proc.pid):
			os.killpg(leader, 9)
		proc.kill()
		proc.wait()


def test_a_copy_id_that_timed_out_names_ssh_copy_id(monkeypatch):
	# --copy_id runs sshpass in an sh -c line: the note named sh. Stopped, ssh-copy-id cleans up and goes
	# on, saying "All keys were skipped because they already exist on the remote system."
	monkeypatch.setattr(multiSSH3, "_binPaths", {"sh": "/bin/sh", "sshpass": "/usr/bin/sshpass", "ssh-copy-id": "/usr/bin/ssh-copy-id"})
	line = ["/bin/sh", "-c", "/usr/bin/sshpass -e /usr/bin/ssh-copy-id -o ConnectTimeout=30 bob@mock-a"]

	assert multiSSH3._stopped_command_note(line) == "ssh-copy-id was stopped: the key may not be installed"


@posix_only
def test_no_session_is_looked_for_below_init_or_no_process():
	# pgrep -P 0 lists init: its group must never get mssh's SIGINT
	assert multiSSH3._sessions_below(0) == []
	assert multiSSH3._sessions_below(1) == []
	assert multiSSH3._sessions_below(None) == []
