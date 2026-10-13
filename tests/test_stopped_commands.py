"""
-t and Ctrl C stop only mssh's local ssh (or rsync, scp, ...): the remote command gets no signal and
may run on. -t fires after that many seconds without output. A host mssh stopped says so, and what
stopping it left; one stopped by Ctrl C is never a success (sshpass exits 0 when interrupted).
"""
import io
import threading

import multiSSH3


class RunningProc:
	"""A command that runs until it is terminated."""
	def __init__(self):
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


def _run(fake_host, monkeypatch, proc, timeout=0, passwds=None, **host_kwargs):
	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "/usr/bin/ssh", "sshpass": "/usr/bin/sshpass", "rsync": "/usr/bin/rsync", "scp": "/usr/bin/scp"})
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *args, **kwargs: proc)
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
	monkeypatch.setattr(multiSSH3, "_emo", True)
	proc = RunningProc()

	host = _run(fake_host, monkeypatch, proc, command="sleep 100")

	assert proc.signals == [multiSSH3.signal.SIGINT]
	assert host.returncode == 130
	assert host.stderr == ["Ctrl C detected, Emergency Stop!", "ssh was stopped: the command may still run on the host."]


def test_ctrl_c_that_reached_ssh_first(fake_host, monkeypatch):
	# the terminal's Ctrl C reaches ssh as well as mssh: ssh ends before mssh stops it, saying only
	# "Killed by signal 2." (hidden)
	monkeypatch.setattr(multiSSH3, "_emo", True)

	host = _run(fake_host, monkeypatch, EndedProc(255, b"Killed by signal 2.\n"), command="sleep 100")

	assert host.returncode == 130
	assert host.stderr == ["Ctrl C detected, Emergency Stop!", "ssh was stopped: the command may still run on the host."]


def test_ctrl_c_with_sshpass_is_not_a_success(fake_host, monkeypatch):
	# sshpass exits 0 when Ctrl C stops it
	monkeypatch.setattr(multiSSH3, "_emo", True)

	host = _run(fake_host, monkeypatch, EndedProc(0), passwds="pw", command="sleep 100")

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
