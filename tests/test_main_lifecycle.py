import io
import json
import os
import select
import struct
import subprocess
import sys
import threading
import time

import pytest

import multiSSH3
from conftest import MULTISSH3_PY


def test_main_runs_immediately_and_sleeps_only_between_repeats(fake_host, monkeypatch):
	events = []
	host = fake_host("mock-a", "true")
	host.returncode = 0

	def fake_run(**kwargs):
		events.append("run")
		return [host]

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: events.append(("sleep", seconds)))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["mock-a", "true", "--repeat", "3", "--interval", "2", "--no_output", "--no_history"])

	assert exc_info.value.code == 0
	assert events == ["run", ("sleep", 2), "run", ("sleep", 2), "run"]


def test_main_aggregates_failed_and_successful_hosts(fake_host, monkeypatch, capsys):
	failed = fake_host("bad", "false")
	failed.returncode = 7
	succeeded = fake_host("good", "true")
	succeeded.returncode = 0
	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", lambda **kwargs: [failed, succeeded])

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["mock-a", "true", "--success_hosts", "--no_history"])

	assert exc_info.value.code == 1
	assert multiSSH3.__failedHosts == {"bad"}
	assert "failed_hosts: bad" in capsys.readouterr().err


def test_record_command_history_writes_timestamped_command(tmp_path, monkeypatch):
	path = tmp_path / "history"
	monkeypatch.setattr(multiSSH3.time, "time", lambda: 1234)
	multiSSH3.record_command_history({
		"hosts": "127.0.0.1",
		"commands": ["true"],
		"history_file": str(path),
	})

	line = path.read_text()
	assert line.startswith("1234\t")
	assert "127.0.0.1" in line
	assert "true" in line


def test_signal_handler_first_interrupt_sets_emergency_stop(monkeypatch, capsys):
	monkeypatch.setattr(multiSSH3, "_emo", False)
	monkeypatch.setattr(multiSSH3, "_commands_started", True)  # commands are running
	multiSSH3.signal_handler(None, None)

	assert multiSSH3._emo is True
	assert "Ctrl C caught" in capsys.readouterr().err


def test_signal_handler_second_interrupt_kills_only_own_children(monkeypatch):
	class Proc:
		killed = False
		def kill(self):
			self.killed = True

	class DeadProc:
		def kill(self):
			raise ProcessLookupError()

	commands = []
	child, dead_child = Proc(), DeadProc()
	monkeypatch.setattr(multiSSH3, "_emo", True)
	monkeypatch.setattr(multiSSH3, "_commands_started", True)
	monkeypatch.setattr(multiSSH3, "__running_procs", {child, dead_child})
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: commands.append(command))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.signal_handler(None, None)

	assert exc_info.value.code == 1
	assert child.killed
	assert commands == []


class _TerminalWithoutFileno:
	"""A terminal stdin select() cannot wait on (e.g. IDLE's): the prompt reads it with a thread."""
	def __init__(self, line=""):
		self.line = line

	def isatty(self):
		return True

	def fileno(self):
		raise io.UnsupportedOperation("no file descriptor")

	def readline(self):
		return self.line


def test_input_with_timeout_returns_inline_input(monkeypatch):
	class InlineThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			self.target()

	monkeypatch.setattr(multiSSH3.threading, "Thread", InlineThread)
	monkeypatch.setattr(sys, "stdin", _TerminalWithoutFileno("multiple\n"))

	assert multiSSH3.input_with_timeout_and_countdown(3) == "multiple"


def test_input_with_timeout_returns_none(monkeypatch):
	class IdleThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			return None

	ticks = iter([0.0, 2.0])
	monkeypatch.setattr(sys, "stdin", _TerminalWithoutFileno())
	monkeypatch.setattr(multiSSH3.threading, "Thread", IdleThread)
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	assert multiSSH3.input_with_timeout_and_countdown(1) is None


@pytest.fixture
def terminal_stdin(monkeypatch):
	"""stdin on a fresh pty: returns (master, slave), what is written to master is what the user types."""
	pty = pytest.importorskip("pty")
	master, slave = pty.openpty()
	monkeypatch.setattr(sys, "stdin", io.open(slave, "r", closefd=False))
	yield master, slave
	os.close(master)
	os.close(slave)


def _new_threads(before):
	return [thread for thread in threading.enumerate() if thread not in before and thread.is_alive()]


def _next_read(fd, settle=0.3):
	"""What the next reader of the terminal gets, without blocking (a stray reader may take it first)."""
	fcntl = pytest.importorskip("fcntl")
	time.sleep(settle)
	flags = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
	try:
		return os.read(fd, 1024)
	except BlockingIOError:
		return b""
	finally:
		fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def test_prompt_returns_the_line_typed_at_the_terminal(terminal_stdin):
	master, slave = terminal_stdin
	os.write(master, b" m \n")

	assert multiSSH3.input_with_timeout_and_countdown(3) == "m"


def test_prompt_leaves_no_reader_behind_when_time_is_up(terminal_stdin, capsys):
	# the TUI starts right after the prompt: a reader left waiting on the terminal took its first line
	master, slave = terminal_stdin
	before = set(threading.enumerate())

	assert multiSSH3.input_with_timeout_and_countdown(2) is None

	assert _new_threads(before) == []
	os.write(master, b"hi\n")
	assert _next_read(slave) == b"hi\n"
	err = capsys.readouterr().err
	assert "Please enter your selection [2s]: " in err
	assert "\rPlease enter your selection [1s]: " in err


def test_prompt_drops_a_half_typed_answer_when_time_is_up(terminal_stdin):
	# typed during the prompt, it was meant for the prompt: it must not end up in the next reader's line
	master, slave = terminal_stdin
	os.write(master, b"m")

	assert multiSSH3.input_with_timeout_and_countdown(1) is None

	os.write(master, b"\n")
	assert _next_read(slave) == b"\n"


def test_prompt_on_windows_reads_the_console_with_a_thread(monkeypatch):
	# select() only waits on sockets there
	def no_select(*args):
		raise AssertionError("select() on a Windows console")
	monkeypatch.setattr(select, "select", no_select)
	stdin = _TerminalWithoutFileno("m\n")
	stdin.fileno = lambda: 0
	monkeypatch.setattr(sys, "stdin", stdin)
	monkeypatch.setattr(multiSSH3.os, "name", "nt")

	assert multiSSH3.input_with_timeout_and_countdown(3) == "m"


def test_prompt_takes_the_default_at_once_when_stdin_is_not_a_terminal(monkeypatch, capsys):
	# e.g. `while read host; do mssh $host ls pwd; done < hosts`: the pipe holds the loop's next hosts, not an answer
	read_end, write_end = os.pipe()
	os.write(write_end, b"zz-nohost-2.invalid\nzz-nohost-3.invalid\n")
	os.close(write_end)
	monkeypatch.setattr(sys, "stdin", io.open(read_end, "r", closefd=False))
	start = time.monotonic()
	try:
		assert multiSSH3.input_with_timeout_and_countdown(3) is None
		assert time.monotonic() - start < 1
		assert os.read(read_end, 1024) == b"zz-nohost-2.invalid\nzz-nohost-3.invalid\n"
	finally:
		os.close(read_end)
	assert "stdin is not a terminal" in capsys.readouterr().err


_FAKE_SSH = '''#!{python}
import os, select, sys, time
if sys.argv[1:2] == ["-G"]:
	print("hostname " + sys.argv[-1])
	sys.exit(0)
log = os.environ["FAKE_SSH_LOG"]
with open(log, "a") as f:
	f.write("START\\n")
got = b""
deadline = time.monotonic() + 8
while b"\\n" not in got and time.monotonic() < deadline:
	if select.select([0], [], [], 0.1)[0]:
		data = os.read(0, 1024)
		if not data:
			break
		got += data
with open(log, "a") as f:
	f.write("GOT " + repr(got) + "\\n")
'''


def test_tui_gets_the_first_line_typed_after_the_one_word_prompt(tmp_path):
	# `mssh 127.0.0.1 sleep 9` asks whether `sleep 9` is one command; once the prompt timed out, the
	# first line typed into the TUI must reach the command (a leftover prompt reader used to take it)
	pty = pytest.importorskip("pty")
	termios = pytest.importorskip("termios")
	fcntl = pytest.importorskip("fcntl")
	pytest.importorskip("curses")
	fake_ssh = tmp_path / "fake_ssh"
	fake_ssh.write_text(_FAKE_SSH.format(python=sys.executable))
	fake_ssh.chmod(0o755)
	# in HOME, not --config_file: the program paths are set from the config files read at import
	config = tmp_path / ".multiSSH3.config.json"
	config.write_text(json.dumps({"_sshPath": str(fake_ssh), "_scpPath": str(fake_ssh), "_rsyncPath": str(fake_ssh)}))
	config.chmod(0o600)
	hosts_file = tmp_path / "hosts"
	hosts_file.write_text("")
	runtime = tmp_path / "run"
	runtime.mkdir(mode=0o700)
	log = tmp_path / "fake_ssh.log"
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime), TERM="xterm-256color", FAKE_SSH_LOG=str(log))
	for name in ("COLUMNS", "LINES"):
		env.pop(name, None)
	# never let a real ssh run: check the program mssh will call before running it
	ssh_used = subprocess.run(
		[sys.executable, "-c", "import multiSSH3; print(multiSSH3._binPaths['ssh'])"],
		env=env, cwd=str(MULTISSH3_PY.parent), stdout=subprocess.PIPE, universal_newlines=True, timeout=60,
	).stdout.strip()
	assert ssh_used == str(fake_ssh)
	master, slave = pty.openpty()
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
	proc = subprocess.Popen(
		[sys.executable, str(MULTISSH3_PY), "-ef", "/dev/null", "--host_file", str(hosts_file), "--no_history",
		 "127.0.0.1", "sleep", "9"],
		stdin=slave, stdout=slave, stderr=slave, env=env, cwd=str(tmp_path), start_new_session=True,
	)
	os.close(slave)
	screen = bytearray()

	def read_until(done, timeout):
		end = time.monotonic() + timeout
		while not done() and time.monotonic() < end:
			if select.select([master], [], [], 0.05)[0]:
				try:
					data = os.read(master, 65536)
				except OSError:
					break
				if not data:
					break
				screen.extend(data)
		return done()

	def logged(text):
		return log.exists() and text in log.read_text()

	try:
		assert read_until(lambda: b"Multiple one word command" in screen, 15), bytes(screen)
		# the prompt times out (3 s), the command starts, then curses takes the terminal (alternate screen)
		assert read_until(lambda: logged("START") and b"\x1b[?1049h" in screen, 15), bytes(screen)
		read_until(lambda: False, 0.5)
		os.write(master, b"hi\r")
		assert read_until(lambda: logged("GOT"), 15), bytes(screen)
		assert "GOT b'hi\\n'" in log.read_text()
		read_until(lambda: proc.poll() is not None, 10)
	finally:
		if proc.poll() is None:
			proc.kill()
		proc.wait(timeout=10)
		os.close(master)


def test_process_config_file_generates_and_exits_without_work(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["--generate_config_file"])
	calls = []
	monkeypatch.setattr(
		multiSSH3,
		"write_default_config",
		lambda parsed, CONFIG_FILE=None, force=False: calls.append((CONFIG_FILE, force)),
	)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_config_file(args)

	assert exc_info.value.code == 0
	assert calls == [(None, True)]


def test_process_config_file_generates_and_returns_when_commands_remain(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["mock-a", "true", "--generate_config_file"])
	calls = []
	monkeypatch.setattr(
		multiSSH3,
		"write_default_config",
		lambda parsed, CONFIG_FILE=None, force=False: calls.append((CONFIG_FILE, force)),
	)

	result = multiSSH3.process_config_file(args)

	assert result is args
	assert calls == [(None, True)]


def test_exit_with_code_caps_status_at_255(monkeypatch):
	monkeypatch.setattr(multiSSH3, "__returnZero", False)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3._exit_with_code(256)

	assert exc_info.value.code == 255


def test_main_counts_each_failed_host_when_outputs_merge(monkeypatch, tmp_path, capsys):
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())

	def fail_same_way(host, sem, timeout=60, passwds=None, **kwargs):
		host.stderr.append("same error")
		host.returncode = 1

	monkeypatch.setattr(multiSSH3, "run_command", fail_same_way)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["mock-[1-3]", "true", "--no_watch", "--no_history"])

	assert exc_info.value.code == 3
	assert multiSSH3.__failedHosts == {"mock-1", "mock-2", "mock-3"}
	assert "Failed hosts (Return Code not 0) count: 3" in capsys.readouterr().err


def test_record_command_history_creates_owner_only_file(tmp_path):
	import os
	import stat
	path = tmp_path / "history"
	multiSSH3.record_command_history({
		"hosts": "127.0.0.1",
		"commands": ["true"],
		"password": "secret",
		"history_file": str(path),
	})

	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
	assert "secret" in path.read_text()


def _names_only_resolve_ips(hostname, local=False):
	# keep host validation hermetic: IP literals resolve, names do not
	return hostname if hostname[:1].isdigit() else None


def test_main_no_env_ignores_environment_host_aliases(monkeypatch, tmp_path):
	monkeypatch.setenv("MSSH_TEST_ENV_HOSTS", "127.0.0.2")
	monkeypatch.setattr(multiSSH3, "getIP", _names_only_resolve_ips)
	ran = []
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: ran.extend(h.name for h in kwargs["hosts"]))

	# main() echoes the command (expanding hosts) before it runs it
	with pytest.raises(SystemExit):
		multiSSH3.main(["--no_env", "-q", "--no_history", "-ef", str(tmp_path / "none.env"), "MSSH_TEST_ENV_HOSTS", "true"])

	assert ran == []


def test_main_counts_failures_from_every_repeat(fake_host, monkeypatch, capsys):
	return_codes = iter([7, 0, 0])

	def fake_run(**kwargs):
		host = fake_host("flaky", "check")
		host.returncode = next(return_codes)
		return [host]

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["127.0.0.1", "check", "--repeat", "3", "--no_history"])

	assert exc_info.value.code == 1
	assert "failed_hosts: flaky" in capsys.readouterr().err


def test_main_repeat_counts_failing_hosts_once_and_releases_old_runs(fake_host, monkeypatch, capsys):
	import gc
	import weakref

	earlier_runs = []

	def fake_run(**kwargs):
		gc.collect()
		assert all(ref() is None for ref in earlier_runs)  # earlier runs' output is not kept
		hosts = [fake_host("bad1", "check"), fake_host("bad2", "check")]
		for host in hosts:
			host.returncode = 1
		earlier_runs.append(weakref.ref(hosts[0]))
		return hosts

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["127.0.0.1", "check", "--repeat", "3", "--no_history"])

	assert exc_info.value.code == 2  # two hosts failed, not 2 x 3 runs
	assert "count: 2" in capsys.readouterr().err


def test_history_records_the_cli_options_not_the_default_env_files(monkeypatch, tmp_path):
	history = tmp_path / "history"
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: None)

	with pytest.raises(SystemExit):
		multiSSH3.main(["127.0.0.1", "true", "--repeat", "2", "-hf", str(history)])

	line = history.read_text().splitlines()[0]
	# replaying -efs=... would mark every default env file explicit, skipping the ownership check
	assert "-efs=" not in line
	assert "-r=2" in line


def test_main_repeat_counts_hosts_failing_in_different_runs(fake_host, monkeypatch, capsys):
	failing = iter(["hostA", "hostB"])

	def fake_run(**kwargs):
		host = fake_host(next(failing), "check")
		host.returncode = 1
		return [host]

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["127.0.0.1", "check", "--repeat", "2", "--no_history"])

	assert exc_info.value.code == 2
	assert "failed_hosts: hostA,hostB" in capsys.readouterr().err


def test_repeated_command_is_recorded_in_history_once(monkeypatch, tmp_path):
	history = tmp_path / "history"
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: None)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	with pytest.raises(SystemExit):
		multiSSH3.main(["127.0.0.1", "true", "--repeat", "3", "-hf", str(history)])

	lines = history.read_text().splitlines()
	assert len(lines) == 1  # replaying it repeats 3 times, not 3 x 3
	assert "-r=3" in lines[0]


def test_one_ctrl_c_before_any_command_starts_runs_nothing(tmp_path):
	import signal
	import subprocess
	import sys
	import time
	from pathlib import Path

	marker = tmp_path / "ran"
	script = tmp_path / "mssh_slow_lookup.py"
	script.write_text(
		"import sys, time\n"
		"sys.path.insert(0, {root!r})\n"
		"import multiSSH3\n"
		"multiSSH3._resolve_dns = lambda hostname: time.sleep(3)\n"
		"multiSSH3._ssh_config_target = lambda hostname: None\n"
		"prefetch = multiSSH3._prefetch_ips\n"
		"def announce(names):\n"
		"    print('resolving', flush=True)\n"
		"    prefetch(names)\n"
		"multiSSH3._prefetch_ips = announce\n"
		"multiSSH3.processRunOnHosts = lambda **kwargs: open({marker!r}, 'w').close()\n"
		"multiSSH3.main(['-q', '-I', 'slowhost[1-64]', 'reboot'])\n".format(
			root=str(Path(multiSSH3.__file__).resolve().parent), marker=str(marker)))
	proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmp_path)
	assert proc.stdout.readline().strip() == b"resolving"
	time.sleep(0.3)
	started = time.monotonic()
	proc.send_signal(signal.SIGINT)  # once
	try:
		proc.wait(timeout=20)
	finally:
		proc.kill()

	assert time.monotonic() - started < 2
	assert proc.returncode == 1
	assert not marker.exists()  # reboot was not sent to any host


def test_ctrl_c_during_a_run_skips_the_remaining_repeats(fake_host, monkeypatch):
	runs = []

	def fake_run(**kwargs):
		runs.append(1)
		multiSSH3._emo = True  # Ctrl-C while the command runs
		host = fake_host("mock-a", "true")
		host.returncode = 137
		return [host]

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	with pytest.raises(SystemExit):
		multiSSH3.main(["127.0.0.1", "true", "--repeat", "3", "--no_history"])

	assert len(runs) == 1


def test_cli_run_does_not_start_after_a_ctrl_c(monkeypatch):
	ran = []
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: ran.append(1))
	monkeypatch.setattr(multiSSH3, "_emo", True)  # e.g. pressed during the previous repeat

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.run_command_on_hosts(hosts="127.0.0.1", commands=["true"], no_watch=True, quiet=True,
			no_history=True, called=False, will_update_unreachable_hosts=False)

	assert exc_info.value.code == 1
	assert ran == []


def test_ctrl_c_during_the_first_command_skips_the_next(monkeypatch):
	ran = []

	def fake_process(**kwargs):
		ran.append(kwargs["hosts"][0].command)
		multiSSH3._emo = True

	monkeypatch.setattr(multiSSH3, "processRunOnHosts", fake_process)
	monkeypatch.setattr(multiSSH3, "_emo", False)

	multiSSH3.run_command_on_hosts(hosts="127.0.0.1", commands=["first", "second"], no_watch=True, quiet=True,
		no_history=True, called=False, will_update_unreachable_hosts=False)

	assert ran == ["first"]
