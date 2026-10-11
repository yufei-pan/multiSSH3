import pytest

import multiSSH3


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
	monkeypatch.setattr(multiSSH3, "__running_procs", {child, dead_child})
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: commands.append(command))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.signal_handler(None, None)

	assert exc_info.value.code == 1
	assert child.killed
	assert commands == []


def test_input_with_timeout_returns_inline_input(monkeypatch):
	class InlineThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			self.target()

	monkeypatch.setattr(multiSSH3.threading, "Thread", InlineThread)
	monkeypatch.setattr(multiSSH3.sys.stdin, "readline", lambda: "multiple\n")

	assert multiSSH3.input_with_timeout_and_countdown(3) == "multiple"


def test_input_with_timeout_returns_none(monkeypatch):
	class IdleThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			return None

	ticks = iter([0.0, 2.0])
	monkeypatch.setattr(multiSSH3.threading, "Thread", IdleThread)
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	assert multiSSH3.input_with_timeout_and_countdown(1) is None


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
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(tmp_path / "unavailable.csv"))
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
