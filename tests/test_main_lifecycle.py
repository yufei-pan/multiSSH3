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


def test_signal_handler_second_interrupt_exits(monkeypatch):
	commands = []
	monkeypatch.setattr(multiSSH3, "_emo", True)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: commands.append(command))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.signal_handler(None, None)

	assert exc_info.value.code == 1
	assert commands and commands[0].startswith("pkill -ef")


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
