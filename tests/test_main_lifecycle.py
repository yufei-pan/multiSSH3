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
