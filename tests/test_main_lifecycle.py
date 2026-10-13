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


def _main_with_unreachable_cached(monkeypatch, tmp_path, unreachable, argv):
	'''Run main(argv) with unreachable cached as recently unreachable; returns (exit code, hosts run on).'''
	path = tmp_path / "unavailable.csv"
	expiry = int(multiSSH3.time.monotonic() + 300)
	path.write_text("#boot_id,boot-a\n" + "".join("{},{}\n".format(name, expiry) for name in unreachable))
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())
	ran = []

	def succeed(host, sem, timeout=60, passwds=None, **kwargs):
		ran.append(host.name)
		host.stdout.append("ok")
		host.returncode = 0

	monkeypatch.setattr(multiSSH3, "run_command", succeed)
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(argv + ["--no_watch", "--no_history", "-ef", str(tmp_path / "none.env")])
	return exc_info.value.code, ran


def test_main_fails_when_a_host_is_skipped_as_unreachable(monkeypatch, tmp_path, capsys):
	code, ran = _main_with_unreachable_cached(monkeypatch, tmp_path, ["web1"], ["web1,app1", "systemctl restart x"])

	err = capsys.readouterr().err
	assert ran == ["app1"]
	assert code == 1
	assert "All hosts returned 0" not in err
	assert "failed_hosts: web1" in err
	assert "Skipped 1 host unreachable in a recent run, without trying it: web1" in err


def test_script_mode_does_not_report_success_when_hosts_were_skipped(monkeypatch, tmp_path, capsys):
	code, ran = _main_with_unreachable_cached(monkeypatch, tmp_path, ["web1", "app1"], ["--script", "web1,app1", "deploy --now"])

	out = capsys.readouterr().out
	assert ran == []
	assert code == 2
	assert "Success" not in out
	assert "rc: 255" in out and "unreachable" in out


def _main_recording_runs(monkeypatch, tmp_path, argv):
	'''Run main(argv) with names unresolvable and commands succeeding; returns (exit code, hosts run on).'''
	monkeypatch.setattr(multiSSH3, "getIP", _names_only_resolve_ips)
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: None)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())
	ran = []

	def succeed(host, sem, timeout=60, passwds=None, **kwargs):
		ran.append(host.name)
		host.returncode = 0

	monkeypatch.setattr(multiSSH3, "run_command", succeed)
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(argv + ["--no_watch", "--no_history", "-ef", str(tmp_path / "none.env")])
	return exc_info.value.code, ran


@pytest.mark.parametrize("target, reason", [
	("node[10-1]", "the range [10-1] counts down"),
	("root@node[3-1]", "the range [3-1] counts down"),
	("10.0.0.20-10", "the range 20-10 counts down"),
])
def test_target_naming_no_hosts_stops_with_an_error(monkeypatch, tmp_path, capsys, target, reason):
	code, ran = _main_recording_runs(monkeypatch, tmp_path, [target, "uptime"])

	err = capsys.readouterr().err
	assert ran == []
	assert code == 1
	assert "Error: {!r} names no hosts: {}".format(target, reason) in err
	assert "Exiting: no hosts to run on" in err
	assert "All hosts returned 0" not in err


def test_empty_alias_as_target_stops_with_an_error(monkeypatch, tmp_path, capsys):
	monkeypatch.setenv("MSSH_TEST_EMPTY_GROUP", "")

	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["MSSH_TEST_EMPTY_GROUP", "uptime"])

	err = capsys.readouterr().err
	assert ran == []
	assert code == 1
	assert "Error: 'MSSH_TEST_EMPTY_GROUP' names no hosts: the environment variable MSSH_TEST_EMPTY_GROUP is ''" in err


def test_empty_group_inside_an_alias_is_not_an_error(monkeypatch, tmp_path, capsys):
	# the README's env file example keeps empty groups (eu='') inside bigger ones
	monkeypatch.setenv("MSSH_TEST_EMPTY_GROUP", "")
	monkeypatch.setenv("MSSH_TEST_ALL", "127.0.0.1,MSSH_TEST_EMPTY_GROUP")

	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["MSSH_TEST_ALL", "uptime"])

	assert ran == ["127.0.0.1"]
	assert code == 0
	assert "names no hosts" not in capsys.readouterr().err


def test_a_host_token_naming_no_hosts_fails_the_run_but_the_rest_runs(monkeypatch, tmp_path, capsys):
	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["node[10-1],127.0.0.1", "uptime", "--repeat", "2"])

	err = capsys.readouterr().err
	assert ran == ["127.0.0.1", "127.0.0.1"]
	assert code == 1  # counted once, like a host name that does not resolve
	assert err.count("Error: 'node[10-1]' names no hosts: the range [10-1] counts down") == 1
	assert "failed_hosts: node[10-1]" in err


def test_target_of_invalid_names_only_stops_with_their_count(monkeypatch, tmp_path, capsys):
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)

	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["nosuch-a,nosuch-b", "uptime"])

	err = capsys.readouterr().err
	assert ran == []
	assert code == 2
	assert "Exiting: no hosts to run on" in err


def test_skip_hosts_excluding_every_host_warns(monkeypatch, tmp_path, capsys):
	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["127.0.0.1", "uptime", "-X", "127.0.0.1"])

	assert ran == []
	assert code == 0
	assert "Warning: -X, --skip_hosts leaves no hosts to run on" in capsys.readouterr().err


def test_library_call_on_a_target_naming_no_hosts_returns_nothing(monkeypatch, capsys):
	hosts = multiSSH3.run_command_on_hosts(hosts="node[10-1]", commands=["true"], no_watch=True, quiet=True,
		no_history=True, called=True, will_update_unreachable_hosts=False)

	assert hosts == []
	assert "names no hosts" not in capsys.readouterr().err


def test_failed_hosts_lists_names_that_do_not_resolve(monkeypatch, tmp_path, capsys):
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)

	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["nosuch-a,127.0.0.1", "uptime", "--success_hosts"])

	err = capsys.readouterr().err
	assert ran == ["127.0.0.1"]
	assert code == 1
	assert "failed_hosts: nosuch-a\n" in err
	assert "succeeded_hosts: 127.0.0.1\n" in err


def test_summary_does_not_repeat_host_name_errors(monkeypatch, tmp_path, capsys):
	# an alias naming $nosuch_a validates "$nosuch_a"; the summary must not validate "nosuch_a" again
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)
	monkeypatch.setenv("MSSH_TEST_GROUP", "127.0.0.1,$nosuch_a")

	code, ran = _main_recording_runs(monkeypatch, tmp_path, ["MSSH_TEST_GROUP", "uptime"])

	err = capsys.readouterr().err
	assert ran == ["127.0.0.1"]
	assert code == 1
	assert err.count("Error: 'nosuch_a' is not a valid hostname or IP address!") == 1
	assert "failed_hosts: nosuch_a\n" in err
