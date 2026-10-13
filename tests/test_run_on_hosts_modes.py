import os

import pytest

import multiSSH3


def _mock_run(monkeypatch):
	monkeypatch.setattr(
		multiSSH3,
		"getIP",
		lambda hostname, local=False: hostname.split("@")[-1],
	)

	def fake_run(host, sem, timeout=60, passwds=None, **kwargs):
		host.stdout.append(f"ok-{host.name}")
		host.returncode = 0

	monkeypatch.setattr(multiSSH3, "run_command", fake_run)


def test_run_on_hosts_no_start(monkeypatch):
	_mock_run(monkeypatch)
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a,mock-b",
		commands="true",
		no_start=True,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	assert len(hosts) == 2
	assert all(h.returncode is None for h in hosts)


def test_run_on_hosts_oneonone(monkeypatch):
	_mock_run(monkeypatch)
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a,mock-b",
		commands=["echo a", "echo b"],
		oneonone=True,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	assert len(hosts) == 2
	assert {h.command for h in hosts} == {"echo a", "echo b"}


def test_run_on_hosts_skip_hosts(monkeypatch):
	_mock_run(monkeypatch)
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a,mock-b,mock-c",
		commands="true",
		skip_hosts="mock-b",
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	names = {h.name for h in hosts}
	assert "mock-b" not in names
	assert "mock-a" in names and "mock-c" in names


def test_run_on_hosts_file_sync_builds_hosts(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	src = tmp_path / "src.txt"
	src.write_text("data")
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a",
		commands=str(tmp_path / "dest"),
		file=[str(src)],
		file_sync=True,
		scp=True,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	assert len(hosts) == 1
	assert hosts[0].files == [str(src.resolve())]
	assert hosts[0].command == str(src.resolve().parent) + os.path.sep
	assert hosts[0].scp is True
	assert hosts[0].gatherMode is False


def test_run_on_hosts_gather_mode(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	dest = tmp_path / "local"
	dest.mkdir()
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a",
		commands=str(dest),
		file=["/tmp/remote"],
		gather_mode=True,
		scp=True,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	assert len(hosts) >= 1
	assert hosts[0].gatherMode is True


@pytest.mark.parametrize(
	"requested,safe_limit,expected",
	[
		(None, 100, 32),
		(0, 100, 100),
		(0, 0, 32),
		(-2, 100, 16),
		(3, 100, 3),
		(200, 100, 100),
	],
)
def test_normalize_max_connections(requested, safe_limit, expected, monkeypatch):
	monkeypatch.setattr(multiSSH3.os, "cpu_count", lambda: 8)
	monkeypatch.setattr(multiSSH3, "__max_connections_nofile_limit_supported", safe_limit)

	assert multiSSH3._normalize_max_connections(requested) == expected


def test_run_on_hosts_zero_forwards_safe_limit(monkeypatch):
	forwarded = []
	monkeypatch.setattr(multiSSH3, "__max_connections_nofile_limit_supported", 17)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	monkeypatch.setattr(
		multiSSH3,
		"processRunOnHosts",
		lambda *args, **kwargs: forwarded.append(kwargs["max_connections"]),
	)

	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a",
		commands="true",
		max_connections=0,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)

	assert len(hosts) == 1
	assert forwarded == [17]


def test_run_on_hosts_username_prefix(monkeypatch):
	_mock_run(monkeypatch)
	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a",
		commands="true",
		username="bob",
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)
	assert hosts[0].name.startswith("bob@") or "bob" in hosts[0].name


def test_file_sync_missing_globs_raises_when_called(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	missing = tmp_path / "does-not-exist-*.txt"
	try:
		multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			commands=str(tmp_path / "dest"),
			file=[str(missing)],
			file_sync=True,
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)
		assert False, "expected MultiSSHError"
	except multiSSH3.MultiSSHError as e:
		assert e.code == 66


def test_oneonone_count_mismatch_raises_when_called(monkeypatch):
	_mock_run(monkeypatch)
	try:
		multiSSH3.run_command_on_hosts(
			hosts="mock-a,mock-b",
			commands=["echo only-one"],
			oneonone=True,
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)
		assert False, "expected MultiSSHError"
	except multiSSH3.MultiSSHError as e:
		assert e.code == 255


def test_file_sync_missing_globs_exits_when_cli(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	missing = tmp_path / "does-not-exist-*.txt"
	with pytest.raises(SystemExit) as ei:
		multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			commands=str(tmp_path / "dest"),
			file=[str(missing)],
			file_sync=True,
			no_watch=True,
			quiet=True,
			no_history=True,
			called=False,
			will_update_unreachable_hosts=False,
		)
	assert ei.value.code == 66


def _oneonone(monkeypatch, tmp_path, hosts, commands, **kwargs):
	_mock_run(monkeypatch)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	return multiSSH3.run_command_on_hosts(
		hosts=hosts,
		commands=commands,
		oneonone=True,
		no_start=True,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
		**kwargs,
	)


def test_oneonone_pairs_commands_in_given_host_order(monkeypatch, tmp_path):
	hosts = _oneonone(monkeypatch, tmp_path, "mock-z,mock-a[9-10],mock-m", ["cz", "ca9", "ca10", "cm"])

	assert [(h.name, h.command) for h in hosts] == [
		("mock-z", "cz"), ("mock-a9", "ca9"), ("mock-a10", "ca10"), ("mock-m", "cm"),
	]


def test_oneonone_keeps_list_order_and_username(monkeypatch, tmp_path):
	hosts = _oneonone(monkeypatch, tmp_path, ["mock-b", "root@mock-a"], ["cb", "ca"], username="bob")

	assert [(h.name, h.command) for h in hosts] == [("bob@mock-b", "cb"), ("root@mock-a", "ca")]


def test_oneonone_skip_hosts_are_left_out_before_pairing(monkeypatch, tmp_path):
	hosts = _oneonone(monkeypatch, tmp_path, "mock-a,mock-b,mock-c", ["cb", "cc"], skip_hosts="mock-a")

	assert [(h.name, h.command) for h in hosts] == [("mock-b", "cb"), ("mock-c", "cc")]


def test_oneonone_unreachable_host_keeps_its_command_slot(monkeypatch, tmp_path):
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {"mock-a": int(multiSSH3.time.monotonic() + 100)})

	hosts = _oneonone(monkeypatch, tmp_path, "mock-a,mock-b", ["ca", "cb"], skip_unreachable=True)

	# the unreachable host is returned with its command, not run and failed
	assert [(h.name, h.command, h.skipped, h.returncode) for h in hosts] == [
		("mock-a", "ca", True, 255), ("mock-b", "cb", False, None)]


def test_copy_id_does_not_repeat_username_and_quotes_arguments(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setitem(multiSSH3._binPaths, "ssh-copy-id", "ssh-copy-id")
	monkeypatch.delitem(multiSSH3._binPaths, "sshpass", raising=False)
	commands = []
	monkeypatch.setattr(multiSSH3.os, "system", commands.append)

	with pytest.raises(multiSSH3.MultiSSHError):
		multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			copy_id=True,
			username="bob",
			identity_file="~/my key",
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)

	assert commands == ["ssh-copy-id -i '{}' bob@mock-a".format(os.path.expanduser("~/my key"))]


def test_copy_id_with_sshpass_quotes_password(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setitem(multiSSH3._binPaths, "ssh-copy-id", "ssh-copy-id")
	monkeypatch.setitem(multiSSH3._binPaths, "sshpass", "sshpass")
	started = []
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: started.extend(kwargs["hosts"]))

	with pytest.raises(multiSSH3.MultiSSHError):
		multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			copy_id=True,
			username="bob",
			password="p@ss word;",
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)

	assert [h.command for h in started] == ["sshpass -p 'p@ss word;' ssh-copy-id bob@mock-a"]


def test_missing_globs_error_names_every_pattern(monkeypatch, tmp_path):
	_mock_run(monkeypatch)
	first = str(tmp_path / "missing-a-*.txt")
	second = str(tmp_path / "missing-b-*.txt")
	with pytest.raises(multiSSH3.MultiSSHError) as ei:
		multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			commands=str(tmp_path / "dest"),
			file=[first, second],
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)
	assert ei.value.code == 66
	assert first in str(ei.value)
	assert second in str(ei.value)
