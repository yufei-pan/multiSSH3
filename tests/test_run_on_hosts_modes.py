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
	assert len(hosts) >= 1
	assert hosts[0].files or hosts[0].scp or hosts[0].command


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
