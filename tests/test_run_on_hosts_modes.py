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


def test_run_on_hosts_max_connections_variants(monkeypatch):
	_mock_run(monkeypatch)
	for max_conn in (None, 0, -2, 3):
		hosts = multiSSH3.run_command_on_hosts(
			hosts="mock-a",
			commands="true",
			max_connections=max_conn,
			no_watch=True,
			quiet=True,
			no_history=True,
			called=True,
			will_update_unreachable_hosts=False,
		)
		assert len(hosts) == 1
		assert hosts[0].returncode == 0


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
