import multiSSH3


def test_read_unavailable_hosts_discards_malformed_and_expired(tmp_path):
	path = tmp_path / "unavailable.csv"
	path.write_text("live-a,150\nexpired,99\nbad\nmissing-number,nope\n")

	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100) == {"live-a": 150}


def test_read_unavailable_hosts_io_failure_returns_empty_and_warns(
	tmp_path, monkeypatch, capsys
):
	path = str(tmp_path / "unreadable.csv")

	def fail_open(*args, **kwargs):
		raise OSError("read failed")

	monkeypatch.setattr("builtins.open", fail_open)

	assert multiSSH3._read_unavailable_hosts_file(path, now=100) == {}
	assert capsys.readouterr().err.strip() == (
		"Warning: Unable to read unavailable hosts from {!r}: read failed".format(path)
	)


def test_write_unavailable_hosts_is_canonical_and_removes_available(tmp_path):
	path = tmp_path / "unavailable.csv"
	result = multiSSH3._write_unavailable_hosts_file(
		str(path),
		{"z-host": 180, "a-host": 170, "expired": 90},
		available_hosts={"z-host"},
		now=100,
	)

	assert result == {"a-host": 170}
	assert path.read_text() == "a-host,170\n"
	assert list(tmp_path.iterdir()) == [path]


def test_write_unavailable_hosts_cleans_temp_file_after_replace_error(tmp_path, monkeypatch, capsys):
	path = tmp_path / "unavailable.csv"
	monkeypatch.setattr(multiSSH3.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("replace failed")))

	result = multiSSH3._write_unavailable_hosts_file(str(path), {"a": 200}, now=100)

	assert result == {"a": 200}
	assert list(tmp_path.iterdir()) == []
	assert "replace failed" in capsys.readouterr().err


def test_process_run_marks_timeout_unavailable(tmp_path, fake_host, monkeypatch):
	path = tmp_path / "unavailable.csv"
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Timeout!"]
	unavailable = {}
	monkeypatch.setattr(multiSSH3.tempfile, "gettempdir", lambda: str(tmp_path))
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(path))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(
		timeout=1,
		password=None,
		max_connections=1,
		hosts=[host],
		return_unfinished=False,
		no_watch=True,
		json=False,
		no_output=True,
		greppable=False,
		unavailableHosts=unavailable,
		will_update_unreachable_hosts=True,
		pre_merge=False,
	)

	assert "mock-a" in unavailable
	assert multiSSH3._read_unavailable_hosts_file(str(path)) == unavailable
	assert multiSSH3.__globalUnavailableHosts == unavailable


def test_process_run_marks_timeout_unavailable_when_late_stderr_follows_marker(
	tmp_path, fake_host, monkeypatch
):
	path = tmp_path / "unavailable.csv"
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Timeout!", "late child stderr"]
	unavailable = {}
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(path))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(
		timeout=1,
		password=None,
		max_connections=1,
		hosts=[host],
		return_unfinished=False,
		no_watch=True,
		json=False,
		no_output=True,
		greppable=False,
		unavailableHosts=unavailable,
		will_update_unreachable_hosts=True,
		pre_merge=False,
	)

	assert set(unavailable) == {"mock-a"}


def test_run_on_hosts_without_skipping_preserves_unrelated_unavailable_records(
	tmp_path, monkeypatch
):
	path = tmp_path / "unavailable.csv"
	expiry = int(multiSSH3.time.monotonic() + 1000)
	path.write_text("available-now,{}\nstill-down,{}\n".format(expiry, expiry))
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(path))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)

	def finish_hosts(hosts, **kwargs):
		for host in hosts:
			host.returncode = 0
		return []

	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", finish_hosts)

	hosts = multiSSH3.run_command_on_hosts(
		hosts="available-now",
		commands="true",
		skip_unreachable=False,
		no_watch=True,
		no_output=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=True,
		pre_merge_hosts=False,
	)

	assert len(hosts) == 1
	assert multiSSH3._read_unavailable_hosts_file(str(path)) == {"still-down": expiry}
	assert multiSSH3.__globalUnavailableHosts == {"still-down": expiry}
