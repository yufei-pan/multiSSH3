import os
import stat

import pytest

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


def test_write_unavailable_hosts_is_canonical_and_removes_available(tmp_path, monkeypatch):
	path = tmp_path / "unavailable.csv"
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: None)
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
	# the cache is optional, a full or read-only disk must not warn on every run
	assert "replace failed" not in capsys.readouterr().err


def test_write_unavailable_hosts_error_is_shown_with_debug(tmp_path, monkeypatch, capsys):
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", True)
	monkeypatch.setattr(multiSSH3.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("replace failed")))

	multiSSH3._write_unavailable_hosts_file(str(tmp_path / "unavailable.csv"), {"a": 200}, now=100)

	assert "replace failed" in capsys.readouterr().err


def test_process_run_marks_timeout_unavailable(tmp_path, fake_host, monkeypatch):
	path = tmp_path / "unavailable.csv"
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Timeout!"]
	unavailable = {}
	monkeypatch.setattr(multiSSH3.tempfile, "gettempdir", lambda: str(tmp_path))
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
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
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
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
	path.write_text("#boot_id,boot-a\navailable-now,{}\nstill-down,{}\n".format(expiry, expiry))
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
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


def test_read_unavailable_hosts_removes_file_from_previous_boot(tmp_path, monkeypatch):
	path = tmp_path / "unavailable.csv"
	path.write_text("#boot_id,old-boot\nhost-a,150\n")
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "new-boot")

	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100, max_ttl=600) == {}
	assert not path.exists()


def test_read_unavailable_hosts_trusts_matching_boot_id_over_ttl(tmp_path, monkeypatch):
	path = tmp_path / "unavailable.csv"
	path.write_text("#boot_id,boot-a\nhost-a,100000\n")
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")

	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100, max_ttl=600) == {"host-a": 100000}


def test_read_unavailable_hosts_without_boot_id_drops_file_beyond_ttl(tmp_path, monkeypatch):
	path = tmp_path / "unavailable.csv"
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: None)
	path.write_text("host-a,150\n")
	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100, max_ttl=600) == {"host-a": 150}

	path.write_text("host-a,150\nhost-b,100000\n")
	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100, max_ttl=600) == {}
	assert not path.exists()


def test_write_unavailable_hosts_records_boot_id(tmp_path, monkeypatch):
	path = tmp_path / "unavailable.csv"
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")

	multiSSH3._write_unavailable_hosts_file(str(path), {"a": 200}, now=100)

	assert path.read_text() == "#boot_id,boot-a\na,200\n"
	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100, max_ttl=600) == {"a": 200}


posix_only = pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership checks")


@pytest.fixture
def cache_dirs(tmp_path, monkeypatch):
	runtime_dir = tmp_path / "run"
	runtime_dir.mkdir(mode=0o700)
	temp_dir = tmp_path / "tmp"
	temp_dir.mkdir()
	monkeypatch.setattr(multiSSH3.tempfile, "gettempdir", lambda: str(temp_dir))
	return runtime_dir, temp_dir


@posix_only
def test_cache_lives_in_runtime_dir_when_set(cache_dirs, monkeypatch):
	runtime_dir, _ = cache_dirs
	monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))

	path = multiSSH3._unavailable_hosts_file_path()

	assert os.path.dirname(path) == str(runtime_dir / "multiSSH3")
	assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


@posix_only
def test_cache_falls_back_to_private_temp_dir(cache_dirs, monkeypatch):
	_, temp_dir = cache_dirs
	monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)

	path = multiSSH3._unavailable_hosts_file_path()

	assert os.path.dirname(path) == str(temp_dir / "multiSSH3-{}".format(os.getuid()))
	assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


@posix_only
@pytest.mark.parametrize("planted", ["open_mode", "symlink", "other_owner"])
def test_cache_refuses_temp_dir_someone_else_controls(cache_dirs, monkeypatch, planted):
	_, temp_dir = cache_dirs
	monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
	uid = os.getuid()
	if planted == "other_owner":
		uid = 12345  # we pretend to be 12345, the directory belongs to the real uid
		monkeypatch.setattr(multiSSH3.os, "getuid", lambda: 12345)
	cache_dir = temp_dir / "multiSSH3-{}".format(uid)
	if planted == "symlink":
		target = temp_dir / "attacker"
		target.mkdir(mode=0o700)
		cache_dir.symlink_to(target)
	else:
		cache_dir.mkdir()
		cache_dir.chmod(0o777 if planted == "open_mode" else 0o700)

	assert multiSSH3._unavailable_hosts_file_path() is None


def test_process_run_without_cache_location_keeps_state_in_memory(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Timeout!"]
	unavailable = {}
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: None)
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(timeout=1, password=None, max_connections=1, hosts=[host], return_unfinished=False,
		no_watch=True, json=False, no_output=True, greppable=False, unavailableHosts=unavailable,
		will_update_unreachable_hosts=True, pre_merge=False)

	assert "mock-a" in unavailable
	assert "mock-a" in multiSSH3.__globalUnavailableHosts


def test_run_on_hosts_without_cache_location_runs(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: None)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)

	hosts = multiSSH3.run_command_on_hosts(hosts="127.0.0.1", commands=["true"], no_start=True, no_watch=True,
		quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)

	assert [host.name for host in hosts] == ["127.0.0.1"]


@posix_only
def test_runtime_dir_others_can_write_to_is_not_used(cache_dirs, monkeypatch):
	runtime_dir, temp_dir = cache_dirs
	runtime_dir.chmod(0o777)
	monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))

	path = multiSSH3._unavailable_hosts_file_path()

	assert os.path.dirname(path) == str(temp_dir / "multiSSH3-{}".format(os.getuid()))


@posix_only
@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to chown")
def test_runtime_dir_of_another_user_is_not_used(cache_dirs, monkeypatch):
	# e.g. root running with a user's environment (sudo -E): that user owns XDG_RUNTIME_DIR
	runtime_dir, temp_dir = cache_dirs
	os.chown(runtime_dir, 23456, -1)
	monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))

	path = multiSSH3._unavailable_hosts_file_path()

	assert os.path.dirname(path) == str(temp_dir / "multiSSH3-{}".format(os.getuid()))


@posix_only
def test_own_cache_dir_readable_by_others_is_tightened(cache_dirs, monkeypatch):
	_, temp_dir = cache_dirs
	monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
	cache_dir = temp_dir / "multiSSH3-{}".format(os.getuid())
	cache_dir.mkdir()
	cache_dir.chmod(0o755)

	path = multiSSH3._unavailable_hosts_file_path()

	assert os.path.dirname(path) == str(cache_dir)
	assert stat.S_IMODE(os.stat(cache_dir).st_mode) == 0o700


@posix_only
def test_run_without_updating_the_cache_sets_up_the_directory_but_writes_no_file(cache_dirs, monkeypatch):
	runtime_dir, temp_dir = cache_dirs
	monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)

	multiSSH3.run_command_on_hosts(hosts="127.0.0.1", commands=["true"], no_start=True, no_watch=True, quiet=True,
		no_history=True, called=True, will_update_unreachable_hosts=False)

	# reading the cache sets its directory up as writing does: private, and empty
	assert [path.name for path in runtime_dir.iterdir()] == ["multiSSH3"]
	assert list((runtime_dir / "multiSSH3").iterdir()) == []
	assert list(temp_dir.iterdir()) == []


def _cache_unreachable(monkeypatch, tmp_path, *names):
	'''Use a cache file in tmp_path that lists names as unreachable for 300 more seconds.'''
	path = tmp_path / "unavailable.csv"
	expiry = int(multiSSH3.time.monotonic() + 300)
	path.write_text("#boot_id,boot-a\n" + "".join("{},{}\n".format(name, expiry) for name in names))
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
	return path


def _record_runs(monkeypatch):
	'''Hosts resolve to themselves and every command succeeds; returns the names run_command ran on.'''
	ran = []

	def succeed(host, sem, timeout=60, passwds=None, **kwargs):
		ran.append(host.name)
		host.stdout.append("ok")
		host.returncode = 0

	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "run_command", succeed)
	return ran


def test_library_call_returns_hosts_skipped_as_unreachable_as_failed(monkeypatch, tmp_path):
	path = _cache_unreachable(monkeypatch, tmp_path, "mock-a")
	ran = _record_runs(monkeypatch)

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=["true"], no_watch=True,
		no_output=True, no_history=True, called=True)

	by_name = {host.name: host for host in hosts}
	assert ran == ["mock-b"]
	assert sorted(by_name) == ["mock-a", "mock-b"]
	skipped = by_name["mock-a"]
	# ssh's own code for a host it could not reach: callers checking returncode see the failure
	assert skipped.returncode == 255
	assert skipped.skipped is True
	assert skipped.command == "true"
	assert "unreachable" in skipped.stderr[0]
	assert by_name["mock-b"].returncode == 0 and by_name["mock-b"].skipped is False
	# skipping a host does not make it count as reachable
	assert "mock-a" in multiSSH3._read_unavailable_hosts_file(str(path))


def test_hosts_skipped_in_every_command_of_a_run_are_returned_for_each(monkeypatch, tmp_path):
	_cache_unreachable(monkeypatch, tmp_path, "mock-a")
	ran = _record_runs(monkeypatch)

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=["first", "second"], no_watch=True,
		no_output=True, no_history=True, called=True)

	assert sorted((host.name, host.command, host.returncode) for host in hosts) == [
		("mock-a", "first", 255), ("mock-a", "second", 255), ("mock-b", "first", 0), ("mock-b", "second", 0)]
	assert ran == ["mock-b", "mock-b"]


def test_interactive_run_returns_hosts_skipped_as_unreachable(monkeypatch, tmp_path):
	_cache_unreachable(monkeypatch, tmp_path, "mock-a")
	_record_runs(monkeypatch)

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=None, no_watch=True,
		no_output=True, no_history=True, called=True)

	assert sorted((host.name, host.returncode) for host in hosts) == [("mock-a", 255), ("mock-b", 0)]


def test_host_skipped_as_unreachable_is_not_started_later(monkeypatch, tmp_path):
	_cache_unreachable(monkeypatch, tmp_path, "mock-a")
	ran = _record_runs(monkeypatch)
	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=["true"], no_start=True, no_watch=True,
		no_output=True, no_history=True, called=True)

	for thread in multiSSH3.start_run_on_hosts(hosts, timeout=5):
		thread.join(5)

	assert ran == ["mock-b"]
	assert sorted((host.name, host.returncode) for host in hosts) == [("mock-a", 255), ("mock-b", 0)]


def test_skip_hosts_leaves_out_a_host_that_is_also_unreachable(monkeypatch, tmp_path):
	_cache_unreachable(monkeypatch, tmp_path, "mock-a")
	_record_runs(monkeypatch)

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=["true"], skip_hosts="mock-a",
		no_watch=True, no_output=True, no_history=True, called=True)

	assert [host.name for host in hosts] == ["mock-b"]


def test_skipped_host_is_printed_with_the_failures(monkeypatch, tmp_path, capsys):
	_cache_unreachable(monkeypatch, tmp_path, "mock-a")
	_record_runs(monkeypatch)

	multiSSH3.run_command_on_hosts(hosts="mock-a,mock-b", commands=["true"], no_watch=True, error_only=True,
		greppable=True, no_output=False, no_history=True, called=False)

	out = capsys.readouterr().out
	assert "Success" not in out
	assert "mock-a" in out and "rc: 255" in out and "unreachable" in out
	assert "mock-b" not in out


def _unreachable_after_run(monkeypatch, tmp_path, host, cached=(), ssh_config_hostnames=None):
	'''
	Let processRunOnHosts record a finished host; returns the hosts it then counts as unreachable.

	ssh_config_hostnames maps names to the HostName ssh -G gives them (default: the name itself).
	'''
	hostnames = ssh_config_hostnames or {}
	# ssh -G is stubbed: the test does not need an installed ssh (the Docker test images have none)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: {"hostname": hostnames.get(hostname, hostname.lower())})
	expiry = int(multiSSH3.time.monotonic() + 300)
	unavailable = {name: expiry for name in cached}
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", dict(unavailable))
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])
	multiSSH3.processRunOnHosts(timeout=1, password=None, max_connections=1, hosts=[host], return_unfinished=False,
		no_watch=True, json=False, no_output=True, greppable=False, unavailableHosts=unavailable,
		will_update_unreachable_hosts=True, pre_merge=False)
	return set(unavailable)


@pytest.mark.parametrize("name, line", [
	("web1", "ssh: connect to host web1 port 22: No route to host"),
	("root@Web1", "ssh: connect to host web1 port 22: No route to host"),  # ssh lowercases the name
	("web1", "ssh: connect to host 10.0.0.5 port 2222: Connection timed out"),
	("web1", "ssh: connect to host web1.corp.example port 22: Connection timed out"),  # CanonicalizeHostname
	# a ProxyJump host that cannot reach the target (older OpenSSH prints this)
	("web1", "channel 0: open failed: connect failed: No route to host"),
])
def test_ssh_failing_to_connect_marks_the_host_unreachable(fake_host, monkeypatch, tmp_path, name, line):
	host = fake_host(name, "true", ip="10.0.0.5")
	host.returncode = 255
	host.stderr = [line]

	assert _unreachable_after_run(monkeypatch, tmp_path, host) == {name}


def test_ssh_failing_to_connect_to_the_ssh_config_hostname_marks_the_host_unreachable(fake_host, monkeypatch, tmp_path):
	host = fake_host("db", "true", ip="10.0.0.9")
	host.returncode = 255
	host.stderr = ["ssh: connect to host db-primary.corp.example port 22: No route to host"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host,
		ssh_config_hostnames={"db": "db-primary.corp.example"}) == {"db"}


def test_remote_ssh_failing_to_reach_another_host_does_not_mark_the_host(fake_host, monkeypatch, tmp_path):
	# mssh hostA 'ssh backup ...' with backup down: the remote ssh exits 255 with its own error
	host = fake_host("hosta", "ssh backup tar c /data", ip="10.0.0.7")
	host.returncode = 255
	host.stderr = ["ssh: connect to host backup port 22: No route to host"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["hosta"]) == set()


def test_ssh_naming_the_host_itself_needs_no_ssh_config_lookup(fake_host, monkeypatch, tmp_path):
	looked_up = []
	host = fake_host("web1", "true", ip="10.0.0.5")
	host.returncode = 255
	host.stderr = ["ssh: connect to host web1 port 22: No route to host"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host) == {"web1"}
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: looked_up.append(hostname))
	multiSSH3._found_unreachable(host)
	assert looked_up == []


@pytest.mark.parametrize("returncode, line", [
	# the remote command's own errors: ssh connected
	(7, "curl: (7) Failed to connect to repo.example port 443: No route to host"),
	(255, "rsync: failed to connect to mirror.example: Connection timed out (110)"),
	(1, "ssh: connect to host other-host port 22: No route to host"),
	# ssh reached the host but could not log in
	(255, "Permission denied (publickey)."),
])
def test_remote_errors_mentioning_routes_or_timeouts_do_not_mark_the_host_unreachable(
	fake_host, monkeypatch, tmp_path, returncode, line
):
	host = fake_host("mock-a", "true")
	host.returncode = returncode
	host.stderr = [line]

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["mock-a"]) == set()





@pytest.mark.parametrize("returncode, files, stderr", [
	(255, None, ["Connection timed out during banner exchange", "Connection to 10.0.0.5 port 22 timed out"]),
	# through a ProxyJump ssh has no address for the far end
	(255, None, ["Connection timed out during banner exchange", "Connection to UNKNOWN port 65535 timed out"]),
	# legacy-protocol scp exits with 1
	(1, ["f.txt"], ["Connection timed out during banner exchange", "Connection to 10.0.0.5 port 22 timed out",
		"lost connection"]),
])
def test_a_host_whose_sshd_never_answered_is_unreachable(fake_host, monkeypatch, tmp_path, returncode, files, stderr):
	# ssh's ConnectTimeout ran out after the host took the connection, before its sshd said a word
	host = fake_host("web1", "/tmp/" if files else "true", files=files, ip="10.0.0.5")
	host.returncode = returncode
	host.stderr = stderr

	assert _unreachable_after_run(monkeypatch, tmp_path, host) == {"web1"}


@pytest.mark.parametrize("stderr", [
	# the remote command's own ssh gave up on another host
	["Connection timed out during banner exchange", "Connection to 10.9.9.9 port 22 timed out"],
	["Connection timed out during banner exchange"],
])
def test_a_banner_timeout_not_naming_the_host_does_not_mark_it(fake_host, monkeypatch, tmp_path, stderr):
	host = fake_host("web1", "ssh other true", ip="10.0.0.5")
	host.returncode = 255
	host.stderr = stderr

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["web1"]) == set()


def test_a_host_that_stopped_answering_during_its_command_is_not_unreachable(fake_host, monkeypatch, tmp_path):
	# ssh's ServerAlive*: it answered, ran the command for a while, then went away
	host = fake_host("web1", "sleep 100", ip="10.0.0.5")
	host.returncode = 255
	host.stderr = ["Timeout, server web1 not responding."]

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["web1"]) == set()

def test_file_copy_that_could_not_connect_marks_the_host_unreachable(fake_host, monkeypatch, tmp_path):
	# scp's legacy protocol (the default before OpenSSH 9.0, and scp -O) exits 1 when ssh cannot
	# connect; mssh falls back to scp after rsync failed, so scp's result is the host's
	host = fake_host("mock-a", "/tmp/", files=["f.txt"])
	host.returncode = 1
	host.stderr = ["ssh: connect to host mock-a port 22: No route to host", "lost connection"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host) == {"mock-a"}


def test_command_exiting_1_after_ssh_connect_words_does_not_mark_the_host(fake_host, monkeypatch, tmp_path):
	# only a file copy's scp exits 1 for a connect failure, a command's ssh exits 255
	host = fake_host("mock-a", "true")
	host.returncode = 1
	host.stderr = ["ssh: connect to host mock-a port 22: No route to host"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["mock-a"]) == set()


@pytest.mark.parametrize("returncode, files, stderr", [
	(124, None, ["Resolved name: mock-a", "Running command: ssh -- mock-a sleep 9", "Timeout!"]),
	(255, None, ["Resolved name: mock-a", "Running command: ssh -- mock-a true",
		"ssh: connect to host mock-a port 22: No route to host"]),
	# --debug keeps the failed rsync attempt's lines before scp's
	(1, ["f.txt"], ["Resolved name: mock-a", "Running command: rsync -ahlX f.txt mock-a:/tmp/",
		"ssh: connect to host mock-a port 22: No route to host", "rsync: connection unexpectedly closed",
		"Rsync connection failed! Trying SCP connection...", "Resolved name: mock-a",
		"Running command: scp -rp f.txt mock-a:/tmp/", "ssh: connect to host mock-a port 22: No route to host",
		"lost connection"]),
])
def test_debug_lines_do_not_hide_an_unreachable_host(fake_host, monkeypatch, tmp_path, returncode, files, stderr):
	# with --debug mssh writes its own lines to stderr before the command's
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", True)
	host = fake_host("mock-a", "/tmp/" if files else "true", files=files)
	host.returncode = returncode
	host.stderr = stderr

	assert _unreachable_after_run(monkeypatch, tmp_path, host) == {"mock-a"}


def test_debug_lines_do_not_count_as_the_command_printing(fake_host, monkeypatch, tmp_path):
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", True)
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Resolved name: mock-a", "Running command: ssh -- mock-a make", "make: warning: jobserver unavailable",
		"Timeout!"]

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["mock-a"]) == set()

def test_ssh_connect_error_splits_only_ssh_own_line():
	# the same helper as patch/ssh-error-text's, so the two merge into one
	assert multiSSH3._ssh_connect_error(" ssh: connect to host web1 port 22: No route to host\n") == (
		"web1", "22", "No route to host")
	assert multiSSH3._ssh_connect_error("curl: (7) Failed to connect to repo.example port 443: No route to host") is None
	assert multiSSH3._ssh_connect_error("remote says ssh: connect to host web1 port 22: No route to host") is None

def test_with_no_skip_unreachable_a_host_is_skipped_after_an_earlier_command_without_an_a_hint(monkeypatch, tmp_path):
	# -a only stops using earlier runs: within one run a host found unreachable is still skipped
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)

	def unreachable(host, sem, timeout=60, passwds=None, **kwargs):
		host.stderr.append("ssh: connect to host mock-a port 22: No route to host")
		host.returncode = 255

	monkeypatch.setattr(multiSSH3, "run_command", unreachable)

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a", commands=["first", "second"], skip_unreachable=False,
		no_watch=True, no_output=True, no_history=True, called=False)

	assert [(host.command, host.skipped) for host in hosts] == [("first", False), ("second", True)]
	assert hosts[1].stderr == ["Skipped: unreachable in an earlier command of this run"]


@pytest.mark.parametrize("stdout, stderr", [
	(["connected-and-running"], ["Timeout!"]),
	([], ["make: warning: jobserver unavailable", "Timeout!"]),
])
def test_host_that_printed_before_timing_out_is_not_unreachable(fake_host, monkeypatch, tmp_path, stdout, stderr):
	# it answered, the command was just quiet for longer than -t
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stdout = stdout
	host.stderr = stderr

	assert _unreachable_after_run(monkeypatch, tmp_path, host, cached=["mock-a"]) == set()
