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
	path.write_text("#boot_id,boot-a\navailable-now,{}\nstill-down,{}\n".format(expiry, expiry))
	monkeypatch.setattr(multiSSH3, "_get_boot_id", lambda: "boot-a")
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
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: None)
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(timeout=1, password=None, max_connections=1, hosts=[host], return_unfinished=False,
		no_watch=True, json=False, no_output=True, greppable=False, unavailableHosts=unavailable,
		will_update_unreachable_hosts=True, pre_merge=False)

	assert "mock-a" in unavailable
	assert "mock-a" in multiSSH3.__globalUnavailableHosts


def test_run_on_hosts_without_cache_location_runs(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: None)
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
