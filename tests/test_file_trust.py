import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import multiSSH3

pytestmark = pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership checks")

PACKAGE_ROOT = Path(multiSSH3.__file__).resolve().parent


def _owned_by_someone_else(monkeypatch, path):
	# pretend to be uid 12345; as root also give the file to a third uid
	monkeypatch.setattr(multiSSH3.os, "getuid", lambda: 12345)
	if os.geteuid() == 0:
		os.chown(path, 23456, -1)


def _fake_owner_and_group(monkeypatch, group_name, group_members):
	monkeypatch.setattr(multiSSH3.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="alice", pw_gid=os.getgid()))
	monkeypatch.setattr(multiSSH3.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name=group_name, gr_mem=group_members))


def _config(tmp_path, mode=0o644):
	path = tmp_path / "multiSSH3.config.json"
	path.write_text('{"DEFAULT_WINDOW_WIDTH": 77}')
	path.chmod(mode)
	return str(path)


def test_world_writable_config_in_cwd_cannot_replace_ssh(tmp_path):
	config = Path(_config(tmp_path, 0o666))
	config.write_text('{"_sshPath": "/bin/echo"}')
	code = "import sys; sys.path.insert(0, {!r}); import multiSSH3; print(multiSSH3._binPaths.get('ssh'))".format(str(PACKAGE_ROOT))

	result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path, timeout=60)

	assert result.stdout.strip() != "/bin/echo"
	assert "chmod g-w,o-w" in result.stderr


def test_config_owned_by_someone_else_is_ignored(monkeypatch, tmp_path, capsys):
	path = _config(tmp_path)
	_owned_by_someone_else(monkeypatch, path)

	assert multiSSH3.load_config_file(path) == {}
	assert "--config_file" in capsys.readouterr().err


def test_group_writable_config_with_private_group_loads(monkeypatch, tmp_path):
	path = _config(tmp_path, 0o664)
	monkeypatch.setattr(multiSSH3.os, "getuid", lambda: os.stat(path).st_uid)
	_fake_owner_and_group(monkeypatch, "alice", [])

	assert multiSSH3.load_config_file(path) == {"DEFAULT_WINDOW_WIDTH": 77}


def test_group_writable_config_with_shared_group_is_ignored(monkeypatch, tmp_path, capsys):
	path = _config(tmp_path, 0o664)
	monkeypatch.setattr(multiSSH3.os, "getuid", lambda: os.stat(path).st_uid)
	_fake_owner_and_group(monkeypatch, "users", ["alice", "bob"])

	assert multiSSH3.load_config_file(path) == {}
	assert "chmod g-w,o-w" in capsys.readouterr().err


def test_explicit_config_file_is_trusted(monkeypatch, tmp_path):
	path = _config(tmp_path, 0o666)
	monkeypatch.setattr(multiSSH3, "DEFAULT_WINDOW_WIDTH", multiSSH3.DEFAULT_WINDOW_WIDTH)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})

	args = multiSSH3.process_args(["--config_file", path, "127.0.0.1", "true"])

	assert args.window_width == 77


def _env_file(tmp_path, mode):
	path = tmp_path / "hosts.env"
	path.write_text("MSSH_TRUST_ALIAS=127.0.0.5\n")
	path.chmod(mode)
	return str(path)


def test_world_writable_env_file_on_search_path_is_ignored(monkeypatch, tmp_path):
	monkeypatch.setattr(multiSSH3, "_env_files", [_env_file(tmp_path, 0o666)])
	multiSSH3.readEnvFromFile.cache_clear()

	assert "MSSH_TRUST_ALIAS" not in multiSSH3.readEnvFromFile()


def test_explicit_env_file_is_trusted(monkeypatch, tmp_path):
	path = _env_file(tmp_path, 0o666)
	args = multiSSH3.process_args(["-ef", path, "127.0.0.1", "true"])
	multiSSH3.set_global_with_args(args)
	multiSSH3.readEnvFromFile.cache_clear()

	assert multiSSH3.readEnvFromFile()["MSSH_TRUST_ALIAS"] == "127.0.0.5"
