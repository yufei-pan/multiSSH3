import json
import os
import stat
from pathlib import Path

import pytest

import multiSSH3
from conftest import run_cli


def test_version_flag():
	r = run_cli(["--version"])
	assert r.returncode == 0
	assert multiSSH3.version in (r.stdout + r.stderr)


def test_load_config_file_roundtrip(tmp_path):
	cfg = tmp_path / "multiSSH3.config.json"
	data = {"DEFAULT_TIMEOUT": 12, "DEFAULT_HOSTS": "127.0.0.1"}
	cfg.write_text(json.dumps(data))
	loaded = multiSSH3.load_config_file(str(cfg))
	assert loaded == data


def test_cli_rejects_nonpositive_repeat_from_numeric_config_default(tmp_path):
	cfg = tmp_path / "multiSSH3.config.json"
	cfg.write_text(json.dumps({"DEFAULT_REPEAT": 0}))

	result = run_cli(["--config_file", str(cfg), "127.0.0.1", "true"])

	assert result.returncode == 2


def test_parser_hosts_and_command():
	parser = multiSSH3.get_parser()
	args = parser.parse_args(["127.0.0.1", "echo", "ok"])
	assert args.hosts == "127.0.0.1"
	assert args.commands == ["echo", "ok"]


def test_malformed_config_returns_empty(tmp_path, capsys):
	cfg = tmp_path / "bad.json"
	cfg.write_text("{not-json")
	assert multiSSH3.load_config_file(str(cfg)) == {}


def test_missing_config_returns_empty(tmp_path):
	assert multiSSH3.load_config_file(str(tmp_path / "nope.json")) == {}


def test_apply_config_key_compat_deafult_ipmi_args():
	cfg = {"DEAFULT_IPMI_ARGS": "-I lanplus"}
	multiSSH3.apply_config_key_compat(cfg)
	assert cfg["DEFAULT_IPMI_ARGS"] == "-I lanplus"
	assert cfg["DEAFULT_IPMI_ARGS"] == "-I lanplus"


def test_apply_config_key_compat_prefers_correct_key():
	cfg = {"DEAFULT_IPMI_ARGS": "old", "DEFAULT_IPMI_ARGS": "new"}
	multiSSH3.apply_config_key_compat(cfg)
	assert cfg["DEFAULT_IPMI_ARGS"] == "new"


@pytest.fixture
def umask_002():
	# user-private-group accounts get umask 002, so plain open() makes 0664 files
	old = os.umask(0o002)
	yield
	os.umask(old)


def _store_config(monkeypatch, path):
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(path), force=True)
	assert json.loads(path.read_text())["DEFAULT_PASSWORD"] == "secret"
	return stat.S_IMODE(path.stat().st_mode)


def test_store_config_file_is_owner_only(monkeypatch, tmp_path, umask_002):
	assert _store_config(monkeypatch, tmp_path / "new.json") == 0o600

	existing = tmp_path / "existing.json"
	existing.write_text("{}")
	existing.chmod(0o664)
	assert _store_config(monkeypatch, existing) == 0o600


def test_store_config_file_keeps_system_wide_location_readable(monkeypatch, tmp_path, umask_002):
	system_config = tmp_path / "etc" / "multiSSH3.config.json"
	system_config.parent.mkdir()
	monkeypatch.setattr(multiSSH3, "CONFIG_FILE_CHAIN", ["~/.multiSSH3.config.json", str(system_config)])

	assert _store_config(monkeypatch, system_config) == 0o644


def test_store_config_file_still_writes_when_permissions_cannot_change(monkeypatch, tmp_path):
	shared = tmp_path / "team.json"
	shared.write_text('{"DEFAULT_TIMEOUT": 5}')

	def not_our_file(fd, mode):
		raise PermissionError(1, "Operation not permitted")

	monkeypatch.setattr(multiSSH3.os, "fchmod", not_our_file)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(shared), force=True)

	assert json.loads(shared.read_text())["DEFAULT_PASSWORD"] == "secret"  # not left truncated


def test_store_config_file_keeps_locked_down_system_config_locked(monkeypatch, tmp_path, umask_002):
	system_config = tmp_path / "etc" / "multiSSH3.config.json"
	system_config.parent.mkdir()
	system_config.write_text("{}")
	system_config.chmod(0o600)
	monkeypatch.setattr(multiSSH3, "CONFIG_FILE_CHAIN", [str(system_config)])

	assert _store_config(monkeypatch, system_config) == 0o600
