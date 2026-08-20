import json
import os

import pytest

import multiSSH3


def test_write_default_config_force_tmp(tmp_path, monkeypatch):
	cfg_path = tmp_path / "multiSSH3.config.json"
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true", "-q"])
	# Avoid interactive prompt paths
	multiSSH3.write_default_config(args, CONFIG_FILE=str(cfg_path), force=True)
	assert cfg_path.exists()
	data = json.loads(cfg_path.read_text())
	assert data["DEFAULT_HOSTS"] == "127.0.0.1"


def test_write_default_config_stdout_when_no_path(capsys):
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true"])
	multiSSH3.write_default_config(args, CONFIG_FILE=None, force=True)
	out = capsys.readouterr().out
	assert "DEFAULT_HOSTS" in out


def test_validate_expand_hostname_loopback():
	# Direct call — clear cache first
	if hasattr(multiSSH3.__validate_expand_hostname, "cache_clear"):
		multiSSH3.__validate_expand_hostname.cache_clear()
	assert multiSSH3.__validate_expand_hostname("127.0.0.1") == ["127.0.0.1"]


def test_validate_expand_hostname_from_environ(monkeypatch):
	if hasattr(multiSSH3.__validate_expand_hostname, "cache_clear"):
		multiSSH3.__validate_expand_hostname.cache_clear()
	if hasattr(multiSSH3.__expand_hostnames, "cache_clear"):
		multiSSH3.__expand_hostnames.cache_clear()
	monkeypatch.setenv("MSSH_TEST_GROUP", "127.0.0.1,127.0.0.2")
	multiSSH3._no_env = False
	got = multiSSH3.__validate_expand_hostname("MSSH_TEST_GROUP")
	assert "127.0.0.1" in got
	assert "127.0.0.2" in got


def test_validate_expand_hostname_invalid(monkeypatch):
	if hasattr(multiSSH3.__validate_expand_hostname, "cache_clear"):
		multiSSH3.__validate_expand_hostname.cache_clear()
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: None)
	monkeypatch.setattr(multiSSH3, "readEnvFromFile", lambda: {})
	multiSSH3._no_env = True
	multiSSH3.__mainReturnCode = 0
	multiSSH3.__failedHosts = set()
	assert multiSSH3.__validate_expand_hostname("not-a-real-host-xyz") == []
	assert "not-a-real-host-xyz" in multiSSH3.__failedHosts
	assert multiSSH3.__mainReturnCode >= 1


def test_write_default_config_backup_choice(tmp_path, monkeypatch):
	path = tmp_path / "config.json"
	path.write_text('{"old": true}')
	args = multiSSH3.get_parser().parse_args(["mock-a", "true"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda timeout: "b")

	multiSSH3.write_default_config(args, CONFIG_FILE=str(path), force=False)

	assert (tmp_path / "config.json.bak").read_text() == '{"old": true}'
	assert json.loads(path.read_text())["DEFAULT_HOSTS"] == "mock-a"


def test_write_default_config_abort_choice(tmp_path, monkeypatch):
	path = tmp_path / "config.json"
	path.write_text("{}")
	args = multiSSH3.get_parser().parse_args(["mock-a", "true"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda timeout: "n")

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.write_default_config(args, CONFIG_FILE=str(path), force=False)

	assert exc_info.value.code == 0
	assert path.read_text() == "{}"
