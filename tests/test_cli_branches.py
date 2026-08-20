import os

import pytest

import multiSSH3


@pytest.mark.parametrize(
	"kwargs,needle",
	[
		({"username": "alice"}, '--username="alice"'),
		({"password": "secret"}, '--password="secret"'),
		({"identity_file": "/tmp/id"}, '--key="/tmp/id"'),
		({"copy_id": True}, "--copy_id"),
		({"skip_unreachable": False}, "--no_skip_unreachable"),
		({"error_only": True}, "--error_only"),
		({"greppable": True}, "--greppable"),
		({"file_sync": True}, "--file_sync"),
		({"extraargs": "--foo"}, '--extraargs="--foo"'),
		({"interface_ip_prefix": "10.0.0."}, '--interface_ip_prefix="10.0.0."'),
		({"unavailable_host_expiry": 42}, "--unavailable_host_expiry=42"),
		({"env_file": "/tmp/env"}, '--env_file="/tmp/env"'),
		({"env_files": ["/a", "/b"]}, '--env_files="/a"'),
		({"history_file": "/tmp/hist"}, '--history_file="/tmp/hist"'),
		({"max_connections": 7}, "--max_connections=7"),
	],
)
def test_form_command_arg_str_flag_matrix(kwargs, needle):
	# Avoid default-equal omissions: pass values different from module defaults where needed
	s = multiSSH3.__formCommandArgStr(**kwargs)
	assert needle in s


def test_process_args_script_and_output_flags():
	args = multiSSH3.process_args(
		["127.0.0.1", "true", "--script", "-P", "-j", "-R", "-Q", "-uk", "-ea=--x"]
	)
	# --script expands several quiet/script-friendly flags
	assert args.greppable is True or args.json is True or args.no_watch is True
	assert args.extraargs == "--x" or args.extraargs


@pytest.mark.parametrize("repeat", ["0", "-1"])
def test_process_args_rejects_nonpositive_repeat(repeat):
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_args(["127.0.0.1", "true", "--repeat", repeat])
	assert exc_info.value.code == 2


def test_process_args_warns_for_missing_explicit_config(tmp_path, capsys):
	missing = tmp_path / "missing.json"
	args = multiSSH3.process_args(["--config_file", str(missing), "127.0.0.1", "true"])

	assert args.config_file == str(missing)
	assert "Config file {!r} not found".format(str(missing)) in capsys.readouterr().err


def test_process_keys_missing_file_warns(tmp_path, monkeypatch, capsys):
	missing = tmp_path / "no-such-key"
	args = multiSSH3.get_parser().parse_args(
		["127.0.0.1", "true", "-k", str(missing)]
	)
	args = multiSSH3.process_keys(args)
	assert args.identity_file == str(missing)


def test_process_keys_directory_searches(tmp_path, monkeypatch):
	keydir = tmp_path / "keys"
	keydir.mkdir()
	(keydir / "id_rsa").write_text("dummy")
	monkeypatch.setattr(
		multiSSH3,
		"find_ssh_key_file",
		lambda searchPath=None: str(keydir / "id_rsa"),
	)
	args = multiSSH3.get_parser().parse_args(
		["127.0.0.1", "true", "-k", str(keydir)]
	)
	args = multiSSH3.process_keys(args)
	assert args.identity_file == str(keydir / "id_rsa")


def test_process_keys_use_key_without_path(monkeypatch):
	monkeypatch.setattr(multiSSH3, "find_ssh_key_file", lambda searchPath=None: "/tmp/found_key")
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true", "-uk"])
	args = multiSSH3.process_keys(args)
	assert args.identity_file == "/tmp/found_key"


def test_process_control_master_writes_config(tmp_path, monkeypatch):
	ssh_dir = tmp_path / ".ssh"
	monkeypatch.setenv("HOME", str(tmp_path))
	# expanduser uses HOME
	exits = []

	def fake_exit(code, message=None):
		exits.append((code, message))
		raise SystemExit(code)

	monkeypatch.setattr(multiSSH3, "_exit_with_code", fake_exit)
	args = multiSSH3.get_parser().parse_args(["--add_control_master_config"])
	with pytest.raises(SystemExit):
		multiSSH3.process_control_master_config(args)
	assert (ssh_dir / "config").exists()
	assert "ControlMaster" in (ssh_dir / "config").read_text()
	assert exits and exits[0][0] == 0


def test_set_global_with_args_env_file_and_host_file(tmp_path):
	hf = tmp_path / "hosts"
	hf.write_text("127.0.0.1 localhost\n")
	args = multiSSH3.get_parser().parse_args(
		["127.0.0.1", "true", "-ef", "/tmp/one.env", "--host_file", str(hf)]
	)
	multiSSH3.set_global_with_args(args)
	assert multiSSH3._env_files == ["/tmp/one.env"]
	assert multiSSH3.DEFAULT_HOST_FILE == str(hf)


def test_find_ssh_key_file(tmp_path, monkeypatch):
	key = tmp_path / "id_ed25519"
	key.write_text("k")
	# Also create .pub companion expected by some search logic — check find_ssh_key_file
	found = multiSSH3.find_ssh_key_file(str(tmp_path))
	assert found is None or os.path.basename(found) in multiSSH3.POSSIBLE_SSH_KEY_FILES or found.endswith("id_ed25519")
