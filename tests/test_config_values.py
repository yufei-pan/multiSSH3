import copy
import json
import os
import subprocess
import sys

import pytest

import multiSSH3
from conftest import MULTISSH3_PY


def _run_mssh(home, *args):
	'''
	Run mssh in a fresh process with HOME (and so the config file chain) at home.

	A run that reaches hosts must also get a fake ssh (_sshPath) from a config in home, -ef /dev/null
	and a --host_file of its own: short names resolve on some machines (search domain wildcards).
	'''
	runtime = home / "run"
	runtime.mkdir(mode=0o700, exist_ok=True)
	env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime))
	return subprocess.run([sys.executable, str(MULTISSH3_PY)] + list(args), stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, universal_newlines=True, env=env, cwd=str(home), timeout=60)


def _write_config(path, content):
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(content if isinstance(content, str) else json.dumps(content))
	path.chmod(0o600)  # files on the default chain must not be writable by others
	return path


@pytest.mark.parametrize("content", ["null", "[1, 2]", '"text"', "5", '[["DEFAULT_HOSTS", "x"]]'],
	ids=["null", "list", "string", "number", "pairs"])
def test_config_that_is_not_an_object_is_rejected_naming_the_file(tmp_path, capsys, content):
	path = _write_config(tmp_path / "multiSSH3.config.json", content)

	assert multiSSH3.load_config_file(str(path)) == {}
	err = capsys.readouterr().err
	assert str(path) in err
	assert "object" in err


def test_chain_config_that_is_not_an_object_does_not_break_mssh(tmp_path):
	broken = _write_config(tmp_path / ".multiSSH3.config.json", "null")
	_write_config(tmp_path / ".config" / "multiSSH3" / "multiSSH3.config.json", {"DEFAULT_HOSTS": "lower-in-chain"})

	version = _run_mssh(tmp_path, "-V")
	generated = _run_mssh(tmp_path, "--generate_config_file")

	assert version.returncode == 0, version.stderr
	assert multiSSH3.version in version.stdout
	assert str(broken) in version.stderr
	assert generated.returncode == 0, generated.stderr
	# the rest of the chain still applies
	assert json.loads(generated.stdout)["DEFAULT_HOSTS"] == "lower-in-chain"


def test_config_file_option_that_is_not_an_object_is_reported(tmp_path, monkeypatch, capsys):
	path = _write_config(tmp_path / "team.json", "[]")
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})

	args = multiSSH3.process_args(["--config_file", str(path), "127.0.0.1", "true"])

	assert args.hosts == "127.0.0.1"
	assert str(path) in capsys.readouterr().err


# what applying a --config_file changes besides the settings it names
_DERIVED = ("__configs_from_file", "__working_config_file", "__ERROR_MESSAGES_TO_IGNORE_REGEX", "_binPaths",
	"DEFAULT_ENV_FILES")


def _process_args_with_config(monkeypatch, tmp_path, config, *argv):
	'''process_args with --config_file holding config; every module global it may change is restored afterwards.'''
	path = _write_config(tmp_path / "extra.json", config)
	for name in list(config) + list(_DERIVED):
		value = getattr(multiSSH3, name, None)
		# a copy, so changes made in place are undone too (a compiled regex cannot be copied on Python 3.6)
		monkeypatch.setattr(multiSSH3, name, copy.deepcopy(value) if isinstance(value, (list, dict)) else value, raising=False)
	return multiSSH3.process_args(["--config_file", str(path)] + list(argv or ["127.0.0.1", "true"]))


def _fake_ssh(tmp_path):
	'''An ssh that prints its arguments and a line on stderr, for running mssh without a host.'''
	path = tmp_path / "fakessh"
	path.write_text("#!/bin/sh\n"
		"if [ \"$1\" = -G ]; then echo \"hostname $3\"; exit 0; fi\n"
		"echo \"FAKESSH $*\"\n"
		"echo \"FAKEERR on stderr\" >&2\n")
	path.chmod(0o755)
	return str(path)


@pytest.mark.parametrize("key,given,expected", [
	("DEFAULT_TIMEOUT", "50", 50),
	("DEFAULT_TIMEOUT", " 7 ", 7),
	("DEFAULT_TIMEOUT", 2.0, 2),
	("DEFAULT_TIMEOUT", 2.5, 2.5),
	("DEFAULT_DIFF_DISPLAY_THRESHOLD", "0.5", 0.5),
	("DEFAULT_DIFF_DISPLAY_THRESHOLD", 1, 1.0),
	("DEFAULT_SKIP_UNREACHABLE", "false", False),
	("DEFAULT_NO_WATCH", "True", True),
	("DEFAULT_NO_WATCH", "yes", True),
	("DEFAULT_NO_WATCH", 0, False),
	("DEFAULT_PASSWORD", 1234, "1234"),
	("DEFAULT_USERNAME", None, None),
	("DEFAULT_USERNAME", "alice", "alice"),
	# what --store_config_file writes for the default
	("DEFAULT_MAX_CONNECTIONS", None, None),
	("DEFAULT_HOSTS", ["node1", "node2"], "node1,node2"),
	("DEFAULT_EXTRA_ARGS", ["-o", "Port=2222"], ["-o", "Port=2222"]),
	("DEFAULT_ENCODING", "latin-1", "latin-1"),
	("DEFAULT_IPMI_DEFINITIONS", [{"username": "x"}], [{"username": "x"}]),
	("ERROR_MESSAGES_TO_IGNORE", ["FAKEERR"], ["FAKEERR"]),
	("__ERROR_MESSAGES_TO_IGNORE_REGEX", "FAKE.*", "FAKE.*"),
	("_sshPath", "/opt/ssh/bin/ssh", "/opt/ssh/bin/ssh"),
	# kept as they are: --store_config_file writes them back
	("NOT_A_SETTING", {"x": 1}, {"x": 1}),
])
def test_config_values_are_converted_to_the_type_of_the_setting(tmp_path, capsys, key, given, expected):
	path = _write_config(tmp_path / "multiSSH3.config.json", {key: given})

	loaded = multiSSH3.load_config_file(str(path))

	assert loaded == {key: expected}
	assert type(loaded[key]) is type(expected)
	assert "Warning" not in capsys.readouterr().err


@pytest.mark.parametrize("key,given", [
	("DEFAULT_TIMEOUT", "fifty"),
	("DEFAULT_TIMEOUT", True),
	("DEFAULT_TIMEOUT", None),
	("DEFAULT_TIMEOUT", [50]),
	("DEFAULT_SKIP_UNREACHABLE", "maybe"),
	("DEFAULT_SKIP_UNREACHABLE", 2),
	("DEFAULT_HOSTS", {"node1": 1}),
	("DEFAULT_IPMI_DEFINITIONS", {"username": "x"}),
	("DEFAULT_IPMI_DEFINITIONS", ["x"]),
	("DEFAULT_ENV_FILES", "~/hosts.env"),
	("ERROR_MESSAGES_TO_IGNORE", "FAKEERR"),
	("ERROR_MESSAGES_TO_IGNORE", ["("]),
	("__ERROR_MESSAGES_TO_IGNORE_REGEX", "("),
	("DEFAULT_ENCODING", "utf8x"),
	("DEFAULT_ENCODING", "rot13"),
	("COLOR_PALETTE", [1, 2, 3]),
	("_sshPath", 5),
])
def test_unusable_config_values_are_ignored_with_a_warning(tmp_path, capsys, key, given):
	path = _write_config(tmp_path / "multiSSH3.config.json", {key: given, "DEFAULT_WINDOW_WIDTH": 77})

	loaded = multiSSH3.load_config_file(str(path))

	# the file's other settings still apply
	assert loaded == {"DEFAULT_WINDOW_WIDTH": 77}
	err = capsys.readouterr().err
	assert key in err
	assert str(path) in err


def test_string_false_in_a_config_turns_skipping_off(monkeypatch, tmp_path):
	args = _process_args_with_config(monkeypatch, tmp_path, {"DEFAULT_SKIP_UNREACHABLE": "false"})

	assert args.skip_unreachable is False


def test_string_timeout_in_a_config_does_not_fail_the_hosts(tmp_path):
	_write_config(tmp_path / ".multiSSH3.config.json", {"DEFAULT_TIMEOUT": "50", "_sshPath": _fake_ssh(tmp_path)})

	hosts_file = tmp_path / "hosts"
	hosts_file.write_text("")

	result = _run_mssh(tmp_path, "-ef", "/dev/null", "--host_file", str(hosts_file), "-I", "-q", "-T", "127.0.0.1", "echo hi")

	assert result.returncode == 0, result.stdout + result.stderr
	assert "FAKESSH" in result.stdout
	assert "not supported" not in result.stdout + result.stderr


@pytest.mark.parametrize("encoding", ["utf8x", "rot13"])
def test_unusable_encoding_is_refused_before_any_host_runs(capsys, encoding):
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_args(["-e", encoding, "127.0.0.1", "true"])

	assert exc_info.value.code == 2
	assert encoding in capsys.readouterr().err
