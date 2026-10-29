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


def _process_args_with_config(monkeypatch, tmp_path, config, *argv, **options):
	'''
	process_args with --config_file holding config; every module global it may change is restored afterwards.

	options: config_arg, how --config_file names the file (default: its full path)
	'''
	path = _write_config(tmp_path / "extra.json", config)
	for name in list(config) + list(_DERIVED):
		value = getattr(multiSSH3, name, None)
		# a copy, so changes made in place are undone too (a compiled regex cannot be copied on Python 3.6)
		monkeypatch.setattr(multiSSH3, name, copy.deepcopy(value) if isinstance(value, (list, dict)) else value, raising=False)
	return multiSSH3.process_args(["--config_file", options.get("config_arg", str(path))] + list(argv or ["127.0.0.1", "true"]))


def _fake_ssh(tmp_path, name="FAKESSH"):
	'''An ssh that prints name and its arguments, and a line on stderr, for running mssh without a host.'''
	path = tmp_path / name.lower()
	path.write_text("#!/bin/sh\n"
		"if [ \"$1\" = -G ]; then echo \"hostname $3\"; exit 0; fi\n"
		"echo \"" + name + " $*\"\n"
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


def _ignored_errors():
	return getattr(multiSSH3, "__ERROR_MESSAGES_TO_IGNORE_REGEX")


def test_config_file_option_sets_the_program_paths(monkeypatch, tmp_path):
	_process_args_with_config(monkeypatch, tmp_path, {"_sshPath": "/opt/fake/ssh", "_rsyncPath": "/opt/fake/rsync"})

	assert multiSSH3._binPaths["ssh"] == "/opt/fake/ssh"
	assert multiSSH3._binPaths["rsync"] == "/opt/fake/rsync"


def test_config_file_option_adds_its_env_file(monkeypatch, tmp_path):
	env_file = tmp_path / "lab.env"
	env_file.write_text("MSSH_CONFIG_ALIAS=127.0.0.9\n")
	env_file.chmod(0o600)

	args = _process_args_with_config(monkeypatch, tmp_path, {"DEFAULT_ENV_FILE": str(env_file)})
	multiSSH3.set_global_with_args(args)

	assert str(env_file) in multiSSH3._env_files
	assert multiSSH3.readEnvFromFile().get("MSSH_CONFIG_ALIAS") == "127.0.0.9"


def test_config_file_option_sets_the_error_messages_to_ignore(monkeypatch, tmp_path):
	_process_args_with_config(monkeypatch, tmp_path, {"ERROR_MESSAGES_TO_IGNORE": ["FAKEERR"]})

	assert _ignored_errors().search("FAKEERR on stderr")
	assert not _ignored_errors().search("Connection to node1 closed.")


def test_config_file_option_regex_is_compiled(monkeypatch, tmp_path):
	_process_args_with_config(monkeypatch, tmp_path, {"__ERROR_MESSAGES_TO_IGNORE_REGEX": "FAKE.*"})

	assert _ignored_errors().search("FAKEERR on stderr")
	assert not _ignored_errors().search("Permission denied")


@pytest.mark.parametrize("messages", [[], [""]], ids=["empty_list", "empty_pattern"])
def test_no_error_messages_to_ignore_hides_no_line(monkeypatch, tmp_path, messages):
	# an empty pattern matches every line: all of stderr would be dropped
	_process_args_with_config(monkeypatch, tmp_path, {"ERROR_MESSAGES_TO_IGNORE": messages})

	assert not _ignored_errors().search("Permission denied")


def test_config_file_cannot_replace_internal_state(monkeypatch, tmp_path):
	args = _process_args_with_config(monkeypatch, tmp_path, {"_binPaths": "x", "eprint": 1, "__running_procs": None})

	assert args.hosts == "127.0.0.1"
	assert isinstance(multiSSH3._binPaths, dict)
	assert callable(multiSSH3.eprint)


@pytest.mark.parametrize("ignore", [{"ERROR_MESSAGES_TO_IGNORE": ["FAKEERR"]}, {"__ERROR_MESSAGES_TO_IGNORE_REGEX": "FAKEERR"}],
	ids=["messages", "regex"])
def test_config_file_option_applies_like_the_chain(tmp_path, ignore):
	# the chain's fake ssh runs if --config_file's _sshPath is not applied: never a real one
	_write_config(tmp_path / ".multiSSH3.config.json", {"_sshPath": _fake_ssh(tmp_path, "CHAINSSH")})
	extra = _write_config(tmp_path / "extra.json", dict(ignore, _sshPath=_fake_ssh(tmp_path, "CONFIGSSH")))
	hosts_file = tmp_path / "hosts"
	hosts_file.write_text("")

	result = _run_mssh(tmp_path, "--config_file", str(extra), "-ef", "/dev/null", "--host_file", str(hosts_file),
		"-I", "-q", "127.0.0.1", "echo hi")

	assert result.returncode == 0, result.stdout + result.stderr
	assert "CONFIGSSH" in result.stdout
	assert "FAKEERR" not in result.stdout


def test_config_file_option_expands_tilde(monkeypatch, tmp_path, capsys):
	monkeypatch.setenv("HOME", str(tmp_path))

	args = _process_args_with_config(monkeypatch, tmp_path, {"DEFAULT_WINDOW_WIDTH": 77}, config_arg="~/extra.json")

	assert args.window_width == 77
	assert "not found" not in capsys.readouterr().err


def test_store_config_file_expands_tilde(monkeypatch, tmp_path):
	monkeypatch.setenv("HOME", str(tmp_path))
	monkeypatch.chdir(tmp_path)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["--store_config_file=~/stored.json", "-w"])

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_config_file(args)

	assert exc_info.value.code == 0
	assert json.loads((tmp_path / "stored.json").read_text())["DEFAULT_PRINT_SUCCESS_HOSTS"] is True


def test_names_outside_the_settings_cannot_be_set(monkeypatch, tmp_path):
	_process_args_with_config(monkeypatch, tmp_path, {"version": "0.0", "CONFIG_FILE_CHAIN": ["/tmp/x.json"], "ERRORS": [1]})

	assert multiSSH3.version != "0.0"
	assert multiSSH3.CONFIG_FILE_CHAIN != ["/tmp/x.json"]


def test_internal_names_among_the_settings_cannot_be_set(monkeypatch, tmp_path, capsys):
	# mssh's own state sits next to the settings (a lock, the path the help names, a reference copy)
	_process_args_with_config(monkeypatch, tmp_path, {"_SYSTEM_HOST_FILE": "/tmp/hosts", "_etc_hosts_lock": None,
		"_BUILTIN_IPMI_DEFINITION": {"username": "x"}})

	assert multiSSH3._SYSTEM_HOST_FILE == "/etc/hosts"
	assert hasattr(multiSSH3._etc_hosts_lock, "acquire")
	assert multiSSH3._BUILTIN_IPMI_DEFINITION["username"] == "admin"
	assert "Warning" not in capsys.readouterr().err


def test_documented_underscore_settings_can_be_set(monkeypatch, tmp_path):
	_process_args_with_config(monkeypatch, tmp_path,
		{"_DEFAULT_NO_START": True, "_etc_hosts": {"node1": "10.0.0.1"}, "__DEBUG_MODE": True})

	assert multiSSH3._DEFAULT_NO_START is True
	assert multiSSH3._etc_hosts == {"node1": "10.0.0.1"}
	assert getattr(multiSSH3, "__DEBUG_MODE") is True


def test_etc_hosts_from_a_config_must_map_names_to_addresses(tmp_path, capsys):
	path = _write_config(tmp_path / "multiSSH3.config.json", {"_etc_hosts": {"node1": 5}})

	assert multiSSH3.load_config_file(str(path)) == {}
	assert "_etc_hosts" in capsys.readouterr().err


@pytest.mark.parametrize("key", ["DEFAULT_HOSTS", "DEFAULT_PASSWORD", "DEFAULT_SKIP_HOSTS", "DEFAULT_ENV_FILE", "DEFAULT_IPMI_ARGS",
	"DEFAULT_IPMI_USERNAME", "DEFAULT_IPMI_INTERFACE_IP_PREFIX", "DEFAULT_SSH_KEY_SEARCH_PATH", "DEFAULT_HISTORY_FILE",
	"DEFAULT_HOST_FILE", "DEFAULT_IPMI_METHOD", "DEFAULT_ENCODING"])
def test_null_for_a_string_setting_means_its_built_in_value(tmp_path, capsys, key):
	# mssh ran with these before they were checked; null reads as "not set"
	path = _write_config(tmp_path / "multiSSH3.config.json", {key: None})

	assert multiSSH3.load_config_file(str(path)) == {key: multiSSH3._BUILTIN_SETTINGS[key]}
	assert "Warning" not in capsys.readouterr().err


def test_null_hosts_in_a_config_reaches_the_command_line_as_all(tmp_path):
	# null hosts crashed a bare mssh ('NoneType' object is not iterable): null is "not set", so "all"
	path = _write_config(tmp_path / "multiSSH3.config.json", {"DEFAULT_HOSTS": None})

	args = multiSSH3.process_args(["--config_file", str(path)])

	assert args.hosts == "all"
	assert multiSSH3.getStrCommand(**vars(args))


def _import_with_system_config(tmp_path, home_config, system_config, expression):
	'''Import a copy of multiSSH3 whose /etc config is in tmp_path, HOME at tmp_path/home; print expression.'''
	system = _write_config(tmp_path / "etc" / "multiSSH3.config.json", system_config)
	home = tmp_path / "home"
	_write_config(home / ".multiSSH3.config.json", home_config)
	source = MULTISSH3_PY.read_text()
	assert source.count("'/etc/multiSSH3.config.json'") == 1
	(tmp_path / "relocated.py").write_text(source.replace("'/etc/multiSSH3.config.json'", repr(str(system))))
	code = "import sys; sys.path.insert(0, {!r}); import relocated; print({})".format(str(tmp_path), expression)
	result = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
		universal_newlines=True, env=dict(os.environ, HOME=str(home)), cwd=str(tmp_path), timeout=60)
	return system, result


def test_a_bad_value_a_more_specific_config_replaces_does_not_warn(tmp_path):
	# a user cannot edit /etc: its value they replace in their own config must not warn on every run
	system, result = _import_with_system_config(tmp_path,
		{"DEFAULT_TIMEOUT": 20, "DEFAULT_PASSWORD": None},
		{"DEFAULT_TIMEOUT": "abc", "DEFAULT_WINDOW_WIDTH": "wide", "DEFAULT_PASSWORD": "from-etc"},
		"relocated.DEFAULT_TIMEOUT, repr(relocated.DEFAULT_PASSWORD), relocated.DEFAULT_WINDOW_WIDTH")

	assert result.stdout.split() == ["20", "''", "40"], result.stderr
	assert "DEFAULT_TIMEOUT" not in result.stderr
	# a bad value nothing replaces still warns
	assert "DEFAULT_WINDOW_WIDTH" in result.stderr
	assert str(system) in result.stderr
