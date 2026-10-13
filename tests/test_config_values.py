import json
import os
import subprocess
import sys

import pytest

import multiSSH3
from conftest import MULTISSH3_PY


def _run_mssh(home, *args):
	'''Run mssh in a fresh process with HOME (and so the config file chain) at home.'''
	env = dict(os.environ, HOME=str(home))
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
