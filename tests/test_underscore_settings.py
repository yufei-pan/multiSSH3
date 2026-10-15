'''
_DEFAULT_CALLED, _DEFAULT_RETURN_UNFINISHED, _DEFAULT_UPDATE_UNREACHABLE_HOSTS and _DEFAULT_NO_START are
read when run_command_on_hosts is called, not when mssh is imported: a script setting them after the
import, and --config_file, reach it. The command line always starts its hosts and waits for them.
'''
import json

import pytest

import multiSSH3


@pytest.fixture
def runs(monkeypatch):
	'''The keyword arguments of each processRunOnHosts call: hosts are made, none is run.'''
	calls = []
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda *args, **kwargs: calls.append(kwargs))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	return calls


def _call(**kwargs):
	return multiSSH3.run_command_on_hosts("127.0.0.1", ["true"], no_watch=True, quiet=True, no_history=True, **kwargs)


def test_no_start_set_after_the_import_is_used(monkeypatch, runs):
	monkeypatch.setattr(multiSSH3, "_DEFAULT_NO_START", True)

	hosts = _call(called=True)

	assert runs == [] and [host.name for host in hosts] == ["127.0.0.1"]


def test_return_unfinished_and_update_unreachable_set_after_the_import_are_used(monkeypatch, runs):
	monkeypatch.setattr(multiSSH3, "_DEFAULT_RETURN_UNFINISHED", True)
	monkeypatch.setattr(multiSSH3, "_DEFAULT_UPDATE_UNREACHABLE_HOSTS", False)

	_call(called=True)

	assert runs[0]["return_unfinished"] is True
	assert runs[0]["will_update_unreachable_hosts"] is False


def test_called_set_after_the_import_is_used(monkeypatch, runs):
	monkeypatch.setattr(multiSSH3, "_DEFAULT_CALLED", False)
	seen = []
	monkeypatch.setattr(multiSSH3, "_report_tokens_naming_no_hosts", lambda tokens: seen.append(tokens))

	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("typed")])

	_call()

	# only a run from the command line (called False) reports host words naming no hosts, and keeps the
	# keys typed in an earlier run's TUI
	assert seen
	assert multiSSH3.__keyPressesIn == [list("typed")]


def _main(config, tmp_path):
	path = tmp_path / "c.json"
	path.write_text(json.dumps(config))
	with pytest.raises(SystemExit):
		multiSSH3.main(["--config_file", str(path), "--no_history", "-nw", "-q", "127.0.0.1", "true"])


def test_the_command_line_takes_update_unreachable_from_config_file(tmp_path, runs):
	_main({"_DEFAULT_UPDATE_UNREACHABLE_HOSTS": False}, tmp_path)

	assert runs[0]["will_update_unreachable_hosts"] is False


@pytest.mark.parametrize("name", ["_DEFAULT_NO_START", "_DEFAULT_RETURN_UNFINISHED"])
@pytest.mark.parametrize("how", ["config_file", "imported"])
def test_the_command_line_always_runs_its_hosts_and_waits(tmp_path, monkeypatch, runs, name, how):
	# from ~/.multiSSH3.config.json these made mssh say "Complete. All hosts returned 0." having run
	# nothing, or before the hosts finished
	if how == "imported":
		monkeypatch.setattr(multiSSH3, name, True)
		_main({}, tmp_path)
	else:
		_main({name: True}, tmp_path)

	assert len(runs) == 1 and runs[0]["return_unfinished"] is False
