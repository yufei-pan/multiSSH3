import io
import shlex
import shutil
import subprocess
import threading

import pytest

import multiSSH3

# what mssh gives ssh by default (DEFAULT_SSH_CONNECT_TIMEOUT, DEFAULT_SSH_SERVER_ALIVE_*)
DEFAULTS = {"connecttimeout": "30", "serveraliveinterval": "15", "serveralivecountmax": "4"}


class FakeProc:
	def __init__(self):
		self.stdout = io.BytesIO()
		self.stderr = io.BytesIO()
		self.stdin = io.BytesIO()
		self.returncode = 0

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""


def _run(fake_host, monkeypatch, name="mock-a", command="true", **host_kwargs):
	'''Run one host with fake ssh / scp / rsync, returns the command line mssh started.'''
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	for tool in ("ssh", "scp", "rsync"):
		monkeypatch.setitem(multiSSH3._binPaths, tool, tool)
	monkeypatch.delitem(multiSSH3._binPaths, "sshpass", raising=False)
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_popen)
	multiSSH3.run_command(fake_host(name, command, **host_kwargs), threading.Semaphore(1), timeout=5)
	assert len(calls) == 1
	return calls[0]


def _timeout_options(words):
	'''The ConnectTimeout / ServerAlive* -o options in words, as {keyword: value} (lowercased keywords).'''
	words = [str(word) for word in words]
	found = {}
	for index, word in enumerate(words):
		if word == "-o" and index + 1 < len(words):
			option = words[index + 1]
		elif word.startswith("-o"):
			option = word[2:]
		else:
			continue
		keyword, _, value = option.strip().replace("=", " ", 1).partition(" ")
		if keyword.lower() in DEFAULTS:
			found.setdefault(keyword.lower(), []).append(value.strip())
	return {keyword: values[0] if len(values) == 1 else values for keyword, values in found.items()}


def _before_destination(argv):
	return argv[:argv.index("--")]


def test_ssh_gives_up_on_a_host_that_does_not_answer_or_stops_answering(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch)

	assert _timeout_options(_before_destination(argv)) == DEFAULTS
	assert argv[-3:] == ["--", "mock-a", "true"]


def test_scp_gets_the_same_timeouts(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], scp=True)

	assert argv[0] == "scp"
	assert _timeout_options(_before_destination(argv)) == DEFAULTS


def test_rsync_gets_the_timeouts_in_the_ssh_it_runs(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"])

	assert argv[0] == "rsync"
	assert _rsh_options(argv) == DEFAULTS


@pytest.mark.parametrize("extraargs", [
	"-o ConnectTimeout=5",
	"-oConnectTimeout=5",
	"-o connecttimeout=5",
	"-v -o ConnectTimeout=5 -A",
	["-o", "ConnectTimeout 5"],
	["-o ConnectTimeout=5"],
])
def test_a_connect_timeout_given_with_extraargs_wins(fake_host, monkeypatch, extraargs):
	# ssh uses the first value it gets: mssh's own options come after -ea's
	argv = _run(fake_host, monkeypatch, extraargs=extraargs)

	options = _timeout_options(_before_destination(argv))
	assert options["connecttimeout"] == ["5", "30"]
	assert options["serveraliveinterval"] == "15"


def test_a_keepalive_interval_given_with_extraargs_wins_and_mssh_still_gives_the_count(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, extraargs="-o ServerAliveInterval=60")

	assert _timeout_options(_before_destination(argv)) == {"connecttimeout": "30", "serveraliveinterval": ["60", "15"],
		"serveralivecountmax": "4"}


def test_a_keepalive_count_given_with_extraargs_wins(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, extraargs="-o ServerAliveCountMax=10")

	assert _timeout_options(_before_destination(argv)) == {"connecttimeout": "30", "serveraliveinterval": "15",
		"serveralivecountmax": ["10", "4"]}


def _rsh_options(argv):
	return _timeout_options(shlex.split(argv[argv.index("--rsh") + 1]))


def test_rsyncs_own_options_in_extraargs_set_no_ssh_options(fake_host, monkeypatch):
	# rsync's -o is --owner and its -F a filter rule, neither takes a value
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], extraargs="-o -F -FF")

	assert _rsh_options(argv) == DEFAULTS


def test_an_ssh_option_in_an_rsync_copys_extraargs_wins_too(fake_host, monkeypatch):
	# rsync's own -o takes no value: -o ConnectTimeout=5 can only be meant for its ssh
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], extraargs="-o ConnectTimeout=5")

	# -ea's ssh options go into --rsh too, before mssh's: ssh takes -ea's ConnectTimeout
	assert _rsh_options(argv) == dict(DEFAULTS, connecttimeout=["5", "30"])


def test_zero_leaves_an_option_to_ssh(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_CONNECT_TIMEOUT", 0)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_SERVER_ALIVE_INTERVAL", 0)

	argv = _run(fake_host, monkeypatch)

	# without mssh's keepalive interval, its count would change nothing ssh does
	assert _timeout_options(argv) == {}


@pytest.mark.parametrize("value, expected", [("45", "45"), (2.5, "3"), (None, None), ("soon", None), (-5, None)])
def test_config_values_become_whole_seconds(fake_host, monkeypatch, value, expected):
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_CONNECT_TIMEOUT", value)

	argv = _run(fake_host, monkeypatch)

	assert _timeout_options(argv).get("connecttimeout") == expected


def test_the_settings_are_in_a_generated_config():
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true"])
	config = multiSSH3.generate_default_config(args)

	assert config["DEFAULT_SSH_CONNECT_TIMEOUT"] == 30
	assert config["DEFAULT_SSH_SERVER_ALIVE_INTERVAL"] == 15
	assert config["DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX"] == 4


@pytest.mark.skipif(not shutil.which("ssh"), reason="needs OpenSSH's ssh (ssh -G does not connect)")
def test_real_ssh_takes_extraargs_values_over_the_options_as_mssh_writes_them(tmp_path):
	# -F: only this file. A command-line -o beats the ssh config, and the first one beats the later
	config = tmp_path / "config"
	config.write_text("Host *\n  ConnectTimeout 7\n  ServerAliveInterval 9\n")
	options = multiSSH3._ssh_timeout_options()
	for extra, expected in (([], DEFAULTS), (["-o", "ConnectTimeout=5"], dict(DEFAULTS, connecttimeout="5"))):
		result = subprocess.run([shutil.which("ssh"), "-F", str(config), "-G"] + extra + options + ["--", "mock-a"],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=10)

		assert result.returncode == 0, result.stderr
		shown = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
		assert {keyword: shown[keyword] for keyword in DEFAULTS} == expected


def _copy_id_commands(monkeypatch, tmp_path, **kwargs):
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setitem(multiSSH3._binPaths, "ssh-copy-id", "ssh-copy-id")
	commands = []
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: commands.append(command) or 0)
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **run: commands.extend(host.command for host in run["hosts"]))
	try:
		multiSSH3.run_command_on_hosts(hosts="mock-a", copy_id=True, username="bob", no_watch=True, quiet=True,
			no_history=True, called=True, will_update_unreachable_hosts=False, **kwargs)
	except multiSSH3.MultiSSHError:
		pass  # no command to run after the copy
	return commands


@pytest.mark.parametrize("password", ["", "pw"])
def test_ssh_copy_id_gives_up_on_a_host_that_does_not_answer(monkeypatch, tmp_path, password):
	if password:
		monkeypatch.setitem(multiSSH3._binPaths, "sshpass", "sshpass")

	[command] = _copy_id_commands(monkeypatch, tmp_path, password=password)

	words = shlex.split(command)
	assert words[words.index("ssh-copy-id"):][-1] == "bob@mock-a"
	assert _timeout_options(words) == DEFAULTS


def _unreachable_after(monkeypatch, tmp_path, host):
	unavailable = {}
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])
	multiSSH3.processRunOnHosts(timeout=0, password=None, max_connections=1, hosts=[host], return_unfinished=False,
		no_watch=True, json=False, no_output=True, greppable=False, unavailableHosts=unavailable,
		will_update_unreachable_hosts=True, pre_merge=False)
	return set(unavailable)


def test_a_host_whose_sshd_never_answered_is_unreachable(fake_host, monkeypatch, tmp_path):
	# ConnectTimeout: the host took the connection but sshd never said a word
	host = fake_host("mock-a", "true", ip="10.0.0.5")
	host.returncode = 255
	host.stderr = ["Connection timed out during banner exchange", "Connection to 10.0.0.5 port 22 timed out"]

	assert _unreachable_after(monkeypatch, tmp_path, host) == {"mock-a"}


def test_a_host_that_stopped_answering_during_its_command_is_not_unreachable(fake_host, monkeypatch, tmp_path):
	# ServerAlive*: it answered, ran the command for a while, then went away
	host = fake_host("mock-a", "sleep 100")
	host.returncode = 255
	host.stderr = ["Warning: Permanently added 'mock-a' (ED25519) to the list of known hosts.",
		"Timeout, server mock-a not responding."]

	assert _unreachable_after(monkeypatch, tmp_path, host) == set()
