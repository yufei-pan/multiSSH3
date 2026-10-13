import io
import shlex
import shutil
import subprocess
import threading

import pytest

import multiSSH3

# what mssh gives ssh by default (DEFAULT_SSH_CONNECT_TIMEOUT, DEFAULT_SSH_SERVER_ALIVE_*)
DEFAULTS = {"connecttimeout": "30", "serveraliveinterval": "15", "serveralivecountmax": "4"}
# what ssh -G shows for options nothing sets
SSH_BUILT_IN = {"connecttimeout": "none", "serveraliveinterval": "0", "serveralivecountmax": "3"}


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
	# ssh uses the first value it gets, and mssh's own options come first
	argv = _run(fake_host, monkeypatch, extraargs=extraargs)

	options = _timeout_options(_before_destination(argv))
	assert options["connecttimeout"] == "5"
	assert options["serveraliveinterval"] == "15"


@pytest.mark.parametrize("extraargs", [None, "", "-o ConnectTimeout=5", "-o 'ConnectTimeout 5'"])
def test_extraargs_may_be_given_as_they_are_stored(extraargs):
	# as Host.extraargs and DEFAULT_EXTRA_ARGS hold them: None, or the string as typed
	options = _timeout_options(multiSSH3._ssh_timeout_options("mock-a", extraargs))

	assert options.get("connecttimeout") == (None if extraargs and "5" in extraargs else "30")


def test_a_keepalive_interval_given_with_extraargs_leaves_the_count_to_ssh_too(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, extraargs="-o ServerAliveInterval=60")

	assert _timeout_options(_before_destination(argv)) == {"connecttimeout": "30", "serveraliveinterval": "60"}


def test_a_keepalive_count_given_with_extraargs_wins(fake_host, monkeypatch):
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], scp=True,
		extraargs="-o ServerAliveCountMax=10")

	assert _timeout_options(_before_destination(argv)) == {"connecttimeout": "30", "serveraliveinterval": "15",
		"serveralivecountmax": "10"}


def _rsh_options(argv):
	return _timeout_options(shlex.split(argv[argv.index("--rsh") + 1]))


def test_rsyncs_own_options_in_extraargs_set_no_ssh_options(fake_host, monkeypatch):
	# rsync's -o is --owner and its -F a filter rule, neither takes a value
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], extraargs="-o -F -FF")

	assert _rsh_options(argv) == DEFAULTS


def test_an_ssh_option_in_an_rsync_copys_extraargs_wins_too(fake_host, monkeypatch):
	# rsync's own -o takes no value: -o ConnectTimeout=5 can only be meant for its ssh
	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], extraargs="-o ConnectTimeout=5")

	assert _rsh_options(argv) == {"serveraliveinterval": "15", "serveralivecountmax": "4"}


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


def _ssh_config(tmp_path, monkeypatch, user="", system=""):
	'''Make ssh's config files (user: ~/.ssh/config, system: /etc/ssh/ssh_config) the given text.'''
	user_dir = tmp_path / "user-ssh"
	system_dir = tmp_path / "etc-ssh"
	user_dir.mkdir()
	system_dir.mkdir()
	(user_dir / "config").write_text(user)
	(system_dir / "ssh_config").write_text(system)
	monkeypatch.setattr(multiSSH3, "_ssh_config_dirs", lambda: (str(user_dir), str(system_dir)))
	multiSSH3._ssh_config_keywords.cache_clear()
	return user_dir, system_dir


def _fake_ssh_g(monkeypatch, settings_by_destination):
	'''ssh -G stubbed: settings_by_destination[destination] over ssh's built-in values. Returns the asked destinations.'''
	asked = []

	def fake(hostname, config_file=None):
		asked.append(hostname if config_file is None else (hostname, config_file))
		return dict(SSH_BUILT_IN, **settings_by_destination.get(hostname, {}))

	monkeypatch.setattr(multiSSH3, "_ssh_config_values", fake)
	return asked


def test_an_ssh_config_without_these_options_is_not_asked_about_each_host(fake_host, monkeypatch, tmp_path):
	# ssh -G runs the Match exec lines of the ssh config: not for every host of every run
	_ssh_config(tmp_path, monkeypatch, user="Host *\n  ControlMaster auto\n  # ConnectTimeout 5\n",
		system="Host *\n    SendEnv LANG LC_*\n#   ConnectTimeout 0\n#   ServerAliveInterval 0\n")
	asked = _fake_ssh_g(monkeypatch, {})

	argv = _run(fake_host, monkeypatch)

	assert asked == []
	assert _timeout_options(argv) == DEFAULTS


def test_a_connect_timeout_from_the_ssh_config_wins(fake_host, monkeypatch, tmp_path):
	# a command-line -o beats the ssh config: mssh adds its own only where the config sets none
	_ssh_config(tmp_path, monkeypatch, user="Host slow\n  ConnectTimeout 120\n")
	asked = _fake_ssh_g(monkeypatch, {"root@slow": {"connecttimeout": "120"}})

	slow = _run(fake_host, monkeypatch, name="root@slow")
	fast = _run(fake_host, monkeypatch, name="root@fast")

	assert asked == ["root@slow", "root@fast"]
	assert _timeout_options(slow) == {"serveraliveinterval": "15", "serveralivecountmax": "4"}
	assert _timeout_options(fast) == DEFAULTS


def test_no_connect_timeout_set_on_purpose_in_the_ssh_config_wins(fake_host, monkeypatch, tmp_path):
	_ssh_config(tmp_path, monkeypatch, user="Host lab*\n  ConnectTimeout 0\n")
	_fake_ssh_g(monkeypatch, {"lab1": {"connecttimeout": "0"}})

	assert "connecttimeout" not in _timeout_options(_run(fake_host, monkeypatch, name="lab1"))


def test_keepalive_from_the_ssh_config_wins(fake_host, monkeypatch, tmp_path):
	_ssh_config(tmp_path, monkeypatch, system="Host *\n  ServerAliveInterval 60\n")
	_fake_ssh_g(monkeypatch, {"mock-a": {"serveraliveinterval": "60"}})

	assert _timeout_options(_run(fake_host, monkeypatch)) == {"connecttimeout": "30"}


def test_a_keepalive_count_from_the_ssh_config_wins(fake_host, monkeypatch, tmp_path):
	_ssh_config(tmp_path, monkeypatch, user="ServerAliveCountMax=10\n")
	_fake_ssh_g(monkeypatch, {"mock-a": {"serveralivecountmax": "10"}})

	assert _timeout_options(_run(fake_host, monkeypatch)) == {"connecttimeout": "30", "serveraliveinterval": "15"}


def test_an_ssh_config_ssh_cannot_read_leaves_mssh_its_defaults(fake_host, monkeypatch, tmp_path):
	_ssh_config(tmp_path, monkeypatch, user="Host *\n  ConnectTimeout 5\n")
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname, config_file=None: None)

	assert _timeout_options(_run(fake_host, monkeypatch)) == DEFAULTS


def test_options_in_included_files_count(tmp_path, monkeypatch):
	user_dir, system_dir = _ssh_config(tmp_path, monkeypatch,
		user="Host *\n  Include conf.d/*.conf\n",
		system="Include {}/ssh_config.d/*.conf\n".format(tmp_path / "etc-ssh"))
	(user_dir / "conf.d").mkdir()
	(user_dir / "conf.d" / "a.conf").write_text("Host db*\n\tServerAliveInterval 30\n")
	(system_dir / "ssh_config.d").mkdir()
	(system_dir / "ssh_config.d" / "50-site.conf").write_text("Match host *.lab\n  ConnectTimeout = 3\n")

	keywords = multiSSH3._ssh_config_keywords()

	assert {"serveraliveinterval", "connecttimeout"} <= keywords
	assert "serveralivecountmax" not in keywords


def test_an_include_ssh_expands_itself_makes_every_option_count(tmp_path, monkeypatch):
	# tokens (%d) and variables (${HOME}): mssh cannot tell which file ssh reads, so ssh -G is asked
	_ssh_config(tmp_path, monkeypatch, user="Include %d/.ssh/more.conf\n")

	assert multiSSH3._ssh_config_keywords() is None


def test_an_include_loop_ends(tmp_path, monkeypatch):
	user_dir, _ = _ssh_config(tmp_path, monkeypatch, user="Include config\nConnectTimeout 4\n")

	assert "connecttimeout" in multiSSH3._ssh_config_keywords()


def test_a_config_file_given_with_extraargs_is_the_one_read(fake_host, monkeypatch, tmp_path):
	# ssh -F reads that file only
	_ssh_config(tmp_path, monkeypatch, user="Host *\n  ConnectTimeout 5\n")
	cluster = tmp_path / "cluster.conf"
	cluster.write_text("Host *\n  ServerAliveInterval 20\n")
	asked = _fake_ssh_g(monkeypatch, {"mock-a": {"serveraliveinterval": "20"}})

	argv = _run(fake_host, monkeypatch, extraargs="-F {}".format(cluster))

	assert asked == [("mock-a", str(cluster))]
	assert _timeout_options(argv) == {"connecttimeout": "30"}


@pytest.mark.parametrize("extraargs", ["-FF", "-F --delete", "-F no-such-file"])
def test_an_F_that_names_no_file_leaves_the_ssh_config_as_it_is(fake_host, monkeypatch, tmp_path, extraargs):
	# rsync's -FF are filter rules
	_ssh_config(tmp_path, monkeypatch, user="Host *\n  ConnectTimeout 5\n")
	asked = _fake_ssh_g(monkeypatch, {"mock-a": {"connecttimeout": "5"}})

	argv = _run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], extraargs=extraargs)

	assert asked == ["mock-a"]
	assert _rsh_options(argv) == {"serveraliveinterval": "15", "serveralivecountmax": "4"}


@pytest.mark.skipif(not shutil.which("ssh"), reason="needs OpenSSH's ssh (ssh -G does not connect)")
def test_real_ssh_reads_the_ssh_config_as_mssh_expects(tmp_path, monkeypatch):
	# -F: only this file, not the ssh config of the machine running the tests
	config = tmp_path / "config"
	config.write_text("Host slow\n  ConnectTimeout 120\nHost *\n  ServerAliveInterval 1m\n")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", shutil.which("ssh"))

	slow = multiSSH3._ssh_timeout_options("root@slow", ["-F", str(config)])
	other = multiSSH3._ssh_timeout_options("other", ["-F", str(config)])

	assert _timeout_options(slow) == {}
	assert _timeout_options(other) == {"connecttimeout": "30"}


@pytest.mark.skipif(not shutil.which("ssh"), reason="needs OpenSSH's ssh (ssh -G does not connect)")
def test_real_ssh_accepts_the_options_as_mssh_writes_them():
	options = multiSSH3._ssh_timeout_options("mock-a")
	result = subprocess.run([shutil.which("ssh"), "-F", "/dev/null", "-G"] + options + ["--", "mock-a"],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=10)

	assert result.returncode == 0, result.stderr
	shown = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
	assert {keyword: shown[keyword] for keyword in DEFAULTS} == DEFAULTS


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
