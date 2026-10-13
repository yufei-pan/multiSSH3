"""
A connection the server drops before login (sshd's MaxStartups turning away connections opened at
once, often at a ProxyJump bastion) is noted, and the run ends with a hint.

The stderr lines are what OpenSSH 10.0 and 8.0 clients printed in the real-ssh Docker harness.
"""
import io
import threading

import pytest

import multiSSH3

# OpenSSH 10.0 through a ProxyJump bastion that reset the connection (sshd MaxStartups 10:30:100)
JUMP_RESET_10 = (b"kex_exchange_identification: read: Connection reset by peer\r\n"
	b"Connection reset by 10.0.0.240 port 22\r\n"
	b"Connection closed by UNKNOWN port 65535\r\n")
# OpenSSH 10.0 through a ProxyJump bastion that closed the connection
JUMP_CLOSED_10 = b"Connection closed by 10.0.0.240 port 22\r\nConnection closed by UNKNOWN port 65535\r\n"
# OpenSSH 10.0 when the target behind the bastion closed the connection
TARGET_BEHIND_JUMP_CLOSED_10 = b"Connection closed by UNKNOWN port 65535\r\n"
# OpenSSH 10.0, no jump host: the target closed / reset the connection
DIRECT_CLOSED_10 = b"Connection closed by 10.0.0.7 port 22\r\n"
DIRECT_RESET_10 = b"kex_exchange_identification: read: Connection reset by peer\r\nConnection reset by 10.0.0.7 port 22\r\n"
# OpenSSH 8.0 (EL8) through the bastion: no host named
JUMP_RESET_80 = b"kex_exchange_identification: read: Connection reset by peer\r\nkex_exchange_identification: Connection closed by remote host\r\n"
# the session died after login (OpenSSH 10.0 and 8.0 alike)
CLOSED_AFTER_LOGIN = b"Warning: Permanently added 'node1' (ED25519) to the list of known hosts.\r\nConnection to node1 closed by remote host.\r\n"
OK = (b"node1\n", b"", 0)
BINS = {"ssh": "/bin/ssh", "scp": "/bin/scp", "rsync": "/bin/rsync", "sshpass": "/bin/sshpass", "sh": "/bin/sh", "ipmitool": "/bin/ipmitool"}
JUMP_CONFIG = {"hostname": "node1", "port": "22", "proxyjump": "root@bastion", "proxycommand": "none"}
DIRECT_CONFIG = {"hostname": "node1", "port": "22", "proxyjump": "none", "proxycommand": "none"}


class FakeProc:
	def __init__(self, stdout, stderr, returncode):
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
		self.returncode = returncode

	def poll(self):
		return self.returncode

	def communicate(self, timeout=None):
		return b"", b""


def run(monkeypatch, results, ssh_config=JUMP_CONFIG, retry_limit=..., passwds=None, debug=False,
		addresses=None, **host_kwargs):
	"""Run one host against fake processes, one result per process started; return (host, argvs, sleeps)."""
	monkeypatch.setattr(multiSSH3, "_binPaths", dict(BINS))
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", debug)
	monkeypatch.setattr(multiSSH3, "_emo", False)
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: dict(ssh_config) if ssh_config else None)
	# no DNS: the addresses each name has
	monkeypatch.setattr(multiSSH3.socket, "getaddrinfo",
		lambda name, *args: [(2, 1, 6, "", (address, 0)) for address in (addresses or {}).get(name, [])])
	sem = threading.Semaphore(1)
	results = list(results)
	argvs = []
	sleeps = []

	def popen(argv, **kwargs):
		argvs.append(list(argv))
		return FakeProc(*results.pop(0))

	def sleep(seconds):
		# the wait must not hold a connection slot
		assert sem.acquire(blocking=False), "slept while holding the semaphore"
		sem.release()
		sleeps.append(seconds)

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", sleep)
	host_kwargs.setdefault("command", "hostname")
	host = multiSSH3.Host(name=host_kwargs.pop("name", "node1"), ip="10.0.0.7", **host_kwargs)
	host.interactive_stdin = False
	kwargs = {} if retry_limit is ... else {"retry_limit": retry_limit}
	multiSSH3.run_command(host, sem, 30, passwds, **kwargs)
	return host, argvs, sleeps


@pytest.mark.parametrize("stderr", [JUMP_RESET_10, JUMP_CLOSED_10, TARGET_BEHIND_JUMP_CLOSED_10, DIRECT_CLOSED_10,
	DIRECT_RESET_10, JUMP_RESET_80], ids=["bastion-reset", "bastion-closed", "target-closed", "closed", "reset", "openssh-8.0"])
def test_a_host_still_dropped_at_the_end_is_noted(monkeypatch, stderr):
	host, _, _ = run(monkeypatch, [(b"", stderr, 255)] * 4)

	assert host.returncode == 255
	assert host.dropped_before_login is True


@pytest.mark.parametrize("result", [
	(b"", CLOSED_AFTER_LOGIN, 255),
	# a reset alone can come after login too
	(b"", b"Connection reset by 10.0.0.7 port 22\r\n", 255),
	(b"partial\n", JUMP_RESET_10, 255),
	(b"", JUMP_RESET_10, 1),
	(b"", b"Welcome to node1\r\n" + JUMP_RESET_10, 255),
], ids=["closed-after-login", "reset-alone", "stdout", "rc-1", "other-line"])
def test_other_failures_are_not_noted(monkeypatch, result):
	host, _, _ = run(monkeypatch, [result, OK])

	assert host.returncode == result[2]
	assert host.dropped_before_login is False


def test_openssh_8_0_names_no_host_so_it_is_not_tried_again_but_noted(monkeypatch):
	# a remote command's own ssh dropped the same way prints the very same lines
	host, argvs, _ = run(monkeypatch, [(b"", JUMP_RESET_80, 255), OK])

	assert len(argvs) == 1
	assert host.returncode == 255
	assert host.dropped_before_login is True


def test_legacy_scp_naming_no_host_is_not_tried_again(monkeypatch):
	# OpenSSH 8.0's scp: exit code 1, no host named
	stderr = b"kex_exchange_identification: read: Connection reset by peer\r\nlost connection\n"
	host, argvs, _ = run(monkeypatch, [(b"", stderr, 1), OK], ssh_config=DIRECT_CONFIG,
		command="/dest/", files=["/src/a"], scp=True)

	assert len(argvs) == 1
	assert host.returncode == 1
	assert host.dropped_before_login is True


def test_dropped_host_is_not_marked_unreachable(tmp_path, monkeypatch):
	host, _, _ = run(monkeypatch, [(b"", JUMP_RESET_10, 255)] * 4)
	assert host.returncode == 255
	path = tmp_path / "unavailable.csv"
	unavailable = {}
	monkeypatch.setattr(multiSSH3, "__globalUnavailableHosts", {})
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(path))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(timeout=1, password=None, max_connections=1, hosts=[host], return_unfinished=False,
		no_watch=True, json=False, no_output=True, greppable=False, unavailableHosts=unavailable,
		will_update_unreachable_hosts=True, pre_merge=False)

	assert unavailable == {}


def test_dropped_flag_survives_copies():
	host = multiSSH3.Host(name="node1", command="true", ip="10.0.0.7")
	host.dropped_before_login = True

	assert host.copy().dropped_before_login is True


def _main_with_hosts(monkeypatch, hosts, args=()):
	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", lambda **kwargs: hosts)
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["127.0.0.1", "true", "--no_history", *args])
	return exc_info.value.code


def test_run_ending_with_dropped_logins_hints_at_max_startups(monkeypatch, capsys):
	dropped = [multiSSH3.Host(name="10.0.0.{}".format(i), command="hostname", ip="10.0.0.{}".format(i)) for i in (1, 2)]
	for host in dropped:
		host.returncode = 255
		host.dropped_before_login = True
	good = multiSSH3.Host(name="10.0.0.3", command="hostname", ip="10.0.0.3")
	good.returncode = 0

	assert _main_with_hosts(monkeypatch, dropped + [good], ["-m", "64"]) == 2

	err = capsys.readouterr().err
	assert "Hint: the server dropped 2 connections before login" in err
	assert "MaxStartups" in err and "-m 10" in err


def test_hint_with_a_low_max_connections_asks_for_lower(monkeypatch, capsys):
	host = multiSSH3.Host(name="10.0.0.1", command="hostname", ip="10.0.0.1")
	host.returncode = 255
	host.dropped_before_login = True

	_main_with_hosts(monkeypatch, [host], ["-m", "8"])

	err = capsys.readouterr().err
	assert "dropped 1 connection before login" in err
	assert "-m 10" not in err and "lower -m" in err


def test_no_hint_for_other_failures(monkeypatch, capsys):
	host = multiSSH3.Host(name="10.0.0.1", command="hostname", ip="10.0.0.1")
	host.returncode = 255

	_main_with_hosts(monkeypatch, [host])

	assert "Hint:" not in capsys.readouterr().err
