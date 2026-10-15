"""
--copy_id: what ssh-copy-id is given, and how its results count. The tools are fakes: Popen records
each command line and ends it as the test says, os.system stands for the runs on the terminal.
"""
import io
import os
import signal

import pytest

import multiSSH3

BINS = {"sh": "/bin/sh", "ssh": "/bin/ssh", "sshpass": "/bin/sshpass", "ssh-copy-id": "/bin/ssh-copy-id"}
HOST_KEY_OPTIONS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
# ssh-copy-id gives up on a host that does not answer (test_ssh_timeouts.py)
TIMEOUT_OPTIONS = "-o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
OK = (b"", b"", 0)


class _FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout, self.stderr, self.stdin = io.BytesIO(stdout), io.BytesIO(stderr), None
		self.returncode = returncode

	def poll(self):
		return self.returncode

	def communicate(self, timeout=None):
		return b"", b""


def _fake_tools(monkeypatch, tmp_path, results=None, bins=BINS, command_results=None):
	"""
	Record every command line run. The ssh-copy-id of a host in results ends that way, the ssh command
	of a host in command_results too; the others succeed.
	"""
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "_binPaths", dict(bins))
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())
	monkeypatch.setattr(multiSSH3, "SSH_STRICT_HOST_KEY_CHECKING", False)
	# what ssh -G would say: no ProxyJump
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: {"proxyjump": "none", "proxycommand": "none"})
	argvs = []

	def popen(argv, **kwargs):
		argvs.append(list(argv))
		if _copy_id_lines([argv]):
			# the sh -c line ends with the host
			return _FakeProc(*next((result for name, result in (results or {}).items() if argv[2].endswith(" " + name)), OK))
		return _FakeProc(*next((result for name, result in (command_results or {}).items() if name in argv), OK))

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	return argvs


def _copy_id_lines(argvs):
	return [argv[2] for argv in argvs if argv[:2] == ["/bin/sh", "-c"] and "ssh-copy-id" in argv[2]]


def _run(**kwargs):
	options = dict(no_watch=True, quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)
	options.update(kwargs)
	return multiSSH3.run_command_on_hosts(**options)


@pytest.mark.parametrize("strict", [False, True])
def test_copy_id_checks_host_keys_as_every_ssh_mssh_runs(monkeypatch, tmp_path, strict):
	argvs = _fake_tools(monkeypatch, tmp_path)
	monkeypatch.setattr(multiSSH3, "SSH_STRICT_HOST_KEY_CHECKING", strict)

	_run(hosts="mock-a", commands=["true"], copy_id=True, username="bob", password="pw")

	# a new node's unknown key made sshpass give up (exit 6) before ssh-copy-id got anywhere
	options = "" if strict else HOST_KEY_OPTIONS + " "
	assert _copy_id_lines(argvs) == ["/bin/sshpass -e /bin/ssh-copy-id {}{} bob@mock-a".format(options, TIMEOUT_OPTIONS)]


def test_copy_id_takes_the_extra_args_ssh_copy_id_knows(monkeypatch, tmp_path):
	argvs = _fake_tools(monkeypatch, tmp_path)

	_run(hosts="mock-a", commands=["true"], copy_id=True, password="pw", identity_file="~/my key",
		extraargs="-p 2222 -oConnectTimeout=5 -J admin@jump -F /etc/cfg -i /login/key -v -l alice --delete")

	# the port, ssh options and jump host reach the host as ssh's do. ssh-copy-id's -i is the key to install
	# (-k), so ssh's -i (a key to log in with) stays out, as do -F (ssh-copy-id 7.4 and 8.0 fail on it)
	# and what ssh-copy-id has no option for
	# -ea's ConnectTimeout wins over mssh's
	assert _copy_id_lines(argvs) == ["/bin/sshpass -e /bin/ssh-copy-id -i '{}' {} -o ServerAliveInterval=15 "
		"-o ServerAliveCountMax=4 -p 2222 -o ConnectTimeout=5 -o ProxyJump=admin@jump mock-a".format(os.path.expanduser("~/my key"), HOST_KEY_OPTIONS)]


def test_copy_id_without_password_asks_on_the_terminal_with_the_same_options(monkeypatch, tmp_path):
	argvs = _fake_tools(monkeypatch, tmp_path, bins={k: v for k, v in BINS.items() if k != "sshpass"})
	typed = []
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: typed.append(command) or 0)

	hosts = _run(hosts="mock-[a-b]", copy_id=True, username="bob", extraargs="-p 2222")

	assert sorted(typed) == ["/bin/ssh-copy-id {} {} -p 2222 bob@mock-{}".format(HOST_KEY_OPTIONS, TIMEOUT_OPTIONS, name) for name in "ab"]
	assert argvs == []
	assert sorted((host.name, host.returncode) for host in hosts) == [("bob@mock-a", 0), ("bob@mock-b", 0)]


def test_copy_id_alone_returns_its_hosts_to_library_callers(monkeypatch, tmp_path):
	_fake_tools(monkeypatch, tmp_path, results={"mock-b": (b"", b"", 6)})

	# no MultiSSHError (code 0) for a copy that went fine, and the hosts it failed on can be seen
	hosts = _run(hosts="mock-[a-b]", copy_id=True, password="pw")

	assert sorted((host.name, host.returncode) for host in hosts) == [("mock-a", 0), ("mock-b", 6)]
	assert all("/bin/ssh-copy-id " in host.command for host in hosts)


def _failed_hosts(err):
	"""The failed_hosts line of the summary, with mock-[b-c] written out."""
	line = next(line for line in err.splitlines() if line.startswith("failed_hosts: "))
	return line.replace("mock-[b-c]", "mock-b,mock-c")


def _main(*args):
	with pytest.raises(SystemExit) as exit_info:
		multiSSH3.main(list(args) + ["--no_watch", "--no_history"])
	return exit_info.value.code


def test_cli_copy_id_exits_with_the_number_of_hosts_it_failed_on(monkeypatch, tmp_path, capsys):
	_fake_tools(monkeypatch, tmp_path, results={"bob@mock-b": (b"", b"", 6), "bob@mock-c": (b"", b"", 1)})

	code = _main("-ci", "-p", "pw", "bob@mock-[a-c]")

	err = capsys.readouterr().err
	assert code == 2
	assert "Copy id finished" not in err
	assert "Failed hosts (Return Code not 0) count: 2" in err
	assert "mock-a" not in _failed_hosts(err) and "mock-b" in _failed_hosts(err) and "mock-c" in _failed_hosts(err)


def test_cli_copy_id_with_a_command_counts_failed_copies(monkeypatch, tmp_path, capsys):
	# the command still runs on every host: with -p it does not need the key
	argvs = _fake_tools(monkeypatch, tmp_path, results={"bob@mock-b": (b"", b"", 6), "bob@mock-c": (b"", b"", 1)},
		command_results={"bob@mock-c": (b"", b"", 1)})

	code = _main("-ci", "-p", "pw", "bob@mock-[a-c]", "hostname")

	err = capsys.readouterr().err
	# mock-b's copy failed, mock-c failed both: each failed host counts once
	assert code == 2
	assert "mock-a" not in _failed_hosts(err) and "mock-b" in _failed_hosts(err) and "mock-c" in _failed_hosts(err)
	assert sum(argv[-1] == "hostname" for argv in argvs) == 3


def test_cli_copy_id_without_password_counts_failed_copies(monkeypatch, tmp_path, capsys):
	_fake_tools(monkeypatch, tmp_path, bins={k: v for k, v in BINS.items() if k != "sshpass"})
	# os.system returns a wait status: exit status 1 is 256
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: 256 if command.endswith("mock-b") else 0)

	code = _main("-ci", "mock-[a-b]")

	assert code == 1
	assert "failed_hosts: mock-b" in capsys.readouterr().err


def test_copy_id_ctrl_c_on_the_terminal_stops_before_the_next_host(monkeypatch, tmp_path, capsys):
	_fake_tools(monkeypatch, tmp_path, bins={k: v for k, v in BINS.items() if k != "sshpass"})
	typed = []
	# os.system itself ignores Ctrl-C: the terminal's SIGINT ended ssh-copy-id (its shell), not mssh
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: typed.append(command) or signal.SIGINT)
	monkeypatch.setattr(multiSSH3, "_emo", False)

	hosts = _run(hosts="mock-[a-c]", copy_id=True, quiet=False)

	assert len(typed) == 1
	assert [host.returncode for host in hosts] == [-signal.SIGINT]
	assert "Ctrl C" in capsys.readouterr().err
