'''
Passwords reach sshpass and ipmitool through their environment (sshpass -e, ipmitool -E), not their
command line: ps shows every process's command line to every user of the machine, its environment
only to the same user and root. Through sh -c (IPMI, --copy_id) a password stayed in sh's command line
for the whole run.
'''
import shlex
import threading

import pytest

import multiSSH3
from test_run_command_characterization import AUTH_FAILURE, OK, FakeProc, bins, ipmi

SSH_SECRET = "Hunter2 it's 100%"
BMC_SECRET = "Bmc s3cret's 5%"


def started(monkeypatch, host, passwds=None, definitions=None, binaries=("ssh", "sshpass"), results=None):
	'''(argv, the environment variables added for it) of each command run_command starts for host.'''
	monkeypatch.setattr(multiSSH3, "_binPaths", bins(*binaries))
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_DEFINITIONS", [dict(d) for d in definitions or [ipmi()]])
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	runs = []
	results = list(results or [OK])

	def popen(argv, **kwargs):
		env = kwargs.get("env")
		added = {name: value for name, value in (env or {}).items() if multiSSH3.os.environ.get(name) != value}
		runs.append((list(argv), added, env))
		return FakeProc(*results.pop(0))

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	host.interactive_stdin = False
	multiSSH3.run_command(host, threading.Semaphore(1), 30, passwds)
	return runs


def _no_secret_in(argv):
	return not [word for word in argv if "Hunter2" in word or "s3cret" in word]


@pytest.mark.parametrize("files, program", [(None, "/bin/ssh"), (["/src/a"], "/bin/rsync")])
def test_sshpass_reads_the_password_from_its_environment(monkeypatch, files, program):
	host = multiSSH3.Host("node1", "/dest/" if files else "uptime", files=files, ip="10.0.0.7")

	(argv, added, env), = started(monkeypatch, host, SSH_SECRET, binaries=("ssh", "sshpass", "rsync"))

	assert argv[:3] == ["/bin/sshpass", "-e", program] and _no_secret_in(argv)
	assert added == {"SSHPASS": SSH_SECRET}
	# the rest of the environment is mssh's own
	assert env["PATH"] == multiSSH3.os.environ["PATH"]


def test_without_a_password_the_environment_is_inherited(monkeypatch):
	host = multiSSH3.Host("node1", "uptime", ip="10.0.0.7")

	(argv, added, env), = started(monkeypatch, host)

	assert argv[0] == "/bin/ssh" and env is None


def test_copy_id_through_sh_keeps_the_password_out_of_sh_s_command_line(monkeypatch):
	host = multiSSH3.Host("bob@node1", "ssh-copy-id bob@node1", shell=True, ip="10.0.0.7")

	(argv, added, _), = started(monkeypatch, host, SSH_SECRET, binaries=("sh", "ssh", "sshpass"))

	assert argv[:2] == ["/bin/sh", "-c"] and shlex.split(argv[2])[:3] == ["/bin/sshpass", "-e", "ssh-copy-id"]
	assert _no_secret_in(argv) and added == {"SSHPASS": SSH_SECRET}


@pytest.mark.parametrize("binaries", [("sh", "ipmitool", "ssh"), ("ipmitool", "ssh")])
def test_ipmitool_reads_the_password_from_its_environment(monkeypatch, binaries):
	host = multiSSH3.Host("node1", "power status", ipmi=True, ip="10.0.0.7")

	(argv, added, _), = started(monkeypatch, host, definitions=[ipmi(password=BMC_SECRET)], binaries=binaries)

	words = shlex.split(argv[2]) if argv[0] == "/bin/sh" else argv
	assert "-E" in words and "-P" not in " ".join(words) and _no_secret_in(argv)
	# ipmitool 1.8.19 and later read IPMITOOL_PASSWORD first, older ones IPMI_PASSWORD
	assert added == {"IPMI_PASSWORD": BMC_SECRET, "IPMITOOL_PASSWORD": BMC_SECRET}


def test_ipmi_logins_differing_only_in_password_are_each_tried(monkeypatch):
	# their command lines are the same now: the one already run must not count as this one
	host = multiSSH3.Host("node1", "power status", ipmi=True, ip="10.0.0.7")
	definitions = [ipmi(username="admin", password="first"), ipmi(username="admin", password="second")]

	runs = started(monkeypatch, host, definitions=definitions, binaries=("sh", "ipmitool", "ssh"),
		results=[AUTH_FAILURE, OK])

	assert [added["IPMI_PASSWORD"] for _, added, _ in runs] == ["first", "second"]
	assert host.returncode == 0


def test_a_rejected_password_is_still_explained(monkeypatch):
	host = multiSSH3.Host("node1", "uptime", ip="10.0.0.7")

	started(monkeypatch, host, SSH_SECRET, results=[(b"", b"", 5)])

	assert [line for line in host.stderr if line.startswith("sshpass: the password was not accepted")]


def test_the_shown_command_line_has_no_password(monkeypatch):
	host = multiSSH3.Host("node1", "uptime", ip="10.0.0.7")

	started(monkeypatch, host, SSH_SECRET)

	assert [line for line in host.output if line.startswith("Running command: /bin/sshpass -e /bin/ssh")]
