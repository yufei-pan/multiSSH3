"""
sshpass's own exit codes said in words. sshpass types the password at ssh's prompt; when ssh asks
for it again (5), asks whether to trust an unknown host key (6) or warns that the key known for the
host's IP address differs (7), sshpass gives up and prints nothing: ssh asked on sshpass's terminal.
"""
import io
import threading

import pytest

import multiSSH3

BINS = {"ssh": "/bin/ssh", "sshpass": "/bin/sshpass", "scp": "/bin/scp", "rsync": "/bin/rsync", "sh": "/bin/sh",
	"ssh-copy-id": "/bin/ssh-copy-id"}
PASSWORD = "pw-secret"
NO_PROXY = {"hostname": "mock-a", "proxyjump": "none", "proxycommand": "none"}
PROXY = dict(NO_PROXY, proxyjump="admin@bastion")


class _FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout, self.stderr, self.stdin = io.BytesIO(stdout), io.BytesIO(stderr), None
		self.returncode = returncode

	def poll(self):
		return self.returncode

	def communicate(self, timeout=None):
		return b"", b""


def _run(monkeypatch, host, results, passwds=PASSWORD, bins=BINS, strict=False, ssh_config=NO_PROXY):
	"""
	Run host with run_command, each attempt ending as the next of results says; return the argvs run.
	ssh_config is what ssh -G says about the host.
	"""
	monkeypatch.setattr(multiSSH3, "_binPaths", dict(bins))
	monkeypatch.setattr(multiSSH3, "_ssh_config_values", lambda hostname: ssh_config)
	monkeypatch.setattr(multiSSH3, "SSH_STRICT_HOST_KEY_CHECKING", strict)
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", False)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	results = list(results)
	argvs = []

	def popen(argv, **kwargs):
		argvs.append(list(argv))
		return _FakeProc(*results.pop(0))

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	host.interactive_stdin = False
	multiSSH3.run_command(host, threading.Semaphore(1), 30, passwds)
	return argvs


def _sshpass_lines(lines):
	"""mssh's lines about sshpass: the first says what happened, the next one how to fix it."""
	starts = [index for index, line in enumerate(lines) if line.startswith("sshpass: ")]
	return lines[starts[0]:starts[0] + 2] if starts else []


@pytest.mark.parametrize("code, meaning", [
	(5, "the password was not accepted"),
	(6, "whether to trust"),
	(7, "a different key"),
])
def test_sshpass_exit_codes_say_what_ssh_asked(monkeypatch, fake_host, code, meaning):
	host = fake_host("bob@mock-a", "hostname", ip="10.0.0.7")

	_run(monkeypatch, host, [(b"", b"", code)], strict=True)

	said = _sshpass_lines(host.stderr)
	assert host.returncode == code
	assert said and meaning in said[0] and "exit code {}".format(code) in said[0]
	# a remote command can exit with the same code: the host would then show it without output, too
	assert "unless the command itself exited with {}".format(code) in said[0]
	# the TUI window shows it as well, and no password is ever in it
	assert _sshpass_lines(host.output) == said
	assert not any(PASSWORD in line for line in said)


@pytest.mark.parametrize("strict, cause, remedy", [
	(True, "SSH_STRICT_HOST_KEY_CHECKING is true", "ssh-keyscan mock-a >> ~/.ssh/known_hosts"),
	(False, "SSH_STRICT_HOST_KEY_CHECKING is false", "ProxyJump host"),
])
def test_sshpass_unknown_host_key_says_why_ssh_asked_and_how_to_accept_it(monkeypatch, fake_host, strict, cause, remedy):
	host = fake_host("bob@mock-a", "hostname")

	_run(monkeypatch, host, [(b"", b"", 6)], strict=strict, ssh_config=PROXY)

	text = "\n".join(_sshpass_lines(host.stderr))
	assert cause in text and remedy in text


def test_sshpass_changed_ip_key_says_how_to_remove_the_old_one(monkeypatch, fake_host):
	host = fake_host("bob@mock-a", "hostname", ip="10.0.0.7")

	_run(monkeypatch, host, [(b"", b"", 7)], strict=True)

	assert "ssh-keygen -R 10.0.0.7" in "\n".join(_sshpass_lines(host.stderr))


@pytest.mark.parametrize("ssh_config, extraargs", [(NO_PROXY, None), (PROXY, None), (None, None), (NO_PROXY, "-J admin@bastion")])
def test_without_host_key_checks_only_a_host_on_the_way_gives_6_and_7(monkeypatch, fake_host, ssh_config, extraargs):
	# mssh tells ssh not to check the host's key: unless ssh goes through another host (or mssh cannot
	# tell), a 6 or 7 is the command's own, like curl -s failing to resolve (6) or connect (7)
	may_be_sshpass = ssh_config is not NO_PROXY or extraargs is not None
	for code in (6, 7):
		host = fake_host("bob@mock-a", "check", extraargs=extraargs)

		_run(monkeypatch, host, [(b"", b"", code)], strict=False, ssh_config=ssh_config)

		assert bool(_sshpass_lines(host.stderr)) == may_be_sshpass
	# a password ssh asked for again is not about host keys
	host = fake_host("bob@mock-a", "check", extraargs=extraargs)
	_run(monkeypatch, host, [(b"", b"", 5)], strict=False, ssh_config=ssh_config)
	assert _sshpass_lines(host.stderr)


def test_sshpass_exit_code_of_ssh_copy_id_is_sure(monkeypatch, tmp_path):
	# ssh-copy-id itself exits with 0 or 1, scp too: the code can only be sshpass's
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname.split("@")[-1])
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "_binPaths", dict(BINS))
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: _FakeProc(
		b"", b"/bin/ssh-copy-id: INFO: Source of key(s) to be installed: ...\n", 6))

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-a", copy_id=True, password=PASSWORD, no_watch=True,
		quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)

	said = _sshpass_lines(hosts[0].stderr)
	assert said and "exit code 6" in said[0] and "unless" not in said[0]


def test_sshpass_exit_code_of_scp_is_sure(monkeypatch, fake_host):
	host = fake_host("mock-a", "/dest/", files=["/src/a"], scp=True)

	_run(monkeypatch, host, [(b"", b"Host key verification failed.\n", 6)], strict=True)

	said = _sshpass_lines(host.stderr)
	assert said and "exit code 6" in said[0] and "unless" not in said[0]


def test_rsync_turned_down_by_sshpass_is_not_tried_again_with_scp(monkeypatch, fake_host):
	host = fake_host("mock-a", "/dest/", files=["/src/a"])
	refused = (b"", b"Permission denied, please try again.\nrsync error: unexplained error (code 255)\n", 5)

	# scp would be turned down the same way, after one more wrong password on the host
	argvs = _run(monkeypatch, host, [refused, refused])

	assert len(argvs) == 1 and argvs[0][3] == "/bin/rsync"
	said = _sshpass_lines(host.stderr)
	assert said and "unless rsync itself exited with 5" in said[0]


@pytest.mark.parametrize("passwds, result", [
	(None, (b"", b"", 6)),  # no sshpass: the code is the command's
	(PASSWORD, (b"", b"", 1)),  # not one of sshpass's
	(PASSWORD, (b"partial\n", b"", 6)),  # the command printed: ssh got past its questions
])
def test_other_exit_codes_are_left_as_they_are(monkeypatch, fake_host, passwds, result):
	host = fake_host("mock-a", "check")

	_run(monkeypatch, host, [result], passwds=passwds)

	assert host.returncode == result[2]
	assert _sshpass_lines(host.stderr) == [] and _sshpass_lines(host.output) == []


def test_ssh_ipmitool_still_tries_the_next_definition_after_sshpass_gives_up(monkeypatch, fake_host):
	definition = dict(multiSSH3.get_default_ipmi_definition(), ipmi_method="ssh_ipmitool", username="u", password="p")
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_DEFINITIONS", [dict(definition), dict(definition, password="p2")])
	host = fake_host("node1", "power status", ipmi=True)

	argvs = _run(monkeypatch, host, [(b"", b"", 5), (b"on\n", b"", 0)])

	assert len(argvs) == 2 and host.returncode == 0
	# the TUI window kept what happened to the first login
	assert any("password was not accepted" in line for line in _sshpass_lines(host.output))
