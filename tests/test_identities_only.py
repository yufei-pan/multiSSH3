"""
-k / -uk name a key: ssh must log in with that key only (IdentitiesOnly=yes). Without it ssh offers
every ssh-agent key first, and with 6 or more in the agent sshd ends the login (MaxAuthTries) before
the key is tried: "Too many authentication failures" on every host.
"""
import io
import shlex
import threading

import multiSSH3


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


def _argv_of_run(fake_host, monkeypatch, passwds=None, **host_kwargs):
	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "ssh", "scp": "scp", "rsync": "rsync", "sshpass": "sshpass"})
	calls = []

	def popen(argv, **kwargs):
		calls.append(list(argv))
		return FakeProc()

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	host = fake_host("mock-a", **host_kwargs)
	multiSSH3.run_command(host, threading.Semaphore(1), 5, passwds)
	assert host.returncode == 0
	return calls[0]


def _has_option(words, option):
	return any(words[i:i + 2] == ["-o", option] for i in range(len(words) - 1))


def test_ssh_uses_only_the_key_given(fake_host, monkeypatch, tmp_path):
	key = tmp_path / "id_ed25519"
	key.write_text("key")

	argv = _argv_of_run(fake_host, monkeypatch, command="hostname", identity_file=str(key))

	assert argv[0] == "ssh"
	assert _has_option(argv, "IdentitiesOnly=yes")
	assert argv[argv.index("-i") + 1] == str(key)
	assert argv.index("IdentitiesOnly=yes") < argv.index("--")


def test_password_runs_use_only_the_key_given(fake_host, monkeypatch, tmp_path):
	# with sshpass too: the agent's keys would use up the tries before the password is asked
	key = tmp_path / "id_ed25519"
	key.write_text("key")

	argv = _argv_of_run(fake_host, monkeypatch, passwds="pw", command="hostname", identity_file=str(key))

	assert argv[:4] == ["sshpass", "-p", "pw", "ssh"]
	assert _has_option(argv, "IdentitiesOnly=yes")


def test_scp_uses_only_the_key_given(fake_host, monkeypatch, tmp_path):
	key = tmp_path / "id_ed25519"
	key.write_text("key")

	argv = _argv_of_run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], scp=True, identity_file=str(key))

	assert argv[0] == "scp"
	assert _has_option(argv, "IdentitiesOnly=yes")
	assert argv.index("IdentitiesOnly=yes") < argv.index("--")


def test_rsync_ssh_uses_only_the_key_given(fake_host, monkeypatch, tmp_path):
	key = tmp_path / "id_ed25519"
	key.write_text("key")

	argv = _argv_of_run(fake_host, monkeypatch, command="/tmp/dest", files=["/tmp/a"], identity_file=str(key))

	assert argv[0] == "rsync"
	rsh = shlex.split(argv[argv.index("--rsh") + 1])
	assert _has_option(rsh, "IdentitiesOnly=yes")
	assert rsh[rsh.index("-i") + 1] == str(key)


def test_a_key_file_that_is_not_there_leaves_the_agent_keys_usable(fake_host, monkeypatch, tmp_path):
	# ssh skips a missing key file; IdentitiesOnly would then leave it no key at all
	missing = tmp_path / "no_such_key"

	argv = _argv_of_run(fake_host, monkeypatch, command="hostname", identity_file=str(missing))

	assert argv[argv.index("-i") + 1] == str(missing)
	assert not _has_option(argv, "IdentitiesOnly=yes")


def test_without_a_key_ssh_chooses_its_keys(fake_host, monkeypatch):
	argv = _argv_of_run(fake_host, monkeypatch, command="hostname")

	assert "-i" not in argv
	assert not _has_option(argv, "IdentitiesOnly=yes")
