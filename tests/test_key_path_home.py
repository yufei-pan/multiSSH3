"""
A key given as ~/... (-uk finds ~/.ssh/id_..., -k '~/key', DEFAULT_IDENTITY_FILE) is looked up in
$HOME by mssh, but ssh expands a ~ itself from the passwd entry, not $HOME. Under sudo -E or in a
container the two differ, and ssh used another user's key: mssh hands ssh the path it found.
The history keeps the ~, so a replay looks in the HOME it runs with.
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


def _home_with_key(tmp_path, monkeypatch):
	home = tmp_path / "althome"
	(home / ".ssh").mkdir(parents=True)
	(home / ".ssh" / "id_ed25519").write_text("key")
	monkeypatch.setenv("HOME", str(home))
	return home


def _argv_of_run(host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "ssh", "rsync": "rsync", "scp": "scp"})
	calls = []

	def popen(argv, **kwargs):
		calls.append(list(argv))
		return FakeProc()

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	multiSSH3.run_command(host, threading.Semaphore(1), 5)
	assert host.returncode == 0
	return calls[0]


def test_use_key_hands_ssh_the_key_found_in_home_and_records_the_tilde(fake_host, monkeypatch, tmp_path):
	home = _home_with_key(tmp_path, monkeypatch)
	history = tmp_path / "history"
	args = multiSSH3.get_parser().parse_args(["mock-a", "hostname", "-uk", "--history_file", str(history)])

	args = multiSSH3.process_keys(args)
	multiSSH3.record_command_history(vars(args))
	argv = _argv_of_run(fake_host("mock-a", "hostname", identity_file=args.identity_file), monkeypatch)

	assert argv[argv.index("-i") + 1] == str(home / ".ssh" / "id_ed25519")
	line = history.read_text()
	assert "~/.ssh/id_ed25519" in line
	assert str(home) not in line


def test_a_key_given_with_a_tilde_is_expanded_from_home(fake_host, monkeypatch, tmp_path):
	home = _home_with_key(tmp_path, monkeypatch)

	argv = _argv_of_run(fake_host("mock-a", "hostname", identity_file="~/.ssh/id_ed25519"), monkeypatch)

	assert argv[argv.index("-i") + 1] == str(home / ".ssh" / "id_ed25519")


def test_rsync_hands_its_ssh_the_key_found_in_home(fake_host, monkeypatch, tmp_path):
	home = _home_with_key(tmp_path, monkeypatch)
	host = fake_host("mock-a", "/tmp/dest", files=["/tmp/a"], identity_file="~/.ssh/id_ed25519")

	argv = _argv_of_run(host, monkeypatch)

	rsh = shlex.split(argv[argv.index("--rsh") + 1])
	assert rsh[rsh.index("-i") + 1] == str(home / ".ssh" / "id_ed25519")


def test_a_key_path_without_tilde_is_passed_as_given(fake_host, monkeypatch, tmp_path):
	_home_with_key(tmp_path, monkeypatch)

	argv = _argv_of_run(fake_host("mock-a", "hostname", identity_file="keys/id_rsa"), monkeypatch)

	assert argv[argv.index("-i") + 1] == "keys/id_rsa"
