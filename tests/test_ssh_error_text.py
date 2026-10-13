"""
ssh's own messages against the remote command's: which stderr lines mssh hides, and how the pretty
output summarizes ssh's connect errors. A remote program's error must reach the user as printed,
even when it mentions the same words as one of ssh's notices.
"""
import io
import json
import os
import re
import subprocess
import sys
import threading

import pytest

import multiSSH3
from conftest import MULTISSH3_PY

# the built-in ERROR_MESSAGES_TO_IGNORE from 4.81 to 6.31 (4.81 started with the first five); up to 6.18,
# --store_config_file wrote it into config files
OLD_DEFAULT_IGNORE_LIST = [
	'Pseudo-terminal will not be allocated because stdin is not a terminal',
	'Connection to .* closed',
	'Warning: Permanently added',
	'mux_client_request_session',
	'disabling multiplexing',
	'Killed by signal',
	'Connection reset by peer',
]

# remote programs' errors that mention the words of one of ssh's notices
REMOTE_ERRORS = [
	"curl: (56) Recv failure: Connection reset by peer",
	"psql: error: Connection to server at db1 closed unexpectedly",
	"Connection to db1 closed unexpectedly, retrying",
	"worker: Killed by signal 9 (OOM)",
]

# ssh's own notices, exactly as OpenSSH prints them
SSH_NOTICES = [
	"Pseudo-terminal will not be allocated because stdin is not a terminal.",
	"Warning: Permanently added 'node1' (ED25519) to the list of known hosts.",
	"Warning: Permanently added the ECDSA host key for IP address '10.0.0.7' to the list of known hosts.",
	"mux_client_request_session: session request failed: Session open refused by peer",
	"ControlSocket /run/user/0/ssh_sockets_0123abcd already exists, disabling multiplexing",
	"Connection to node1 closed.",
	"Connection to node1 closed by remote host.",
	"Killed by signal 15.",
]


class FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
		self.returncode = returncode

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""


def _run(fake_host, monkeypatch, stderr, returncode):
	host = fake_host("node1", "cmd")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *a, **k: FakeProc(stderr=stderr, returncode=returncode))
	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)
	return host


def _ssh_lines(lines):
	# ssh ends its messages with \r\n
	return "".join(line + "\r\n" for line in lines).encode()


def test_remote_errors_that_mention_ssh_notices_are_kept(fake_host, monkeypatch):
	stderr = "".join(line + "\n" for line in REMOTE_ERRORS).encode()

	host = _run(fake_host, monkeypatch, stderr, 56)

	assert host.returncode == 56
	assert host.stderr == REMOTE_ERRORS


def test_ssh_connection_setup_resets_are_kept(fake_host, monkeypatch):
	# what sshd's MaxStartups throttling gives; ssh before 8.0 prints only the first line
	setup_reset = ["kex_exchange_identification: read: Connection reset by peer", "Connection reset by 10.0.0.7 port 22"]
	legacy_setup_reset = ["ssh_exchange_identification: read: Connection reset by peer"]

	assert _run(fake_host, monkeypatch, _ssh_lines(setup_reset), 255).stderr == setup_reset
	assert _run(fake_host, monkeypatch, _ssh_lines(legacy_setup_reset), 255).stderr == legacy_setup_reset


def test_ssh_own_notices_are_still_hidden(fake_host, monkeypatch):
	stderr = _ssh_lines(SSH_NOTICES[:4]) + b"real error\n" + _ssh_lines(SSH_NOTICES[4:])

	host = _run(fake_host, monkeypatch, stderr, 3)

	assert host.stderr == ["real error"]


def test_configured_patterns_match_anywhere_in_a_line(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "__ERROR_MESSAGES_TO_IGNORE_REGEX", re.compile("noisy tool"))

	host = _run(fake_host, monkeypatch, b"warning from noisy tool: ignored\nreal error\n", 1)

	assert host.stderr == ["real error"]


@pytest.mark.parametrize("stored", [OLD_DEFAULT_IGNORE_LIST, OLD_DEFAULT_IGNORE_LIST[:5]])
def test_stored_copy_of_the_old_default_ignore_list_gives_way_to_the_current_one(stored):
	config = {"ERROR_MESSAGES_TO_IGNORE": list(stored), "DEFAULT_HOSTS": "all"}

	multiSSH3.apply_config_key_compat(config)

	assert config == {"DEFAULT_HOSTS": "all"}


def test_customized_ignore_list_is_kept():
	custom = OLD_DEFAULT_IGNORE_LIST + ["my tool's noise"]
	config = {"ERROR_MESSAGES_TO_IGNORE": list(custom)}

	multiSSH3.apply_config_key_compat(config)

	assert config["ERROR_MESSAGES_TO_IGNORE"] == custom


def test_config_file_with_the_old_defaults_keeps_remote_errors(tmp_path):
	"""The whole chain: a config file written by an older mssh, the fake ssh, the JSON output."""
	home = tmp_path / "home"
	bin_dir = tmp_path / "bin"
	runtime_dir = tmp_path / "run"
	for directory in (home, bin_dir, runtime_dir):
		directory.mkdir(mode=0o700)
	# runs the command locally: skips ssh's options up to --, then the host
	fake_ssh = bin_dir / "ssh"
	fake_ssh.write_text('#!/bin/sh\nwhile [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done\n[ $# -ge 2 ] || exit 255\nshift 2\nexec sh -c "$*"\n')
	fake_ssh.chmod(0o755)
	(home / ".multiSSH3.config.json").write_text(json.dumps({"ERROR_MESSAGES_TO_IGNORE": OLD_DEFAULT_IGNORE_LIST}))
	env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime_dir), PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
	command = 'echo "{}" >&2; echo "Warning: Permanently added \'127.0.0.1\' (ED25519) to the list of known hosts." >&2; exit 56'.format(REMOTE_ERRORS[0])

	result = subprocess.run([sys.executable, str(MULTISSH3_PY), "-nw", "-j", "-C", "-I", "127.0.0.1", command],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env, timeout=30)

	hosts = json.loads(result.stdout)
	assert hosts[0]["returncode"] == 56
	assert hosts[0]["stderr"] == [REMOTE_ERRORS[0]]
