import io
import os
import errno
import threading

import pytest

import multiSSH3


class FakeProc:
	def __init__(self, stdout=b"", stderr=b"", returncode=0):
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
		self.returncode = returncode
		self.signals = []

	def poll(self):
		return self.returncode

	def communicate(self, *args, **kwargs):
		return b"", b""

	def send_signal(self, sig):
		self.signals.append(sig)

	def terminate(self):
		self.returncode = -15


def _patch_popen(monkeypatch, fake_factory):
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_factory)


def test_run_command_shell_mode(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("ignored", "echo shell", shell=True)
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"shell\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert calls and calls[0][0] == "/bin/sh"
	assert calls[0][1] == "-c"


def test_shell_fallback_returns_after_single_ssh_attempt(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("ignored", "echo fallback", shell=True)
	calls = []
	monkeypatch.delitem(multiSSH3._binPaths, "sh", raising=False)

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"fallback\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)

	assert len(calls) == 1
	assert calls[0][-3:] == ["--", "localhost", "echo fallback"]
	assert host.returncode == 0


def test_run_command_scp_files(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host(
		"mock-a",
		"/tmp/dest",
		files=["/tmp/a"],
		scp=True,
	)
	host.use_terminal = True  # a lone -nw command: test_command_terminal.py covers the options added without one
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	scp_calls = []

	def fake_popen(argv, **kwargs):
		scp_calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert scp_calls[0] == [
		"scp", "-rp",
		"-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]


def test_run_command_rsync_files(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "/tmp/dest", files=["/tmp/a"], scp=False)
	# Prefer rsync path
	host.use_terminal = True  # a lone -nw command: test_command_terminal.py covers the options added without one
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.delitem(multiSSH3._binPaths, "scp", raising=False)
	rsync_calls = []

	def fake_popen(argv, **kwargs):
		rsync_calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert rsync_calls[0] == [
		"rsync", "-ahlX", "--partial-dir=.rsync-partial", "--info=name",
		"--rsh", "ssh '-o StrictHostKeyChecking=no' '-o UserKnownHostsFile=/dev/null'"
			" -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4",
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]


@pytest.mark.parametrize("gather", [False, True], ids=["push", "gather"])
def test_rsync_writes_a_new_file_and_renames_it_into_place(fake_host, monkeypatch, gather):
	# --inplace wrote into the destination file itself: "Text file busy" on a running binary, and
	# readers saw it half written
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], gatherMode=gather)

	assert calls[0][0] == "rsync"
	assert "--inplace" not in calls[0]


@pytest.mark.parametrize("gather", [False, True], ids=["push", "gather"])
def test_interrupted_rsync_keeps_its_partial_file_beside_the_destination(fake_host, monkeypatch, gather):
	# --partial renamed the part copied so far over the destination when -t, Ctrl-C or a lost
	# connection stopped rsync: the host's file was replaced by a truncated one
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], gatherMode=gather)

	assert "--partial" not in calls[0]
	assert "--partial-dir=.rsync-partial" in calls[0]


def test_run_command_gather_mode_scp(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host(
		"mock-a",
		"/tmp/local",
		files=["/tmp/remote"],
		scp=True,
		gatherMode=True,
	)
	host.use_terminal = True  # a lone -nw command: test_command_terminal.py covers the options added without one
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	gather_calls = []

	def fake_popen(argv, **kwargs):
		gather_calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert gather_calls[0] == [
		"scp", "-rp",
		"-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"--", "mock-a:/tmp/remote", "/tmp/local",
	]


# what rsync prints when the remote host has no rsync: the remote shell's words, then rsync's own
RSYNC_MISSING_BASH = (b"bash: line 1: rsync: command not found\n"
	b"rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n"
	b"rsync error: error in rsync protocol data stream (code 12) at io.c(285) [sender=3.5.0]\n")


def _copy_with_results(fake_host, monkeypatch, results, files, command="/dest/", **host_kwargs):
	'''Run one copy to mock-a against fake rsync / scp runs, return the host and the argv of each run.'''
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	results = list(results)
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return results.pop(0)

	_patch_popen(monkeypatch, fake_popen)
	host = fake_host("mock-a", command, files=files, **host_kwargs)
	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)
	return host, calls


@pytest.mark.parametrize("returncode,stderr", [
	(24, b'file has vanished: "/src/a/tmp.swp"\n'
		b"rsync warning: some files vanished before they could be transferred (code 24) at main.c(1338) [sender=3.5.0]\n"),
	(23, b'rsync: [sender] send_files failed to open "/src/a/secret": Permission denied (13)\n'
		b"rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1338) [sender=3.5.0]\n"),
	(11, b"rsync: [receiver] write failed on \"/dest/a\": No space left on device (28)\n"),
	(5, b"@ERROR: auth failed on module data\n"),
	(12, b"rsync: connection unexpectedly closed (4521 bytes received so far) [sender]\n"),
], ids=["vanished", "partial", "disk_full", "auth", "dropped_midway"])
def test_rsync_error_stands_without_scp_retry(fake_host, monkeypatch, returncode, stderr):
	# rsync ran and reported on its copy: scp would copy everything again (nested, for a src/ directory)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc(stderr=stderr, returncode=returncode)], ["/src/a"])

	assert [argv[0] for argv in calls] == ["rsync"]
	assert host.returncode == returncode
	assert host.scp is False


@pytest.mark.parametrize("returncode,stderr", [
	(12, RSYNC_MISSING_BASH),
	(12, b"sh: 1: rsync: not found\nrsync: connection unexpectedly closed (0 bytes received so far) [sender]\n"),
	(12, b"zsh:1: command not found: rsync\n"),
	(12, b"rsync: Command not found.\n"),
	(12, b"fish: Unknown command: rsync\n"),
	(12, b"'rsync' is not recognized as an internal or external command,\noperable program or batch file.\n"),
	(12, b"bash: rsync: Befehl nicht gefunden.\n"
		b"rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n"),
	(127, b"rsync error: remote command not found (code 127) at io.c(232) [sender=3.2.7]\n"),
	(255, b"ssh: connect to host mock-a port 22: Connection refused\n"
		b"rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n"),
	# an rsync older than mssh's options (--info is 3.1, -X 3.0): macOS's stock 2.6.9, openrsync
	(1, b"rsync: --info=name: unknown option\n"
		b"rsync error: syntax or usage error (code 1) at /BuildRoot/Library/Caches/com.apple.xbs/Sources/rsync/rsync-55/rsync/main.c(1337) [client=2.6.9]\n"),
	(1, b"rsync: unrecognized option `--info=name'\nusage: rsync [-0aBCcDEgHIJKkLlmnOoPpRrStuVvWx] [-e program] [--del] source ... directory\n"),
	(2, b"rsync: -ahlX: unknown option\n"),
], ids=["bash", "dash", "zsh", "tcsh", "fish", "windows", "localized", "code127", "ssh_failed", "rsync_2.6.9", "openrsync", "code2"])
def test_rsync_that_never_ran_is_retried_with_scp(fake_host, monkeypatch, returncode, stderr):
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=stderr, returncode=returncode), FakeProc()], ["/src/a"])

	assert [argv[0] for argv in calls] == ["rsync", "scp"]
	assert calls[1][-3:] == ["--", "/src/a", "mock-a:/dest/"]
	assert host.returncode == 0
	assert host.scp is True


# what rsync -X says when the destination (NFSv3, vfat, ...) keeps no extended attributes; the data is copied
RSYNC_XATTRS_UNSUPPORTED = (b'rsync: [receiver] rsync_xal_set: fsetxattr("/dest/a","user.origin") failed: Operation not supported (95)\n'
	b"rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1394) [sender=3.5.0]\n")


@pytest.mark.parametrize("gather", [False, True], ids=["push", "gather"])
def test_rsync_that_cannot_set_xattrs_copies_again_without_them(fake_host, monkeypatch, gather):
	# mssh adds -X on its own: a destination that cannot keep extended attributes is no failed copy
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_XATTRS_UNSUPPORTED, returncode=23), FakeProc()], ["/src/a"], gatherMode=gather)

	assert [argv[:2] for argv in calls] == [["rsync", "-ahlX"], ["rsync", "-ahl"]]
	assert calls[0][2:] == calls[1][2:]
	assert host.returncode == 0
	assert host.scp is False
	assert any("extended attributes" in line and "Operation not supported" in line for line in host.stderr)


def test_rsync_without_xattrs_keeps_its_other_errors(fake_host, monkeypatch):
	permission = (b'rsync: [sender] send_files failed to open "/src/a/secret": Permission denied (13)\n'
		b"rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1394) [sender=3.5.0]\n")
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_XATTRS_UNSUPPORTED + permission, returncode=23), FakeProc(stderr=permission, returncode=23)], ["/src/a"])

	assert [argv[:2] for argv in calls] == [["rsync", "-ahlX"], ["rsync", "-ahl"]]
	assert host.returncode == 23


def test_scp_retry_copies_the_contents_of_a_trailing_slash_directory(fake_host, monkeypatch, tmp_path):
	# rsync puts the contents of src/ into /dest/, scp src/ would make /dest/src
	src = tmp_path / "src"
	(src / "sub").mkdir(parents=True)
	(src / "b.txt").write_text("b")
	(src / ".hidden").write_text("h")
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()], [str(src) + "/"])

	assert calls[1][-5:] == ["--", str(src) + "/.hidden", str(src) + "/b.txt", str(src) + "/sub", "mock-a:/dest/"]
	assert host.returncode == 0


@pytest.mark.parametrize("command", ["/dest/", "/dest"])
def test_scp_retry_puts_a_single_directory_inside_the_destination(fake_host, monkeypatch, tmp_path, command):
	# alone, scp would copy it to the name /dest when /dest does not exist; destination/. fails instead
	src = tmp_path / "src"
	src.mkdir()
	(src / "only.txt").write_text("o")
	plain = tmp_path / "plain"
	plain.mkdir()
	for files, source in (([str(src) + "/"], str(src) + "/only.txt"), ([str(plain)], str(plain))):
		host, calls = _copy_with_results(fake_host, monkeypatch,
			[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()], files, command=command)

		assert calls[1][-3:] == ["--", source, "mock-a:/dest/."]
		assert host.returncode == 0


def test_scp_retry_keeps_a_single_file_destination(fake_host, monkeypatch, tmp_path):
	# copying one file to a new name works the same with both tools
	source = tmp_path / "a.txt"
	source.write_text("a")
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()], [str(source)], command="/dest/b.txt")

	assert calls[1][-3:] == ["--", str(source), "mock-a:/dest/b.txt"]


def test_scp_retry_skipped_for_an_empty_trailing_slash_directory(fake_host, monkeypatch, tmp_path):
	empty = tmp_path / "empty"
	empty.mkdir()
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12)], [str(empty) + "/"])

	assert [argv[0] for argv in calls] == ["rsync"]
	assert host.returncode == 12
	assert any("scp" in line and str(empty) + "/" in line for line in host.stderr)


def test_scp_retry_skipped_when_the_entries_overflow_the_command_line(fake_host, monkeypatch, tmp_path):
	# 60000 files made scp fail to start (E2BIG) with a traceback; the budget is made small here
	monkeypatch.setattr(multiSSH3, "_SCP_ARGV_BUDGET", 4096, raising=False)
	src = tmp_path / "src"
	src.mkdir()
	for index in range(50):
		(src / ("file_%02d_" % index + "x" * 100)).write_text("")
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12)], [str(src) + "/"])

	assert [argv[0] for argv in calls] == ["rsync"]
	assert host.returncode == 12
	assert any("50 entries" in line and str(src) + "/" in line for line in host.stderr)


def test_gather_scp_retry_skipped_for_a_trailing_slash_source_into_an_existing_destination(fake_host, monkeypatch, tmp_path):
	# the remote directory cannot be listed here, scp would copy it whole into the local destination
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12)], ["/var/log/app/"], command=str(tmp_path) + "/", gatherMode=True)

	assert [argv[0] for argv in calls] == ["rsync"]
	assert host.returncode == 12
	assert any("scp" in line and "/var/log/app/" in line for line in host.stderr)


def test_gather_scp_retry_skipped_for_trailing_slash_sources_together(fake_host, monkeypatch, tmp_path):
	# several sources go into the destination directory, each one whole
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12)],
		["/var/log/app/", "/etc/hosts"], command=str(tmp_path / "new") + "/", gatherMode=True)

	assert [argv[0] for argv in calls] == ["rsync"]
	assert host.returncode == 12


def test_gather_scp_retry_for_a_trailing_slash_source_into_a_new_destination(fake_host, monkeypatch, tmp_path):
	# scp creates the missing destination as the copy, which holds the contents, as rsync's does
	destination = str(tmp_path / "new") + "/"
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()], ["/var/log/app/"], command=destination, gatherMode=True)

	assert calls[1][-3:] == ["--", "mock-a:/var/log/app/", destination]
	assert host.returncode == 0


def test_gather_scp_retry_for_a_plain_source(fake_host, monkeypatch):
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()], ["/etc/hosts"], command="/tmp/mock-a_hosts", gatherMode=True)

	assert calls[1][-3:] == ["--", "mock-a:/etc/hosts", "/tmp/mock-a_hosts"]
	assert host.returncode == 0


def test_requested_scp_copies_a_trailing_slash_directory_itself(fake_host, monkeypatch, tmp_path):
	# with -W the whole run uses scp's rules, only a retry for rsync copies the way rsync does
	src = tmp_path / "src"
	src.mkdir()
	(src / "b.txt").write_text("b")
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], [str(src) + "/"], scp=True)

	assert calls[0][-3:] == ["--", str(src) + "/", "mock-a:/dest/"]


@pytest.mark.parametrize("name,remote", [
	("root@fd00::5", "root@[fd00::5]"),
	("fd00::5", "[fd00::5]"),
	("fe80::1%eth0", "[fe80::1%eth0]"),
	("root@[fd00::5]", "root@[fd00::5]"),
	("root@10.0.0.5", "root@10.0.0.5"),
])
@pytest.mark.parametrize("scp", [False, True], ids=["rsync", "scp"])
def test_copy_brackets_an_ipv6_address(fake_host, monkeypatch, name, remote, scp):
	# rsync and scp take the first colon as the end of the host: fd00::5:/dest/ means host fd00
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	calls = []
	_patch_popen(monkeypatch, lambda argv, **kwargs: calls.append(argv) or FakeProc())
	push = fake_host(name, "/dest/", files=["/src/a"], scp=scp)
	gather = fake_host(name, "/local/", files=["/remote/a"], scp=scp, gatherMode=True)

	multiSSH3.run_command(push, threading.Semaphore(1), timeout=5)
	multiSSH3.run_command(gather, threading.Semaphore(1), timeout=5)

	assert calls[0][-2:] == ["/src/a", remote + ":/dest/"]
	assert calls[1][-2:] == [remote + ":/remote/a", "/local/"]


def test_ssh_command_keeps_an_ipv6_address_as_given(fake_host, monkeypatch):
	calls = []
	_patch_popen(monkeypatch, lambda argv, **kwargs: calls.append(argv) or FakeProc())
	host = fake_host("root@fd00::5", "uptime")

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert calls[0][-2:] == ["root@fd00::5", "uptime"]


def _rsync_split(command):
	'''Split an rsync --rsh command into words as rsync does (main.c do_cmd): spaces separate words,
	single or double quotes keep spaces, a doubled quote inside the same quotes is one literal quote,
	backslashes are not special.'''
	words = []
	i = 0
	while i < len(command):
		if command[i] == " ":
			i += 1
			continue
		word = []
		in_quote = ""
		while i < len(command) and (command[i] != " " or in_quote):
			char = command[i]
			if char in "'\"" and not in_quote:
				in_quote = char
				i += 1
				continue
			if char == in_quote:
				if command[i + 1:i + 2] == in_quote:
					word.append(char)
					i += 2
				else:
					in_quote = ""
					i += 1
				continue
			word.append(char)
			i += 1
		assert not in_quote, "rsync rejects a missing trailing quote"
		words.append("".join(word))
	return words


@pytest.mark.parametrize("identity_file", [
	"/home/u/my keys/id_ed25519",
	"/home/u/o'brien/id_rsa",
	'/home/u/"quoted" \\back/id',
	"~/.ssh/id_ed25519",
])
def test_rsync_rsh_is_the_configured_ssh_with_each_argument_intact(fake_host, monkeypatch, tmp_path, identity_file):
	# rsync splits --rsh on spaces: an identity path with a space became two arguments, and the
	# configured ssh was ignored for a plain "ssh"
	monkeypatch.setenv("HOME", str(tmp_path))  # a ~ key is expanded from HOME, where there is none
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	calls = []
	_patch_popen(monkeypatch, lambda argv, **kwargs: calls.append(argv) or FakeProc())
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "/opt/open ssh/bin/ssh")
	host = fake_host("mock-a", "/dest/", files=["/src/a"], identity_file=identity_file)
	# run alone on the terminal: no NumberOfPasswordPrompts=0 (no-tty-prompts) among the words checked here
	host.use_terminal = True

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	rsh = calls[0][calls[0].index("--rsh") + 1]
	assert _rsync_split(rsh) == ["/opt/open ssh/bin/ssh", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"-i", os.path.expanduser(identity_file), "-o", "ConnectTimeout=30", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]


MSSH_SSH_OPTIONS = ["ssh", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null"]


@pytest.mark.parametrize("extraargs,ssh_words,rsync_words", [
	("-o ConnectTimeout=5", ["-o", "ConnectTimeout=5"], []),
	("-oConnectTimeout=5", ["-oConnectTimeout=5"], []),
	("-p 2222", ["-p", "2222"], []),
	("-p2222", ["-p2222"], []),
	("-i /home/u/.ssh/id_ed25519", ["-i", "/home/u/.ssh/id_ed25519"], []),  # rsync -i sent the private key as a file
	("-J root@bastion", ["-J", "root@bastion"], []),
	("-F /home/u/ssh_config", ["-F", "/home/u/ssh_config"], []),
	("-l root", ["-l", "root"], []),
	("-c aes128-ctr", ["-c", "aes128-ctr"], []),
	("--delete -o ConnectTimeout=5 -z", ["-o", "ConnectTimeout=5"], ["--delete", "-z"]),
	# rsync's own options stay rsync's
	("--delete", [], ["--delete"]),
	("-i", [], ["-i"]),
	("-p --delete", [], ["-p", "--delete"]),
	("-P", [], ["-P"]),
	("--bwlimit=1000 -z", [], ["--bwlimit=1000", "-z"]),
	(["-o", "ConnectTimeout=5", "--delete"], ["-o", "ConnectTimeout=5"], ["--delete"]),
	# as shlex.split gives it (-ea "-o 'ProxyCommand=ssh -W %h:%p bastion'"): one word in ssh's argv
	(["-o", "ProxyCommand=ssh -W %h:%p bastion"], ["-o", "ProxyCommand=ssh -W %h:%p bastion"], []),
], ids=["o", "o_attached", "p", "p_attached", "i", "J", "F", "l", "c", "mixed", "delete", "itemize", "perms", "progress",
	"bwlimit", "list", "value_with_spaces"])
@pytest.mark.parametrize("gather", [False, True], ids=["push", "gather"])
def test_rsync_hands_ssh_options_from_extraargs_to_ssh(fake_host, monkeypatch, extraargs, ssh_words, rsync_words, gather):
	# rsync read -ea "-o ConnectTimeout=5" as --owner and a file to copy named ConnectTimeout=5
	# a host run alone on the terminal: no NumberOfPasswordPrompts=0 (no-tty-prompts) among the words checked here
	monkeypatch.setattr(multiSSH3, "_ssh_cannot_ask", lambda host, passwds: False)
	# and no ssh timeout options (ssh-timeouts, whose own tests check -ea winning over them)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_CONNECT_TIMEOUT", 0)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_SERVER_ALIVE_INTERVAL", 0)
	monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], extraargs=extraargs, gatherMode=gather)

	argv = calls[0]
	assert _rsync_split(argv[argv.index("--rsh") + 1]) == MSSH_SSH_OPTIONS + ssh_words
	assert argv[argv.index("--rsh") + 2:argv.index("--")] == rsync_words


@pytest.mark.parametrize("extraargs,scp_words", [
	("-p 2222", ["-P", "2222"]),  # scp's -p keeps times, its port is -P
	("-p2222", ["-P2222"]),
	("-P 2222", ["-P", "2222"]),
	("-o ConnectTimeout=5 -J root@bastion", ["-o", "ConnectTimeout=5", "-J", "root@bastion"]),
	("-l 8192", ["-l", "8192"]),  # scp's bandwidth limit
], ids=["p", "p_attached", "P", "o_J", "limit"])
def test_scp_gets_ssh_options_from_extraargs_its_way(fake_host, monkeypatch, extraargs, scp_words):
	# a host run alone on the terminal: no NumberOfPasswordPrompts=0 (no-tty-prompts) among the words checked here
	monkeypatch.setattr(multiSSH3, "_ssh_cannot_ask", lambda host, passwds: False)
	# and no ssh timeout options (ssh-timeouts, whose own tests check -ea winning over them)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_CONNECT_TIMEOUT", 0)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_SERVER_ALIVE_INTERVAL", 0)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], extraargs=extraargs, scp=True)

	argv = calls[0]
	assert argv[argv.index("-o UserKnownHostsFile=/dev/null") + 1:argv.index("--")] == scp_words


def test_ssh_command_gets_extraargs_as_given(fake_host, monkeypatch):
	# a host run alone on the terminal: no NumberOfPasswordPrompts=0 (no-tty-prompts) among the words checked here
	monkeypatch.setattr(multiSSH3, "_ssh_cannot_ask", lambda host, passwds: False)
	# and no ssh timeout options (ssh-timeouts, whose own tests check -ea winning over them)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_CONNECT_TIMEOUT", 0)
	monkeypatch.setattr(multiSSH3, "DEFAULT_SSH_SERVER_ALIVE_INTERVAL", 0)
	calls = []
	_patch_popen(monkeypatch, lambda argv, **kwargs: calls.append(argv) or FakeProc())
	host = fake_host("mock-a", "uptime", extraargs="-p 2222 -o ConnectTimeout=5")

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert calls[0][calls[0].index("-o UserKnownHostsFile=/dev/null") + 1:calls[0].index("--")] == ["-p", "2222", "-o", "ConnectTimeout=5"]


@pytest.mark.parametrize("path,keep_globs,quoted", [
	("/tmp/dst y/", False, "/tmp/dst\\ y/"),
	("/tmp/it's $HOME/", False, "/tmp/it\\'s\\ \\$HOME/"),
	("/a;b&c|d<e>f(g)h`i\"j\\k#l!m\tn", False, "/a\\;b\\&c\\|d\\<e\\>f\\(g\\)h\\`i\\\"j\\\\k\\#l\\!m\\\tn"),
	("/data/*.log", False, "/data/\\*.log"),  # a destination is a name
	("/data/[ab]{1,2}?.log", True, "/data/[ab]{1,2}?.log"),  # sources stay globs, as for rsync and scp
	("/var/log/my app/*.log", True, "/var/log/my\\ app/*.log"),
	("~/my dir/", False, "~/my\\ dir/"),  # still the home directory
	("/plain/path-1_2.txt", False, "/plain/path-1_2.txt"),
], ids=["space", "quote_dollar", "shell_characters", "star_in_destination", "globs", "glob_and_space", "home", "plain"])
def test_scp_shell_quoted(path, keep_globs, quoted):
	assert multiSSH3._scp_shell_quoted(path, keep_globs) == quoted


def _no_protocol_probe(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_scp_uses_remote_shell", lambda argv: pytest.fail("scp's protocol is not needed"))


@pytest.mark.parametrize("legacy,destination", [(True, "mock-a:/tmp/dst\\ y/"), (False, "mock-a:/tmp/dst y/")],
	ids=["legacy", "sftp"])
@pytest.mark.parametrize("retry", [False, True], ids=["requested", "retry"])
def test_scp_quotes_the_destination_for_its_legacy_protocol(fake_host, monkeypatch, legacy, destination, retry):
	# OpenSSH < 9.0 scp hands the destination to the host's shell: "scp: ambiguous target";
	# the SFTP protocol takes it as written
	probed = []
	monkeypatch.setattr(multiSSH3, "_scp_uses_remote_shell", lambda argv: probed.append(argv) or legacy)
	results = [FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12), FakeProc()] if retry else [FakeProc()]
	host, calls = _copy_with_results(fake_host, monkeypatch, results, ["/src/a"], command="/tmp/dst y/",
		scp=not retry, extraargs="-p 2222")

	assert calls[-1][0] == "scp"
	assert calls[-1][-1] == destination
	assert probed and probed[0] == calls[-1][:calls[-1].index("--")]


def test_scp_destination_without_shell_characters_needs_no_probe(fake_host, monkeypatch):
	_no_protocol_probe(monkeypatch)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], command="/tmp/dst-1/", scp=True)

	assert calls[0][-1] == "mock-a:/tmp/dst-1/"


def test_scp_gather_quotes_its_sources_for_either_protocol(fake_host, monkeypatch, tmp_path):
	# the legacy protocol reads them in the host's shell, the SFTP one as globs: a backslash serves both
	_no_protocol_probe(monkeypatch)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/tmp/dst y/r.txt", "/var/log/*.log"],
		command=str(tmp_path) + "/", scp=True, gatherMode=True)

	assert calls[0][-3:] == ["mock-a:/tmp/dst\\ y/r.txt", "mock-a:/var/log/*.log", str(tmp_path) + "/"]


def test_rsync_takes_remote_paths_as_written(fake_host, monkeypatch, tmp_path):
	# rsync 3.2.4+ protects its arguments itself
	_no_protocol_probe(monkeypatch)
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], ["/src/a"], command="/tmp/dst y/")

	assert calls[0][-1] == "mock-a:/tmp/dst y/"


class _Ran:
	def __init__(self, stderr):
		self.stderr = stderr
		self.returncode = 1


@pytest.mark.parametrize("stderr,legacy", [
	(b"Executing: program /usr/bin/false host mssh-scp-protocol.invalid, user (unspecified), command scp -v -r -p -t /\nlost connection\n", True),
	(b"Executing: program /usr/bin/false host mssh-scp-protocol.invalid, user (unspecified), command sftp\nscp: Connection closed\n", False),
	(b"unknown option -- O\nusage: scp [-346BCpqrTv] ...\n", False),
], ids=["legacy", "sftp", "usage"])
def test_scp_protocol_probe_reads_what_scp_would_run(monkeypatch, stderr, legacy):
	monkeypatch.setattr(multiSSH3, "_scp_protocol_cache", {})
	runs = []

	def fake_run(argv, **kwargs):
		runs.append(argv)
		return _Ran(stderr)

	monkeypatch.setattr(multiSSH3.subprocess, "run", fake_run)
	argv = ["/usr/bin/scp", "-rp", "-o StrictHostKeyChecking=no"]

	assert multiSSH3._scp_uses_remote_shell(argv) is legacy
	assert multiSSH3._scp_uses_remote_shell(argv) is legacy
	assert len(runs) == 1  # once per command line
	# nothing is connected to: scp's ssh is a program that exits at once
	assert runs[0][:3] == argv and "-S" in runs[0] and "-v" in runs[0]
	assert os.path.basename(runs[0][runs[0].index("-S") + 1]) in ("false", "true")


def test_scp_protocol_probe_that_fails_quotes_nothing(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_scp_protocol_cache", {})

	def fake_run(argv, **kwargs):
		raise OSError("no scp")

	monkeypatch.setattr(multiSSH3.subprocess, "run", fake_run)

	assert multiSSH3._scp_uses_remote_shell(["/missing/scp", "-rp"]) is False


@pytest.fixture
def linked_tree(tmp_path):
	'''A config that is a relative link to a file, a link to a directory, a dangling link and a directory.'''
	(tmp_path / "srv").mkdir()
	(tmp_path / "srv" / "app.conf").write_text("new")
	(tmp_path / "etc").mkdir()
	(tmp_path / "etc" / "app.conf").symlink_to("../srv/app.conf")
	(tmp_path / "etc" / "plain.conf").write_text("plain")
	(tmp_path / "app-2").mkdir()
	(tmp_path / "current").symlink_to("app-2")
	(tmp_path / "gone").symlink_to("nowhere")
	(tmp_path / "dir").mkdir()
	(tmp_path / "dir" / "inner").symlink_to("../srv/app.conf")
	return tmp_path


@pytest.mark.parametrize("names", [["etc/app.conf"], ["etc/app.conf", "etc/plain.conf"]], ids=["link", "link_and_file"])
def test_rsync_copies_the_file_a_linked_source_points_to(fake_host, monkeypatch, linked_tree, names):
	# rsync -l replaced the host's /etc/app.conf with a link to ../srv/app.conf, which points nowhere there
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], [str(linked_tree / name) for name in names])

	assert "--copy-links" in calls[0]
	assert calls[0][-len(names) - 1:-1] == [str(linked_tree / name) for name in names]


@pytest.mark.parametrize("names", [
	["etc/plain.conf"],
	["dir"],  # --copy-links would follow the links inside it too
	["current"],  # a link to a directory: --copy-links would also follow every link inside it
	["gone"],  # points nowhere: copied as the link it is
	["etc/app.conf", "dir"],
	["current/"],  # the trailing slash already copies the directory's contents
], ids=["file", "directory", "link_to_directory", "dangling_link", "link_with_directory", "link_to_directory_contents"])
def test_rsync_keeps_these_links_as_links(fake_host, monkeypatch, linked_tree, names):
	host, calls = _copy_with_results(fake_host, monkeypatch, [FakeProc()], [str(linked_tree) + "/" + name for name in names])

	assert "--copy-links" not in calls[0]


def test_rsync_reports_a_dangling_link_among_linked_files(linked_tree):
	# with --copy-links rsync says "symlink has no referent" for it, as scp fails on it: no warning
	assert multiSSH3._rsync_link_sources([str(linked_tree / "etc/app.conf"), str(linked_tree / "gone")]) == (True, [])


def test_rsync_link_sources_name_the_links_copied_as_links(linked_tree):
	copy_links, kept = multiSSH3._rsync_link_sources([str(linked_tree / "etc/app.conf"), str(linked_tree / "dir"),
		str(linked_tree / "current"), str(linked_tree / "gone")])

	assert copy_links is False
	assert [(path[len(str(linked_tree)) + 1:], target) for path, target, _ in kept] == [
		("etc/app.conf", "../srv/app.conf"), ("current", "app-2"), ("gone", "nowhere")]


def _gather_with_rsync(fake_host, monkeypatch, files, destination, results, make_links=(), second_run_copies=None):
	'''Gather files from mock-a with fake rsync runs; the first run leaves the given local links behind
	as rsync -l does for a source that is a link on the host, the second one copies files to the
	second_run_copies paths (default: where each link was). Return the host, each run's argv and
	whether each link still existed when the next run started.'''
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	results = list(results)
	calls = []
	links_before_run = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		links_before_run.append([os.path.islink(path) for path, _ in make_links])
		if len(calls) == 1:
			for path, target in make_links:
				os.symlink(target, path)
		elif len(calls) == 2 and not results[0].returncode:
			for path in ([path for path, _ in make_links] if second_run_copies is None else second_run_copies):
				with open(path, "w") as copy:
					copy.write("what the link points to")
		return results.pop(0)

	_patch_popen(monkeypatch, fake_popen)
	host = fake_host("mock-a", destination, files=files, gatherMode=True)
	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)
	return host, calls, links_before_run


@pytest.mark.parametrize("files,destination,copy", [
	(["/etc/os-release"], "{tmp}/g/", "{tmp}/g/os-release"),
	(["/etc/os-release"], "{tmp}/existing", "{tmp}/existing/os-release"),
	(["/etc/os-release"], "{tmp}/one_file", "{tmp}/one_file"),
	(["/etc/os-release", "/etc/hostname"], "{tmp}/g", "{tmp}/g/os-release"),
], ids=["into_directory", "into_existing_directory", "to_a_new_name", "with_another_file"])
def test_gathered_link_is_copied_again_as_what_it_points_to(fake_host, monkeypatch, tmp_path, files, destination, copy):
	# rsync brought /etc/os-release back as a link to ../usr/lib/os-release, which points into this machine
	(tmp_path / "existing").mkdir()
	(tmp_path / "g").mkdir()
	destination, copy = destination.format(tmp=tmp_path), copy.format(tmp=tmp_path)
	host, calls, links_before_run = _gather_with_rsync(fake_host, monkeypatch, files, destination,
		[FakeProc(stdout=b"os-release -> ../usr/lib/os-release\n"), FakeProc(stdout=b"os-release\n")],
		make_links=[(copy, "../usr/lib/os-release")])

	assert len(calls) == 2
	assert "--copy-links" not in calls[0]
	# --no-recursive: a link to a directory is skipped, --copy-links would follow every link inside it
	assert "--copy-links" in calls[1] and "--no-recursive" in calls[1]
	assert calls[1][-2:] == ["mock-a:/etc/os-release", destination]
	assert links_before_run[1] == [False]  # removed first: rsync -L would follow it here
	# without -X: no retry follows, which would find the links that are put back (see run_command)
	assert [arg for arg in calls[1][:calls[1].index("--")] if arg not in ("--copy-links", "--no-recursive")] == (
		[calls[0][0], "-ahl"] + calls[0][2:calls[0].index("--")])
	assert not os.path.islink(copy)
	assert host.returncode == 0
	assert host.stdout == ["os-release"]
	assert any("/etc/os-release" in line and "link" in line for line in host.output)


def test_gathered_link_into_a_linked_destination_stays_a_link(fake_host, monkeypatch, tmp_path):
	# rsync writes through a destination that is a link; following links there could write anywhere
	(tmp_path / "real").mkdir()
	(tmp_path / "via").symlink_to("real")
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/etc/os-release"], str(tmp_path / "via"),
		[FakeProc()], make_links=[(str(tmp_path / "real" / "os-release"), "../usr/lib/os-release")])

	assert len(calls) == 1
	assert host.returncode == 0


@pytest.mark.parametrize("source", ["/etc/", "/etc/*.conf"], ids=["contents", "glob"])
def test_gather_without_a_single_copy_per_source_is_not_rerun(fake_host, monkeypatch, tmp_path, source):
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, [source], str(tmp_path) + "/",
		[FakeProc()], make_links=[(str(tmp_path / "app.conf"), "../srv/app.conf")])

	assert len(calls) == 1


def test_failed_gather_rerun_is_not_retried_with_scp(fake_host, monkeypatch, tmp_path):
	# scp would copy every source again into a destination that may hold links rsync made
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/etc/os-release"], str(tmp_path) + "/",
		[FakeProc(), FakeProc(stderr=RSYNC_MISSING_BASH, returncode=12)], make_links=[(str(tmp_path / "os-release"), "x")])

	assert [argv[0] for argv in calls] == ["rsync", "rsync"]
	assert host.returncode == 12


def test_gathered_link_to_a_directory_is_put_back_as_the_link(fake_host, monkeypatch, tmp_path):
	# copied as a directory, the next gather failed: rsync cannot replace a directory with the link
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/srv/current", "/etc/os-release"], str(tmp_path) + "/",
		[FakeProc(), FakeProc(stdout=b"skipping directory current\nos-release\n")],
		make_links=[(str(tmp_path / "current"), "app-2"), (str(tmp_path / "os-release"), "../usr/lib/os-release")],
		second_run_copies=[str(tmp_path / "os-release")])

	assert len(calls) == 2
	assert os.readlink(str(tmp_path / "current")) == "app-2"
	assert host.returncode == 0
	assert host.stderr == ["Warning: /srv/current is a symbolic link to a directory on the host, copied as the link (-> app-2)."]


def test_gathered_link_to_nothing_on_the_host_ends_with_rsyncs_error(fake_host, monkeypatch, tmp_path):
	dangling = (b'rsync: [sender] link_stat "/etc/broken" failed: No such file or directory (2)\n'
		b"rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1394) [sender=3.5.0]\n")
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/etc/broken"], str(tmp_path) + "/",
		[FakeProc(), FakeProc(stderr=dangling, returncode=23)], make_links=[(str(tmp_path / "broken"), "/nonexistent")])

	assert len(calls) == 2
	assert host.returncode == 23
	assert any("link_stat" in line for line in host.stderr)
	# rsync's error alone does not say the source is a link; the link rsync copied first is put back
	assert host.stderr[-1].startswith("Warning: /etc/broken is a symbolic link on the host") and "-> /nonexistent" in host.stderr[-1]
	assert os.readlink(str(tmp_path / "broken")) == "/nonexistent"


def test_gathered_links_are_put_back_after_a_failed_second_copy(fake_host, monkeypatch, tmp_path):
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/etc/os-release"], str(tmp_path) + "/",
		[FakeProc(), FakeProc(stderr=b"ssh: connect to host mock-a port 22: Connection refused\n", returncode=255)],
		make_links=[(str(tmp_path / "os-release"), "../usr/lib/os-release")])

	assert host.returncode == 255
	assert os.readlink(str(tmp_path / "os-release")) == "../usr/lib/os-release"
	assert host.stderr[0].startswith("ssh: connect to host")  # the connect error stays first


def test_gathered_link_copied_again_has_no_note_when_it_works(fake_host, monkeypatch, tmp_path):
	host, calls, _ = _gather_with_rsync(fake_host, monkeypatch, ["/etc/os-release"], str(tmp_path) + "/",
		[FakeProc(), FakeProc()], make_links=[(str(tmp_path / "os-release"), "x")])

	assert len(calls) == 2
	assert host.stderr == []


def test_run_command_ipmitool_local(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"Chassis Power is on\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(
		host,
		sem,
		timeout=5,
		ipmi_definitions_list=[multiSSH3.get_default_ipmi_definition()],
	)
	assert host.returncode == 0
	assert calls and "ipmitool" in " ".join(calls[0])


def test_run_command_ipmi_unsupported_method(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	defn = multiSSH3.get_default_ipmi_definition()
	defn["ipmi_method"] = "not-a-method"
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[defn])
	assert host.returncode == 1
	assert any("not supported" in line for line in host.stderr + host.output)


def test_run_command_retry_limit_exhausted(fake_host):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	multiSSH3.run_command(host, sem, timeout=5, retry_limit=-1)
	assert host.returncode == 1
	assert any("Retry limit" in line for line in host.stderr + host.output)


def test_run_command_emfile_retries_after_releasing_semaphore(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def fake_popen(*args, **kwargs):
		attempts.append(args[0])
		if len(attempts) == 1:
			raise OSError(errno.EMFILE, "too many open files")
		return FakeProc()

	def fake_sleep(seconds):
		acquired = sem.acquire(blocking=False)
		assert acquired, "EMFILE backoff ran while the semaphore was held"
		sem.release()
		delays.append(seconds)

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", fake_sleep)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 0


def test_run_command_emfile_exhausts_retry_budget(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def always_emfile(*args, **kwargs):
		attempts.append(args[0])
		raise OSError(errno.EMFILE, "too many open files")

	_patch_popen(monkeypatch, always_emfile)
	monkeypatch.setattr(multiSSH3.time, "sleep", delays.append)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 1
	assert any("Retry limit" in line for line in host.stderr)


def test_run_command_post_launch_emfile_does_not_launch_command_again(
	fake_host, monkeypatch
):
	class PostLaunchEmfileProc(FakeProc):
		def poll(self):
			raise OSError(errno.EMFILE, "post-launch too many open files")

	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "non-idempotent-command")
	launches = []

	def fake_popen(argv, **kwargs):
		launches.append(argv)
		return PostLaunchEmfileProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(launches) == 1
	assert host.returncode == -1
	assert "post-launch too many open files" in host.stderr[0]


def _out_of_processes():
	# what fork fails with under a process limit (ulimit -u, a container's pids limit)
	return OSError(errno.EAGAIN, "Resource temporarily unavailable")


def _limit_threads(monkeypatch, allowed):
	'''Let only `allowed` more threads start, as under a process / thread limit. Returns the count left, to change.'''
	left = [allowed]

	class LimitedThread(threading.Thread):
		def start(self):
			if left[0] <= 0:
				raise RuntimeError("can't start new thread")
			left[0] -= 1
			super().start()

	monkeypatch.setattr(multiSSH3.threading, "Thread", LimitedThread)
	return left


def test_run_command_retries_when_no_process_can_be_started(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def fake_popen(*args, **kwargs):
		attempts.append(args[0])
		if len(attempts) == 1:
			raise _out_of_processes()  # fork failed: nothing ran
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", delays.append)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 0
	assert "Warning: Too many processes or threads. retrying..." in host.output


def test_run_command_starts_no_command_without_threads_for_its_output(fake_host, monkeypatch):
	# the threads reading the output start before the command: when they cannot, it has not run yet
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "non-idempotent-command")
	left = _limit_threads(monkeypatch, 1)  # the stdout reader starts, the stderr one does not
	launches = []
	delays = []

	def fake_popen(argv, **kwargs):
		launches.append(argv)
		return FakeProc(stdout=b"ok\n")

	def fake_sleep(seconds):
		delays.append(seconds)
		left[0] = 10  # threads ended meanwhile

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", fake_sleep)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(launches) == 1  # once, after its threads could start
	assert delays == [0.1]
	assert host.returncode == 0
	assert host.stdout == ["ok"]


def test_run_command_waits_for_running_commands_when_out_of_processes(fake_host, monkeypatch):
	# commands still running give back their processes and threads when they end: waiting for
	# them uses up no retries, and adds no line per try
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	failures = [5]

	def fake_popen(argv, **kwargs):
		if failures[0]:
			failures[0] -= 1
			raise _out_of_processes()
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3, "__running_procs", {object()})  # another host's command

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert host.returncode == 0
	running = "Running command: " + " ".join(multiSSH3._build_command(fake_host("mock-a", "true"), None, ...).argv)
	assert host.output == [running, "Warning: Too many processes or threads. retrying...", running,
		"Command finished with return code 0"]


def test_run_command_keeps_waiting_for_running_commands_however_long_they_take(fake_host, monkeypatch):
	# a wait of over a thousand back-offs (about 17 minutes, e.g. next to commands run with -t 0)
	# must go on waiting, not fail on the back-off growing past what a float holds
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	failures = [1100]
	delays = []

	def fake_popen(argv, **kwargs):
		if failures[0]:
			failures[0] -= 1
			raise _out_of_processes()
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", delays.append)
	monkeypatch.setattr(multiSSH3, "__running_procs", {object()})  # another host's command

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert host.returncode == 0
	assert len(delays) == 1100
	assert delays[:5] == [0.1, 0.2, 0.4, 0.8, 1.0]
	assert max(delays) == 1.0


def test_run_command_out_of_processes_uses_up_the_retries_when_nothing_else_runs(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []

	def always_out_of_processes(*args, **kwargs):
		attempts.append(args[0])
		raise _out_of_processes()

	_patch_popen(monkeypatch, always_out_of_processes)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3, "__running_procs", set())

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert len(attempts) == 2
	assert host.returncode == 1
	assert "Error: Retry limit reached after too many processes or threads!" in host.stderr


def test_run_command_post_launch_thread_error_does_not_launch_command_again(fake_host, monkeypatch):
	class PostLaunchThreadErrorProc(FakeProc):
		def poll(self):
			raise RuntimeError("can't start new thread")

	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "non-idempotent-command")
	launches = []

	def fake_popen(argv, **kwargs):
		launches.append(argv)
		return PostLaunchThreadErrorProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(launches) == 1
	assert host.returncode == -1
	assert "can't start new thread" in host.stderr[0]


def test_run_command_ends_its_threads_when_the_command_cannot_start(fake_host, monkeypatch):
	import time

	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	host.interactive_stdin = True  # three threads: stdout, stderr and stdin

	def missing_ssh(argv, **kwargs):
		raise FileNotFoundError(errno.ENOENT, "No such file or directory", "/missing/ssh")

	_patch_popen(monkeypatch, missing_ssh)
	# threads left by earlier tests (readers given up on a background process) may end meanwhile: count only new ones
	before = set(threading.enumerate())

	def started_here():
		return [thread for thread in threading.enumerate() if thread not in before]

	multiSSH3.run_command(host, sem, timeout=5)

	deadline = time.monotonic() + 2
	while started_here() and time.monotonic() < deadline:
		threading.Event().wait(0.01)
	assert started_here() == []
	assert host.returncode == -1


def test_run_command_magic_user_ip_uuid(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("alice@mock-a", "echo #USER# #IP# #UUID#")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"ok\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	remote = calls[0][-1]
	assert "alice" in remote
	assert "mock-a" in remote
	assert str(host.uuid) in remote


def test_run_command_interface_ip_prefix(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", interface_ip_prefix="10.1.2.")
	# Host.ip is mock-a from fake getIP — prefix rewrite may warn; still should run
	host.ip = "192.168.1.5"
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 0
	assert "10.1.2.5" in " ".join(calls[0]) or host.address.startswith("10.1.2.")


def test_run_command_extraargs_list(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", extraargs=["-o", "Foo=1"])
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	assert "-o" in calls[0] and "Foo=1" in calls[0]


@pytest.mark.parametrize("extraargs, expected", [
	("-o Port=2222 -v", ["-o", "Port=2222", "-v"]),
	# split as a shell would: a quoted value with spaces stays one argument
	("-o ProxyCommand='ssh -W %h:%p bastion'", ["-o", "ProxyCommand=ssh -W %h:%p bastion"]),
	('-o "ProxyCommand=ssh -W %h:%p bastion" -v', ["-o", "ProxyCommand=ssh -W %h:%p bastion", "-v"]),
	("-o Foo='bar", ["-o", "Foo='bar"]),  # an unclosed quote is split on spaces, as before
])
def test_run_command_extraargs_string_is_split_like_a_shell(fake_host, monkeypatch, extraargs, expected):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", extraargs=extraargs)
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)
	# mssh's timeout options (3 x 2 words) come last, after -ea's
	end = calls[0].index("--") - 6
	assert calls[0][end - len(expected):end] == expected


@pytest.mark.parametrize("os_name, extraargs, expected", [
	# Windows paths keep their backslashes: shell escapes made -i C:\keys\id into C:keysid
	("nt", r"-i C:\keys\id", ["-i", r"C:\keys\id"]),
	("nt", r'-i "C:\my keys\id"', ["-i", r"C:\my keys\id"]),
	("nt", "-o ProxyCommand='ssh -W %h:%p bastion'", ["-o", "ProxyCommand=ssh -W %h:%p bastion"]),
	("posix", r"-o Foo=a\ b", ["-o", "Foo=a b"]),  # elsewhere a backslash escapes, as in a shell
])
def test_run_command_extraargs_backslashes_by_platform(fake_host, monkeypatch, os_name, extraargs, expected):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true", extraargs=extraargs)
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc()

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.os, "name", os_name)
	multiSSH3.run_command(host, sem, timeout=5)
	monkeypatch.undo()  # os.name back before pytest reports
	# mssh's timeout options (3 x 2 words) come last, after -ea's
	end = calls[0].index("--") - 6
	assert calls[0][end - len(expected):end] == expected


def _redfish_then_ipmitool():
	redfish = multiSSH3.get_default_ipmi_definition()
	redfish["ipmi_method"] = "redfish"
	return [redfish, multiSSH3.get_default_ipmi_definition()]


def test_redfish_without_redfishtool_tries_the_next_ipmi_definition(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("node1", "", ipmi=True)
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"Chassis Power is on\n")

	monkeypatch.setattr(multiSSH3, "_binPaths", {"sh": "/bin/sh", "ipmitool": "/bin/ipmitool", "ssh": "ssh"})
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", fake_popen)
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=_redfish_then_ipmitool())

	assert host.returncode == 0
	assert len(calls) == 1 and "ipmitool -H" in calls[0][-1]  # the second definition ran
	assert any("redfishtool not found" in line for line in host.output)
	assert not any("Traceback" in line for line in host.output)


def test_redfish_without_redfishtool_and_no_other_definition_fails_clearly(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("node1", "", ipmi=True)
	calls = []
	monkeypatch.setattr(multiSSH3, "_binPaths", {"sh": "/bin/sh", "ssh": "ssh"})
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or FakeProc())
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=_redfish_then_ipmitool()[:1])

	assert (host.returncode, calls) == (1, [])
	assert any("redfishtool not found" in line for line in host.stderr)
	assert not any("Traceback" in line for line in host.stderr)


def test_run_command_missing_file_tools(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "/dest", files=["/tmp/a"], scp=True)
	monkeypatch.delitem(multiSSH3._binPaths, "scp", raising=False)
	monkeypatch.delitem(multiSSH3._binPaths, "rsync", raising=False)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	multiSSH3.run_command(host, sem, timeout=5)
	assert host.returncode == 1


def test_run_command_records_non_emfile_oserror(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")

	def fake_popen(argv, **kwargs):
		raise FileNotFoundError(errno.ENOENT, "No such file or directory", "/missing/ssh")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)

	assert host.returncode == -1
	assert "No such file or directory" in host.stderr[0]
	assert sem.acquire(blocking=False)


def test_run_command_thread_records_exception_from_run_command(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")

	def boom(*args, **kwargs):
		raise RuntimeError("boom")

	monkeypatch.setattr(multiSSH3, "run_command", boom)
	multiSSH3._run_command_thread(host, threading.Semaphore(1), 5, None)

	assert host.returncode == -1
	assert host.stderr[0] == "boom"


def test_run_command_thread_sets_returncode_left_unset(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	monkeypatch.setattr(multiSSH3, "run_command", lambda *args, **kwargs: None)

	multiSSH3._run_command_thread(host, threading.Semaphore(1), 5, None)

	assert host.returncode == -1
	assert host.stderr == ["Error: Command thread exited without a return code!"]


def _ipmi_failure(**overrides):
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update(overrides)
	return definition


def _non_negative_sleep(sleeps):
	def sleep(seconds):
		if seconds < 0:
			raise ValueError("sleep length must be non-negative")
		sleeps.append(seconds)
	return sleep


def test_ipmi_invalid_retry_lockout_time_finishes_host(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_RETRY_LOCKOUT_TIME", -1)
	sleeps = []
	monkeypatch.setattr(multiSSH3.time, "sleep", _non_negative_sleep(sleeps))
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)
	_patch_popen(monkeypatch, lambda argv, **kwargs: FakeProc(stderr=b"RAKP 2 HMAC is invalid\n", returncode=1))

	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[_ipmi_failure(retry_lockout_time="30s")])

	assert host.returncode == 1
	assert sleeps == []


def test_ipmitool_shell_command_quotes_credentials(fake_host, monkeypatch):
	import shlex
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	calls = []

	def fake_popen(argv, **kwargs):
		calls.append((argv, kwargs.get("env")))
		return FakeProc(stdout=b"Chassis Power is on\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[
		_ipmi_failure(username="ad min", password="p$ss;touch x"),
	])

	assert shlex.split(calls[0][0][2]) == [
		"ipmitool", "-H", "127.0.0.1", "-U", "ad min", "-E", "power", "status",
	]
	# the password is not in the shell's line at all: in the environment the shell passes on
	assert calls[0][1]["IPMI_PASSWORD"] == "p$ss;touch x"


def test_run_command_default_retry_limit_counts_current_ipmi_definitions(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	# eight different logins (copies of one login are tried once): more attempts than a fixed limit of 7 allows
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_DEFINITIONS", [_ipmi_failure(username="u{}".format(i)) for i in range(8)])
	launches = []

	def fake_popen(argv, **kwargs):
		launches.append(argv)
		return FakeProc(stderr=b"Error: Unable to establish IPMI v2 / RMCP+ session\n", returncode=1)

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)

	# each login, then ipmitool on the host over ssh: once, every failed login queues the same one
	assert len(launches) == 9
	assert host.stderr == ["Error: Exhausted all matching ipmi definitions!"]


def test_run_command_ipmi_with_files_succeeds(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True, files=["a.txt"])
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	_patch_popen(monkeypatch, lambda argv, **kwargs: FakeProc(stdout=b"Chassis Power is on\n"))

	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[_ipmi_failure()])

	assert host.returncode == 0
