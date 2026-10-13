import io
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
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]


def test_run_command_rsync_files(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "/tmp/dest", files=["/tmp/a"], scp=False)
	# Prefer rsync path
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
		"rsync", "-ahlX", "--partial", "--inplace", "--info=name",
		"--rsh", "ssh '-o StrictHostKeyChecking=no' '-o UserKnownHostsFile=/dev/null'",
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]


def test_run_command_gather_mode_scp(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host(
		"mock-a",
		"/tmp/local",
		files=["/tmp/remote"],
		scp=True,
		gatherMode=True,
	)
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
], ids=["bash", "dash", "zsh", "tcsh", "fish", "windows", "localized", "code127", "ssh_failed"])
def test_rsync_that_never_ran_is_retried_with_scp(fake_host, monkeypatch, returncode, stderr):
	host, calls = _copy_with_results(fake_host, monkeypatch,
		[FakeProc(stderr=stderr, returncode=returncode), FakeProc()], ["/src/a"])

	assert [argv[0] for argv in calls] == ["rsync", "scp"]
	assert calls[1][-3:] == ["--", "/src/a", "mock-a:/dest/"]
	assert host.returncode == 0
	assert host.scp is True


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
def test_rsync_rsh_is_the_configured_ssh_with_each_argument_intact(fake_host, monkeypatch, identity_file):
	# rsync splits --rsh on spaces: an identity path with a space became two arguments, and the
	# configured ssh was ignored for a plain "ssh"
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	calls = []
	_patch_popen(monkeypatch, lambda argv, **kwargs: calls.append(argv) or FakeProc())
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "/opt/open ssh/bin/ssh")
	host = fake_host("mock-a", "/dest/", files=["/src/a"], identity_file=identity_file)

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	rsh = calls[0][calls[0].index("--rsh") + 1]
	assert _rsync_split(rsh) == ["/opt/open ssh/bin/ssh", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"-i", identity_file]


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
		calls.append(argv)
		return FakeProc(stdout=b"Chassis Power is on\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[
		_ipmi_failure(username="ad min", password="p$ss;touch x"),
	])

	assert shlex.split(calls[0][2]) == [
		"ipmitool", "-H", "127.0.0.1", "-U", "ad min", "-P", "p$ss;touch x", "power", "status",
	]


def test_run_command_default_retry_limit_counts_current_ipmi_definitions(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_DEFINITIONS", [_ipmi_failure() for _ in range(5)])
	launches = []

	def fake_popen(argv, **kwargs):
		launches.append(argv)
		return FakeProc(stderr=b"Error: Unable to establish IPMI v2 / RMCP+ session\n", returncode=1)

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)

	# each ipmitool definition is retried once through ssh_ipmitool
	assert len(launches) == 10
	assert host.stderr == ["Error: Exhausted all matching ipmi definitions!"]


def test_run_command_ipmi_with_files_succeeds(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("127.0.0.1", "power status", ipmi=True, files=["a.txt"])
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	_patch_popen(monkeypatch, lambda argv, **kwargs: FakeProc(stdout=b"Chassis Power is on\n"))

	multiSSH3.run_command(host, sem, timeout=5, ipmi_definitions_list=[_ipmi_failure()])

	assert host.returncode == 0
