import io
import threading

import pytest

import multiSSH3


class ImmediateProc:
	def __init__(self, returncode=0, stdout=b"", stderr=b""):
		self.returncode = returncode
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()

	def poll(self):
		return self.returncode

	def communicate(self, timeout=None):
		return b"", b""


def test_run_command_ssh_ipmitool_defaults_and_user(fake_host, monkeypatch):
	host = fake_host("cli-user@mock-a", "", ipmi=True)
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update({"ipmi_method": "ssh_ipmitool", "username": "bmc-user", "password": "bmc-pass"})
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, passwds="cli-pass", ipmi_definitions_list=[definition])

	assert host.returncode == 0
	assert host.command == "ipmitool power status"
	assert "bmc-user@mock-a" in calls[0]


def test_run_command_rsync_failure_retries_with_scp(fake_host, monkeypatch):
	host = fake_host("mock-a", "/dest", files=["/source"], scp=False)
	calls = []
	procs = iter([ImmediateProc(returncode=1, stderr=b"rsync failed\n"), ImmediateProc(returncode=0)])
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or next(procs))

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert calls[0][0] == "rsync"
	assert calls[1][0] == "scp"
	assert host.scp is True
	assert host.returncode == 0


def test_run_command_ipmi_definition_exhaustion(fake_host):
	host = fake_host("mock-a", "status", ipmi=True)

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, ipmi_definitions_list=[])

	assert host.returncode == 1
	assert host.stderr == ["Error: Exhausted all matching ipmi definitions!"]


def test_run_command_missing_local_ipmitool_falls_back_to_ssh(fake_host, monkeypatch):
	host = fake_host("mock-a", "power status", ipmi=True)
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	monkeypatch.delitem(multiSSH3._binPaths, "ipmitool", raising=False)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, ipmi_definitions_list=[definition])

	assert calls[0][0] == "ssh"
	assert "ipmitool power status" in calls[0][-1]
	assert host.returncode == 0


def test_run_command_debug_ssh_ipmitool_preserves_auth_argv(fake_host, monkeypatch):
	host = fake_host("cli-user@mock-a", "", ipmi=True, identity_file="/tmp/id_ed25519")
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update({
		"ipmi_method": "ssh_ipmitool",
		"username": "bmc-user",
		"password": "bmc-pass",
		"interface_ip_prefix": "10.20.30.",
	})
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_INTERFACE_IP_PREFIX", "10.20.30.")
	monkeypatch.setattr(multiSSH3, "SSH_STRICT_HOST_KEY_CHECKING", True)
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", True)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setitem(multiSSH3._binPaths, "sshpass", "sshpass")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(
		host,
		threading.Semaphore(1),
		timeout=5,
		passwds="cli-pass",
		ipmi_definitions_list=[definition],
	)

	assert calls == [[
		"sshpass", "-p", "bmc-pass", "ssh", "-i", "/tmp/id_ed25519",
		"--", "bmc-user@mock-a", "ipmitool power status",
	]]
	assert host.returncode == 0
	assert any("SSH_USERNAME cli-user" in line for line in host.stderr)
	assert any("SSH_PASSWORD  cli-pass" in line for line in host.stderr)
	assert any("DEFAULT_IPMI_INTERFACE_IP_PREFIX" in line for line in host.stderr)


@pytest.mark.parametrize(
	"command,expected_command",
	[
		("", "power status"),
		("ipmitool power cycle", "power cycle"),
		("/opt/ipmitool power off", " power off"),
	],
)
def test_run_command_local_ipmitool_normalizes_command_argv(
	fake_host, monkeypatch, command, expected_command
):
	host = fake_host("mock-a", command, ipmi=True)
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update({"username": "bmc-user", "password": "bmc-pass"})
	monkeypatch.delitem(multiSSH3._binPaths, "sh", raising=False)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "/opt/ipmitool")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(
		host,
		threading.Semaphore(1),
		timeout=5,
		ipmi_definitions_list=[definition],
	)

	assert calls == [[
		"/opt/ipmitool", "-H mock-a", "-U bmc-user", "-P bmc-pass", expected_command,
	]]
	assert host.command == expected_command
	assert host.returncode == 0


def test_process_run_return_unfinished_registers_threads(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = None
	thread = object()
	monkeypatch.setattr(multiSSH3, "__running_threads", set())
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [thread])

	multiSSH3.processRunOnHosts(
		1, None, 1, [host], True, True, False, True, False,
		{}, False, pre_merge=False,
	)

	assert thread in multiSSH3.__running_threads


def test_process_run_premerges_and_prints(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = 0
	events = []
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])
	monkeypatch.setattr(multiSSH3, "pre_merge_hosts", lambda hosts: events.append("merge") or hosts)
	monkeypatch.setattr(multiSSH3, "print_output", lambda hosts, usejson=False, quiet=False, greppable=False: events.append("print"))

	multiSSH3.processRunOnHosts(
		1, None, 1, [host], False, True, False, False, False,
		{}, False, pre_merge=True,
	)

	assert events == ["merge", "print"]


def test_generate_output_plain_formats_connection_refused(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = 255
	host.stderr = ["ssh: connect to host mock-a port 22: Connection refused"]
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (120, 30))

	text = multiSSH3.generate_output([host], greppable=False, quiet=False)

	assert " SSH not reachable!" in text
	assert host.stderr == ["SSH not reachable!"]


def test_generate_output_greppable_marks_empty_host_and_user_input(fake_host):
	host = fake_host("mock-a", "true")
	host.returncode = 1
	key_presses = [list("typed-command")]

	text = multiSSH3.generate_output(
		[host],
		greppable=True,
		quiet=False,
		keyPressesIn=key_presses,
	)

	assert "mock-a" in text
	assert "<EMPTY>" in text
	assert "User Inputs: typed-command" in text


@pytest.mark.parametrize(
	"color_capability,expected",
	[
		("None", "Success"),
		("TrueColor", "\x1b[32mSuccess\x1b[0m"),
	],
)
def test_generate_output_errors_only_success_uses_terminal_color(
	fake_host, monkeypatch, color_capability, expected
):
	host = fake_host("mock-a", "true")
	host.returncode = 0
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: color_capability)

	text = multiSSH3.generate_output([host], errors_only=True)

	assert text == expected


def test_generate_output_plain_recovers_invalid_threshold_and_renders_input(
	fake_host, monkeypatch, capsys
):
	host = fake_host("mock-a", "true")
	host.returncode = 1
	host.stdout = ["command-output"]
	key_presses = [list("typed-command")]
	monkeypatch.setattr(multiSSH3, "DEFAULT_DIFF_DISPLAY_THRESHOLD", "invalid")
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")

	text = multiSSH3.generate_output(
		[host],
		quiet=False,
		keyPressesIn=key_presses,
	)

	assert "command-output" in text
	assert "typed-command" in text
	assert key_presses == [[]]
	assert "diff_display_threshold" in capsys.readouterr().err


@pytest.mark.parametrize("quiet", [False, True])
def test_print_output_clears_transient_output_and_honors_quiet(
	fake_host, capsys, quiet
):
	host = fake_host("mock-a", "true")
	host.returncode = 0
	host.output = ["transient"]
	host.stdout = ["persisted"]

	text = multiSSH3.print_output([host], usejson=True, quiet=quiet)
	captured = capsys.readouterr().out

	assert "persisted" in text
	assert "transient" not in text
	assert host.output == []
	assert (text in captured) is (not quiet)
