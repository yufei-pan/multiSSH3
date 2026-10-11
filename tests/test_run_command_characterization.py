"""
Characterization of run_command: every command-building mode and retry chain, run against fake
processes and compared with tests/data/run_command_golden.json, recorded from the code before
run_command was split into build / execute / retry steps.

Regenerate only for an intentional behavior change, and review the diff:
	MSSH_REGEN_GOLDEN=1 python -m pytest tests/test_run_command_characterization.py
"""
import errno
import io
import json
import os
import threading
from pathlib import Path

import pytest

import multiSSH3

GOLDEN = Path(__file__).parent / "data" / "run_command_golden.json"

BINS_ALL = {"ssh": "/bin/ssh", "sshpass": "/bin/sshpass", "scp": "/bin/scp", "rsync": "/bin/rsync",
	"sh": "/bin/sh", "ipmitool": "/bin/ipmitool", "redfishtool": "/bin/redfishtool"}


def bins(*names):
	return {name: BINS_ALL[name] for name in names}


def ipmi(**overrides):
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update(overrides)
	return definition


AUTH_FAILURE = (b"", b"Error: Unable to establish IPMI v2 / RMCP+ session\nunauthorized name\n", 1)
NO_ROUTE = (b"", b"Error: Unable to establish IPMI v2 / RMCP+ session\nno route to host\n", 1)
OK = (b"ok\n", b"", 0)
EMFILE = OSError(errno.EMFILE, "Too many open files")

SCENARIOS = {
	"ssh_magic_strings_key_extraargs": dict(
		host=dict(name="alice@node1", command="echo #HOST# #USER# #I# #UUID# #IP# #RESOLVED#",
			identity_file="~/.ssh/id_x", extraargs="-p 2222"),
		bins=bins("ssh"), results=[OK]),
	"ssh_current_user_and_list_extraargs": dict(
		host=dict(name="node1", command="whoami #user#", extraargs=["-o", 5]), bins=bins("ssh"), results=[OK]),
	"ssh_strict_host_key_checking": dict(
		host=dict(name="node1", command="true"), bins=bins("ssh"), strict=True, results=[OK]),
	"ssh_password_with_sshpass": dict(
		host=dict(name="node1", command="uptime"), passwds="pw", bins=bins("ssh", "sshpass"), results=[OK]),
	"ssh_password_without_sshpass": dict(
		host=dict(name="node1", command="uptime"), passwds="pw", bins=bins("ssh"), results=[OK]),
	"ssh_password_without_sshpass_debug": dict(
		host=dict(name="node1", command="uptime"), passwds="pw", bins=bins("ssh"), debug=True, results=[OK]),
	"ssh_failure_exit_code_and_ignored_stderr": dict(
		host=dict(name="node1", command="false"), bins=bins("ssh"),
		results=[(b"", b"Warning: Permanently added 'node1'\nreal error\n", 3)]),
	"interface_ip_prefix": dict(
		host=dict(name="node1", command="echo #IP# #RESOLVED#", interface_ip_prefix="192.168.1."),
		bins=bins("ssh"), results=[OK]),
	"rsync_push": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a", "/src/b"], extraargs="--delete"),
		bins=bins("ssh", "rsync", "scp"), results=[OK]),
	"rsync_gather": dict(
		host=dict(name="node1", command="/local/", files=["/remote/a"], gatherMode=True),
		bins=bins("ssh", "rsync", "scp"), results=[OK]),
	"rsync_failure_falls_back_to_scp": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"]), bins=bins("ssh", "rsync", "scp"),
		results=[(b"", b"rsync: connection unexpectedly closed\n", 12), OK]),
	"rsync_failure_falls_back_to_scp_debug": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"]), bins=bins("ssh", "rsync", "scp"), debug=True,
		results=[(b"", b"rsync: connection unexpectedly closed\n", 12), OK]),
	"scp_requested": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"], scp=True), passwds="pw",
		bins=bins("ssh", "scp", "sshpass"), results=[OK]),
	"scp_requested_but_missing_uses_rsync": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"], scp=True), bins=bins("ssh", "rsync"), results=[OK]),
	"rsync_missing_uses_scp": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"]), bins=bins("ssh", "scp"), results=[OK]),
	"no_copy_tool": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"]), bins=bins("ssh"), results=[]),
	"no_copy_tool_scp_requested": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"], scp=True), bins=bins("ssh"), results=[]),
	"local_shell": dict(
		host=dict(name="localhost", command="echo #HOST#", shell=True), bins=bins("sh", "ssh"), results=[OK]),
	"local_shell_without_sh_uses_ssh": dict(
		host=dict(name="node1", command="echo hi", shell=True), bins=bins("ssh"), results=[OK]),
	"ipmitool_via_sh": dict(
		host=dict(name="node1", command="ipmitool chassis status", ipmi=True),
		ipmi=[ipmi(username="admin", password="p w", args="-I lanplus")], bins=bins("sh", "ipmitool", "ssh"),
		results=[(b"System Power : on\n", b"", 0)]),
	"ipmitool_direct": dict(
		host=dict(name="node1", command="", ipmi=True), ipmi=[ipmi(args="-I lanplus -L ADMINISTRATOR")],
		bins=bins("ipmitool", "ssh"), results=[OK]),
	"ipmitool_interface_prefix": dict(
		host=dict(name="node1", command="power status", ipmi=True), ipmi=[ipmi(interface_ip_prefix="10.99.0.")],
		bins=bins("sh", "ipmitool", "ssh"), results=[OK]),
	"ipmitool_auth_failure_waits_then_ssh_ipmitool": dict(
		host=dict(name="node1", command="power status", ipmi=True), ipmi=[ipmi(retry_lockout_time=5)],
		bins=bins("sh", "ipmitool", "ssh"), results=[AUTH_FAILURE, OK]),
	"ipmitool_unreachable_skips_wait": dict(
		host=dict(name="node1", command="power status", ipmi=True), ipmi=[ipmi(retry_lockout_time=5)],
		bins=bins("sh", "ipmitool", "ssh"), results=[NO_ROUTE, OK]),
	"ipmitool_bad_lockout_time_falls_back": dict(
		host=dict(name="node1", command="power status", ipmi=True), ipmi=[ipmi(retry_lockout_time="soon")],
		bins=bins("sh", "ipmitool", "ssh"), results=[AUTH_FAILURE, OK]),
	"ipmitool_missing_locally_uses_ssh_ipmitool": dict(
		host=dict(name="bob@node1", command="power on", ipmi=True), passwds="pw",
		ipmi=[ipmi(username="bmc", password="bmcpw")], bins=bins("sh", "ssh", "sshpass"), results=[OK]),
	"two_definitions_all_failing_exhaust": dict(
		host=dict(name="nodeA1", command="power status", ipmi=True),
		ipmi=[ipmi(username="u1", password="p1", hostname_keyword="nodeA"), ipmi(username="u2", password="p2"),
			ipmi(username="u3", password="p3", hostname_keyword="other")],
		bins=bins("sh", "ipmitool", "ssh", "sshpass"), results=[AUTH_FAILURE] * 4),
	"two_definitions_all_failing_exhaust_debug": dict(
		host=dict(name="nodeA1", command="power status", ipmi=True),
		ipmi=[ipmi(username="u1", password="p1"), ipmi(username="u2", password="p2")], debug=True,
		bins=bins("sh", "ipmitool", "ssh", "sshpass"), results=[AUTH_FAILURE] * 4),
	"ssh_ipmitool_definition_overrides_user_and_password": dict(
		host=dict(name="alice@node1", command="", ipmi=True), passwds="pw",
		ipmi=[ipmi(ipmi_method="ssh_ipmitool", username="bmcuser", password="bmcpw", interface_ip_prefix="10.1.1.")],
		bins=bins("ssh", "sshpass"), results=[OK]),
	"redfish_via_sh": dict(
		host=dict(name="node1", command="redfishtool Systems", ipmi=True), ipmi=[ipmi(ipmi_method="redfish")],
		bins=bins("sh", "redfishtool", "ssh"), results=[OK]),
	"redfish_direct": dict(
		host=dict(name="node1", command="", ipmi=True), ipmi=[ipmi(ipmi_method="redfish", args="-T 30")],
		bins=bins("redfishtool", "ssh"), results=[OK]),
	"ipmi_unsupported_method": dict(
		host=dict(name="node1", command="power status", ipmi=True), ipmi=[ipmi(ipmi_method="bogus")],
		bins=bins("sh", "ssh"), results=[]),
	"too_many_open_files_then_success": dict(
		host=dict(name="node1", command="true"), bins=bins("ssh"), results=[EMFILE, EMFILE, OK]),
	"too_many_open_files_exhausts_retries": dict(
		host=dict(name="node1", command="true"), bins=bins("ssh"), retry_limit=2, results=[EMFILE] * 5),
	"too_many_open_files_with_rsync_fallback": dict(
		host=dict(name="node1", command="/dest/", files=["/src/a"]), bins=bins("ssh", "rsync", "scp"),
		retry_limit=2, results=[EMFILE, (b"", b"rsync failed\n", 5), EMFILE, EMFILE]),
	"other_os_error": dict(
		host=dict(name="node1", command="true"), bins=bins("ssh"),
		results=[OSError(errno.ENOENT, "No such file or directory")]),
	"retry_limit_already_exhausted": dict(
		host=dict(name="node1", command="true"), bins=bins("ssh"), retry_limit=-1, results=[]),
}


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


def run_scenario(monkeypatch, scenario):
	monkeypatch.setattr(multiSSH3, "_binPaths", dict(scenario["bins"]))
	monkeypatch.setattr(multiSSH3, "DEFAULT_IPMI_DEFINITIONS", [dict(d) for d in scenario.get("ipmi", [ipmi()])])
	monkeypatch.setattr(multiSSH3, "SSH_STRICT_HOST_KEY_CHECKING", scenario.get("strict", False))
	monkeypatch.setattr(multiSSH3, "__DEBUG_MODE", scenario.get("debug", False))
	monkeypatch.setattr(multiSSH3, "_emo", False)
	monkeypatch.setattr(multiSSH3.getpass, "getuser", lambda: "tester")
	sleeps = []
	monkeypatch.setattr(multiSSH3.time, "sleep", sleeps.append)
	results = list(scenario["results"])
	argvs = []

	def popen(argv, **kwargs):
		argvs.append(list(argv))
		result = results.pop(0)
		if isinstance(result, Exception):
			raise result
		return FakeProc(*result)

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", popen)
	host = multiSSH3.Host(ip="10.0.0.7", i=7, uuid="uuid-7", **scenario["host"])
	host.interactive_stdin = False  # no stdin writer thread polling time.sleep
	kwargs = {"retry_limit": scenario["retry_limit"]} if "retry_limit" in scenario else {}

	multiSSH3.run_command(host, threading.Semaphore(1), 30, scenario.get("passwds"), **kwargs)

	return {"argvs": argvs, "returncode": host.returncode, "output": host.output, "stdout": host.stdout,
		"stderr": host.stderr, "sleeps": sleeps, "command": host.command, "address": getattr(host, "address", None),
		"resolvedName": host.resolvedName, "name": host.name, "scp": host.scp, "shell": host.shell}


def _golden():
	return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_run_command_behaviour_is_unchanged(monkeypatch, name):
	got = json.loads(json.dumps(run_scenario(monkeypatch, SCENARIOS[name])))
	if os.environ.get("MSSH_REGEN_GOLDEN"):
		golden = _golden()
		golden[name] = got
		GOLDEN.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n")
		return
	assert got == _golden()[name]


def test_command_formatting_error_is_recorded(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_binPaths", bins("ssh"))
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *a, **k: pytest.fail("must not run"))
	host = multiSSH3.Host("node1", None, ip="10.0.0.7")  # no command: formatting fails

	multiSSH3.run_command(host, threading.Semaphore(1), 30)

	assert host.returncode == -1
	assert host.output[0] == "Error occurred while formatting the command : None!"
