import multiSSH3


class _Host:
	def __init__(self, stderr, returncode=1):
		self.stdout = []
		self.stderr = stderr
		self.output = []
		self.returncode = returncode


def test_ipmi_lockout_wait_skips_when_bmc_was_not_reached():
	cases = [
		["Could not open socket!", "Error: Unable to establish IPMI v2 / RMCP+ session"],
		["Error: Unable to establish LAN session", "Error: Unable to establish IPMI v1.5 / RMCP session"],
		["Timeout!"],
		["ssh: connect to host 10.251.5.57 port 22: Connection timed out"],
		["Permission denied, please try again."],
	]
	for stderr in cases:
		assert multiSSH3._ipmi_failure_should_wait(_Host(stderr, 124 if stderr == ["Timeout!"] else 1)) is False


def test_ipmi_lockout_wait_runs_after_bmc_auth_failure():
	cases = [
		["RAKP 2 HMAC is invalid", "Error: Unable to establish IPMI v2 / RMCP+ session"],
		["RAKP 2 message indicates an error : insufficient resources for session"],
		["Error: Unable to establish IPMI v2 / RMCP+ session"],
		["Set Session Privilege Level to ADMINISTRATOR failed"],
	]
	for stderr in cases:
		assert multiSSH3._ipmi_failure_should_wait(_Host(stderr)) is True


def test_ipmi_lockout_wait_ignores_lines_from_earlier_attempts():
	host = _Host(["Error: Unable to establish IPMI v2 / RMCP+ session"])
	host.output = [
		"Could not open socket!",
		"IPMI connection failed! Trying next ipmi definition...",
		"Error: Unable to establish IPMI v2 / RMCP+ session",
	]
	assert multiSSH3._ipmi_failure_should_wait(host, (2, 0, 0)) is True

	host = _Host(["Timeout!"], 124)
	host.output = ["RAKP 2 HMAC is invalid", "Timeout!"]
	assert multiSSH3._ipmi_failure_should_wait(host, (1, 0, 0)) is False


def test_ipmi_lockout_wait_after_unreached_attempt_still_waits_on_rejection(fake_host, monkeypatch):
	import io
	import threading

	class Proc:
		def __init__(self, stderr, returncode):
			self.stdout = io.BytesIO()
			self.stderr = io.BytesIO(stderr)
			self.stdin = io.BytesIO()
			self.returncode = returncode
		def poll(self):
			return self.returncode
		def communicate(self, *args, **kwargs):
			return b"", b""

	procs = [
		Proc(b"Could not open socket!\n", 1),
		Proc(b"Error: Unable to establish IPMI v2 / RMCP+ session\n", 1),
		Proc(b"Chassis Power is on\n", 0),
	]
	sleeps = []
	host = fake_host("127.0.0.1", "power status", ipmi=True)
	monkeypatch.setitem(multiSSH3._binPaths, "ipmitool", "ipmitool")
	monkeypatch.setitem(multiSSH3._binPaths, "sh", "/bin/sh")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: procs.pop(0))
	monkeypatch.setattr(multiSSH3.time, "sleep", sleeps.append)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)
	definitions = []
	# two logins: the same login twice is run once
	for user, lockout in (("u1", 5), ("u2", 7)):
		definition = multiSSH3.get_default_ipmi_definition()
		definition["username"] = user
		definition["retry_lockout_time"] = lockout
		definitions.append(definition)

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, ipmi_definitions_list=definitions)

	assert host.returncode == 0
	assert 5 not in sleeps
	assert 7 in sleeps
