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
