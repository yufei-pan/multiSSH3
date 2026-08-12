import shutil

import pytest

import multiSSH3


def test_default_ipmi_definition_keys():
	d = multiSSH3.get_default_ipmi_definition()
	assert "username" in d
	assert "password" in d
	assert "ipmi_method" in d


@pytest.mark.smoke_optional
def test_ipmitool_on_path_or_skip():
	if not shutil.which("ipmitool"):
		pytest.skip("ipmitool not installed")
	assert shutil.which("ipmitool")


@pytest.mark.smoke_optional
def test_scp_flag_in_command_string():
	if not shutil.which("scp"):
		pytest.skip("scp not installed")
	s = multiSSH3.getStrCommand(
		hosts="127.0.0.1",
		commands=["/tmp/dest"],
		scp=True,
		file=["/tmp/a"],
		no_history=True,
	)
	assert "--scp" in s or " -W" in s or s.endswith("127.0.0.1")
	# __formCommandArgStr adds '--scp' when scp=True
	assert "--scp" in multiSSH3.__formCommandArgStr(scp=True, file=["/tmp/a"])
