import shutil

import pytest

import multiSSH3


def test_default_ipmi_definition_keys():
	d = multiSSH3.get_default_ipmi_definition()
	assert "username" in d
	assert "password" in d
	assert "ipmi_method" in d


def test_optional_programs_are_found_on_path(monkeypatch, tmp_path):
	ipmitool = tmp_path / "ipmitool"
	ipmitool.write_text("#!/bin/sh\n")
	ipmitool.chmod(0o755)
	monkeypatch.setenv("PATH", str(tmp_path))
	monkeypatch.delitem(multiSSH3._binPaths, "ipmitool", raising=False)
	monkeypatch.delitem(multiSSH3._binPaths, "redfishtool", raising=False)

	assert multiSSH3.check_path("ipmitool") is True
	assert multiSSH3._binPaths["ipmitool"] == str(ipmitool)
	# one that is not installed stays out, so --ipmi can say so
	assert multiSSH3.check_path("redfishtool") is False
	assert "redfishtool" not in multiSSH3._binPaths
	# a path set in the config (_ipmitoolPath) wins over PATH
	monkeypatch.setattr(multiSSH3, "_ipmitoolPath", "/opt/ipmitool/bin/ipmitool", raising=False)
	assert multiSSH3.check_path("ipmitool") is True
	assert multiSSH3._binPaths["ipmitool"] == "/opt/ipmitool/bin/ipmitool"


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
