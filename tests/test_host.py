import multiSSH3


def test_host_defaults(fake_host):
	h = fake_host("127.0.0.1", "echo hi")
	assert h.name == "127.0.0.1"
	assert h.command == "echo hi"
	assert h.returncode is None
	assert h.uuid is not None
	assert h.i >= 0


def test_host_copy_preserves_outputs(fake_host):
	h = fake_host("127.0.0.1", "true")
	h.stdout = ["a"]
	h.stderr = ["b"]
	h.returncode = 0
	c = h.copy()
	assert c.stdout == ["a"]
	assert c.stderr == ["b"]
	assert c.returncode == 0
	assert c.uuid == h.uuid


def test_replace_magic_strings_host():
	s = multiSSH3.replace_magic_strings("run on #HOST#", ["#HOST#", "#HOSTNAME#"], "node1")
	assert s == "run on node1"



def test_replace_magic_strings_inserts_backslashes_literally():
	# re.sub would read these as an escape (\a) and a group reference (\1)
	assert multiSSH3.replace_magic_strings("whoami #USER#", ["#USER#"], "CORP\\alice") == "whoami CORP\\alice"
	assert multiSSH3.replace_magic_strings("echo #user#", ["#USER#"], "a\\1b") == "echo a\\1b"


def test_host_with_ip_none_still_looks_the_name_up(monkeypatch, tmp_path):
	monkeypatch.setattr(multiSSH3, "DEFAULT_HOST_FILE", str(tmp_path / "no-hosts"))
	monkeypatch.setattr(multiSSH3, "_etc_hosts", {})
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: "10.1.2.3" if hostname == "node1" else None)
	multiSSH3.getIP.cache_clear()

	assert multiSSH3.Host("node1", "true", ip=None).ip == "10.1.2.3"
	assert multiSSH3.Host("bob@node1", "true", ip=None).ip == "10.1.2.3"
	multiSSH3.getIP.cache_clear()
