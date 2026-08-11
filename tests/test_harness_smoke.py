from tests.conftest import run_cli, ssh_localhost_works, parse_mssh_test_hosts


def test_version_cli():
	r = run_cli(["-V"])
	assert r.returncode == 0
	assert "6." in (r.stdout + r.stderr)


def test_parse_hosts_default():
	hosts = parse_mssh_test_hosts()
	assert "127.0.0.1" in hosts
	assert all(h.startswith("127.") for h in hosts)


def test_ssh_probe_returns_bool():
	assert isinstance(ssh_localhost_works(), bool)
