import pytest

import multiSSH3


@pytest.mark.live_ssh
def test_multi_host_echo(hosts_for_run, ssh_mode, monkeypatch):
	if ssh_mode == "mock":
		monkeypatch.setattr(
			multiSSH3,
			"getIP",
			lambda hostname, local=False: hostname.split("@")[-1],
		)

		def fake_run(host, sem, timeout=60, passwds=None):
			host.stdout.append(f"ok-{host.name}")
			host.returncode = 0

		monkeypatch.setattr(multiSSH3, "run_command", fake_run)

	result = multiSSH3.run_command_on_hosts(
		hosts=",".join(hosts_for_run),
		commands="echo ok",
		no_watch=True,
		quiet=True,
		no_history=True,
		timeout=30,
		skip_unreachable=True,
		will_update_unreachable_hosts=False,
		called=True,
		max_connections=4,
	)

	assert isinstance(result, list)
	assert len(result) == len(hosts_for_run)
	assert {host.name for host in result} == set(hosts_for_run)
	assert all(isinstance(host, multiSSH3.Host) for host in result)
	assert all(host.returncode == 0 for host in result)
	if ssh_mode == "live":
		assert all(any(line.strip() == "ok" for line in host.stdout) for host in result)
	else:
		assert all(f"ok-{host.name}" in host.stdout for host in result)


def test_distinct_loopback_list(local_ssh_hosts, ssh_mode):
	if ssh_mode != "live":
		pytest.skip("live SSH not available")
	assert len(set(local_ssh_hosts)) >= 2
	assert all(host.startswith("127.") for host in local_ssh_hosts)


def test_no_env_change_between_library_calls_is_honoured(monkeypatch, tmp_path):
	monkeypatch.setenv("MSSH_TEST_ENV_HOSTS", "127.0.0.2")
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname if hostname[:1].isdigit() else None)
	monkeypatch.setattr(multiSSH3, "_env_files", [str(tmp_path / "none.env")])
	common = dict(hosts="MSSH_TEST_ENV_HOSTS", commands=["true"], no_start=True, no_watch=True, quiet=True,
		no_history=True, called=True, will_update_unreachable_hosts=False)

	with_env = multiSSH3.run_command_on_hosts(no_env=False, **common)
	without_env = multiSSH3.run_command_on_hosts(no_env=True, **common)

	assert [host.name for host in with_env] == ["127.0.0.2"]
	assert without_env == []


@pytest.mark.parametrize("commands", [["true"], None], ids=["command", "interactive"])
def test_skipped_unreachable_host_message_goes_to_stderr(monkeypatch, tmp_path, capsys, commands):
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: None)
	multiSSH3.__globalUnavailableHosts["127.0.0.9"] = int(multiSSH3.time.monotonic() + 300)

	multiSSH3.run_command_on_hosts(hosts="127.0.0.9", commands=commands, no_watch=True, json=True,
		no_history=True, called=False, skip_unreachable=True)

	captured = capsys.readouterr()
	assert "Skipping unavailable host" not in captured.out  # stdout carries the -j JSON
	assert "Skipping unavailable host: 127.0.0.9" in captured.err


@pytest.fixture
def ssh_config_only_hosts(monkeypatch):
	# jump-* are reachable only through the ssh config: valid, but with no IP
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: hostname if hostname.startswith("jump-") else None)
	multiSSH3.getIP.cache_clear()
	yield
	multiSSH3.getIP.cache_clear()


def test_skip_hosts_works_for_hosts_without_ip(ssh_config_only_hosts):
	hosts = multiSSH3.run_command_on_hosts(hosts="jump-a,jump-b", commands=["true"], skip_hosts="jump-a",
		no_start=True, no_watch=True, quiet=True, no_history=True, called=True, will_update_unreachable_hosts=False)

	assert [host.name for host in hosts] == ["jump-b"]
