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
