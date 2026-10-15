'''
run_command_on_hosts with no hosts: None means the default hosts (DEFAULT_HOSTS when called), an empty
host list means no hosts. Neither looks the "EMPTY_HOSTS" placeholder up in DNS.
'''
import socket

import pytest

import multiSSH3

COMMON = dict(commands=["true"], no_start=True, no_watch=True, quiet=True, no_history=True, called=True,
	will_update_unreachable_hosts=False)


@pytest.fixture
def names_looked_up(monkeypatch):
	names = []
	real = socket.getaddrinfo

	def record(host, *args, **kwargs):
		names.append(host)
		return real(host, *args, **kwargs)

	monkeypatch.setattr(socket, "getaddrinfo", record)
	return names


@pytest.mark.parametrize("hosts", ["", [], set()])
def test_no_hosts_run_on_none_without_a_lookup(hosts, names_looked_up, capsys):
	assert multiSSH3.run_command_on_hosts(hosts, **COMMON) == []
	assert "EMPTY_HOSTS" not in names_looked_up
	assert "EMPTY_HOSTS" not in capsys.readouterr().err


def test_no_hosts_with_a_username_run_on_none(names_looked_up, capsys):
	assert multiSSH3.run_command_on_hosts("", username="root", **COMMON) == []
	assert not [name for name in names_looked_up if name and "root" in str(name)]
	assert "not a valid hostname" not in capsys.readouterr().err


def test_hosts_none_are_the_default_hosts_when_called(monkeypatch):
	monkeypatch.setattr(multiSSH3, "DEFAULT_HOSTS", "127.0.0.7")

	hosts = multiSSH3.run_command_on_hosts(None, **COMMON)

	assert [host.name for host in hosts] == ["127.0.0.7"]
