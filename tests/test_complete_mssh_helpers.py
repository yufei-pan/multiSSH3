import socket

import pytest

import multiSSH3


def test_history_records_hosts_as_typed(tmp_path, monkeypatch):
	monkeypatch.setenv('us_east', '127.0.0.5,127.0.0.6')
	path = tmp_path / 'history'
	multiSSH3.record_command_history({'hosts': 'us_east,zz-no-such-host.invalid,127.0.0.[1-3]', 'commands': ['uptime'], 'history_file': str(path)})
	fields = path.read_text().rstrip('\n').split('\t')
	assert fields[3] == "'us_east,zz-no-such-host.invalid,127.0.0.[1-3]'"


def test_history_keeps_list_order_of_typed_hosts(tmp_path):
	path = tmp_path / 'history'
	multiSSH3.record_command_history({'hosts': ['b', 'a'], 'commands': ['true'], 'history_file': str(path)})
	assert path.read_text().split('\t')[3] == 'b,a'


def test_command_echo_still_formats_hosts():
	line = multiSSH3.getStrCommand(hosts='127.0.0.[1-2]', commands=['true'])
	assert '127.0.0.[1-2]' in line


@pytest.fixture
def no_dns(monkeypatch):
	def fail(*args, **kwargs):
		raise AssertionError('DNS lookup during a local expansion')
	monkeypatch.setattr(socket, 'getaddrinfo', fail)
	monkeypatch.setattr(multiSSH3, '_resolve_dns', fail)


def test_expand_hostnames_local_expands_ranges_and_aliases_without_dns(no_dns, monkeypatch):
	monkeypatch.setenv('rack_a', '127.0.0.5,rack[1-2]')
	monkeypatch.setenv('everything', '$rack_a,10.1.1.1-3')
	expanded, unresolved = multiSSH3.expand_hostnames_local('everything,root@node[01-02],zz-bad')
	assert expanded == ['10.1.1.1', '10.1.1.2', '10.1.1.3', '127.0.0.5', 'rack1', 'rack2', 'root@node01', 'root@node02', 'zz-bad']
	assert unresolved == ['rack1', 'rack2', 'root@node01', 'root@node02', 'zz-bad']


def test_expand_hostnames_local_reads_env_files(no_dns, tmp_path, monkeypatch):
	env_file = tmp_path / 'hosts.env'
	env_file.write_text("gpus='gpu[1-3]'\n")
	monkeypatch.setattr(multiSSH3, '_env_files', [str(env_file)])
	monkeypatch.setattr(multiSSH3, '_explicit_env_files', {str(env_file)})
	assert multiSSH3.expand_hostnames_local(['gpus'])[0] == ['gpu1', 'gpu2', 'gpu3']


def test_expand_hostnames_local_stops_alias_loops(no_dns, monkeypatch):
	monkeypatch.setenv('loop_a', 'loop_b')
	monkeypatch.setenv('loop_b', 'loop_a')
	assert multiSSH3.expand_hostnames_local('loop_a') == ([], [])


def test_expand_hostnames_local_counts_no_failures(no_dns):
	multiSSH3.expand_hostnames_local('zz-bad-host')
	assert multiSSH3.__failedHosts == set()
	assert multiSSH3.__mainReturnCode == 0


def test_compact_hostnames_local_round_trips_without_dns(no_dns):
	names = ['node01', 'node02', 'node03', 'gpu1', '10.0.0.1', '10.0.0.2']
	assert multiSSH3.compact_hostnames_local(names) == ['10.0.0.[1-2]', 'gpu1', 'node[01-03]']
	assert multiSSH3.compact_hostnames_local([]) == []
