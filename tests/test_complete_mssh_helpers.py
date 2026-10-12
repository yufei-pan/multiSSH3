import socket
import subprocess
import sys
import threading

import pytest

import multiSSH3
from conftest import MULTISSH3_PY


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


def test_completion_option_prints_glue():
	result = subprocess.run([sys.executable, str(MULTISSH3_PY), '--completion', 'bash'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert result.returncode == 0
	assert b'MSSH_COMPLETE_GLUE' in result.stdout
	assert b'complete -o default -o bashdefault -F _mssh_complete mssh' in result.stdout


def test_completion_option_rejects_unknown_action():
	result = subprocess.run([sys.executable, str(MULTISSH3_PY), '--completion', 'tcsh'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert result.returncode == 2
	assert b'usage: mssh --completion' in result.stderr


def test_completion_option_is_completed():
	import mssh_complete as mc
	spec = mc.spec_from_parser(multiSSH3.get_parser())
	context = mc.parse_context('mssh --completion ', '', spec)
	assert (context.slot, context.option.dest) == ('value', 'completion')
	response = mc.Engine(spec).query(mc.Request('bash', 'mssh --completion ', '', ''))
	assert sorted(candidate.text for candidate in response.candidates) == ['bash', 'fish', 'install', 'uninstall', 'zsh']


def test_completion_option_without_module(tmp_path):
	lone = tmp_path / 'multiSSH3.py'
	lone.write_bytes(MULTISSH3_PY.read_bytes())
	result = subprocess.run([sys.executable, '-I', str(lone), '--completion', 'bash'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd=str(tmp_path))
	assert result.returncode == 1
	assert b'autocomplete needs mssh_complete.py' in result.stderr



def _finishes(function, seconds=5):
	result = []
	thread = threading.Thread(target=lambda: result.append(function()), daemon=True)
	thread.start()
	thread.join(seconds)
	return result


def test_expand_hostnames_local_handles_alias_cycles_with_fan_out(no_dns, monkeypatch):
	monkeypatch.setenv('AA', 'BB,BB')
	monkeypatch.setenv('BB', 'AA,AA')
	assert _finishes(lambda: multiSSH3.expand_hostnames_local('AA')) == [([], [])]


def test_expand_hostnames_local_handles_deep_shared_aliases(no_dns, monkeypatch):
	for level in range(26):
		monkeypatch.setenv('LV{}'.format(level), 'LV{0},LV{0}'.format(level + 1))
	monkeypatch.setenv('LV26', '127.0.0.9')
	assert _finishes(lambda: multiSSH3.expand_hostnames_local('LV0')) == [(['127.0.0.9'], [])]
