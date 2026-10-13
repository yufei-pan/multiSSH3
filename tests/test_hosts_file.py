'''mssh's hosts file (/etc/hosts, or --host_file): read as hosts(5) is, and pointed out when it resolves nothing.'''
import threading
import time

import pytest

import multiSSH3


@pytest.fixture
def hosts_file(monkeypatch, tmp_path):
	'''write(content): make a file with content (str or bytes) the hosts file mssh looks names up in.'''
	path = tmp_path / 'hosts'

	def write(content):
		path.write_bytes(content if isinstance(content, bytes) else content.encode())
		monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(path))
		monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
		multiSSH3.getIP.cache_clear()
		return str(path)
	yield write
	multiSSH3.getIP.cache_clear()


def local(*names):
	'''What getIP finds for names without DNS: the hosts file only.'''
	return [multiSSH3.getIP(name, local=True) for name in names]


def test_a_byte_that_is_not_utf8_does_not_stop_the_lookup(hosts_file):
	# one Latin-1 byte, even in a comment, made every mssh run die with a UnicodeDecodeError
	hosts_file(b'127.0.0.1\tlocalhost\n10.0.0.5 node5 # rack B, ask Jos\xe9\n')
	assert local('node5', 'localhost') == ['10.0.0.5', '127.0.0.1']


def test_text_after_a_hash_is_a_comment(hosts_file):
	hosts_file('10.0.0.5 node5 # old rack\n#10.0.0.6 node6\n10.0.0.7 node7#gpu\n')
	assert local('node5', 'old', 'rack', '#', 'node6', 'node7', 'node7#gpu') == ['10.0.0.5', None, None, None, None, '10.0.0.7', None]


def test_a_name_keeps_its_first_address(hosts_file):
	# as the C library's own hosts file lookup does
	hosts_file('10.0.0.5 node5\n10.0.0.50 node5 node5-old\n')
	assert local('node5', 'node5-old') == ['10.0.0.5', '10.0.0.50']


@pytest.mark.parametrize('content', ['10.0.0.5 node5\nfd00::5 node5\n', 'fd00::5 node5\n10.0.0.5 node5\n'],
	ids=['ipv4-first', 'ipv6-first'])
def test_ipv4_is_preferred_when_a_name_has_both(hosts_file, content):
	# as for names looked up in DNS; -pre (interface_ip_prefix) only applies to IPv4 addresses
	hosts_file(content)
	assert local('node5') == ['10.0.0.5']


def test_debian_s_stock_hosts_file_keeps_localhost_on_ipv4(hosts_file):
	hosts_file('127.0.0.1\tlocalhost\n127.0.1.1\tworkstation\n\n'
		'# The following lines are desirable for IPv6 capable hosts\n'
		'::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\n')
	assert local('localhost', 'workstation', 'ip6-localhost', 'ip6-allnodes') == ['127.0.0.1', '127.0.1.1', '::1', 'ff02::1']


def test_an_ipv6_only_name_keeps_its_first_address(hosts_file):
	hosts_file('fd00::7 node7\nfd00::77 node7\n')
	assert local('node7') == ['fd00::7']


def test_lines_without_an_ip_address_are_skipped(hosts_file):
	# as the C library skips them: no name may become another name's "address"
	hosts_file('node1 node2\nlocalhost\n10.0.0.300 node3\nfe80::1%eth0 node4\n10.0.0.9 node9\n')
	assert local('node1', 'node2', 'localhost', 'node3', 'node4', 'node9') == [None, None, None, None, None, '10.0.0.9']


def test_a_dict_put_in_etc_hosts_is_used_instead_of_the_file(hosts_file, monkeypatch):
	# documented for library use (README: _etc_hosts)
	hosts_file('10.0.0.5 node5\n')
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {'node5': '10.9.9.9'})
	assert local('node5') == ['10.9.9.9']


def test_parallel_lookups_read_the_hosts_file_once(hosts_file, monkeypatch):
	# a cluster's hosts file can be long, and the names of a range are looked up by many threads at once
	path = hosts_file(''.join('10.0.0.{0} node{0}\n'.format(number) for number in range(1, 9)))
	reads = []
	real_read = multiSSH3.read_hosts_file

	def slow_read(path):
		reads.append(path)
		time.sleep(0.1)
		return real_read(path)
	monkeypatch.setattr(multiSSH3, 'read_hosts_file', slow_read)
	threads = [threading.Thread(target=multiSSH3.getIP, args=('node{}'.format(number),), kwargs={'local': True}) for number in range(1, 9)]
	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()
	assert reads == [path]
	assert local('node3') == ['10.0.0.3']


def test_read_hosts_file_of_a_missing_file_is_empty(tmp_path):
	assert multiSSH3.read_hosts_file(str(tmp_path / 'missing')) == {}
	assert multiSSH3.read_hosts_file(str(tmp_path)) == {}  # a directory


@pytest.fixture
def no_dns(monkeypatch, tmp_path):
	'''Names resolve from the hosts file only: no DNS, ssh config or env aliases.'''
	monkeypatch.setattr(multiSSH3, '_resolve_dns', lambda hostname: None)
	monkeypatch.setattr(multiSSH3, '_ssh_config_target', lambda hostname: None)
	monkeypatch.setattr(multiSSH3, '_env_files', [str(tmp_path / 'no-env')])
	monkeypatch.setattr(multiSSH3, '_unavailable_hosts_file_path', lambda create=True: str(tmp_path / 'unavailable.csv'))
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
	multiSSH3.getIP.cache_clear()
	yield
	multiSSH3.getIP.cache_clear()


def run_on_hosts(hosts, **kwargs):
	'''run_command_on_hosts as main() calls it, with no host started.'''
	return multiSSH3.run_command_on_hosts(hosts=hosts, commands=['echo #IP#'], no_watch=True, no_history=True,
		called=False, no_start=True, will_update_unreachable_hosts=False, **kwargs)


def test_a_prefix_that_cannot_apply_is_said_outside_the_tui(hosts_file, no_dns, capsys):
	# -pre rewrites IPv4 addresses only: the others are reached by name, which was said only in the TUI
	hosts_file('fd00::5 node5\n10.0.0.6 node6\nfd00::7 node7\n')
	run_on_hosts('node5,node6,node7', interface_ip_prefix='192.168.7')
	err = capsys.readouterr().err
	assert 'Warning: interface IP prefix 192.168.7 not applied to node5,node7: no IPv4 address, connecting by name' in err


def test_a_prefix_that_applies_everywhere_says_nothing(hosts_file, no_dns, capsys):
	hosts_file('fd00::6 node6\n10.0.0.6 node6\n')
	run_on_hosts('node6', interface_ip_prefix='192.168.7')
	assert 'prefix' not in capsys.readouterr().err


def test_a_quiet_run_leaves_the_prefix_warning_out(hosts_file, no_dns, capsys):
	hosts_file('fd00::5 node5\n')
	run_on_hosts('node5', interface_ip_prefix='192.168.7', quiet=True)
	assert 'prefix' not in capsys.readouterr().err
