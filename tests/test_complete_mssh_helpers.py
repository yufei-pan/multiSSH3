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
