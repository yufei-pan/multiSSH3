'''
The history line and the "> mssh ..." echo replay the run they record: a command line read back from
either runs with the same settings (the Ctrl-R picker and mssh-complete replay history lines).
'''
import copy
import json
import os
import shlex

import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())

# Settings a replay does not reproduce, on purpose: -T / -uk are folded by main() into the timeout /
# key file they choose, which are recorded instead.
NOT_REPLAYED = ('use_script_timeout', 'use_key')
# -ip is never recorded (an IPMI password is not spread further; -p is, by design), and with it none
# of the IPMI options: a replay of such a run tries the configured logins, as a plain --ipmi run does
IPMI_LOGIN = ('ipmi_password', 'ipmi_username', 'ipmi_args', 'ipmi_method', 'ipmi_interface_ip_prefix',
	'ipmi_retry_lockout_time', 'ipmi_definitions', 'ipmi_logins')
# an IPMI login the config file lists
CONFIGURED_LOGIN = {'username': 'x', 'password': 'px'}

# module state main() changes (process_args, --config_file, set_global_with_args), restored after a run
RUN_STATE = ('FORCE_TRUECOLOR', '_encoding', '__DEBUG_MODE', '__returnZero', '__global_suppress_printout',
	'_no_env', '_env_files', '_explicit_env_files', '__mainReturnCode', '__failedHosts', '_emo', '_etc_hosts')


def _ipmi_logins(password):
	'''The IPMI logins (username, password) a run tries on 127.0.0.1, in order, without running any.'''
	logins = []
	remaining = ...
	for _ in range(50):
		host = multiSSH3.Host('127.0.0.1', 'power status', ipmi=True, ip='127.0.0.1')
		attempt = multiSSH3._build_command(host, password, remaining)
		if not attempt.ipmi_definition:
			break  # every login was tried
		if attempt.action != 'rebuild':
			logins.append((attempt.ipmi_definition.get('username'), attempt.ipmi_definition.get('password')))
		remaining = attempt.ipmi_definitions_list
	return logins


def _run_main(argv, capsys):
	'''
	Run mssh's main() on argv without running anything.

	Returns:
		tuple: (what run_command_on_hosts was given, plus the IPMI definitions; the "> mssh" echo
			line or None)
	'''
	ran = {}

	def fake_run(**kwargs):
		ran.update(kwargs)
		# the echo lists the hosts expanded, the history as typed: both must reach the same hosts
		ran['expanded_hosts'] = sorted(multiSSH3.expand_hostnames_local(kwargs['hosts'])[0])
		ran['ipmi_definitions'] = [dict(definition) for definition in multiSSH3.DEFAULT_IPMI_DEFINITIONS]
		if kwargs.get('ipmi'):
			ran['ipmi_logins'] = _ipmi_logins(kwargs.get('password'))
		return []

	names = [name for name in vars(multiSSH3) if name.startswith('DEFAULT_')] + list(RUN_STATE)
	capsys.readouterr()
	# each run reads the host file it is given, like a new mssh process
	multiSSH3._getIP.cache_clear()
	with pytest.MonkeyPatch.context() as patch:
		for name in names:
			patch.setattr(multiSSH3, name, copy.deepcopy(getattr(multiSSH3, name)))
		patch.setattr(multiSSH3, 'run_command_on_hosts', fake_run)
		# never run: _ipmi_logins only builds the command lines
		patch.setitem(multiSSH3._binPaths, 'ipmitool', '/nonexistent/ipmitool')
		# --repeat sleeps --interval between runs
		patch.setattr(multiSSH3.time, 'sleep', lambda seconds: None)
		with pytest.raises(SystemExit):
			multiSSH3.main(list(argv))
	echo = [line for line in capsys.readouterr().err.splitlines() if line.startswith('> ')]
	assert ran, 'main() ran nothing for {!r}'.format(argv)
	return ran, (echo[0][2:] if echo else None)


def _effective(ran, original, typed_hosts=True):
	'''
	The settings of a run a replay of original must reproduce (the hosts as typed, else only where
	they lead): all of them, but for -T / -uk, and the IPMI login when original gave its password.
	'''
	skip = NOT_REPLAYED + (IPMI_LOGIN if original['ipmi_password'] != multiSSH3.DEFAULT_IPMI_PASSWORD else ())
	settings = {key: value for key, value in ran.items() if key not in skip and (typed_hosts or key != 'hosts')}
	if settings.get('config_file'):
		settings['config_file'] = os.path.abspath(settings['config_file'])
	return settings


def _history_argv(line):
	'''The mssh arguments a history line replays: <ts> <program> <options> <hosts> <commands>.'''
	fields = line.split('\t')
	assert len(fields) == 5
	return shlex.split(fields[2]) + shlex.split(fields[3]) + shlex.split(fields[4])


@pytest.fixture
def replay_env(tmp_path, monkeypatch):
	'''A HOME with an ssh key, a host file, an env file, a config file and files to copy.'''
	home = tmp_path / 'home'
	(home / '.ssh').mkdir(parents=True)
	(home / '.ssh' / 'id_ed25519').write_text('key')
	monkeypatch.setenv('HOME', str(home))
	keys = tmp_path / 'keys'
	keys.mkdir()
	(keys / 'id_rsa').write_text('key')
	(tmp_path / 'hosts').write_text('127.0.0.5 replay-node\n')
	(tmp_path / 'hosts.env').write_text("replay_group='127.0.0.6,127.0.0.7'\n")
	(tmp_path / 'a.txt').write_text('a')
	(tmp_path / 'b.txt').write_text('b')
	(tmp_path / 'replay.config.json').write_text(json.dumps({
		'DEFAULT_CLI_TIMEOUT': 30, 'DEFAULT_INTERVAL': 5, 'DEFAULT_SKIP_HOSTS': '127.0.0.9', 'DEFAULT_WINDOW_WIDTH': 60}))
	monkeypatch.chdir(tmp_path)
	monkeypatch.setattr(multiSSH3, 'input_with_timeout_and_countdown', lambda *args, **kwargs: '1')
	# hermetic: the host file given is read afresh (it is cached once read), and no name reaches DNS or ssh -G
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
	monkeypatch.setattr(multiSSH3, '_resolve_dns', lambda hostname: None)
	monkeypatch.setattr(multiSSH3, '_ssh_config_target', lambda hostname: None)
	multiSSH3._getIP.cache_clear()
	yield tmp_path
	multiSSH3._getIP.cache_clear()


# (options, DEFAULT_* the mssh config sets, hosts, commands): T stands for the replay_env directory
ROUND_TRIPS = [
	(['-t', '50'], {}, '127.0.0.1', ['true']),
	(['-T'], {}, '127.0.0.1', ['true']),
	(['-t', '20'], {}, '127.0.0.1', ['true']),
	(['-t', '0'], {'DEFAULT_CLI_TIMEOUT': 30}, '127.0.0.1', ['true']),
	(['-t', '30'], {'DEFAULT_CLI_TIMEOUT': 30}, '127.0.0.1', ['true']),
	(['-T'], {'DEFAULT_CLI_TIMEOUT': 30}, '127.0.0.1', ['true']),
	(['-t', '20', '-M', '-iu', 'bmcadmin', '-ip', 'bmcpw', '-ia=-I lanplus'], {}, '127.0.0.1', ['power status']),
	(['-M', '-mpre', '10.1.', '-im', 'ipmiutil', '-irlt', '30'], {}, '127.0.0.1', ['power status']),
	(['-M', '-iu', 'admin', '-ia', ''], {'DEFAULT_IPMI_USERNAME': 'root', 'DEFAULT_IPMI_ARGS': '-I lanplus'}, '127.0.0.1', ['power status']),
	(['-M', '-iu', 'a'], {'DEFAULT_IPMI_DEFINITIONS': [CONFIGURED_LOGIN]}, '127.0.0.1', ['power status']),
	# the password given is the default one: the replay tries the same logins
	(['-M', '-iu', 'a', '-ip', 'admin', '-ia=-I lanplus'], {'DEFAULT_IPMI_DEFINITIONS': [CONFIGURED_LOGIN]}, '127.0.0.1', ['power status']),
	(['-B', '-ww', '80', '-wh', '5'], {}, '127.0.0.1', ['true']),
	(['-Q'], {}, '127.0.0.1', ['true']),
	(['-w', '-Z', '--debug'], {}, '127.0.0.1', ['true']),
	(['-e', 'latin-1', '-dt', '0.5', '--force_truecolor'], {}, '127.0.0.1', ['true']),
	(['-uk'], {}, '127.0.0.1', ['true']),
	(['-k', 'T/keys'], {}, '127.0.0.1', ['true']),
	(['--host_file', 'T/hosts'], {}, 'replay-node', ['true']),
	(['--config_file', 'T/replay.config.json'], {}, '127.0.0.1', ['true']),
	(['--config_file', 'replay.config.json', '-t', '0', '-i', '0'], {}, '127.0.0.1', ['true']),
	(['-i', '0', '-r', '2'], {'DEFAULT_INTERVAL': 5}, '127.0.0.1', ['true']),
	(['-m', '0'], {}, '127.0.0.1', ['true']),
	(['-X', ''], {'DEFAULT_SKIP_HOSTS': '127.0.0.9'}, '127.0.0.1', ['true']),
	(['-pre', ''], {'DEFAULT_INTERFACE_IP_PREFIX': '10.0.'}, '127.0.0.1', ['true']),
	(['-u', '', '-ea', ''], {'DEFAULT_USERNAME': 'root', 'DEFAULT_EXTRA_ARGS': '-o Port=2222'}, '127.0.0.1', ['true']),
	(['-p', 'secret'], {}, '127.0.0.1', ['true']),
	(['-s', 'T/a.txt'], {}, '127.0.0.1', ['/tmp/dst/']),
	(['-f', 'T/a.txt', '-f', 'T/b.txt', '-W'], {}, '127.0.0.1', ['/tmp/dst/']),
	(['-fs', '-f', 'T/a.txt'], {}, '127.0.0.1', []),
	(['-G', '-f', '/remote/x'], {}, '127.0.0.1', ['T/']),
	(['-11'], {}, '127.0.0.1,127.0.0.2', ['echo a', 'echo b']),
	(['-u', 'root', '-ea=-o Port=2222', '-ci', '-j', '-g', '-eo', '-uhe', '42', '-r', '2', '-a'], {}, '127.0.0.1', ['true']),
	(['-C', '-efs', 'T/hosts.env', '-X', '127.0.0.7', '-pre', '10.0.', '-q'], {'DEFAULT_ENV_FILES': []}, 'replay_group', ['true']),
	(['-ef', 'T/hosts.env'], {}, 'replay_group,127.0.0.1', ['true']),
	# a command word starting with "-" follows a "--", else it is read as an mssh option (-x, -a)
	(['-q'], {}, '127.0.0.1', ['--', '-x']),
	(['-a'], {}, '127.0.0.1', ['--', '-x', 'ls -l']),
]


def _case_argv(options, hosts, commands, directory):
	fill = lambda text: text.replace('T/', str(directory) + os.sep) if text.startswith('T/') else text
	history = directory / 'history'
	# no env files but the case's own: this machine's could define any alias
	env = [] if '-ef' in options or '-efs' in options else ['-ef', os.devnull]
	return env + ['-hf', str(history)] + [fill(option) for option in options] + [hosts] + [fill(command) for command in commands]


@pytest.mark.parametrize('options, config, hosts, commands', ROUND_TRIPS)
def test_history_line_replays_the_same_run(options, config, hosts, commands, replay_env, monkeypatch, capsys):
	for name, value in config.items():
		monkeypatch.setattr(multiSSH3, name, value)
	first, _ = _run_main(_case_argv(options, hosts, commands, replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]

	replayed, _ = _run_main(_history_argv(line), capsys)

	assert _effective(replayed, first) == _effective(first, first), line
	assert 'bmcpw' not in line


@pytest.mark.parametrize('options, config, hosts, commands', ROUND_TRIPS)
def test_command_echo_replays_the_same_run(options, config, hosts, commands, replay_env, monkeypatch, capsys):
	for name, value in config.items():
		monkeypatch.setattr(multiSSH3, name, value)
	first, echo = _run_main(_case_argv(options, hosts, commands, replay_env), capsys)
	if echo is None:
		assert first['no_output']  # -Q prints nothing, the echo included
		return

	replayed, _ = _run_main(shlex.split(echo)[1:], capsys)

	assert _effective(replayed, first, typed_hosts=False) == _effective(first, first, typed_hosts=False), echo
	assert 'bmcpw' not in echo


@pytest.mark.parametrize('options, config, hosts, commands', ROUND_TRIPS)
def test_mssh_complete_reads_every_recorded_option(options, config, hosts, commands, replay_env, monkeypatch, capsys):
	for name, value in config.items():
		monkeypatch.setattr(multiSSH3, name, value)
	ran, _ = _run_main(_case_argv(options, hosts, commands, replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]

	entry = mc.parse_history_line(line, SPEC)

	recorded = [word for word in shlex.split(line.split('\t')[2])]
	assert entry is not None
	# every option is recorded as one word, its value attached: each one names an mssh option
	assert len(entry.options) == len(recorded), (recorded, entry.option_texts)
	assert entry.hosts == hosts
	assert entry.commands == ran['commands']
	# the Ctrl-R picker and the diagnostics replay read the line with its fields joined
	fields = line.split('\t')
	text = ' '.join(['mssh'] + [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS'])
	assert mc.parse_context(text + ' ', '', SPEC).hosts == hosts


def test_script_timeout_is_recorded_as_the_timeout_it_chose(replay_env, capsys):
	_run_main(_case_argv(['-T'], '127.0.0.1', ['true'], replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]
	assert '-t={}'.format(multiSSH3.DEFAULT_TIMEOUT) in shlex.split(line.split('\t')[2])


@pytest.mark.parametrize('config, options', [
	({'DEFAULT_IPMI_DEFINITIONS': [CONFIGURED_LOGIN]}, ['-iu', 'a', '-ip', 'b']),
	({'DEFAULT_IPMI_DEFINITIONS': [CONFIGURED_LOGIN]}, ['-iu', 'a', '-ip', 'b', '-ia=-I lanplus', '-mpre', '10.9.', '-irlt', '30']),
	({'DEFAULT_IPMI_DEFINITIONS': [CONFIGURED_LOGIN]}, ['-ip', 'b', '-ia=-I lanplus']),
	({'DEFAULT_IPMI_USERNAME': 'u', 'DEFAULT_IPMI_PASSWORD': 'p'}, ['-iu', 'a', '-ip', 'b']),
	({}, ['-iu', 'a', '-ip', 'b', '-im', 'ipmitool']),
])
def test_replay_without_the_ipmi_password_tries_only_the_configured_logins(config, options, replay_env, monkeypatch, capsys):
	# -ip is not recorded: an IPMI option recorded without it would pair with the configured password
	# into a login nobody gave, tried first on every BMC, a failed login each towards locking it
	for name, value in config.items():
		monkeypatch.setattr(multiSSH3, name, value)
	first, _ = _run_main(_case_argv(['-M'] + options, '127.0.0.1', ['power status'], replay_env), capsys)
	plain, _ = _run_main(_case_argv(['-M', '-nh'], '127.0.0.1', ['power status'], replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]

	replayed, _ = _run_main(_history_argv(line), capsys)

	assert first['ipmi_logins'][0] == ('a', 'b') or '-iu' not in options
	assert replayed['ipmi_logins'] == plain['ipmi_logins'], line
	assert ('a', multiSSH3.DEFAULT_IPMI_PASSWORD) not in replayed['ipmi_logins']


def test_ipmi_password_is_neither_recorded_nor_echoed(replay_env, capsys):
	ran, echo = _run_main(_case_argv(['-M', '-iu', 'bmcadmin', '-ip', 'bmcpw', '--ipmi_password=bmcpw2'], '127.0.0.1', ['power status'], replay_env), capsys)
	line = (replay_env / 'history').read_text()
	assert ran['ipmi_password'] == 'bmcpw2'
	assert 'bmcpw' not in line and 'bmcpw' not in echo


def test_config_file_is_recorded_with_its_absolute_path(replay_env, capsys):
	# a relative path would load whatever config file the directory of a later replay holds
	_run_main(_case_argv(['--config_file', 'replay.config.json'], '127.0.0.1', ['true'], replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]
	assert '--config_file={}'.format(replay_env / 'replay.config.json') in shlex.split(line.split('\t')[2])


def test_file_sync_does_not_take_the_hosts_as_a_path(replay_env, capsys):
	# -fs takes an optional path: recorded last, it would read the hosts field as one
	_run_main(_case_argv(['-s', 'T/a.txt'], '127.0.0.1', ['/tmp/dst/'], replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]
	recorded = shlex.split(line.split('\t')[2])
	assert recorded[-1] != '-fs'


def test_dash_commands_follow_a_double_dash_after_the_hosts(replay_env, capsys):
	# "-- HOSTS -x" would do on 3.12+, but argparse 3.11 and older read -x as an option there
	_, echo = _run_main(_case_argv(['-a'], '127.0.0.1', ['--', '-x', 'ls -l'], replay_env), capsys)
	fields = (replay_env / 'history').read_text().splitlines()[-1].split('\t')
	assert '--' not in shlex.split(fields[2])
	assert shlex.split(fields[3]) == ['127.0.0.1', '--']
	assert shlex.split(fields[4]) == ['-x', 'ls -l']
	assert shlex.split(echo)[-4:] == ['127.0.0.1', '--', '-x', 'ls -l']


def test_replaying_a_found_key_warns_of_nothing(replay_env, capsys):
	# -uk records the key it found as -k='~/.ssh/id_ed25519': the replay must find it there too
	_run_main(_case_argv(['-uk'], '127.0.0.1', ['true'], replay_env), capsys)
	line = (replay_env / 'history').read_text().splitlines()[-1]
	argv = _history_argv(line)
	assert '-k=~/.ssh/id_ed25519' in argv

	capsys.readouterr()
	args = multiSSH3.process_keys(multiSSH3.get_parser().parse_args(argv))

	assert args.identity_file == '~/.ssh/id_ed25519'
	assert 'not found' not in capsys.readouterr().err


def test_library_run_records_the_timeout_the_cli_would_not_use(tmp_path):
	# run_command_on_hosts defaults to DEFAULT_TIMEOUT, the CLI to DEFAULT_CLI_TIMEOUT
	path = tmp_path / 'history'
	multiSSH3.record_command_history({'hosts': '127.0.0.1', 'commands': ['true'], 'history_file': str(path),
		'timeout': multiSSH3.DEFAULT_TIMEOUT, 'no_output': ..., 'files': ['/tmp/x']})
	options = shlex.split(path.read_text().split('\t')[2])
	assert '-t={}'.format(multiSSH3.DEFAULT_TIMEOUT) in options
	assert '-f=/tmp/x' in options
	assert '-no' not in options
