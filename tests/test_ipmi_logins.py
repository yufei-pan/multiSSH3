'''Which IPMI logins --ipmi tries, in order: each wrong one can count towards a BMC lockout.'''
import copy
import io
import json
import os
import shlex
import subprocess
import sys
import threading

import pytest

import multiSSH3
from conftest import MULTISSH3_PY

# what DEFAULT_IPMI_* hold when no config file sets them
BUILTIN = {
	'DEFAULT_IPMI_INTERFACE_IP_PREFIX': '',
	'DEFAULT_IPMI_USERNAME': 'admin',
	'DEFAULT_IPMI_PASSWORD': 'admin',
	'DEFAULT_IPMI_ARGS': '',
	'DEFAULT_IPMI_METHOD': 'ipmitool',
	'DEFAULT_IPMI_RETRY_LOCKOUT_TIME': -1,
}
# one definition with every key, as --generate_config_file / --store_config_file write them
BUILTIN_DEFINITION = {'interface_ip_prefix': '', 'username': 'admin', 'password': 'admin', 'args': '',
	'ipmi_method': 'ipmitool', 'hostname_keyword': '', 'retry_lockout_time': -1}
AUTH_FAILURE = b'Error: Unable to establish IPMI v2 / RMCP+ session\n'


class FailingProc:
	def __init__(self):
		self.stdout = io.BytesIO()
		self.stderr = io.BytesIO(AUTH_FAILURE)
		self.stdin = io.BytesIO()
		self.returncode = 1

	def poll(self):
		return self.returncode

	def communicate(self, timeout=None):
		return b'', b''


def _login(argv):
	'''(user, password, args) of an ipmitool command line run through sh -c, else the argv.'''
	if argv[:2] != ['/bin/sh', '-c']:
		return tuple(argv)
	words = shlex.split(argv[2])
	user = words[words.index('-U') + 1]
	password = words[words.index('-P') + 1]
	rest = words[words.index('-P') + 2:]
	return (user, password, ' '.join(rest[:-2]))


def logins_tried(monkeypatch, config=None, argv=(), host='bmc1', command_line=True):
	'''
	The ipmitool logins mssh tries on host, in order, when every one fails.

	config is what the config files set, applied to the module the way loading them at import
	does; argv is the rest of the command line after "-M host 'power status'". Without
	command_line the module runs the host as when imported (no process_args).
	'''
	runs = commands_run(monkeypatch, config, argv, host, command_line)
	return [_login(run) for run in runs if run[:2] == ['/bin/sh', '-c']]


def commands_run(monkeypatch, config=None, argv=(), host='bmc1', command_line=True, bins=('sh', 'ipmitool', 'ssh')):
	'''Every command line mssh runs for host in --ipmi mode when each one fails (see logins_tried).'''
	for name, value in BUILTIN.items():
		monkeypatch.setattr(multiSSH3, name, value)
	# DEFAULT_IPMI_DEFINITIONS as the module builds it before any config file loads
	monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_DEFINITIONS', [dict(BUILTIN_DEFINITION)])
	monkeypatch.setattr(multiSSH3, '__configs_from_file', {})
	for name, value in (config or {}).items():
		monkeypatch.setattr(multiSSH3, name, copy.deepcopy(value))
	if command_line:
		args = multiSSH3.process_args(['-M', host, 'power status'] + list(argv))
		assert args.ipmi
	monkeypatch.setattr(multiSSH3, '_binPaths', {name: '/bin/' + name for name in bins})
	monkeypatch.setattr(multiSSH3.time, 'sleep', lambda seconds: None)
	runs = []

	def popen(argv, **kwargs):
		runs.append(list(argv))
		return FailingProc()

	monkeypatch.setattr(multiSSH3.subprocess, 'Popen', popen)
	target = multiSSH3.Host(host, 'power status', ipmi=True, ip='10.0.0.1')
	target.interactive_stdin = False
	multiSSH3.run_command(target, threading.Semaphore(1), 5)
	assert target.stderr == ['Error: Exhausted all matching ipmi definitions!']
	return runs


def test_nothing_configured_tries_the_built_in_login(monkeypatch):
	assert logins_tried(monkeypatch) == [('admin', 'admin', '')]


def test_command_line_login_alone(monkeypatch):
	assert logins_tried(monkeypatch, argv=['-iu', 'root', '-ip', 'pw']) == [('root', 'pw', '')]


def test_config_login_is_tried_without_admin_admin(monkeypatch):
	# a hand-written config with only the login: admin / admin was tried first
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}
	assert logins_tried(monkeypatch, config) == [('cfguser', 'cfgpass', '')]


def test_command_line_username_with_config_password_without_admin_admin(monkeypatch):
	# admin / admin was tried second
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}
	assert logins_tried(monkeypatch, config, ['-iu', 'cliuser']) == [('cliuser', 'cfgpass', '')]


def test_configured_definitions_without_admin_admin_after_them(monkeypatch):
	# admin / admin was tried last
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'u2', 'password': 'p2'}]}
	assert logins_tried(monkeypatch, config) == [('u1', 'p1', ''), ('u2', 'p2', '')]


def test_command_line_ipmi_args_go_to_the_definitions_not_to_admin_admin(monkeypatch):
	# -ia alone made admin / admin (with -I lanplus) the first login, and the definitions went without it
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'u2', 'password': 'p2', 'args': '-I lan'}]}
	assert logins_tried(monkeypatch, config, ['-ia=-I lanplus']) == [('u1', 'p1', '-I lanplus'), ('u2', 'p2', '-I lan')]


def test_command_line_ipmi_args_with_config_login_go_first(monkeypatch):
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass',
		'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config, ['-ia=-I lanplus']) == [('cfguser', 'cfgpass', '-I lanplus'), ('u1', 'p1', '-I lanplus')]


def test_definition_repeating_the_config_login_is_tried_once(monkeypatch):
	config = {'DEFAULT_IPMI_USERNAME': 'root', 'DEFAULT_IPMI_PASSWORD': 'x',
		'DEFAULT_IPMI_DEFINITIONS': [{'username': 'root', 'password': 'x'}]}
	assert logins_tried(monkeypatch, config) == [('root', 'x', '')]


def test_config_login_comes_after_the_definitions(monkeypatch):
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass',
		'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config) == [('u1', 'p1', ''), ('cfguser', 'cfgpass', '')]


def test_command_line_login_comes_before_the_definitions(monkeypatch):
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config, ['-iu', 'cliuser', '-ip', 'clipass']) == [('cliuser', 'clipass', ''), ('u1', 'p1', '')]


def test_command_line_admin_admin_is_tried_first_when_typed(monkeypatch):
	# typed on the command line it is the operator's choice, even though it equals the defaults
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config, ['-iu', 'admin', '-ip', 'admin']) == [('admin', 'admin', ''), ('u1', 'p1', '')]


def test_command_line_username_fills_definitions_without_one(monkeypatch):
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'password': 'p1'}]}
	assert logins_tried(monkeypatch, config, ['-iu', 'root']) == [('root', 'admin', ''), ('root', 'p1', '')]


def test_config_username_without_password_adds_no_login_after_the_definitions(monkeypatch):
	# root / admin, the configured user with the built-in password, was tried last
	config = {'DEFAULT_IPMI_USERNAME': 'root', 'DEFAULT_IPMI_DEFINITIONS': [{'password': 'p1'}, {'password': 'p2'}]}
	assert logins_tried(monkeypatch, config) == [('root', 'p1', ''), ('root', 'p2', '')]


def test_admin_admin_listed_in_the_definitions_is_tried_once(monkeypatch):
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'admin', 'password': 'admin'}]}
	assert logins_tried(monkeypatch, config) == [('u1', 'p1', ''), ('admin', 'admin', '')]


def test_host_no_definition_applies_to_gets_the_default_login(monkeypatch):
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'hostname_keyword': 'gpu', 'username': 'root', 'password': 'x'}]}
	assert logins_tried(monkeypatch, config, host='gpu1') == [('root', 'x', '')]
	assert logins_tried(monkeypatch, config, host='cpu1') == [('admin', 'admin', '')]


def test_generated_config_with_a_definition_added(monkeypatch):
	# --generate_config_file writes the built-in definition into the list; one was added after it by hand
	config = {'DEFAULT_IPMI_DEFINITIONS': [dict(BUILTIN_DEFINITION), {'hostname_keyword': 'gpu', 'username': 'root', 'password': 'x'}]}
	assert logins_tried(monkeypatch, config, host='gpu1') == [('root', 'x', '')]
	assert logins_tried(monkeypatch, config, host='cpu1') == [('admin', 'admin', '')]


def test_config_stored_from_a_hand_written_login_by_6_31(monkeypatch):
	# what --store_config_file wrote up to 6.31 over a config holding only DEFAULT_IPMI_USERNAME / PASSWORD
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass', 'DEFAULT_IPMI_DEFINITIONS': [
		dict(BUILTIN_DEFINITION), dict(BUILTIN_DEFINITION, username='cfguser', password='cfgpass')]}
	assert logins_tried(monkeypatch, config) == [('cfguser', 'cfgpass', '')]


def test_config_stored_with_ipmi_args_by_6_31(monkeypatch):
	# what `--store_config_file -ia='-I lanplus'` wrote up to 6.31 over a config holding one definition
	config = {'DEFAULT_IPMI_ARGS': '-I lanplus', 'DEFAULT_IPMI_DEFINITIONS': [
		dict(BUILTIN_DEFINITION, args='-I lanplus'), {'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config) == [('u1', 'p1', '-I lanplus')]


def test_imported_module_uses_the_config_login(monkeypatch):
	# run_command_on_hosts(ipmi=True) without the command line tried admin / admin only
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}
	assert logins_tried(monkeypatch, config, command_line=False) == [('cfguser', 'cfgpass', '')]
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	assert logins_tried(monkeypatch, config, command_line=False) == [('u1', 'p1', '')]


def test_command_line_ipmi_args_with_config_login_only(monkeypatch):
	# admin / admin was tried after it
	config = {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}
	assert logins_tried(monkeypatch, config, ['-ia=-I lanplus']) == [('cfguser', 'cfgpass', '-I lanplus')]


SSH_FALLBACK = ['/bin/ssh', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null', '--', 'bmc1', 'ipmitool power status']


def test_ssh_fallback_runs_once_after_every_login_failed(monkeypatch):
	# each failed ipmitool login queued the same ssh login again
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'u2', 'password': 'p2'}]}
	runs = commands_run(monkeypatch, config)
	assert [_login(run) for run in runs] == [('u1', 'p1', ''), ('u2', 'p2', ''), tuple(SSH_FALLBACK)]


def test_without_local_ipmitool_ssh_runs_once(monkeypatch):
	# every definition turns into the same ssh login when ipmitool is not installed here
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'u2', 'password': 'p2'}]}
	assert commands_run(monkeypatch, config, bins=('sh', 'ssh')) == [SSH_FALLBACK]


def _stored_definitions(monkeypatch, tmp_path, config, argv):
	'''DEFAULT_IPMI_DEFINITIONS and the login as `mssh ARGV --store_config_file` writes them over config.'''
	for name, value in BUILTIN.items():
		monkeypatch.setattr(multiSSH3, name, value)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_DEFINITIONS', [dict(BUILTIN_DEFINITION)])
	monkeypatch.setattr(multiSSH3, '__configs_from_file', copy.deepcopy(config))
	for name, value in config.items():
		monkeypatch.setattr(multiSSH3, name, copy.deepcopy(value))
	path = tmp_path / 'stored.json'
	args = multiSSH3.process_args(list(argv) + ['--store_config_file', str(path)])
	assert multiSSH3.write_default_config(args, str(path), force=True)
	stored = json.loads(path.read_text())
	return {name: value for name, value in stored.items() if name.startswith('DEFAULT_IPMI_') and name != 'DEFAULT_IPMI'}


@pytest.mark.parametrize('config, argv', [
	({}, []),
	({}, ['-iu', 'cfguser', '-ip', 'cfgpass']),
	({'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}, []),
	({'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}, ['-ia=-I lanplus']),
	({'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}, ['-iu', 'root', '-ip', 'pw']),
])
def test_stored_config_tries_what_the_run_tried(monkeypatch, tmp_path, config, argv):
	ran = logins_tried(monkeypatch, config, argv)
	stored = _stored_definitions(monkeypatch, tmp_path, config, argv)
	assert logins_tried(monkeypatch, stored) == ran


def test_stored_config_keeps_its_definitions_and_marks_the_command_line_login(monkeypatch, tmp_path):
	config = {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}]}
	stored = _stored_definitions(monkeypatch, tmp_path, config, ['-iu', 'root', '-ip', 'pw'])
	assert stored['DEFAULT_IPMI_DEFINITIONS'] == [dict(BUILTIN_DEFINITION, username='root', password='pw'), {'username': 'u1', 'password': 'p1'}]
	stored = _stored_definitions(monkeypatch, tmp_path, {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}, [])
	# a reader before this change appends the DEFAULT_IPMI_* login after a list that does not end with it
	assert stored['DEFAULT_IPMI_DEFINITIONS'] == [dict(BUILTIN_DEFINITION, username='cfguser', password='cfgpass')]


# ---- end to end: real config files in a scratch HOME, fake ipmitool / ssh logging what they ran ----

FAKE_TOOL = '''#!{python}
import json, os, sys
with open(os.environ['FAKE_LOG'], 'a') as log:
	log.write(json.dumps([{name!r}] + sys.argv[1:]) + '\\n')
sys.stderr.write('Error: Unable to establish IPMI v2 / RMCP+ session\\n')
sys.exit(1)
'''


def _mssh_ipmi_run(tmp_path, config, argv=()):
	'''Run `mssh -M 127.0.0.1 'power status'` with config as ~/.multiSSH3.config.json; the tools it ran, in order.'''
	home = tmp_path / 'home'
	bin_dir = tmp_path / 'bin'
	runtime = tmp_path / 'runtime'
	for directory in (home, bin_dir, runtime):
		directory.mkdir(exist_ok=True)
	runtime.chmod(0o700)
	tools = {}
	for name in ('ipmitool', 'ssh', 'sshpass', 'scp', 'rsync', 'redfishtool'):
		tool = bin_dir / name
		tool.write_text(FAKE_TOOL.format(python=sys.executable, name=name))
		tool.chmod(0o755)
		tools['_{}Path'.format(name)] = str(tool)
	config_file = home / '.multiSSH3.config.json'
	config_file.write_text(json.dumps(dict(tools, **config)))
	config_file.chmod(0o600)
	hosts = tmp_path / 'hosts'
	hosts.write_text('127.0.0.1 localhost\n')
	log = tmp_path / 'tools.log'
	if log.exists():
		log.unlink()
	env = {'HOME': str(home), 'PATH': '{}:/usr/bin:/bin'.format(bin_dir), 'XDG_RUNTIME_DIR': str(runtime),
		'FAKE_LOG': str(log), 'LANG': 'C.UTF-8'}
	subprocess.run([sys.executable, str(MULTISSH3_PY), '-M', '127.0.0.1', 'power status', '-ef', '/dev/null',
		'--host_file', str(hosts), '-I', '-S', '-uhe', '1'] + list(argv),
		env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	if not log.exists():
		return []
	return [json.loads(line) for line in log.read_text().splitlines()]


def _ipmitool_logins(runs):
	logins = []
	for run in runs:
		if run[0] == 'ipmitool':
			logins.append((run[run.index('-U') + 1], run[run.index('-P') + 1]))
	return logins


def test_end_to_end_config_login_only(tmp_path):
	runs = _mssh_ipmi_run(tmp_path, {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'})
	assert _ipmitool_logins(runs) == [('cfguser', 'cfgpass')]


def test_end_to_end_definitions_only(tmp_path):
	runs = _mssh_ipmi_run(tmp_path, {'DEFAULT_IPMI_DEFINITIONS': [{'username': 'u1', 'password': 'p1'}, {'username': 'u2', 'password': 'p2'}]})
	assert _ipmitool_logins(runs) == [('u1', 'p1'), ('u2', 'p2')]
	# then ipmitool on the host over ssh, once
	assert [run for run in runs if run[0] == 'ssh'] == [['ssh', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null', '--', '127.0.0.1', 'ipmitool power status']]


def test_end_to_end_command_line_login_with_config_login(tmp_path):
	runs = _mssh_ipmi_run(tmp_path, {'DEFAULT_IPMI_USERNAME': 'cfguser', 'DEFAULT_IPMI_PASSWORD': 'cfgpass'}, ['-iu', 'cliuser'])
	assert _ipmitool_logins(runs) == [('cliuser', 'cfgpass')]
