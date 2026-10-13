'''The prober: checks queued hosts in the background, as parallel as the machine allows, never connecting to them.'''
import errno
import os
import socket
import subprocess
import types

import pytest

import multiSSH3
import mssh_complete as mc

NOW = 1790000000.0
REAL_HOST_VALIDITY = multiSSH3.host_validity
# a stand-in for ping: the last argument is the host; hosts in $FAKE_PING_UP answer
FAKE_PING = '''#!/bin/sh
for host; do :; done
echo "$host" >> "$FAKE_PING_LOG"
case " $FAKE_PING_HANG " in *" $host "*) exec sleep 30 ;; esac
case " $FAKE_PING_UP " in *" $host "*) exit 0 ;; esac
exit "${FAKE_PING_SILENT:-1}"
'''


@pytest.fixture
def env(tmp_path, monkeypatch):
	bin_dir = tmp_path / 'bin'
	bin_dir.mkdir()
	(bin_dir / 'ping').write_text(FAKE_PING)
	(bin_dir / 'ping').chmod(0o755)
	monkeypatch.setenv('PATH', str(bin_dir) + os.pathsep + os.environ.get('PATH', ''))
	monkeypatch.setenv('FAKE_PING_LOG', str(tmp_path / 'ping.log'))
	monkeypatch.setenv('FAKE_PING_UP', 'node1 node2')
	verdicts = {'node1': 'valid', 'node2': 'valid', 'node3': 'valid', 'gpu017': 'invalid'}
	monkeypatch.setattr(multiSSH3, 'host_validity', lambda host, timeout=2.0: verdicts.get(host, 'valid'))
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	# the prober lowers its own priority: not the test runner's
	monkeypatch.setattr(mc.os, 'nice', lambda increment: 0)
	directory = tmp_path / 'run'
	directory.mkdir(mode=0o700)
	log = tmp_path / 'ping.log'
	return types.SimpleNamespace(directory=str(directory), pinged=lambda: log.read_text().split() if log.exists() else [])


def states(env):
	return {host: (state.validity, state.ping, state.pinged_at, state.answered_at) for host, state in mc.read_host_states(env.directory).items()}


def test_queued_hosts_are_checked_and_pinged(env):
	mc.queue_probes(env.directory, ['node1', 'node3', 'gpu017'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert states(env) == {
		'node1': ('valid', 'answer', NOW, NOW),
		'node3': ('valid', 'silent', NOW, 0.0),
		'gpu017': ('invalid', '', 0.0, 0.0),
	}
	# a host that does not exist is not pinged
	assert sorted(env.pinged()) == ['node1', 'node3']
	assert mc.take_probe_queue(env.directory) == []


def test_fresh_answers_are_not_asked_for_again(env):
	mc.write_host_states(env.directory, {'node1': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	mc.queue_probes(env.directory, ['node1'])
	mc.run_probe(env.directory, now=lambda: NOW + 30)
	assert env.pinged() == []


def test_a_host_going_silent_keeps_when_it_last_answered(env):
	mc.write_host_states(env.directory, {'node3': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	mc.queue_probes(env.directory, ['node3'])
	mc.run_probe(env.directory, now=lambda: NOW + 90)
	assert states(env)['node3'] == ('valid', 'silent', NOW + 90, NOW)


@pytest.mark.parametrize('ping', ['missing', 'failing'])
def test_without_a_working_ping_hosts_get_none(env, monkeypatch, ping):
	if ping == 'missing':
		monkeypatch.setenv('PATH', '/nonexistent')
	else:
		# iputils ping exits 2 on errors (no permission, a name it cannot resolve)
		monkeypatch.setenv('FAKE_PING_SILENT', '2')
	mc.queue_probes(env.directory, ['node3', 'node4'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert {host: state[1] for host, state in states(env).items()} == {'node3': 'none', 'node4': 'none'}


def test_a_ping_that_does_not_finish_says_nothing(env, monkeypatch):
	# ping -W1 is done in about a second: one that runs out of time is stuck on its own name lookup
	# (a slow DNS server), which says nothing about the host
	monkeypatch.setattr(mc, 'PING_TIMEOUT', 0.5, raising=False)
	monkeypatch.setenv('FAKE_PING_HANG', 'node3')
	mc.write_host_states(env.directory, {'node3': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	mc.queue_probes(env.directory, ['node3'])
	mc.run_probe(env.directory, now=lambda: NOW + 90)
	assert states(env)['node3'] == ('valid', 'none', NOW + 90, NOW)


def test_parallelism_follows_mssh_and_backs_off_under_load(monkeypatch):
	monkeypatch.setattr(multiSSH3, '_normalize_max_connections', lambda value: value)
	monkeypatch.setattr(mc.os, 'cpu_count', lambda: 8)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 40)
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (2.0, 2.0, 2.0))
	assert mc.probe_parallelism(multiSSH3) == 40
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (8.0, 8.0, 8.0))
	assert mc.probe_parallelism(multiSSH3) == 20
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 6)
	assert mc.probe_parallelism(multiSSH3) == 4


def test_the_open_file_limit_caps_parallelism(monkeypatch):
	# mssh's own rule clamps to what the descriptor limit supports
	monkeypatch.setattr(multiSSH3, '__max_connections_nofile_limit_supported', 10)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 400)
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (0.0, 0.0, 0.0))
	assert mc.probe_parallelism(multiSSH3) == 10


def test_running_out_of_descriptors_halves_and_retries(env, monkeypatch):
	real_run = subprocess.run
	calls = []

	def flaky_run(argv, **kwargs):
		calls.append(argv)
		if len(calls) == 1:
			raise OSError(errno.EMFILE, 'Too many open files')
		return real_run(argv, **kwargs)
	monkeypatch.setattr(subprocess, 'run', flaky_run)
	monkeypatch.setattr(mc, 'probe_parallelism', lambda mssh: 8)
	mc.queue_probes(env.directory, ['node1', 'node2', 'node3'])
	summary = mc.run_probe(env.directory, now=lambda: NOW)
	assert summary['parallel'] == 4
	assert {host: state[1] for host, state in states(env).items()} == {'node1': 'answer', 'node2': 'answer', 'node3': 'silent'}


def test_a_run_stops_at_its_limit_and_leaves_the_rest_queued(env, monkeypatch):
	monkeypatch.setattr(mc, 'probe_parallelism', lambda mssh: 4)
	hosts = ['node{}'.format(number) for number in range(10, 20)]
	mc.queue_probes(env.directory, hosts)
	clock = [NOW]
	write = mc.write_host_states

	def write_and_tick(directory, host_states):
		write(directory, host_states)
		clock[0] = NOW + 500  # the first batch took the whole run
	monkeypatch.setattr(mc, 'write_host_states', write_and_tick)
	mc.run_probe(env.directory, now=lambda: clock[0], limit=100)
	# the newest four were checked, the rest wait for the next run, newest first
	assert sorted(states(env)) == ['node16', 'node17', 'node18', 'node19']
	assert mc.take_probe_queue(env.directory) == ['node15', 'node14', 'node13', 'node12', 'node11', 'node10']


def test_the_prober_never_connects_to_a_host(env, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'host_validity', REAL_HOST_VALIDITY)

	def no_connection(*args, **kwargs):
		raise AssertionError('the prober opened a connection')
	monkeypatch.setattr(socket.socket, 'connect', no_connection)
	monkeypatch.setattr(socket.socket, 'connect_ex', no_connection)
	monkeypatch.setattr(socket, 'create_connection', no_connection)
	monkeypatch.setattr(multiSSH3.socket, 'getaddrinfo', lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, 'fake')))
	real_run = subprocess.run
	commands = []

	def recording_run(argv, **kwargs):
		commands.append(list(argv))
		if os.path.basename(argv[0]) == 'ssh':
			return subprocess.CompletedProcess(argv, 0, stdout='hostname {}\n'.format(argv[-1]))
		return real_run(argv, **kwargs)
	monkeypatch.setattr(subprocess, 'run', recording_run)
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', '/usr/bin/ssh')
	mc.queue_probes(env.directory, ['node1', 'typo1'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert commands and all(os.path.basename(argv[0]) == 'ping' or (os.path.basename(argv[0]) == 'ssh' and '-G' in argv) for argv in commands)


def test_one_prober_at_a_time(tmp_path, monkeypatch):
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda argv, **kwargs: started.append(argv))
	assert mc.spawn_probe(str(tmp_path)) is True
	assert mc.spawn_probe(str(tmp_path)) is False
	assert len(started) == 1 and started[0][-3:] == ['probe', '--lock', os.path.join(str(tmp_path), mc.PROBE_LOCK_NAME)]


def test_answers_are_kept_for_the_longest_ping_expiry_known(monkeypatch):
	monkeypatch.delenv('MSSH_COMPLETE_PING_TTL', raising=False)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_UNAVAILABLE_HOST_EXPIRY', 600)
	# -uhe on a line can ask for more than mssh's default: a day at least
	assert mc.answer_horizon(multiSSH3) == mc.ANSWER_KEEP == 86400
	monkeypatch.setattr(multiSSH3, 'DEFAULT_UNAVAILABLE_HOST_EXPIRY', 3 * 86400)
	assert mc.answer_horizon(multiSSH3) == 3 * 86400
	monkeypatch.setenv('MSSH_COMPLETE_PING_TTL', str(5 * 86400))
	assert mc.answer_horizon(multiSSH3) == 5 * 86400
	monkeypatch.setenv('MSSH_COMPLETE_PING_TTL', 'soon')
	monkeypatch.setattr(multiSSH3, 'DEFAULT_UNAVAILABLE_HOST_EXPIRY', 'later')
	assert mc.answer_horizon(multiSSH3) == mc.ANSWER_KEEP


def test_the_prober_writes_only_states_queries_can_use(env, monkeypatch):
	monkeypatch.delenv('MSSH_COMPLETE_PING_TTL', raising=False)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_UNAVAILABLE_HOST_EXPIRY', 600)
	day = 86400.0
	mc.write_host_states(env.directory, {
		'typo1': mc.HostState('invalid', NOW - 700),
		'old1': mc.HostState('valid', NOW - 2 * day, 'answer', NOW - 2 * day, NOW - 2 * day),
		'node4': mc.HostState('valid', NOW - 3600, 'answer', NOW - 3600, NOW - 3600),
	})
	mc.queue_probes(env.directory, ['node1'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert sorted(states(env)) == ['node1', 'node4']
