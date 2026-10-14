"""
start_run_on_hosts runs the hosts on a pool of at most max_connections threads, so a run on thousands
of hosts does not need a thread per host: a process / thread limit (ulimit -u, a container's pids
limit) counts every thread, and running out of them must not crash the run or lose hosts.
"""
import threading
import time

import pytest

import multiSSH3


def _allow_threads(monkeypatch, allowed):
	'''Let only `allowed` more threads start, as under a process / thread limit. Returns the count left, to change.'''
	left = [allowed]

	class LimitedThread(threading.Thread):
		def start(self):
			if left[0] <= 0:
				raise RuntimeError("can't start new thread")
			left[0] -= 1
			super().start()

	monkeypatch.setattr(multiSSH3.threading, "Thread", LimitedThread)
	return left


class Runs:
	'''A fake run_command recording which thread ran which host, and how many ran at once.'''

	def __init__(self, monkeypatch, gate=None):
		self.gate = gate
		self.lock = threading.Lock()
		self.running = 0
		self.most = 0
		self.order = []  # (host name, thread, whether the gate was open)
		monkeypatch.setattr(multiSSH3, "run_command", self.run)

	def run(self, host, sem, timeout=60, passwds=None):
		with self.lock:
			self.running += 1
			self.most = max(self.most, self.running)
			self.order.append((host.name, threading.current_thread(), bool(self.gate and self.gate.is_set())))
		if self.gate:
			self.gate.wait(10)
		else:
			threading.Event().wait(0.002)  # long enough for the others to overlap (time.sleep may be faked)
		with self.lock:
			self.running -= 1
		host.returncode = 0


def _hosts(fake_host, count):
	return [fake_host("h{}".format(number)) for number in range(count)]


def test_more_hosts_than_connections_share_that_many_threads(fake_host, monkeypatch):
	runs = Runs(monkeypatch)
	hosts = _hosts(fake_host, 40)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=4)
	multiSSH3.join_threads(threads, timeout=10)

	assert len(threads) == 4
	assert all(host.returncode == 0 for host in hosts)
	assert runs.most <= 4
	assert {thread for _, thread, _ in runs.order} <= set(threads)
	assert all(host.thread in threads for host in hosts)  # the worker that ran it


def test_hosts_start_in_the_given_order(fake_host, monkeypatch):
	runs = Runs(monkeypatch)
	hosts = _hosts(fake_host, 20)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=1)
	multiSSH3.join_threads(threads, timeout=10)

	assert [name for name, _, _ in runs.order] == [host.name for host in hosts]


def test_fewer_hosts_than_connections_start_a_thread_each(fake_host, monkeypatch):
	Runs(monkeypatch)
	hosts = _hosts(fake_host, 3)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=50)
	multiSSH3.join_threads(threads, timeout=10)

	assert len(threads) == 3
	assert all(host.returncode == 0 for host in hosts)


def test_ipmi_hosts_wait_out_their_lockouts_at_once(fake_host, monkeypatch):
	# between two IPMI passwords a host waits out retry_lockout_time running nothing, outside the
	# connection limit: as before, IPMI hosts get a thread each, so their waits overlap
	gate = threading.Event()
	runs = Runs(monkeypatch, gate)  # each host waits for the gate, like a lockout wait
	hosts = [fake_host("bmc{}".format(number), "power status", ipmi=True) for number in range(6)]

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=2)
	deadline = time.monotonic() + 5
	while runs.running < 6 and time.monotonic() < deadline:
		threading.Event().wait(0.01)
	gate.set()
	multiSSH3.join_threads(threads, timeout=10)

	assert len(threads) == 6
	assert runs.most == 6
	assert all(host.returncode == 0 for host in hosts)


def test_the_call_returns_while_hosts_wait_for_a_thread(fake_host, monkeypatch):
	# return_unfinished relies on it: the caller gets the hosts back at once, and join_threads waits for all
	gate = threading.Event()
	Runs(monkeypatch, gate)
	hosts = _hosts(fake_host, 6)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=2)

	assert all(host.returncode is None for host in hosts)
	gate.set()
	multiSSH3.join_threads(threads, timeout=10)
	assert all(host.returncode == 0 for host in hosts)
	assert not any(thread.is_alive() for thread in threads)


def test_hosts_all_run_when_fewer_threads_can_start(fake_host, monkeypatch, capsys):
	runs = Runs(monkeypatch)
	_allow_threads(monkeypatch, 3)
	hosts = _hosts(fake_host, 20)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=10)
	multiSSH3.join_threads(threads, timeout=10)

	assert len(threads) == 3
	assert all(host.returncode == 0 for host in hosts)
	assert sorted(name for name, _, _ in runs.order) == sorted(host.name for host in hosts)  # each once
	assert "running the hosts at most 1 at a time" in capsys.readouterr().err


def test_out_of_threads_the_pool_shrinks_to_leave_room_for_the_commands(fake_host, monkeypatch):
	# the workers started took what the system allows, and each command needs more (ssh, threads
	# reading its output): half of the workers stop before taking another host
	gate = threading.Event()
	runs = Runs(monkeypatch, gate)
	_allow_threads(monkeypatch, 4)
	hosts = _hosts(fake_host, 30)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=10)
	gate.set()
	multiSSH3.join_threads(threads, timeout=10)

	assert len(threads) == 4
	assert all(host.returncode == 0 for host in hosts)
	later = {thread for _, thread, gate_open in runs.order if gate_open}
	assert len(later) <= 2


def test_a_thread_that_can_start_after_a_back_off_runs_the_hosts(fake_host, monkeypatch):
	Runs(monkeypatch)
	left = _allow_threads(monkeypatch, 0)
	sleeps = []

	def sleep(seconds):
		sleeps.append(seconds)
		if len(sleeps) == 1:
			left[0] = 1  # a process ended meanwhile

	monkeypatch.setattr(multiSSH3.time, "sleep", sleep)
	hosts = _hosts(fake_host, 5)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=4)
	multiSSH3.join_threads(threads, timeout=10)

	assert sleeps[0] == 0.1
	assert len(threads) == 1
	assert all(host.returncode == 0 for host in hosts)


def test_every_host_fails_with_a_message_when_no_thread_can_start(fake_host, monkeypatch):
	runs = Runs(monkeypatch)
	_allow_threads(monkeypatch, 0)
	sleeps = []
	monkeypatch.setattr(multiSSH3.time, "sleep", sleeps.append)
	hosts = _hosts(fake_host, 5)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=4)

	assert threads == []
	assert runs.order == []
	assert sleeps and sleeps[0] == 0.1  # waited for threads before giving up
	assert sum(sleeps) < 10
	for host in hosts:
		assert host.returncode == 1
		assert any("no more processes or threads" in line for line in host.stderr)
		assert host.stderr == [line for line in host.output if line.startswith("Error")]


def test_ctrl_c_stops_waiting_for_a_thread(fake_host, monkeypatch):
	Runs(monkeypatch)
	_allow_threads(monkeypatch, 0)
	sleeps = []

	def sleep(seconds):
		sleeps.append(seconds)
		multiSSH3._emo = True  # Ctrl-C while waiting

	monkeypatch.setattr(multiSSH3.time, "sleep", sleep)
	hosts = _hosts(fake_host, 3)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=4)

	assert threads == []
	assert len(sleeps) == 1
	assert all(host.returncode == 1 for host in hosts)


def test_thread_start_delay_spaces_the_thread_starts(fake_host, monkeypatch):
	Runs(monkeypatch)
	sleeps = []
	monkeypatch.setattr(multiSSH3.time, "sleep", sleeps.append)
	monkeypatch.setattr(multiSSH3, "__thread_start_delay", 0.25)
	hosts = _hosts(fake_host, 5)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=2)
	multiSSH3.join_threads(threads, timeout=10)

	assert sleeps == [0.25, 0.25]  # one per thread started, as it throttles starting threads


def test_a_worker_survives_a_host_that_exits_its_thread(fake_host, monkeypatch):
	ran = []

	def run(host, sem, timeout=60, passwds=None):
		ran.append(host.name)
		if host.name == "h0":
			raise SystemExit(3)  # would end the only worker, leaving the other hosts waiting forever
		host.returncode = 0

	monkeypatch.setattr(multiSSH3, "run_command", run)
	hosts = _hosts(fake_host, 3)

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=5, max_connections=1)
	multiSSH3.join_threads(threads, timeout=10)

	assert ran == ["h0", "h1", "h2"]
	assert hosts[0].returncode == -1
	assert [host.returncode for host in hosts[1:]] == [0, 0]


def test_ctrl_c_stops_the_running_and_the_waiting_hosts(fake_host):
	# the first Ctrl-C stops every command: the running ones, and the ones still waiting for a thread do not start
	if "sh" not in multiSSH3._binPaths:
		pytest.skip("needs sh")
	hosts = [fake_host("localhost", "exec sleep 5", shell=True) for _ in range(6)]
	started = time.monotonic()

	threads = multiSSH3.start_run_on_hosts(hosts, timeout=30, max_connections=2)
	time.sleep(0.3)
	multiSSH3._emo = True
	multiSSH3.join_threads(threads, timeout=10)

	assert time.monotonic() - started < 4
	assert all(host.returncode is not None for host in hosts)
	stopped = [host for host in hosts if "Ctrl C detected, Emergency Stop!" in host.stderr]
	not_started = [host for host in hosts if host.stderr == ["Not started: Ctrl C"]]
	assert (len(stopped), len(not_started)) == (2, 4)
	assert all(host.returncode == 130 for host in not_started)
