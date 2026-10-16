"""
Hosts printing the same lines (package lists, configuration files, the same command's output on a
fleet) keep one copy of each line between them: 200 hosts x 20,000 lines alike took 660 MB, 234 MB
shared. Sharing costs a lookup per line, and an entry per distinct line: when most lines are distinct
(logs), it stops, and what it held is let go.
"""
import io

import pytest

import multiSSH3


@pytest.fixture(autouse=True)
def fresh_pool(monkeypatch):
	monkeypatch.setattr(multiSSH3, "_SHARED_LINES_CHECK", 1000)
	multiSSH3._reset_shared_lines()
	yield
	multiSSH3._reset_shared_lines()


def _read(name, data):
	host = multiSSH3.Host(name, "cmd", ip="127.0.0.1")
	multiSSH3.__handle_reading_stream(io.BytesIO(data), host.stdout, host, host.stdout_buffer)
	return host


ALIKE = b"".join(b"package-%d-1.0.x86_64\n" % (number % 50) for number in range(3000))


def test_hosts_printing_the_same_lines_share_them():
	first, second = _read("a", ALIKE), _read("b", ALIKE)

	assert first.stdout == second.stdout == [line.decode() for line in ALIKE.split(b"\n")[:-1]]
	assert all(mine is theirs for mine, theirs in zip(first.stdout, second.stdout))
	assert all(line is shown for line, shown in zip(first.stdout, first.output))


def test_sharing_stops_when_most_lines_are_distinct():
	logs = b"".join(b"log line %d of a host\n" % number for number in range(5000))
	host = _read("a", logs)

	assert host.stdout == [line.decode() for line in logs.split(b"\n")[:-1]]
	assert multiSSH3._shared_lines_state["sharing"] is False
	# what it held is let go: the lines are the host's alone
	assert multiSSH3._shared_lines == {}


def test_sharing_goes_on_while_most_lines_were_seen():
	for name in "abcde":
		_read(name, ALIKE)

	assert multiSSH3._shared_lines_state["sharing"] is True
	assert len(multiSSH3._shared_lines) == 50


def test_each_run_starts_sharing_again(monkeypatch):
	for name in "ab":
		_read(name, b"".join(name.encode() + b" log line %d\n" % number for number in range(1500)))
	assert multiSSH3._shared_lines_state["sharing"] is False
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)

	multiSSH3.run_command_on_hosts(hosts="mock-a", commands=["true"], no_start=True, called=True,
		return_unfinished=False, will_update_unreachable_hosts=False, no_history=True)

	assert multiSSH3._shared_lines_state["sharing"] is True


def test_lines_read_one_at_a_time_are_shared_too():
	# a line arriving in reads of its own goes through the line buffer, not the whole-lines path
	class OneLineReads(io.BytesIO):
		def read1(self, size=-1):
			return self.readline()

	hosts = []
	for name in "ab":
		host = multiSSH3.Host(name, "cmd", ip="127.0.0.1")
		multiSSH3.__handle_reading_stream(OneLineReads(ALIKE[:2000]), host.stdout, host, host.stdout_buffer)
		hosts.append(host)

	assert hosts[0].stdout == hosts[1].stdout
	assert all(mine is theirs for mine, theirs in zip(hosts[0].stdout, hosts[1].stdout))


class _BusyPool(dict):
	"""The shared lines while other readers add theirs: each lookup comes with a line of another host's."""
	def setdefault(self, key, default=None):
		dict.setdefault(self, "line of another host %d" % len(self), "x")
		return dict.setdefault(self, key, default)


def test_lines_found_are_counted_whatever_other_readers_add(monkeypatch):
	# counting by the pool's growth took the lines other readers added meanwhile for misses: on
	# free-threaded Python sharing stopped after the first check with 99% of lines found
	_read("a", ALIKE)
	monkeypatch.setattr(multiSSH3, "_shared_lines", _BusyPool(multiSSH3._shared_lines))
	multiSSH3._shared_lines_state.update(looked_up=0, found=0)

	# whole lines: a cut last one would be new
	_read("b", ALIKE[:ALIKE.index(b"\n", 500) + 1])

	assert multiSSH3._shared_lines_state["found"] == multiSSH3._shared_lines_state["looked_up"] > 0


def test_one_check_with_few_lines_found_does_not_stop_sharing():
	# with -m 1 the first host's lines are all new to the pool: the first check finds few
	first = b"".join(b"line %d of the first host\n" % number for number in range(1200))
	_read("a", first)
	_read("b", first)

	assert multiSSH3._shared_lines_state["sharing"] is True


def test_two_checks_in_a_row_with_few_lines_found_stop_sharing():
	_read("a", b"".join(b"log line %d\n" % number for number in range(1500)))
	assert multiSSH3._shared_lines_state["sharing"] is True

	_read("b", b"".join(b"another log line %d\n" % number for number in range(1500)))

	assert multiSSH3._shared_lines_state["sharing"] is False
	assert multiSSH3._shared_lines == {}


def test_a_run_returning_unfinished_shares_nothing(monkeypatch):
	# its readers go on after it returned: lines shared then would stay held until the next run
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	multiSSH3.run_command_on_hosts(hosts="mock-a", commands=["true"], no_start=True, called=True,
		return_unfinished=True, will_update_unreachable_hosts=False, no_history=True)

	assert multiSSH3._shared_lines_state["sharing"] is False
	_read("a", ALIKE)
	assert multiSSH3._shared_lines == {}


def test_lines_read_after_a_run_ended_are_not_held():
	# readers given up at the end of a run (a process left in the background) may still add lines
	multiSSH3._reset_shared_lines(sharing=False)

	_read("a", ALIKE)

	assert multiSSH3._shared_lines == {}


def test_every_command_of_a_run_shares(monkeypatch):
	# a command's end switched sharing off for the next command of the same run
	import subprocess
	real_popen = subprocess.Popen
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: "/dev/null")
	monkeypatch.setattr(multiSSH3, "_binPaths", {"ssh": "/usr/bin/ssh", "sh": "/bin/sh"})
	monkeypatch.setattr(multiSSH3.subprocess, "Popen",
		lambda command, **kwargs: real_popen(["sh", "-c", "yes 'the same line' | head -n 3000"], **kwargs))

	hosts = multiSSH3.run_command_on_hosts(hosts="mock-[a-b]", commands=["first", "second"], no_watch=True, quiet=True,
		no_history=True, called=True, return_unfinished=False, will_update_unreachable_hosts=False)

	assert len(hosts) == 4
	for first, second in (hosts[:2], hosts[2:]):
		assert first.stdout == second.stdout == ["the same line"] * 3000
		assert all(mine is theirs for mine, theirs in zip(first.stdout, second.stdout))


def test_free_threaded_python_shares_nothing(monkeypatch):
	# every reader thread using one dict made them wait for each other: 200 hosts x 20,000 lines alike
	# took 4.85 s instead of 0.58 s on 3.13t
	monkeypatch.setattr(multiSSH3.sys, "_is_gil_enabled", lambda: False, raising=False)
	multiSSH3._reset_shared_lines()

	assert multiSSH3._shared_lines_state["sharing"] is False
	_read("a", ALIKE)
	assert multiSSH3._shared_lines == {}
