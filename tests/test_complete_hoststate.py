'''What the prober learned about hosts (host-state.tsv) and the hosts queries asked about (probe-queue).'''
import os
import stat

import pytest

import mssh_complete as mc

NOW = 1790000000.0


@pytest.fixture
def directory(tmp_path, monkeypatch):
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	return str(tmp_path)


def test_states_survive_a_write_and_a_read(directory):
	states = {
		'node1': mc.HostState('valid', NOW, 'answer', NOW, NOW),
		'gpu017': mc.HostState('invalid', NOW - 5),
		'node9': mc.HostState('unsure', NOW, 'silent', NOW - 1, NOW - 300),
	}
	mc.write_host_states(directory, states)
	again = mc.read_host_states(directory)
	assert {host: (state.validity, state.checked_at, state.ping, state.pinged_at, state.answered_at) for host, state in again.items()} == {
		'node1': ('valid', NOW, 'answer', NOW, NOW),
		'gpu017': ('invalid', NOW - 5, '', 0.0, 0.0),
		'node9': ('unsure', NOW, 'silent', NOW - 1, NOW - 300),
	}
	path = os.path.join(directory, mc.HOST_STATE_NAME)
	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
	assert os.listdir(directory) == [mc.HOST_STATE_NAME]


def test_states_from_another_boot_are_ignored(directory, monkeypatch):
	mc.write_host_states(directory, {'node1': mc.HostState('valid', NOW)})
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-b')
	assert mc.read_host_states(directory) == {}


@pytest.mark.parametrize('content', [
	'',
	'node1\tvalid\t1790000000\t\t0\t0\n',                      # no boot id line: not ours
	'#boot_id,boot-a\nnode1\tmaybe\t1\t\t0\t0\nnode2\tvalid\tx\t\t0\t0\nnode3\tvalid\t1\n',
])
def test_foreign_or_broken_lines_are_skipped(directory, content):
	with open(os.path.join(directory, mc.HOST_STATE_NAME), 'w') as f:
		f.write(content)
	assert mc.read_host_states(directory) == {}


@pytest.mark.parametrize('state, age, validity, ping', [
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 30, 'valid', 'answer'),
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 90, 'valid', ''),
	(mc.HostState('invalid', NOW), 599, 'invalid', ''),
	(mc.HostState('invalid', NOW), 601, '', ''),
	(mc.HostState('unsure', NOW, 'none', NOW), 59, 'unsure', 'none'),
	(mc.HostState('unsure', NOW, 'none', NOW), 61, '', ''),
])
def test_answers_stay_fresh_for_their_time(state, age, validity, ping):
	assert (state.fresh_validity(NOW + age), state.fresh_ping(NOW + age)) == (validity, ping)


@pytest.mark.parametrize('state, age, needed', [
	(None, 0, True),
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 30, False),
	# the ping is old: ping again
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 90, True),
	# a host that does not exist is not pinged
	(mc.HostState('invalid', NOW), 90, False),
	# could not ping (no ping command): that is an answer too, until it is old
	(mc.HostState('unsure', NOW, 'none', NOW), 30, False),
])
def test_which_hosts_the_prober_must_look_at(state, age, needed):
	assert mc.needs_probe(state, NOW + age) is needed


def test_the_queue_hands_out_hosts_newest_first_once(directory):
	mc.queue_probes(directory, ['node1', 'node2'])
	mc.queue_probes(directory, ['node3', 'bad\thost', 'esc\x1bhost', ''])
	assert mc.take_probe_queue(directory) == ['node3', 'node2', 'node1']
	assert mc.take_probe_queue(directory) == []


def test_a_host_already_queued_is_not_queued_again(directory):
	# a query for a long range repeats on every keystroke
	mc.queue_probes(directory, ['node1', 'node2'])
	mc.queue_probes(directory, ['node2', 'node3', 'node3'])
	with open(os.path.join(directory, mc.PROBE_QUEUE_NAME)) as f:
		assert f.read().split() == ['node1', 'node2', 'node3']


DAY = 86400.0


def test_states_nothing_can_use_any_more_are_dropped():
	states = {
		# no fresh result and never answered ping: as good as never checked
		'typo1': mc.HostState('invalid', NOW - 601),
		'quiet1': mc.HostState('valid', NOW - 700, 'silent', NOW - 61, 0.0),
		'noping1': mc.HostState('unsure', NOW - 61, 'none', NOW - 61),
		# answered ping, but longer ago than any ping expiry the prober keeps answers for
		'old1': mc.HostState('valid', NOW - DAY - 1, 'answer', NOW - DAY - 1, NOW - DAY - 1),
		'old2': mc.HostState('valid', NOW - 900, 'silent', NOW - 900, NOW - DAY - 1),
	}
	assert mc.prune_host_states(states, NOW, DAY) == {}


def test_states_queries_still_use_are_kept():
	states = {
		'gpu017': mc.HostState('invalid', NOW - 599),                           # unknown host, fresh for 10 minutes
		'node2': mc.HostState('unsure', NOW - 59),                               # unsure, fresh for a minute
		'node3': mc.HostState('valid', NOW - 700, 'silent', NOW - 59, 0.0),      # a fresh ping
		# when a host last answered ping: a silent ping later says "answered N min ago" while that
		# is within the ping expiry, which -uhe on the line can raise up to the horizon
		'node4': mc.HostState('valid', NOW - 700, 'answer', NOW - 700, NOW - 700),
		'node5': mc.HostState('valid', NOW - DAY, 'answer', NOW - DAY, NOW - DAY),
		'node6': mc.HostState('valid', NOW - 900, 'silent', NOW - 900, NOW - 3600),
		# a clock set back: still fresh to the readers
		'node7': mc.HostState('valid', NOW + 300),
	}
	kept = mc.prune_host_states(states, NOW, DAY)
	assert sorted(kept) == sorted(states)
	assert all(kept[host] is states[host] for host in states)


def test_past_the_limit_only_the_latest_answers_are_kept(monkeypatch):
	monkeypatch.setattr(mc, 'ANSWER_ROWS', 2)
	states = {'node{}'.format(number): mc.HostState('valid', NOW - 3600, 'answer', NOW - 3600 + number, NOW - 3600 + number) for number in range(5)}
	# fresh results do not count against the limit: queries use them now
	states['gpu017'] = mc.HostState('invalid', NOW)
	states['node9'] = mc.HostState('valid', NOW - 700, 'silent', NOW - 10, NOW - 7200)
	assert sorted(mc.prune_host_states(states, NOW, DAY)) == ['gpu017', 'node3', 'node4', 'node9']
