'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000.0
HOSTS_FILE, HISTORY = mc.SRC_HOSTS_FILE, mc.SRC_HISTORY


def index(tmp_path, hosts, aliases=None):
	'''An index holding hosts (name -> sources) and aliases (name -> members).'''
	names = sorted(hosts)
	number = {name: str(position) for position, name in enumerate(names)}
	aliases = aliases or {}
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {}, [
		('host_names', [names]),
		('host_meta', [[str(hosts[name]), ''] for name in names]),
		('alias_names', [sorted(aliases)]),
		('aliases', [['env'] + [number[member] for member in aliases[name]] for name in sorted(aliases)]),
	])
	return mc.NsvIndex.load(path)


@pytest.fixture
def engine(tmp_path, monkeypatch):
	'''An engine with a runtime directory, a host table and host states; the prober is not started.'''
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)
	started = []
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: started.append(directory) or True)
	directory = tmp_path / 'run'
	directory.mkdir(mode=0o700)
	hosts = {'gpu17': HOSTS_FILE, 'gpu18': HOSTS_FILE, 'login1': HISTORY, 'nodex1': HISTORY, 'nodey1': HISTORY, 'db1': HISTORY, 'ghost1': mc.SRC_ALIAS}
	hosts.update({'node{:02d}'.format(number): HOSTS_FILE for number in range(1, 17)})
	engine = mc.Engine(SPEC, [], mc.HostTable(index(tmp_path, hosts, {'all': ['node01', 'ghost1']})))
	engine.directory = str(directory)
	engine.started = started
	return engine


def seed(engine, **validities):
	mc.write_host_states(engine.directory, {host: mc.HostState(validity, NOW) for host, validity in validities.items()})


def warnings(engine, line, cursor=None, probe=True):
	before, after = line[:cursor], line[cursor:] if cursor is not None else ''
	found, pending = engine.diagnose(mc.Request('bash', before, after, ''), probe=probe, now=NOW)
	return [(line[item.start:item.end], item.kind, item.message) for item in found], pending


def test_an_unknown_host_is_marked_with_the_host_it_was_meant_to_be(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 nvidia-smi') == ([('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')], False)


def test_the_word_being_typed_is_left_alone(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017')[0] == []
	# the cursor back inside it: still being edited
	assert warnings(engine, 'mssh gpu017 nvidia-smi', cursor=8)[0] == []


def test_a_host_without_an_answer_yet_is_queued_for_the_prober(engine):
	assert warnings(engine, 'mssh login1,10.0.0.5,gpu17 uptime') == ([], True)
	# all are pinged; an IP address and a hosts-file name need no DNS (they are valid at once)
	assert mc.take_probe_queue(engine.directory) == ['gpu17', '10.0.0.5', 'login1']
	assert engine.started == [engine.directory]


def test_hosts_with_fresh_answers_are_not_queued(engine):
	mc.write_host_states(engine.directory, {
		'login1': mc.HostState('valid', NOW, 'answer', NOW, NOW), 'gpu17': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	assert warnings(engine, 'mssh login1,gpu17 uptime') == ([], False)
	assert mc.take_probe_queue(engine.directory) == []


def test_without_probe_nothing_is_queued(engine):
	assert warnings(engine, 'mssh login1 uptime', probe=False) == ([], True)
	assert mc.take_probe_queue(engine.directory) == [] and engine.started == []


@pytest.mark.parametrize('typed, meant', [
	('gpu017', 'gpu17'),       # zero padding
	('gpu99', None),           # nothing close
	('login2', 'login1'),      # one substitution
	('lgoin1', 'login1'),      # two letters swapped
	('gp17', 'gpu17'),         # one letter left out
	('nodez1', None),          # nodex1 and nodey1 are equally close
	('db2', None),             # too short to guess from one edit
])
def test_did_you_mean_needs_one_clear_candidate(engine, typed, meant):
	seed(engine, **{typed: 'invalid'})
	message = warnings(engine, 'mssh {} uptime'.format(typed))[0][0][2]
	assert message == typed + ': unknown host' + (' — did you mean {}?'.format(meant) if meant else '')


def test_a_host_known_not_to_exist_is_never_suggested(engine):
	seed(engine, gpu017='invalid', gpu17='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host'


def test_each_host_of_a_list_is_marked_on_its_own(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh root@node01,root@gpu017 uptime')[0] == [('root@gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	# inside quotes the whole word is marked
	assert warnings(engine, 'mssh "node01,gpu017" uptime')[0][0][0] == '"node01,gpu017"'


def test_a_range_with_unknown_members_suggests_the_padded_range(engine):
	seed(engine, **{'node{}'.format(number): 'invalid' for number in range(1, 10)})
	assert warnings(engine, 'mssh node[1-16] uptime')[0] == [(
		'node[1-16]', 'range', 'node[1-16]: 9 of 16 hosts unknown (node1, node2, node3, …) — did you mean node[01-16]?')]


def test_a_range_still_being_checked_says_how_far_it_got(engine):
	seed(engine, gpu5='invalid', gpu6='valid')
	assert warnings(engine, 'mssh gpu[1-8] uptime') == ([('gpu[1-8]', 'range', 'gpu[1-8]: 2 of 8 checked, 1 unknown so far')], True)


def test_an_alias_with_unknown_members(engine):
	seed(engine, ghost1='invalid')
	assert warnings(engine, 'mssh all uptime')[0] == [('all', 'range', 'all: 1 of 2 hosts unknown (ghost1)')]


def test_an_ascii_terminal_gets_ascii_messages(engine, monkeypatch):
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: False)
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host - did you mean gpu17?'


def test_a_range_mssh_completion_cannot_expand_says_nothing(engine):
	# letter ranges: nothing is known about their members
	assert warnings(engine, 'mssh node[a-c] uptime') == ([], False)


def test_a_huge_range_is_checked_up_to_the_member_limit(engine, monkeypatch):
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	seed(engine, host1='invalid')
	assert warnings(engine, 'mssh host[1-100000] uptime', probe=False) == ([(
		'host[1-100000]', 'range', 'host[1-100000]: 1 of 100000 checked, 1 unknown so far')], True)


def test_lines_that_do_not_run_mssh_get_nothing(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'ssh gpu017 uptime') == ([], False)


def test_diag_requests_answer_with_w_records(engine, monkeypatch):
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	seed(engine, gpu017='invalid')
	response = engine.query(mc.Request('bash', 'mssh gpu017,login1 uptime', '', '', flags={'diag': '1'}))
	text = mc.format_response(response, nul=False).decode()
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text
