'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import os

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
	# the reason line every shell shows under the prompt
	assert 'R ⚠ gpu017: unknown host — did you mean gpu17?\n' in text
	assert '\nR ' not in mc.format_response(mc.Response(None), nul=False).decode()


def unavailable(engine, *hosts, boot='boot-a', left=300):
	'''mssh's unavailable_hosts.csv, as a run that failed on hosts writes it.'''
	expiry = int(mc.time.monotonic()) + left
	with open(os.path.join(engine.directory, 'unavailable_hosts.csv'), 'w') as f:
		f.write('#boot_id,{}\n'.format(boot) + ''.join('{},{}\n'.format(host, expiry) for host in hosts))


@pytest.fixture
def skipping(engine):
	'''Skipping unreachable hosts on by default, as mssh ships.'''
	engine.flag_sets, engine.flag_defaults = mc.flag_settings(multiSSH3.get_parser())
	engine.flag_defaults['skip_unreachable'] = True
	return engine


@pytest.mark.parametrize('options, message', [
	('', 'node05: will be skipped — unreachable in a recent mssh run'),
	('-nsu ', 'node05: unreachable in a recent mssh run'),
	# --script skips unreachable hosts whatever else is given
	('--script -nsu ', 'node05: will be skipped — unreachable in a recent mssh run'),
])
def test_a_host_that_failed_in_a_recent_run(skipping, options, message):
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh {}node05 uptime'.format(options))[0] == [('node05', 'unreachable', message)]


def test_when_skipping_is_off_by_default_only_su_skips(skipping):
	skipping.flag_defaults['skip_unreachable'] = False
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh node05 uptime')[0][0][2] == 'node05: unreachable in a recent mssh run'
	assert warnings(skipping, 'mssh -su node05 uptime')[0][0][2] == 'node05: will be skipped — unreachable in a recent mssh run'


@pytest.mark.parametrize('boot, left', [('boot-b', 300), ('boot-a', -5)], ids=['another_boot', 'expired'])
def test_old_failures_are_forgotten(skipping, boot, left):
	unavailable(skipping, 'node05', boot=boot, left=left)
	assert warnings(skipping, 'mssh node05 uptime')[0] == []


def pinged(engine, host, ping, pinged_ago, answered_ago=None):
	mc.write_host_states(engine.directory, {host: mc.HostState('valid', NOW, ping, NOW - pinged_ago, 0.0 if answered_ago is None else NOW - answered_ago)})


def test_a_host_that_stopped_answering_ping(skipping):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=240)
	assert warnings(skipping, 'mssh login1 uptime') == ([('login1', 'unreachable', 'login1: no answer to ping (answered 4 min ago)')], False)


@pytest.mark.parametrize('pinged_ago, answered_ago', [
	(10, None),   # never answered: ping may be blocked, ssh may still work
	(10, 700),    # answered longer ago than the ping expiry (600 s)
	(90, 120),    # the silent ping is older than a minute: asked again
])
def test_ping_silence_alone_says_nothing(skipping, pinged_ago, answered_ago):
	pinged(skipping, 'login1', 'silent', pinged_ago, answered_ago)
	assert warnings(skipping, 'mssh login1 uptime')[0] == []


def test_the_ping_expiry_follows_mssh_or_the_environment(skipping, monkeypatch):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=700)
	monkeypatch.setenv('MSSH_COMPLETE_PING_TTL', '900')
	assert warnings(skipping, 'mssh login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'
	monkeypatch.delenv('MSSH_COMPLETE_PING_TTL')
	# -uhe on the line is mssh's expiry for this run
	assert warnings(skipping, 'mssh -uhe 900 login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'


def test_unreachable_members_of_a_range(skipping):
	unavailable(skipping, 'node03')
	mc.write_host_states(skipping.directory, {'node07': mc.HostState('valid', NOW, 'silent', NOW - 5, NOW - 60)})
	assert warnings(skipping, 'mssh node[01-08] uptime')[0] == [('node[01-08]', 'unreachable', 'node[01-08]: 2 unreachable (node03, node07)')]


def test_an_unknown_host_is_not_also_unreachable(skipping):
	seed(skipping, gpu017='invalid')
	unavailable(skipping, 'gpu017')
	assert [kind for _, kind, _ in warnings(skipping, 'mssh gpu017 uptime')[0]] == ['unknown']


def test_options_of_one_exclusive_group(skipping):
	assert warnings(skipping, 'mssh -su -nsu node01 uptime')[0] == [('-nsu', 'options', '-nsu cannot be used with -su (mssh stops with an error)')]
	# the same option twice is allowed
	assert warnings(skipping, 'mssh -su -su node01 uptime')[0] == []


def test_an_option_given_twice(engine):
	assert warnings(engine, 'mssh -u admin -u=root node01 uptime')[0] == [('-u', 'options', '-u given twice: mssh uses root')]
	assert warnings(engine, 'mssh -u root -u root node01 uptime')[0] == []
	# a password never shows
	assert warnings(engine, 'mssh -p one --password=two node01 uptime')[0] == [('-p', 'options', '-p given twice: mssh uses the last one')]
	# the second value is still being typed
	assert warnings(engine, 'mssh -u admin -u ro')[0] == []


@pytest.fixture
def no_effect(skipping):
	skipping.no_effect = [(option, kind, tuple(others), why) for option, kind, others, why in multiSSH3.OPTION_NO_EFFECT]
	skipping.flag_defaults['ipmi'] = False
	return skipping


@pytest.mark.parametrize('line, expected', [
	('mssh --script -nsu node01 true', [('-nsu', 'options', '-nsu does nothing: --script skips unreachable hosts anyway')]),
	('mssh -iu admin node01 true', [('-iu', 'options', '-iu does nothing: only used with --ipmi')]),
	('mssh -M -iu admin node01 true', []),
	('mssh -iu admin --generate_config_file node01 true', []),
	# the message names the option, never the value given with it
	('mssh -ip=secret node01 true', [('-ip=secret', 'options', '-ip does nothing: only used with --ipmi')]),
])
def test_options_that_do_nothing_here(no_effect, line, expected):
	assert warnings(no_effect, line)[0] == expected


def test_settings_used_by_default_are_not_flagged(no_effect):
	# the mssh config turns --ipmi on
	no_effect.flag_defaults['ipmi'] = True
	assert warnings(no_effect, 'mssh -iu admin node01 true')[0] == []
