'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import os
import types

import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000.0
HOSTS_FILE, HISTORY = mc.SRC_HOSTS_FILE, mc.SRC_HISTORY


def index(tmp_path, hosts, aliases=None, alias_users=None):
	'''
	An index holding hosts (name -> sources) and aliases (name -> members). alias_users (name -> the
	user of each member, '' for none) adds the section for members written user@host; without it the
	index is like one built before that section existed.
	'''
	names = sorted(hosts)
	number = {name: str(position) for position, name in enumerate(names)}
	aliases = aliases or {}
	path = str(tmp_path / 'index.nsv')
	sections = [
		('host_names', [names]),
		('host_meta', [[str(hosts[name]), ''] for name in names]),
		('alias_names', [sorted(aliases)]),
		('aliases', [['env'] + [number[member] for member in aliases[name]] for name in sorted(aliases)]),
	]
	if alias_users is not None:
		sections.append(('alias_users', [alias_users.get(name, []) for name in sorted(aliases)]))
	mc.write_nsv(path, {}, sections)
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


@pytest.mark.parametrize('options', ['--env_files lab.env ', '-ef lab.env ', '--host_file lab.hosts ', '--config_file lab.json '])
def test_a_line_with_its_own_lookup_files_calls_no_host_unknown(engine, options):
	# mssh reads those files at Enter, from the shell's directory: the prober cannot see what they define
	seed(engine, LABGPUS='invalid', gpu017='invalid')
	assert warnings(engine, 'mssh {}LABGPUS,gpu017 uptime'.format(options))[0] == []


@pytest.mark.parametrize('word', ['LABGPUS', 'root@LABGPUS'])
def test_a_variable_of_the_shell_is_not_an_unknown_host(engine, monkeypatch, word):
	# mssh expands an exported variable named by the hosts word; the prober may run with another environment
	monkeypatch.setenv('LABGPUS', 'node01,node02')
	seed(engine, LABGPUS='invalid')
	assert warnings(engine, 'mssh {} uptime'.format(word))[0] == []


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
	# nor pending: the prober was not asked
	assert warnings(engine, 'mssh login1 uptime', probe=False) == ([], False)
	assert mc.take_probe_queue(engine.directory) == [] and engine.started == []


def test_without_a_runtime_directory_nothing_is_pending(engine, monkeypatch):
	# no prober can be asked: asking again could only bring the same answer
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	engine.directory = None
	assert warnings(engine, 'mssh login1 uptime') == ([], False)
	response = engine.query(mc.Request('bash', 'mssh login1 uptime', '', '', flags={'diag': '1'}))
	assert 'pending' not in response.directives and engine.started == []


def test_hosts_that_cannot_be_queued_are_not_pending(engine, monkeypatch):
	# a name with a control character is never queued
	assert warnings(engine, "mssh $'gpu\\x01x' uptime") == ([], False)
	def full(directory, hosts):
		raise OSError(28, 'No space left on device')
	monkeypatch.setattr(mc, 'queue_probes', full)
	assert warnings(engine, 'mssh login1 uptime') == ([], False)


def test_hosts_left_to_a_prober_already_running_are_pending(engine, monkeypatch):
	# the running prober holds the lock and takes the queue; a host still waiting in it stays pending
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: False)
	assert warnings(engine, 'mssh login1 uptime') == ([], True)
	assert warnings(engine, 'mssh login1 uptime') == ([], True)
	assert mc.take_probe_queue(engine.directory) == ['login1']


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
	# pending: the members up to the limit without an answer wait in the probe queue
	assert warnings(engine, 'mssh host[1-100000] uptime') == ([(
		'host[1-100000]', 'range', 'host[1-100000]: 1 of 100000 checked, 1 unknown so far')], True)
	assert sorted(mc.take_probe_queue(engine.directory)) == ['host2', 'host3', 'host4']


@pytest.mark.parametrize('text', [
	'node[1-16]', 'node[01-3]', 'rack[1-4]-n[01-12]', 'n[1-9][1-12]', 'n[8-12]x[1-3]', 'n[1-2,01-02]',
	# names made twice: mssh's expansion is a set
	'n[1-11][1-11]', 'n[1-11][0-10]', 'node[1-2,1-2]', 'n[1-3,2-4,7]',
])
def test_range_members_are_the_names_mssh_makes(text):
	expanded = getattr(multiSSH3, '__expand_hostname')(text, validate=False)
	members = list(mc._iter_range(text))
	assert len(members) == len(set(members)) and set(members) == expanded
	assert mc._range_count(text) == len(expanded)


def test_a_host_a_range_makes_twice_counts_once(engine):
	# n[1-11][1-11] makes n111 from 1 and 11, and from 11 and 1: mssh runs on 120 hosts, n111 once
	names = {'n{}{}'.format(first, second) for first in range(1, 12) for second in range(1, 12)}
	seed(engine, **dict({name: 'valid' for name in names}, n111='invalid'))
	assert warnings(engine, 'mssh n[1-11][1-11] uptime')[0] == [(
		'n[1-11][1-11]', 'range', 'n[1-11][1-11]: 1 of 120 hosts unknown (n111)')]


def test_a_host_an_alias_lists_twice_counts_once(engine, tmp_path):
	# an alias of a@ghost1,b@ghost1 lists ghost1 for each user; mssh checks the name once
	(tmp_path / 'pair').mkdir()
	engine.hosts = mc.HostTable(index(tmp_path / 'pair', {'ghost1': mc.SRC_ALIAS, 'node01': HOSTS_FILE}, {'pair': ['ghost1', 'node01', 'ghost1']}))
	seed(engine, ghost1='invalid')
	assert warnings(engine, 'mssh pair uptime')[0] == [('pair', 'range', 'pair: 1 of 2 hosts unknown (ghost1)')]


def test_a_range_whose_names_cannot_repeat_is_counted_without_expanding_it(monkeypatch):
	def expand(text):
		raise AssertionError('expanded ' + text)
	monkeypatch.setattr(mc, '_range_names', expand)
	# one width before the next range, or a separator that is not a digit: each name splits one way
	assert mc._range_count('n[1-9][1-100000]') == 900000
	assert mc._range_count('rack[1-1000]-node[1-1000]') == 1000000
	assert mc._range_count('node[1-100000]') == 100000


def test_a_range_whose_names_may_repeat_is_counted_up_to_a_limit(engine, monkeypatch):
	# counting n[1-11][1-11]'s hosts expands its 121 names; past RANGE_COUNT_LIMIT nothing is said
	monkeypatch.setattr(mc, 'RANGE_COUNT_LIMIT', 121)
	assert mc._range_count('n[1-11][1-11]') == 120
	monkeypatch.setattr(mc, 'RANGE_COUNT_LIMIT', 120)
	assert mc._range_count('n[1-11][1-11]') is None
	seed(engine, n111='invalid')
	assert warnings(engine, 'mssh n[1-11][1-11] uptime')[0] == []


def test_a_bracket_inside_a_range_says_nothing_about_it(engine):
	# mssh makes one name of it (a[bc[1-2]]); expanding it here used to fail and drop every warning of the line
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017,a[[b]c[1-2]] uptime')[0] == [('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]


def test_ipv4_ranges_hold_only_addresses(engine):
	# mssh's IPv4 range syntax: ranges, x, * or ? in an octet (found replaying real history)
	assert warnings(engine, 'mssh 127.0.0.1-20,10.0.[1-2].x,10.1.1.* uptime')[0] == []


def test_members_of_an_ipv4_range_are_pinged(engine):
	# addresses need no DNS: they are queued for the prober's ping, as members of other ranges are
	assert warnings(engine, 'mssh 10.0.0.1-3 uptime') == ([], True)
	assert sorted(mc.take_probe_queue(engine.directory)) == ['10.0.0.1', '10.0.0.2', '10.0.0.3']


@pytest.mark.parametrize('pattern', ['192.168.1.1-254', '10.0.[1-2].x', '10.1.1.*', '127.0.0.1-20', '10.0.x-1.?', '[10-11].0.0.5'])
def test_ipv4_ranges_expand_as_mssh_expands_them(pattern):
	members, total = mc._ipv4_members(pattern, limit=100000)
	expanded = getattr(multiSSH3, '__expandIPv4Address')(frozenset([pattern]))
	assert sorted(members) == sorted(expanded) and total == len(expanded)
	# past the limit the total is still counted
	assert mc._ipv4_members(pattern, limit=5) == (members[:5], total)


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


@pytest.mark.parametrize('options', ['--ipmi ', '-su --ipmi ', '--script --ipmi '])
def test_with_ipmi_unreachable_hosts_are_not_skipped(skipping, options):
	# mssh skips them only without --ipmi: powering on a host that is down is what --ipmi is for
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh {}node05 power on'.format(options))[0] == [('node05', 'unreachable', 'node05: unreachable in a recent mssh run')]


def test_with_ipmi_on_by_default_unreachable_hosts_are_not_skipped(skipping):
	skipping.flag_defaults['ipmi'] = True
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh node05 power on')[0][0][2] == 'node05: unreachable in a recent mssh run'


@pytest.mark.parametrize('boot, left', [('boot-b', 300), ('boot-a', -5)], ids=['another_boot', 'expired'])
def test_old_failures_are_forgotten(skipping, boot, left):
	unavailable(skipping, 'node05', boot=boot, left=left)
	assert warnings(skipping, 'mssh node05 uptime')[0] == []


def pinged(engine, host, ping, pinged_ago, answered_ago=None):
	mc.write_host_states(engine.directory, {host: mc.HostState('valid', NOW, ping, NOW - pinged_ago, 0.0 if answered_ago is None else NOW - answered_ago)})


def test_a_host_that_stopped_answering_ping(skipping):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=240)
	assert warnings(skipping, 'mssh login1 uptime') == ([('login1', 'unreachable', 'login1: no answer to ping (answered 4 min ago)')], False)
	# ping is the same for every user
	assert warnings(skipping, 'mssh -u root admin@login1 uptime')[0] == [('admin@login1', 'unreachable', 'login1: no answer to ping (answered 4 min ago)')]


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


def test_states_the_prober_drops_change_no_warning(skipping, monkeypatch):
	'''
	What prune_host_states leaves out changes nothing: not the warnings or the hosts asked about
	now, nor after the prober pinged the hosts again and found them silent (it keeps when a host
	last answered), for a ping expiry up to the horizon.
	'''
	import random
	day = mc.ANSWER_KEEP
	ages = [0, 30, 59, 61, 300, 599, 601, 3600, day - 1, day + 1, 2 * day]
	hosts = ['node{:02d}'.format(number) for number in range(1, 17)] + ['login1', 'db1', 'nodex1', 'gpu17', 'gpu017']
	words = 'node[01-16],login1,db1,nodex1,gpu17,gpu017 uptime '
	lines = ['mssh ' + words] + ['mssh -uhe {} '.format(expiry) + words for expiry in (60, 600, 3600, int(day))]
	verdicts = {'gpu017': 'invalid'}
	fake_mssh = types.SimpleNamespace(host_validity=lambda host, timeout=2.0: verdicts.get(host, 'valid'))
	monkeypatch.setattr(mc, 'ping_host', lambda host: 'silent')

	def copied(states):
		return {host: mc.HostState(state.validity, state.checked_at, state.ping, state.pinged_at, state.answered_at) for host, state in states.items()}

	def said(states, line, now):
		'''The warnings, and the hosts the query asks the prober about.'''
		found, _ = skipping.diagnose(mc.Request('bash', line, '', ''), now=now, states=states)
		return [(item.start, item.end, item.kind, item.message) for item in found], sorted(mc.take_probe_queue(skipping.directory))

	rng = random.Random(7)
	changed = 0
	for _ in range(40):
		states = {}
		for host in hosts:
			if rng.random() < 0.15:
				continue
			ping = rng.choice(['', 'answer', 'silent', 'none'])
			pinged = NOW - rng.choice(ages) if ping else 0.0
			answered = pinged if ping == 'answer' else rng.choice([0.0, pinged - rng.choice(ages)])
			states[host] = mc.HostState(rng.choice(['valid', 'invalid', 'unsure']), NOW - rng.choice(ages), ping, pinged, answered)
		pruned = mc.prune_host_states(states, NOW, day)
		changed += len(pruned) < len(states)
		for later in (0, 45, 90, 700, 3600, day / 2, day):
			now = NOW + later
			full, cut = copied(states), copied(pruned)
			for line in lines:
				assert said(full, line, now) == said(cut, line, now)
			# the prober looks at what the line asks for, from what it has (a dropped host starts afresh)
			for known in (full, cut):
				mc._probe_batch(fake_mssh, [host for host in hosts if mc.needs_probe(known.get(host), now)], known, lambda: now, [True])
			for line in lines:
				assert said(full, line, now + 5) == said(cut, line, now + 5)
	# the cases dropped states
	assert changed > 20


def test_unreachable_members_of_a_range(skipping):
	unavailable(skipping, 'node03')
	mc.write_host_states(skipping.directory, {'node07': mc.HostState('valid', NOW, 'silent', NOW - 5, NOW - 60)})
	assert warnings(skipping, 'mssh node[01-08] uptime')[0] == [('node[01-08]', 'unreachable', 'node[01-08]: 2 unreachable (node03, node07)')]


@pytest.mark.parametrize('pattern, down', [
	('192.168.1.1-254', ['192.168.1.5', '192.168.1.9']),
	('10.0.[1-2].x', ['10.0.2.7']),
])
def test_unreachable_members_of_an_ipv4_range(skipping, pattern, down):
	unavailable(skipping, *down)
	assert warnings(skipping, 'mssh {} uptime'.format(pattern))[0] == [
		(pattern, 'unreachable', '{}: {} unreachable ({})'.format(pattern, len(down), ', '.join(down)))]


def test_an_unknown_host_is_not_also_unreachable(skipping):
	seed(skipping, gpu017='invalid')
	unavailable(skipping, 'gpu017')
	assert [kind for _, kind, _ in warnings(skipping, 'mssh gpu017 uptime')[0]] == ['unknown']


# mssh records a failure under the name the run gave the host, user@host when a user applies (typed
# or -u) and the bare name otherwise, and skips a host only when that very name is recorded

def test_a_failure_recorded_for_user_at_host(skipping):
	unavailable(skipping, 'root@node05')
	assert warnings(skipping, 'mssh root@node05 uptime')[0] == [('root@node05', 'unreachable', 'node05: will be skipped — unreachable in a recent mssh run')]
	# without a user, or with another one, it is another name: mssh runs it
	assert warnings(skipping, 'mssh node05 uptime')[0] == []
	assert warnings(skipping, 'mssh admin@node05 uptime')[0] == []


@pytest.mark.parametrize('options', ['-u root ', '-u=root ', '-uroot ', '--username root ', '--username=root '])
def test_u_gives_the_hosts_its_user(skipping, options):
	unavailable(skipping, 'root@node05')
	assert warnings(skipping, 'mssh {}node05 uptime'.format(options))[0] == [('node05', 'unreachable', 'node05: will be skipped — unreachable in a recent mssh run')]


def test_a_user_typed_with_the_host_wins_over_u(skipping):
	unavailable(skipping, 'root@node05')
	assert warnings(skipping, 'mssh -u admin root@node05 uptime')[0] == [('root@node05', 'unreachable', 'node05: will be skipped — unreachable in a recent mssh run')]
	assert warnings(skipping, 'mssh -u root admin@node05 uptime')[0] == []


def test_the_user_from_the_mssh_config_is_the_default_of_u(skipping, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_USERNAME', 'root')
	skipping.spec = mc.spec_from_parser(multiSSH3.get_parser())
	unavailable(skipping, 'root@node05')
	assert warnings(skipping, 'mssh node05 uptime')[0] == [('node05', 'unreachable', 'node05: will be skipped — unreachable in a recent mssh run')]
	assert warnings(skipping, 'mssh -u admin node05 uptime')[0] == []


@pytest.mark.parametrize('line', ['mssh root@node05 uptime', 'mssh -u root node05 uptime'])
def test_a_failure_without_a_user_does_not_skip_user_at_host(skipping, line):
	# the run that failed was the current user's: mssh tries root@node05
	unavailable(skipping, 'node05')
	assert warnings(skipping, line)[0] == []


@pytest.mark.parametrize('line, word', [
	('mssh root@node[01-08] uptime', 'root@node[01-08]'),
	('mssh -u root node[01-08] uptime', 'node[01-08]'),
])
def test_unreachable_members_of_a_range_with_a_user(skipping, line, word):
	# mssh runs root@node03 ... root@node07: node07 failed without the user
	unavailable(skipping, 'root@node03', 'node07')
	assert warnings(skipping, line)[0] == [(word, 'unreachable', 'node[01-08]: 1 unreachable (node03)')]


@pytest.mark.parametrize('line, word', [('mssh root@all uptime', 'root@all'), ('mssh -u root all uptime', 'all')])
def test_unreachable_members_of_an_alias_with_a_user(skipping, line, word):
	unavailable(skipping, 'root@node01', 'ghost1')
	assert warnings(skipping, line)[0] == [(word, 'unreachable', 'all: 1 unreachable (node01)')]


@pytest.mark.parametrize('line, failed, down', [
	('mssh dbs uptime', ['postgres@db1'], 'db1'),
	('mssh dbs uptime', ['db1'], None),
	# a member written with its user keeps it, -u is for the others
	('mssh -u root dbs uptime', ['postgres@db1', 'root@node02'], 'db1, node02'),
	('mssh -u root dbs uptime', ['root@db1'], None),
	# a user typed with the alias goes in front of the member's: mssh runs root@postgres@db1
	('mssh root@dbs uptime', ['root@postgres@db1'], 'db1'),
	('mssh root@dbs uptime', ['root@db1'], None),
])
def test_unreachable_members_of_an_alias_written_with_users(skipping, tmp_path, line, failed, down):
	# dbs=postgres@db1,node02 in an env file
	hosts = {'db1': mc.SRC_ALIAS, 'node02': HOSTS_FILE}
	skipping.hosts = mc.HostTable(index(tmp_path, hosts, {'dbs': ['db1', 'node02']}, {'dbs': ['postgres', '']}))
	unavailable(skipping, *failed)
	word = line.split()[-2]
	expected = [(word, 'unreachable', 'dbs: {} unreachable ({})'.format(len(down.split(', ')), down))] if down else []
	assert warnings(skipping, line)[0] == expected


@pytest.mark.parametrize('failed', [['a@node1'], ['b@node1'], ['a@node1', 'b@node1']])
def test_an_alias_listing_a_host_for_two_users_counts_the_host_once(skipping, tmp_path, failed):
	# pair=a@node1,b@node1: mssh runs two names (either can be skipped), the warning counts one host
	skipping.hosts = mc.HostTable(index(tmp_path, {'node1': HOSTS_FILE}, {'pair': ['node1', 'node1']}, {'pair': ['a', 'b']}))
	unavailable(skipping, *failed)
	assert warnings(skipping, 'mssh pair uptime')[0] == [('pair', 'unreachable', 'pair: 1 unreachable (node1)')]


def test_an_alias_listing_a_host_for_two_users_counts_it_once_as_unknown(skipping, tmp_path):
	seed(skipping, node1='invalid')
	skipping.hosts = mc.HostTable(index(tmp_path, {'node1': HISTORY}, {'pair': ['node1', 'node1']}, {'pair': ['a', 'b']}))
	assert warnings(skipping, 'mssh pair uptime')[0] == [('pair', 'range', 'pair: 1 of 1 hosts unknown (node1)')]


@pytest.mark.parametrize('line', [
	'mssh root@node05 uptime',
	'mssh -u root node05 uptime',
	'mssh -u admin root@node05 uptime',
	'mssh root@node[04-05] uptime',
	'mssh -u root node[04-05] uptime',
	'mssh dbs uptime',
	'mssh -u root dbs uptime',
	'mssh root@dbs uptime',
])
def test_warnings_follow_what_mssh_skips(skipping, monkeypatch, tmp_path, line):
	# mssh itself (run_command_on_hosts, nothing started) decides which hosts it skips for each recorded name
	monkeypatch.setattr(multiSSH3, '_resolve_dns', lambda hostname: '10.9.9.9')
	monkeypatch.setattr(multiSSH3, '_env_files', [str(tmp_path / 'none.env')])
	monkeypatch.setattr(multiSSH3, '_get_boot_id', lambda: 'boot-a')
	monkeypatch.setattr(multiSSH3, '_unavailable_hosts_file_path', lambda create=True: os.path.join(skipping.directory, 'unavailable_hosts.csv'))
	monkeypatch.setenv('dbs', 'postgres@node04,node05')
	multiSSH3.getIP.cache_clear()
	# the index as build_index makes it
	_, members, users = mc.collect_aliases(multiSSH3, {'dbs'}, set())['dbs']
	hosts = {'node04': HOSTS_FILE, 'node05': HOSTS_FILE}
	skipping.hosts = mc.HostTable(index(tmp_path, hosts, {'dbs': members}, {'dbs': users}))
	words = line.split()
	word = words[-2]
	def mssh_runs():
		multiSSH3.__globalUnavailableHosts.clear()
		# mssh returns the hosts it skips too, marked skipped (they fail the run): those it does not run
		return {host.name for host in multiSSH3.run_command_on_hosts(hosts=word, commands=['true'],
			username=words[2] if words[1] == '-u' else None, no_start=True, no_watch=True, quiet=True,
			no_history=True, called=True, will_update_unreachable_hosts=False) if not host.skipped}
	unavailable(skipping)
	every = mssh_runs()
	skips = 0
	try:
		for recorded in [user + host for host in ('node04', 'node05') for user in ('', 'root@', 'admin@', 'postgres@', 'root@postgres@')]:
			unavailable(skipping, recorded)
			skipped = sorted(name.rpartition('@')[2] for name in every - mssh_runs())
			skips += len(skipped)
			if not skipped:
				expected = []
			elif '[' in word or 'dbs' in word:
				expected = [(word, 'unreachable', '{}: 1 unreachable ({})'.format(word.rpartition('@')[2], skipped[0]))]
			else:
				expected = [(word, 'unreachable', '{}: will be skipped — unreachable in a recent mssh run'.format(skipped[0]))]
			assert (recorded, warnings(skipping, line)[0]) == (recorded, expected)
	finally:
		multiSSH3.getIP.cache_clear()
	# each name mssh runs was recorded once, alone
	assert skips == len(every) > 0


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
