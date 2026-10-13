'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import os
import random
import shutil
import subprocess

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


class AllUnknown(object):
	'''Host states saying the prober just found every host it was asked about unknown.'''
	def get(self, host):
		return mc.HostState('invalid', NOW)


def warnings_if_all_unknown(engine, line, shell='bash'):
	'''The warnings for line if every host the engine asks about turned out unknown.'''
	found, _ = engine.diagnose(mc.Request(shell, line, '', ''), now=NOW, states=AllUnknown())
	return [(line[item.start:item.end], item.kind, item.message) for item in found]


@pytest.mark.parametrize('line', [
	'mssh $NODES nvidia-smi',                 # NODES=gpu[01-16], a variable of the shell only
	'mssh ${NODES} nvidia-smi',
	'mssh "$NODES" nvidia-smi',
	'mssh root@$NODES nvidia-smi',
	'mssh ${NODES:-gpu[01-16],login1} nvidia-smi',
	'mssh $(cat hosts.txt) uptime',
	'mssh "$(cat hosts.txt)" uptime',
	'mssh `cat hosts.txt` uptime',
	'mssh $((1+2)) uptime',
	'mssh ~ uptime',                          # tilde expansion
	'mssh ~admin uptime',
	'mssh !$ uptime',                         # history expansion: the last word of the line before
])
def test_a_host_word_the_shell_expands_is_not_checked(engine, line):
	# mssh sees what the shell makes of the word, not the word: nothing can be said about it
	assert warnings_if_all_unknown(engine, line) == []
	# and the prober is not asked about pieces of it
	assert warnings(engine, line) == ([], False)
	assert mc.take_probe_queue(engine.directory) == [] and engine.started == []


def test_literal_hosts_next_to_an_expansion_are_still_checked(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh $NODES,gpu017 nvidia-smi')[0] == [('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	assert warnings(engine, 'mssh "$NODES",gpu017 nvidia-smi')[0] == [('"$NODES",gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	assert warnings(engine, 'mssh gpu017,${A:-x,y}z nvidia-smi')[0] == [('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	assert mc.take_probe_queue(engine.directory) == []


@pytest.mark.parametrize('word', ['$USER@gpu017', '${USER}@gpu017', '"$USER"@gpu017', '`whoami`@gpu017'])
def test_a_user_the_shell_expands_leaves_the_host_checked(engine, word):
	# the shell rewrites only the user: mssh still gets gpu017
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh {} uptime'.format(word))[0] == [(word, 'unknown', 'gpu017: unknown host — did you mean gpu17?')]


def test_a_host_under_a_user_the_shell_makes_is_not_called_unreachable(skipping):
	# mssh skips unreachable hosts by the name it runs them under, user@ included: not known here
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh $USER@node05 uptime') == ([], True)
	# the host itself is still checked
	assert mc.take_probe_queue(skipping.directory) == ['node05']


@pytest.mark.parametrize('word', ['$USER@$HOST', 'root@$NODES', '${A:-x@y}', 'u@${A:-x@y}'])
def test_a_host_the_shell_expands_after_a_user_is_not_checked(engine, word):
	assert warnings_if_all_unknown(engine, 'mssh {} uptime'.format(word)) == []


@pytest.mark.parametrize('raw, how', [
	('a"$b"\\$c\'$d\'', 'uddlull'),
	("$'\\x41$'x", 'llu'),
	('"a\\"b"', 'dld'),
	("'open", 'llll'),
])
def test_quoting_says_how_each_character_was_typed(raw, how):
	assert ''.join(mark for mark, _ in mc._quoting(raw)) == how


def test_quoting_reads_words_as_lex_does():
	rng = random.Random(2005)
	pieces = ['a', ',', '$', "'", '"', '\\', '{', '}', '(', '`', '~', '!', ' ', '\n', "$'", '\\x41', '\\n', '..']
	for _ in range(5000):
		line = ''.join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
		for token in mc.lex(line):
			assert len(mc._quoting(token.raw)) == len(token.text), line


@pytest.mark.parametrize('line, message', [
	# the shell passes these as typed; mssh drops the $ and looks the name up in its environment
	("mssh '$NODES' uptime", 'NODES: unknown host'),
	('mssh \\$NODES uptime', 'NODES: unknown host'),
	("mssh '${NODES}' uptime", '{NODES}: unknown host'),
	("mssh $'$NODES' uptime", 'NODES: unknown host'),
	('mssh node$ uptime', 'node: unknown host'),
	# no brace expansion in quotes: mssh splits node{1,2} at its comma
	('mssh "node{1,2}" uptime', 'node{1: unknown host'),
	# an unmatched glob reaches mssh as typed (mssh takes [ ], * and ? in ranges)
	('mssh node* uptime', 'node*: unknown host'),
])
def test_text_the_shell_leaves_alone_is_checked_as_mssh_reads_it(engine, line, message):
	assert warnings_if_all_unknown(engine, line)[0][2] == message


@pytest.mark.parametrize('shell, line, kinds', [
	('zsh', 'mssh $NODES uptime', []),
	('zsh', 'mssh !$ uptime', []),
	('zsh', 'mssh gpu{01..16} uptime', ['range']),
	('fish', 'mssh $NODES uptime', []),
	('fish', 'mssh (cat hosts.txt) uptime', []),  # fish's command substitution
	('fish', 'mssh node{1,2} uptime', ['range']),
	# fish has no history expansion and no {a..b} sequences
	('fish', 'mssh !$ uptime', ['unknown']),
	('fish', 'mssh gpu{01..16} uptime', ['unknown']),
])
def test_what_the_shell_expands_depends_on_the_shell(engine, shell, line, kinds):
	assert [kind for _, kind, _ in warnings_if_all_unknown(engine, line, shell)] == kinds


@pytest.mark.parametrize('shell, word, words, second, meant', [
	('bash', 'node{1,2}', 2, 'node2', 'node1,node2'),
	('bash', 'gpu{01..16}', 16, 'gpu02', 'gpu[01-16]'),
	('bash', 'node{1..16}', 16, 'node2', 'node[1-16]'),
	('bash', 'n{001..12}', 12, 'n002', 'n[001-012]'),
	('bash', 'n{10..8}', 3, 'n9', 'n[8-10]'),
	('bash', 'rack[1-2]-n{1..3}', 3, 'rack[1-2]-n2', 'rack[1-2]-n[1-3]'),
	('bash', 'n{a..c}', 3, 'nb', 'na,nb,nc'),
	('bash', 'n{1..10..3}', 4, 'n4', 'n1,n4,n7,n10'),
	('bash', 'n{1,2}-{a,b}', 4, 'n1-b', 'n1-a,n1-b,n2-a,n2-b'),
	('zsh', 'gpu{01..16}', 16, 'gpu02', 'gpu[01-16]'),
	('fish', 'node{1,2}', 2, 'node2', 'node1,node2'),
	# fish varies the first braces fastest
	('fish', 'n{1,2}-{a,b}', 4, 'n2-a', 'n1-a,n2-a,n1-b,n2-b'),
])
def test_braces_the_shell_expands_make_mssh_run_a_host_as_the_command(engine, shell, word, words, second, meant):
	# mssh takes the first word as its hosts and the others as the command
	message = '{}: the shell makes {} words of this; mssh would run {} as the command — did you mean {}?'.format(word, words, second, meant)
	assert warnings_if_all_unknown(engine, 'mssh {} uptime'.format(word), shell) == [(word, 'range', message)]
	# no prober needed
	found, pending = engine.diagnose(mc.Request(shell, 'mssh {} uptime'.format(word), '', ''), now=NOW)
	assert [item.message for item in found] == [message] and not pending
	assert mc.take_probe_queue(engine.directory) == []


@pytest.mark.skipif(shutil.which('bash') is None, reason='needs bash')
@pytest.mark.parametrize('word', ['node{1,2}', 'gpu{01..16}', 'node{1..16}', 'n{001..12}', 'n{10..8}', 'n{010..8}',
	'rack[1-2]-n{1..3}', 'n{a..c}', 'n{1..10..3}', 'n{1,2}-{a,b}', 'a,n{1..3}', 'a,n{1,2}'])
def test_what_a_brace_warning_suggests_gives_mssh_the_hosts_the_shell_made(engine, tmp_path, word):
	message, = [message for _, kind, message in warnings_if_all_unknown(engine, 'mssh {} uptime'.format(word)) if kind == 'range']
	meant = message.rsplit('did you mean ', 1)[1][:-1]
	# in an empty directory: no file names for the shell's globs
	made = subprocess.run(['bash', '-c', 'printf "%s\\n" ' + word], cwd=str(tmp_path), stdout=subprocess.PIPE,
		universal_newlines=True, check=True).stdout.split()
	assert len(made) > 1
	assert sorted(multiSSH3.expand_hostnames_local([meant])[0]) == sorted(multiSSH3.expand_hostnames_local(made)[0])


def test_a_brace_warning_lists_the_hosts_beside_the_braces_once(engine):
	# login1 is also checked on its own
	assert warnings_if_all_unknown(engine, 'mssh login1,n{1,2} uptime') == [('login1', 'unknown', 'login1: unknown host'), ('login1,n{1,2}', 'range',
		'login1,n{1,2}: the shell makes 2 words of this; mssh would run login1,n2 as the command — did you mean login1,n1,n2?')]


def test_a_brace_warning_without_a_suggestion(engine):
	# quoted text in the braces: what to type instead is not worked out
	assert warnings_if_all_unknown(engine, 'mssh n{1,"2"} uptime') == [
		('n{1,"2"}', 'range', 'n{1,"2"}: the shell makes 2 words of this; mssh would run n2 as the command')]
	# too many hosts to list
	word = 'n{' + ','.join(str(number) for number in range(1, 21)) + '}'
	assert warnings_if_all_unknown(engine, 'mssh {} uptime'.format(word)) == [
		(word, 'range', '{}: the shell makes 20 words of this; mssh would run n2 as the command'.format(word))]


@pytest.mark.parametrize('line', [
	'mssh node{1..1} uptime',     # one word
	'mssh {,node1} uptime',       # the shell drops the empty word: one word
	'mssh n{1,{2,3}} uptime',     # nested: not worked out
	'mssh {2..{1..3}} uptime',     # braces the shell leaves around expanded ones: not worked out
	'mssh n{1,2}',                # still being typed
])
def test_no_brace_warning_without_a_second_word(engine, line):
	assert warnings_if_all_unknown(engine, line) == []


def test_braces_the_shell_leaves_alone_are_checked_as_hosts(engine):
	assert warnings_if_all_unknown(engine, 'mssh node{1} uptime') == [('node{1}', 'unknown', 'node{1}: unknown host')]
	assert warnings_if_all_unknown(engine, 'mssh "node{1,2}" uptime')[0][:2] == ('"node{1,2}"', 'unknown')
	# no sequence bash knows: as typed (zsh makes a range of characters of it)
	assert warnings_if_all_unknown(engine, 'mssh n{1..a} uptime') == [('n{1..a}', 'unknown', 'n{1..a}: unknown host')]
	assert [kind for _, kind, _ in warnings_if_all_unknown(engine, 'mssh n{1..a} uptime', 'zsh')] == ['range']


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
