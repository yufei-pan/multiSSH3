'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import argparse
import contextlib
import io
import os
import random
import shutil
import string
import subprocess
import sys
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


@pytest.mark.parametrize('line', ['mssh -- gpu017 nvidia-smi', 'mssh -u root -- gpu017 nvidia-smi'])
def test_the_hosts_after_double_dash_are_checked(engine, line):
	# "--" ends the options; argparse still reads the next word as the hosts
	seed(engine, gpu017='invalid')
	assert warnings(engine, line)[0] == [('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]


def test_a_command_word_after_double_dash_is_no_host(engine):
	seed(engine, gpu017='invalid', gpu17='valid')
	assert warnings(engine, 'mssh gpu17 -- gpu017 uptime')[0] == []


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


def test_a_sequence_too_long_to_count_in_a_word(engine):
	# more words than len() takes: the other warnings of the line stay
	seed(engine, gpu017='invalid')
	word = 'gpu017,n{1..99999999999999999999}'
	assert warnings(engine, 'mssh {} uptime'.format(word))[0] == [
		('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?'),
		(word, 'range', '{}: the shell makes 99999999999999999999 words of this; mssh would run gpu017,n2 as the command'.format(word))]
	assert warnings(engine, 'mssh n{1..99999999999999999999}{a,b} uptime')[0][0][2].startswith('n{1..99999999999999999999}{a,b}: the shell makes 199999999999999999998 words of this; mssh would run n1b as')


def test_a_failing_brace_warning_leaves_the_other_warnings(engine, monkeypatch):
	def fail(token, shell):
		raise ValueError('odd braces')
	monkeypatch.setattr(mc, '_brace_split', fail)
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017,n{1,2} uptime')[0] == [('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]


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


def strip_zeros(name):
	'''name with leading zeros dropped from every run of digits: gpu017 -> gpu17.'''
	out = []
	index = 0
	while index < len(name):
		end = index
		while end < len(name) and name[end] in '0123456789':
			end += 1
		if end > index:
			out.append(name[index:end].lstrip('0') or '0')
			index = end
		else:
			out.append(name[index])
			index += 1
	return ''.join(out)


def did_you_mean_by_scan(names, name, states, now):
	'''What mssh_complete 0.4 suggested, looking at every host name: the reference for the faster search.'''
	def possible(candidate):
		state = states.get(candidate)
		return candidate != name and not (state is not None and state.fresh_validity(now) == 'invalid')
	stripped = strip_zeros(name)
	same = [candidate for candidate in names if candidate != name and strip_zeros(candidate) == stripped and possible(candidate)]
	if same:
		return same[0] if len(same) == 1 else None
	if len(name) < 4:
		return None
	close = [candidate for candidate in names if abs(len(candidate) - len(name)) <= 1 and mc._one_edit(name, candidate) and possible(candidate)]
	return close[0] if len(close) == 1 else None


def engine_with_names(names):
	engine = mc.Engine(SPEC, [], mc.HostTable())
	engine.hosts.names = sorted(set(names))
	return engine


def mistype(rng, name, chars):
	'''name with one random slip: a character changed, added, dropped or swapped, or zeros added or dropped.'''
	at = rng.randrange(len(name) + 1)
	slip = rng.randrange(6)
	if slip == 0 and at < len(name):
		return name[:at] + rng.choice(chars) + name[at + 1:]
	if slip == 1:
		return name[:at] + rng.choice(chars) + name[at:]
	if slip == 2 and at < len(name):
		return name[:at] + name[at + 1:]
	if slip == 3 and at + 1 < len(name):
		return name[:at] + name[at + 1] + name[at] + name[at + 2:]
	if slip == 4:
		return name[:at] + '0' * rng.randint(1, 3) + name[at:]
	return name.replace('0', '', 1)


def test_did_you_mean_finds_what_a_scan_of_every_name_finds():
	import random
	# few characters, many zeros and digit runs: many names are close to each other; the last ones
	# are non-ASCII, a non-ASCII digit (not a digit for mssh), a surrogate and the highest code point
	chars = 'ab-.' + '0' * 6 + '123' + 'é٣\udcff\U0010ffff'
	for seed_number in range(40):
		rng = random.Random(seed_number)
		names = [''.join(rng.choice(chars) for _ in range(rng.randint(1, 9))) for _ in range(rng.randint(20, 300))]
		names += ['{}{:0{}d}{}'.format(rng.choice(['n', 'gpu', '', 'r1n']), rng.randrange(120), rng.randint(1, 4), rng.choice(['', '-b', '.x0']))
			for _ in range(rng.randint(0, 200))]
		engine = engine_with_names(names)
		states = {name: mc.HostState(rng.choice(['invalid', 'valid']), NOW - rng.choice([0, 10000])) for name in rng.sample(names, len(names) // 5)}
		for _ in range(300):
			typed = rng.choice(names)
			for _ in range(rng.randint(0, 2)):
				typed = mistype(rng, typed, chars)
			if rng.random() < 0.1:
				typed = ''.join(rng.choice(chars) for _ in range(rng.randint(0, 8)))
			assert engine._did_you_mean(typed, states, NOW) == did_you_mean_by_scan(engine.hosts.names, typed, states, NOW), (seed_number, typed)


class CountingNames(list):
	'''A sorted list of host names that counts how many times its names are looked at.'''
	looked = 0

	def __getitem__(self, index):
		item = list.__getitem__(self, index)
		self.looked += len(item) if isinstance(index, slice) else 1
		return item

	def __iter__(self):
		for item in list.__iter__(self):
			self.looked += 1
			yield item


@pytest.mark.parametrize('typed', ['nodx01234', 'node1234', 'node001234', 'node0123x', 'node12345', 'gpu017', 'rack7', 'zz'])
def test_did_you_mean_does_not_look_at_every_known_host(typed):
	# with 50k hosts, looking at each one took 33 ms per unknown host: a line with a dozen of them
	# outlasted the shells' 0.3 s and showed no warning at all
	names = ['node{:05d}'.format(number) for number in range(50000)] + ['gpu{}'.format(number) for number in range(1, 17)] + ['login1']
	engine = engine_with_names(names)
	counting = engine.hosts.names = CountingNames(engine.hosts.names)
	meant = engine._did_you_mean(typed, {}, NOW)
	looked = counting.looked
	assert looked < 5000
	assert meant == did_you_mean_by_scan(list(counting), typed, {}, NOW)


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


@pytest.mark.parametrize('variables, unicode', [
	({'LANG': 'en_US.UTF-8'}, True),
	({'LANG': 'C.utf8'}, True),
	({'LANG': 'C'}, False),
	({'LANG': 'POSIX'}, False),
	({}, False),
	({'LANG': 'en_US'}, False),
	({'LANG': 'en_US.UTF-8', 'LC_ALL': 'C'}, False),
	({'LANG': 'C', 'LC_ALL': 'en_US.UTF-8'}, True),
	({'LANG': 'en_US.UTF-8', 'LC_ALL': ''}, True),
	({'LANG': 'C', 'LC_CTYPE': 'en_US.UTF-8'}, True),
	({'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'C'}, False),
	# what Python 3.7+ sets for a C locale: not the shell's
	({'LANG': 'C', 'LC_CTYPE': 'C.UTF-8'}, False),
	({'LC_CTYPE': 'C.UTF-8'}, False),
	({'LC_CTYPE': 'C.utf8'}, False),
	({'LC_CTYPE': 'UTF-8'}, False),
	({'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'C.UTF-8'}, True),
	# as bash takes them (bash 4.2, 4.4 and 5.2 on glibc): LC_CTYPE=UTF-8 (macOS over ssh) is no locale
	# here, and bash keeps LANG's; a LANG or LC_ALL the C library has not leaves C, whatever LC_CTYPE says
	({'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'UTF-8'}, True),
	({'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'xx_YY.UTF-8'}, True),
	({'LANG': 'xx_YY.UTF-8', 'LC_CTYPE': 'en_US.UTF-8'}, False),
	({'LC_ALL': 'xx_YY.UTF-8', 'LANG': 'en_US.UTF-8'}, False),
	({'LC_CTYPE': 'en_US.UTF-8'}, True),
	({'LC_CTYPE': 'en_US.UTF-8', 'LC_MESSAGES': 'xx_YY.UTF-8'}, False),
	({'LANG': 'C', 'LC_CTYPE': 'en_US.UTF-8', 'LC_MESSAGES': 'xx_YY.UTF-8'}, True),
	({'LANG': 'xx_YY.UTF-8'}, False),
])
def test_a_utf8_terminal_is_told_by_the_locale_variables_as_bash_takes_them(monkeypatch, variables, unicode):
	# as a C library with these locales takes them (en_US: ISO-8859-1)
	system = {'en_US.UTF-8': 'UTF-8', 'C.utf8': 'UTF-8', 'C.UTF-8': 'UTF-8', 'en_US': 'ISO-8859-1'}
	monkeypatch.setattr(mc, '_locale_codeset', lambda name: 'ANSI_X3.4-1968' if name in ('', 'C', 'POSIX') else system.get(name))
	monkeypatch.setattr(mc, '_SHELL_UTF8', None)
	for name in ('LC_ALL', 'LC_CTYPE', 'LANG', 'LC_MESSAGES'):
		monkeypatch.delenv(name, raising=False)
	for name, value in variables.items():
		monkeypatch.setenv(name, value)
	assert mc._unicode_terminal() is unicode


@pytest.mark.parametrize('flag', ['1', '0'])
def test_a_request_of_bash_says_the_locale_it_runs_in(monkeypatch, flag):
	# measured by the glue in the shell: it holds against the variables
	monkeypatch.setattr(mc, '_SHELL_UTF8', None)
	monkeypatch.setenv('LANG', 'C' if flag == '1' else 'C.UTF-8')
	mc._note_shell_locale(mc.Request('bash', 'mssh ', '', '', flags={'utf8': flag}))
	assert mc._unicode_terminal() is (flag == '1')
	mc._note_shell_locale(mc.Request('zsh', 'mssh ', '', '', flags={'utf8': '1' if flag == '0' else '0'}))
	assert mc._unicode_terminal() is (flag == '1')


def test_a_utf8_locale_the_system_lacks_gets_ascii(monkeypatch):
	# the shell runs in C there, and TAB in any case compares so too
	if mc._locale_codeset('xx_YY.UTF-8') is not None:
		pytest.skip('this C library takes any locale name (musl)')
	monkeypatch.setattr(mc, '_SHELL_UTF8', None)
	for name in ('LC_ALL', 'LC_CTYPE'):
		monkeypatch.delenv(name, raising=False)
	monkeypatch.setenv('LANG', 'xx_YY.UTF-8')
	assert mc._unicode_terminal() is False


@pytest.mark.parametrize('lang, unicode', [('C', False), ('POSIX', False), (None, False), ('C.UTF-8', mc._utf8_codeset(mc._locale_codeset('C.UTF-8')))])
def test_a_c_locale_gets_ascii_whatever_python_makes_of_it(lang, unicode):
	# Python 3.7+ starts a C locale as C.UTF-8 (PEP 538) and 3.15 always in UTF-8 mode: its own encoding
	# says UTF-8 where the shell shows the bytes of a ⚠ as \M-b\M-^Z\M-. C.UTF-8 draws Unicode where the
	# system has it (not CentOS 7's glibc 2.17)
	env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
	if lang is not None:
		env['LANG'] = lang
	code = 'import sys; sys.path.insert(0, sys.argv[1]); import mssh_complete; print(mssh_complete._unicode_terminal())'
	output = subprocess.run([sys.executable, '-I', '-c', code, os.path.dirname(mc.__file__)], env=env,
		stdout=subprocess.PIPE, check=True, timeout=30).stdout
	assert output.decode().strip() == str(unicode)


def test_a_range_mssh_completion_cannot_expand_says_nothing(engine):
	# letter ranges: nothing is known about their members
	assert warnings(engine, 'mssh node[a-c] uptime') == ([], False)


@pytest.mark.parametrize('word', ['node[1-]', 'node[-3]', 'rack[a-]', 'rack[-x]'])
def test_a_range_with_an_end_missing_is_one_host_name(engine, word):
	# mssh expands no member of it: the name as typed is checked, and is unknown
	assert warnings(engine, 'mssh {} uptime'.format(word)) == ([], True)
	assert mc.take_probe_queue(engine.directory) == [word]
	seed(engine, **{word: 'invalid'})
	assert warnings(engine, 'mssh {} uptime'.format(word))[0] == [(word, 'unknown', word + ': unknown host')]


@pytest.mark.parametrize('name', ['node[1-]', 'node[-3]', 'rack[ a - ]', 'n[1-2]x[-]', 'n[1-2,5-]', 'node[1-16]', 'rack[a-c]',
	'node[]', 'node[1', 'node]1-[', 'a[x,[]1-]', 'n[1-2][3-]', 'plain'])
def test_open_ranges_are_told_apart_as_mssh_does(name):
	assert mc._has_open_range(name) == getattr(multiSSH3, '_has_open_range')(name)


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


def test_a_huge_alias_is_checked_up_to_the_member_limit(engine, tmp_path, monkeypatch):
	# as a range is: ALLN=node[00000-49999] in ~/.bashrc queued all 50,000 hosts for DNS, ssh -G and ping
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	members = ['gpu{}'.format(number) for number in range(1, 9)]
	engine.hosts = mc.HostTable(index(tmp_path, {member: HISTORY for member in members}, {'gpus': members}))
	seed(engine, gpu1='invalid')
	assert warnings(engine, 'mssh gpus uptime') == ([('gpus', 'range', 'gpus: 1 of 8 checked, 1 unknown so far')], True)
	assert sorted(mc.take_probe_queue(engine.directory)) == ['gpu2', 'gpu3', 'gpu4']


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
	# a user typed with the alias replaces the member's: mssh runs root@db1
	('mssh root@dbs uptime', ['root@db1'], 'db1'),
	('mssh root@dbs uptime', ['postgres@db1'], None),
	('mssh root@dbs uptime', ['root@postgres@db1'], None),
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


# mssh parses its options among its positionals (parse_intermixed_args): in an unquoted remote command,
# a word naming an mssh option is that option, and any other word starting with '-' stops mssh
STOPS = sys.version_info >= (3, 7)  # Python 3.6 mssh passes unknown options on to the commands


@pytest.mark.parametrize('line, marked, message', [
	('mssh web1 journalctl -u slurmd', '-u', "-u is mssh's --username here — quote the command: 'journalctl -u slurmd'"),
	('mssh web1 tail -f /var/log/x', '-f', "-f is mssh's --file here — quote the command: 'tail -f /var/log/x'"),
	('mssh web1 curl -s http://x/', '-s', "-s is mssh's --file_sync here — quote the command: 'curl -s http://x/'"),
	('mssh web1 hostname -I ', '-I', "-I is mssh's --no_history here — quote the command: 'hostname -I'"),
	('mssh web1 df -h ', '-h', "-h is mssh's --help here — quote the command: 'df -h'"),
	# combined short flags: -aux is -a -u x
	('mssh web1 ps -aux ', '-aux', "-aux is mssh's --no_skip_unreachable and --username here — quote the command: 'ps -aux'"),
	# a short option with its value attached
	('mssh web1 find . -exec cat {} +', '-exec', "-exec is mssh's --encoding here — quote the command: 'find . -exec cat {} +'"),
	# a long name
	('mssh web1 jq --json . f', '--json', "--json is an mssh option here — quote the command: 'jq --json . f'"),
	# options of mssh given after the hosts but before the command are mssh's, as meant
	('mssh web1 -q journalctl -u slurmd', '-u', "-u is mssh's --username here — quote the command: 'journalctl -u slurmd'"),
	# quoting one word does not help: mssh gets the same word
	("mssh web1 ls '-I' /tmp", "'-I'", "-I is mssh's --no_history here — quote the command: \"ls '-I' /tmp\""),
])
def test_a_remote_command_word_mssh_reads_as_its_own_option(engine, line, marked, message):
	assert warnings(engine, line, probe=False)[0] == [(marked, 'command', message)]


@pytest.mark.parametrize('line', ['mssh web1 uptime -ea -v ', 'mssh web1 uptime -ea -h ', 'mssh web1 uptime -ea "-p 2222" '])
def test_the_word_after_ea_is_its_value_not_a_command_word(engine, line):
	# -ea takes the next word whatever it looks like: only -ea itself is mssh's
	value = line.split(' -ea ')[1].strip()
	assert warnings(engine, line, probe=False)[0] == [('-ea', 'command',
		"-ea is mssh's --extraargs here — quote the command: {!r}".format('uptime -ea ' + value))]


def test_a_password_after_a_bare_ea_option_is_never_shown(engine):
	found = warnings(engine, 'mssh web1 mysql -ea -p hunter2 db', probe=False)[0]
	assert found and not [message for _, _, message in found if 'hunter2' in message]
	assert [marked for marked, _, _ in found] == ['-ea', '-p']


@pytest.mark.parametrize('line', ['mssh -ea -v web1 journalctl -u slurmd', 'mssh -ea -- web1 journalctl -u slurmd'])
def test_after_an_ea_value_come_the_hosts_and_the_command(engine, line):
	assert warnings(engine, line, probe=False)[0] == [('-u', 'command',
		"-u is mssh's --username here — quote the command: 'journalctl -u slurmd'")]


@pytest.mark.parametrize('line, marked', [
	('mssh web1 ls -la /tmp', '-la'),
	('mssh web1 head -5 /x', '-5'),
	('mssh web1 ls --color=auto /tmp', '--color=auto'),
	# -q then -n, which mssh does not have
	('mssh web1 foo -qn x', '-qn'),
])
def test_a_remote_command_word_mssh_does_not_know(engine, line, marked):
	name = marked.partition('=')[0]
	expected = [(marked, 'command', '{} is not an mssh option (mssh stops with an error) — quote the command: {!r}'.format(
		name, line[len('mssh web1 '):]))]
	if marked != '-qn' and not STOPS:
		expected = []
	assert warnings(engine, line, probe=False)[0] == expected


def test_an_abbreviation_is_read_as_mssh_reads_it(engine):
	# argparse takes -c for -ci (--copy_id); taking full names only, mssh stops at it with an error
	found = warnings(engine, "mssh web1 bash -c 'echo hi'", probe=False)[0]
	if mc._takes_abbreviations(SPEC):
		assert found == [('-c', 'command', "-c is mssh's --copy_id here — quote the command: \"bash -c 'echo hi'\"")]
	else:
		assert found == ([('-c', 'command', "-c is not an mssh option (mssh stops with an error) — quote the command: \"bash -c 'echo hi'\"")]
			if STOPS else [])


@pytest.mark.parametrize('line', [
	"mssh web1 'journalctl -u slurmd'",
	# after a quoted command, options are mssh's (and the completer offers mssh's)
	"mssh web1 'uptime' -q -u root",
	'mssh -q -u root web1 uptime',
	# after --, every word is a command word
	'mssh web1 -- journalctl -u slurmd',
	'mssh web1 journalctl -- -u slurmd',
	# the shell's: what follows an operator is not mssh's
	'mssh web1 uptime | grep -v load',
	'mssh web1 uptime|grep -v load',
	'mssh web1 uptime; ls -la',
	'mssh web1 uptime && ls -la',
	'mssh web1 uptime > out -la',
	'mssh web1 echo $(date -u)',
	'mssh web1 echo `date -u`',
	'mssh web1 echo #HOST# -u',
	# with -f, -s or -G the commands are paths, and options after them are meant for mssh
	'mssh -f ./data web1 /tmp/ -q',
	'mssh -s=/etc/hosts web1 /etc/ -q',
	'mssh -G web1 ./logs -q',
	# a word with a space in it and no option name is a positional (argparse)
	'mssh web1 echo "-n hello" x',
	# the shell expands it: what mssh gets is not known here
	'mssh web1 ls -$OPTS x',
	'mssh web1 ls -* x',
])
def test_words_mssh_does_not_read_as_options_are_left_alone(engine, line):
	assert warnings(engine, line, probe=False)[0] == []


def test_the_option_being_typed_is_left_alone(engine):
	# the cursor inside it: the word is still being changed
	assert warnings(engine, 'mssh web1 journalctl -u slurmd', cursor=len('mssh web1 journalctl -'), probe=False)[0] == []
	# a word on its way to an option, or one that names none (mssh stops with an error on those)
	assert warnings(engine, 'mssh web1 journalctl --user', probe=False)[0] == []
	assert warnings(engine, 'mssh web1 ls -la', probe=False)[0] == []
	# its value being typed: the option is finished
	assert [marked for marked, _, _ in warnings(engine, 'mssh web1 journalctl -u slu', probe=False)[0]] == ['-u']


@pytest.mark.parametrize('line, message', [
	# Enter would run these as they stand: the last word is an mssh option, marked as soon as it is one
	('mssh all df -h', "-h is mssh's --help here — quote the command: 'df -h'"),
	('mssh all uname -a', "-a is mssh's --no_skip_unreachable here — quote the command: 'uname -a'"),
	('mssh web1 journalctl -u', "-u is mssh's --username here — quote the command: 'journalctl -u'"),
	('mssh all free --help', "--help is an mssh option here — quote the command: 'free --help'"),
])
def test_an_mssh_option_ending_the_line_is_marked(engine, line, message):
	assert warnings(engine, line, probe=False)[0] == [(line.rsplit(' ', 1)[1], 'command', message)]


@pytest.mark.parametrize('line, marked, message', [
	# -print is -p rint: the warning names -p, never the value, and quotes no command
	('mssh web1 find . -print ', '-print', "-p is mssh's --password here — quote the command"),
	('mssh web1 find . -qprint ', '-qprint', "-qp is mssh's --no_watch and --password here — quote the command"),
	('mssh web1 mysql --password=secret db', '--password=secret', "--password is an mssh option here — quote the command"),
	('mssh web1 sshpass -p secret ssh x', '-p', "-p is mssh's --password here — quote the command"),
])
def test_a_password_is_never_shown(engine, line, marked, message):
	assert warnings(engine, line, probe=False)[0] == [(marked, 'command', message)]


def test_every_other_option_of_a_command_with_a_password_quotes_nothing(engine):
	found = warnings(engine, 'mssh web1 sshpass -p secret ssh -q x', probe=False)[0]
	assert [marked for marked, _, _ in found] == ['-p', '-q']
	assert not any('secret' in message for _, _, message in found)


@pytest.mark.parametrize('line, example', [
	# single quotes inside: the command is shown in double quotes
	("mssh web1 grep -r 'a b' /etc", '"grep -r \'a b\' /etc"'),
	# both kinds of quotes, or a $: no example
	("mssh web1 grep -r 'a b' \"c\" /etc", None),
	("mssh web1 grep -r 'a b' \\$x /etc", None),
	# too long for the reason line
	('mssh web1 grep -r ' + 'x' * 150, None),
])
def test_the_quoted_command_is_shown_when_it_can_be(engine, line, example):
	message = warnings(engine, line, probe=False)[0][0][2]
	assert message == "-r is mssh's --repeat here — quote the command" + (': ' + example if example else '')


def test_a_command_word_read_as_an_option_comes_first(engine):
	seed(engine, gpu017='invalid')
	found = warnings(engine, 'mssh -su -nsu gpu017 journalctl -u slurmd', probe=False)[0]
	assert [kind for _, kind, _ in found] == ['command', 'unknown', 'options']


def test_an_ascii_terminal_gets_an_ascii_dash(engine, monkeypatch):
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: False)
	assert warnings(engine, 'mssh web1 df -h ', probe=False)[0][0][2] == "-h is mssh's --help here - quote the command: 'df -h'"


# words remote commands take, and the forms argparse reads in a way of its own
ORACLE_WORDS = ['-' + letter for letter in string.ascii_letters + string.digits] + [
	'-', '-la', '-al', '-lh', '-ltr', '-rf', '-fr', '-ef', '-aux', '-sh', '-hT', '-nr', '-tulpn', '-name', '-type', '-exec',
	'-print', '-br', '-10', '-11', '-111', '-11x', '-1x', '-1.5', '-.5', '-ci', '-nw', '-no', '-nh', '-su', '-nsu', '-ns', '-qj',
	'-qI', '-Sj', '-xq', '-xa', '-su5', '-pr', '-uh', '-mp', '-ir', '-irl', '-mpr', '-qpr', '-qn', '-qc', '-qu=x', '-a-b', '-Vq',
	'-uroot', '-u=root', '-u=', '-f=', '-q=', '-qj=', '-ipx', '-iux', '-kx', '-ss', '-sx', '-fq', '-Dfoo=bar', '-Xmx2g', '-é',
	'-e hello', '-n hello', '--no pager', '--user x',
	'--help', '--he', '--help=x', '--version', '--ver', '--all', '--color=auto', '--no-pager', '--follow', '--lines=5',
	'--force', '--user', '--user=root', '--user=', '--usernam', '--now', '--quiet', '--json', '--json=x', '--file', '--time',
	'--no', '--s', '--scr', '--host', '--interval', '--in', '--k', '--key', '--ide', '--identity', '--p', '--pass=x',
	'--ipmi', '--ipmi_', '--ipmi_p', '--c', '--co', '--c=y', '--=x', '--conf', '--config', '--config_file', '--config_file=y',
	'--comp', '--completion', '--generate', '--store', '--add', '--table', '--ta', '--max', '--rep', '--no_w', '--single',
	'--skip', '--return', '--enc', '--gather',
]


def mssh_reads(word, parser):
	'''
	What mssh's own parsing makes of `web1 cmd WORD x`: process_args reads --config_file first with a
	parser of its own, then parses the rest intermixed (parse_known_args on Python 3.6). Values are
	not converted and exclusive options are allowed, so only how words are read decides.

	Returns:
		tuple: (the dests of the options argparse took, in order; whether x was an option's value; the
			exit code, None when parsing went through; the words left over (Python 3.6))
	'''
	taken = []

	def recording(parser):
		for action in parser._actions:
			if action.option_strings:
				base = type(action)

				def call(self, parser, namespace, values, option_string=None, base=base):
					taken.append(self.dest)
					return base.__call__(self, parser, namespace, values, option_string)
				action.type = None
				action.__class__ = type(base.__name__, (base,), {'__call__': call})
		parser._mutually_exclusive_groups = []
		return parser

	recording(parser)
	first = type(parser)(add_help=False)
	first.add_argument('--config_file', type=str, nargs='?', const='multiSSH3.config.json', default=None)
	recording(first)
	extras = []
	try:
		with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
			_, rest = first.parse_known_args(['web1', 'cmd', word, 'x'])
			if hasattr(parser, 'parse_intermixed_args'):
				namespace = parser.parse_intermixed_args(rest)
			else:
				namespace, extras = parser.parse_known_args(rest)
	except SystemExit as e:
		return taken, None, e.code, extras
	except Exception:
		# older Pythons crash on some words ("-q="): mssh stops all the same
		return taken, None, 'crash', extras
	return taken, 'x' not in namespace.commands and 'x' not in extras, None, extras


def agrees(word, verdict, readings, outcome):
	'''Whether the engine's reading of a word is what argparse did with it.'''
	taken, took_x, code, extras = outcome
	if verdict == 'positional':
		return (taken, took_x, code) == ([], False, None)
	if verdict == 'unknown':
		return code == 2 if STOPS else (not taken and code is None and word in extras)
	if verdict == 'error':
		return code in (2, 'crash')
	if verdict == 'unsure':
		return True
	dests = []
	for option, attached, _ in readings:
		dests.append(option.dest)
		if option.dest in ('help', 'version'):
			# mssh prints it and exits: the rest of the word is never acted on
			return taken == dests and code == 0
	option, attached, _ = readings[-1]
	return (taken, took_x, code) == (dests, attached is None and option.nargs != '0', None)


def disagreements(parser_factory, abbreviations):
	found = []
	for word in ORACLE_WORDS:
		verdict, readings = mc.read_option_word(word, SPEC, abbreviations)
		outcome = mssh_reads(word, parser_factory())
		if not agrees(word, verdict, readings, outcome):
			found.append((word, verdict, [(option.dest, attached) for option, attached, _ in readings], outcome))
	return found


def test_words_are_read_as_mssh_reads_them():
	assert disagreements(multiSSH3.get_parser, mc._takes_abbreviations(SPEC)) == []


def test_abbreviations_are_taken_as_mssh_takes_them():
	# the spec looks names up as mssh does: abbreviations are read only when mssh reads them
	assert mc._takes_abbreviations(SPEC) is (mssh_reads('--usernam', multiSSH3.get_parser())[0] == ['username'])


class FullNamesParser(argparse.ArgumentParser):
	'''argparse taking option names in full only, as mssh's parser does on patch/no-option-abbrev.'''
	def _get_option_tuples(self, option_string):
		readings = super(FullNamesParser, self)._get_option_tuples(option_string)
		name = option_string.partition('=')[0]
		if any(reading[1] in (name, option_string[:2]) for reading in readings):
			return readings
		return []


def test_words_are_read_as_mssh_reads_them_when_it_takes_full_names_only(monkeypatch):
	# multiSSH3's argparse with that parser (argparse's own code must keep its own ArgumentParser)
	full_names = types.ModuleType('argparse')
	full_names.__dict__.update(argparse.__dict__)
	full_names.ArgumentParser = FullNamesParser
	monkeypatch.setattr(multiSSH3, 'argparse', full_names)
	assert disagreements(multiSSH3.get_parser, False) == []


@pytest.mark.parametrize('word', ['-q=j', '-h=x', '-hz', '-Vz', '-pr=x', "'-q x'", '-qci'])
def test_words_pythons_read_differently_are_left_alone(engine, word):
	# a flag then "=" (-q=j: -q -j on older Pythons, an error on newer ones), help then a letter mssh does
	# not have (-hz: an error, or the help), a name with "=" that abbreviates another (-pr=x: -p r=x, or
	# ambiguous), what follows a letter mssh does not have read again as a word (3.11: -q, "- x" a
	# positional; -q -ci)
	text = mc.lex(word)[0].text
	assert mc.read_option_word(text, SPEC, True)[0] == mc.read_option_word(text, SPEC, False)[0] == 'unsure'
	assert warnings(engine, 'mssh web1 cmd {} x'.format(word), probe=False)[0] == []


def test_the_oracle_covers_every_reading():
	abbreviations = mc._takes_abbreviations(SPEC)
	verdicts = [mc.read_option_word(word, SPEC, abbreviations)[0] for word in ORACLE_WORDS]
	assert {'positional', 'options', 'unknown', 'error'} <= set(verdicts)
	# -qc: -q then -c, an abbreviation of -ci that Python 3.11 reads again (when mssh takes abbreviations)
	unsure = ['-qc'] if abbreviations else []
	assert [word for word, verdict in zip(ORACLE_WORDS, verdicts) if verdict == 'unsure'] == unsure
