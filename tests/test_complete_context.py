import argparse
import random
import shlex

import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())


def test_spec_describes_every_option():
	strings = {string for option in SPEC.options for string in option.strings}
	assert {'-u', '--username', '-S', '-q', '-nw', '--no_watch'} <= strings
	assert SPEC.by_string['-u'].nargs == '1'
	assert SPEC.by_string['-fs'].nargs == '?'
	assert SPEC.by_string['-q'].nargs == '0'
	assert SPEC.by_string['-f'].repeat
	assert SPEC.by_string['-x'].group and SPEC.by_string['-x'].group == SPEC.by_string['-a'].group
	assert SPEC.by_string['-t'].default == str(multiSSH3.DEFAULT_CLI_TIMEOUT)


def test_spec_rows_round_trip():
	again = mc.ParserSpec.from_rows(SPEC.to_rows())
	assert [option.to_row() for option in again.options] == SPEC.to_rows()


@pytest.mark.parametrize('text, dest, value', [
	('-u', 'username', None),
	('--username', 'username', None),
	('-u=root', 'username', 'root'),
	('--no_w', 'no_watch', None),
	('--usern=x', 'username', 'x'),
	('--no', None, None),
	('-zz', None, None),
])
def test_lookup(text, dest, value):
	option, attached = SPEC.lookup(text)
	assert (option.dest if option else None, attached) == (dest, value)


@pytest.mark.parametrize('before, after, slot, dest, value', [
	('mssh ', '', 'hosts', None, ''),
	('mssh -', '', 'option', None, '-'),
	('mssh --no_', '', 'option', None, '--no_'),
	('mssh -u ', '', 'value', 'username', ''),
	('mssh -u r', '', 'value', 'username', 'r'),
	('mssh -f=/et', '', 'value', 'file', '/et'),
	('mssh -fs ', '', 'value', 'file_sync', ''),
	('mssh -q ', '', 'hosts', None, ''),
	('mssh grp ', '', 'command', None, ''),
	('mssh grp "a | gre', '', 'command', None, 'a | gre'),
	('mssh grp ls -', '', 'command', None, '-'),
	("mssh grp 'uptime' -", '', 'option', None, '-'),
	('mssh -- -x', '', 'hosts', None, '-x'),
	('mssh h -- -x', '', 'command', None, '-x'),
])
def test_slot(before, after, slot, dest, value):
	context = mc.parse_context(before, after, SPEC)
	assert context.slot == slot
	assert (context.option.dest if context.option else None) == dest
	assert context.value == value


@pytest.mark.parametrize('before, slot, value', [
	# "--" ends the options, not the hosts: argparse still reads the next word as the hosts
	('mssh -- ', 'hosts', ''),
	('mssh -- gp', 'hosts', 'gp'),
	('mssh -u root -- ', 'hosts', ''),
	('mssh -q -- gp', 'hosts', 'gp'),
	# the README's mssh -fs -- allServers ./data/: "--" keeps -fs from taking the hosts
	('mssh -fs -- all', 'hosts', 'all'),
	('mssh -fs -- allServers ./da', 'command', './da'),
	# and a dash after it starts no option
	('mssh -- -', 'hosts', '-'),
	('mssh -- gpu1 ', 'command', ''),
	('mssh -- gpu1 -', 'command', '-'),
	('mssh gpu1 -- -', 'command', '-'),
])
def test_slot_after_double_dash(before, slot, value):
	context = mc.parse_context(before, '', SPEC)
	assert (context.slot, context.value) == (slot, value)


def test_a_command_after_double_dash_and_hosts_starts_at_its_first_word():
	context = mc.parse_context('mssh -- gpu1 systemctl rest', '', SPEC)
	assert context.hosts == 'gpu1'
	assert (context.command_words, context.command_word_index) == (['systemctl', 'rest'], 1)


@pytest.mark.parametrize('before, after, words, index', [
	# argparse drops the "--": mssh h ls -- -la runs "ls -la"
	('mssh h ls -- -l', '', ['ls', '-l'], 1),
	('mssh h ls -- ', '', ['ls', ''], 1),
	('mssh h -- ls -- -l', '', ['ls', '--', '-l'], 2),
	('mssh h -- l', ' -la', ['l'], 0),
	("mssh h 'uptime' -- l", '', ['l'], 0),
])
def test_double_dash_between_command_words_does_not_split_the_command(before, after, words, index):
	context = mc.parse_context(before, after, SPEC)
	assert (context.slot, context.command_words, context.command_word_index) == ('command', words, index)
	# the words of the command being typed are not a command of their own
	assert 'c:ls' not in context.features and 'p:ls' not in context.features


def test_program_name_has_no_context():
	assert mc.parse_context('mss', '', SPEC) is None


def test_features_come_from_both_sides_of_the_cursor():
	context = mc.parse_context('mssh ', " 'systemctl restart slurmd' -u root", SPEC)
	assert context.slot == 'hosts'
	assert context.features == ['c:systemctl restart slurmd', 'm:plain', 'o:--username', 'p:systemctl', 's:systemctl restart', 'v:username=root']


def test_passwords_never_become_features():
	context = mc.parse_context('mssh -p=secret -ip hunter2 -u ', ' h c', SPEC)
	assert not any('secret' in feature or 'hunter2' in feature or 'password' in feature for feature in context.features)


def test_quoted_command_delegates_its_last_segment():
	context = mc.parse_context('mssh grp "cat x | gre', '', SPEC)
	assert (context.command_words, context.command_word_index, context.command_prefix) == (['gre'], 0, 'cat x | ')


def test_unquoted_command_words_are_one_command():
	context = mc.parse_context('mssh grp systemctl rest', ' x', SPEC)
	assert (context.command_words, context.command_word_index, context.command_prefix) == (['systemctl', 'rest'], 1, '')
	assert not any(feature.startswith('c:') for feature in context.features)


def test_path_modes_make_path_features():
	assert mc.parse_context('mssh -fs ', ' h /etc/hosts', SPEC).mode == 'sync'
	assert 'f:/data/x' in mc.parse_context('mssh -u ', ' -G h /data/x', SPEC).features


def test_history_line():
	entry = mc.parse_history_line('1762909714\t/x/multiSSH3.py\t-su -f="/etc/a b" -p=pw -u=root\t\'node[1-3],root@gpu1\'\t"lscpu | grep X" uptime', SPEC)
	assert entry.ts == 1762909714
	assert [(option.dest, value) for option, value in entry.options] == [('skip_unreachable', None), ('file', '/etc/a b'), ('password', 'pw'), ('username', 'root')]
	assert entry.option_texts == ['-su', '-f', '-p', '-u']
	assert entry.hosts == 'node[1-3],root@gpu1'
	assert entry.commands == ['lscpu | grep X', 'uptime']
	assert 'h:node[1-3],root@gpu1' in entry.features() and 't:gpu1' in entry.features()
	assert not any('pw' in feature for feature in entry.features())


@pytest.mark.parametrize('line', ['garbage', '1\t2\t3', 'x\ta\tb\tc\td'])
def test_history_line_in_another_format(line):
	assert mc.parse_history_line(line, SPEC) is None


def _generated_lines(count=300, seed=7):
	rng = random.Random(seed)
	options = [['-q'], ['-u', 'root'], ['-u=admin'], ['-t', '30'], ['-su'], ['-fs'], ['-k'], ['--no_watch'], ['-j'], ['-f', '/tmp/a']]
	hosts = ['gpu[01-16]', 'node1,node2', 'us_east']
	commands = [['uptime'], ['df -h'], ['echo', 'hi'], []]
	for _ in range(count):
		words = []
		for _ in range(rng.randint(0, 3)):
			words += rng.choice(options)
		words.append(rng.choice(hosts))
		words += rng.choice(commands)
		yield words


def test_roles_agree_with_argparse():
	parser = multiSSH3.get_parser()
	if not hasattr(parser, 'parse_intermixed_args'):
		pytest.skip('Python 3.6 has no parse_intermixed_args; mssh falls back to parse_known_args there')
	for words in _generated_lines():
		try:
			parsed = parser.parse_intermixed_args(words)
		except SystemExit:
			continue
		tokens = mc.lex(' '.join(shlex.quote(word) for word in words))
		roles = mc.assign_roles(tokens, SPEC)
		hosts = [token.text for token, (role, _) in zip(tokens, roles) if role == 'hosts']
		commands = [token.text for token, (role, _) in zip(tokens, roles) if role == 'command']
		assert hosts == ([parsed.hosts] if parsed.hosts != multiSSH3.DEFAULT_HOSTS or 'all' in words else []), words
		assert commands == parsed.commands, words


# what mssh's argparse makes of "--" (Python 3.12 and later): it ends the options, the next word
# is still the hosts, and every later word is a positional, a dash word or another "--" included.
# Python 3.6 (parse_known_args) agrees but for a second "--", which it drops.
DOUBLE_DASH_LINES = [
	('-- h c', 'h', ['c']),
	('-- h c d', 'h', ['c', 'd']),
	('h -- c', 'h', ['c']),
	('h -- -x', 'h', ['-x']),
	('-u x -- h c', 'h', ['c']),
	('-k -- h c', 'h', ['c']),
	('-fs -- allServers ./data/', 'allServers', ['./data/']),
	('h -u y -- c', 'h', ['c']),
	('h c -- -x', 'h', ['c', '-x']),
	('h c -- -u y', 'h', ['c', '-u', 'y']),
	('-- -weirdhost c', '-weirdhost', ['c']),
	('-- h -u y', 'h', ['-u', 'y']),
	('-- -u y', '-u', ['y']),
	('-- h -- c', 'h', ['--', 'c']),
	('-- -- c', '--', ['c']),
	('-- h --config_file x', 'h', ['--config_file', 'x']),
]


def _roles_as_argparse_values(line):
	tokens = mc.lex(line)
	roles = mc.assign_roles(tokens, SPEC)
	hosts = [token.text for token, (role, _) in zip(tokens, roles) if role == 'hosts']
	commands = [token.text for token, (role, _) in zip(tokens, roles) if role == 'command']
	return hosts, commands


@pytest.mark.parametrize('line, hosts, commands', DOUBLE_DASH_LINES)
def test_roles_after_double_dash(line, hosts, commands):
	assert _roles_as_argparse_values(line) == ([hosts], commands)


def _intermixed_reads_options_after_double_dash():
	'''Python 3.7 to 3.11's parse_intermixed_args drops a "--" in front of the positionals and reads the options after it.'''
	parser = argparse.ArgumentParser()
	parser.add_argument('hosts', nargs='?')
	parser.add_argument('-o', action='store_true')
	return parser.parse_intermixed_args(['--', '-o']).o


def _modern_intermixed_parser():
	parser = multiSSH3.get_parser()
	if not hasattr(parser, 'parse_intermixed_args'):
		pytest.skip('Python 3.6 has no parse_intermixed_args; mssh falls back to parse_known_args there')
	if _intermixed_reads_options_after_double_dash():
		pytest.skip("this Python's parse_intermixed_args reads options after a leading --; Python 3.12 does not")
	return parser


@pytest.mark.parametrize('line, hosts, commands', DOUBLE_DASH_LINES)
def test_double_dash_lines_are_what_mssh_parses(line, hosts, commands):
	parsed = _modern_intermixed_parser().parse_intermixed_args(shlex.split(line))
	assert (parsed.hosts, parsed.commands) == (hosts, commands)


def test_roles_agree_with_argparse_around_double_dash():
	parser = _modern_intermixed_parser()
	rng = random.Random(11)
	checked = 0
	for words in _generated_lines(150, seed=13):
		words.insert(rng.randint(0, len(words)), '--')
		try:
			parsed = parser.parse_intermixed_args(words)
		except SystemExit:
			continue
		checked += 1
		hosts, commands = _roles_as_argparse_values(' '.join(shlex.quote(word) for word in words))
		assert hosts == ([parsed.hosts] if parsed.hosts != multiSSH3.DEFAULT_HOSTS or 'all' in words else []), words
		assert commands == parsed.commands, words
	assert checked > 100


def test_shell_history_reads_hosts_after_double_dash():
	features = mc.line_features(mc.lex('-u root -- gpu1 uptime'), SPEC)
	assert 'h:gpu1' in features and 'c:uptime' in features and not any(feature.startswith('c:gpu1') for feature in features)



@pytest.mark.parametrize('text, dest, value', [
	('-pHunter2pw', 'password', 'Hunter2pw'), ('-t30', 'timeout', '30'), ('-uroot', 'username', 'root'),
	# an attached value may hold '=' itself
	('-pS3c=t', 'password', 'S3c=t'), ('-uroot=x', 'username', 'root=x'),
])
def test_attached_short_option_values_follow_argparse(text, dest, value):
	option, attached = SPEC.lookup(text)
	assert (option.dest if option else None, attached) == (dest, value)
	assert str(vars(multiSSH3.get_parser().parse_args([text]))[dest]) == value


def test_a_password_attached_with_an_equals_sign_is_never_learned():
	tokens = mc.lex('-pS3c=t host uptime')
	assert mc._sets_password(tokens, SPEC)
	assert not [feature for feature in mc.line_features(tokens, SPEC) if 'S3c' in feature]
