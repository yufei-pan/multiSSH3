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
	('mssh -- -x', '', 'command', None, '-x'),
])
def test_slot(before, after, slot, dest, value):
	context = mc.parse_context(before, after, SPEC)
	assert context.slot == slot
	assert (context.option.dest if context.option else None) == dest
	assert context.value == value


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
