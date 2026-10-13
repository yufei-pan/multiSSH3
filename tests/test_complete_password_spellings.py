'''
Passwords given with spellings mssh no longer takes: mssh 6.31 took any unique abbreviation of an
option name ("--pass x", "--ipmi_passw=x"), and the shell's history and ~/.mssh_history keep such
lines. mssh now refuses them, but their passwords are still never offered or shown, and neither
are those given after short flags written together ("-qp x") or attached to -ip ("-ipx").
'''
import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000
SECRET = 's3cretPW'


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


# the options of a line as typed, and the password in them
SPELLINGS = [
	('--pass ' + SECRET, SECRET),
	('--passw=' + SECRET, SECRET),
	('--p ' + SECRET, SECRET),
	('--ipmi_pass ' + SECRET, SECRET),
	('--ipmi_passw ' + SECRET, SECRET),
	('--ipmi_p=' + SECRET, SECRET),
	('-qp ' + SECRET, SECRET),
	('-qp' + SECRET, SECRET),
	('-ip' + SECRET, SECRET),
	('--passw -Tr0ub4dor', '-Tr0ub4dor'),
]


@pytest.mark.parametrize('text, dest, value', [
	('--pass', 'password', None),
	('--passw=x', 'password', 'x'),
	('--p', 'password', None),
	('--ipmi_pass', 'ipmi_password', None),
	('--ipmi_passw=x', 'ipmi_password', 'x'),
	('-qp', 'password', None),
	('-qpx', 'password', 'x'),
	('-Sqp=x', 'password', 'x'),
	('-ipx', 'ipmi_password', 'x'),
	# no password: other abbreviations, several options, flags alone, another value-taking option
	('--ipmi_', None, None),
	('--user', None, None),
	('-SCRIPT', None, None),
	('-qj', None, None),
	('-qu', None, None),
])
def test_password_spellings_are_password_options(text, dest, value):
	option, attached = SPEC.lookup(text)
	assert (option.dest if option else None, attached) == (dest, value)


def test_every_abbreviation_mssh_took_for_a_password_is_one():
	# every prefix argparse matched to --password or --ipmi_password alone (Python 3.6 to 3.15)
	for name, dest in (('--password', 'password'), ('--ipmi_password', 'ipmi_password')):
		start = 3 if dest == 'password' else len('--ipmi_p')
		for end in range(start, len(name) + 1):
			assert SPEC.lookup(name[:end])[0].dest == dest, name[:end]
			assert SPEC.lookup(name[:end] + '=x') == (SPEC.by_string[name], 'x')


def _never_shows(secret, knowledges, history=()):
	engine = mc.Engine(SPEC, knowledges)
	for before in ('mssh ', 'mssh s3', 'mssh -', 'mssh node1 ', 'mssh node1 "', 'mssh node1 up', 'mssh node1 uptime ',
			'mssh -Tr', 'mssh node1 -', 'mssh node1 --', 'mssh node1 -T', 'mssh -u '):
		word = '' if before.endswith(' ') else before.split(' ')[-1].lstrip('"')
		request = mc.Request('bash', before, '', word, history=list(history))
		for candidate in engine.query(request).candidates:
			assert secret not in candidate.text, (before, candidate.text)
		ghost = engine.suggest(mc.Request('bash', before, '', ''))
		assert ghost is None or secret not in ghost.text, (before, ghost.text)
		slot, _, rows, _ = mc.picker_items(request, engine, [], NOW)
		assert not [item.text for item in slot + rows if secret in item.text], before


@pytest.mark.parametrize('options, secret', SPELLINGS)
def test_shell_history_never_offers_the_password(options, secret):
	shell = ['mssh {} node1 uptime'.format(options)] * 3
	_never_shows(secret, [mc.shell_history_knowledge(shell, SPEC)], history=shell)


@pytest.mark.parametrize('options, secret', SPELLINGS)
def test_mssh_history_never_shows_the_password(options, secret):
	history = [line(NOW - number, '-su ' + options, 'node1', '"uptime"') for number in range(3)]
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	engine = mc.Engine(SPEC, [memory])
	_never_shows(secret, [memory])
	_, _, rows, _ = mc.picker_items(mc.Request('bash', 'mssh ', '', ''), engine, history, NOW)
	assert not [item.text for item in rows if secret in item.text]


@pytest.mark.parametrize('options, secret', SPELLINGS)
def test_a_line_with_the_password_is_not_learned(options, secret):
	tokens = mc.lex('{} node1 uptime'.format(options))
	assert mc._sets_password(tokens, SPEC)
	assert not [feature for feature in mc.line_features(tokens, SPEC) if secret in feature]


def test_the_value_after_an_abbreviated_password_option_is_never_completed():
	response = mc.Engine(SPEC, []).query(mc.Request('bash', 'mssh --pass ', '', ''))
	assert response.candidates == [] and 'nodefault' in response.directives
