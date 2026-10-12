'''Grey suggestions: how much of the line the engine dares to predict, and that it only ever extends what was typed.'''
import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su', 'gpu[01-16]', '"nvidia-smi"') for number in range(6)]
HISTORY += [line(NOW - 50 * number, '-su -u=root', 'storage1', '"df -h /data"') for number in range(3)]
HISTORY += [line(NOW - 70 * number, '-su', 'login1', '"uptime"') for number in range(2)]
HISTORY += [line(NOW - 90 * number, '-su', 'login1', '"w"') for number in range(2)]


def suggest(before, after='', shell='bash', history=HISTORY):
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	return mc.Engine(SPEC, [memory]).suggest(mc.Request(shell, before, after, ''))


def test_whole_line_when_one_invocation_dominates():
	ghost = suggest('mssh gp')
	assert (ghost.kind, ghost.text) == ('line', 'u[01-16] "nvidia-smi"')


def test_only_the_word_when_what_follows_is_unclear():
	# login1 ran uptime and w equally often: the host is clear, the command is not
	ghost = suggest('mssh log')
	assert (ghost.kind, ghost.text) == ('word', 'in1')


def test_nothing_when_the_word_itself_is_unclear():
	# gpu[01-16] is the most used host, but not by enough
	assert suggest('mssh ') is None
	assert suggest('mssh x') is None


def test_option_values_continue_with_hosts_and_command():
	ghost = suggest('mssh -u ro')
	assert (ghost.kind, ghost.text) == ('line', 'ot storage1 "df -h /data"')


def test_inside_an_open_quote_the_suggestion_closes_it():
	ghost = suggest('mssh gpu[01-16] "nv')
	assert ghost.text == 'idia-smi"'


def test_unquoted_command_words_are_escaped():
	ghost = suggest('mssh storage1 cat /da', history=[line(NOW - number, '-su', 'storage1', '"cat /data|wc"') for number in range(5)])
	assert ghost.text == 'ta\\|wc'


def test_zsh_escapes_glob_characters():
	assert suggest('mssh gp', shell='zsh').text == 'u\\[01-16\\] "nvidia-smi"'


@pytest.mark.parametrize('before, after', [('mssh gp', 'x'), ('ls gp', ''), ('mssh -p ', ''), ('mssh -p se', '')])
def test_no_suggestion(before, after):
	assert suggest(before, after) is None


def test_a_value_seen_once_is_not_suggested():
	assert suggest('mssh on', history=[line(NOW, '-su', 'onlyonce1', '"uptime"')]) is None


def test_every_suggestion_extends_what_was_typed():
	for entry in HISTORY:
		full = 'mssh ' + ' '.join(entry.split('\t')[2:])
		for cut in range(5, len(full)):
			ghost = suggest(full[:cut])
			if ghost is not None:
				assert ghost.text and (ghost.kind in ('line', 'word'))
				words = [token.text for token in mc.lex(full[:cut] + ghost.text)]
				assert words[0] == 'mssh'


def test_ghost_requests_answer_with_one_g_record():
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, SPEC, NOW)
	engine = mc.Engine(SPEC, [memory])
	response = engine.query(mc.Request('bash', 'mssh gp', '', 'gp', flags={'ghost': '1'}))
	assert mc.format_response(response, nul=False) == 'MSSHC1\nG line\tu[01-16] "nvidia-smi"\nE\n'.encode()
