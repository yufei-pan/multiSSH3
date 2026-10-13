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


SPLIT = [line(NOW - number, '-su', 'cloud', '"date"') for number in range(3)]
SPLIT += [line(NOW - 10 - number, '-su', 'cloud,la,localhost,rtr', '"uptime"') for number in range(3)]


def test_the_start_all_values_share_when_none_is_sure():
	# cloud and cloud,la,localhost,rtr split the share, but both start with cloud
	ghost = suggest('mssh cl', history=SPLIT)
	assert (ghost.kind, ghost.text) == ('word', 'oud')


def test_the_shared_start_is_escaped_for_the_shell():
	history = [line(NOW - number, '-su', 'gpu[01-16]', '"date"') for number in range(3)]
	history += [line(NOW - 10 - number, '-su', 'gpu[01-16],login1', '"uptime"') for number in range(3)]
	assert suggest('mssh gp', shell='zsh', history=history).text == 'u\\[01-16\\]'


def test_inside_a_quote_the_shared_start_leaves_the_quote_open():
	history = [line(NOW - number, '-su', 'web1', '"systemctl status nginx"') for number in range(3)]
	history += [line(NOW - 10 - number, '-su', 'web1', '"systemctl restart nginx"') for number in range(3)]
	assert suggest('mssh web1 "sys', history=history).text == 'temctl '


def test_no_shared_start_from_values_seen_once():
	history = [line(NOW, '-su', 'onlyonce1', '"uptime"'), line(NOW - 1, '-su', 'onlyonce2', '"uptime"')]
	assert suggest('mssh on', history=history) is None


def test_option_values_continue_with_hosts_and_command():
	ghost = suggest('mssh -u ro')
	assert (ghost.kind, ghost.text) == ('line', 'ot storage1 "df -h /data"')


def test_inside_an_open_quote_the_suggestion_closes_it():
	ghost = suggest('mssh gpu[01-16] "nv')
	assert ghost.text == 'idia-smi"'


# bash and zsh expand ! inside double quotes when they read the line (history expansion, on by default)
BANG = [line(NOW - number, '-su -u=ops', 'web1', "'grep !important /etc/x'") for number in range(6)]


@pytest.mark.parametrize('shell, quoted', [
	('bash', "'grep !important /etc/x'"), ('zsh', "'grep !important /etc/x'"), ('fish', '"grep !important /etc/x"')])
def test_a_command_holding_a_bang_is_suggested_in_single_quotes(shell, quoted):
	assert suggest('mssh -u o', shell=shell, history=BANG).text == 'ps web1 ' + quoted


def test_a_command_holding_a_bang_and_a_single_quote_is_not_suggested():
	history = [line(NOW - number, '-su -u=ops', 'web1', '"echo it\'s done!"') for number in range(6)]
	assert suggest('mssh -u o', history=history).text == 'ps'


@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_no_bang_is_suggested_inside_an_open_double_quote(shell):
	assert suggest('mssh -u=ops web1 "gr', shell=shell, history=BANG) is None
	assert suggest("mssh -u=ops web1 'gr", shell=shell, history=BANG).text == "ep !important /etc/x'"
	# nor in the start values share
	shared = [line(NOW - number, '-su', 'web1', "'echo hi!{}'".format(end)) for number in range(3) for end in 'ab']
	assert suggest('mssh web1 "ec', shell=shell, history=shared) is None
	assert suggest("mssh web1 'ec", shell=shell, history=shared).text == 'ho hi!'


def test_fish_suggests_a_bang_inside_double_quotes():
	assert suggest('mssh -u=ops web1 "gr', shell='fish', history=BANG).text == 'ep !important /etc/x"'


def test_unquoted_command_words_are_escaped():
	ghost = suggest('mssh storage1 cat /da', history=[line(NOW - number, '-su', 'storage1', '"cat /data|wc"') for number in range(5)])
	assert ghost.text == 'ta\\|wc'


def test_bash_escapes_what_it_would_expand_in_command_words():
	# a comment, a home directory and a glob belong to the remote command, not to the local shell
	history = [line(NOW - number, '-su', 'node1', '"echo #HOST# ~ *.log"') for number in range(5)]
	assert suggest('mssh node1 ec', history=history).text == 'ho \\#HOST\\# \\~ \\*.log'


def test_never_an_empty_suggestion():
	# lsblk is the likeliest whole command, ls the likeliest word: ls is typed already
	history = [line(NOW - number, '-su', 'node1', 'lsblk') for number in range(10)]
	history += [line(NOW - 20 - number, '-su', 'node1', '"ls {}"'.format(name)) for number, name in enumerate('abcdefghij') for _ in range(5)]
	ghost = suggest('mssh node1 ls', history=history)
	assert ghost is None or ghost.text


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
