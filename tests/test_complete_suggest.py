'''Grey suggestions: how much of the line the engine dares to predict, and that it only ever extends what was typed.'''
import signal

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


def test_inside_an_ansi_c_quote_backslashes_are_never_suggested():
	# in $'...' a backslash starts an escape: printf "%s\n" x would become printf "%s<newline>" x
	history = [line(NOW - number, '-su', 'node1', '\'printf "%s\\n" x\'') for number in range(5)]
	assert suggest("mssh node1 'pri", history=history).text == 'ntf "%s\\n" x\''
	assert suggest("mssh node1 $'pri", history=history) is None
	# nor the start two such commands share
	history = [line(NOW - number, '-su', 'node1', '\'printf "%s\\n" {}\''.format(name)) for number in range(3) for name in 'ab']
	assert suggest("mssh node1 'pri", history=history).text == 'ntf "%s\\n" '
	assert suggest("mssh node1 $'pri", history=history) is None


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


def mssh_runs(line_text, monkeypatch):
	'''The remote commands mssh runs for an mssh line, answering its "one command or several" question with the default.'''
	monkeypatch.setattr(multiSSH3, 'input_with_timeout_and_countdown', lambda *args, **kwargs: None)
	handler = signal.getsignal(signal.SIGINT)
	try:
		return multiSSH3.process_commands(multiSSH3.process_args([token.text for token in mc.lex(line_text)[1:]])).commands
	finally:
		signal.signal(signal.SIGINT, handler)


def test_no_suggestion_mssh_would_run_as_several_commands(monkeypatch):
	# mssh joins the command words into one command only when none of them holds whitespace:
	# `echo hello\ world` runs echo, then `hello world`
	history = [line(NOW - number, '-su', 'web1', '\'echo "hello world"\'') for number in range(5)]
	history += [line(NOW - 100 - number, '-su', 'web2', "'echo hello world'") for number in range(5)]
	shown = 0
	for before in ('mssh web1 ec', 'mssh web1 echo ', 'mssh web1 echo hel', 'mssh web2 ec'):
		ghost = suggest(before, history=history)
		if ghost is not None:
			shown += 1
			assert len(mssh_runs(before + ghost.text, monkeypatch)) == 1, before + ghost.text
	assert shown


def test_commands_with_quoted_words_are_suggested_as_typed(monkeypatch):
	# as mssh records `mssh web1 "systemctl status 'ssh*'"`
	history = [line(NOW - number, '-su', 'web1', multiSSH3._shell_quote("systemctl status 'ssh*'")) for number in range(5)]
	ghost = suggest('mssh web1 sys', history=history)
	assert (ghost.kind, ghost.text) == ('line', "temctl status \\'ssh\\*\\'")
	assert mssh_runs('mssh web1 sys' + ghost.text, monkeypatch) == ["systemctl status 'ssh*'"]
	assert suggest('mssh web1 systemctl status ', history=history).text == "\\'ssh\\*\\'"
	assert suggest('mssh web1 sys', shell='zsh', history=history).text == "temctl status \\'ssh\\*\\'"
