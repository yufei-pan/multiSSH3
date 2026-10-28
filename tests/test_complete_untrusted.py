'''Text from outside (file names, host names, history) never reaches the command line or the screen with a control character in it.'''
import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000
# a newline would run what follows it when Enter is pressed; ESC sequences drive the terminal
EVIL = ['x\nreboot', 'y\x1b]0;owned\x07', 'z\rw', 'v\x9b2J']
# a byte 0x9b that is not UTF-8 (text written in another encoding) is read as U+DC9B
# (surrogateescape) and written back as that byte: CSI on a terminal that takes 8-bit controls
RAW_CSI = 'node\udc9b2Jx'


def control(text):
	return any(ord(char) < 32 or 127 <= ord(char) < 160 or 0xdc80 <= ord(char) < 0xdca0 for char in text)


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


def engine(history):
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	return mc.Engine(SPEC, [memory])


def test_editor_file_names(tmp_path, monkeypatch):
	for name in EVIL + ['plain']:
		(tmp_path / name).write_text('')
	monkeypatch.chdir(tmp_path)
	assert mc.editor_completions(mc.Engine(SPEC, []), 'mssh -f ')[0] == ['plain']


def test_candidates_and_grey_text():
	for evil in EVIL[1:]:
		history = [line(NOW - number, '-su', evil, 'uptime') for number in range(5)]
		for shell in ('bash', 'zsh', 'fish'):
			response = engine(history).query(mc.Request(shell, 'mssh ' + evil[0], '', evil[0]))
			assert not [candidate.text for candidate in response.candidates if control(candidate.text)]
			ghost = engine(history).suggest(mc.Request(shell, 'mssh ' + evil[0], '', ''))
			assert ghost is None or not control(ghost.text)


def test_raw_c1_bytes_are_control_characters():
	assert mc._has_control(RAW_CSI) and mc._printable(RAW_CSI) == 'node?2Jx'
	# other bytes that are not UTF-8 are no control: é written in Latin-1 stays
	assert not mc._has_control('caf\udce9') and mc._printable('caf\udce9') == 'caf\udce9'


def test_raw_c1_bytes_from_history_never_reach_the_shell():
	history = [line(NOW - number, '-su', RAW_CSI, '"uptime"') for number in range(5)]
	for shell in ('bash', 'zsh', 'fish'):
		for before, flags in (('mssh no', {}), ('mssh no', {'ghost': '1'}), ('mssh ', {'ghost': '1'}), ('mssh no', {'insert': '1'})):
			response = engine(history).query(mc.Request(shell, before, '', '' if before.endswith(' ') else 'no', flags=flags))
			assert b'\x9b' not in mc.format_response(response)
	history.append(line(NOW, '-su', 'node1', 'w'))
	request = mc.Request('bash', 'mssh ', '', '', history=['mssh {} w'.format(RAW_CSI)])
	_, _, items, _ = mc.picker_items(request, engine(history), history)
	assert [item.text for item in items] == ['mssh -su node1 w']


def test_picker_history():
	history = [line(NOW, '-su', 'node1', '"echo \x1b[2J"'), line(NOW, '-su', 'node1', 'uptime')]
	request = mc.Request('bash', 'mssh ', '', '', history=['mssh node1 printf "\x1b]0;owned\x07"'])
	_, _, items, _ = mc.picker_items(request, engine(history), history)
	assert [item.text for item in items] == ['mssh -su node1 uptime']


def test_picker_draws_no_control_character():
	# option help shows defaults from the operator's config; the title holds hosts from the line
	evil = 'a\x1b]0;owned\x07b'
	picker = mc.Picker([mc.PickItem('node1', evil), mc.PickItem(evil)], [mc.PickItem('mssh ' + evil)], 'commands for ' + evil, now=NOW, unicode=True)
	for tab in ('slot', 'history'):
		picker.tab = tab
		drawn = ''.join(picker.render(80, 3))
		assert '\x1b]' not in drawn and '\x07' not in drawn


def test_descriptions_sent_to_the_shell_hold_no_control_character():
	response = mc.Response(None)
	response.candidates = [mc.Candidate('node1', 'a\x1b]0;owned\x07b', 'hosts', 1.0)]
	assert '\x1b' not in mc.format_response(response, nul=False).decode()
	# nor warnings about a host typed with a raw C1 byte, which the shell prints under the prompt
	response.diagnostics = [mc.Diagnostic(5, 13, 'unknown', RAW_CSI + ': unknown host')]
	assert b'\x9b' not in mc.format_response(response)


def test_checking_for_control_characters_scans_at_c_speed():
	# the picker checks every history line each time it opens: 20,000 lines took ~130 ms in a Python loop
	import timeit
	text = 'mssh -su gpu[01-16] "nvidia-smi -q -d TEMPERATURE" ' * 40
	ours = min(timeit.repeat(lambda: mc._has_control(text), number=200, repeat=5))
	scan = min(timeit.repeat(lambda: text.isprintable(), number=200, repeat=5))
	assert ours < 10 * scan


def test_text_that_is_not_printable_for_other_reasons_is_not_control():
	assert not mc._has_control('no\xa0break') and not mc._has_control('line separator')
	assert mc._has_control('csi\x9b') and mc._has_control('tab\there') and mc._has_control('del\x7f')
