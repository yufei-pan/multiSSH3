'''Text from outside (file names, host names, history) never reaches the command line or the screen with a control character in it.'''
import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000
# a newline would run what follows it when Enter is pressed; ESC sequences drive the terminal
EVIL = ['x\nreboot', 'y\x1b]0;owned\x07', 'z\rw', 'v\x9b2J']


def control(text):
	return any(ord(char) < 32 or 127 <= ord(char) < 160 for char in text)


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


def test_picker_history():
	history = [line(NOW, '-su', 'node1', '"echo \x1b[2J"'), line(NOW, '-su', 'node1', 'uptime')]
	shell = ['mssh node1 printf "\x1b]0;owned\x07"', 'mssh node1 w']
	request = mc.Request('bash', 'mssh ', '', '', history=shell)
	_, _, items, _ = mc.picker_items(request, engine(history), history)
	assert sorted(item.text for item in items) == ['mssh -su node1 uptime', 'mssh node1 w']
