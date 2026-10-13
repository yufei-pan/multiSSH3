'''The plain-bash mssh line editor as a state machine, its drawing, and the bash 4.2/4.3 prompt expander.'''
import pytest

import multiSSH3
import mssh_complete as mc
from vt_grid import FakeTerminal, Grid

GHOST = 'u[01-16] "nvidia-smi"'


def suggester(calls=None):
	'''A suggestion source that knows one line: mssh gpu[01-16] "nvidia-smi".'''
	full = 'mssh gpu[01-16] "nvidia-smi"'

	def suggest(before):
		if calls is not None:
			calls.append(before)
		if full.startswith(before) and len(before) > len('mssh ') and before != full:
			return mc.Ghost('line', full[len(before):], 0.9)
		return None
	return suggest


def editor(text='mssh ', **kwargs):
	kwargs.setdefault('suggest', suggester())
	return mc.LineEditor(text, **kwargs)


def keys(edit, *names):
	'''Apply keys by name ('left', 'tab') or character; the outcome of the last one.'''
	outcome = None
	for name in names:
		outcome = edit.handle(name, name.encode('utf-8') if len(name) == 1 else b'')
	return outcome


def test_typing_inserts_and_asks_for_a_suggestion():
	edit = editor()
	assert keys(edit, 'g', 'p') is None
	assert (edit.text, edit.cursor, edit.ghost) == ('mssh gp', 7, GHOST)


def test_typing_along_the_suggestion_does_not_ask_again():
	calls = []
	edit = editor(suggest=suggester(calls))
	keys(edit, 'g', 'p')
	asked = len(calls)
	keys(edit, 'u', '[')
	assert len(calls) == asked and edit.ghost == '01-16] "nvidia-smi"'


@pytest.mark.parametrize('key', ['right', 'end', 'ctrl-f', 'ctrl-e'])
def test_accept_all(key):
	edit = editor()
	keys(edit, 'g', 'p')
	assert edit.handle(key, b'') is None
	assert (edit.text, edit.cursor) == ('mssh gpu[01-16] "nvidia-smi"', 28)


@pytest.mark.parametrize('key', ['alt-right', 'ctrl-right', 'alt-f'])
def test_accept_a_word(key):
	edit = editor()
	keys(edit, 'g', 'p')
	edit.handle(key, b'')
	assert edit.text == 'mssh gpu[01-16]' and edit.ghost == ' "nvidia-smi"'
	edit.handle(key, b'')
	assert edit.text == 'mssh gpu[01-16] "nvidia-smi"'


@pytest.mark.parametrize('ghost, word', [
	('my\\ file.txt node1', 'my\\ file.txt'), (' "ls -la" x', ' "ls -la"'), (" 'a b'c d", " 'a b'c"), ('-h /data"', '-h'),
])
def test_accept_a_word_keeps_escapes_and_quotes_together(ghost, word):
	edit = editor(suggest=lambda before: mc.Ghost('line', ghost, 0.9) if before == 'mssh -f m' else None)
	keys(edit, '-', 'f', ' ', 'm', 'alt-f')
	assert edit.text == 'mssh -f m' + word


def test_moving_off_the_end_hides_the_suggestion_and_right_moves():
	edit = editor()
	keys(edit, 'g', 'p', 'left')
	assert edit.ghost == '' and edit.cursor == 6
	edit.handle('right', b'')
	assert edit.cursor == 7 and edit.ghost == GHOST


def test_enter_hands_the_typed_line_back():
	edit = editor()
	keys(edit, 'g', 'p')
	assert edit.handle('enter', b'\r') == ('pass', b'\r')
	assert edit.text == 'mssh gp'


def test_ctrl_c_abandons():
	assert editor().handle('ctrl-c', b'\x03') == ('abandon', b'')


@pytest.mark.parametrize('name, raw', [('up', b'\x1b[A'), ('ctrl-k', b'\x0b'), ('ctrl-l', b'\x0c'), ('alt-.', b'\x1b.'), ('unknown', b'\x1b[15~')])
def test_keys_it_does_not_handle_are_passed_on(name, raw):
	edit = editor('mssh x')
	assert edit.handle(name, raw) == ('pass', raw)
	assert edit.text == 'mssh x'


def test_backspace_into_the_prefix_hands_the_line_back():
	edit = editor()
	keys(edit, 'x')
	assert edit.handle('backspace', b'\x7f') is None and edit.text == 'mssh '
	assert edit.handle('backspace', b'\x7f') == ('pass', b'')
	assert (edit.text, edit.cursor) == ('mssh', 4)


def test_moving_left_of_the_prefix_hands_the_line_back():
	edit = editor()
	assert edit.handle('left', b'\x1b[D') == ('pass', b'\x1b[D')


def test_ctrl_u_and_ctrl_w_at_the_prefix_hand_the_line_back():
	edit = editor('mssh ')
	keys(edit, 'a', 'b')
	assert edit.handle('ctrl-u', b'\x15') == ('pass', b'')
	assert (edit.text, edit.cursor) == ('', 0)
	edit = editor('mssh ')
	keys(edit, 'a', 'b')
	assert edit.handle('ctrl-w', b'\x17') is None and edit.text == 'mssh '
	assert edit.handle('ctrl-w', b'\x17') == ('pass', b'\x17')


def test_home_goes_to_the_start_of_the_editors_part():
	edit = editor()
	keys(edit, 'a', 'b', 'home')
	assert edit.cursor == 5


def test_tab_inserts_the_common_part_then_a_space():
	edit = editor(complete=lambda before: (['gpu01', 'gpu02'], 'g'))
	keys(edit, 'g', 'tab')
	assert edit.text == 'mssh gpu0'
	edit = editor(complete=lambda before: (['gpu01'], 'g'))
	keys(edit, 'g', 'tab')
	assert edit.text == 'mssh gpu01 '


def test_tab_ends_a_unique_match_as_the_picker_does():
	# no space after a directory; inside an open quote, the quote is closed first
	edit = editor('mssh -f ', complete=lambda before: (['dir/'], 'di'))
	keys(edit, 'd', 'i', 'tab')
	assert edit.text == 'mssh -f dir/'
	edit = editor('mssh host "', complete=lambda before: (['ls -la'], 'ls -l'))
	keys(edit, 'l', 's', ' ', '-', 'l', 'tab')
	assert edit.text == 'mssh host "ls -la" '


def test_editor_file_names_follow_bash(tmp_path, monkeypatch):
	# like bash's TAB: ~ expanded, [ ] and * read as names, hidden files listed, the result escaped
	for name in ('my file.txt', 'a[1].txt', '.hidden'):
		(tmp_path / name).write_text('')
	(tmp_path / 'sub').mkdir()
	monkeypatch.chdir(tmp_path)
	monkeypatch.setenv('HOME', str(tmp_path))
	engine = mc.Engine(mc.spec_from_parser(multiSSH3.get_parser()), [])

	def texts(before):
		return sorted(mc.editor_completions(engine, before)[0])
	assert texts('mssh -f my') == ['my\\ file.txt']
	assert texts('mssh -f my\\ f') == ['my\\ file.txt']
	assert texts('mssh -f a') == ['a\\[1\\].txt']
	assert texts('mssh -f .h') == ['.hidden']
	assert texts('mssh -f s') == ['sub/']
	assert texts('mssh -f ~/my') == ['~/my\\ file.txt']


def test_editor_tab_inside_an_ansi_c_quote_keeps_the_command():
	# in $'...' a backslash starts an escape: printf "%s\n" x would become printf "%s<newline>" x
	spec = mc.spec_from_parser(multiSSH3.get_parser())
	memory = mc.MemoryKnowledge()
	memory.add_history(['1790000000\t/x/multiSSH3.py\t-su\tnode1\t\'printf "%s\\n" x\'', '1790000000\t/x/multiSSH3.py\t-su\tnode1\t"printf ok"'], spec, 1790000000)
	engine = mc.Engine(spec, [memory])
	assert mc.editor_completions(engine, "mssh node1 $'pri") == (["$'printf ok"], "$'pri")


def test_tab_with_nothing_to_insert_opens_the_slot_menu():
	opened = []

	def pick(text, cursor, slot_only):
		opened.append(slot_only)
		return 'mssh gpu02 ', 11
	edit = editor(complete=lambda before: (['gpu01', 'gpu02'], 'gpu0'), pick=pick)
	keys(edit, 'g', 'p', 'u', '0', 'tab')
	assert opened == [True] and (edit.text, edit.cursor) == ('mssh gpu02 ', 11)
	keys(edit, 'ctrl-r')
	assert opened == [True, False]


def test_run_hands_back_the_ending_key_and_leaves_later_keys_unread():
	term = FakeTerminal(['g', 'x\x1b[Ayz'])
	edit = editor()
	assert edit.run(term, '$ ', '\x1b[2m') == ('pass', b'\x1b[A')
	assert edit.text == 'mssh gx'
	assert [name for name, _ in term.queue] == ['y', 'z']


def test_keys_typed_after_ctrl_r_reach_the_picker_then_the_editor():
	term = FakeTerminal(['\x12\rXY\r'])

	def pick(text, cursor, slot_only):
		picker = mc.Picker([mc.PickItem('gpu01')], [], 'hosts')
		assert picker.run(term) == 'choose'
		return text + 'gpu01 ', len(text) + 6
	edit = editor(pick=pick)
	assert edit.run(term, '$ ', None) == ('pass', b'\r')
	assert edit.text == 'mssh gpu01 XY'


def test_no_suggestion_is_asked_while_more_keys_wait():
	calls = []
	edit = editor(suggest=suggester(calls))
	edit.run(FakeTerminal(['gpu', '\r']), '$ ', None)
	assert calls == ['mssh ', 'mssh gpu']


def test_an_accept_key_in_a_burst_still_takes_the_suggestion():
	edit = editor()
	assert edit.run(FakeTerminal(['gp\x1b[C\r']), '$ ', None) == ('pass', b'\r')
	assert edit.text == 'mssh gpu[01-16] "nvidia-smi"'


def test_draw_shows_grey_text_and_puts_the_cursor_after_the_typed_text():
	grid = Grid(5, 80)
	edit = editor()
	keys(edit, 'g', 'p')
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[38;5;244m')
	assert grid.line(0) == '$ mssh gpu[01-16] "nvidia-smi"'
	styles = grid.styles(0)
	assert styles[8] == '' and styles[9] == '38;5;244' and styles[29] == '38;5;244'
	assert grid.cursor == (0, 9)
	edit.erase(FakeTerminal([], grid=grid))
	assert grid.line(0) == '' and grid.cursor == (0, 0)


def test_draw_without_a_style_shows_no_grey_text():
	grid = Grid(5, 80)
	edit = editor()
	keys(edit, 'g', 'p')
	edit.draw(FakeTerminal([], grid=grid), '$ ', None)
	assert grid.line(0) == '$ mssh gp'


def test_draw_wraps_and_comes_back_to_the_cursor():
	grid = Grid(5, 10)
	edit = editor('mssh 漢字 ')
	edit.ghost = 'abcdef'
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[2m')
	assert grid.lines()[:2] == ['$ mssh 漢', '字 abcdef']
	assert grid.cursor == (1, 3)
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[2m')
	assert grid.lines()[:3] == ['$ mssh 漢', '字 abcdef', '']
	edit.erase(FakeTerminal([], grid=grid))
	assert grid.lines()[:2] == ['', ''] and grid.cursor == (0, 0)


def test_layout_counts_the_line_the_terminal_has_not_wrapped_yet():
	edit = editor('mssh ab')
	assert edit.layout('$ ', 9) == (1, 0, 9, 9)


def test_expand_prompt_does_what_bash_does_for_common_escapes():
	environ = {'USER': 'ops', 'HOME': '/home/ops', 'PWD': '/home/ops/src', 'BASH_VERSION': '4.2.46(2)-release'}
	text = mc.expand_prompt('\\[\\e[1m\\]\\u:\\w \\W \\v\\033[0m\\$ $(date)', environ)
	assert text == '\x01\x1b[1m\x02ops:~/src src 4.2\x1b[0m{} $(date)'.format('#' if mc.os.geteuid() == 0 else '$')


def test_expand_prompt_takes_only_octal_digits():
	# as bash: \\128 and \\9ab stay as written, \\101 is A
	assert mc.expand_prompt('\\128 \\9ab \\101$ ', {'HOME': '/h', 'PWD': '/h'}) == '\\128 \\9ab A$ '


@pytest.mark.parametrize('raw, keyseq', [
	(b'\x1b[A', '\\e[A'), (b'"\\', '\\"\\\\'), (b'\r', '\\C-m'), (b'\x7f', '\\C-?'),
	('é'.encode('utf-8'), '\\303\\251'), (b'', ''),
])
def test_readline_keyseq(raw, keyseq):
	assert mc.readline_keyseq(raw) == keyseq


UNKNOWN = [mc.Diagnostic(5, 11, 'unknown', 'gpu017: unknown host')]


@pytest.fixture
def warning_terminal(monkeypatch):
	monkeypatch.delenv('NO_COLOR', raising=False)
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)


@pytest.mark.parametrize('no_color, style', [(False, '4;31'), (True, '4')])
def test_a_warning_underlines_its_span_and_explains_below(warning_terminal, monkeypatch, no_color, style):
	if no_color:
		monkeypatch.setenv('NO_COLOR', '1')
	edit = editor('mssh gpu017 ', diagnose=lambda text, cursor: (UNKNOWN, False))
	term = FakeTerminal([])
	edit.refresh_warnings()
	edit.draw(term, '$ ', None)
	assert term.grid.lines()[:2] == ['$ mssh gpu017', '⚠ gpu017: unknown host']
	assert [column for column, cell in enumerate(term.grid.styles(0)) if cell] == list(range(7, 13))
	assert term.grid.styles(0)[7] == style and term.grid.cursor == (0, 14)
	edit.erase(term)
	assert term.grid.lines()[:2] == ['', '']


def test_while_the_prober_works_the_editor_asks_again(warning_terminal):
	answers = [([], True), ([], True), (UNKNOWN, False)]
	asked = []
	seen = []

	def diagnose(text, cursor):
		asked.append(text)
		return answers.pop(0) if answers else (UNKNOWN, False)

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(self.grid.lines()[1])
			return FakeTerminal.read_key(self, timeout)

	term = Watching([None, None, '\r'])
	assert editor('mssh gpu017 ', diagnose=diagnose).run(term, '$ ') == ('pass', b'\r')
	# at 0.3 s and 1 s after the first answer (the fake terminal lets no time pass); the third answer is
	# not pending, so the editor waits for keys
	assert len(asked) == 3 and term.timeouts == [pytest.approx(0.3, abs=0.1), pytest.approx(1.0, abs=0.1)]
	assert seen[-1] == '⚠ gpu017: unknown host'


def test_no_warnings_are_asked_for_while_keys_wait(warning_terminal):
	asked = []
	edit = editor('mssh ', diagnose=lambda text, cursor: (asked.append((text, cursor)) or ([], False)))
	assert edit.run(FakeTerminal(['abc', '\r']), '$ ') == ('pass', b'\r')
	assert asked == [('mssh ', 5), ('mssh abc', 8)]
