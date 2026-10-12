'''The Ctrl-R picker: fuzzy filter, keys, drawing below the prompt, and what a choice does to the line.'''
import multiSSH3
import mssh_complete as mc
from vt_grid import FakeTerminal, Grid

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su', 'gpu[01-16]', '"nvidia-smi"') for number in range(5)]
HISTORY += [line(NOW - 3600, '-su -u=root', 'storage1', '"df -h /data"')]


def engine(history=HISTORY):
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	return mc.Engine(SPEC, [memory])


def items(*texts):
	return [mc.PickItem(text) for text in texts]


def test_fuzzy_score_prefers_consecutive_characters_and_word_starts():
	assert mc.fuzzy_score('gpu', 'gpu[01-16]') > mc.fuzzy_score('gpu', 'xgxpxu')
	assert mc.fuzzy_score('df', 'df -h /data') > mc.fuzzy_score('df', 'xdxf')
	assert mc.fuzzy_score('zz', 'gpu') is None
	assert mc.fuzzy_score('df data', 'df -h /data') is not None
	assert mc.fuzzy_score('df zz', 'df -h /data') is None
	assert mc.fuzzy_score('', 'anything') == 0


def test_filter_keeps_matches_and_the_context_rank_breaks_ties():
	picker = mc.Picker(items('login1', 'gpu01', 'gpu02'), [])
	for char in 'gpu':
		picker.handle(char)
	assert [item.text for item in picker.matches()] == ['gpu01', 'gpu02']
	picker.handle('backspace')
	assert picker.query == 'gp'


def test_keys_move_choose_and_cancel():
	picker = mc.Picker(items('a', 'b', 'c'), items('mssh x y'))
	assert picker.handle('down') is None and picker.chosen().text == 'b'
	assert picker.handle('ctrl-r') is None and picker.chosen().text == 'c'
	assert picker.handle('down') is None and picker.chosen().text == 'c'
	assert picker.handle('ctrl-p') is None and picker.chosen().text == 'b'
	assert picker.handle('tab') is None and picker.tab == 'history' and picker.chosen().text == 'mssh x y'
	assert picker.handle('enter') == 'choose'
	assert picker.handle('esc') == 'cancel'
	assert picker.handle('ctrl-g') == 'cancel'


def test_enter_with_nothing_matching_cancels():
	picker = mc.Picker(items('a'), [])
	picker.handle('z')
	assert picker.handle('enter') == 'cancel'


def test_tab_stays_when_the_other_tab_is_empty():
	picker = mc.Picker(items('a'), [])
	picker.handle('tab')
	assert picker.tab == 'slot'


def test_render_shows_title_rows_uses_and_status():
	picker = mc.Picker([mc.PickItem('gpu[01-16]', 'host', uses=12, last=NOW - 7200), mc.PickItem('login1')], items('mssh a b'), 'hosts', now=NOW, unicode=True)
	lines = picker.render(60, 3)
	assert len(lines) == 5
	assert lines[0].startswith('┌ hosts ') and lines[0].endswith(' 1/2 ┐')
	assert 'gpu[01-16]' in lines[1] and 'host  used 12x · 2h ago' in lines[1] and '\x1b[7m' in lines[1]
	assert 'login1' in lines[2] and '\x1b[7m' not in lines[2]
	assert lines[3] == '│' + ' ' * 57 + '│'
	assert 'type to filter · Tab: history · Esc' in lines[4]
	assert all(mc.text_width(text) <= 60 for text in lines)


def test_render_without_unicode_uses_ascii():
	picker = mc.Picker(items('a'), [], 'hosts', unicode=False)
	assert all(ord(char) < 128 for text in picker.render(40, 2) for char in text)


def test_run_draws_below_the_line_and_erases_after():
	grid = Grid(24, 80)
	grid.feed('$ mssh gp')
	term = FakeTerminal(['\x1b[B', '\r'], grid=grid)
	picker = mc.Picker(items('gpu01', 'gpu02'), [], 'hosts')
	assert picker.run(term) == 'choose'
	assert picker.chosen().text == 'gpu02'
	assert grid.lines()[0] == '$ mssh gp' and grid.lines()[1:] == [''] * 23
	assert grid.cursor == (0, 9)


def test_run_shows_the_rows_while_open():
	grid = Grid(24, 80)
	grid.feed('$ mssh gp')
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(grid.lines())
			return FakeTerminal.read_key(self, timeout)

	assert mc.Picker(items('gpu01', 'gpu02'), [], 'hosts').run(Watching(['\x1b'], grid=grid)) == 'cancel'
	assert ' hosts ' in seen[0][1] and 'gpu01' in seen[0][2] and 'gpu02' in seen[0][3]


def test_run_at_the_bottom_scrolls_and_keeps_the_column():
	grid = Grid(24, 80)
	grid.feed('\n' * 23 + '$ mssh gp')
	assert mc.Picker(items('gpu01'), [], 'hosts').run(FakeTerminal(['\x1b'], grid=grid)) == 'cancel'
	assert grid.cursor[1] == 9
	assert grid.line(grid.cursor[0]) == '$ mssh gp'


def test_run_redraws_the_line_bash_cleared_and_ends_at_its_start():
	grid = Grid(24, 80)
	assert mc.Picker(items('gpu01'), [], 'hosts').run(FakeTerminal(['\x1b'], grid=grid), '$ mssh gp x', '$ mssh gp') == 'cancel'
	assert grid.line(0) == '$ mssh gp x'
	assert grid.cursor == (0, 0)


def test_run_on_a_wrapped_line_opens_below_all_of_it():
	grid = Grid(24, 20)
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append((grid.lines(), grid.cursor))
			return FakeTerminal.read_key(self, timeout)

	line = '$ mssh gpu[01-16] nvidia-smi -q'
	assert mc.Picker(items('gpu01'), [], 'hosts').run(Watching(['\x1b'], grid=grid), line, '$ mssh gpu[01-16] ') == 'cancel'
	shown, cursor = seen[0]
	assert shown[:2] == ['$ mssh gpu[01-16] nv', 'idia-smi -q']
	assert ' hosts ' in shown[2] and 'gpu01' in shown[3]
	assert cursor == (0, 18)
	assert grid.lines()[:3] == ['$ mssh gpu[01-16] nv', 'idia-smi -q', '']
	assert grid.cursor == (0, 0)


def test_run_is_unavailable_on_a_tiny_terminal():
	assert mc.Picker(items('a'), []).run(FakeTerminal([], rows=4)) == 'unavailable'


def request(before, after='', history=()):
	return mc.Request('bash', before, after, '', history=list(history))


def test_slot_tab_offers_the_slot_and_a_choice_replaces_the_word():
	req = request('mssh gpu[01-16] nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	assert title == 'commands for gpu[01-16]' and word == 'nv'
	assert slot[0].text == 'nvidia-smi' and slot[0].uses == 5
	picker = mc.Picker(slot, history, title)
	assert mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC)) == ('mssh gpu[01-16] nvidia-smi ', 27)


def test_a_choice_inside_an_open_quote_closes_it():
	req = request('mssh gpu[01-16] "nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	picker = mc.Picker(slot, history, title)
	line, cursor = mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC))
	assert line == 'mssh gpu[01-16] "nvidia-smi" ' and cursor == len(line)


def test_history_tab_never_offers_passwords():
	history = HISTORY + [line(NOW, '-su -p=hunter2', 'gpu[01-16]', '"nvidia-smi"'), line(NOW, '-su --ipmi_password=s3cret', 'bmc1', '"power status"')]
	shell = ['mssh -p hunter2 storage1 uptime', 'mssh --password=hunter2 storage1 w', 'mssh storage1 df']
	_, _, offered, _ = mc.picker_items(request('mssh ', history=shell), engine(history), history, NOW)
	texts = [item.text for item in offered]
	assert 'mssh storage1 df' in texts
	assert not [text for text in texts if 'hunter2' in text or 's3cret' in text]


def test_history_tab_rebuilds_whole_lines_with_the_typed_name():
	# what is typed (-u root) ranks the lines that share it first, then recency
	req = request('multissh -u root ', history=['ls', 'multissh -u admin login1 uptime'])
	_, _, history, _ = mc.picker_items(req, engine(), HISTORY, NOW)
	texts = [item.text for item in history]
	assert texts[0] == 'multissh -su -u=root storage1 "df -h /data"'
	assert 'multissh -su gpu[01-16] "nvidia-smi"' in texts
	assert 'multissh -u admin login1 uptime' in texts and 'ls' not in texts
	assert len(texts) == len(set(texts))
	picker = mc.Picker([], history)
	assert mc.apply_pick(req, picker, None, None) == (texts[0], len(texts[0]))


def run_engine(args, data, env):
	'''Run the engine with no controlling terminal.'''
	import subprocess
	from complete_shell_harness import ENGINE
	return subprocess.run(ENGINE + args, input=data, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, timeout=60)


def test_pick_and_edit_without_a_terminal_step_aside(tmp_path):
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	pick = b'\0'.join([b'MSSHC1', b'bash', b'5.2', b'pick=1', b'mssh gp', b'', b'', b''])
	for data, term in ((pick, 'xterm'), (pick, 'dumb'), (b'not a request', 'xterm')):
		result = run_engine(['pick'], data, dict(env, TERM=term))
		assert (result.returncode, result.stdout, result.stderr) == (2, b'', b'')
	# shell history that is not UTF-8 does not stop it either
	for history in (b'', b'ls\n\xff\xfe\n'):
		edit = run_engine(['edit', 'mssh '], history, env)
		assert (edit.returncode, edit.stdout, edit.stderr) == (3, b'', b'')
