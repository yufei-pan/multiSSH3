'''The Ctrl-R picker: fuzzy filter, keys, drawing below the prompt, and what a choice does to the line.'''
import pytest

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


FLAGS = mc.flag_settings(multiSSH3.get_parser())


def shell_engine(history, shell, defaults=None):
	'''An engine as the shells get one: mssh's history, the shell's lines of the request, mssh's flags.'''
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	built = mc.Engine(SPEC, [memory, mc.shell_history_knowledge(shell, SPEC)])
	built.flag_sets, built.flag_defaults = FLAGS[0], dict(FLAGS[1], **(defaults or {}))
	return built


def offered(history, shell, before='mssh ', defaults=None):
	'''The picker's slot rows and history rows as (text, uses).'''
	built = shell_engine(history, shell, defaults)
	slot, _, rows, _ = mc.picker_items(request(before, history=shell), built, history, NOW)
	return [(item.text, item.uses) for item in slot], [(item.text, item.uses) for item in rows]


def runs(count, options, hosts, command):
	'''count runs as mssh records them, a minute apart, the newest last.'''
	return [line(NOW - 60 * (count - number), options, hosts, command) for number in range(count)]


def test_a_run_in_both_histories_is_used_once():
	# mssh records `mssh gpu[01-16] nvidia-smi` its own way (short options, -su always, its quoting);
	# the shell keeps the line as typed: one run all the same
	assert offered(runs(1, '-su', "'gpu[01-16]'", 'nvidia-smi'), ['mssh gpu[01-16] nvidia-smi']) == (
		[('gpu[01-16]', 1)], [("mssh -su 'gpu[01-16]' nvidia-smi", 1)])


def test_each_run_is_counted_once():
	history = runs(3, '-su', "'gpu[01-16]'", 'nvidia-smi')
	expected = ([('gpu[01-16]', 3)], [("mssh -su 'gpu[01-16]' nvidia-smi", 3)])
	assert offered(history, ['mssh gpu[01-16] nvidia-smi'] * 3) == expected
	# the shell may keep fewer of them (ignoredups, its tail), or more: runs mssh's history no longer holds
	assert offered(history, ['mssh gpu[01-16] nvidia-smi']) == expected
	assert offered(history[-1:], ['mssh gpu[01-16] nvidia-smi'] * 3) == expected


def test_a_line_mssh_did_not_record_counts_each_time():
	# mssh records no -I run: the shell's history is all there is
	assert offered([], ['mssh -I login1 w'] * 2) == ([('login1', 2)], [('mssh -I login1 w', 2)])


def test_runs_only_the_shell_holds_count_with_the_history_tab_full(monkeypatch):
	# HISTORY_LIMIT bounds the rows, not the uses
	monkeypatch.setattr(mc, 'HISTORY_LIMIT', 2)
	history = runs(1, '-su', 'node1', 'uptime') + runs(1, '-su', 'node2', 'uptime') + runs(1, '-su', 'node1', 'df')
	slot, rows = offered(history, ['mssh -I login1 w'] * 2 + ['mssh node1 df'])
	assert ('login1', 2) in slot and ('node1', 2) in slot
	assert rows == [('mssh -su node1 df', 1), ('mssh -su node2 uptime', 1)]


def test_spellings_of_one_run_are_one_row():
	# the program's name and path, option spellings, their order and quoting
	shell = ['mssh3 -u root -t 5 storage1 "df -h /data"', "multissh storage1 --timeout=5 --username root 'df -h /data'",
		'/usr/local/bin/mssh -t5 -u=root storage1 df\\ -h\\ /data']
	assert offered(runs(3, '-u=root -t=5 -su', 'storage1', "'df -h /data'"), shell) == (
		[('storage1', 3)], [("mssh -u=root -t=5 -su storage1 'df -h /data'", 3)])
	# mssh runs unquoted words as one command
	assert offered(runs(1, '-su', 'node1', "'df /data'"), ['mssh node1 df /data'])[1] == [("mssh -su node1 'df /data'", 1)]


def test_runs_that_differ_stay_apart():
	history = runs(1, '-nsu', 'node1', 'uptime') + runs(1, '-su', 'node1', 'uptime')
	slot, rows = offered(history, ['mssh -nsu node1 uptime', 'mssh node1 uptime', 'mssh -q node1 uptime'])
	assert slot == [('node1', 3)]
	assert rows == [('mssh -su node1 uptime', 1), ('mssh -nsu node1 uptime', 1), ('mssh -q node1 uptime', 1)]
	# with -nsu the default of mssh's config, mssh records it on every line
	assert offered(runs(1, '-nsu', 'node1', 'uptime'), ['mssh node1 uptime'], defaults={'skip_unreachable': False})[1] == [
		('mssh -nsu node1 uptime', 1)]


# runs as typed, then as mssh 6.31 and as later versions record them (main() up to the history line):
# 6.31 left many options out; both fold -uk and -k DIR into the key found, -s PATH into -f PATH -fs;
# later versions record -T as -t=50 and --config_file absolute
FOLDED_RUNS = [
	('mssh -T node1 uptime', '-su', '-t=50 -su', 'uptime'),
	('mssh -uk node1 uptime', "-k='~/.ssh/id_ed25519' -su", "-k='~/.ssh/id_ed25519' -su", 'uptime'),
	('mssh --host_file hosts.txt node1 uptime', '-su', '-su --host_file=hosts.txt', 'uptime'),
	('mssh -w node1 uptime', '-su', '-su -w', 'uptime'),
	('mssh --config_file c.json node1 uptime', '-su', '-su --config_file=/home/u/c.json', 'uptime'),
	('mssh -s /tmp/x node1', '-f=/tmp/x -su -fs', '-f=/tmp/x -fs -su', ''),
	('mssh -k ~/.ssh/ node1 uptime', "-k='~/.ssh/id_ed25519' -su", "-k='~/.ssh/id_ed25519' -su", 'uptime'),
	('mssh -t 50 node1 uptime', '-su', '-t=50 -su', 'uptime'),
	('mssh -m 0 node1 uptime', '-su', '-m=0 -su', 'uptime'),
]


@pytest.mark.parametrize('version', [1, 2], ids=['6.31', 'later'])
def test_runs_mssh_records_in_another_form_are_used_once(version):
	history = [line(NOW - 60 * (len(FOLDED_RUNS) - number), run[version], 'node1', run[3]) for number, run in enumerate(FOLDED_RUNS)]
	slot, rows = offered(history, [run[0] for run in FOLDED_RUNS])
	assert slot == [('node1', len(FOLDED_RUNS))]
	recorded = {}
	for run in FOLDED_RUNS:
		text = ' '.join(part for part in ('mssh', run[version], 'node1', run[3]) if part)
		recorded[text] = recorded.get(text, 0) + 1
	assert sorted(rows) == sorted(recorded.items())


def test_a_line_counts_towards_its_own_record_first():
	# mssh may record a timeout differently (6.31 left -t 50 out), but a record of this one is this run
	history = [line(NOW - 120, '-t=5 -su', 'node1', 'uptime'), line(NOW - 60, '-t=10 -su', 'node1', 'uptime')]
	assert offered(history, ['mssh -t 5 node1 uptime'] * 3)[1] == [('mssh -t=10 -su node1 uptime', 1), ('mssh -t=5 -su node1 uptime', 3)]
	# runs only the shell's history holds stay apart however little they differ
	_, rows = offered([], ['mssh -I -t 5 node1 uptime', 'mssh -I -t 10 node1 uptime', 'mssh -I -k /k/a node1 uptime', 'mssh -I --host_file a node1 uptime'])
	assert len(rows) == 4


def test_local_commands_are_not_mssh_uses():
	slot, _ = offered(runs(1, '-su', 'node1', 'uptime'), ['uptime', 'uptime', 'mssh node1 uptime'], 'mssh node1 up')
	assert slot == [('uptime', 1)]


def test_a_line_typed_many_times_is_read_once(monkeypatch):
	lex = mc.lex
	parsed = []
	monkeypatch.setattr(mc, 'lex', lambda text: parsed.append(text) or lex(text))
	mc.picker_items(request('mssh ', history=['mssh node1 uptime'] * 500), engine(), [], NOW)
	assert parsed.count('mssh node1 uptime') == 1


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


@pytest.mark.parametrize('shell', ['zsh', 'fish'])
def test_slot_items_inside_an_open_quote_in_every_shell(shell):
	# zsh and fish send the word as typed, quote included: the picker must too (here it ends in a space)
	before = 'mssh storage1 "df '
	bash = mc.picker_items(mc.Request('bash', before, '', None), engine(), HISTORY)
	other = mc.picker_items(mc.Request(shell, before, '', None), engine(), HISTORY)
	assert [item.text for item in bash[0]] == ['df -h /data']
	assert [item.text for item in other[0]] == ['df -h /data'] and other[3] == bash[3]


WARNINGS = ['gpu017: unknown host — did you mean gpu17?', 'node05: unreachable in a recent mssh run', '-nsu cannot be used with -su', 'one more']


def test_render_lists_up_to_three_warnings_under_the_title():
	picker = mc.Picker(items('gpu01', 'gpu02'), [], 'hosts', now=NOW, unicode=True, warnings=WARNINGS)
	lines = picker.render(60, 2)
	assert len(lines) == 1 + 3 + 2 + 1
	assert lines[1].startswith('│ ⚠ gpu017: unknown host') and lines[3].startswith('│ ⚠ -nsu cannot') and 'one more' not in ''.join(lines)
	assert 'gpu01' in lines[4] and all(mc.text_width(text) <= 60 for text in lines)
	assert mc.Picker(items('gpu01'), [], 'hosts', unicode=False, warnings=WARNINGS[:1]).render(60, 1)[1].startswith('| ! gpu017')


def test_run_makes_room_for_the_warnings():
	grid = Grid(24, 80)
	grid.feed('$ mssh gpu017 ')
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(grid.lines())
			return FakeTerminal.read_key(self, timeout)

	picker = mc.Picker(items('nvidia-smi'), [], 'commands', unicode=True, warnings=WARNINGS[:1])
	assert picker.run(Watching(['\x1b'], grid=grid)) == 'cancel'
	assert ' commands ' in seen[0][1] and 'gpu017: unknown host' in seen[0][2] and 'nvidia-smi' in seen[0][3]
	assert grid.lines()[1:] == [''] * 23


@pytest.mark.parametrize('unicode, expected', [(True, '⚠ a (+2 more)'), (False, '! a (+2 more)')])
def test_reason_line_shows_the_first_warning_and_counts_the_rest(unicode, expected):
	found = [mc.Diagnostic(0, 1, 'unknown', 'a'), mc.Diagnostic(2, 3, 'range', 'b'), mc.Diagnostic(4, 5, 'options', 'c')]
	assert mc.reason_line(found, unicode) == expected
	assert mc.reason_line(found[:1], unicode) == expected[:3]
	assert mc.reason_line([], unicode) == ''


def test_picker_warnings_come_from_the_line(tmp_path, monkeypatch):
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: True)
	warned = engine()
	warned.directory = str(tmp_path)
	mc.write_host_states(str(tmp_path), {'gpu017': mc.HostState('invalid', NOW)})
	assert mc.picker_warnings(warned, mc.Request('bash', 'mssh gpu017 ', '', '')) == ['gpu017: unknown host']


def test_history_past_what_the_picker_shows_is_not_parsed(monkeypatch):
	# the history tab holds HISTORY_LIMIT entries: older lines (thousands on a cluster) are skipped unparsed.
	# The shell's lines are all read (they count as uses): the shell sends a bounded tail
	monkeypatch.setattr(mc, 'HISTORY_LIMIT', 10)
	lex = mc.lex
	shell = ['mssh -su host{} date'.format(number) for number in range(20)]

	def parses(count):
		history = [line(NOW - number, '-su', 'node{}'.format(number), 'uptime') for number in range(count)]
		built = engine()
		parsed = []
		monkeypatch.setattr(mc, 'lex', lambda text: parsed.append(text) or lex(text))
		_, _, items, _ = mc.picker_items(request('mssh ', history=shell), built, history)
		monkeypatch.setattr(mc, 'lex', lex)
		assert len(items) == 10
		return len(parsed)
	assert parses(2000) == parses(20)
