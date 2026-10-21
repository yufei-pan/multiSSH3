'''The Ctrl-R picker: fuzzy filter, keys, drawing below the prompt, and what a choice does to the line.'''
import sys
import time

import pytest

import multiSSH3
import mssh_complete as mc
from vt_grid import FakeTerminal, Grid, Resize

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


@pytest.mark.parametrize('burst', ['\x1b', '\x1b\x1b', '\x1b[27u', '\x1b[27;1u', '\x1b[27;1;27~', '\x1b[27;3u'])
def test_run_cancels_on_esc_however_the_terminal_sends_it(burst):
	# a lone Esc; two at once (a double press over ssh or mosh, Alt+Esc); the kitty keyboard
	# protocol's CSI u; xterm's modifyOtherKeys
	assert mc.Picker(items('gpu01', 'gpu02'), [], 'hosts').run(FakeTerminal([burst])) == 'cancel'


def test_run_takes_keys_sent_as_csi_u():
	picker = mc.Picker(items('gpu01', 'gpu02', 'gpu03'), items('mssh x y'), 'hosts')
	# Ctrl-R and Ctrl-N move down, Ctrl-P up, Enter chooses (the kitty protocol, flags 1 and 8)
	assert picker.run(FakeTerminal(['\x1b[114;5u', '\x1b[110;5u', '\x1b[112;5u', '\x1b[13u'])) == 'choose'
	assert picker.chosen().text == 'gpu02'
	# Tab switches, typing filters, Backspace edits the filter, Ctrl-G cancels
	picker = mc.Picker(items('gpu01'), items('mssh x y', 'mssh z'), 'hosts')
	assert picker.run(FakeTerminal(['\x1b[9u', '\x1b[122u', '\x1b[120u', '\x1b[127u', '\x1b[103;5u'])) == 'cancel'
	assert (picker.tab, picker.query) == ('history', 'z')
	assert picker.run(FakeTerminal(['\x1b[99;5u'])) == 'cancel'


def test_run_on_a_wrapped_line_draws_again_below_all_of_it():
	# between draws the cursor is in the line, on its first row here: the next draw starts below the line
	grid = Grid(24, 20)
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(grid.lines())
			return FakeTerminal.read_key(self, timeout)

	line = '$ mssh gpu[01-16] nvidia-smi -q'
	assert mc.Picker(items('gpu01', 'gpu02'), [], 'hosts').run(Watching(['\x1b[B', '\x1b'], grid=grid), line, '$ mssh gpu[01-16] ') == 'cancel'
	shown = seen[1]
	assert shown[:2] == ['$ mssh gpu[01-16] nv', 'idia-smi -q']
	assert ' 2/2 ' in shown[2] and '> gpu02' in shown[4] and shown[2 + 1 + 10].startswith('└') and shown[2 + 1 + 10 + 1] == ''


@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_run_opens_again_at_the_new_size(shell):
	# bash cleared the line, so the picker draws it; zsh left it on screen, the cursor in it
	grid = Grid(24, 80)
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append((grid.lines(), grid.cursor))
			return FakeTerminal.read_key(self, timeout)

	picker = mc.Picker(items('gpu01', 'gpu02'), [], 'hosts', unicode=True)
	term = Watching([Resize(24, 30), '\x1b'], grid=grid)
	if shell == 'bash':
		assert picker.run(term, '$ mssh gp x', '$ mssh gp') == 'cancel'
	else:
		grid.feed('$ mssh gp x\x1b[2D')
		assert picker.run(term) == 'cancel'
	shown, cursor = seen[1]
	assert shown[0] == '$ mssh gp x' and cursor == (0, 9)
	box = shown[1:13]
	assert box[0].startswith('┌ hosts ') and box[0].endswith('┐') and box[-1].startswith('└') and box[-1].endswith('┘')
	assert len(set(len(row) for row in box)) == 1 and len(box[0]) < 30 and '> gpu01' in box[1]
	assert shown[13:] == [''] * 11
	# closed: the line alone, and the cursor where the shell redraws it
	assert grid.lines() == ['$ mssh gp x'] + [''] * 23
	assert grid.cursor == ((0, 0) if shell == 'bash' else (0, 9))


def test_run_cancels_when_the_terminal_gets_too_small():
	grid = Grid(24, 80)
	assert mc.Picker(items('gpu01'), [], 'hosts').run(FakeTerminal([Resize(24, 15)], grid=grid), '$ mssh gp', '$ mssh gp') == 'cancel'
	assert grid.lines() == ['$ mssh gp'] + [''] * 23 and grid.cursor == (0, 0)


def test_run_is_unavailable_on_a_tiny_terminal():
	assert mc.Picker(items('a'), []).run(FakeTerminal([], rows=4)) == 'unavailable'


# A line break that chooses in the middle of a paste leaves the rest of the paste to the shell, which
# runs it (its own line breaks are Enter there): a paste only ever filters.

def test_a_paste_filters_and_never_chooses():
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	term = FakeTerminal(['\x1b[200~stor\r\necho INJECTED\n\x1b[201~', '\x1b'])
	assert picker.run(term) == 'cancel'
	# line breaks and runs of white space are one space: words for the filter
	assert picker.query == 'stor echo INJECTED '


def test_a_pasted_line_with_its_line_break_waits_for_enter():
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	term = FakeTerminal(['\x1b[200~stor\n\x1b[201~', '\r'])
	assert picker.run(term) == 'choose'
	assert picker.query == 'stor ' and picker.chosen().text == 'storage1'


def test_a_paste_adds_to_the_filter_without_control_characters():
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(FakeTerminal(['gp', '\x1b[200~u\x1b[A\x03\t01\x1b[201~', '\x1b'])) == 'cancel'
	assert picker.query == 'gpu 01'


def test_a_long_paste_is_cut_for_the_filter():
	# the filter is matched against every row at every key: a whole file pasted would freeze it
	picker = mc.Picker(items('gpu01'), [], 'hosts')
	assert picker.run(FakeTerminal(['\x1b[200~' + 'gpu ' * 5000 + '\x1b[201~', '\x1b'])) == 'cancel'
	assert len(picker.query) == mc.PICKER_FILTER_LIMIT


@pytest.mark.parametrize('paste', ['stor\recho INJECTED\r', 'stor\r\r', '\recho INJECTED\r', 'stor\r\necho INJECTED\r\n'])
def test_a_paste_the_terminal_does_not_mark_never_chooses(paste):
	# bracketed paste off (bash before 5.1; fish 4 and ble.sh turn it off while the picker runs): a line
	# break with another one in the keys right behind it is in a paste, and all of them filter
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(FakeTerminal([paste, '\x1b'])) == 'cancel'
	assert picker.query.split() == paste.split()


@pytest.mark.parametrize('enter', ['\r', '\r\n', '\r\x00'])
def test_enter_chooses_however_the_terminal_sends_it(enter):
	# CR LF (newline mode, serial consoles set to send it) and CR NUL (telnet) are one Enter: the LF
	# is not left for the shell, where it would run the line
	term = FakeTerminal(['st', enter])
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(term) == 'choose'
	assert picker.chosen().text == 'storage1' and picker.typed_after == '' and term.queue == []


def test_keys_typed_right_after_enter_follow_the_choice():
	# a fast typist's next keys, or keys a slow link brought with the Enter: no line break among them,
	# so no paste. Their text goes after the choice, where the shell would have put it
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(FakeTerminal(['st', '\r-x\x1b[A'])) == 'choose'
	assert picker.chosen().text == 'storage1' and picker.typed_after == '-x'


def test_enter_typed_alone_chooses():
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(FakeTerminal(['s', 't', '\r'])) == 'choose'
	assert picker.chosen().text == 'storage1'


def test_enter_typed_ahead_after_the_filter_chooses():
	# typed before the picker was ready: nothing comes after the line break
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(FakeTerminal([], typed_ahead='st\r')) == 'choose'
	assert picker.chosen().text == 'storage1'


def test_enter_typed_ahead_first_chooses_and_leaves_the_keys_after_it():
	term = FakeTerminal([], typed_ahead='\rXY')
	picker = mc.Picker(items('gpu01', 'storage1'), [], 'hosts')
	assert picker.run(term) == 'choose'
	assert picker.chosen().text == 'gpu01' and [name for name, _ in term.queue] == ['X', 'Y']


def request(before, after='', history=()):
	return mc.Request('bash', before, after, '', history=list(history))


def test_slot_tab_offers_the_slot_and_a_choice_replaces_the_word():
	req = request('mssh gpu[01-16] nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	assert title == 'commands for gpu[01-16]' and word == 'nv'
	assert slot[0].text == 'nvidia-smi' and slot[0].uses == 5
	picker = mc.Picker(slot, history, title)
	assert mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC)) == ('mssh gpu[01-16] nvidia-smi ', 27)


def test_keys_typed_right_after_the_choice_are_in_the_new_line():
	req = request('mssh gpu[01-16] nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	picker = mc.Picker(slot, history, title)
	picker.typed_after = '-q'
	assert mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC)) == ('mssh gpu[01-16] nvidia-smi -q', 29)


def test_a_choice_inside_an_open_quote_closes_it():
	req = request('mssh gpu[01-16] "nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	picker = mc.Picker(slot, history, title)
	line, cursor = mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC))
	assert line == 'mssh gpu[01-16] "nvidia-smi" ' and cursor == len(line)


def test_a_choice_inside_an_ansi_c_quote_keeps_the_command():
	# in $'...' a backslash starts an escape: printf "%s\n" x would become printf "%s<newline>" x
	history = [line(NOW - number, '-su', 'node1', '\'printf "%s\\n" x\'') for number in range(3)] + [line(NOW - 10, '-su', 'node1', '"printf ok"')]
	req = request("mssh node1 $'pri")
	slot, title, items, word = mc.picker_items(req, engine(history), history, NOW)
	assert [item.text for item in slot] == ['printf ok']
	line_after, _ = mc.apply_pick(req, mc.Picker(slot, items, title), word, mc.parse_context(req.before, req.after, SPEC))
	assert line_after == "mssh node1 $'printf ok' "


def test_history_tab_never_offers_passwords():
	history = HISTORY + [line(NOW, '-su -p=hunter2', 'gpu[01-16]', '"nvidia-smi"'), line(NOW, '-su --ipmi_password=s3cret', 'bmc1', '"power status"')]
	shell = ['mssh -p hunter2 storage1 uptime', 'mssh --password=hunter2 storage1 w', 'mssh storage1 df']
	_, _, offered, _ = mc.picker_items(request('mssh ', history=shell), engine(history), history, NOW)
	texts = [item.text for item in offered]
	assert 'mssh storage1 df' in texts
	assert not [text for text in texts if 'hunter2' in text or 's3cret' in text]


def test_options_slot_never_shows_a_configured_password(monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_PASSWORD', "Hunter2 pa%ss it's")
	monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_PASSWORD', 'Bmc 100% s3cret')
	spec = mc.spec_from_parser(multiSSH3.get_parser())
	for before in ('mssh -', 'mssh -p', 'mssh --ipmi_p'):
		slot, title, history, _ = mc.picker_items(request(before), mc.Engine(spec, []), [], NOW)
		assert title == 'options' and slot
		shown = [item.text + ' ' + item.description for item in slot]
		shown += mc.Picker(slot, history, title, now=NOW, unicode=True).render(200, len(slot))
		assert not [text for text in shown if 'Hunter2' in text or 's3cret' in text], before


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


def test_runs_past_the_history_tab_are_not_counted_twice(monkeypatch):
	# mssh's history past HISTORY_LIMIT is not read, but its index counts the runs there: only a line
	# mssh never records here (-I, --script, another history file) is a run of its own
	monkeypatch.setattr(mc, 'HISTORY_LIMIT', 2)
	history = runs(1, '-su', 'node1', 'uptime') + runs(1, '-su', 'node2', 'uptime') + runs(1, '-su', 'node3', 'df')
	shell = ['mssh node1 uptime', 'mssh --script node1 w', 'mssh -hf /tmp/h node1 w', 'mssh node3 df']
	assert offered(history, shell)[0] == [('node1', 3), ('node3', 1), ('node2', 1)]


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
	mc.picker_items(request('mssh ', history=['mssh node1 uptime', 'ls -la /tmp'] * 500), engine(), [], NOW)
	assert parsed.count('mssh node1 uptime') == 1
	# a line that cannot run mssh is not read at all
	assert 'ls -la /tmp' not in parsed


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_history_tab_takes_a_bang_out_of_double_quotes(shell):
	# mssh 6.26 and older recorded commands in double quotes, where bash and zsh expand ! when the line runs
	history = [line(NOW, '-su', 'web1', '"grep !important /etc/x"')]
	req = mc.Request(shell, 'mssh ', '', '')
	_, _, offered, _ = mc.picker_items(req, engine(history), history, NOW)
	recorded = 'mssh -su web1 "grep !important /etc/x"'
	assert [item.text for item in offered] == [recorded]
	inserted = recorded if shell == 'fish' else 'mssh -su web1 "grep "\\!"important /etc/x"'
	assert mc.apply_pick(req, mc.Picker([], offered), None, None) == (inserted, len(inserted))


@pytest.mark.parametrize('text, moved', [
	('mssh h "grep !x f"', 'mssh h "grep "\\!"x f"'),
	('mssh h "echo done!"', 'mssh h "echo done"\\!'),
	('mssh h "!x" "a!!b"', 'mssh h \\!"x" "a"\\!\\!"b"'),
	('mssh h "a\\"!b"', 'mssh h "a\\""\\!"b"'),
	# bash reads $"..." as "..." (translated), zsh as $ and "...": the quote after $ is never taken back
	('mssh h $"!x"', 'mssh h $""\\!"x"'),
	# never expanded: in single quotes, in $'...', escaped, before a blank or =, and $!
	("mssh h 'a!b' $'c!d' e\\!f", None),
	('mssh h "a != b" "a!=b" "$!"', None),
	# expansions read the quotes inside them again
	('mssh h "${!name}" "${x:-a!b}" "$(echo a!b)" "`echo a!b`"', None),
])
def test_bangs_out_of_double_quotes(text, moved):
	moved = text if moved is None else moved
	assert mc.bangs_out_of_double_quotes(text) == moved
	# the words are what they were
	assert [token.text for token in mc.lex(moved)] == [token.text for token in mc.lex(text)]


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


def start_on_a_terminal(args, data, env, listening, command=None, stderr=None):
	'''
	Start the engine with a pseudo-terminal as its controlling terminal, the request on stdin and
	stdout a pipe; listening False: nobody reads that pipe any more (the shell stopped waiting).
	data None: stdin is /dev/null. command: the engine command to run (default ENGINE); stderr: where
	its stderr goes (default /dev/null). Returns (process, the terminal's master side, the pipe's read end or None).
	'''
	import os
	import pty
	import subprocess
	from complete_shell_harness import ENGINE
	master, slave = pty.openpty()
	name = os.ttyname(slave)
	read_end, write_end = os.pipe()
	# a new session that opens the terminal gets it as its controlling terminal
	process = subprocess.Popen((ENGINE if command is None else command) + args, stdin=subprocess.DEVNULL if data is None else subprocess.PIPE,
		stdout=write_end, stderr=subprocess.DEVNULL if stderr is None else stderr, env=env, start_new_session=True, preexec_fn=lambda: os.close(os.open(name, os.O_RDWR)))
	os.close(write_end)
	os.close(slave)
	if not listening:
		os.close(read_end)
		read_end = None
	if data is not None:
		process.stdin.write(data)
		process.stdin.close()
	return process, master, read_end


def terminal_output(fd, seconds, until=None):
	'''What the program wrote to fd (the terminal, or a pipe) in that many seconds, or until it wrote until.'''
	import os
	import select
	out = b''
	end = time.monotonic() + seconds
	while time.monotonic() < end and not (until and until in out):
		if select.select([fd], [], [], 0.05)[0]:
			try:
				chunk = os.read(fd, 1 if until else 65536)
			except OSError:
				break
			if not chunk:
				break
			out += chunk
	return out


READY_PICK = b'\0'.join([b'MSSHC1', b'bash', b'5.2', b'pick=1 ready=1 redraw=1 expand=0 term=xterm', b'mssh gpu[01-16] ', b'', b'', b''])


@pytest.mark.parametrize('args, data', [(['pick'], READY_PICK), (['edit', '--ready', '--', 'mssh '], b'')], ids=['pick', 'edit'])
def test_pick_and_edit_say_ready_before_they_take_the_terminal(tmp_path, args, data):
	import os
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	process, master, read_end = start_on_a_terminal(args, data, env, listening=True)
	try:
		first = terminal_output(read_end, 5.0, until=b'\n')
		# until it drew: a second was too little while other tests loaded the machine
		expected = b'type to filter' if args[0] == 'pick' else b'mssh '
		drawn = terminal_output(master, 5.0, until=expected)
		assert first == b'ready\n' and expected in drawn
		os.write(master, b'\x1b' if args[0] == 'pick' else b'\r')
		assert process.wait(10) in (0, 1)
	finally:
		process.kill()
		os.close(master)
		os.close(read_end)


@pytest.mark.parametrize('args, data, status', [(['pick'], READY_PICK, 2), (['edit', '--ready', '--', 'mssh '], b'', 3)], ids=['pick', 'edit'])
def test_pick_and_edit_leave_the_terminal_alone_when_nobody_waits_any_more(tmp_path, args, data, status):
	# the shell gave up on an engine slow to start: drawing now would fight readline for the terminal
	import os
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	process, master, _ = start_on_a_terminal(args, data, env, listening=False)
	try:
		assert process.wait(10) == status
		assert terminal_output(master, 0.3) == b''
	finally:
		process.kill()
		os.close(master)


# the engine run with a function of its replaced first: python -I -c CODE REPO ARGS...
PATCHED_ENGINE = ('import sys; sys.path.insert(0, sys.argv[1]); import mssh_complete as mc; '
	'exec(sys.argv[2]); sys.exit(mc.main(sys.argv[3:]))')


def patched_engine(patch, ascii_locale=False):
	'''The engine command with patch run first (python code, mc the module); ascii_locale: in C, not in UTF-8 mode.'''
	import os
	return [sys.executable, '-I'] + (['-X', 'utf8=0'] if ascii_locale else []) + ['-c', PATCHED_ENGINE, os.path.dirname(mc.__file__), patch]


@pytest.mark.parametrize('debug', ['1', '0'])
def test_edit_delivers_its_answer_whatever_its_debug_messages_do(tmp_path, debug):
	# _without_passwords made the editor's debug messages, debug on or off: raising before the editor ran it
	# fell back to pass, and after the answer was written it made the exit status 1, so the glue dropped the line
	import os
	import subprocess
	from complete_shell_harness import make_home, with_debug_log
	env, _ = make_home(tmp_path, HISTORY)
	env = with_debug_log(env, debug)
	patch = 'def boom(*args): raise RuntimeError("boom")\nmc._without_passwords = boom'
	process, master, read_end = start_on_a_terminal(['edit', '--ready', '--', 'mssh '], None, env, listening=True,
		command=patched_engine(patch), stderr=subprocess.PIPE)
	try:
		assert terminal_output(read_end, 10.0, until=b'\n') == b'ready\n'
		assert b'mssh ' in terminal_output(master, 10.0, until=b'mssh ')
		os.write(master, b'h\r')
		assert process.wait(20) == 0, process.stderr.read()
		# the line the editor made, and Enter handed back to readline (the fallback hands back no key)
		assert terminal_output(read_end, 2.0) == b'MSSHC1\nL 6\tmssh h\nK pass\t\\C-m\nE\n'
	finally:
		process.kill()
		process.wait()
		process.stderr.close()
		os.close(master)
		os.close(read_end)


def test_a_debug_message_the_locale_cannot_write_still_lets_pick_fall_back(tmp_path):
	# in C, not in UTF-8 mode (Python 3.6 there), the log took the locale's encoding: the failure message,
	# quoting "— … ⚠", raised writing it, and pick ended 1 (cancelled) for 2 (do what Ctrl-R did)
	import os
	import subprocess
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	env = dict(env, LC_ALL='C')
	env.pop('LANG', None)
	# escapes in the code: an ASCII locale takes the command line's bytes as surrogates
	patch = 'def boom(*args): raise RuntimeError("\\u26a0 \\u2014 \\u2026")\nmc.picker_items = boom'
	result = subprocess.run(patched_engine(patch, ascii_locale=True) + ['pick'], input=READY_PICK.replace(b' ready=1', b''), env=env,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, timeout=60)
	assert (result.returncode, result.stdout, result.stderr) == (2, b'', b'')
	with open(os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3', 'complete.log'), encoding='utf-8') as f:
		log = f.read()
	# Python 3.6 shows the exception as RuntimeError('...',)
	assert "pick failed: RuntimeError('\u26a0 \u2014 \u2026'" in log


CLAIM_PICK = b'\0'.join([b'MSSHC1', b'zsh', b'5.9', b'pick=1 nul=0 term=xterm', b'mssh gpu[01-16] ', b'', b'', b''])


def test_pick_claims_the_terminal_before_it_takes_it(tmp_path):
	# zsh and fish give the picker MSSH_COMPLETE_CLAIM: the directory it creates says it has the terminal
	import os
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	claim = tmp_path / 'wait dir' / 'claim'
	claim.parent.mkdir()
	process, master, read_end = start_on_a_terminal(['pick'], CLAIM_PICK, dict(env, MSSH_COMPLETE_CLAIM=str(claim)), listening=True)
	try:
		# claimed first: the terminal is read only once the picker has it open
		end = time.monotonic() + 10
		while not claim.is_dir() and time.monotonic() < end and process.poll() is None:
			time.sleep(0.02)
		assert claim.is_dir()
		assert b'type to filter' in terminal_output(master, 5.0, until=b'type to filter')
		os.write(master, b'\x1b')
		assert process.wait(10) == 1
	finally:
		process.kill()
		os.close(master)
		os.close(read_end)


@pytest.mark.parametrize('taken', ['by the shell', 'gone'])
def test_pick_leaves_the_terminal_alone_when_the_shell_claimed_it(tmp_path, taken):
	# the shell stopped waiting (time limit, Ctrl-C) and claimed it first, or cleaned up its directory
	import os
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	claim = tmp_path / 'wait' / 'claim'
	if taken == 'by the shell':
		claim.mkdir(parents=True)
	process, master, read_end = start_on_a_terminal(['pick'], CLAIM_PICK, dict(env, MSSH_COMPLETE_CLAIM=str(claim)), listening=True)
	try:
		assert process.wait(10) == 2
		assert terminal_output(master, 0.3) == b'' and terminal_output(read_end, 0.3) == b''
	finally:
		process.kill()
		os.close(master)
		os.close(read_end)


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


@pytest.mark.parametrize('line', [
	'mssh -p hunter2 web1 uptime', 'mssh -phunter2 web1 uptime', 'mssh -p=hunter2 web1 uptime',
	'mssh --password hunter2 web1 uptime', 'mssh --password=hunter2 web1 uptime', 'mssh --pass hunter2 web1 uptime',
	'mssh -qp hunter2 web1 uptime', 'mssh -qphunter2 web1 uptime', 'mssh -ip hunter2 -M bmc1 power status',
	"mssh --ipmi_password='hunter2' -M bmc1 power status", 'mssh web1 -p hunter2 uptime'])
def test_the_debug_log_shows_a_line_without_its_passwords(line):
	# make_home turns the log on for every shell test, and a failed test's report carries it
	masked = mc._without_passwords(line, SPEC)
	assert 'hunter2' not in masked and '***' in masked
	assert masked.replace('***', '') == line.replace('hunter2', '').replace("''", '')
	assert mc._without_passwords('mssh -u root web1 uptime', SPEC) == 'mssh -u root web1 uptime'


def test_pick_refused_the_terminal_logs_once_why(tmp_path, monkeypatch):
	# zsh and fish make the claim: when the shell went on, its own line said so, and a second blamed "ready",
	# which zsh never asked for
	import io
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	claim = tmp_path / 'claim'
	claim.mkdir()
	for name, value in dict(env, MSSH_COMPLETE_CLAIM=str(claim)).items():
		monkeypatch.setenv(name, value)
	logged = []
	monkeypatch.setattr(mc, '_debug', lambda message: logged.append(message() if callable(message) else message))
	monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(CLAIM_PICK)))
	assert mc._cmd_pick() == 2
	logged = [message for message in logged if message.startswith('pick:')]
	assert len(logged) == 1 and 'claim' in logged[0] and 'ready' not in logged[0], logged
	# how slowly the picker started is what explains a lost claim
	assert 's in' in logged[0] and 'went on' in logged[0], logged


@pytest.mark.parametrize('error', [PermissionError(13, 'Permission denied'), OSError(30, 'Read-only file system'), OSError(28, 'No space left on device')])
def test_a_claim_that_failed_for_another_reason_does_not_blame_the_shell(tmp_path, monkeypatch, error):
	# only a directory made first (or the claim's parent removed) means the shell went on
	import os
	logged = []
	monkeypatch.setattr(mc, '_debug', lambda message: logged.append(message() if callable(message) else message))
	monkeypatch.setenv('MSSH_COMPLETE_CLAIM', str(tmp_path / 'claim'))

	def refuse(*args):
		raise error
	monkeypatch.setattr(os, 'mkdir', refuse)
	assert mc._claim_terminal(time.monotonic()) is False
	assert len(logged) == 1 and 'went on' not in logged[0] and error.strerror in logged[0] and ' s in' in logged[0], logged


def test_pick_falls_back_when_the_failure_cannot_be_shown(tmp_path, monkeypatch):
	# the failure message was made even with the debug log off: a __repr__ raising there skipped the answer 2
	import io
	from complete_shell_harness import make_home, with_debug_log
	env, _ = make_home(tmp_path, HISTORY)
	for name, value in with_debug_log(env, '0').items():
		monkeypatch.setenv(name, value)
	monkeypatch.delenv('MSSH_COMPLETE_DEBUG', raising=False)

	class Unshowable(Exception):
		def __repr__(self):
			raise RuntimeError('no repr')

	def fail(*args):
		raise Unshowable()
	monkeypatch.setattr(mc, 'picker_items', fail)
	monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(CLAIM_PICK)))
	assert mc._cmd_pick() == 2


class _Steps(object):
	'''What _cmd_edit and _cmd_pick do, in order: saying ready, taking the terminal, logging.'''
	def __init__(self, monkeypatch):
		self.done = []
		steps = self

		class FakeTerminal(object):
			def __init__(self, *args):
				pass

			def __enter__(self):
				steps.done.append('terminal taken')
				return self

			def __exit__(self, *args):
				return False
		monkeypatch.setattr(mc, 'Terminal', FakeTerminal)
		monkeypatch.setattr(mc, '_ready', lambda: steps.done.append('ready') or True)
		def debug(message):
			# a message, or a function making it (_debug calls it only when debugging)
			message = message() if callable(message) else message
			steps.done.append(message.split(' ')[0] + ' ' + message.split(' ')[1])
		monkeypatch.setattr(mc, '_debug', debug)


@pytest.mark.parametrize('command', ['edit', 'pick'])
def test_nothing_comes_between_ready_and_taking_the_terminal(tmp_path, monkeypatch, command):
	# keys typed after "ready" and before the terminal is raw are echoed by it: no log line between them
	import io
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	for name, value in env.items():
		monkeypatch.setenv(name, value)
	steps = _Steps(monkeypatch)
	if command == 'edit':
		monkeypatch.setattr(mc.LineEditor, 'run', lambda self, term, prompt, style=None: ('pass', b''))
		monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'')))
		monkeypatch.setattr(sys, 'stdout', io.TextIOWrapper(io.BytesIO()))
		mc._cmd_edit(['--ready', '--', 'mssh '])
	else:
		monkeypatch.setattr(mc.Picker, 'run', lambda self, term, line=None, before=None: 'cancel')
		monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(READY_PICK)))
		mc._cmd_pick()
	ready = steps.done.index('ready')
	assert steps.done[ready + 1] == 'terminal taken', steps.done
	assert '{}: ready'.format(command) in steps.done[ready + 2:], steps.done
