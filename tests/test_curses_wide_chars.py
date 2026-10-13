'''The curses display counts terminal columns: wide characters (CJK, most emoji) take two, combining marks none.'''
import fcntl
import json
import os
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

import multiSSH3
from vt_grid import width as reference_width

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_char_columns_count_wide_combining_and_ambiguous_characters():
	# ambiguous width characters (box drawing, arrows) take one column outside CJK locales: the display's borders are made of them
	assert [multiSSH3._char_columns(char) for char in 'a日ｆ✅😀\u0301\u200b─│↑é'] == [1, 2, 2, 2, 2, 0, 0, 1, 1, 1, 1]


def test_text_columns_leave_out_color_codes():
	assert multiSSH3._text_columns('plain') == 5
	assert multiSSH3._text_columns('日本語.txt') == 10
	assert multiSSH3._text_columns('\x1b[01;34m日本\x1b[0m!') == 5
	assert multiSSH3._text_columns('cafe\u0301') == 4


def test_curses_fit_cuts_whole_characters_at_the_column_limit():
	assert multiSSH3._curses_fit('plain ascii', 5) == ('plain', 5, False)
	assert multiSSH3._curses_fit('plain', 5) == ('plain', 5, True)
	assert multiSSH3._curses_fit('日本語', 5) == ('日本', 4, False)
	assert multiSSH3._curses_fit('ab日', 3) == ('ab', 2, False)
	# a combining mark stays with the character it marks
	assert multiSSH3._curses_fit('cafe\u0301!', 4) == ('cafe\u0301', 4, False)


def test_curses_fit_expands_tabs_and_shows_control_characters():
	# curses would expand a tab from the window's edge, and wrap one that passes its right side
	assert multiSSH3._curses_fit('a\tb', 20) == ('a       b', 9, True)
	assert multiSSH3._curses_fit('\tb', 20, 3) == ('     b', 6, True)
	# curses draws a control character as ^X in two columns, and moves the cursor for a backspace
	assert multiSSH3._curses_fit('x\x1b[Ky\x07\x7f\x08\0', 20) == ('x^[[Ky^G^?^H^@', 14, True)
	assert multiSSH3._curses_fit('ab\x07', 3) == ('ab', 2, False)


class CellWindow(object):
	'''A curses window stub that lays text out in cells as a terminal does (vt_grid's widths), and notes text that would wrap.'''
	def __init__(self, rows, columns):
		self.rows = rows
		self.columns = columns
		self.cells = [[' '] * columns for _ in range(rows)]
		self.overflows = []

	def getmaxyx(self):
		return (self.rows, self.columns)

	def addnstr(self, y, x, text, count, attr=0):
		column = x
		for char in text[:count]:
			size = reference_width(char)
			if column + size > self.columns:
				# curses would go on at the start of the next line, or scroll the window from the last one
				self.overflows.append((y, text))
				return
			if size:
				self.cells[y][column] = char
				if size == 2:
					self.cells[y][column + 1] = ''
			elif column:
				self.cells[y][column - 1] += char
			column += size

	def row(self, y):
		return ''.join(self.cells[y])


@pytest.mark.parametrize('line, expected', [
	('日本語のファイル名.txt', '│日本語のファ'),
	('ｆｕｌｌｗｉｄｔｈ', '│ｆｕｌｌｗｉ'),
	('ok ✅ 😀 done!', '│ok ✅ 😀 done'),
	('cafe\u0301 re\u0301sume\u0301', '│cafe\u0301 re\u0301sume\u0301'),
	('tab\tx', '│tab     x'),
])
def test_curses_add_string_stops_at_the_window_edge(line, expected, curses_color_mocks):
	window = CellWindow(3, 15)

	multiSSH3._curses_add_string_to_window(window=window, y=1, line=line, lead_str='│', fill_char='')

	assert window.overflows == []
	assert window.row(1).rstrip() == expected


def test_curses_add_string_centers_and_fills_by_columns(curses_color_mocks):
	window = CellWindow(3, 15)

	multiSSH3._curses_add_string_to_window(window=window, y=0, line='h:[ls 日本]', centered=True, fill_char='─', lead_str='┼')
	multiSSH3._curses_add_string_to_window(window=window, y=1, line='\x1b[31m日本\x1b[0mé', fill_char='.', lead_str='│')
	multiSSH3._curses_add_string_to_window(window=window, y=2, line='日本語のファイル名', fill_char='.', lead_str='│')

	assert window.overflows == []
	assert window.row(0) == '┼─h:[ls 日本]─ '
	assert window.row(1) == '│日本é........ '
	# the column a wide character did not fit in is filled too
	assert window.row(2) == '│日本語のファ. '


@pytest.fixture
def curses_color_mocks(monkeypatch):
	import curses
	monkeypatch.setattr(curses, 'COLOR_PAIRS', 256, raising=False)
	monkeypatch.setattr(curses, 'init_pair', lambda *args: None)
	monkeypatch.setattr(curses, 'color_pair', lambda pair: pair << 8)
	monkeypatch.setattr(multiSSH3, '__curses_global_color_pairs', {})
	monkeypatch.setattr(multiSSH3, '__curses_current_color_pair_index', 1)


def _painted(window, rows, columns):
	'''The cells the recorded addnstr calls of a StubWindow cover, and the calls that would wrap.'''
	cells = CellWindow(rows, columns)
	for method, args, _kwargs in window.calls:
		if method == 'addnstr':
			cells.addnstr(*args)
	return cells


def test_generate_display_fits_wide_typed_text_title_and_output(stub_curses_harness, fake_host, monkeypatch):
	host = fake_host('mock-a', 'ls 日本語のディレクトリ')
	host.output = ['日本語のファイル名.txt ' * 6]
	host.lineNumToPrintSet = {0}
	# typed into the input line: the stats bar shows it
	monkeypatch.setattr(multiSSH3, '__keyPressesIn', [list('日本語のファイル')])
	monkeypatch.setattr(multiSSH3.time, 'perf_counter', lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, 'sleep', lambda seconds: None)
	stub_curses_harness.inject_keys([-1, 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result[6] == 'Refresh requested'
	# an 80 column terminal: each window is 81 columns wide, the last one spare
	stats_window, host_window = stub_curses_harness.windows[:2]
	assert host_window.getmaxyx() == (23, 81)
	stats = _painted(stats_window, 1, 81)
	assert stats.overflows == []
	assert stats.row(0) == '┍' + '━' * 26 + 'Send CMD: 日本語のファイル ' + '━' * 26 + ' '
	shown = _painted(host_window, 23, 81)
	assert shown.overflows == []
	assert shown.row(0) == '┼' + '─' * 23 + 'mock-a:[ls 日本語のディレクトリ]' + '─' * 24 + ' '
	assert shown.row(1) == '│' + '日本語のファイル名.txt ' * 3 + '日本語のフ' + ' '


CHILD = r'''
import curses, json, locale, sys
for name in ('', 'C.UTF-8', 'C.utf8', 'en_US.UTF-8', 'en_US.utf8'):
	try:
		locale.setlocale(locale.LC_ALL, name)
	except locale.Error:
		continue
	if locale.nl_langinfo(locale.CODESET).upper().replace('-', '') == 'UTF8':
		break
else:
	sys.exit(77)
import multiSSH3
rows, columns, calls, out = json.loads(sys.argv[1])
shown = []
def draw(stdscr):
	curses.start_color()
	curses.use_default_colors()
	curses.init_pair(1, -1, -1)
	# a host window as __generate_display makes one: scrolls, and one column wider than its text
	window = curses.newwin(rows, columns, 0, 0)
	window.idlok(True)
	window.scrollok(True)
	window.leaveok(True)
	for call in calls:
		multiSSH3._curses_add_string_to_window(window=window, **call)
	for row in range(rows):
		shown.append(window.instr(row, 0).decode('utf-8').rstrip())
curses.wrapper(draw)
with open(out, 'w') as file:
	json.dump(shown, file)
'''


def _draw_in_curses(tmp_path, rows, columns, calls):
	'''The rows of a real curses window after the calls to _curses_add_string_to_window, drawn in a pty.'''
	out = str(tmp_path / 'shown.json')
	master, slave = os.openpty()
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
	env = dict(os.environ, TERM='xterm', PYTHONPATH=str(PACKAGE_ROOT), HOME=str(tmp_path), XDG_RUNTIME_DIR=str(tmp_path))
	process = subprocess.Popen([sys.executable, '-c', CHILD, json.dumps([rows, columns, calls, out])],
		stdin=slave, stdout=slave, stderr=slave, env=env, cwd=str(tmp_path), close_fds=True)
	os.close(slave)
	printed = b''
	deadline = time.monotonic() + 30
	try:
		while time.monotonic() < deadline:
			ready, _, _ = select.select([master], [], [], 0.5)
			if ready:
				try:
					data = os.read(master, 65536)
				except OSError:
					break
				if not data:
					break
				printed += data
			elif process.poll() is not None:
				break
	finally:
		os.close(master)
		code = process.wait(timeout=10)
	if code == 77:
		pytest.skip('no UTF-8 locale for curses')
	assert code == 0, printed.decode('utf-8', 'replace')[-2000:]
	with open(out) as file:
		return json.load(file)


def test_wide_output_scrolls_through_a_curses_host_window(tmp_path):
	pytest.importorskip('curses')
	lines = ['line 1', 'ok ✅ 😀 done!', 'cafe\u0301 re\u0301sume\u0301', 'a日本語のファイル名.txt', 'tab\tx', 'last 日本語']
	calls = [dict(y=0, line='h:[ls 日本]', centered=True, fill_char='─', lead_str='┼')]
	calls += [dict(y=number + 1, line=line, lead_str='│', keep_top_n_lines=1, fill_char='') for number, line in enumerate(lines)]

	shown = _draw_in_curses(tmp_path, 5, 15, calls)

	# the title stays, and every line keeps a row of its own, cut where the window's text ends
	assert shown == [
		'┼─h:[ls 日本]─',
		'│cafe\u0301 re\u0301sume\u0301',
		'│a日本語のファ',
		'│tab     x',
		'│last 日本語',
	]


@pytest.mark.parametrize('stdout, stderr, width', [
	# 30 characters in 60 columns, 60 characters in 30 columns
	(['日本語' * 10], [], 62),
	(['e\u0301' * 30], ['ok'], 32),
	(['short'], ['ｆｕｌｌｗｉｄｔｈ ' * 3], 59),
])
def test_merged_output_lines_are_as_wide_as_the_widest_output(fake_host, stdout, stderr, width):
	host = fake_host('mock-a', 'true')
	host.stdout = stdout
	host.stderr = stderr
	host.returncode = 0

	line_length = multiSSH3.get_host_raw_output([host], terminal_width=200)[4]

	# the dividers between host blocks: the longest line and two columns more
	assert line_length == width
