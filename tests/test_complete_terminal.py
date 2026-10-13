'''The terminal layer the picker and the editor draw with: keys, display width, raw mode.'''
import fcntl
import os
import pty
import signal
import struct
import termios
import threading
import time

import pytest

import mssh_complete as mc
from vt_grid import Grid


@pytest.mark.parametrize('data, expected', [
	(b'ab', [('a', b'a'), ('b', b'b')]),
	(b'\x1b[A\x1bOB\x1b[C\x1b[D', [('up', b'\x1b[A'), ('down', b'\x1bOB'), ('right', b'\x1b[C'), ('left', b'\x1b[D')]),
	(b'\x1b[1;5C\x1b[1;3D', [('ctrl-right', b'\x1b[1;5C'), ('alt-left', b'\x1b[1;3D')]),
	(b'\x1b[H\x1b[4~\x1b[3~\x1b[5~', [('home', b'\x1b[H'), ('end', b'\x1b[4~'), ('delete', b'\x1b[3~'), ('pgup', b'\x1b[5~')]),
	(b'\x1bf\x1bb', [('alt-f', b'\x1bf'), ('alt-b', b'\x1bb')]),
	(b'\x1b', [('esc', b'\x1b')]),
	(b'\x1b[15~', [('unknown', b'\x1b[15~')]),
	(b'\r\t\x7f\x08\x12\x03', [('enter', b'\r'), ('tab', b'\t'), ('backspace', b'\x7f'), ('backspace', b'\x08'), ('ctrl-r', b'\x12'), ('ctrl-c', b'\x03')]),
	('é漢'.encode('utf-8'), [('é', 'é'.encode('utf-8')), ('漢', '漢'.encode('utf-8'))]),
])
def test_decode_keys(data, expected):
	assert mc.decode_keys(data) == expected


def test_display_width_counts_wide_and_combining_characters():
	assert [mc.char_width(char) for char in 'a漢́\x07'] == [1, 2, 0, 0]
	assert mc.text_width('\x1b[1mab\x1b[0m漢') == 4
	assert mc.text_width('\x01\x1b[32m\x02$ ') == 2


def test_fit_cuts_at_columns_and_keeps_escapes():
	assert mc.fit('漢字ab', 3) == '漢'
	assert mc.fit('\x1b[7mabc', 2) == '\x1b[7mab'
	assert mc.fit('abc', 5) == 'abc'


@pytest.mark.parametrize('term, style', [
	('', None), ('dumb', None), ('xterm', '\x1b[2m'), ('screen', '\x1b[2m'),
	('xterm-256color', '\x1b[38;5;244m'), ('tmux-256color', '\x1b[38;5;244m'),
])
def test_ghost_style(term, style):
	assert mc.ghost_style(term) == style


@pytest.fixture
def tty_pair():
	master, slave = pty.openpty()
	path = os.ttyname(slave)
	yield master, slave, path
	os.close(master)
	os.close(slave)


def test_terminal_keeps_keys_typed_before_it_started(tty_pair):
	master, slave, path = tty_pair
	os.write(master, b'xy')
	with mc.Terminal(path) as term:
		assert [term.read_key(timeout=1)[0], term.read_key(timeout=1)[0]] == ['x', 'y']


def test_terminal_reads_one_key_and_leaves_the_rest_to_the_shell(tty_pair):
	master, slave, path = tty_pair
	os.write(master, b'a\x1b[Ab\xc3\xa9\x1bf\x1b\x1b[Ccd')
	with mc.Terminal(path) as term:
		assert term.read_key(timeout=1) == ('a', b'a')
		assert term.has_input()
		assert term.read_key(timeout=1) == ('up', b'\x1b[A')
		assert term.read_key(timeout=1) == ('b', b'b')
		assert term.read_key(timeout=1) == ('é', 'é'.encode('utf-8'))
		assert term.read_key(timeout=1) == ('alt-f', b'\x1bf')
		assert term.read_key(timeout=1) == ('alt-right', b'\x1b\x1b[C')
		# what nobody read is still in the terminal, for whoever reads next
		assert os.read(term.fd, 10) == b'cd'
		assert not term.has_input()


def test_terminal_tells_a_lone_esc_from_a_sequence(tty_pair):
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		os.write(master, b'\x1b')
		assert term.read_key(timeout=1) == ('esc', b'\x1b')
		assert term.read_key(timeout=0.05) is None


def test_terminal_restores_the_mode(tty_pair):
	master, slave, path = tty_pair
	before = termios.tcgetattr(slave)
	with mc.Terminal(path) as term:
		assert not termios.tcgetattr(slave)[3] & termios.ICANON
		term.write('drawn')
	assert termios.tcgetattr(slave) == before
	assert os.read(master, 100).endswith(b'drawn')


def test_terminal_reads_its_size(tty_pair):
	# the kernel writes a whole struct winsize: Python 3.14+ refuses a smaller buffer
	master, slave, path = tty_pair
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 960, 600))
	with mc.Terminal(path) as term:
		assert term.size() == (30, 120)


def test_terminal_reports_a_resize_before_the_keys_waiting(tty_pair):
	master, slave, path = tty_pair
	os.write(master, b'ab')
	with mc.Terminal(path) as term:
		os.kill(os.getpid(), signal.SIGWINCH)
		assert term.read_key(timeout=1) == ('resize', b'')
		assert [term.read_key(timeout=1), term.read_key(timeout=1)] == [('a', b'a'), ('b', b'b')]
		# one report for one resize
		assert term.read_key(timeout=0.05) is None


def test_terminal_wakes_up_on_a_resize(tty_pair):
	# the editor and the picker wait for a key with no timeout: a resize must end that wait
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		timer = threading.Timer(0.2, os.kill, (os.getpid(), signal.SIGWINCH))
		timer.start()
		started = time.monotonic()
		try:
			assert term.read_key(timeout=5) == ('resize', b'')
		finally:
			timer.cancel()
		assert time.monotonic() - started < 2


def test_terminal_puts_the_resize_handler_back(tty_pair):
	master, slave, path = tty_pair
	seen = []
	previous = signal.signal(signal.SIGWINCH, lambda number, frame: seen.append(number))
	try:
		with mc.Terminal(path) as term:
			os.kill(os.getpid(), signal.SIGWINCH)
			assert term.read_key(timeout=1) == ('resize', b'') and seen == []
		os.kill(os.getpid(), signal.SIGWINCH)
		assert seen == [signal.SIGWINCH]
	finally:
		signal.signal(signal.SIGWINCH, previous)


def test_terminal_joins_a_character_cut_between_writes(tty_pair):
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		os.write(master, b'a\xc3')
		assert term.read_key(timeout=1) == ('a', b'a')
		os.write(master, b'\xa9')
		assert term.read_key(timeout=1) == ('é', 'é'.encode('utf-8'))
		assert term.read_key(timeout=0.05) is None


def test_text_layout_counts_wrapping_and_wide_characters():
	assert mc.text_layout('abc', 5) == (0, 3)
	assert mc.text_layout('abcde', 5) == (0, 5)
	assert mc.text_layout('abcdef', 5) == (1, 1)
	assert mc.text_layout('abcd漢', 5) == (1, 2)
	assert mc.text_layout('\x1b[1mab', 5) == (0, 2)


def test_grid_wraps_wide_characters_and_restores_the_cursor():
	grid = Grid(3, 5)
	grid.feed('abcd漢\x1b7xy\r\n\x1b[2Cz\x1b8!')
	assert grid.lines() == ['abcd', '漢!y', '  z']
	assert grid.cursor == (1, 3)


def test_grid_resizes_like_xterm():
	# nothing reflows: rows are cut on the right, and the cursor's row stays on screen
	grid = Grid(4, 10)
	grid.feed('0123456789\r\nab\r\ncd\r\nef\x1b[2D')
	grid.resize(3, 5)
	assert grid.lines() == ['ab', 'cd', 'ef'] and grid.cursor == (2, 0)
	grid.resize(3, 8)
	assert grid.lines() == ['ab', 'cd', 'ef'] and (grid.rows, grid.columns) == (3, 8)
