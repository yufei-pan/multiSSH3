'''The terminal layer the picker and the editor draw with: keys, display width, raw mode.'''
import fcntl
import os
import pty
import struct
import termios
import threading

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


@pytest.mark.parametrize('data, expected', [
	# two Esc bytes together: a double press that arrived at once (ssh, mosh, a multiplexer) or Alt+Esc
	(b'\x1b\x1b', ('esc', b'\x1b\x1b')),
	# the kitty keyboard protocol ("CSI u"), with and without its default modifier
	(b'\x1b[27u', ('esc', b'\x1b')),
	(b'\x1b[27;1u', ('esc', b'\x1b')),
	# xterm's modifyOtherKeys
	(b'\x1b[27;1;27~', ('esc', b'\x1b')),
	# Alt+Esc in the kitty protocol: what a legacy terminal sends for it
	(b'\x1b[27;3u', ('esc', b'\x1b\x1b')),
	# Alt + an arrow as Esc Esc [ C is still Alt + the arrow
	(b'\x1b\x1b[C', ('alt-right', b'\x1b\x1b[C')),
])
def test_decode_keys_reads_esc_however_it_is_sent(data, expected):
	assert mc.decode_keys(data) == [expected]


@pytest.mark.parametrize('data, expected', [
	# the key, with the bytes a terminal sends for it without the kitty protocol or modifyOtherKeys:
	# what readline understands when the editor hands it the key
	(b'\x1b[13u', ('enter', b'\r')),
	(b'\x1b[9u', ('tab', b'\t')),
	(b'\x1b[127u', ('backspace', b'\x7f')),
	(b'\x1b[99;5u', ('ctrl-c', b'\x03')),
	(b'\x1b[103;5u', ('ctrl-g', b'\x07')),
	(b'\x1b[114;5u', ('ctrl-r', b'\x12')),
	(b'\x1b[110;5u', ('ctrl-n', b'\x0e')),
	(b'\x1b[32;5u', ('ctrl-space', b'\x00')),
	(b'\x1b[91;5u', ('esc', b'\x1b')),
	(b'\x1b[27;5;99~', ('ctrl-c', b'\x03')),
	(b'\x1b[27;5;114~', ('ctrl-r', b'\x12')),
	(b'\x1b[102;3u', ('alt-f', b'\x1bf')),
	(b'\x1b[27;3;98~', ('alt-b', b'\x1bb')),
	(b'\x1b[97u', ('a', b'a')),
	(b'\x1b[97;2u', ('A', b'A')),
	(b'\x1b[97;65u', ('A', b'A')),
	(b'\x1b[97;66u', ('a', b'a')),
	(b'\x1b[97;129u', ('a', b'a')),
	(b'\x1b[49:33;2u', ('!', b'!')),
	(b'\x1b[49;2;33u', ('!', b'!')),
	(b'\x1b[233u', ('é', 'é'.encode('utf-8'))),
	(b'\x1b[13;2u', ('enter', b'\r')),
	(b'\x1b[99;5:1u', ('ctrl-c', b'\x03')),
	(b'\x1b[99;5:2u', ('ctrl-c', b'\x03')),
	# keys with no legacy bytes, or not keys typed: unknown, as read
	(b'\x1b[9;2u', ('unknown', b'\x1b[Z')),
	(b'\x1b[13;5u', ('unknown', b'\x1b[13;5u')),
	(b'\x1b[97;9u', ('unknown', b'\x1b[97;9u')),
	(b'\x1b[49;2u', ('unknown', b'\x1b[49;2u')),
	(b'\x1b[99;5:3u', ('unknown', b'\x1b[99;5:3u')),
	(b'\x1b[57414u', ('unknown', b'\x1b[57414u')),
	(b'\x1b[1114112u', ('unknown', b'\x1b[1114112u')),
	(b'\x1b[55296u', ('unknown', b'\x1b[55296u')),
	(b'\x1b[;5u', ('unknown', b'\x1b[;5u')),
	(b'\x1b[?1u', ('unknown', b'\x1b[?1u')),
	(b'\x1b[27;5;99;1~', ('unknown', b'\x1b[27;5;99;1~')),
	(b'\x1b[15;5~', ('unknown', b'\x1b[15;5~')),
])
def test_decode_keys_reads_csi_u_and_modify_other_keys(data, expected):
	assert mc.decode_keys(data) == [expected]


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


@pytest.mark.parametrize('typed, expected', [
	(b'\x1b[27u', ('esc', b'\x1b')),
	(b'\x1b[27;1u', ('esc', b'\x1b')),
	(b'\x1b[27;1;27~', ('esc', b'\x1b')),
	(b'\x1b[13u', ('enter', b'\r')),
	(b'\x1b[99;5u', ('ctrl-c', b'\x03')),
	(b'\x1b[27;5;114~', ('ctrl-r', b'\x12')),
])
def test_terminal_reads_a_csi_u_key_and_no_more(tty_pair, typed, expected):
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		os.write(master, typed + b'z')
		assert term.read_key(timeout=1) == expected
		assert term.read_key(timeout=1) == ('z', b'z')
		assert term.read_key(timeout=0.05) is None


@pytest.mark.parametrize('typed', [
	b'\x1b\x1b',
	# Esc pressed again and again, or Esc and then a key, all at once: what was read cannot go back
	# to the terminal, so it comes with the Esc
	b'\x1b\x1b\x1b', b'\x1b\x1bf', b'\x1b\x1b\x1b[A',
])
def test_terminal_reads_esc_pressed_twice_as_esc(tty_pair, typed):
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		os.write(master, typed)
		assert term.read_key(timeout=1) == ('esc', typed)
		assert term.read_key(timeout=0.05) is None
		# a key typed after the Esc presses is a key of its own
		os.write(master, b'z')
		assert term.read_key(timeout=1) == ('z', b'z')


@pytest.mark.parametrize('typed', [b'\x1b', b'\x1b\x1b', b'\x1b[27u', b'\x1b[27;1u', b'\x1b[27;1;27~', b'\x1b[103;5u', b'\x1b[99;5u'])
def test_the_picker_closes_on_esc_however_the_terminal_sends_it(tty_pair, typed):
	master, slave, path = tty_pair
	fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
	picker = mc.Picker([mc.PickItem('gpu01'), mc.PickItem('gpu02')], [], 'hosts')
	# a picker that missed the key would wait for ever: Enter comes later and chooses
	enter = threading.Timer(2, os.write, (master, b'\r'))
	try:
		with mc.Terminal(path) as term:
			os.write(master, typed)
			enter.start()
			assert picker.run(term) == 'cancel'
			assert not term.has_input()
	finally:
		enter.cancel()
		enter.join()


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
