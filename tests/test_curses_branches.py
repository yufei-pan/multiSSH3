import curses

import pytest

import multiSSH3


@pytest.fixture
def curses_color_mocks(monkeypatch):
	monkeypatch.setattr(curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(curses, "can_change_color", lambda: False)
	monkeypatch.setattr(curses, "init_pair", lambda *a, **k: None)
	monkeypatch.setattr(curses, "color_pair", lambda pair: pair << 8)
	monkeypatch.setattr(curses, "A_BOLD", 1 << 16, raising=False)
	monkeypatch.setattr(curses, "A_DIM", 1 << 17, raising=False)
	monkeypatch.setattr(curses, "A_UNDERLINE", 1 << 18, raising=False)
	monkeypatch.setattr(curses, "A_BLINK", 1 << 19, raising=False)
	monkeypatch.setattr(curses, "A_REVERSE", 1 << 20, raising=False)
	monkeypatch.setattr(curses, "A_INVIS", 1 << 21, raising=False)
	monkeypatch.setattr(multiSSH3, "__curses_global_color_pairs", {})
	monkeypatch.setattr(multiSSH3, "__curses_current_color_pair_index", 1)
	monkeypatch.setattr(multiSSH3, "__curses_color_table", {})
	monkeypatch.setattr(multiSSH3, "__curses_current_color_index", 10)


def test_approximate_color_8bit_ranges(curses_color_mocks):
	assert multiSSH3.__approximate_color_8bit(1) == curses.COLOR_RED
	assert multiSSH3.__approximate_color_8bit(9) is not None
	assert multiSSH3.__approximate_color_8bit(20) is not None  # cube
	assert multiSSH3.__approximate_color_8bit(240) is not None  # gray
	assert multiSSH3.__approximate_color_8bit(999) == curses.COLOR_WHITE


def test_approximate_color_24bit_fallback(curses_color_mocks):
	assert multiSSH3.__approximate_color_24bit(255, 0, 0) == curses.COLOR_RED
	assert multiSSH3.__approximate_color_24bit(0, 0, 0) == curses.COLOR_BLACK


@pytest.mark.parametrize(
	"escape",
	[
		"",
		"\x1b[38;5m",  # invalid short
		"\x1b[38m",  # invalid
	],
)
def test_parse_ansi_malformed_escape_does_not_raise(curses_color_mocks, escape):
	state = [-1, -1, 1]
	multiSSH3.__parse_ansi_escape_sequence_to_curses_attr(escape, state)


@pytest.mark.parametrize(
	"escape,state_index,expected",
	[
		("\x1b[31m", 0, curses.COLOR_RED),
		("\x1b[41m", 1, curses.COLOR_RED),
		("\x1b[91m", 0, curses.COLOR_RED),
		("\x1b[101m", 1, curses.COLOR_RED),
	],
)
def test_parse_ansi_updates_exact_color_state(curses_color_mocks, escape, state_index, expected):
	state = [-1, -1, 1]
	attr = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr(escape, state)

	assert state[state_index] == expected
	assert state[2] == attr


def test_parse_ansi_reset_clears_styles(curses_color_mocks):
	state = [curses.COLOR_RED, curses.COLOR_BLUE, curses.A_BOLD | curses.A_UNDERLINE]
	attr = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr("\x1b[0m", state)

	assert state == [-1, -1, attr]
	assert attr & curses.A_BOLD == 0
	assert attr & curses.A_UNDERLINE == 0


def test_curses_add_string_centered_and_ansi(curses_harness, curses_color_mocks):
	win = curses_harness.window
	multiSSH3._curses_add_string_to_window(
		window=win,
		line="\x1b[31mhi\x1b[0m",
		y=0,
		x=0,
		centered=True,
		lead_str="[",
		trail_str="]",
		parse_ansi_colors=True,
		fill_char=".",
	)
	assert any(c[0] == "addnstr" for c in win.calls)


def test_curses_add_string_scroll_and_early_returns(curses_harness):
	win = curses_harness.window
	# early return: number_of_char_to_write == 0
	multiSSH3._curses_add_string_to_window(window=win, line="x", y=0, x=0, number_of_char_to_write=0)
	# scroll path y < 0
	before = len(win.calls)
	multiSSH3._curses_add_string_to_window(
		window=win,
		line="bottom",
		y=-1,
		x=0,
		parse_ansi_colors=False,
		keep_top_n_lines=1,
	)
	assert len(win.calls) > before
	assert any(c[0] == "deleteln" for c in win.calls)


def test_curses_add_string_negative_x_and_box(curses_harness, curses_color_mocks):
	win = curses_harness.window
	multiSSH3._curses_add_string_to_window(
		window=win,
		line="tail",
		y=1,
		x=-5,
		parse_ansi_colors=False,
		box_ansi_color="\x1b[32m",
		leave_space_for_cursor=True,
	)
	assert win.calls


def test_get_hosts_to_display_offset_and_rearrange(fake_host):
	hosts = [fake_host(f"127.0.0.{i}", "true") for i in range(1, 5)]
	for h in hosts:
		h.returncode = 0
		h.output = ["done"]
	first, stats, rearranged = multiSSH3._get_hosts_to_display(hosts, 2, indexOffset=1)
	assert len(first) == 2
	assert stats["finished"] == 4
	second, _stats2, rearranged2 = multiSSH3._get_hosts_to_display(
		hosts, 2, hosts_to_display=first, indexOffset=0
	)
	assert isinstance(rearranged2, set)
