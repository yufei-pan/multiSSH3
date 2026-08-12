import curses

import pytest

import multiSSH3


def test_get_hosts_to_display_windowing(fake_host):
	hosts = [fake_host(f"127.0.0.{i}", "true") for i in range(1, 6)]
	for host in hosts[:2]:
		host.returncode = 0
		host.output = ["done"]

	displayed, stats, rearranged = multiSSH3._get_hosts_to_display(
		hosts,
		max_num_hosts=2,
		indexOffset=0,
	)

	assert displayed == hosts[:2]
	assert stats == {
		"running": 0,
		"failed": 0,
		"finished": 2,
		"waiting": 3,
	}
	assert rearranged == set(displayed)


def test_curses_add_string_records(curses_harness):
	win = curses_harness.window

	multiSSH3._curses_add_string_to_window(
		window=win,
		line="hello",
		y=0,
		x=0,
		number_of_char_to_write=5,
		parse_ansi_colors=False,
	)

	assert win.calls
	assert win.calls[0][0] == "addnstr"
	assert win.calls[0][1][:4] == (0, 0, "hello", 5)


def test_parse_ansi_escape_basic(monkeypatch):
	initialized_pairs = []
	monkeypatch.setattr(curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(
		curses,
		"init_pair",
		lambda pair, foreground, background: initialized_pairs.append(
			(pair, foreground, background)
		),
	)
	monkeypatch.setattr(curses, "color_pair", lambda pair: pair << 8)
	monkeypatch.setattr(multiSSH3, "__curses_global_color_pairs", {})
	monkeypatch.setattr(multiSSH3, "__curses_current_color_pair_index", 1)
	color_state = [-1, -1, 1]

	attr = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr(
		"\x1b[31m",
		color_state,
	)

	assert initialized_pairs == [(1, curses.COLOR_RED, -1)]
	assert attr == 1 << 8
	assert color_state == [curses.COLOR_RED, -1, attr]


@pytest.mark.live_tui
def test_curses_initscr_smoke(curses_harness):
	if curses_harness.mode != "live":
		assert curses_harness.window is not None
		return

	def _probe(stdscr):
		stdscr.addstr(0, 0, "mssh")
		return True

	assert curses.wrapper(_probe) is True
