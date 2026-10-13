"""
mssh's UserKnownHostsFile=/dev/null makes ssh print "Warning: Permanently added ..." on every
connection. The output at the end leaves such notices out (ERROR_MESSAGES_TO_IGNORE); the curses
display drew them, so while a command was quiet every host's line showed that warning.
"""
import time

import multiSSH3


NOTICE = "Warning: Permanently added 'mock-a' (ED25519) to the list of known hosts."


def _drawn_text(stub_curses_harness, fake_host, monkeypatch, output):
	host = fake_host("mock-a", "sleep 5")
	host.returncode = None
	host.output = list(output)
	host.lineNumToPrintSet = set(range(len(output)))

	def finish_without_input():
		host.returncode = 0
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", finish_without_input)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=1)
	return [
		arg
		for window in stub_curses_harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]


def test_a_host_window_does_not_show_ssh_notices(stub_curses_harness, fake_host, monkeypatch):
	drawn = _drawn_text(stub_curses_harness, fake_host, monkeypatch,
		["Running command: ssh -- mock-a sleep 5", NOTICE])

	assert not any("Permanently added" in text for text in drawn)
	assert any(text.startswith("Running command: ssh") for text in drawn)


def test_a_host_window_shows_the_output_after_a_notice(stub_curses_harness, fake_host, monkeypatch):
	drawn = _drawn_text(stub_curses_harness, fake_host, monkeypatch,
		["Running command: ssh -- mock-a sleep 5", NOTICE, "remote output"])

	assert "remote output" in drawn
	assert not any("Permanently added" in text for text in drawn)


def test_a_one_line_window_shows_the_last_line_before_a_notice():
	# with many hosts each window has one line: it shows "Running command: ..." while the command is quiet
	output = ["Running command: ssh -- mock-a sleep 5", NOTICE]

	assert multiSSH3._tui_first_shown_line(output, 1) == 0
	assert multiSSH3._tui_first_shown_line(output + ["out"], 1) == 2
	assert multiSSH3._tui_first_shown_line(["a", "b", NOTICE, "c"], 2) == 1


def test_without_notices_a_window_shows_its_last_lines():
	output = ["l{}".format(i) for i in range(10)]

	assert multiSSH3._tui_first_shown_line(output, 3) == 7
	assert multiSSH3._tui_first_shown_line(output, 20) == 0
	assert multiSSH3._tui_first_shown_line([], 3) == 0


def test_a_huge_output_line_is_checked_quickly():
	# a host's output line can be megabytes long, and made to be slow to search: on main the ignore list
	# holds the unanchored "Connection to .* closed"
	line = "Connection to " * 74898 + "x"

	started = time.perf_counter()
	assert not multiSSH3._tui_leaves_out(line)
	assert multiSSH3._tui_first_shown_line([line, line], 1) == 1
	elapsed = time.perf_counter() - started

	assert elapsed < 0.01


def test_a_long_line_is_output_not_a_notice():
	assert not multiSSH3._tui_leaves_out(NOTICE + " " * 2000)
