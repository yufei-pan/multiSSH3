import curses

import pytest

import multiSSH3


def _running_host(fake_host):
	host = fake_host("mock-a", "true")
	host.returncode = None
	host.output = ["working"]
	host.lineNumToPrintSet = {0}
	return host


def test_stub_curses_harness_records_windows_and_keys(stub_curses_harness):
	harness = stub_curses_harness
	harness.inject_keys([410])
	child = harness.newwin(3, 20, 1, 2)

	assert harness.window.getch() == 410
	assert child.getmaxyx() == (3, 20)
	assert child.calls[0] == ("origin", (1, 2), {})


@pytest.mark.parametrize(
	"key,expected_index,expected_value,reason",
	[
		(410, None, None, "Terminal resize requested"),
		(95, 3, 1, "Decrease line length"),
		(43, 3, 3, "Increase line length"),
		(123, 2, 9, "Decrease character length"),
		(125, 2, 11, "Increase character length"),
		(124, 4, True, "Toggle single window mode"),
	],
)
def test_generate_display_geometry_keys(
	stub_curses_harness, fake_host, key, expected_index, expected_value, reason
):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([key])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
		single_window=False,
	)

	assert result[6] == reason
	if expected_index is not None:
		assert result[expected_index] == expected_value


def test_generate_display_rejects_tiny_terminal(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.window.set_size(1, 1)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host])

	assert result[6] == "Terminal too small"


def test_generate_display_reports_no_hosts(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	stats = {"running": 0, "failed": 0, "finished": 0, "waiting": 0}
	monkeypatch.setattr(multiSSH3, "_get_hosts_to_display", lambda *args, **kwargs: ([], stats, set()))

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result[6] == "No hosts to display"


def test_generate_display_shows_help_then_refreshes(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([63, 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result[5] is True
	assert result[6] == "Refresh requested"
	assert "show" in stub_curses_harness.panels[-1].calls
	assert stub_curses_harness.panel_updates >= 2


def test_generate_display_edits_input_and_redraws_host(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([ord("x"), 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert multiSSH3.__keyPressesIn == [["x"]]
	assert result[1] == 1
	assert result[6] == "Refresh requested"
	assert any(call[0] == "vline" for window in stub_curses_harness.windows for call in window.calls)
	assert stub_curses_harness.screen_updates >= 1


@pytest.mark.parametrize(
	"history,key,start_line,start_cursor,expected_line,expected_cursor",
	[
		([list("old\n"), []], 259, -1, 0, -2, 4),
		([list("old\n"), []], 258, -2, 0, -1, 0),
		([list("ab")], 260, -1, 2, -1, 1),
		([list("ab")], 261, -1, 0, -1, 1),
		([list("one\n"), list("two\n"), []], 339, -1, 0, -3, 0),
		([list("one\n"), list("two\n"), []], 338, -3, 0, -1, 0),
		([list("ab")], 262, -1, 2, -1, 0),
		([list("ab")], 360, -1, 0, -1, 2),
	],
)
def test_generate_display_navigation_keys(
	stub_curses_harness,
	fake_host,
	monkeypatch,
	history,
	key,
	start_line,
	start_cursor,
	expected_line,
	expected_cursor,
):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list(line) for line in history])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		lineToDisplay=start_line,
		curserPosition=start_cursor,
		min_char_len=10,
		min_line_len=2,
	)

	assert result[0] == expected_line
	assert result[1] == expected_cursor
	assert result[6] == "Refresh requested"


@pytest.mark.parametrize(
	"key,start_cursor,expected_history,expected_cursor",
	[
		(8, 1, [list("b")], 0),
		(330, 0, [list("b")], 0),
		(10, 2, [list("ab\n"), []], 0),
	],
)
def test_generate_display_mutates_input(
	stub_curses_harness, fake_host, monkeypatch, key, start_cursor, expected_history, expected_cursor
):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("ab")])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window, [host], curserPosition=start_cursor, min_char_len=10, min_line_len=2
	)

	assert multiSSH3.__keyPressesIn == expected_history
	assert result[1] == expected_cursor


def test_generate_display_ctrl_d_queues_exit(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([4, 12])

	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert multiSSH3.__keyPressesIn == [list("exit\n"), []]


def test_generate_display_host_offset_updates_stats(stub_curses_harness, fake_host, monkeypatch):
	hosts = [_running_host(fake_host) for _ in range(2)]
	hosts[0].name = "mock-a"
	hosts[1].name = "mock-b"
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([62, 12])

	multiSSH3.__generate_display(stub_curses_harness.window, hosts, min_char_len=10, min_line_len=2)

	text_args = [
		arg
		for window in stub_curses_harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]
	assert any("i:1" in text for text in text_args)


def test_curses_print_reloads_configuration(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	responses = iter([
		(-1, 0, 20, 4, True, False, "Toggle single window mode"),
		None,
	])
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: next(responses))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(multiSSH3.curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "can_change_color", lambda: False)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.curses_print(stub_curses_harness.window, [host], [object()])

	addstr_text = [call[1][2] for call in stub_curses_harness.window.calls if call[0] == "addstr"]
	assert any("Toggle single window mode" in text for text in addstr_text)
	assert any(call[0] == "refresh" for call in stub_curses_harness.window.calls)


def test_curses_print_returns_before_generation_for_tiny_screen(stub_curses_harness, monkeypatch):
	stub_curses_harness.window.set_size(1, 1)
	calls = []
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: calls.append(args))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)

	multiSSH3.curses_print(stub_curses_harness.window, [], [])

	assert calls == []


def test_curses_print_renders_error_traceback(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	responses = iter([
		(-1, 0, 20, 4, False, False, "Error: boom", "line-one\nline-two"),
		None,
	])
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: next(responses))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(multiSSH3.curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "can_change_color", lambda: False)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.curses_print(stub_curses_harness.window, [host], [object()])

	text = [call[1][2] for call in stub_curses_harness.window.calls if call[0] == "addstr"]
	assert any("Error: boom" in item for item in text)
	assert "line-one" in text
	assert "line-two" in text
