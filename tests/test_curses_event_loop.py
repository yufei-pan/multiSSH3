import io
import threading

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
	"key,expected_result",
	[
		(410, (-1, 0, 10, 2, False, False, "Terminal resize requested")),
		(95, (-1, 0, 10, 1, False, False, "Decrease line length")),
		(43, (-1, 0, 10, 3, False, False, "Increase line length")),
		(123, (-1, 0, 9, 2, False, False, "Decrease character length")),
		(125, (-1, 0, 11, 2, False, False, "Increase character length")),
		(124, (-1, 0, 10, 2, True, False, "Toggle single window mode")),
	],
)
def test_generate_display_geometry_keys(stub_curses_harness, fake_host, key, expected_result):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([key])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
		single_window=False,
	)

	assert result == expected_result


def test_generate_display_rejects_tiny_terminal(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.window.set_size(1, 1)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host])

	assert result[6] == "Terminal too small"


def test_generate_display_single_window_uses_full_terminal(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
		single_window=True,
	)

	assert result == (-1, 0, 10, 2, True, False, "Refresh requested")
	assert stub_curses_harness.windows[1].getmaxyx() == (23, 81)


def test_generate_display_finishes_after_idle_redraw(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	getch_calls = []

	def finish_on_second_poll():
		getch_calls.append(None)
		if len(getch_calls) == 2:
			host.returncode = 0
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", finish_on_second_poll)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
	)

	assert result is None
	assert len(getch_calls) == 2
	assert stub_curses_harness.screen_updates == 2
	assert host.lastPrintedUpdateTime == host.lastUpdateTime


def test_generate_display_renders_compound_ansi_output_without_escape_text(
	stub_curses_harness, fake_host, monkeypatch
):
	host = _running_host(fake_host)
	host.output = [
		"\x1b[0;38;5;196;48;2;1;2;3;1;2;4;5;7;8;21;22;24;25;27;28;39;49m"
		"colored-output\x1b[0m"
	]
	host.lineNumToPrintSet = {0}

	def finish_without_input():
		host.returncode = 0
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", finish_without_input)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
	)
	rendered_text = [
		arg
		for window in stub_curses_harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]

	assert result is None
	assert "colored-output" in rendered_text
	assert not any("\x1b[" in text for text in rendered_text)


def test_generate_display_renders_partial_output_buffer_once(
	stub_curses_harness, fake_host, monkeypatch
):
	host = _running_host(fake_host)
	host.output_buffer.write(b"buffer-tail")

	def finish_without_input():
		host.returncode = 0
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", finish_without_input)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
	)
	rendered_text = [
		arg
		for window in stub_curses_harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]

	assert result is None
	assert [text for text in rendered_text if text == "buffer-tail"] == ["buffer-tail"]


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


def test_generate_display_hides_open_help_then_refreshes(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([63, 63, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
	)

	assert result == (-1, 0, 10, 2, False, False, "Refresh requested")
	assert stub_curses_harness.panels[-1].calls[-2:] == ["show", "hide"]
	assert stub_curses_harness.panels[-1].hidden is True


@pytest.mark.parametrize(
	"key,min_char_len,min_line_len",
	[
		(95, 10, 1),
		(123, 1, 2),
	],
)
def test_generate_display_does_not_decrease_minimum_geometry(
	stub_curses_harness, fake_host, monkeypatch, key, min_char_len, min_line_len
):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=min_char_len,
		min_line_len=min_line_len,
	)

	assert result == (
		-1, 0, min_char_len, min_line_len, False, False, "Refresh requested",
	)


def test_generate_display_escape_closes_display(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([27])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
	)

	assert result is None


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
		([list("old\n"), list("current")], 259, -1, 0, -2, 0),
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
		(8, 0, [list("ab")], 0),
		(330, 0, [list("b")], 0),
		(330, 2, [list("ab")], 2),
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


@pytest.mark.parametrize("key", [60, 62])
def test_generate_display_host_offset_updates_stats(stub_curses_harness, fake_host, monkeypatch, key):
	hosts = [_running_host(fake_host) for _ in range(2)]
	hosts[0].name = "mock-a"
	hosts[1].name = "mock-b"
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

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
	display_calls = []
	responses = iter([
		(-1, 0, 20, 4, True, False, "Toggle single window mode"),
		None,
	])

	def generate_display(*args):
		display_calls.append(args)
		return next(responses)

	monkeypatch.setattr(multiSSH3, "__generate_display", generate_display)
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
	assert len(display_calls) == 2
	assert display_calls[1][:2] == (stub_curses_harness.window, [host])
	assert display_calls[1][2:] == (-1, 0, 20, 4, True, False, "new config")


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


def test_generate_display_escape_with_input_clears_line(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([ord("x"), 27, 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert multiSSH3.__keyPressesIn == [[]]
	assert result is not None
	assert result[1] == 0


def _rendered_text(harness):
	return [
		arg
		for window in harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]


def _reject_text_like_curses(monkeypatch, harness, bad=lambda text: "\0" in text):
	"""Make the stub windows raise for text real curses cannot draw (addnstr rejects a NUL)."""
	window_class = type(harness.window)
	record = window_class.addnstr

	def addnstr(self, *args, **kwargs):
		if any(isinstance(arg, str) and bad(arg) for arg in args):
			raise ValueError("embedded null character")
		return record(self, *args, **kwargs)

	monkeypatch.setattr(window_class, "addnstr", addnstr)


def _finish_after_one_redraw(harness, host, monkeypatch):
	def finish_without_input():
		host.returncode = 0
		return -1

	monkeypatch.setattr(harness.window, "getch", finish_without_input)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)


def test_generate_display_shows_nul_in_output_and_keeps_later_lines(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	host.output = ["before", "a\0b", "after"]
	host.lineNumToPrintSet = {0, 1, 2}
	_reject_text_like_curses(monkeypatch, stub_curses_harness)
	_finish_after_one_redraw(stub_curses_harness, host, monkeypatch)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)
	rendered = _rendered_text(stub_curses_harness)

	assert result is None
	assert "a^@b" in rendered  # NUL shown the way curses shows the other control characters (^A, ^[)
	assert "after" in rendered


def test_generate_display_one_line_failing_to_draw_keeps_the_others(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	host.output = ["before", "cannot-draw", "after"]
	host.lineNumToPrintSet = {0, 1, 2}
	_reject_text_like_curses(monkeypatch, stub_curses_harness, bad=lambda text: text == "cannot-draw")
	_finish_after_one_redraw(stub_curses_harness, host, monkeypatch)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)
	rendered = _rendered_text(stub_curses_harness)

	assert result is None
	assert "before" in rendered
	assert "after" in rendered


def test_generate_display_shows_nul_in_unfinished_output_line(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	host.output_buffer.write(b"part\0ial")  # printf 'part\0ial'; sleep 60: no newline yet
	_reject_text_like_curses(monkeypatch, stub_curses_harness)
	_finish_after_one_redraw(stub_curses_harness, host, monkeypatch)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result is None  # not "Error: embedded null character"
	assert "part^@ial" in _rendered_text(stub_curses_harness)


def test_generate_display_shows_typed_nul_in_input_line(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [["a", "\0", "b"]])  # Ctrl-@ types a NUL
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	_reject_text_like_curses(monkeypatch, stub_curses_harness)
	stub_curses_harness.inject_keys([-1, 12])  # one redraw, then Ctrl-R

	result = multiSSH3.__generate_display(
		stub_curses_harness.window, [host], curserPosition=3, min_char_len=10, min_line_len=2
	)

	assert result[6] == "Refresh requested"  # not "Error: embedded null character"
	assert any("a^@b" in text for text in _rendered_text(stub_curses_harness))


def _type_keys(harness, fake_host, monkeypatch, keys, history=None):
	"""Feed keys to the display as getch() returns them, then Ctrl-R; returns the display's result."""
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list(line) for line in history or [[]]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	harness.inject_keys(list(keys) + [12])
	return multiSSH3.__generate_display(harness.window, [host], min_char_len=10, min_line_len=2)


def _sent_bytes(fake_host):
	"""What the hosts' stdin gets for the lines typed so far."""
	class RecordingPipe(io.BytesIO):
		def close(self):
			self.sent = self.getvalue()
			super().close()

	pipe = RecordingPipe()
	host = fake_host("mock-b", "cat")
	host.interactive_stdin = False  # the TUI is gone: send every finished line, then end of input
	multiSSH3.__handle_writing_stream(pipe, threading.Event(), host)
	return pipe.sent


@pytest.mark.parametrize(
	"typed",
	["héllo", "€", "日本", "😀"],
)
def test_generate_display_decodes_characters_typed_in_several_bytes(stub_curses_harness, fake_host, monkeypatch, typed):
	# getch() returns each byte of a UTF-8 character on its own: é comes as 0xc3, then 0xa9
	result = _type_keys(stub_curses_harness, fake_host, monkeypatch, typed.encode("utf-8"))

	assert multiSSH3.__keyPressesIn == [list(typed)]  # not "hÃ©llo"
	assert result[1] == len(typed)  # the cursor moved one place per character


def test_characters_typed_in_several_bytes_reach_the_hosts_as_typed(stub_curses_harness, fake_host, monkeypatch):
	_type_keys(stub_curses_harness, fake_host, monkeypatch, "héllo\n".encode("utf-8"))

	assert _sent_bytes(fake_host) == "héllo\n".encode("utf-8")  # not 68 c3 83 c2 a9 6c 6c 6f 0a


def test_bytes_outside_the_encoding_reach_the_hosts_unchanged_and_in_order(stub_curses_harness, fake_host, monkeypatch):
	# a Latin-1 terminal in a UTF-8 session: é is the single byte 0xe9, which starts a UTF-8 sequence
	# that the next key (a, then Enter) cuts short
	_type_keys(stub_curses_harness, fake_host, monkeypatch, b"caf\xe9a\xe9\n")

	assert _sent_bytes(fake_host) == b"caf\xe9a\xe9\n"


def test_input_line_shows_bytes_outside_the_encoding_as_hex(stub_curses_harness, fake_host, monkeypatch):
	_type_keys(stub_curses_harness, fake_host, monkeypatch, [*b"caf\xe9!", -1])  # one redraw before Ctrl-R

	assert any("caf\\xe9!" in text for text in _rendered_text(stub_curses_harness))  # the byte sent, not \udce9


def test_sent_line_echo_shows_what_was_sent(fake_host, monkeypatch):
	import time

	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("hé caf\udce9\n"), []])
	host = fake_host("mock-b", "cat")
	host.interactive_stdin = True
	stop = threading.Event()
	writer = threading.Thread(target=multiSSH3.__handle_writing_stream, args=(io.BytesIO(), stop, host), daemon=True)
	writer.start()
	deadline = time.monotonic() + 5
	while not host.output and time.monotonic() < deadline:
		time.sleep(0.01)
	stop.set()
	writer.join(timeout=5)

	assert host.output == ["> hé caf\\xe9↵"]


@pytest.mark.parametrize("key", [266, 276, 331, 409], ids=["F2", "F12", "Insert", "mouse"])
def test_function_keys_without_a_binding_type_nothing(stub_curses_harness, fake_host, monkeypatch, key):
	_type_keys(stub_curses_harness, fake_host, monkeypatch, [ord("a"), key, ord("b")])

	assert multiSSH3.__keyPressesIn == [list("ab")]  # F2 used to type chr(266), "Ċ"


def test_function_key_without_a_binding_leaves_a_history_line_alone(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("old\n"), []])
	stub_curses_harness.inject_keys([266, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window, [host], lineToDisplay=-2, min_char_len=10, min_line_len=2
	)

	assert multiSSH3.__keyPressesIn == [list("old\n"), []]
	assert result[0] == -2


def test_keypad_enter_sends_the_line(stub_curses_harness, fake_host, monkeypatch):
	import curses

	_type_keys(stub_curses_harness, fake_host, monkeypatch, [ord("y"), curses.KEY_ENTER])

	assert multiSSH3.__keyPressesIn == [list("y\n"), []]  # it used to type chr(343), "ŗ"


def test_question_mark_is_typed_once_the_input_line_has_text(stub_curses_harness, fake_host, monkeypatch):
	result = _type_keys(stub_curses_harness, fake_host, monkeypatch, b"is it?")

	assert multiSSH3.__keyPressesIn == [list("is it?")]  # sent to the hosts, e.g. answering a prompt
	assert result[5] is False  # the help stays closed
	assert "show" not in stub_curses_harness.panels[-1].calls


def test_f1_toggles_help_while_the_input_line_has_text(stub_curses_harness, fake_host, monkeypatch):
	result = _type_keys(stub_curses_harness, fake_host, monkeypatch, [ord("a"), 265])  # 265: F1

	assert multiSSH3.__keyPressesIn == [list("a")]
	assert result[5] is True


TOO_SMALL = (-1, 0, 10, 2, False, False, "Terminal too small")


def _curses_print_too_small(harness, host, monkeypatch, keys, then=None):
	'''curses_print on a terminal too small for the display; then: what the display returns once there is room.'''
	displays = []
	responses = iter([TOO_SMALL, then])

	def generate_display(*args):
		displays.append(args)
		return next(responses)

	ungot = []
	sleeps = []
	harness.inject_keys(keys)
	monkeypatch.setattr(multiSSH3, "__generate_display", generate_display)
	monkeypatch.setattr(multiSSH3.curses, "ungetch", ungot.append, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.time, "sleep", sleeps.append)
	multiSSH3.curses_print(harness.window, [host], [object()])
	return displays, ungot, sleeps


def test_curses_print_too_small_leaves_the_display_on_escape(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)

	displays, ungot, sleeps = _curses_print_too_small(stub_curses_harness, host, monkeypatch, [27])

	# Esc on an empty input line leaves the display, as it does when the hosts are shown
	assert len(displays) == 1 and ungot == [] and sleeps == []


def test_curses_print_too_small_waits_for_a_key_instead_of_redrawing(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	window = stub_curses_harness.window
	polls = []
	original_getch = window.getch

	def getch():
		polls.append(1)
		if len(polls) == 5:
			host.returncode = 0
		return original_getch()

	monkeypatch.setattr(window, "getch", getch)

	displays, _, sleeps = _curses_print_too_small(stub_curses_harness, host, monkeypatch, [])

	# about 100 redraws a second before: now one, then a wait of a quarter second for each key
	assert len(displays) == 1 and sleeps == []
	assert [call[0] for call in window.calls].count("clear") == 2
	assert ("timeout", (250,), {}) in window.calls


def test_curses_print_too_small_keeps_the_keys_typed_for_the_display(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)

	displays, ungot, _ = _curses_print_too_small(stub_curses_harness, host, monkeypatch, [ord("y"), 27, 410])

	# the resize redraws; the keys typed meanwhile, the Esc after text among them, come back in their order
	assert len(displays) == 2 and displays[1][2:] == TOO_SMALL[:6] + ("new config",)
	assert ungot == [27, ord("y")]


def test_hosts_without_a_window_keep_no_lines_to_draw(stub_curses_harness, fake_host, monkeypatch):
	# a host coming into a window is drawn whole: the lines noted while it had none were never drawn,
	# and held one entry per line of its output until it came in
	shown, hidden = _running_host(fake_host), _running_host(fake_host)
	shown.name, hidden.name = "mock-a", "mock-b"
	hidden.output = ["line {}".format(number) for number in range(1000)]
	hidden.lineNumToPrintSet = set(range(1000))
	polls = []

	def finish_on_second_poll():
		polls.append(None)
		if len(polls) == 2:
			shown.returncode = hidden.returncode = 0
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", finish_on_second_poll)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	# room for one host window
	multiSSH3.__generate_display(stub_curses_harness.window, [shown, hidden], min_char_len=80, min_line_len=20)

	drawn = [arg for window in stub_curses_harness.windows for method, args, kwargs in window.calls
		for arg in args if method == "addnstr" and isinstance(arg, str)]
	assert any("mock-a" in text for text in drawn) and not any("mock-b" in text for text in drawn)
	assert hidden.lineNumToPrintSet == set()


def test_readers_note_no_line_numbers_while_the_tui_runs(fake_host):
	# the TUI draws the lines added since its last frame: a set holding every new line's number was
	# 136 MB per million lines when output came faster than frames
	host = fake_host("mock-a", "true")
	host.interactive_stdin = True
	stream = io.BytesIO(b"".join(b"line %d\n" % number for number in range(1000)))

	multiSSH3.__handle_reading_stream(stream, host.stdout, host, host.stdout_buffer)

	assert len(host.output) == 1000
	assert host.lineNumToPrintSet == set()


def _frames(stub_curses_harness, host, monkeypatch, between):
	"""Run the display over host; between(frame) runs before each frame's drawing; the texts drawn."""
	frames = []

	def poll():
		frames.append(None)
		between(len(frames))
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", poll)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=8)
	return [arg for window in stub_curses_harness.windows for method, args, kwargs in window.calls
		for arg in args if method == "addnstr" and isinstance(arg, str)]


def test_generate_display_draws_the_lines_added_since_the_last_frame(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	host.lineNumToPrintSet = set()

	def between(frame):
		if frame == 2:
			host.output.extend(["second line", "third line"])
		elif frame == 4:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert any("second line" in text for text in drawn) and any("third line" in text for text in drawn)


def test_generate_display_draws_lines_written_again_after_a_cut(stub_curses_harness, fake_host, monkeypatch):
	# a host tried again drops what its attempt said (see _cut_output): the lines then added take the
	# places of lines already drawn
	host = _running_host(fake_host)
	host.output = ["attempt one", "said this", "and this"]

	def between(frame):
		if frame == 2:
			multiSSH3._cut_output(host, 1, 0, 0)
			host.output.extend(["attempt two", "says that"])
		elif frame == 4:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert any("said this" in text for text in drawn)
	assert any("attempt two" in text for text in drawn) and any("says that" in text for text in drawn)


def test_generate_display_redraws_a_line_replaced_in_place(stub_curses_harness, fake_host, monkeypatch):
	# the -t countdown replaces the last line
	host = _running_host(fake_host)
	host.output = ["working", "Timeout in [5] seconds!"]

	def between(frame):
		if frame == 2:
			host.output[-1] = "Timeout in [4] seconds!"
			host.lineNumToPrintSet.add(1)
		elif frame == 4:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert any("Timeout in [4] seconds!" in text for text in drawn)


def test_generate_display_draws_a_host_coming_into_a_window_whole(stub_curses_harness, fake_host, monkeypatch):
	# drawn before in another window or layout: its new window starts empty
	host = _running_host(fake_host)
	host.output = ["first", "second", "third"]
	host.printedLines = len(host.output)

	def between(frame):
		if frame == 3:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert all(any(line in text for text in drawn) for line in ("first", "second", "third"))


def test_generate_display_draws_unchanged_lines_once(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)

	def between(frame):
		if frame == 6:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert sum("working" in text for text in drawn) == 1


def test_generate_display_draws_lines_written_after_a_cut_a_frame_interrupts(stub_curses_harness, fake_host, monkeypatch):
	# a frame drawing between _cut_output's deleting and marking: the lines then added into the cut
	# places are still drawn
	host = _running_host(fake_host)
	host.output = ["attempt one", "said this", "and this"]
	real_update = set.update

	class Marks(set):
		def update(self, *others):
			# the cut has deleted: a frame draws now, before the marks
			between_frames.append(len(host.output))
			return real_update(self, *others)
	between_frames = []

	def between(frame):
		if frame == 2:
			host.lineNumToPrintSet = Marks(host.lineNumToPrintSet)
			multiSSH3._cut_output(host, 1, 0, 0)
		elif frame == 3:
			host.output.extend(["attempt two", "says that"])
		elif frame == 6:
			host.returncode = 0

	drawn = _frames(stub_curses_harness, host, monkeypatch, between)

	assert between_frames == [1]
	assert any("attempt two" in text for text in drawn) and any("says that" in text for text in drawn)


def test_generate_display_survives_output_shrinking_while_it_draws(stub_curses_harness, fake_host, monkeypatch):
	# a cut (or the -t countdown's pop) by another thread while a frame draws the lines it counted
	host = _running_host(fake_host)
	host.output = ["a", "b", "c"]
	original = multiSSH3._tui_first_shown_line
	frame_now = []

	def between(frame):
		frame_now.append(frame)
		if frame == 2:
			host.output.extend(["d", "e"])
		elif frame == 4:
			host.returncode = 0

	def first_shown(output, rows):
		if frame_now[-1] == 2 and len(output) == 5:
			multiSSH3._cut_output(host, 3)
		return original(output, rows)

	monkeypatch.setattr(multiSSH3, "_tui_first_shown_line", first_shown)
	polls = []

	def poll():
		polls.append(None)
		between(len(polls))
		return -1

	monkeypatch.setattr(stub_curses_harness.window, "getch", poll)
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=8)

	# it started over with "Error: list index out of range"
	assert result is None
