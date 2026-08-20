def test_stub_curses_harness_records_windows_and_keys(stub_curses_harness):
	harness = stub_curses_harness
	harness.inject_keys([410])
	child = harness.newwin(3, 20, 1, 2)

	assert harness.window.getch() == 410
	assert child.getmaxyx() == (3, 20)
	assert child.calls[0] == ("origin", (1, 2), {})
