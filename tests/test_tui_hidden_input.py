"""
A line typed in the curses display goes to every host and was shown everywhere: as "> S3cretPw" in
each host's window, in each host's stdout (JSON, the output at the end, scrollback) and under "User
Inputs". A line typed while a host asks for a password (its last line ends like "Password:",
"[sudo] password for alice: ", "Enter passphrase for key '...': ") is sent as typed but never shown or
kept: the input line shows one * per character, the rest a fixed "********".
"""
import io
import threading
import time

import pytest

import multiSSH3


SECRET = "S3cretPw"


@pytest.mark.parametrize("prompt", [
	"Password: ",
	"password:",
	"[sudo] password for alice: ",
	"[sudo] Passwort für alice: ",
	"Enter passphrase for key '/home/alice/.ssh/id_ed25519': ",
	"Password for 'https://alice@example.com':",
	"(alice@node1) Password:",
	"Enter PEM pass phrase:",
	"BECOME password: ",
	"Mot de passe :",
])
def test_password_prompts_are_recognised(fake_host, prompt):
	host = fake_host("mock-a", "sudo -S true")
	host.stderr_buffer.write(prompt.encode())

	assert multiSSH3._asks_for_password(host)


@pytest.mark.parametrize("last_line", ["", "$ ", "Continue? [y/N] ", "password changed for alice", "Name: "])
def test_other_lines_are_not_password_prompts(fake_host, last_line):
	host = fake_host("mock-a", "true")
	host.stdout_buffer.write(last_line.encode())
	host.output = ["Running command: ssh -- mock-a true"]

	assert not multiSSH3._asks_for_password(host)


def test_a_prompt_that_ended_its_line_counts(fake_host):
	host = fake_host("mock-a", "true")
	host.output = ["Running command: ssh -- mock-a true", "Enter password:"]

	assert multiSSH3._asks_for_password(host)


def _display(stub_curses_harness, fake_host, monkeypatch, keys, prompt="[sudo] password for alice: "):
	host = fake_host("mock-a", "sudo -S true")
	host.returncode = None
	host.output = ["Running command: ssh -- mock-a sudo -S true"]
	host.stderr_buffer.write(prompt.encode())
	host.lineNumToPrintSet = {0}
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stats = []
	draw = multiSSH3._curses_add_string_to_window

	def record(window, line="", **kwargs):
		stats.append(line)
		return draw(window, line=line, **kwargs)

	monkeypatch.setattr(multiSSH3, "_curses_add_string_to_window", record)
	# 12 is the refresh key here: it ends this round of the display
	stub_curses_harness.inject_keys(keys + [12])
	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)
	return stats


def test_a_password_typed_at_a_prompt_is_sent_but_not_shown(stub_curses_harness, fake_host, monkeypatch):
	drawn = _display(stub_curses_harness, fake_host, monkeypatch, [ord(c) for c in SECRET])

	typed = multiSSH3.__keyPressesIn[-1]
	assert "".join(typed) == SECRET
	assert isinstance(typed, multiSSH3._HiddenInput)
	assert not any(SECRET[:3] in line for line in drawn)
	assert any("Send CMD: " + "*" * (len(SECRET) - 1) in line for line in drawn)


def test_enter_keeps_the_line_hidden(stub_curses_harness, fake_host, monkeypatch):
	_display(stub_curses_harness, fake_host, monkeypatch, [ord(c) for c in SECRET] + [10])

	assert "".join(multiSSH3.__keyPressesIn[0]) == SECRET + "\n"
	assert isinstance(multiSSH3.__keyPressesIn[0], multiSSH3._HiddenInput)


def test_a_line_typed_without_a_prompt_is_shown(stub_curses_harness, fake_host, monkeypatch):
	drawn = _display(stub_curses_harness, fake_host, monkeypatch, [ord(c) for c in "uptime"], prompt="$ ")

	assert not isinstance(multiSSH3.__keyPressesIn[-1], multiSSH3._HiddenInput)
	assert any("Send CMD: uptim" in line for line in drawn)


def test_a_hidden_line_recalled_from_the_history_stays_hidden(stub_curses_harness, fake_host, monkeypatch):
	host = fake_host("mock-a", "bash")
	host.returncode = None
	host.output = ["Running command: ssh -- mock-a bash"]
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [multiSSH3._HiddenInput(SECRET + "\n"), []])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	# up arrow, then a key that edits the recalled line, then refresh
	stub_curses_harness.inject_keys([259, ord("x"), 12])

	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert isinstance(multiSSH3.__keyPressesIn[-1], multiSSH3._HiddenInput)
	assert "".join(multiSSH3.__keyPressesIn[-1]).startswith(SECRET)


def test_the_hosts_get_the_password_but_show_and_keep_only_stars(fake_host, monkeypatch):
	host = fake_host("mock-a", "sudo -S true")
	host.interactive_stdin = True
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [multiSSH3._HiddenInput(SECRET + "\n"), list("uptime\n"), []])
	stream = io.BytesIO()
	stream.close = lambda: None
	stop = threading.Event()

	def stop_when_sent():
		deadline = time.monotonic() + 5
		while len(host.stdout) < 2 and time.monotonic() < deadline:
			time.sleep(0.01)
		stop.set()

	threading.Thread(target=stop_when_sent, daemon=True).start()
	multiSSH3.__handle_writing_stream(stream, stop, host)

	assert stream.getvalue() == (SECRET + "\nuptime\n").encode()
	assert host.stdout == ["> ******** (hidden at a password prompt)↵", "> uptime↵"]
	assert not any(SECRET in line for line in host.output)


@pytest.mark.parametrize("greppable", [False, True])
def test_user_inputs_at_the_end_hide_a_password(fake_host, greppable):
	host = fake_host("mock-a", "sudo -S true")
	host.returncode = 0
	host.stdout = ["done"]
	typed = [multiSSH3._HiddenInput(SECRET + "\n"), list("uptime\n"), list("partial")]

	text = multiSSH3.generate_output([host], greppable=greppable, keyPressesIn=typed)

	assert "User Inputs" in text
	assert SECRET not in text
	# the pretty output wraps the footer to the width of the output
	assert "******** (hidden" in text
	assert "uptime" in text


# the line comes from the host: megabytes long, maybe made to be slow to search
HUGE_LINES = [
	"password:" * 116509 + "x",
	"password " * 116509 + "x",
	"password:" * 116509,
	"x" * 1048576,
]


@pytest.mark.parametrize("line", HUGE_LINES, ids=["colons", "no-colon", "ends-with-colon", "plain"])
def test_a_huge_last_line_is_checked_quickly(fake_host, line):
	host = fake_host("mock-a", "true")
	host.output = [line]
	host.stdout_buffer.write(line.encode())

	started = time.perf_counter()
	multiSSH3._asks_for_password(host)
	elapsed = time.perf_counter() - started

	assert elapsed < 0.01


def test_only_the_end_of_a_long_line_can_make_it_a_prompt(fake_host):
	host = fake_host("mock-a", "true")
	host.stdout_buffer.write(("password " + "x" * 1000 + ":").encode())

	assert not multiSSH3._asks_for_password(host)
