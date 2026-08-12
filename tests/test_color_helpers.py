from types import SimpleNamespace

import multiSSH3


def test_rgb_to_256_gray_and_cube():
	assert multiSSH3._rgb_to_256_color(0, 0, 0) == 232
	assert multiSSH3._rgb_to_256_color(255, 255, 255) == 255
	cube = multiSSH3._rgb_to_256_color(255, 0, 0)
	assert 16 <= cube <= 231


def test_rgb_to_16_and_8():
	assert multiSSH3._rgb_to_16_color(0, 0, 0) == 0
	assert multiSSH3._rgb_to_16_color(255, 0, 0) == 9
	assert 0 <= multiSSH3._rgb_to_8_color(255, 128, 0) <= 7


def test_rgb_to_ansi_under_forced_caps(monkeypatch):
	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()

	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	assert multiSSH3.rgb_to_ansi_color_string(1, 2, 3) == ""

	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "24bit")
	assert "38;2;10;20;30" in multiSSH3.rgb_to_ansi_color_string(10, 20, 30)

	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "256")
	s = multiSSH3.rgb_to_ansi_color_string(255, 0, 0)
	assert s.startswith("\x1b[38;5;")

	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "16")
	assert multiSSH3.rgb_to_ansi_color_string(255, 0, 0).startswith("\x1b[")

	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "8")
	assert multiSSH3.rgb_to_ansi_color_string(0, 0, 0).startswith("\x1b[")


def test_int_to_color_and_unique_ansi(monkeypatch):
	rgb = multiSSH3.int_to_color(0x808080)
	assert len(rgb) == 3
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "24bit")
	if hasattr(multiSSH3.int_to_unique_ansi_color, "cache_clear"):
		multiSSH3.int_to_unique_ansi_color.cache_clear()
	if hasattr(multiSSH3.rgb_to_ansi_color_string, "cache_clear"):
		multiSSH3.rgb_to_ansi_color_string.cache_clear()
	code = multiSSH3.int_to_unique_ansi_color(42)
	assert isinstance(code, str) and "\x1b[" in code


def test_get_terminal_color_capability_notty(monkeypatch):
	fake_out = SimpleNamespace(isatty=lambda: False)
	monkeypatch.setattr(multiSSH3.sys, "stdout", fake_out)
	assert multiSSH3.get_terminal_color_capability() == "None"


def test_get_terminal_color_capability_env(monkeypatch):
	# Zero-arg helper is lru-cached; clear between env changes.
	fake_out = SimpleNamespace(isatty=lambda: True)
	monkeypatch.setattr(multiSSH3.sys, "stdout", fake_out)
	monkeypatch.delenv("COLORTERM", raising=False)
	multiSSH3.FORCE_TRUECOLOR = False

	def _cap():
		if hasattr(multiSSH3.get_terminal_color_capability, "cache_clear"):
			multiSSH3.get_terminal_color_capability.cache_clear()
		return multiSSH3.get_terminal_color_capability()

	monkeypatch.setenv("TERM", "dumb")
	assert _cap() == "None"

	monkeypatch.setenv("TERM", "xterm-256color")
	assert _cap() == "256"

	monkeypatch.setenv("COLORTERM", "truecolor")
	assert _cap() == "24bit"
