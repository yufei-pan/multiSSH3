'''
The final output wraps the command and the typed input to the terminal in columns: a CJK character
takes two, so a wrapped line of it is not twice as wide as the terminal.
'''
import textwrap

import pytest

import multiSSH3

COLUMNS = 40


@pytest.fixture
def output_at_40_columns(monkeypatch):
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (COLUMNS, 24))
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")

	def generate(command, typed=None):
		host = multiSSH3.Host("127.0.0.1", command)
		host.stdout, host.stderr, host.returncode = ["ok"], [], 0
		keys = [list(typed)] if typed else [[]]
		return multiSSH3.generate_output([host], keyPressesIn=keys).splitlines()

	return generate


def _section(lines, start, end):
	begin = next(i for i, line in enumerate(lines) if start in line)
	stop = next((i for i, line in enumerate(lines) if i > begin and end in line), len(lines))
	return lines[begin + 1:stop]


def test_a_wide_command_wraps_within_the_terminal(output_at_40_columns):
	command = "echo '" + "中文命令" * 8 + "' && df -h /data/共享目录"

	lines = _section(output_at_40_columns(command), "EXECUTED COMMAND", "STDOUT")

	assert len(lines) > 1
	assert all(multiSSH3._text_columns(line) <= COLUMNS - 1 for line in lines), lines
	# nothing is lost: the lines without their indents are the command
	assert "".join(line[1:] for line in lines) == command


def test_wide_typed_input_wraps_within_the_terminal(output_at_40_columns):
	typed = "输入的回答" * 6

	lines = output_at_40_columns("true", typed)
	shown = lines[lines.index(next(line for line in lines if "User Inputs" in line)) + 1:]
	shown = [line for line in shown if not line.startswith("─")]

	assert len(shown) > 1
	assert all(multiSSH3._text_columns(line) <= COLUMNS - 1 for line in shown), shown
	assert "".join(line[1:] for line in shown) == typed


@pytest.mark.parametrize("text", [
	"echo a fairly long command line that has to wrap at forty columns -- " * 3,
	"x" * 100,
	"tab\tseparated\twords " * 5,
])
def test_text_without_wide_characters_wraps_as_before(text):
	wrap = dict(width=39, tabsize=4, replace_whitespace=False, drop_whitespace=False, break_on_hyphens=False,
		initial_indent=" ", subsequent_indent="-")

	assert multiSSH3._wrap_columns(text, **wrap) == textwrap.wrap(text, **wrap)


@pytest.mark.parametrize("width", [1, 2, 3, 5, 8])
def test_a_narrow_width_still_shows_every_wide_character(width):
	text = "中文 abc 命令"

	lines = multiSSH3._wrap_columns(text, width=width, tabsize=4, replace_whitespace=False, drop_whitespace=False,
		break_on_hyphens=False, initial_indent="", subsequent_indent="")

	assert "".join(lines) == text
	# a wide character wider than the width itself is the only exception: it gets a line of its own
	assert all(multiSSH3._text_columns(line) <= max(width, 2) for line in lines), lines
