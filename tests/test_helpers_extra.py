import multiSSH3


def test_pretty_format_table_list_and_empty():
	assert multiSSH3.pretty_format_table([]) == ""
	out = multiSSH3.pretty_format_table([["a", "bb"], ["ccc", "d"]])
	assert "a" in out and "ccc" in out
	assert "|" in out


def test_pretty_format_table_string_and_dict():
	tsv = "h1\th2\nv1\tv2"
	out = multiSSH3.pretty_format_table(tsv)
	assert "h1" in out and "v1" in out

	out2 = multiSSH3.pretty_format_table({"k": ["x", "y"]})
	assert "k" in out2 and "x" in out2


def test_pretty_format_table_with_header():
	out = multiSSH3.pretty_format_table(
		[["1", "2"], ["3", "4"]],
		header=["A", "B"],
	)
	assert "A" in out and "B" in out
	assert "1" in out


def test_get_terminal_size_fallback(monkeypatch):
	import os as std_os

	# get_terminal_size() does a local `import os`, so patch the stdlib module.
	monkeypatch.setattr(
		std_os,
		"get_terminal_size",
		lambda *_a, **_k: std_os.terminal_size((100, 40)),
	)
	cols, rows = multiSSH3.get_terminal_size()
	assert cols == 100
	assert rows == 40
