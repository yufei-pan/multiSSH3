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


def test_pretty_format_table_pads_wide_characters_by_display_width():
	# East Asian wide characters take two terminal columns, a combining mark none.
	out = multiSSH3.pretty_format_table([["name", "v"], ["中文", "1"], ["abcd", "2"], ["e\u0301", "3"]])
	assert out == "name | v\n-----+--\n中文 | 1\nabcd | 2\ne\u0301    | 3\n"


def test_pretty_format_table_pads_colored_cells_by_visible_width():
	out = multiSSH3.pretty_format_table([["k", "v"], ["\x1b[31mred\x1b[0m", "1"], ["plain", "2"]])
	assert out == "k     | v\n------+--\n\x1b[31mred\x1b[0m   | 1\nplain | 2\n"


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


def test_join_threads_resolves_global_at_call_time():
	"""Regression: default must not bind the set object at def time (multiCMD sentinel)."""
	import threading

	original = multiSSH3.__running_threads
	multiSSH3.join_threads(timeout=0.01)
	# After pruning, global may be a new set object
	assert multiSSH3.join_threads.__defaults__[0] is ...

	# Simulate processRunOnHosts assigning a fresh global set after a join
	joined = []

	def worker():
		joined.append(True)

	t = threading.Thread(target=worker)
	multiSSH3.__running_threads = {t}
	t.start()
	multiSSH3.join_threads(timeout=2)  # must see the *current* global
	assert joined == [True]
	assert t not in multiSSH3.__running_threads or not t.is_alive()
	multiSSH3.__running_threads = original


def _fake_nofile_limits(monkeypatch, soft, hard, max_soft):
	limits = {"value": (soft, hard)}
	calls = []

	def setrlimit(kind, value):
		calls.append(value)
		if value[0] > max_soft:
			raise ValueError("current limit exceeds maximum limit")
		limits["value"] = value

	monkeypatch.setattr(multiSSH3.resource, "getrlimit", lambda kind: limits["value"])
	monkeypatch.setattr(multiSSH3.resource, "setrlimit", setrlimit)
	return calls


def test_raise_nofile_soft_limit_with_unlimited_hard_limit(monkeypatch):
	infinity = multiSSH3.resource.RLIM_INFINITY
	calls = _fake_nofile_limits(monkeypatch, 256, infinity, max_soft=10240)

	assert multiSSH3._raise_nofile_soft_limit() == 10240
	assert calls == [(65536, infinity), (10240, infinity)]


def test_raise_nofile_soft_limit_keeps_soft_limit_when_raise_fails(monkeypatch):
	_fake_nofile_limits(monkeypatch, 256, multiSSH3.resource.RLIM_INFINITY, max_soft=0)

	assert multiSSH3._raise_nofile_soft_limit() == 256


def test_raise_nofile_soft_limit_raises_to_finite_hard_limit(monkeypatch):
	calls = _fake_nofile_limits(monkeypatch, 1024, 524288, max_soft=524288)

	assert multiSSH3._raise_nofile_soft_limit() == 524288
	assert calls == [(524288, 524288)]


def test_import_and_max_connections_survive_unknown_cpu_count(tmp_path):
	import subprocess
	import sys
	from pathlib import Path

	package_root = Path(multiSSH3.__file__).resolve().parent
	code = (
		"import os, sys\n"
		"os.cpu_count = lambda: None\n"
		"sys.path.insert(0, {!r})\n"
		"import multiSSH3\n"
		"print(multiSSH3._normalize_max_connections(None), multiSSH3._normalize_max_connections(-2))\n"
	).format(str(package_root))
	result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path, timeout=60)

	assert result.returncode == 0, result.stderr
	assert result.stdout.split() == ["4", "2"]
