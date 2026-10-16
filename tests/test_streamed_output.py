'''
mssh writes its final output a chunk at a time as it makes it: the same text generate_output returns and
print_output prints, without the whole of it (or a copy of every line) in memory at once.
'''
import sys
import tracemalloc

import pytest

import multiSSH3

_COMMON = ["common output line %d of the hosts" % k for k in range(40)]


def _host(fake_host, name, stdout=(), stderr=(), returncode=0, command="cmd"):
	host = fake_host(name, command)
	host.stdout = list(stdout)
	host.stderr = list(stderr)
	host.returncode = returncode
	return host


# host sets, as functions of a function making a host
_CASES = {
	"no hosts": lambda h: [],
	"one host": lambda h: [h("127.0.0.1", ["hello"])],
	"no output": lambda h: [h("127.0.0.1"), h("127.0.0.2", returncode=1), h("127.0.0.3", returncode=None)],
	"identical hosts": lambda h: [h("127.0.0.%d" % i, _COMMON) for i in range(1, 5)],
	"near identical hosts": lambda h: [h("127.0.0.%d" % i, _COMMON + ["uptime %d" % i]) for i in range(1, 6)],
	"different hosts": lambda h: [h("127.0.0.%d" % i, ["line %d" % k for k in range(i * 7)]) for i in range(1, 5)],
	"wide lines": lambda h: [
		h("127.0.0.1", ["中文输出 %d 测试" % k for k in range(5)] + ["é combining", "emoji \U0001F600 x"]),
		h("节点2", ["全角文字" * 30]),
		h("127.0.0.3", ["中文输出 %d 测试" % k for k in range(5)], command="echo 中文\necho 第二行"),
	],
	"long lines": lambda h: [
		h("127.0.0.1", ["x" * 3000, "y " * 1500, "two spaces  "]),
		h("127.0.0.2", ["short"], command="echo " + "word " * 100),
	],
	"stderr and failures": lambda h: [
		h("127.0.0.1", ["out"], ["err 1", "err 2"], returncode=2),
		h("127.0.0.2", stderr=["only stderr"], returncode=1),
		h("127.0.0.3", stderr=["ssh: connect to host 127.0.0.3 port 22: Connection refused"], returncode=255),
		h("127.0.0.4", stderr=["ssh: connect to host 127.0.0.4 port 22: Connection refused"], returncode=255),
		h("127.0.0.5", ["ok"]),
	],
	"some merge, some not": lambda h: [h("127.0.0.%d" % i, _COMMON + ["uptime %d" % i], returncode=i % 2) for i in range(1, 5)]
		+ [h("127.0.0.%d" % i, ["alone %d" % i] * i, ["warning"]) for i in range(5, 8)]
		+ [h("root@127.0.0.9", _COMMON)],
}

_TYPED = [list("ls -l\n"), list("echo 中文")]


class _Recorder(object):
	'''Stands in for sys.stdout: notes each write, and how many writes came before the last flush.'''

	def __init__(self):
		self.writes = []
		self.flushed_after = None

	def write(self, text):
		self.writes.append(text)
		return len(text)

	def flush(self):
		self.flushed_after = len(self.writes)

	def isatty(self):
		return False


@pytest.fixture
def colors(monkeypatch):
	'''Sets the terminal's color capability; the color strings cached for it are dropped before and after.'''
	def clear():
		for function in (multiSSH3.rgb_to_ansi_color_string, multiSSH3.int_to_unique_ansi_color):
			function.cache_clear()

	def set_capability(capability):
		clear()
		monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: capability)
	yield set_capability
	clear()


def _streamed(monkeypatch, hosts, usejson, greppable, errors_only, typed):
	'''What mssh writes to stdout for hosts, and the recorder that took it.'''
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list(keys) for keys in typed])
	monkeypatch.setattr(multiSSH3, "__global_suppress_printout", errors_only)
	recorder = _Recorder()
	saved = sys.stdout
	sys.stdout = recorder
	try:
		multiSSH3._stream_output(hosts, usejson, greppable=greppable)
	finally:
		sys.stdout = saved
	return "".join(recorder.writes), recorder


@pytest.mark.parametrize("case", sorted(_CASES))
@pytest.mark.parametrize("mode", ["pretty", "greppable", "json"])
def test_streamed_output_is_the_generated_output(fake_host, monkeypatch, colors, case, mode):
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (80, 24))
	hosts = _CASES[case](lambda *args, **kwargs: _host(fake_host, *args, **kwargs))
	usejson, greppable = mode == "json", mode == "greppable"
	for capability in ("None", "24bit"):
		colors(capability)
		for errors_only in (False, True):
			for typed in ([[]], _TYPED):
				expected = multiSSH3.generate_output(hosts, usejson, greppable, encoding="utf-8",
					keyPressesIn=[list(keys) for keys in typed], errors_only=errors_only)

				text, recorder = _streamed(monkeypatch, hosts, usejson, greppable, errors_only, typed)

				# print_output's text, and the newline print adds; flushed after the last write
				assert text == expected + "\n", (capability, errors_only, typed)
				assert recorder.flushed_after == len(recorder.writes)


def test_streamed_output_takes_the_typed_keys_as_print_output_does(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	hosts = [_host(fake_host, "127.0.0.1", ["hello"])]

	text, _recorder = _streamed(monkeypatch, hosts, False, False, False, _TYPED)

	assert "░ User Inputs:" in text and "\n ls -l\n" in text and "\n echo 中文\n" in text
	# printed once: the next run's output does not show them again
	assert multiSSH3.__keyPressesIn[-1] == []


def test_streamed_output_clears_the_hosts_tui_lines(fake_host, monkeypatch):
	host = _host(fake_host, "127.0.0.1", ["persisted"])
	host.output = ["transient"]

	_streamed(monkeypatch, [host], True, False, False, [[]])

	assert host.output == []


def _big_hosts(fake_host, count=40, lines=5000):
	'''Hosts whose outputs do not merge: the same long output, and one line of their own.'''
	line = "common output line shared by all hosts, about sixty bytes"
	return [_host(fake_host, "127.0.0.%d" % i, [line] * lines + ["uptime %d" % i]) for i in range(1, count + 1)]


@pytest.mark.parametrize("mode", ["pretty", "greppable", "json"])
def test_big_output_is_written_in_chunks(fake_host, monkeypatch, mode):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	hosts = _big_hosts(fake_host)

	text, recorder = _streamed(monkeypatch, hosts, mode == "json", mode == "greppable", False, [[]])

	assert len(recorder.writes) > 10
	assert max(map(len, recorder.writes)) < len(text) / 10


class _Sink(object):
	'''A stdout that keeps nothing: only how much was written.'''

	def __init__(self):
		self.size = 0

	def write(self, text):
		self.size += len(text)
		return len(text)

	def flush(self):
		pass


@pytest.mark.parametrize("mode", ["pretty", "greppable", "json"])
def test_big_output_is_written_without_a_copy_of_it(fake_host, monkeypatch, mode):
	# neither the whole text nor a copy of every line (the pretty output's one space indent) is ever made
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	hosts = _big_hosts(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3, "__global_suppress_printout", False)
	sink = _Sink()
	monkeypatch.setattr(sys, "stdout", sink)

	tracemalloc.start()
	try:
		multiSSH3._stream_output(hosts, mode == "json", greppable=mode == "greppable")
		peak = tracemalloc.get_traced_memory()[1]
	finally:
		tracemalloc.stop()

	assert sink.size > 10 * 1000 * 1000
	assert peak < sink.size / 4


def _greppable_from_the_whole_table(hosts, keyPressesIn, encoding="utf-8"):
	'''The greppable output as pretty_format_table lays out the table of every output line.'''
	text = '*' * 80 + '\n'
	rows = [['host_name', 'return_code', 'output_type', 'output']]
	for host in hosts:
		added = False
		for line in host.stdout:
			rows.append([host.name, "rc: {}".format(host.returncode), 'stdout', line])
			added = True
		for line in host.stderr:
			rows.append([host.name, "rc: {}".format(host.returncode), 'stderr', line])
			added = True
		if not added:
			rows.append([host.name, "rc: {}".format(host.returncode), 'N/A', '<EMPTY>'])
		rows.append(['', '', '', ''])
	table = multiSSH3.pretty_format_table([rows[0]] + [row[:3] + [''] for row in rows[1:]]).split('\n')
	lines = table[:2]
	for line, row in zip(table[2:], rows[1:]):
		lines.append(line.rstrip(' ') + ' ' + row[3] if any(row) else line)
	text += '\n'.join(lines) + '\n' + '*' * 80 + '\n'
	if keyPressesIn[-1]:
		typed = [''.join(keys).encode(encoding, 'backslashreplace').decode(encoding, 'backslashreplace').replace('\\n', '↵')
			for keys in keyPressesIn if keys]
		text += 'User Inputs: ' + '\nUser Inputs: '.join(typed)
	return text


@pytest.mark.parametrize("case", sorted(_CASES))
def test_greppable_output_is_laid_out_as_the_whole_table(fake_host, monkeypatch, case):
	# the widths of the first three columns come from one row per host and output type, not every line
	hosts = _CASES[case](lambda *args, **kwargs: _host(fake_host, *args, **kwargs))
	for typed in ([[]], _TYPED):
		expected = _greppable_from_the_whole_table(hosts, typed)

		assert multiSSH3.generate_output(hosts, greppable=True, keyPressesIn=[list(keys) for keys in typed]) == expected
		assert _streamed(monkeypatch, hosts, False, True, False, typed)[0] == expected + "\n"
