import io
import itertools
import random
import threading
import time

import pytest

import multiSSH3


def legacy_reader(stream, target, host, buffer):
	"""multiSSH3 6.26's byte-at-a-time reader without its unicode line break split, the reference the chunked reader must match."""
	_encoding = multiSSH3._encoding
	def add_line(buffer,target, host):
		current_line_str = buffer.getvalue().decode(_encoding,errors='backslashreplace')
		target.append(current_line_str)
		host.output.append(current_line_str)
		host.lineNumToPrintSet.add(len(host.output)-1)
		buffer.seek(0)
		buffer.truncate(0)
		host.output_buffer.seek(0)
		host.output_buffer.truncate(0)
	try:
		for char in iter(lambda:stream.read(1), b''):
			host.lastUpdateTime = time.monotonic()
			if char == b'\n':
				add_line(buffer,target, host)
				continue
			elif char == b'\r':
				buffer.seek(0)
				host.output_buffer.seek(0)
			elif char == b'\x08':
				if buffer.tell() > 0:
					buffer.seek(buffer.tell() - 1)
					buffer.truncate()
				if host.output_buffer.tell() > 0:
					host.output_buffer.seek(host.output_buffer.tell() - 1)
					host.output_buffer.truncate()
			else:
				buffer.write(char)
				host.output_buffer.write(char)
	except ValueError:
		pass
	if buffer.tell() > 0:
		add_line(buffer,target, host)


class ChunkedPipe:
	"""Hands the data out in the given chunk sizes, the way reads from a pipe return it."""
	def __init__(self, data, sizes):
		self.data = data
		self.pos = 0
		self.sizes = itertools.cycle(sizes)

	def read1(self, size):
		chunk = self.data[self.pos:self.pos + min(size, next(self.sizes))]
		self.pos += len(chunk)
		return chunk


def _final_state(reader, stream):
	host = multiSSH3.Host("h", "cmd", ip="127.0.0.1")
	# with the TUI running. The reference also notes each line's number for the TUI, which the reader no
	# longer does (the TUI draws the lines added since its last frame): that set is not compared
	host.interactive_stdin = True
	reader(stream, host.stdout, host, host.stdout_buffer)
	return (host.stdout, host.output, host.stdout_buffer.getvalue(),
		host.stdout_buffer.tell(), host.output_buffer.getvalue(), host.output_buffer.tell())


def _assert_same_as_legacy(data, sizes):
	want = _final_state(legacy_reader, io.BytesIO(data))
	got = _final_state(multiSSH3.__handle_reading_stream, ChunkedPipe(data, sizes))
	assert got == want, (data[:120], sizes[:5])


CASES = [
	b"",
	b"one line\n",
	b"no newline at the end",
	b"a\nb\n\nc\n",
	b"crlf\r\nline\r\n",
	b"10%\r20%\r100%\n",
	b"progress 100%\r",  # ends on \r
	b"progress\rab",
	b"abc\x08\x08X\n",
	b"\x08\x08start\n",
	b"x\x08\x08\x08\n",
	b"bad \xff\xfe bytes\n",
	"café 中文 \U0001F600\n".encode(),
	("a" * 50 + "\x0c" + "b" * 100 + "\n").encode(),  # a form feed does not end a line
	("a" * 150 + " " + "b" * 200).encode(),
	("x" * 99 + "\x1e" + "y" * 300 + "\n").encode(),
	("p" * 120 + "\x85" + "q" * 100 + "\n").encode(),  # NEL
	("o" * 98 + " ").encode() * 3,  # a long line without a line break
	b"y" * 70000 + b"\n" + b"tail",  # a line longer than one read
	b"".join(b"line %d\n" % i for i in range(3000)) + b"unfinished",  # many short lines
	b"".join(b"line %d\r\n" % i for i in range(3000)) + b"unfinished\r",  # windows line ends
	b"unix\nwin\r\nmac\rold\n\rx\r\r\ny\n" * 40,  # mixed line ends
	b"abcdefgh\rXY" + b"\nplain" * 300 + b"\n",  # whole lines after a \r in an unfinished line
	b"bad \xff\xfe bytes\n\xc3\n\xe2\x80\n\xed\xa0\x80\nok\n" * 30,  # invalid utf-8 in whole lines
	"café 中文 \U0001F600\n".encode() * 300,
	b"plain\n" * 300 + ("x" * 150 + "\u2028" + "y" * 150 + "\n").encode() + b"plain\n" * 300,
	b"plain\n" * 300 + b"form\x0cfeed\n" + b"plain\n" * 300,  # a line holding a form feed
	"中".encode() * 30000 + b"\nend\n",  # a long multibyte line
	("\x0c" + "x" * 999 + "\n").encode() * 3,  # a form feed, then a long run
	(("o" * 98 + "\x1c") * 30 + "\r" + ("p" * 98 + "\x1d") * 30 + "\n").encode(),
	b"progress " + b"".join(b"%d%%\r" % i for i in range(300)) + b"\x08\x08done\n",
	("r" * 180 + "\r" + "s" * 30 + " " + "t" * 150 + "\n").encode(),
]
CHUNKINGS = [[1], [2], [7], [64], [65536], [3, 1, 100, 5, 4096]]


@pytest.mark.parametrize("data", CASES)
@pytest.mark.parametrize("sizes", CHUNKINGS, ids=lambda sizes: "chunks{}".format(sizes))
def test_chunked_reader_matches_byte_reader(data, sizes):
	_assert_same_as_legacy(data, sizes)


TOKENS = [b"a"] * 12 + [b"\n", b"\n", b"\r", b"\x08", b"\x0c", b"\x1e", b"\xff", b"\x85",
	"é".encode(), "中".encode(), " ".encode(), " ".encode()]


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1"])
def test_chunked_reader_matches_byte_reader_on_random_streams(monkeypatch, encoding):
	monkeypatch.setattr(multiSSH3, "_encoding", encoding)
	rng = random.Random(6027)
	for _ in range(200):
		data = b"".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 700)))
		sizes = [rng.randint(1, 150) for _ in range(8)]
		_assert_same_as_legacy(data, sizes)


# mostly whole lines, so that many chunks are added at once, with each special case mixed in
LINE_TOKENS = [b"word "] * 10 + [b"\n"] * 10 + [b"\r\n"] * 3 + [b"x" * 97, b"y" * 150, b"\r", b"\x08",
	b"\x0b", b"\x0c", b"\x1c", b"\x85", "\x85".encode(), "\u2028".encode(), b"\xff", b"\xc3", b"\xe2\x80",
	"é".encode(), "中".encode(), "\U0001F600".encode(), b"\xef\xbb\xbf"]


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "ascii", "utf-8-sig", "gbk"])
def test_chunked_reader_matches_byte_reader_on_random_line_streams(monkeypatch, encoding):
	monkeypatch.setattr(multiSSH3, "_encoding", encoding)
	rng = random.Random(6031)
	for _ in range(150):
		data = b"".join(rng.choice(LINE_TOKENS) for _ in range(rng.randint(0, 900)))
		sizes = [rng.randint(1, 400) for _ in range(8)]
		_assert_same_as_legacy(data, sizes)


class CountingBuffer(io.BytesIO):
	"""A line buffer that counts its writes: per line or per byte work in the reader shows as writes."""
	def __init__(self):
		super().__init__()
		self.writes = 0

	def write(self, data):
		self.writes += 1
		return super().write(data)


@pytest.mark.parametrize("line_end", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_reader_adds_a_chunk_of_whole_lines_at_once(line_end):
	lines = ["line {}".format(index) for index in range(1000)]
	data = line_end.join(line.encode() for line in lines) + line_end + b"unfinished"
	host = multiSSH3.Host("h", "cmd", ip="127.0.0.1")
	buffer = CountingBuffer()
	multiSSH3.__handle_reading_stream(io.BytesIO(data), host.stdout, host, buffer)
	assert host.stdout == lines + ["unfinished"]
	# only the first line (it may end one begun in an earlier chunk) and the unfinished one pass through the line buffer
	assert buffer.writes == 2


# in two reads: a first line with a \r and whole lines after it (added at once), then a line holding a
# form feed, and an unfinished line
TUI_LINES_READS = [b"a\rb\n" + b"whole\n" * 10 + b"x", ("x" * 49 + "\x0c" + "y" * 100 + "\n").encode() + b"unfinished"]


@pytest.mark.parametrize("tui", [True, False], ids=["tui", "no-tui"])
def test_reader_notes_no_lines_to_redraw(tui):
	host = multiSSH3.Host("h", "cmd", ip="127.0.0.1")
	host.interactive_stdin = tui
	stream = ChunkedPipe(b"".join(TUI_LINES_READS), [len(data) for data in TUI_LINES_READS])
	multiSSH3.__handle_reading_stream(stream, host.stdout, host, host.stdout_buffer)
	assert host.stdout == ["b"] + ["whole"] * 10 + ["x" * 50 + "\x0c" + "y" * 100, "unfinished"]
	assert host.output == host.stdout
	# the TUI draws the lines added since its last frame (Host.printedLines): a set of every new line's
	# number held 136 MB per million lines when output came faster than frames
	assert host.lineNumToPrintSet == set()


def test_a_command_with_no_output_runs_quietly_under_an_unknown_encoding(monkeypatch, capsys):
	# set_global_with_args takes args.encoding as it is (a caller's mistake): the readers must not die with a traceback
	monkeypatch.setattr(multiSSH3, "_encoding", "no-such-codec")
	failures = []
	# Python 3.8+ hands a thread's exception to threading.excepthook; 3.6 and 3.7 print it to stderr
	monkeypatch.setattr(threading, "excepthook", lambda hook_args: failures.append(hook_args.exc_value), raising=False)
	host = multiSSH3.Host("h", "true", shell=True)

	multiSSH3.run_command(host, threading.Semaphore(1), 20)

	assert failures == []
	assert "Traceback" not in capsys.readouterr().err
	assert host.returncode == 0
	assert host.stdout == []
