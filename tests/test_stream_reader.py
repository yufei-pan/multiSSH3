import io
import itertools
import random
import time

import pytest

import multiSSH3


def legacy_reader(stream, target, host, buffer):
	"""multiSSH3 6.26's byte-at-a-time reader, verbatim, the reference the chunked reader must match."""
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
			if buffer.tell() % 100 == 0 and buffer.tell() > 0:
				try:
					decodedLine = buffer.getvalue().decode(_encoding,errors='backslashreplace')
					lines = decodedLine.splitlines()
					if len(lines) > 1:
						for line in lines[:-1]:
							target.append(line)
							host.output.append(line)
							host.lineNumToPrintSet.add(len(host.output)-1)
						buffer.seek(0)
						buffer.truncate(0)
						buffer.write(lines[-1].encode(_encoding,errors='backslashreplace'))
						host.output_buffer.seek(0)
						host.output_buffer.truncate(0)
						host.output_buffer.write(lines[-1].encode(_encoding,errors='backslashreplace'))
				except UnicodeDecodeError:
					continue
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
	reader(stream, host.stdout, host, host.stdout_buffer)
	return (host.stdout, host.output, sorted(host.lineNumToPrintSet), host.stdout_buffer.getvalue(),
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
	("a" * 50 + "\x0c" + "b" * 100 + "\n").encode(),  # form feed before the 100 byte check
	("a" * 150 + " " + "b" * 200).encode(),
	("x" * 99 + "\x1e" + "y" * 300 + "\n").encode(),
	("p" * 120 + "\x85" + "q" * 100 + "\n").encode(),  # NEL
	("o" * 98 + " ").encode() * 3,  # separator straddling the 100 byte check
	b"y" * 70000 + b"\n" + b"tail",  # a line longer than one read
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
