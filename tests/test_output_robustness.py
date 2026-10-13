"""The printed results: their order, and printing them to a closed pipe or a narrow encoding."""
import codecs
import json
import os
import subprocess
import sys
from pathlib import Path

import multiSSH3

ROOT = str(Path(multiSSH3.__file__).resolve().parent)

# Renders hosts given as JSON [[name, stdout lines], ...] with the plain (merged) output, no colors.
_RENDER_SCRIPT = (
	"import json, sys\n"
	"sys.path.insert(0, {root!r})\n"
	"import multiSSH3\n"
	"multiSSH3.get_terminal_color_capability = lambda: 'None'\n"
	"multiSSH3.get_terminal_size = lambda: (100, 40)\n"
	"hosts = []\n"
	"for name, stdout in json.loads(sys.argv[1]):\n"
	"\thost = multiSSH3.Host(name, 'cmd', ip=name)\n"
	"\thost.stdout = stdout\n"
	"\thost.returncode = 0\n"
	"\thosts.append(host)\n"
	"sys.stdout.write(multiSSH3.generate_output(hosts))\n"
).format(root=ROOT)


def _render_with_hash_seeds(hosts, seeds=range(6)):
	"""The plain output of hosts, once per string hash seed: sets of host names iterate in a different order each."""
	renders = set()
	for seed in seeds:
		result = subprocess.run(
			[sys.executable, "-c", _RENDER_SCRIPT, json.dumps(hosts)],
			env=dict(os.environ, PYTHONHASHSEED=str(seed)),
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60,
		)
		assert result.returncode == 0, result.stderr
		renders.add(result.stdout)
	return renders


def _host_headers(text):
	return [line.lstrip("■").strip() for line in text.splitlines() if line.startswith("■")]


def test_hosts_that_do_not_merge_print_in_natural_order():
	# outputs of very different lengths never merge; .10 must come after .2 (natural, not string order)
	hosts = [
		["127.0.0.10", ["line %d" % k for k in range(80)]],
		["127.0.0.2", ["line %d" % k for k in range(20)]],
		["127.0.0.1", ["line %d" % k for k in range(10)]],
		["127.0.0.3", ["line %d" % k for k in range(40)]],
	]

	renders = _render_with_hash_seeds(hosts)

	assert len(renders) == 1
	assert _host_headers(renders.pop()) == ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.10"]


def test_merge_groups_print_in_natural_order_of_their_hosts():
	# two groups of the same output size: the one holding 127.0.0.1 comes first
	alpha = ["alpha %d" % k for k in range(10)]
	beta = ["beta %d" % k for k in range(10)]
	hosts = [
		["127.0.0.4", beta],
		["127.0.0.3", alpha],
		["127.0.0.2", beta],
		["127.0.0.1", alpha],
	]

	renders = _render_with_hash_seeds(hosts)

	assert len(renders) == 1
	text = renders.pop()
	assert text.index("alpha 0") < text.index("beta 0")


def test_lines_only_some_hosts_print_come_in_natural_host_order():
	names = ["127.0.0.10", "127.0.0.3", "127.0.0.1", "127.0.0.2"]
	hosts = [
		[name, ["common %d" % k for k in range(30)] + ["only " + name] + ["tail %d" % k for k in range(10)]]
		for name in names
	]

	renders = _render_with_hash_seeds(hosts)

	assert len(renders) == 1
	text = renders.pop()
	only_lines = [line.strip() for line in text.splitlines() if line.strip().startswith("only ")]
	assert only_lines == ["only 127.0.0.1", "only 127.0.0.2", "only 127.0.0.3", "only 127.0.0.10"]


class _YieldsFirst(set):
	"""A set that yields one chosen item first, like a string hash seed could make a real set do."""

	def __init__(self, items, first):
		super().__init__(items)
		self.first = first

	def __iter__(self):
		yield self.first
		for item in set.__iter__(self):
			if item != self.first:
				yield item


def _line_bags(fake_host, *return_codes):
	hosts = []
	for i, returncode in enumerate(return_codes, 1):
		host = fake_host("127.0.0.%d" % i, "cmd")
		host.stdout = ["line %d" % k for k in range(5)]
		host.returncode = returncode
		hosts.append(host)
	_outputs, line_bags, _by_len, _keys, _width = multiSSH3.get_host_raw_output(hosts, terminal_width=80)
	return [line_bags[host.name] for host in hosts]


def test_outputs_over_the_merge_threshold_merge_whatever_the_set_order(fake_host):
	# the same 5 lines with return codes 0 and 1: 12 of 13 items shared, over the 0.9 threshold
	ok_bag, failed_bag = _line_bags(fake_host, 0, 1)
	assert len(ok_bag & failed_bag) >= 0.9 * len(ok_bag)
	(only_in_ok,) = ok_bag - failed_bag

	assert multiSSH3.can_merge(_YieldsFirst(ok_bag, only_in_ok), failed_bag, 0.9)
	assert multiSSH3.can_merge(_YieldsFirst(failed_bag, (only_in_ok[0], "1")), ok_bag, 0.9)


def test_a_larger_first_bag_merges_whatever_the_set_order(fake_host):
	(bag,) = _line_bags(fake_host, 0)
	larger = set(bag) | {"one more line"}

	assert multiSSH3.can_merge(_YieldsFirst(larger, "one more line"), bag, 0.9)


def _greppable(fake_host, *stdouts):
	hosts = []
	for i, stdout in enumerate(stdouts, 1):
		host = fake_host("127.0.0.%d" % i, "cmd")
		host.stdout = list(stdout)
		host.returncode = 0
		hosts.append(host)
	return multiSSH3.generate_output(hosts, greppable=True).split("\n")


def test_greppable_lines_are_not_padded_to_the_longest_output_line(fake_host):
	long_line = "x" * 5000
	lines = _greppable(fake_host, ["1", "2", long_line], ["short"])

	assert "127.0.0.1 | rc: 0       | stdout      | 1" in lines
	assert "127.0.0.1 | rc: 0       | stdout      | " + long_line in lines
	assert "127.0.0.2 | rc: 0       | stdout      | short" in lines
	assert [line for line in lines if line.endswith(" ")] == []
	# the dividers between hosts do not stretch to the long line either
	dividers = [line for line in lines if line.startswith("---")]
	assert len(dividers) == 3
	assert max(map(len, dividers)) <= 80


def test_greppable_lines_keep_the_spaces_the_output_ends_with(fake_host):
	lines = _greppable(fake_host, ["two spaces  ", "x" * 100])

	assert "127.0.0.1 | rc: 0       | stdout      | two spaces  " in lines


# Runs two commands (or the arguments) on 127.0.0.[1-4] (.2 and .4 fail) through main, with run_command
# replaced (nothing is run, IP addresses need no lookup) and no env files; each command run is logged
_CLI_SCRIPT = (
	"import sys\n"
	"sys.path.insert(0, {root!r})\n"
	"import multiSSH3\n"
	"def fake_run(host, sem, timeout=60, passwds=None, **kwargs):\n"
	"\twith open({ran!r}, 'a', encoding='utf-8', errors='surrogateescape') as ran:\n"
	"\t\tran.write(host.command + '\\n')\n"
	"\thost.stdout.extend({stdout!a})\n"
	"\thost.returncode = 1 if host.name in ('127.0.0.2', '127.0.0.4') else 0\n"
	"multiSSH3.run_command = fake_run\n"
	"multiSSH3.main(['127.0.0.[1-4]'] + (sys.argv[1:] or ['echo first', 'echo second']) + ['--no_watch', '--no_history', '-ef', '/dev/null'])\n"
)


def _run_cli_script(tmp_path, stdout_lines, env_changes=None, drop_env=(), commands=(), **popen_args):
	run_dir = tmp_path / "run"
	run_dir.mkdir(mode=0o700)
	ran = tmp_path / "ran"
	script = tmp_path / "mssh_cli.py"
	script.write_text(_CLI_SCRIPT.format(root=ROOT, ran=str(ran), stdout=list(stdout_lines)))
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(run_dir), **(env_changes or {}))
	for name in drop_env:
		env.pop(name, None)
	result = subprocess.run([sys.executable, str(script)] + list(commands), env=env, cwd=str(tmp_path), timeout=60, **popen_args)
	return result, ran.read_text(encoding="utf-8").splitlines() if ran.exists() else []


def _closed_pipe():
	"""A pipe nobody reads: its write end, the read end already closed (like head that exited)."""
	read_fd, write_fd = os.pipe()
	os.close(read_fd)
	return write_fd


def test_a_closed_stdout_ends_the_run_quietly_with_its_own_status(tmp_path):
	write_fd = _closed_pipe()
	try:
		result, ran = _run_cli_script(tmp_path, ["line %d" % k for k in range(2000)], stdout=write_fd, stderr=subprocess.PIPE)
	finally:
		os.close(write_fd)
	stderr = result.stderr.decode("utf-8", "replace")

	assert "Traceback" not in stderr
	assert "BrokenPipeError" not in stderr
	# the two failed hosts, as if stdout had been read
	assert result.returncode == 2, stderr
	# like a program SIGPIPE ends, the second command does not start
	assert ran == ["echo first"] * 4


def test_a_closed_stdout_and_stderr_pipe_ends_the_run_with_its_own_status(tmp_path):
	# mssh ... 2>&1 | head: the flush at exit must not fail on stderr either (Python would exit 120)
	write_fd = _closed_pipe()
	try:
		result, ran = _run_cli_script(tmp_path, ["line %d" % k for k in range(2000)], stdout=write_fd, stderr=write_fd)
	finally:
		os.close(write_fd)

	assert result.returncode == 2
	assert ran == ["echo first"] * 4


def test_output_that_fits_the_pipe_buffer_still_ends_quietly(tmp_path):
	# a short output waits in stdout's buffer: the failed write must not wait for the flush at exit
	write_fd = _closed_pipe()
	try:
		result, ran = _run_cli_script(tmp_path, ["short"], stdout=write_fd, stderr=subprocess.PIPE)
	finally:
		os.close(write_fd)
	stderr = result.stderr.decode("utf-8", "replace")

	assert "Traceback" not in stderr and "BrokenPipeError" not in stderr
	assert result.returncode == 2, stderr
	assert ran == ["echo first"] * 4


def test_characters_stdout_cannot_encode_print_as_escapes(tmp_path):
	# PYTHONIOENCODING=latin-1 (or ascii): the output step used to raise UnicodeEncodeError after the commands ran
	result, ran = _run_cli_script(
		tmp_path, ["check \u2713 ok", "\u4e2d\u6587"], {"PYTHONIOENCODING": "ascii"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout = result.stdout.decode("ascii")
	stderr = result.stderr.decode("ascii", "replace")

	assert "Traceback" not in stderr and "UnicodeEncodeError" not in stderr
	assert result.returncode == 2, stderr
	assert "check \\u2713 ok" in stdout
	assert "\\u4e2d\\u6587" in stdout
	assert ran == ["echo first"] * 4 + ["echo second"] * 4


def test_the_c_locale_prints_the_output(tmp_path):
	# Python 3.6 under cron on CentOS 7: an ASCII stdout. Newer Pythons switch the C locale to UTF-8 themselves
	result, ran = _run_cli_script(
		tmp_path, ["check \u2713 ok"], {"LANG": "C", "LC_ALL": "C"}, ("PYTHONIOENCODING", "PYTHONUTF8", "LC_CTYPE"),
		commands=["echo mark \u2713", "echo second"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout = result.stdout.decode("utf-8")
	stderr = result.stderr.decode("utf-8", "replace")

	assert "Traceback" not in stderr and "UnicodeEncodeError" not in stderr
	assert result.returncode == 2, stderr
	assert "check \u2713 ok" in stdout or "check \\u2713 ok" in stdout
	# the command came in as bytes the C locale cannot decode (3.6): it is printed back as those bytes
	assert "echo mark \u2713" in stdout


def test_the_escape_handler_writes_undecodable_bytes_back_and_escapes_the_rest():
	codecs.register_error("test-mssh-escape", multiSSH3._escape_or_restore_bytes)
	# an argument decoded with surrogateescape, then a character ASCII lacks
	text = "argv \udce2\udc9c\udc93 output \u2713"

	assert text.encode("ascii", "test-mssh-escape") == b"argv \xe2\x9c\x93 output \\u2713"
	assert text.encode("utf-8", "test-mssh-escape") == b"argv \xe2\x9c\x93 output \xe2\x9c\x93"
