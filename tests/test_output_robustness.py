"""The printed results: their order, and printing them to a closed pipe or a narrow encoding."""
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
