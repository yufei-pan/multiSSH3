'''
Autocomplete timing and size at the target scale (not a test): 10k hosts, 20k invocations.

Run: python3 tests/bench_complete.py
Prints observations only; nothing passes or fails on them (see the autocomplete spec).
'''
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def synthetic(home, hosts=10000, invocations=20000):
	lines = []
	commands = ['nvidia-smi', 'uptime', 'df -h /data', 'systemctl restart slurmd', 'free -h', 'zpool status']
	for number in range(invocations):
		host = 'node{:05d}'.format(number * 7919 % hosts)
		lines.append('{}\t/x/multiSSH3.py\t-su -u=root\t{}\t"{} {}"'.format(1790000000 + number, host, commands[number % len(commands)], number % 997))
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in lines))
	(home / '.ssh').mkdir()
	(home / '.ssh' / 'config').write_text(''.join('Host node{:05d}\n'.format(number) for number in range(hosts)))


def main():
	tmp = Path(tempfile.mkdtemp())
	try:
		home = tmp / 'home'
		home.mkdir()
		runtime = tmp / 'runtime'
		runtime.mkdir(mode=0o700)
		synthetic(home)
		env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime))
		engine = [sys.executable, '-I', str(REPO / 'mssh_complete.py')]
		started = time.monotonic()
		path = subprocess.run(engine + ['rebuild'], env=env, stdout=subprocess.PIPE, check=True).stdout.decode().strip()
		print('rebuild: {:.0f} ms, index {:.1f} MB'.format((time.monotonic() - started) * 1000, os.path.getsize(path) / 1e6))
		for line in ('mssh ', 'mssh node0', 'mssh node00042 "', 'mssh -u ', 'mssh ', "mssh -u root node1 'nvid"):
			word = '' if line.endswith((' ', '"')) else line.split(' ')[-1].lstrip("'")
			request = 'MSSHC1\0bash\x005.2\0nosort=1\0{}\0\0{}\0'.format(line, word).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('query {!r:32} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)


if __name__ == '__main__':
	main()
