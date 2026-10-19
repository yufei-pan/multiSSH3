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


def host_states(directory, hosts=10000, rows=40000):
	'''
	host-state.tsv as the prober leaves it at most: rows hosts that answered ping over the last day
	(the hosts of the cluster and more), cut down as the prober writes it. Returns how many rows it holds.
	'''
	sys.path.insert(0, str(REPO))
	import mssh_complete
	now = time.time()
	states = {}
	for number in range(rows):
		at = now - number * mssh_complete.ANSWER_KEEP / rows
		name = 'node{:05d}'.format(number) if number < hosts else 'other{:05d}'.format(number)
		states[name] = mssh_complete.HostState('valid', at, 'answer', at, at)
	states = mssh_complete.prune_host_states(states, now, mssh_complete.ANSWER_KEEP)
	mssh_complete.write_host_states(str(directory), states)
	return len(states)


def warnings(engine, env, label):
	'''Warning queries alone (the prober's lock is held, so no prober competes for the CPU).'''
	for line in ('mssh node00042 uptime ', 'mssh node[00001-00100] uptime ', 'mssh -u root node00042,nodeX uptime '):
		request = 'MSSHC1\0bash\x005.2\0diag=1 nul=0\0{}\0\0\0'.format(line).encode()
		timings = []
		for _ in range(15):
			started = time.monotonic()
			subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
			timings.append((time.monotonic() - started) * 1000)
		timings.sort()
		print('warnings{} {!r:34} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(label, line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))


def on_terminal(command, data, env):
	'''
	Start command with data on stdin and a pseudo-terminal as its controlling terminal.
	Returns (process, master fd, slave fd); the slave stays open here so the master never reads EIO.
	'''
	import fcntl
	import pty
	import termios
	master, slave = pty.openpty()

	def attach():
		os.setsid()
		fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, preexec_fn=attach)
	process.stdin.write(data)
	process.stdin.close()
	return process, master, slave


def wait_output(master, timeout=10.0):
	'''Read what the program draws next; the time it took in ms.'''
	import select
	started = time.monotonic()
	ready, _, _ = select.select([master], [], [], timeout)
	if ready:
		os.read(master, 65536)
		# the rest of the same frame
		while select.select([master], [], [], 0.005)[0]:
			os.read(master, 65536)
	return (time.monotonic() - started) * 1000


def interactive(engine, env):
	'''Editor start and per-key time, picker open time.'''
	env = dict(env, MSSH_COMPLETE_PROMPT='$ ', TERM='xterm-256color')
	starts, keys, opens = [], [], []
	for _ in range(5):
		started = time.monotonic()
		process, master, slave = on_terminal(engine + ['edit', 'mssh '], b'', env)
		wait_output(master)
		starts.append((time.monotonic() - started) * 1000)
		for key in 'node00042':
			os.write(master, key.encode())
			keys.append(wait_output(master))
		os.write(master, b'\x03')
		process.stdout.read()
		process.wait(timeout=10)
		os.close(master)
		os.close(slave)
		request = 'MSSHC1\0bash\x005.2\0pick=1\0mssh node0\0\0\0'.encode()
		started = time.monotonic()
		process, master, slave = on_terminal(engine + ['pick'], request, env)
		wait_output(master)
		opens.append((time.monotonic() - started) * 1000)
		os.write(master, b'\x1b')
		process.stdout.read()
		process.wait(timeout=10)
		os.close(master)
		os.close(slave)
	keys.sort()
	print('editor start: p50 {:6.1f} ms'.format(statistics.median(starts)))
	print('editor key:   p50 {:6.1f} ms  max {:6.1f} ms'.format(statistics.median(keys), keys[-1]))
	print('picker open:  p50 {:6.1f} ms'.format(statistics.median(opens)))


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
		queries = [(line, '') for line in ('mssh ', 'mssh node0', 'mssh node00042 "', 'mssh -u ', 'mssh ', "mssh -u root node1 'nvid")]
		# bash with completion-ignore-case on: every lookup in any case
		queries += [(line, ' icase=1') for line in ('mssh ', 'mssh NODE0', "mssh -u root node1 'NVID")]
		for line, flags in queries:
			word = '' if line.endswith((' ', '"')) else line.split(' ')[-1].lstrip("'")
			request = 'MSSHC1\0bash\x005.2\0nosort=1{}\0{}\0\0{}\0'.format(flags, line, word).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			label = 'query' + (' icase' if flags else '')
			print('{} {!r:32} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(label, line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		for line in ('mssh node0004', 'mssh -u r', 'mssh node00042 "nvid'):
			request = 'MSSHC1\0bash\x005.2\0ghost=1 nul=0\0{}\0\0\0'.format(line).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('suggest {!r:30} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		(runtime / 'multiSSH3' / 'probe.lock').write_text('')
		warnings(engine, env, '')
		rows = host_states(runtime / 'multiSSH3')
		warnings(engine, env, ' ({} host states)'.format(rows))
		os.unlink(str(runtime / 'multiSSH3' / 'host-state.tsv'))
		interactive(engine, env)
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)


if __name__ == '__main__':
	main()
