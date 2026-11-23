'''Drive real shells for the autocomplete tests: a pseudo-terminal session, or a direct call.'''
import fcntl
import functools
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

import mssh_complete

REPO = Path(__file__).resolve().parents[1]
# what the glue runs when mssh-complete is not on PATH: this python, the file from its bytecode cache
ENGINE = mssh_complete.module_command(str(REPO / 'mssh_complete.py'))
# 2026-10-13 00:00 UTC, when the histories these tests write were given their fixed times (1790000000 on)
WRITTEN = 1791849600

def aged(stamp):
	'''
	A fixed time from before WRITTEN, moved to be as old now as it was then. The engine weighs history
	by its age on the real clock (a use halves its weight every week), so fixed times would rank
	differently as the days pass: a suggestion the tests do not expect appeared 24 days on.
	'''
	stamp = int(stamp)
	return stamp + max(0, int(time.time()) - WRITTEN) if stamp < WRITTEN else stamp

def _aged_line(line):
	'''An mssh history line with its time aged.'''
	stamp, tab, rest = line.partition('\t')
	return '{}\t{}'.format(aged(stamp), rest) if tab and stamp.isdigit() else line

@functools.lru_cache(maxsize=None)
def _bash_major(path):
	'''The major version of the bash at path, as that bash says it (0 when it does not).'''
	output = subprocess.run([path, '-c', 'echo ${BASH_VERSINFO[0]}'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30).stdout.strip()
	return int(output) if output.isdigit() else 0

def require_shell(name, old_bash=False):
	'''
	The path of shell name; skip the test if it is missing, unless MSSH_REQUIRE_SHELLS lists it. A bash older than 4
	(macOS's /bin/bash is 3.2) counts as missing: the glue registers nothing there, so there is no completion to drive
	(old_bash=True takes it, for the test that checks exactly that: MSSH_REQUIRE_SHELLS=bash3 asks for such a bash).
	'''
	required = [shell for shell in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(',') if shell]
	path = shutil.which(name)
	if path is None:
		if name in required:
			pytest.fail('{} is required here (MSSH_REQUIRE_SHELLS) but not installed'.format(name))
		pytest.skip('{} is not installed'.format(name))
	if name == 'bash' and not old_bash and _bash_major(path) < 4:
		if 'bash' in required and 'bash3' not in required:
			pytest.fail('bash 4 or newer is required here (MSSH_REQUIRE_SHELLS) but {} is bash {}'.format(path, _bash_major(path)))
		pytest.skip('{} is bash {}: the glue registers nothing before bash 4'.format(path, _bash_major(path)))
	return path

@functools.lru_cache(maxsize=None)
def _gnu_userland():
	'''Whether this machine's ls is GNU's (the others the rows name, cp, ps, tar, grep, su, come with it on the systems the tests run on).'''
	try:
		return b'GNU' in subprocess.run(['ls', '--version'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30).stdout
	except OSError:
		return False

# For a row written where zsh completes the long options of ls, cp, ps, tar and grep, and su's -c, as the GNU tools have them: with the BSD
# ones (macOS) Apple's zsh offers nothing for them, with no mssh at all (typed ls --color=, then TAB, the line stays)
GNU_TOOLS = pytest.mark.skipif(not _gnu_userland(), reason="this machine's ls, cp, ps, tar, grep and su are not GNU's: zsh completes their long options by the GNU variant only")
# For a row naming what a Linux system has: user bin (home /bin, holding bash, base64 and basename), root's home /root, /etc/host.conf,
# /etc/hostname and /etc/os-release (macOS: no user bin, root is /var/root, /etc has hosts and no os-release)
LINUX_FILES = pytest.mark.skipif(not sys.platform.startswith('linux'), reason="the row names the users and files of a Linux system")

def zsh_version():
	'''zsh's version as (major, minor).'''
	output = subprocess.run([require_shell('zsh'), '-fc', 'print -r -- $ZSH_VERSION'], stdout=subprocess.PIPE, timeout=30).stdout
	return tuple(int(part) for part in re.findall(r'\d+', output.decode('ascii', 'replace'))[:2])

def require_zsh_5_3():
	'''Skip the test before zsh 5.3: the glue's own grey text and warnings are not set up there.'''
	if zsh_version() < (5, 3):
		pytest.skip("mssh's own grey text and warnings need zsh 5.3 (add-zle-hook-widget)")

def bash_locale(env, multibyte=False):
	"""
	How bash takes the locale the variables of env name, measured as bash's glue measures it: (utf8,
	turkic), whether it reads UTF-8 (a two-byte UTF-8 character as one, two bytes that are none as two)
	and lowers I to another letter than i; with multibyte, also whether it reads two-byte characters
	(the GB18030, EUC and Big5 locales count both pairs as one).
	"""
	script = ("u=$'\\xc3\\xa9'; g=$'\\xa1\\xa1'; i=I; t=1; [[ ${i,,} == i ]] && t=0; "
		"echo \"$(( ${#u} == 1 && ${#g} == 2 )) $t $(( ${#g} == 1 ))\"")
	output = subprocess.run([require_shell('bash'), '-c', script], env=env, stdout=subprocess.PIPE,
		stderr=subprocess.DEVNULL, timeout=30).stdout.split()
	measured = output[0] == b'1', output[1] == b'1'
	return measured + (output[2] == b'1',) if multibyte else measured

# make_home turns the engine's debug log on (a failing test's report carries it); the tests this marks run
# with it off too, as mssh ships, so the path that writes no log runs in the pty suites
WITH_AND_WITHOUT_DEBUG_LOG = pytest.mark.parametrize('debug', ['1', '0'], ids=['debug-log', 'no-debug-log'])

def with_debug_log(env, debug):
	'''env with the debug log on (debug '1') or as mssh ships, MSSH_COMPLETE_DEBUG not set at all (debug '0').'''
	env = dict(env)
	if debug == '1':
		env['MSSH_COMPLETE_DEBUG'] = '1'
	else:
		env.pop('MSSH_COMPLETE_DEBUG', None)
	return env

def debug_log_size(env):
	'''How much the engine's debug log holds now (0 when there is none).'''
	path = os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3', 'complete.log')
	return os.path.getsize(path) if os.path.exists(path) else 0

# descriptors holding the probers' locks of the latest tests (tests run one at a time)
_HELD = []

def hold_lock(path):
	'''Hold the lock at path as a running prober or rebuild holds it; returns the descriptor.'''
	fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
	fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	return fd

def make_home(tmp_path, history_lines=()):
	'''
	A private HOME and XDG_RUNTIME_DIR holding the given mssh history, its fixed times aged. Returns (env, home).

	The prober's lock is held while the test runs, so no prober runs (no DNS, no ping): tests that want
	answers about hosts write host-state.tsv themselves. An mssh config in HOME keeps this machine's
	/etc/hosts and /etc/profile.d/hosts.sh out of the host names the engine offers.
	'''
	import multiSSH3
	home = tmp_path / 'home'
	runtime = tmp_path / 'runtime'
	home.mkdir()
	runtime.mkdir(mode=0o700)
	(runtime / 'multiSSH3').mkdir(mode=0o700)
	_HELD.append(hold_lock(str(runtime / 'multiSSH3' / 'probe.lock')))
	while len(_HELD) > 8:
		os.close(_HELD.pop(0))
	(home / '.mssh_history').write_text(''.join(_aged_line(line) + '\n' for line in history_lines))
	(home / '.multiSSH3.config.json').write_text(json.dumps({'DEFAULT_HOST_FILE': str(home / 'hosts'),
		'DEFAULT_ENV_FILES': [path for path in multiSSH3.DEFAULT_ENV_FILES if path.startswith('~')]}))
	env = {
		'HOME': str(home), 'XDG_RUNTIME_DIR': str(runtime), 'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
		'TERM': 'xterm-256color', 'LANG': os.environ.get('LANG', 'C.UTF-8'), 'MSSH_COMPLETE_TIMEOUT': '30',
		'MSSH_COMPLETE_START_TIMEOUT': '10',
		# ble.sh reads this one, not MSSH_COMPLETE_TIMEOUT, for its grey text and warnings (milliseconds): at the operator's 300 the
		# tests lost them on a loaded machine. A test that means to run into the limit sets its own.
		'MSSH_COMPLETE_GHOST_TIMEOUT': '30000',
		# the debug log (runtime/multiSSH3/complete.log): a failing test shows it (conftest.py)
		'MSSH_COMPLETE_DEBUG': '1',
	}
	return env, home

def build_index(env):
	'''Build the index the engine will use for env, so a test does not wait for the first build.'''
	subprocess.run(ENGINE + ['rebuild'], env=env, stdout=subprocess.DEVNULL, check=True, timeout=60)

def without_command(env, name, directory):
	'''
	env with a PATH that finds every command env's PATH finds except name (macOS has no coreutils
	timeout, for one): a new directory of links to them.
	'''
	directory.mkdir()
	for folder in env['PATH'].split(os.pathsep):
		if not os.path.isdir(folder):
			continue
		for entry in os.listdir(folder):
			path = os.path.join(folder, entry)
			link = directory / entry
			if entry == name or os.path.lexists(str(link)) or not (os.path.isfile(path) and os.access(path, os.X_OK)):
				continue
			os.symlink(path, str(link))
	return dict(env, PATH=str(directory))

# (read and write, nothing else: busybox's cat, the one of the matrix's bash images, copies with sendfile, which holds the pipe's lock
# while it waits for the terminal, and the test's read of the pipe waited for ever, uninterruptibly)
_READ_TERMINAL = '''import os
while True:
	try:
		data = os.read(0, 65536)
	except OSError:
		break
	if not data:
		break
	os.write(1, data)
'''

def read_terminal(master):
	'''
	A process reading the master of a pseudo-terminal all the time, as the terminal emulator showing it does; its stdout is what it read.
	macOS keeps what a program writes to its terminal in the pty until the master reads it, and holds 1024 bytes of it: a program
	that writes more waits for the test to read (a picker drawing its menu, between two keys), and one that ends waits for it
	in tcsetattr(TCSADRAIN), for ever (Linux took 19600 bytes, and drains at once). Not a thread: tcsetattr holds the GIL while it waits.
	'''
	return subprocess.Popen([sys.executable, '-I', '-S', '-c', _READ_TERMINAL], stdin=master, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

class Session(object):
	'''An interactive shell on a pseudo-terminal. print_key makes the shell print its command line.'''
	def __init__(self, argv, env, cwd=None, print_key='\x18\x10', settle=False):
		self.print_key = print_key
		# line_after waits for the shell to go idle after the keys (wait_idle) instead of a fixed time
		self.settle = settle
		self.pid, self.fd = pty.fork()
		if self.pid == 0:
			# a real terminal has a size (ble.sh sizes its panels from it)
			fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
			if cwd:
				os.chdir(str(cwd))
			os.execvpe(argv[0], argv, env)
		self.output = b''
		# (where in output, rows, columns) for each resize
		self.resizes = []
		self._screen = read_terminal(self.fd)

	def _read(self, wait):
		'''Add what the shell wrote within wait seconds to output; False once it ended.'''
		screen = self._screen.stdout.fileno()
		ready, _, _ = select.select([screen], [], [], wait)
		if not ready:
			return True
		try:
			chunk = os.read(screen, 65536)
		except OSError:
			return False
		self.output += chunk
		return bool(chunk)

	def read_until(self, marker, timeout=40.0):
		'''Read until marker (bytes) shows up after what was read so far, for timeout seconds at most; return the new output.'''
		start = len(self.output)
		end = time.monotonic() + timeout
		while marker not in self.output[start:] and time.monotonic() < end and self._read(0.05):
			pass
		return self.output[start:].decode('utf-8', 'replace')

	def read_for(self, seconds):
		'''Read for seconds, whatever comes; return the new output.'''
		start = len(self.output)
		end = time.monotonic() + seconds
		while time.monotonic() < end and self._read(0.05):
			pass
		return self.output[start:].decode('utf-8', 'replace')

	def resize(self, rows, columns):
		'''Change the terminal's size: the kernel sends SIGWINCH to what runs in it. Read what was drawn first.'''
		self.read_for(0.3)
		self.resizes.append((len(self.output), rows, columns))
		fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))

	def _busy(self):
		'''
		What the shell is doing: (its state, the CPU time it used, whether it has children), from /proc, or from ps where
		there is none (macOS). None where neither can say.
		'''
		try:
			with open('/proc/{}/stat'.format(self.pid)) as f:
				fields = f.read().rsplit(')', 1)[1].split()
			with open('/proc/{}/task/{}/children'.format(self.pid, self.pid)) as f:
				children = bool(f.read().split())
			return fields[0], int(fields[11]) + int(fields[12]), children
		except (OSError, IndexError):
			pass
		try:
			rows = subprocess.run(['ps', '-A', '-o', 'pid=,ppid=,state=,cputime='], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
				timeout=10).stdout.decode('ascii', 'replace').splitlines()
		except (OSError, subprocess.SubprocessError):
			return None
		rows = [row.split() for row in rows]
		mine = [row for row in rows if len(row) == 4 and row[0] == str(self.pid)]
		if not mine:
			return None
		# (ps marks a process asleep for over 20 s I: still asleep)
		return 'S' if mine[0][2][0] == 'I' else mine[0][2][0], mine[0][3], any(len(row) == 4 and row[1] == str(self.pid) for row in rows)

	def wait_idle(self, timeout=10.0, window=0.2):
		'''
		Wait until the shell has done with what was typed: asleep (not running, not waiting for the CPU, which
		a loaded host makes it do for long), with no child (an engine still answering) and no CPU used for
		window seconds. Returns whether it did; where neither /proc nor ps says, after a fixed 0.3 s. ble.sh gives up a completion
		when a key comes while it runs, so a key sent after a time that was long enough on an idle host
		found the line as typed on a loaded one.
		'''
		if self._busy() is None:
			time.sleep(0.3)
			return False
		end = time.monotonic() + timeout
		since, seen = None, None
		while time.monotonic() < end:
			# what the shell writes meanwhile is read, so that it never waits on a full terminal
			self.read_for(0.05)
			now = self._busy()
			if now is None or now[0] != 'S' or now[2] or now != seen:
				since, seen = time.monotonic(), now
			elif time.monotonic() - since >= window:
				return True
		return False

	def send(self, data):
		os.write(self.fd, data.encode('utf-8') if isinstance(data, str) else data)

	def line_after(self, typed, keys='\t', timeout=160.0, settle=None):
		'''
		Type typed, press keys, then return the command line as the test binding (print_key) prints it. The
		binding waits until the shell is idle (wait_idle) when the session settles (settle overrides), or
		0.3 s.
		'''
		self.send(typed + keys)
		if self.settle if settle is None else settle:
			self.wait_idle(timeout)
		else:
			time.sleep(0.3)
		self.send(self.print_key)
		text = self.read_until(b']@@', timeout)
		start = text.rfind('@@LINE[')
		end = text.find(']@@', start)
		self.send('\x15')   # clear the line for the next case
		return text[start + 7:end] if start >= 0 and end > start else None

	def close(self):
		try:
			os.kill(self.pid, signal.SIGKILL)
		except OSError:
			pass
		# the masters before the wait: on macOS a killed shell stays in exit (state E) while what it wrote to the pty is unread,
		# and only closing every master lets it go: waitpid(pid, 0) first waited for ever
		self._screen.kill()
		self._screen.wait()
		self._screen.stdout.close()
		os.close(self.fd)
		try:
			os.waitpid(self.pid, 0)
		except OSError:
			pass

BASH_TEST_RC = r'''
PS1='@@READY@@ '
bind -x '"\C-x\C-p": printf "@@LINE[%s]@@\n" "$READLINE_LINE"'
{bash_completion}
{pre}
# a command with its own completion, for delegation tests
_fakecmd() {{ COMPREPLY=($(compgen -W "alpha beta" -- "$2")); }}
complete -F _fakecmd fakecmd
# a command whose completion turns on filename quoting and offers nothing itself
_fakefile() {{ compopt -o filenames; COMPREPLY=(); }}
complete -F _fakefile fakefile
[ -r {glue} ] && . {glue} 2>/dev/null
{extra}
'''

ZSH_TEST_RC = r'''
PS1='@@READY@@ '
{compinit}
{pre}
_mssh_test_print() {{ print -r -- "@@LINE[$BUFFER]@@" }}
zle -N _mssh_test_print
bindkey '^X^P' _mssh_test_print
# a command with its own completion, for delegation tests
_fakecmd() {{ compadd alpha beta }}
(( $+functions[compdef] )) && compdef _fakecmd fakecmd
[[ -r {glue} ]] && source {glue} 2>/dev/null
{extra}
'''
ZSH_COMPINIT = 'autoload -Uz compinit && compinit -u -D'

def require_blesh():
	'''The ble.sh script named by MSSH_TEST_BLESH; skip without it, unless MSSH_REQUIRE_SHELLS lists blesh.'''
	path = os.environ.get('MSSH_TEST_BLESH', '')
	if not path or not os.path.isfile(path):
		if 'blesh' in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(','):
			pytest.fail('ble.sh is required here (MSSH_REQUIRE_SHELLS) but MSSH_TEST_BLESH does not name it')
		pytest.skip('ble.sh is not installed (set MSSH_TEST_BLESH to its ble.sh)')
	return path

# ble.sh waits for a second key after Ctrl-X (a prefix there): the print binding is Ctrl-T instead
BLESH_TEST_RC = r'''
[[ $- == *i* ]] && source {blesh} --noattach
PS1='@@READY@@ '
bind -x '"\C-t": printf "@@LINE[%s]@@\n" "$READLINE_LINE"'
_fakecmd() {{ COMPREPLY=($(compgen -W "alpha beta" -- "$2")); }}
complete -F _fakecmd fakecmd
{pre}
{glue_line}
{extra}
[[ ${{BLE_VERSION-}} ]] && ble-attach
'''

def blesh_session(home, env, glue=None, pre='', extra=''):
	'''
	An interactive bash running ble.sh, with the glue unless glue is None (ble.sh caches warmed first);
	pre runs before the glue loads, extra after.
	'''
	blesh = require_blesh()
	require_shell('bash')
	rc = home / 'blesh.bashrc'
	glue_line = '[ -r {0} ] && . {0} 2>/dev/null'.format(glue) if glue else ''
	rc.write_text(BLESH_TEST_RC.format(blesh=blesh, glue_line=glue_line, pre=pre, extra=extra))
	env = dict(env, USER=env.get('USER') or 'mssh-test')
	argv = ['bash', '--noprofile', '--rcfile', str(rc), '-i']
	if not (home / '.cache' / 'blesh').exists():
		# the first start builds ble.sh's caches and says so: keep that out of the session
		warm = Session(argv, env, cwd=home, print_key='\x14', settle=True)
		warm.read_until(b'@@READY@@', timeout=240)
		warm.close()
	session = Session(argv, env, cwd=home, print_key='\x14', settle=True)
	session.read_until(b'@@READY@@', timeout=240)
	return session

def bash_session(home, env, glue, bash_completion=True, extra='', pre=''):
	'''An interactive bash with the glue; pre runs before the glue loads, extra after.'''
	rc = home / 'test.bashrc'
	loader = '. /usr/share/bash-completion/bash_completion 2>/dev/null' if bash_completion else ''
	rc.write_text(BASH_TEST_RC.format(bash_completion=loader, glue=glue, extra=extra, pre=pre))
	session = Session([require_shell('bash'), '--noprofile', '--rcfile', str(rc), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@')
	return session

def zsh_session(home, env, glue, pre='', extra='', compinit=ZSH_COMPINIT):
	'''An interactive zsh with the glue; compinit (zsh's completion system) and pre run before the glue loads, extra after.'''
	(home / '.zshrc').write_text(ZSH_TEST_RC.format(glue=glue, pre=pre, extra=extra, compinit=compinit))
	session = Session([require_shell('zsh'), '-i'], dict(env, ZDOTDIR=str(home)), cwd=home)
	session.read_until(b'@@READY@@')
	return session

def fish_complete(env, glue, line, cwd=None):
	'''Completions fish offers for line (complete -C) in cwd, as (text, description) pairs. fish must print nothing else.'''
	fish = require_shell('fish')
	# fakecmd: a command with its own completion, for delegation tests
	script = 'complete -c fakecmd -f -a "alpha beta"; source {}; complete -C{}'.format(glue, _fish_quote(line))
	output = subprocess.run([fish, '--no-config', '-c', script], env=env, cwd=None if cwd is None else str(cwd),
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stderr == b'', 'fish printed: ' + output.stderr.decode('utf-8', 'replace')
	pairs = []
	for row in output.stdout.decode('utf-8', 'replace').splitlines():
		text, _, description = row.partition('\t')
		pairs.append((text, description))
	return pairs

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"

FISH_TEST_CONFIG = r'''
set -g fish_greeting
function fish_prompt; printf '@@READY@@ '; end
bind \cx\cp 'printf "@@LINE[%s]@@\\n" (commandline)'
{pre}
'''

def fish_session(home, env, keys_glue, pre=''):
	'''An interactive fish with the Ctrl-R glue in conf.d; pre runs in config.fish (after conf.d).'''
	config = home / '.config' / 'fish'
	(config / 'conf.d').mkdir(parents=True, exist_ok=True)
	(config / 'conf.d' / 'mssh-complete.fish').write_text(keys_glue)
	(config / 'config.fish').write_text(FISH_TEST_CONFIG.format(pre=pre))
	session = Session([require_shell('fish'), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@', timeout=80)
	return session
