'''Drive real shells for the autocomplete tests: a pseudo-terminal session, or a direct call.'''
import fcntl
import json
import os
import pty
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

REPO = Path(__file__).resolve().parents[1]
ENGINE = [sys.executable, '-I', str(REPO / 'mssh_complete.py')]
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

def require_shell(name):
	'''The path of shell name; skip the test if it is missing, unless MSSH_REQUIRE_SHELLS lists it.'''
	path = shutil.which(name)
	if path is None:
		required = [shell for shell in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(',') if shell]
		if name in required:
			pytest.fail('{} is required here (MSSH_REQUIRE_SHELLS) but not installed'.format(name))
		pytest.skip('{} is not installed'.format(name))
	return path

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

def debug_log_size(env):
	'''How much the engine's debug log holds now (0 when there is none).'''
	path = os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3', 'complete.log')
	return os.path.getsize(path) if os.path.exists(path) else 0

def make_home(tmp_path, history_lines=()):
	'''
	A private HOME and XDG_RUNTIME_DIR holding the given mssh history, its fixed times aged. Returns (env, home).

	The prober's lock is taken, so no prober runs (no DNS, no ping): tests that want answers about
	hosts write host-state.tsv themselves. An mssh config in HOME keeps this machine's /etc/hosts and
	/etc/profile.d/hosts.sh out of the host names the engine offers.
	'''
	import multiSSH3
	home = tmp_path / 'home'
	runtime = tmp_path / 'runtime'
	home.mkdir()
	runtime.mkdir(mode=0o700)
	(runtime / 'multiSSH3').mkdir(mode=0o700)
	(runtime / 'multiSSH3' / 'probe.lock').write_text('')
	(home / '.mssh_history').write_text(''.join(_aged_line(line) + '\n' for line in history_lines))
	(home / '.multiSSH3.config.json').write_text(json.dumps({'DEFAULT_HOST_FILE': str(home / 'hosts'),
		'DEFAULT_ENV_FILES': [path for path in multiSSH3.DEFAULT_ENV_FILES if path.startswith('~')]}))
	env = {
		'HOME': str(home), 'XDG_RUNTIME_DIR': str(runtime), 'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
		'TERM': 'xterm-256color', 'LANG': os.environ.get('LANG', 'C.UTF-8'), 'MSSH_COMPLETE_TIMEOUT': '5',
		'MSSH_COMPLETE_START_TIMEOUT': '10',
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

class Session(object):
	'''An interactive shell on a pseudo-terminal. print_key makes the shell print its command line.'''
	def __init__(self, argv, env, cwd=None, print_key='\x18\x10'):
		self.print_key = print_key
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

	def read_until(self, marker, timeout=10.0):
		'''Read until marker (bytes) shows up after what was read so far; return the new output.'''
		start = len(self.output)
		end = time.monotonic() + timeout
		while marker not in self.output[start:] and time.monotonic() < end:
			ready, _, _ = select.select([self.fd], [], [], 0.05)
			if ready:
				try:
					chunk = os.read(self.fd, 65536)
				except OSError:
					break
				if not chunk:
					break
				self.output += chunk
		return self.output[start:].decode('utf-8', 'replace')

	def resize(self, rows, columns):
		'''Change the terminal's size: the kernel sends SIGWINCH to what runs in it. Read what was drawn first.'''
		self.read_until(b'@@never@@', 0.3)
		self.resizes.append((len(self.output), rows, columns))
		fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))

	def send(self, data):
		os.write(self.fd, data.encode('utf-8') if isinstance(data, str) else data)

	def line_after(self, typed, keys='\t', timeout=10.0):
		'''Type typed, press keys, then return the command line as the test binding (print_key) prints it.'''
		self.send(typed + keys)
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
			os.waitpid(self.pid, 0)
		except OSError:
			pass
		os.close(self.fd)

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
		warm = Session(argv, env, cwd=home, print_key='\x14')
		warm.read_until(b'@@READY@@', timeout=60)
		warm.close()
	session = Session(argv, env, cwd=home, print_key='\x14')
	session.read_until(b'@@READY@@', timeout=60)
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
	session.read_until(b'@@READY@@', timeout=20)
	return session
