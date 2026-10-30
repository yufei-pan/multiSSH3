#!/usr/bin/env python3
# /// script
# requires-python = ">=3.6"
# dependencies = []
# ///
import argparse
import codecs
import copy
import errno
import functools
import getpass
import glob
import io
import ipaddress
import itertools
import json
import math
import operator
import os
import queue
import random
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import string
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import typing
import unicodedata
from uuid import uuid4
from collections import Counter, defaultdict, deque, ChainMap, namedtuple
from itertools import count, product
from pprint import pformat


version = '6.39'
VERSION = version
__version__ = version
COMMIT_DATE = '2026-10-29'

# no current-directory entry: a cloned repo or unpacked archive could set a setting or a program path
# (e.g. _sshPath), use --config_file to load one
CONFIG_FILE_CHAIN = ['~/multiSSH3.config.json',
					 '~/.multiSSH3.config.json',
					 '~/.config/multiSSH3/multiSSH3.config.json',
					 '/etc/multiSSH3.d/multiSSH3.config.json',
					 '/etc/multiSSH3.config.json'] # The first one has the highest priority

ERRORS = []

#%% ------------ User Defined Global Variables ----------------
# the names defined before this section, to tell the settings below apart (see _BUILTIN_SETTINGS)
_names_before_settings = set(globals())
AUTHOR = 'Yufei Pan'
AUTHOR_EMAIL = 'pan@zopyr.us'
DEFAULT_HOSTS = 'all'
DEFAULT_USERNAME = None
DEFAULT_PASSWORD = ''
DEFAULT_IDENTITY_FILE = None
DEFAULT_SSH_KEY_SEARCH_PATH = '~/.ssh/'
DEFAULT_USE_KEY = False
DEFAULT_EXTRA_ARGS = None
DEFAULT_ONE_ON_ONE = False
DEFAULT_SCP = False
DEFAULT_FILE_SYNC = False
DEFAULT_TIMEOUT = 50
DEFAULT_CLI_TIMEOUT = 0
# seconds after which ssh gives up on a host that does not answer (ConnectTimeout) or stops answering
# (ServerAliveInterval x ServerAliveCountMax), after -ea's options so an -o there wins; 0 leaves one to ssh
DEFAULT_SSH_CONNECT_TIMEOUT = 30
DEFAULT_SSH_SERVER_ALIVE_INTERVAL = 15
DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX = 4
DEFAULT_UNAVAILABLE_HOST_EXPIRY = 600
DEFAULT_REPEAT = 1
DEFAULT_INTERVAL = 0
DEFAULT_IPMI = False
DEFAULT_IPMI_INTERFACE_IP_PREFIX = ''
DEFAULT_IPMI_USERNAME = 'admin'
DEFAULT_IPMI_PASSWORD = 'admin'
DEFAULT_IPMI_ARGS=''
DEFAULT_IPMI_METHOD = 'ipmitool'
DEFAULT_IPMI_RETRY_LOCKOUT_TIME = -1
def get_default_ipmi_definition():
	return {'interface_ip_prefix': DEFAULT_IPMI_INTERFACE_IP_PREFIX,
	'username': DEFAULT_IPMI_USERNAME,
	'password': DEFAULT_IPMI_PASSWORD,
	'args': DEFAULT_IPMI_ARGS,
	'ipmi_method': DEFAULT_IPMI_METHOD,
	'hostname_keyword': '',
	'retry_lockout_time': DEFAULT_IPMI_RETRY_LOCKOUT_TIME,
}
# the built-in values, before config files change them: see _ipmi_definitions_for_host
_BUILTIN_IPMI_DEFINITION = get_default_ipmi_definition()
DEFAULT_IPMI_DEFINITIONS = [get_default_ipmi_definition()]
DEFAULT_INTERFACE_IP_PREFIX = None
DEFAULT_NO_WATCH = False
DEFAULT_WINDOW_WIDTH = 40
DEFAULT_WINDOW_HEIGHT = 1
DEFAULT_SINGLE_WINDOW = False
DEFAULT_ERROR_ONLY = False
DEFAULT_NO_OUTPUT = False
DEFAULT_RETURN_ZERO = False
DEFAULT_NO_ENV = False
DEFAULT_ENV_FILE = ''
DEFAULT_ENV_FILES = ['/etc/profile.d/hosts.sh',
					 '~/.bashrc',
					 '~/.zshrc',
					 '~/host.env',
					 '~/hosts.env',
					 ]  # no current-directory files (could redirect host aliases), use --env_files
DEFAULT_NO_HISTORY = False
DEFAULT_HISTORY_FILE = '~/.mssh_history'
def _cpu_count():
	# os.cpu_count() returns None when the count cannot be determined
	return os.cpu_count() or 1
DEFAULT_MAX_CONNECTIONS = 4 * _cpu_count()
DEFAULT_JSON_MODE = False
DEFAULT_PRINT_SUCCESS_HOSTS = False
DEFAULT_GREPPABLE_MODE = False
DEFAULT_SKIP_UNREACHABLE = True
DEFAULT_SKIP_HOSTS = ''
_SYSTEM_HOST_FILE = '/etc/hosts'
DEFAULT_HOST_FILE = _SYSTEM_HOST_FILE
DEFAULT_ENCODING = 'utf-8'
DEFAULT_DIFF_DISPLAY_THRESHOLD = 0.9
SSH_STRICT_HOST_KEY_CHECKING = False
FORCE_TRUECOLOR = False
# ssh's own notices, left out of each host's stderr. Each regex is searched in every stderr line; these
# are anchored to the lines OpenSSH prints, so a remote program's error using the same words is kept.
# Connection resets stay: "kex_exchange_identification: read: Connection reset by peer" is how sshd's
# MaxStartups turns away connections opened at once.
ERROR_MESSAGES_TO_IGNORE = [
	r'^Pseudo-terminal will not be allocated because stdin is not a terminal',
	r'^Connection to \S+ closed( by remote host)?\.$',
	r'^Warning: Permanently added ',
	r'^mux_client_request_session: ',
	r'^ControlSocket .* already exists, disabling multiplexing$',
	r'^Killed by signal \d+\.$',
]
POSSIBLE_SSH_KEY_FILES = ['id_ed25519','id_ed25519_sk','id_ecdsa','id_ecdsa_sk','id_rsa','id_dsa']
__DEFAULT_COLOR_PALETTE = {
	'cyan': (86, 173, 188),
	'green': (114, 180, 43),
	'magenta': (140, 107, 200),
	'red': (196, 38, 94),
	'white': (227, 227, 221),
	'yellow': (179, 180, 43),
	'blue': (106, 126, 200),
	'bright_black': (102, 102, 102),
	'bright_blue': (129, 154, 255),
	'bright_cyan': (102, 217, 239),
	'bright_green': (126, 226, 46),
	'bright_magenta': (174, 129, 255),
	'bright_red': (249, 38, 114),
	'bright_white': (248, 248, 242),
	'bright_yellow': (226, 226, 46),
}
COLOR_PALETTE = __DEFAULT_COLOR_PALETTE.copy()
_DEFAULT_CALLED = True
_DEFAULT_RETURN_UNFINISHED = False
_DEFAULT_UPDATE_UNREACHABLE_HOSTS = True
_DEFAULT_NO_START = False
_etc_hosts = {}
_etc_hosts_lock = threading.Lock()
__ERROR_MESSAGES_TO_IGNORE_REGEX =None
__DEBUG_MODE = False

#%% ------------ Settings a config file can change ----------------
# the settings above whose name starts with _: any other such name there is mssh's own state
_UNDERSCORE_SETTINGS = ('__DEFAULT_COLOR_PALETTE', '_DEFAULT_CALLED', '_DEFAULT_RETURN_UNFINISHED',
	'_DEFAULT_UPDATE_UNREACHABLE_HOSTS', '_DEFAULT_NO_START', '_etc_hosts', '__ERROR_MESSAGES_TO_IGNORE_REGEX', '__DEBUG_MODE')
# the settings (what config files can change) with their built-in values, to check config values against: what
# the section above defines that is public or listed in _UNDERSCORE_SETTINGS and a JSON value (not a function)
_BUILTIN_SETTINGS = {name: copy.deepcopy(globals()[name]) for name in sorted(set(globals()) - _names_before_settings)
	if (not name.startswith('_') or name in _UNDERSCORE_SETTINGS)
	and isinstance(globals()[name], (str, int, float, bool, type(None), list, dict))}
del _names_before_settings

def _setting_type(name):
	'''(type, item type) of setting name: the item type when its built-in value is a list whose items share one.'''
	value = _BUILTIN_SETTINGS[name]
	if name == '_etc_hosts':
		# host name -> address, empty by default
		return dict, str
	item_types = {type(item) for item in value} if isinstance(value, list) else set()
	return type(value), (item_types.pop() if len(item_types) == 1 else None)

#%% ------------ Pre Helper Functions ----------------
def cache_decorator(user_function):
	def _make_hashable(item):
		if isinstance(item, typing.Mapping):
			# Sort items so that {'a':1, 'b':2} and {'b':2, 'a':1} hash the same
			return tuple(
				( _make_hashable(k), _make_hashable(v) )
				for k, v in sorted(item.items(), key=lambda item: item[0])
			)
		if isinstance(item, (list, set, tuple)):
			return tuple(_make_hashable(e) for e in item)
		# Fallback: assume item is already hashable
		return item
	def decorating_function(user_function):
		# Create the real cached function
		cached_func = functools.lru_cache(maxsize=None)(user_function)
		@functools.wraps(user_function)
		def wrapper(*args, **kwargs):
			# Convert all args/kwargs to hashable equivalents
			hashable_args = tuple(_make_hashable(a) for a in args)
			hashable_kwargs = {
				k: _make_hashable(v) for k, v in kwargs.items()
			}
			# Call the lru-cached version
			return cached_func(*hashable_args, **hashable_kwargs)
		# Expose cache statistics and clear method
		wrapper.cache_info = cached_func.cache_info
		wrapper.cache_clear = cached_func.cache_clear
		return wrapper
	return decorating_function(user_function)

def eprint(*args, **kwargs):
	kwargs.setdefault('file', sys.stderr)
	try:
		print(*args, **kwargs)
	except Exception as e:
		# stderr is gone (its reader exited, a hang-up, a full disk): there is nowhere to say it, and stdout may
		# hold the results. Later writes and the flush at exit must not fail on it again
		if isinstance(e, OSError) and kwargs['file'] is sys.stderr:
			sys.stderr = open(os.devnull, 'w')
	ERRORS.append(' '.join(map(str,args)))

def _exit_with_code(code, message=None):
	'''
	Exit the program with a specific code and print a message

	Args:
		code (int): The exit code
		message (str, optional): The message to print. Defaults to None.

	Returns:
		None
	'''
	global __returnZero
	if message:
		eprint('Exiting: '+ message)
	if __returnZero:
		code = 0
	elif isinstance(code, int) and code > 255:
		# exit status is truncated to 8 bits, 256 would read as success
		code = 255
	sys.exit(code)


class MultiSSHError(RuntimeError):
	'''Raised for fatal errors when multiSSH3 is used as a library (called=True).'''
	def __init__(self, message, code=1):
		super().__init__(message)
		self.code = code


def _abort(code, message=None, *, called=True):
	'''
	Abort execution: raise MultiSSHError for library callers, or exit the process for CLI.

	When run_command_on_hosts(..., called=True) hits a fatal condition, prefer raising
	so embedders are not killed by sys.exit. CLI (called=False / main) still exits.
	'''
	if called:
		if message:
			eprint('Error: ' + message)
		raise MultiSSHError(message or f'aborted with code {code}', code=code)
	_exit_with_code(code, message)

def signal_handler(sig, frame):
	'''
	Handle the Ctrl C signal

	Args:
		sig (int): The signal
		frame (frame): The frame

	Returns:
		None
	'''
	global _emo
	if not _commands_started:
		# still resolving hosts: nothing runs yet, so stop before anything does
		_exit_with_code(1, 'Ctrl C caught before any command started, nothing was run')
	if not _emo:
		eprint('Ctrl C caught, exiting...')
		_emo = True
	else:
		eprint('Ctrl C caught again, exiting immediately!')
		_kill_commands_for_exit()
		_exit_with_code(1, 'Exiting immediately due to Ctrl C')

def _kill_commands_for_exit():
	'''
	Kill the commands this process started (only those) and start no more: mssh exits right after.
	'''
	global _emo
	global _stopping
	_emo = True
	# hosts waiting for a connection slot start nothing now
	_stopping = True
	for attempt in range(2):
		if attempt:
			# a command that was starting when the signal came is listed a moment later
			time.sleep(0.05)
		for proc in list(__running_procs):
			try:
				proc.kill()
			except Exception:
				pass

def _stop_signal_handler(sig, frame):
	'''
	Handle SIGTERM, SIGHUP and SIGQUIT (kill, a batch scheduler or service manager stopping mssh, the
	terminal closing, Ctrl-\\) like a second Ctrl C: kill the running commands and exit with 128 + the
	signal number.

	The exit unwinds curses.wrapper on the main thread, which restores the terminal.
	'''
	_kill_commands_for_exit()
	try:
		eprint('Exiting: {} received, the running commands were killed'.format(signal.Signals(sig).name))
	except Exception:
		# the terminal is gone (SIGHUP): nowhere to say it
		pass
	# not _exit_with_code: --return_zero is for failed hosts, a stopped mssh did not succeed
	raise SystemExit(128 + sig)

def _exit_replaced_by(error):
	'''The SystemExit that error replaced while it was being raised, None if there is none.'''
	while error is not None:
		if isinstance(error, SystemExit):
			return error
		error = error.__context__
	return None

def _install_signal_handlers():
	'''
	Install the command line's signal handlers: Ctrl C stops the commands (pressed again: kills them),
	SIGTERM, SIGHUP and SIGQUIT (Ctrl-\\) kill them and exit. Commands running in sessions of their own
	do not get the terminal's Ctrl-\\, so mssh passes it on as it does a closing terminal.

	Only on the main thread, the only one Python lets set them. SIGTERM, SIGHUP and SIGQUIT only when
	not ignored: `nohup mssh ...` must keep running when its terminal closes.
	'''
	if threading.current_thread() is not threading.main_thread():
		return
	signal.signal(signal.SIGINT, signal_handler)
	for name in ('SIGTERM', 'SIGHUP', 'SIGQUIT'):
		number = getattr(signal, name, None)
		if number is not None and signal.getsignal(number) == signal.SIG_DFL:
			signal.signal(number, _stop_signal_handler)

def input_with_timeout_and_countdown(timeout, prompt='Please enter your selection'):
	"""
	Ask the user for a line, counting down `timeout` seconds.

	Returns the line stripped, or None when the time is up or nobody can answer (stdin is not a
	terminal), so the caller takes its default. Outside Windows nothing keeps reading stdin once it
	returns: the TUI that may start next gets every key typed after the prompt.
	"""
	try:
		interactive = sys.stdin.isatty()
	except Exception:
		# no stdin at all (None) or a closed one
		interactive = False
	if not interactive:
		# a pipe or file holds input for someone else (e.g. the hosts left in a `while read host` loop)
		# and nobody is there to answer: take the default without reading any of it
		eprint(f"{prompt}: stdin is not a terminal, taking the default")
		return None
	try:
		fd = sys.stdin.fileno()
	except Exception:
		fd = None
	if fd is None or os.name == 'nt':
		# select() cannot wait on a Windows console, nor on a stdin without a file descriptor
		return _input_with_timeout_by_thread(timeout, prompt)
	encoding = getattr(sys.stdin, 'encoding', None) or 'utf-8'
	eprint(f"{prompt} [{timeout}s]: ", end='', flush=True)
	typed = b''
	shown = timeout
	start_time = time.monotonic()
	try:
		while True:
			elapsed = time.monotonic() - start_time
			remaining = timeout - int(elapsed)
			if remaining <= 0:
				break
			if remaining != shown:
				shown = remaining
				eprint(f"\r{prompt} [{remaining}s]: ", end='', flush=True)
			# wait for a line (a terminal in its usual line mode only shows complete lines), at most
			# until the next whole second, when the countdown changes
			if not select.select([fd], [], [], int(elapsed) + 1 - elapsed)[0]:
				continue
			# read the descriptor itself: sys.stdin would buffer whatever comes after the line
			data = os.read(fd, 4096)
			typed += data
			if not data or b'\n' in typed or b'\r' in typed:
				# Enter, or Ctrl-D (end of input)
				eprint()  # move to the next line
				return typed.decode(encoding, errors='replace').strip()
	except (OSError, ValueError):
		# the terminal went away
		eprint()
		return None
	# time is up: drop a half-typed answer, it was meant for this prompt, not for what reads the terminal next
	try:
		import termios
		termios.tcflush(fd, termios.TCIFLUSH)
	except Exception:
		pass
	eprint()  # move to the next line
	return None

def _input_with_timeout_by_thread(timeout, prompt):
	"""
	input_with_timeout_and_countdown for a stdin select() cannot wait on (Windows, or one without a
	file descriptor). On a timeout the reader thread stays blocked in readline and takes the next line typed.
	"""
	# Queue to receive user input from the background thread
	input_queue = queue.Queue()
	def read_input():
		# Read line from stdin and put it in the queue
		user_input = sys.stdin.readline()
		input_queue.put(user_input)
	# Start a thread that will block on input()
	input_thread = threading.Thread(target=read_input, daemon=True)
	input_thread.start()
	# Print the initial prompt
	eprint(f"{prompt} [{timeout}s]: ", end='', flush=True)
	# Countdown loop
	start_time = time.monotonic()
	while True:
		# Check if the input thread has finished (i.e., user pressed Enter)
		if not input_queue.empty():
			# We got user input
			user_input = input_queue.get().strip()
			eprint()  # move to the next line
			return user_input
		elapsed = int(time.monotonic() - start_time)
		remaining = timeout - elapsed
		if remaining <= 0:
			# Time is up, no input
			eprint()  # move to the next line
			return None
		# Update prompt countdown
		eprint(f"\r{prompt} [{remaining}s]: ", end='', flush=True)
		time.sleep(1)

def read_hosts_file(path):
	'''
	Read a hosts file such as /etc/hosts: lines of an IP address followed by its names.

	It is read as the C library reads it: text after # is a comment, lines that do not start with
	an IP address are skipped, and a name listed twice keeps its first address. When a name has
	both, it gets its first IPv4 address, as names looked up in DNS do. Bytes that are not UTF-8
	are replaced, they never stop the read.

	Args:
		path (str): The hosts file

	Returns:
		dict: host name -> IP address, empty when the file cannot be read
	'''
	hosts = {}
	if not path:
		return hosts
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			for line in f:
				fields = line.split('#', 1)[0].split()
				if len(fields) < 2:
					continue
				address = fields[0]
				ipv4 = ':' not in address
				try:
					socket.inet_pton(socket.AF_INET if ipv4 else socket.AF_INET6, address)
				except (OSError, ValueError):
					continue
				for name in fields[1:]:
					known = hosts.get(name)
					if known is None or (ipv4 and ':' in known):
						hosts[name] = address
	except OSError:
		pass
	return hosts

def _load_etc_hosts():
	'''_etc_hosts, read from DEFAULT_HOST_FILE when empty (by one thread: the parallel lookups of a range all start here).'''
	if not _etc_hosts:
		with _etc_hosts_lock:
			if not _etc_hosts:
				_etc_hosts.update(read_hosts_file(DEFAULT_HOST_FILE))
	return _etc_hosts

def _host_file_warning():
	'''
	Why the hosts file the operator chose (--host_file) gives mssh no host names, or None when it does.

	The system's own /etc/hosts is not checked: a system without one is not the operator's mistake.
	'''
	path = DEFAULT_HOST_FILE
	if not path or path == _SYSTEM_HOST_FILE or _load_etc_hosts():
		return None
	if not os.path.exists(path):
		return f'Warning: --host_file {path} does not exist'
	if os.path.isdir(path) or not os.access(path, os.R_OK):
		return f'Warning: --host_file {path} cannot be read'
	return (f'Warning: --host_file {path} has no address lines, so it gives no host names. It is a hosts file like '
		f'{_SYSTEM_HOST_FILE} (an IP address, then names, per line), not a list of hosts to run on.')

def getIP(hostname: str,local=False):
	'''
	Get the IP address of the hostname

	Args:
		hostname (str): The hostname, user@ is ignored
		local (bool): Only check IP addresses and the hosts file, no DNS

	Returns:
		str: The IP address of the hostname
	'''
	# one cache entry per host, however callers write it (user@, spaces, local as keyword or not)
	if '@' in hostname:
		_, hostname = hostname.rsplit('@',1)
	return _getIP(hostname.strip(), bool(local))

@cache_decorator
def _getIP(hostname, local):
	global _etc_hosts
	global DEFAULT_HOST_FILE
	# First we check if the hostname is an IP address
	try:
		ipaddress.ip_address(hostname)
		return hostname
	except ValueError:
		pass
	# Then we check DEFAULT_HOST_FILE
	if hostname in _load_etc_hosts():
		return _etc_hosts[hostname]
	if local:
		return None
	# Then we check the DNS
	ip = _resolve_dns(hostname)
	if ip is None:
		# an ~/.ssh/config alias: use the address of its HostName
		target = _ssh_config_target(hostname)
		if target and target.lower() != hostname.lower():
			# local lookup only, a HostName that is itself an alias must not recurse
			ip = getIP(target,local=True) or _resolve_dns(target)
	return ip

# hostname -> IP address (or None) of every DNS lookup made, so lookups are done once
_dns_cache = {}

def _clear_ip_caches():
	'''getIP.cache_clear(): forget every lookup result getIP depends on, failures included.'''
	_getIP.cache_clear()
	_dns_cache.clear()
	for cached_function in (_ssh_config_values, _ssh_config_mapping, _ssh_config_target):
		# tests (or embedders) may have replaced them with plain functions
		getattr(cached_function, 'cache_clear', lambda: None)()

getIP.cache_clear = _clear_ip_caches
getIP.cache_info = _getIP.cache_info

def _resolve_dns(hostname):
	'''Look hostname up in DNS (IPv4 or IPv6, preferring IPv4), returning its IP address or None.'''
	if hostname in _dns_cache:
		return _dns_cache[hostname]
	try:
		infos = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
	except Exception:
		infos = []
	addresses = [info[4][0] for info in infos if info[0] == socket.AF_INET]
	addresses += [info[4][0] for info in infos if info[0] == socket.AF_INET6]
	_dns_cache[hostname] = addresses[0] if addresses else None
	return _dns_cache[hostname]

# a name no ssh config can mean on purpose, to tell what catch-all blocks (Host *) do
_SSH_CONFIG_PROBE_NAME = 'multissh3-unknown-host.invalid'

@cache_decorator
def _ssh_config_values(hostname):
	'''The ssh config for hostname from ssh -G (OpenSSH 6.8+, does not connect), or None.'''
	try:
		result = subprocess.run([_binPaths['ssh'], '-G', '--', hostname], stdout=subprocess.PIPE,
						  stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=10)
	except Exception:
		return None
	if result.returncode != 0:
		return None
	config = {}
	for line in result.stdout.splitlines():
		key, _, value = line.partition(' ')
		config[key.lower()] = value.strip()
	return config

@cache_decorator
def _ssh_config_mapping(hostname):
	'''
	What the ssh config does with hostname, before any DNS lookup (see _ssh_config_target).

	Returns:
		tuple: (target, templated). target is the HostName ssh would use when the config gives
			hostname another HostName or a ProxyJump / ProxyCommand, else None. templated is True
			when only a catch-all HostName template (Host * / HostName %h.example) gives it, which
			applies to typos too: such a target counts only when it resolves.
	'''
	if 'ssh' not in _binPaths or not hostname or hostname.startswith('-'):
		return None, False
	config = _ssh_config_values(hostname)
	if not config or not config.get('hostname'):
		return None, False
	target = config['hostname']
	proxies = [config.get(key, 'none').lower() for key in ('proxyjump', 'proxycommand')]
	# for a name it does not know, ssh -G prints the name back (lowercased) as the hostname
	if target.lower() == hostname.lower() and all(proxy == 'none' for proxy in proxies):
		return None, False
	# a catch-all block (Host * with HostName %h.example or a ProxyJump) applies to every name,
	# typos included: only accept names the config treats differently from a made-up one
	probe = _ssh_config_values(_SSH_CONFIG_PROBE_NAME)
	if probe:
		def as_for_this_name(value):
			return value.lower().replace(_SSH_CONFIG_PROBE_NAME, hostname.lower())
		probe_target = as_for_this_name(probe.get('hostname', ''))
		probe_proxies = [as_for_this_name(probe.get(key, 'none')) for key in ('proxyjump', 'proxycommand')]
		if probe_target == target.lower() and probe_proxies == proxies:
			# a HostName template (Host * / HostName %h.example) is only real for names whose target resolves
			if target.lower() != hostname.lower():
				return target, True
			return None, False
	return target, False

@cache_decorator
def _ssh_config_target(hostname):
	'''
	The host ssh really connects to for hostname, when the ssh config maps it.

	Returns:
		str: The HostName ssh would use, when the config gives hostname another HostName or a
			ProxyJump / ProxyCommand (hosts behind a bastion may only resolve on its far side).
			None for names the config does not single out, so typos are still caught.
	'''
	target, templated = _ssh_config_mapping(hostname)
	if templated and not (getIP(target,local=True) or _resolve_dns(target)):
		return None
	return target

def _ssh_timeout_options():
	'''
	The -o options that make ssh give up on a host that does not answer, or stops answering, so it
	cannot hold up the run: ConnectTimeout, ServerAliveInterval and ServerAliveCountMax from the
	DEFAULT_SSH_* settings, 0 leaving one to ssh. They go after -ea's options: ssh uses the first
	value it gets, so an -o in -ea wins.
	'''
	options = []
	for keyword, value in (('ConnectTimeout', DEFAULT_SSH_CONNECT_TIMEOUT),
			('ServerAliveInterval', DEFAULT_SSH_SERVER_ALIVE_INTERVAL),
			('ServerAliveCountMax', DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX)):
		try:
			# ssh takes whole seconds: rounded up
			number = max(0, int(math.ceil(float(value))))
		except (TypeError, ValueError, OverflowError):
			number = 0
		# mssh's ServerAliveCountMax only goes with mssh's ServerAliveInterval
		if number and (keyword != 'ServerAliveCountMax' or 'ServerAliveInterval=' in ' '.join(options)):
			options += ['-o', '{}={}'.format(keyword, number)]
	return options


_i_counter = count()
def _get_i():
	'''
	Get the global counter for the host objects

	Returns:
	int: The global counter for the host objects
	'''
	return next(_i_counter)

#%% ------------ Load Defaults ( Config ) File ----------------
try:
	import grp
	import pwd
except ImportError:
	grp = pwd = None

def _is_private_group(uid, gid):
	'''Whether gid is the user private group of uid: its primary group, named after it, with no other members.'''
	try:
		owner = pwd.getpwuid(uid)
		group = grp.getgrgid(gid)
	except KeyError:
		return False
	return gid == owner.pw_gid and group.gr_name == owner.pw_name and set(group.gr_mem) <= {owner.pw_name}

def _untrusted_file_reason(st):
	'''
	Check a config / env file found on the default search paths before loading it.

	Like ssh, the file must be owned by you or root and not writable by anyone else. Group
	write is allowed when the group is the owner's private group, as user private group
	systems (Debian, Ubuntu, RHEL) create files group-writable by default.

	Args:
		st (os.stat_result): fstat() of the opened file

	Returns:
		tuple: (reason, fixable_with_chmod), or None when the file can be loaded
	'''
	if not stat.S_ISREG(st.st_mode):
		# a FIFO or device could block or never end
		return 'it is not a regular file', False
	if pwd is None or not hasattr(os, 'getuid'):
		return None
	if st.st_uid not in (os.getuid(), 0):
		return 'it is owned by uid {}, not by you or root'.format(st.st_uid), False
	if st.st_mode & stat.S_IWOTH:
		return 'every user can write to it', True
	if st.st_mode & stat.S_IWGRP and not _is_private_group(st.st_uid, st.st_gid):
		try:
			group = grp.getgrgid(st.st_gid).gr_name
		except KeyError:
			group = st.st_gid
		return 'group {} can write to it'.format(group), True
	return None

def _open_trusted_file(path, explicit_flag, errors=None):
	'''
	Open path for reading if it passes _untrusted_file_reason, else warn and return None.

	The check runs on the opened file, so the file cannot be swapped between check and read.
	'''
	# O_NONBLOCK so opening a planted FIFO does not wait for a writer, it is rejected below
	f = os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)), 'r', errors=errors)
	untrusted = _untrusted_file_reason(os.fstat(f.fileno()))
	if not untrusted:
		return f
	f.close()
	reason, fixable = untrusted
	if fixable:
		fix = 'fix with: chmod g-w,o-w {}, or pass it with {}'.format(shlex.quote(path), explicit_flag)
	else:
		fix = 'pass it with {} to use it anyway'.format(explicit_flag)
	eprint('Warning: Ignoring {!r} because {}; {}'.format(path, reason, fix))
	return None

def _json_kind(value):
	'''What value is, in JSON terms, for messages about config files.'''
	if value is None:
		return 'null'
	if isinstance(value, bool):
		return 'true' if value else 'false'
	if isinstance(value, (int, float)):
		return 'a number'
	if isinstance(value, str):
		return 'a string'
	if isinstance(value, list):
		return 'a list'
	return 'an object'

def _encoding_problem(name):
	'''Why output cannot be decoded with the encoding called name (unknown, or not a text encoding), or None.'''
	try:
		# the reader decodes with backslashreplace: idna, for one, refuses that handler
		b'\xff\n'.decode(name, 'backslashreplace')
		'\xe9\n'.encode(name, 'backslashreplace')
	except (LookupError, ValueError) as e:
		# UnicodeError is a ValueError
		return 'cannot decode output with {!r}: {}'.format(name, e)
	return None

def _text_encoding(name):
	'''argparse type of -e: refuse an encoding the reader threads would die on, before any host runs.'''
	problem = _encoding_problem(name)
	if problem:
		raise argparse.ArgumentTypeError(problem)
	return name

def _regex_problem(pattern):
	'''Why pattern is not a regular expression, or None.'''
	try:
		re.compile(pattern)
	except re.error as e:
		return '{!r} is not a valid regular expression: {}'.format(pattern, e)
	return None

def _config_number(value):
	'''value as an int or a float when it is a number or a string holding one, else None.'''
	if isinstance(value, str):
		try:
			return int(value.strip())
		except ValueError:
			try:
				value = float(value.strip())
			except ValueError:
				return None
	if isinstance(value, bool):
		return None
	if isinstance(value, int):
		return value
	if isinstance(value, float) and math.isfinite(value):
		return value
	return None

def _config_value_text(value):
	'''value for a warning: strings and numbers as they are, anything else by its JSON kind.'''
	if isinstance(value, (str, int, float)) and not isinstance(value, bool):
		return repr(value)
	return _json_kind(value)

_TRUE_WORDS = ('true', 'yes', 'on', '1')
_FALSE_WORDS = ('false', 'no', 'off', '0')
# keys naming the program mssh runs, e.g. _sshPath (see check_path)
_PROGRAM_PATH_KEY = re.compile(r'_.+Path$')

def _check_config_value(name, value):
	'''
	Check the value a config file gives setting name against the type of its built-in value.

	Values whose meaning is clear are converted: "false" for a true / false setting, "50" for a
	number, 1234 for a string, a list of host names for a host string.

	Returns:
		tuple: (value, None) when it can be used, else (None, why not)
	'''
	if name not in _BUILTIN_SETTINGS:
		# a program path such as _sshPath: null or empty for the one on PATH
		if value is None or isinstance(value, str):
			return value, None
		return None, 'expected the path to the program, got {}'.format(_config_value_text(value))
	kind, item_kind = _setting_type(name)
	list_of_strings = isinstance(value, list) and all(isinstance(item, str) for item in value)
	if name in ('DEFAULT_HOSTS', 'DEFAULT_SKIP_HOSTS') and list_of_strings:
		return ','.join(value), None
	if name == 'DEFAULT_EXTRA_ARGS' and list_of_strings:
		return value, None
	if value is None and (kind is type(None) or name == 'DEFAULT_MAX_CONNECTIONS'):
		# --store_config_file writes null for the built-in max_connections
		return None, None
	if value is None and kind is str:
		# null reads as "not set": DEFAULT_HOSTS null is the built-in "all" (None crashed a bare mssh)
		return _BUILTIN_SETTINGS[name], None
	if kind is bool:
		if isinstance(value, bool):
			return value, None
		word = str(value).strip().lower() if isinstance(value, (str, int)) else None
		if word in _TRUE_WORDS or word in _FALSE_WORDS:
			return word in _TRUE_WORDS, None
		expected = 'true or false'
	elif kind in (int, float):
		number = _config_number(value)
		if number is not None and kind is float:
			return float(number), None
		if number is not None:
			# whole numbers as int, as the command line gives them; a fraction of a second still works
			return (int(number) if number == int(number) else number), None
		expected = 'a number or null' if name == 'DEFAULT_MAX_CONNECTIONS' else 'a number'
	elif kind in (str, type(None)):
		if isinstance(value, (int, float)) and not isinstance(value, bool):
			value = str(value)
		if not isinstance(value, str):
			expected = 'a string' if kind is str else 'a string or null'
		elif name == 'DEFAULT_ENCODING':
			problem = _encoding_problem(value)
			return (None, problem) if problem else (value, None)
		elif name == '__ERROR_MESSAGES_TO_IGNORE_REGEX':
			problem = _regex_problem(value)
			return (None, problem) if problem else (value, None)
		else:
			return value, None
	elif kind is list:
		if not isinstance(value, list):
			expected = {str: 'a list of strings', dict: 'a list of objects'}.get(item_kind, 'a list')
		elif item_kind and not all(isinstance(item, item_kind) for item in value):
			odd = next(item for item in value if not isinstance(item, item_kind))
			return None, 'expected {}, got a list holding {}'.format(
				{str: 'a list of strings', dict: 'a list of objects'}.get(item_kind, 'a list'), _json_kind(odd))
		elif name == 'ERROR_MESSAGES_TO_IGNORE':
			problem = _regex_problem('|'.join(value))
			return (None, problem) if problem else (value, None)
		else:
			return value, None
	elif kind is dict:
		if not isinstance(value, dict):
			expected = 'an object'
		elif item_kind and not all(isinstance(item, item_kind) for item in value.values()):
			odd = next(item for item in value.values() if not isinstance(item, item_kind))
			return None, 'expected an object of strings, got one holding {}'.format(_json_kind(odd))
		else:
			return value, None
	else:
		return None, 'not a setting a config file can change'
	return None, 'expected {}, got {}'.format(expected, _config_value_text(value))

def _check_config(config, config_file, replaced=()):
	'''
	The settings of config_file that can be used.

	A value of the wrong type is left out with a warning naming the file and the key, so the
	setting keeps its built-in (or less specific config file's) value. Keys that are not settings
	are kept as they are: --store_config_file writes them back.

	Args:
		replaced (set): Keys a more specific config file sets: a wrong value is left out quietly, it
			would not be used anyway (and the user may not be able to edit, say, a file in /etc)
	'''
	checked = {}
	for name, value in config.items():
		if name in _BUILTIN_SETTINGS or _PROGRAM_PATH_KEY.match(name):
			value, problem = _check_config_value(name, value)
			if problem:
				if name not in replaced:
					eprint('Warning: Ignoring {} in config file {!r}: {}'.format(name, config_file, problem))
				continue
		checked[name] = value
	return checked

def load_config_file(config_file, check_trust=True):
	'''
	Load the config file to global variables

	Args:
		config_file (str): The config file
		check_trust (bool): Skip the file unless _untrusted_file_reason accepts it. False for
			files the user named explicitly.

	Returns:
		dict: The config, without values of the wrong type (see _check_config)
	'''
	return _check_config(_read_config_file(config_file, check_trust), config_file)

def _load_config_chain(chain):
	'''
	The settings of the config files in chain (the most specific first, as CONFIG_FILE_CHAIN), merged.

	A wrong value only warns when no more specific file in chain sets that key.
	'''
	files = [(path, _read_config_file(path)) for path in (os.path.expanduser(entry) for entry in reversed(chain))]
	configs = {}
	for index, (path, config) in enumerate(files):
		replaced = set().union(*(more_specific for _, more_specific in files[index + 1:]))
		configs.update(_check_config(config, path, replaced))
	return configs

def _read_config_file(config_file, check_trust=True):
	'''The JSON object config_file holds, legacy keys mapped (see load_config_file), or {} when it cannot be used.'''
	global __working_config_file
	if not os.path.exists(config_file) or os.path.isdir(config_file):
		return {}
	try:
		f = _open_trusted_file(config_file, '--config_file') if check_trust else open(config_file,'r')
		if f is None:
			return {}
		with f:
			config = json.load(f)
	except Exception as e:
		eprint(f"Error: Cannot load config file {config_file!r}: {e}")
		return {}
	if not isinstance(config, dict):
		# null or a list would break every run (and -V) at import, the rest of the chain still applies
		eprint(f"Error: Cannot load config file {config_file!r}: it holds {_json_kind(config)}, not an object of settings")
		return {}
	__working_config_file = config_file
	return apply_config_key_compat(config)


# The built-in ERROR_MESSAGES_TO_IGNORE from 4.81 to 6.31; 4.81 started with the first five. Up to 6.19,
# --store_config_file wrote it into config files. Unanchored, it also hid remote programs' errors.
_OLD_DEFAULT_ERROR_MESSAGES_TO_IGNORE = [
	'Pseudo-terminal will not be allocated because stdin is not a terminal',
	'Connection to .* closed',
	'Warning: Permanently added',
	'mux_client_request_session',
	'disabling multiplexing',
	'Killed by signal',
	'Connection reset by peer',
]

def apply_config_key_compat(configs):
	'''
	Normalize legacy / misspelled config keys in-place.

	Configs written before 6.24 used DEAFULT_IPMI_ARGS (typo). Map it to
	DEFAULT_IPMI_ARGS when the correct key is absent.

	Configs written before 6.20 hold a copy of the built-in ERROR_MESSAGES_TO_IGNORE of the
	time. An unchanged copy is dropped, so the current built-in list applies.
	'''
	if not configs:
		return configs
	if 'DEAFULT_IPMI_ARGS' in configs and 'DEFAULT_IPMI_ARGS' not in configs:
		configs['DEFAULT_IPMI_ARGS'] = configs['DEAFULT_IPMI_ARGS']
	if configs.get('ERROR_MESSAGES_TO_IGNORE') in (_OLD_DEFAULT_ERROR_MESSAGES_TO_IGNORE, _OLD_DEFAULT_ERROR_MESSAGES_TO_IGNORE[:5]):
		del configs['ERROR_MESSAGES_TO_IGNORE']
	return configs

def _apply_config(configs):
	'''
	Set the settings configs holds (checked by load_config_file), then what is derived from them.

	Runs for the config file chain at import and again for --config_file, so both apply the same
	way. Other keys do not become globals, so a config file cannot replace mssh's own state;
	check_path reads the program paths (_sshPath ...) from __configs_from_file.
	'''
	global __ERROR_MESSAGES_TO_IGNORE_REGEX
	global DEFAULT_ENV_FILES
	for name, value in configs.items():
		# the config holds the pattern, the global its compiled form
		if name in _BUILTIN_SETTINGS and name != '__ERROR_MESSAGES_TO_IGNORE_REGEX':
			globals()[name] = value
	pattern = __configs_from_file.get('__ERROR_MESSAGES_TO_IGNORE_REGEX')
	if pattern:
		if configs.get('__ERROR_MESSAGES_TO_IGNORE_REGEX'):
			eprint('Using __ERROR_MESSAGES_TO_IGNORE_REGEX, ignoring ERROR_MESSAGES_TO_IGNORE')
		__ERROR_MESSAGES_TO_IGNORE_REGEX = re.compile(pattern)
	else:
		# an empty pattern matches every line: no messages to ignore must hide nothing
		patterns = [message for message in ERROR_MESSAGES_TO_IGNORE if message]
		__ERROR_MESSAGES_TO_IGNORE_REGEX = re.compile('|'.join(patterns) if patterns else '(?!)')
	if DEFAULT_ENV_FILE and DEFAULT_ENV_FILE not in DEFAULT_ENV_FILES:
		DEFAULT_ENV_FILES = DEFAULT_ENV_FILES + [DEFAULT_ENV_FILE]

#%% Load Config Based Default Global variables
__configs_from_file = {}
# where --store_config_file writes without a path, unless a config file was loaded: one mssh reads by default
__working_config_file = os.path.expanduser('~/.multiSSH3.config.json')
__configs_from_file.update(_load_config_chain(CONFIG_FILE_CHAIN))
_apply_config(__configs_from_file)

#%% Load mssh Functional Global Variables
# IPMI options the command line gives (definition key -> value), set by process_args
_ipmi_command_line = {}
__global_suppress_printout = False
__mainReturnCode = 0
__failedHosts = set()
__wildCharacters = ['*','?','x']
_no_env = DEFAULT_NO_ENV
_env_files = DEFAULT_ENV_FILES
# env files named on the command line, loaded without the ownership / permission check
_explicit_env_files = set()
__globalUnavailableHosts = dict()
__keyPressesIn = [[]]
# the wake events of the threads forwarding typed lines (see __handle_writing_stream): each has its own,
# set for all when the TUI ends a line or ends, and for one when its command stops. One Condition for all
# woke every writer at each command's end: thousands of hosts then spent their time fighting over its lock
_typed_line_waiters = set()
_typed_line_waiters_lock = threading.Lock()

def _typed_lines_changed_notify():
	'''Wake every thread forwarding typed lines: a line was typed, or the TUI ended.'''
	with _typed_line_waiters_lock:
		waiters = list(_typed_line_waiters)
	for wake in waiters:
		wake.set()

_emo = False
# set once the first command starts: before that, Ctrl-C has nothing to stop and exits
_commands_started = False
# set when mssh exits now (a second Ctrl C, SIGTERM, SIGHUP): no command may start any more
_stopping = False
__curses_global_color_pairs = {(-1,-1):1}
__curses_current_color_pair_index = 2  # Start from 1, as 0 is the default color pair
__curses_color_table = {}
__curses_current_color_index = 10
__max_connections_nofile_limit_supported = 0
__thread_start_delay = 0
_encoding = DEFAULT_ENCODING
__returnZero = DEFAULT_RETURN_ZERO
__running_threads = set()
__running_procs = set()
__curses_available = False
__resource_lib_available = False
try:
	import curses
	import curses.panel
	__curses_available = True
except ImportError:
	pass
try:
	import resource
	__resource_lib_available = True
except ImportError:
	pass
def _raise_nofile_soft_limit():
	'''
	Raise the RLIMIT_NOFILE soft limit as far as the system allows.

	An unlimited hard limit (common on macOS) cannot be used as a soft limit, so finite
	caps are tried instead. If nothing can be raised, the current soft limit is kept.

	Returns:
		int: The soft limit in effect afterwards
	'''
	soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
	if soft_limit == resource.RLIM_INFINITY:
		return soft_limit
	if hard_limit == resource.RLIM_INFINITY:
		candidates = [65536, 10240]
	else:
		candidates = [hard_limit]
	for candidate in candidates:
		if candidate <= soft_limit:
			break
		try:
			resource.setrlimit(resource.RLIMIT_NOFILE, (candidate, hard_limit))
			break
		except (ValueError, OSError):
			continue
	return resource.getrlimit(resource.RLIMIT_NOFILE)[0]

if __resource_lib_available:
	try:
		__system_nofile_limit = _raise_nofile_soft_limit()
		if __system_nofile_limit != resource.RLIM_INFINITY:
			__max_connections_nofile_limit_supported = int((__system_nofile_limit - 10) / 3)
	except Exception:
		pass
_binPaths = {}
_binCalled = set(['sshpass', 'ssh', 'scp', 'ipmitool','rsync','sh','ssh-copy-id','redfishtool'])
def check_path(program_name):
	global __configs_from_file
	global _binPaths
	config_key = f'_{program_name}Path'
	program_path = (
		__configs_from_file.get(config_key) or
		globals().get(config_key) or
		shutil.which(program_name)
	)
	if program_path:
		_binPaths[program_name] = program_path
		return True
	return False

def _find_programs():
	'''Look up every program mssh runs, again after --config_file (it can set their paths).'''
	for program in _binCalled:
		check_path(program)

_find_programs()

#%% Mapping of ANSI 4-bit colors to curses colors
if __curses_available:
	ANSI_TO_CURSES_COLOR = {
		30: curses.COLOR_BLACK,
		31: curses.COLOR_RED,
		32: curses.COLOR_GREEN,
		33: curses.COLOR_YELLOW,
		34: curses.COLOR_BLUE,
		35: curses.COLOR_MAGENTA,
		36: curses.COLOR_CYAN,
		37: curses.COLOR_WHITE,
		90: curses.COLOR_BLACK,   # Bright Black (usually gray)
		91: curses.COLOR_RED,     # Bright Red
		92: curses.COLOR_GREEN,   # Bright Green
		93: curses.COLOR_YELLOW,  # Bright Yellow
		94: curses.COLOR_BLUE,    # Bright Blue
		95: curses.COLOR_MAGENTA, # Bright Magenta
		96: curses.COLOR_CYAN,    # Bright Cyan
		97: curses.COLOR_WHITE    # Bright White
	}

#%% ------------ Host Object ----------------
class Host:
	def __init__(self, name, command, files = None,ipmi = False,interface_ip_prefix = None,scp=False,extraargs=None,gatherMode=False,identity_file=None,shell=False,i = -1,uuid=...,ip = None):
		self.name = name # the name of the host (hostname or IP address)
		self.command = command # the command to run on the host
		self.returncode = None # the return code of the command
		self.output = [] # the output of the command for curses
		self.stdout = [] # the stdout of the command
		self.stderr = [] # the stderr of the command
		self.lineNumToPrintSet = set() # line numbers the TUI must draw again: lines it drew that changed (the -t countdown, see _cut_output)
		self.printedLines = 0 # how many lines of output the TUI drew: it draws the ones added since at its next frame
		self.lastUpdateTime = time.monotonic() # the last time the output was updated
		self.lastPrintedUpdateTime = 0 # the last time the output was printed
		self.files = files # the files to be copied to the host
		self.ipmi = ipmi # whether to use ipmi to connect to the host
		self.shell = shell # whether to use shell to run the command
		self.interface_ip_prefix = interface_ip_prefix # the prefix of the ip address of the interface to be used to connect to the host
		self.scp = scp # whether to use scp to copy files to the host
		self.gatherMode = gatherMode # whether the host is in gather mode
		self.extraargs = extraargs # extra arguments to be passed to ssh
		self.resolvedName = None # the resolved IP address of the host
		# also store a globally unique integer i from 0
		self.i = i if i != -1 else _get_i()
		self.uuid = uuid if uuid is not ... else uuid4()
		# the key file mssh found: ssh expands a ~ from the passwd entry, not $HOME (sudo -E, containers)
		self.identity_file = os.path.expanduser(identity_file) if identity_file else identity_file
		self.ip = ip if ip else getIP(name)
		self.current_color_pair = [-1, -1, 1]
		self.output_buffer = io.BytesIO()
		self.stdout_buffer = io.BytesIO()
		self.stderr_buffer = io.BytesIO()
		self.thread = None
		self.use_terminal = False # let the command use the operator's terminal, where ssh asks for passwords and host keys: only when it runs alone without the TUI
		self.interactive_stdin = False # forward the curses TUI key presses to stdin (set while the TUI runs), else /dev/null
		self.skipped = False # True when mssh did not run the command: the host was unreachable in a recent run
		self.dropped_before_login = False # the last try ended with the server dropping ssh's connection before login (sshd MaxStartups?)

	def __iter__(self):
		return zip(['name', 'command', 'returncode', 'stdout', 'stderr'], [self.name, self.command, self.returncode, self.stdout, self.stderr])
	def __repr__(self):
		return f"Host(\n{pformat(self.__dict__)}\n)"
	def __str__(self):
		return f"Host(\n{pformat(dict(self))}\n)"
	def get_output_hash(self):
		return hash((
			self.command,
			tuple(self.stdout),
			tuple(self.stderr),
			self.returncode
		))
	def copy(self):
		newHost = Host(
			name=self.name,
			command=self.command,
			files=self.files,
			ipmi=self.ipmi,
			interface_ip_prefix=self.interface_ip_prefix,
			scp=self.scp,
			extraargs=self.extraargs,
			gatherMode=self.gatherMode,
			identity_file=self.identity_file,
			shell=self.shell,
			i=self.i,
			uuid=self.uuid,
			ip=self.ip
		)
		newHost.returncode = self.returncode
		newHost.output = self.output.copy()
		newHost.stdout = self.stdout.copy()
		newHost.stderr = self.stderr.copy()
		newHost.lineNumToPrintSet = self.lineNumToPrintSet.copy()
		newHost.printedLines = self.printedLines
		newHost.lastUpdateTime = self.lastUpdateTime
		newHost.lastPrintedUpdateTime = self.lastPrintedUpdateTime
		newHost.current_color_pair = self.current_color_pair.copy()
		newHost.use_terminal = self.use_terminal
		newHost.interactive_stdin = self.interactive_stdin
		newHost.skipped = self.skipped
		newHost.dropped_before_login = self.dropped_before_login
		return newHost

#%% ------------ Exportable Help Functions ----------------
def find_ssh_key_file(searchPath = DEFAULT_SSH_KEY_SEARCH_PATH):
	'''
	Find the ssh public key file

	Args:
		searchPath (str, optional): The path to search. Defaults to DEFAULT_SSH_KEY_SEARCH_PATH.

	Returns:
		str: The path to the ssh key file
	'''
	if searchPath:
		sshKeyPath = searchPath
	else:
		sshKeyPath ='~/.ssh'
	for sshKeyFile in POSSIBLE_SSH_KEY_FILES:
		if os.path.exists(os.path.expanduser(os.path.join(sshKeyPath,sshKeyFile))):
			return os.path.join(sshKeyPath,sshKeyFile)
	return None

@cache_decorator
def readEnvFromFile():
	'''
	Read the environment variables from env_file
	Returns:
		dict: A dictionary of environment variables
	'''
	global _env_files
	global _no_env
	envfs = _env_files if _env_files else DEFAULT_ENV_FILES
	if not envfs:
		return {}
	translator = str.maketrans('&|"', ';;\'')
	replacement_re = re.compile(r'\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})')
	environemnt = {}
	scrubCounter = 0
	for envf in envfs:
		envf = os.path.expanduser(os.path.expandvars(envf))
		if os.path.isdir(envf):
			# e.g. a virtualenv named .env
			continue
		if os.path.exists(envf):
			try:
				# --env_files adds to the env file chain, --env_file would replace it
				# shell rc files may hold other encodings: replace what does not decode, keep the rest
				f = open(envf,'r',errors='replace') if os.path.abspath(envf) in _explicit_env_files else _open_trusted_file(envf, '--env_files', errors='replace')
			except OSError as e:
				eprint(f"Warning: Cannot read env file {envf!r}: {e}")
				continue
			if f is None:
				continue
			with f:
				lines = f.readlines()
			for line in lines:
				line = line.strip()
				if not line or line.startswith('#') or '=' not in line:
					continue
				line = line.translate(translator)
				commands = re.split(r";(?=(?:[^']*'[^']*')*[^']*$)", line)
				for command in commands:
					if not command or command.startswith('#') or '=' not in command or command.startswith('alias '):
						continue
					fields = re.split(r" (?=(?:[^']*'[^']*')*[^']*$)", command)
					for field in fields:
						try:
							if field.startswith('export '):
								field = field.replace('export ', '', 1).strip()
							if not field or field.startswith('#') or '=' not in field:
								continue
							key, _, values = field.partition('=')
							key = key.strip().strip("'")
							values = values.strip().strip("'")
							if '$' in values:
								scrubCounter += 16
							# an empty value is kept: an empty host group (eu='') stands for no hosts
							if key and key != values:
								environemnt[key] = values
						except Exception:
							continue
	while scrubCounter:
		scrubCounter -= 1
		found = False
		for key, value in environemnt.items():
			if '$' in value:
				for match in replacement_re.findall(value):
					ref_key = match.strip('${}')
					ref_value = environemnt.get(ref_key) if ref_key != key else None
					if ref_value is None and not _no_env:
						ref_value = _consult_env(ref_key)
					# a variable set to nothing is replaced by nothing, as the shell does
					if ref_value is not None:
						environemnt[key] = value.replace(match, ref_value)
						found = True
		if not found:
			break
	return environemnt

def replace_magic_strings(string,keys,value,case_sensitive=False):
	'''
	Replace the magic strings in the host object

	Args:
		string (str): The string to replace the magic strings
		keys (list): Search for keys to replace
		value (str): The value to replace the key
		case_sensitive (bool, optional): Whether to search for the keys in a case sensitive way. Defaults to False.

	Returns:
		str: The string with the magic strings replaced
	'''
	# verify magic strings have # at the beginning and end
	newKeys = []
	for key in keys:
		if key.startswith('#') and key.endswith('#'):
			newKeys.append(key)
		else:
			newKeys.append('#'+key.strip('#')+'#')
	# replace the magic strings
	for key in newKeys:
		if case_sensitive:
			string = string.replace(key,value)
		else:
			# a function replacement is inserted as is, a string one would expand backslashes
			string = re.sub(re.escape(key),lambda _match: value,string,flags=re.IGNORECASE)
	return string

def pretty_format_table(data, delimiter = '\t',header = None):
	import unicodedata
	version = 1.12
	_ = version
	if not data:
		return ''
	if isinstance(data, str):
		data = data.strip('\n').split('\n')
		data = [line.split(delimiter) for line in data]
	elif isinstance(data, dict):
		# flatten the 2D dict to a list of lists
		if isinstance(next(iter(data.values())), dict):
			tempData = [['key'] + list(next(iter(data.values())).keys())]
			tempData.extend( [[key] + list(value.values()) for key, value in data.items()])
			data = tempData
		else:
			# it is a dict of lists
			data = [[key] + list(value) for key, value in data.items()]
	elif not isinstance(data, list):
		data = list(data)
	# format the list into 2d list of list of strings
	if isinstance(data[0], dict):
		tempData = [data[0].keys()]
		tempData.extend([list(item.values()) for item in data])
		data = tempData
	data = [[str(item) for item in row] for row in data]
	num_cols = len(data[0])
	# Widths count terminal columns: an East Asian wide character takes two,
	# a combining mark and an ANSI color code none.
	def char_width(ch):
		if ch < '\u0300':  # ASCII and Latin-1
			return 1
		if unicodedata.combining(ch) or unicodedata.category(ch) in ('Mn', 'Me', 'Cf') or '\u1160' <= ch <= '\u11ff':
			return 0
		return 2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1
	def visible_len(s):
		if '\x1b' in s:
			s = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', s)
		if not s or max(s) < '\u0300':
			return len(s)
		return sum(char_width(ch) for ch in s)
	if header:
		# pad / truncate header to appropriate length
		if isinstance(header,str):
			header = header.split(delimiter)
		if len(header) < num_cols:
			header += ['']*(num_cols-len(header))
		elif len(header) > num_cols:
			header = header[:num_cols]
		rows = data
	else:
		header = data[0]
		rows = data[1:]
	# Calculate the maximum width of each column
	col_widths = [max(visible_len(row[c]) for row in [header] + rows) for c in range(num_cols)]
	def format_row(row):
		return ' | '.join(cell + ' ' * (width - visible_len(cell)) for cell, width in zip(row, col_widths))
	divider = '-+-'.join('-' * width for width in col_widths)
	outTable = [format_row(header), divider]
	for row in rows:
		# if the row is empty, print an divider
		outTable.append(format_row(row) if any(row) else divider)
	return '\n'.join(outTable) + '\n'

def join_threads(threads=...,timeout=None):
	'''
	Join threads

	@params:
		threads: The threads to join. Defaults to the current __running_threads set
			(resolved at call time — do not bind the set object as a default arg).
		timeout: The timeout

	@returns:
		None
	'''
	global __running_threads
	if threads is ...:
		threads = __running_threads
	for thread in threads:
		thread.join(timeout=timeout)
	if threads is __running_threads:
		__running_threads = {t for t in threads if t.is_alive()}

def format_commands(commands):
	if not commands:
		commands = []
	else:
		commands = [commands] if isinstance(commands,str) else commands
		# reformat commands into a list of strings, join the iterables if they are not strings
		try:
			commands = [' '.join(command) if not isinstance(command,str) else command for command in commands]
		except Exception as e:
			eprint(f"Warning: commands should ideally be a list of strings. Now mssh had failed to convert {commands!r} to a list of strings. Continuing anyway but expect failures. Error: {e}")
	return commands

def get_terminal_size():
	'''
	Get the terminal size: stdout's terminal, else stdin's (mssh ... | less), else COLUMNS / LINES, else 120x30.

	A terminal that reports 0 columns or rows does not know its size (a pty nobody set one on: script
	without a terminal, some CI runners). As shutil.get_terminal_size does, what it does not know comes
	from COLUMNS / LINES or the fallback.

	@params:
		None

	@returns:
		(int,int): the number of columns and rows of the terminal
	'''
	try:
		columns, rows = os.get_terminal_size()
	except Exception:
		try:
			import fcntl
			import struct
			import termios
			packed = fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
			rows, columns = struct.unpack('HHHH', packed)[:2]
		except Exception:
			columns = rows = 0
	def from_environment(name, fallback):
		try:
			value = int(os.environ.get(name, ''))
		except ValueError:
			return fallback
		return value if value > 0 else fallback
	if columns <= 0:
		columns = from_environment('COLUMNS', 120)
	if rows <= 0:
		rows = from_environment('LINES', 30)
	return os.terminal_size((columns, rows))

@cache_decorator
def get_terminal_color_capability():
	'''
	Detect the terminal's color capability string: 'None', '8', '16', '256', or '24bit'.

	Note: This function is process-lifetime cached (lru_cache via cache_decorator) with no
	arguments. The first call's result sticks for the rest of the process even if TERM,
	COLORTERM, or FORCE_TRUECOLOR change later. That matches one-shot CLI usage; long-lived
	embeds that mutate the environment should call cache_clear() (when available) first.
	'''
	global FORCE_TRUECOLOR
	if not sys.stdout.isatty():
		return 'None'
	term = os.environ.get("TERM", "")
	if term == "dumb":
		return 'None'
	elif term == "linux":
		return '8'
	elif FORCE_TRUECOLOR:
		return '24bit'
	colorterm = os.environ.get("COLORTERM", "")
	if colorterm in ("truecolor", "24bit", "24-bit"):
		return '24bit'
	if term in ("xterm-truecolor", "xterm-24bit", "xterm-kitty", "alacritty", "wezterm", "foot", "terminology"):
		return '24bit'
	elif "256" in term:
		return '256'
	elif "16" in term:
		return '16'
	try:
		curses.setupterm()
		colors = curses.tigetnum("colors")
		# tigetnum returns -1 if the capability isn’t defined
		if colors >= 16777216:
			return '24bit'
		elif colors >= 256:
			return '256'
		elif colors >= 16:
			return '16'
		elif colors > 0:
			return '8'
		else:
			return 'None'
	except Exception:
		return 'None'

@cache_decorator
def rgb_to_ansi_color_string(r, g, b):
	"""
	Return an ANSI escape sequence setting the foreground to (r,g,b)
	approximated to the terminal's capability, or '' if none.
	"""
	cap = get_terminal_color_capability()
	if cap == 'None':
		return ''
	if cap == '24bit':
		return f'\x1b[38;2;{r};{g};{b}m'
	if cap == '256':
		idx = _rgb_to_256_color(r, g, b)
		return f'\x1b[38;5;{idx}m'
	if cap == '16':
		idx = _rgb_to_16_color(r, g, b)
		# 0–7 = 30–37, 8–15 = 90–97
		if idx < 8:
			return f'\x1b[{30 + idx}m'
		else:
			return f'\x1b[{90 + (idx - 8)}m'
	if cap == '8':
		idx = _rgb_to_8_color(r, g, b)
		return f'\x1b[{30 + idx}m'
	return ''

def _rgb_to_256_color(r, g, b):
	"""
	Map (r,g,b) to the 256-color cube or grayscale ramp.
	"""
	# if it’s already gray, use the 232–255 grayscale ramp
	if r == g == b:
		# 24 shades from 232 to 255
		return 232 + int(round(r / 255 * 23))
	# else map each channel to 0–5
	def to6(v):
		return int(round(v / 255 * 5))
	r6, g6, b6 = to6(r), to6(g), to6(b)
	return 16 + 36 * r6 + 6 * g6 + b6

def _rgb_to_16_color(r, g, b):
	"""
	Pick the nearest of the 16 ANSI standard colors.
	Returns an index 0-15.
	"""
	palette = [
		(0, 0, 0),       # 0 black
		(128, 0, 0),     # 1 red
		(0, 128, 0),     # 2 green
		(128, 128, 0),   # 3 yellow
		(0, 0, 128),     # 4 blue
		(128, 0, 128),   # 5 magenta
		(0, 128, 128),   # 6 cyan
		(192, 192, 192), # 7 white (light gray)
		(128, 128, 128), # 8 bright black (dark gray)
		(255, 0, 0),     # 9 bright red
		(0, 255, 0),     # 10 bright green
		(255, 255, 0),   # 11 bright yellow
		(0, 0, 255),     # 12 bright blue
		(255, 0, 255),   # 13 bright magenta
		(0, 255, 255),   # 14 bright cyan
		(255, 255, 255), # 15 bright white
	]
	best_idx = 0
	best_dist = float('inf')
	for i, (pr, pg, pb) in enumerate(palette):
		dist = (r - pr)**2 + (g - pg)**2 + (b - pb)**2
		if dist < best_dist:
			best_dist = dist
			best_idx = i
	return best_idx

def _rgb_to_8_color(r, g, b):
	"""
	Reduce to 8 colors by mapping to the 16-color index then clamping 0-7.
	"""
	return _rgb_to_16_color(r//2, g//2, b//2)


def int_to_color(hash_value, min_brightness=100,max_brightness=220):
	r = (hash_value >> 16) & 0xFF
	g = (hash_value >> 8) & 0xFF
	b = hash_value & 0xFF
	brightness = math.sqrt(0.299 * r**2 + 0.587 * g**2 + 0.114 * b**2)
	if brightness < min_brightness:
		return int_to_color(hash(str(hash_value)), min_brightness, max_brightness)
	if brightness > max_brightness:
		return int_to_color(hash(str(hash_value)), min_brightness, max_brightness)
	return (r, g, b)

__previous_color_rgb = ()
@cache_decorator
def int_to_unique_ansi_color(number):
	'''
	Convert a number to a unique ANSI color code

	Args:
		number (int): The number to convert
	Returns:
		int: The ANSI color code
	'''
	global __previous_color_rgb
	# Use a hash function to generate a consistent integer from the string
	color_capability = get_terminal_color_capability()
	if color_capability == 'None':
		return ''
	if color_capability == '24bit':
		r, g, b = int_to_color(number)
	else:
		# for 256 colors and below, reduce brightness threshold as we do not have many color to work with
		r, g, b = int_to_color(number, min_brightness=70, max_brightness=190)
	if sum(abs(a - b) for a, b in zip((r, g, b), __previous_color_rgb)) <= 256:
		r, g, b = int_to_color(hash(str(number)))
	__previous_color_rgb = (r, g, b)
	return rgb_to_ansi_color_string(r, g, b)

#%% ------------ Compacting Hostnames ----------------
def __tokenize_hostname(hostname):
	"""
	Tokenize the hostname into a list of tokens.
	Tokens will be separated by symbols or numbers.

	Args:
		hostname (str): The hostname to tokenize.

	Returns:
		list: A list of tokens.

	Example:
		>>> tokenize_hostname('www.example.com')
		('www', '.', 'example', '.', 'com')
		>>> tokenize_hostname('localhost')
		('localhost',)
		>>> tokenize_hostname('Sub-S1')
		('Sub', '-', 'S', '1')
		>>> tokenize_hostname('Sub-S10')
		('Sub', '-', 'S', '10')
		>>> tokenize_hostname('Process-Client10-1')
		('Process', '-', 'Client', '10', '-', '1')
		>>> tokenize_hostname('Process-C5-15')
		('Process', '-', 'C', '5', '-', '15')
		>>> tokenize_hostname('192.168.1.1')
		('192', '.', '168', '.', '1', '.', '1')
	"""
	# Regular expression to match sequences of letters, digits, or symbols
	tokens = re.findall(r'[A-Za-z]+|\d+|[^A-Za-z0-9]', hostname)
	return tuple(tokens)

def __hashTokens(tokens):
	"""
	Translate a list of tokens in string to a list of integers with positional information.

	Args:
		tokens (tuple): A tuple of tokens.

	Returns:
		list: A list of integers.

	Example:
		>>> tuple(hashTokens(('1')))
		(1,)
		>>> tuple(hashTokens(('1', '2')))
		(1, 2)
		>>> tuple(hashTokens(('1', '.', '2')))
		(1, -5047856122680242044, 2)
		>>> tuple(hashTokens(('Process', '-', 'C', '5', '-', '15')))
		(117396829274297939, 7549860403020794775, 8629208860073383633, 5, 7549860403020794775, 15)
		>>> tuple(hashTokens(('192', '.', '168', '.', '1', '.', '1')))
		(192, -5047856122680242044, 168, -5047856122680242044, 1, -5047856122680242044, 1)
	"""
	return tuple(int(token) if token.isdigit() else hash(token) for token in tokens)

def __findDiffIndex(token1, token2):
	"""
	Find the index of the first difference between two lists of tokens.
	If there is more than one difference, return -1.

	Args:
		token1 (tuple): A list of tokens.
		token2 (tuple): A list of tokens.

	Returns:
		int: The index of the first difference between the two lists of tokens.

	Example:
		>>> findDiffIndex(('1',), ('1',))
		-1
		>>> findDiffIndex(('1','2'), ('1', '1'))
		1
		>>> findDiffIndex(('1','1'), ('1', '1', '1'))
		Traceback (most recent call last):
		...
		ValueError: The two lists must have the same length.
		>>> findDiffIndex(('192', '.', '168', '.', '2', '.', '1'), ('192', '.', '168', '.', '1', '.', '1'))
		4
		>>> findDiffIndex(('192', '.', '168', '.', '2', '.', '1'), ('192', '.', '168', '.', '1', '.', '2'))
		-1
		>>> findDiffIndex(('Process', '-', 'C', '5', '-', '15'), ('Process', '-', 'C', '5', '-', '15'))
		-1
		>>> findDiffIndex(('Process', '-', 'C', '5', '-', '15'), ('Process', '-', 'C', '5', '-', '16'))
		5
		>>> findDiffIndex(tokenize_hostname('nebulahost3'), tokenize_hostname('nebulaleaf3'))
		-1
		>>> findDiffIndex(tokenize_hostname('nebulaleaf3'), tokenize_hostname('nebulaleaf4'))
		1
	"""
	if len(token1) != len(token2):
		raise ValueError('The two lists must have the same length.')
	rtn = -1
	for i, (subToken1, subToken2) in enumerate(zip(token1, token2)):
		if subToken1 != subToken2:
			if rtn == -1 and subToken1.isdigit() and subToken2.isdigit():
				rtn = i
			else:
				return -1
	return rtn

def __generateSumDic(Hostnames):
	"""
	Generate a dictionary of sums of tokens for a list of hostnames.

	Args:
		Hostnames (list): A list of hostnames.

	Example:
		>>> generateSumDic(['localhost'])
		{6564370170492138900: {('localhost',): {}}}
		>>> generateSumDic(['1', '2'])
		{1: {('1',): {}}, 2: {('2',): {}}}
		>>> generateSumDic(['1.1','1.2'])
		{3435203479547611399: {('1', '.', '1'): {}}, 3435203479547611400: {('1', '.', '2'): {}}}
		>>> generateSumDic(['1.2','2.1'])
		{3435203479547611400: {('1', '.', '2'): {}, ('2', '.', '1'): {}}}
	"""
	sumDic = {}
	for hostname in reversed(sorted(Hostnames)):
		tokens = __tokenize_hostname(hostname)
		sumHash = sum(__hashTokens(tokens))
		sumDic.setdefault(sumHash, {})[tokens] = {}
	return sumDic

def __filterSumDic(sumDic):
	"""
	Filter the sumDic to do one order of grouping.

	Args:
		sumDic (dict): A dictionary of sums of tokens.

	Returns:
		dict: A filtered dictionary of sums of tokens.

	Example:
		>>> filterSumDic(generateSumDic(['server15', 'server16', 'server17']))
		{-6728831096159691241: {('server', '17'): {(1, 0): [15, 17]}}}
		>>> filterSumDic(generateSumDic(['server15', 'server16', 'server17', 'server18']))
		{-6728831096159691240: {('server', '18'): {(1, 0): [15, 18]}}}
		>>> filterSumDic(generateSumDic(['server-1', 'server-2', 'server-3']))
		{1441623239094376437: {('server', '-', '3'): {(2, 0): [1, 3]}}}
		>>> filterSumDic(generateSumDic(['server-1-2', 'server-1-1', 'server-2-1', 'server-2-2']))
		{9612077574348444129: {('server', '-', '1', '-', '2'): {(4, 0): [1, 2]}}, 9612077574348444130: {('server', '-', '2', '-', '2'): {(4, 0): [1, 2]}}}
		>>> filterSumDic(generateSumDic(['server-1-2', 'server-1-1', 'server-2-2']))
		{9612077574348444129: {('server', '-', '1', '-', '2'): {(4, 0): [1, 2]}}, 9612077574348444130: {('server', '-', '2', '-', '2'): {}}}
		>>> filterSumDic(generateSumDic(['test1-a', 'test2-a']))
		{12310874833182455839: {('test', '2', '-', 'a'): {(1, 0): [1, 2]}}}
		>>> filterSumDic(generateSumDic(['sub-s1', 'sub-s2']))
		{15455586825715425366: {('sub', '-', 's', '2'): {(3, 0): [1, 2]}}}
		>>> filterSumDic(generateSumDic(['s9', 's10', 's11']))
		{1169697225593811728: {('s', '11'): {(1, 0): [9, 11]}}}
		>>> filterSumDic(generateSumDic(['s99', 's98', 's100','s101']))
		{1169697225593811818: {('s', '101'): {(1, 0): [98, 101]}}}
		>>> filterSumDic(generateSumDic(['s08', 's09', 's10', 's11']))
		{1169697225593811728: {('s', '11'): {(1, 2): [8, 11]}}}
		>>> filterSumDic(generateSumDic(['s099', 's098', 's100','s101']))
		{1169697225593811818: {('s', '101'): {(1, 3): [98, 101]}}}
		>>> filterSumDic(generateSumDic(['server1', 'server2', 'server3','server04']))
		{-6728831096159691255: {('server', '3'): {(1, 0): [1, 3]}}, -6728831096159691254: {('server', '04'): {}}}
		>>> filterSumDic(generateSumDic(['server9', 'server09', 'server10','server10']))
		{-6728831096159691249: {('server', '09'): {}}, -6728831096159691248: {('server', '10'): {(1, 0): [9, 10]}}}
		>>> filterSumDic(generateSumDic(['server09', 'server9', 'server10']))
		{-6728831096159691249: {('server', '9'): {}}, -6728831096159691248: {('server', '10'): {(1, 2): [9, 10]}}}
	"""
	lastSumHash = None
	newSumDic = {}    
	for key, value in sumDic.items():
		newSumDic[key] = value.copy()
	sumDic = newSumDic
	newSumDic = {}
	for sumHash in sorted(sumDic):
		if lastSumHash is None:
			lastSumHash = sumHash
			newSumDic[sumHash] = sumDic[sumHash].copy()
			continue
		if sumHash - lastSumHash == 1:
			# this means the distence between these two group of hostnames is 1, thus we try to group them together
			for hostnameTokens in sumDic[sumHash]:
				added = False
				if lastSumHash in newSumDic and sumDic[lastSumHash]:
					for lastHostnameTokens in sumDic[lastSumHash].copy():
						# if the two hostnames are able to group, we group them together
						# the two hostnames are able to group if:
						# 1. the two hostnames have the same amount of tokens
						# 2. the last hostname is not already been grouped
						# 3. the two hostnames have the same tokens except for one token
						# 4. the two hostnames have the same token groups
						if len(hostnameTokens) == len(lastHostnameTokens) and \
							lastSumHash in newSumDic and lastHostnameTokens in newSumDic[lastSumHash]:
							diffIndex=__findDiffIndex(hostnameTokens, lastHostnameTokens)
							if diffIndex != -1 and \
								sumDic[sumHash][hostnameTokens] == sumDic[lastSumHash][lastHostnameTokens]:
								# the sumDic[sumHash][hostnameTokens] will ba a dic of 2 element value lists with 2 element key representing:
								# (token position that got grouped, the amount of zero padding (length) ):
								#   [ the start int token, the end int token]
								# if we entered here, this means we are able to group the two hostnames together

								if not diffIndex:
									# should never happen, but just in case, we skip grouping
									continue
								tokenToGroup = hostnameTokens[diffIndex]
								try:
									tokenLength = len(tokenToGroup)
									tokenToGroup = int(tokenToGroup)
								except ValueError:
									# if the token is not an int, we skip grouping
									continue
								# group(09 , 10) -> (x, 2): [9, 10]
								# group(9 , 10) -> (x, 0): [9, 10]
								# group(9 , 010) -> not able to group
								# group(009 , 10) -> not able to group
								# group(08, 09) -> (x, 2): [8, 9]
								# group(08, 9) -> not able to group
								# group(8, 09) -> not able to group
								# group(0099, 0100) -> (x, 4): [99, 100]
								# group(0099, 100) -> not able to groups
								# group(099, 100) -> (x, 3): [99, 100]
								# group(99, 100) -> (x, 0): [99, 100]
								lastTokenToGroup = lastHostnameTokens[diffIndex]
								try:
									minimumTokenLength = 0
									lastTokenLength = len(lastTokenToGroup) 
									if lastTokenLength > tokenLength:
										raise ValueError('The last token is longer than the current token.')
									elif lastTokenLength < tokenLength:
										if tokenLength - lastTokenLength != 1:
											raise ValueError('The last token is not one less than the current token.')
										# if the last token is not made out of all 9s, we cannot group
										if any(c != '9' for c in lastTokenToGroup):
											raise ValueError('The last token is not made out of all 9s.')
									elif lastTokenToGroup[0] == '0' and lastTokenLength > 1:
										# we have encoutered a padded last token, will set this as the minimum token length
										minimumTokenLength = lastTokenLength
									lastTokenToGroup = int(lastTokenToGroup)
								except ValueError:
									# if the token is not an int, we skip grouping
									continue
								assert lastTokenToGroup + 1 == tokenToGroup, 'Error! The two tokens are not one apart.'
								# we take the last hostname tokens grouped dic out from the newSumDic
								hostnameGroupDic = newSumDic[lastSumHash][lastHostnameTokens].copy()
								if (diffIndex, minimumTokenLength) in hostnameGroupDic and hostnameGroupDic[(diffIndex, minimumTokenLength)][1] + 1 == tokenToGroup:
									# if the token is already grouped, we just update the end token
									hostnameGroupDic[(diffIndex, minimumTokenLength)][1] = tokenToGroup
								elif (diffIndex, tokenLength) in hostnameGroupDic and hostnameGroupDic[(diffIndex, tokenLength)][1] + 1 == tokenToGroup:
									# alternatively, there is already an exact length padded token grouped
									hostnameGroupDic[(diffIndex, tokenLength)][1] = tokenToGroup
								elif sumDic[lastSumHash][lastHostnameTokens] == newSumDic[lastSumHash][lastHostnameTokens]:
									# only when there are no new groups added to this token group this iter, we can add the new group
									hostnameGroupDic[(diffIndex, minimumTokenLength)] = [lastTokenToGroup, tokenToGroup]
								else:
									# skip grouping if there are new groups added to this token group this iter
									continue
								# move the grouped dic under the new hostname / sum hash
								del newSumDic[lastSumHash][lastHostnameTokens]
								del sumDic[lastSumHash][lastHostnameTokens]
								if not newSumDic[lastSumHash]:
									del newSumDic[lastSumHash]
								newSumDic.setdefault(sumHash, {})[hostnameTokens] = hostnameGroupDic
								# we add the new group to the newSumDic
								added = True
								break
				if not added:
					# if the two hostnames are not able to group, we just add the last group to the newSumDic
					newSumDic.setdefault(sumHash, {})[hostnameTokens] = sumDic[sumHash][hostnameTokens].copy()
		else:
			# this means the distence between these two group of hostnames is not 1, thus we just add the last group to the newSumDic
			newSumDic[sumHash] = sumDic[sumHash].copy()
		lastSumHash = sumHash
	return newSumDic

@cache_decorator
def __compact_hostnames(Hostnames):
	"""
	Compact a list of hostnames.
	Compact numeric numbers into ranges.

	Args:
		Hostnames (list): A list of hostnames.

	Returns:
		list: A list of comapcted hostname list.

	Example:
		>>> compact_hostnames(['server15', 'server16', 'server17'])
		['server[15-17]']
		>>> compact_hostnames(['server-1', 'server-2', 'server-3'])
		['server-[1-3]']
		>>> compact_hostnames(['server-1-2', 'server-1-1', 'server-2-1', 'server-2-2'])
		['server-[1-2]-[1-2]']
		>>> compact_hostnames(['server-1-2', 'server-1-1', 'server-2-2'])
		['server-1-[1-2]', 'server-2-2']
		>>> compact_hostnames(['test1-a', 'test2-a'])
		['test[1-2]-a']
		>>> compact_hostnames(['sub-s1', 'sub-s2'])
		['sub-s[1-2]']
	"""
	sumDic = __generateSumDic(Hostnames)
	filteredSumDic = __filterSumDic(sumDic)
	lastFilteredSumDicLen = len(filteredSumDic) + 1
	while lastFilteredSumDicLen > len(filteredSumDic):
		lastFilteredSumDicLen = len(filteredSumDic)
		filteredSumDic = __filterSumDic(filteredSumDic)
	rtnSet = set()
	for sumHash in filteredSumDic:
		for hostnameTokens in filteredSumDic[sumHash]:
			hostnameGroupDic = filteredSumDic[sumHash][hostnameTokens]
			hostnameList = list(hostnameTokens)
			for tokenIndex, tokenLength in hostnameGroupDic:
				startToken, endToken = hostnameGroupDic[(tokenIndex, tokenLength)]
				if tokenLength:
					hostnameList[tokenIndex] = f'[{startToken:0{tokenLength}d}-{endToken:0{tokenLength}d}]'
				else:
					hostnameList[tokenIndex] = f'[{startToken}-{endToken}]'
			rtnSet.add(''.join(hostnameList))
	return frozenset(rtnSet)

def compact_hostnames(Hostnames,verify = True, hosts_only = False):
	"""
	Compact a list of hostnames.
	Compact numeric numbers into ranges.

	Args:
		Hostnames (list): A list of hostnames.
		hosts_only (bool): Ignored, kept for callers of 6.32 to 6.38 (mssh shows names with compact_hostnames_local now).

	Returns:
		list: A list of comapcted hostname list.

	Example:
		>>> compact_hostnames(['server15', 'server16', 'server17'])
		['server[15-17]']
		>>> compact_hostnames(['server-1', 'server-2', 'server-3'])
		['server-[1-3]']
		>>> compact_hostnames(['server-1-2', 'server-1-1', 'server-2-1', 'server-2-2'])
		['server-[1-2]-[1-2]']
		>>> compact_hostnames(['server-1-2', 'server-1-1', 'server-2-2'])
		['server-1-[1-2]', 'server-2-2']
		>>> compact_hostnames(['test1-a', 'test2-a'])
		['test[1-2]-a']
		>>> compact_hostnames(['sub-s1', 'sub-s2'])
		['sub-s[1-2]']
	"""
	global __global_suppress_printout
	hostSet = frozenset(expand_hostnames((
		hostname.strip()
		for hostnames_str in Hostnames
		for hostname in hostnames_str.split(',')
	)))
	compact_hosts = __compact_hostnames(hostSet)
	if verify:
		if frozenset(expand_hostnames(compact_hosts)) != hostSet:
			if not __global_suppress_printout:
				eprint(f"Error compacting hostnames: {hostSet} -> {compact_hosts}")
			compact_hosts = hostSet
	return sorted(compact_hosts)

#%% ------------ Expanding Hostnames ----------------
# invalid host names reported during the current run_command_on_hosts call
_reported_invalid_hosts = set()
# aliases met inside themselves that are no host either, each counted once towards the exit code
_counted_alias_loops = set()

# env files mssh read from the current directory before 6.27, for a hint when a name is missing
_FORMER_CURRENT_DIR_ENV_FILES = ('.env', 'host.env', 'hosts.env')

def _current_dir_env_file_defining(hostname):
	'''The current-directory env file (no longer read by default) that defines hostname, or None.'''
	pattern = re.compile(r'(?:^|[\s;])(?:export\s+)?' + re.escape(hostname) + r'\s*=', re.MULTILINE)
	for env_file in _FORMER_CURRENT_DIR_ENV_FILES:
		if not os.path.isfile(env_file) or os.path.abspath(env_file) in _explicit_env_files:
			continue
		try:
			with open(env_file, 'r', errors='replace') as f:
				if pattern.search(f.read()):
					return env_file
		except OSError:
			continue
	return None

def _local_hostname_source(hostname):
	'''
	How hostname resolves without DNS, in the order host validation tries.

	Returns:
		str: 'ip' (an IP address or in the hosts file), 'env' (an environment variable alias,
			unless _no_env), 'env_file' (an alias from the env files), or None when DNS is needed
	'''
	if getIP(hostname,local=True):
		return 'ip'
	if not _no_env and _consult_env(hostname) is not None:
		return 'env'
	if hostname in readEnvFromFile():
		return 'env_file'
	return None

# getaddrinfo errors saying the name does not exist; any other failure says nothing about it
_DNS_NO_SUCH_NAME = frozenset(code for code in (getattr(socket, 'EAI_NONAME', None), getattr(socket, 'EAI_NODATA', None)) if code is not None)

def _dns_answer(hostname, timeout):
	''''yes' when DNS resolves hostname, 'no' when it says the name does not exist, else 'unsure'.'''
	result = []
	def lookup():
		try:
			socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
			result.append('yes')
		except socket.gaierror as e:
			result.append('no' if e.errno in _DNS_NO_SUCH_NAME else 'unsure')
		except Exception:
			result.append('unsure')
	# getaddrinfo takes no timeout: a lookup still running after it is left to finish on its own
	thread = threading.Thread(target=lookup, daemon=True)
	thread.start()
	thread.join(timeout)
	return result[0] if result else 'unsure'

def host_validity(hostname, timeout=2.0):
	'''
	Whether mssh would accept hostname: 'valid', 'invalid' or 'unsure'.

	The rule __validate_expand_hostname applies (an IP address, a hosts file name, an env / env
	file alias, a name DNS resolves, a name the ssh config maps to another HostName or puts
	behind a ProxyJump / ProxyCommand), except that DNS answers in three ways: only "no such name"
	(EAI_NONAME, EAI_NODATA) can make a name invalid. A lookup failing otherwise or taking longer
	than timeout seconds, or an ssh -G that fails, makes it 'unsure', and so does such a lookup of
	the target a catch-all HostName template gives the name. This does not connect to the host,
	but ssh -G runs the commands of Match exec lines in the ssh config, which may.

	Args:
		hostname (str): One host name, user@ allowed
		timeout (float): Seconds each DNS lookup may take (the name's, its template target's)
	'''
	if '@' in hostname:
		hostname = hostname.rsplit('@', 1)[1]
	hostname = hostname.strip().strip('$')
	if not hostname:
		return 'invalid'
	if _local_hostname_source(hostname):
		return 'valid'
	answer = _dns_answer(hostname, timeout)
	if answer == 'yes':
		return 'valid'
	if 'ssh' in _binPaths and not hostname.startswith('-'):
		if _ssh_config_values(hostname) is None:
			return 'unsure'
		target, templated = _ssh_config_mapping(hostname)
		if target and not templated:
			return 'valid'
		if target:
			# a HostName template: as _ssh_config_target decides, with the target's lookup bounded
			# too (_resolve_dns waits as long as the resolver does, a minute with timeout:30)
			if getIP(target,local=True):
				return 'valid'
			target_answer = _dns_answer(target, timeout)
			if target_answer != 'no':
				return 'valid' if target_answer == 'yes' else 'unsure'
	return 'invalid' if answer == 'no' else 'unsure'

@cache_decorator
def __validate_expand_hostname(hostname):
	'''
	Validate the hostname and expand it if it is an env / env file alias

	Args:
		hostname (str): The hostname to be validated and expanded

	Returns:
		list: A list of valid hostnames
	'''
	# we will try to get the valid host name from the environment
	hostname = hostname.strip().strip('$')
	source = _local_hostname_source(hostname)
	if source == 'ip':
		return [hostname]
	if source in ('env', 'env_file'):
		return _expand_alias(hostname, source)
	return _validate_host(hostname)

def _validate_host(hostname, loop=None):
	'''
	[hostname] when DNS or the ssh config knows it, else [] after reporting it (once per run).

	Args:
		hostname (str): A host name that is not an IP address, hosts file name or alias
		loop (tuple, optional): The aliases walked to reach hostname, when it is an alias met
			inside its own expansion (see _alias_members)
	'''
	if getIP(hostname,local=False):
		return [hostname]
	if _ssh_config_target(hostname):
		# ssh reaches it through the ssh config, e.g. a host behind a ProxyJump
		return [hostname]
	global __mainReturnCode
	global __failedHosts
	# validated again after the caches refresh: report once per run_command_on_hosts call
	if hostname not in _reported_invalid_hosts:
		if loop:
			eprint(f"Error: alias loop through {hostname!r} ({' -> '.join(loop)}): {hostname!r} is not a valid hostname or IP address!")
		else:
			eprint(f"Error: {hostname!r} is not a valid hostname or IP address!")
			defined_in = _current_dir_env_file_defining(hostname)
			if defined_in:
				eprint(f"Note: {hostname!r} is defined in ./{defined_in}, which is no longer read automatically; use --env_files {defined_in}")
		_reported_invalid_hosts.add(hostname)
	# and count once towards the exit code. The failed hosts are expanded again to be listed:
	# an alias name there would list the alias's members, so a loop is counted on its own
	counted = _counted_alias_loops if loop else __failedHosts
	if hostname not in counted:
		__mainReturnCode += 1
		counted.add(hostname)
	return []

def _alias_value(name, source):
	'''The hosts string an alias holds: source 'env' (an environment variable) or 'env_file'.'''
	value = _consult_env(name) if source == 'env' else readEnvFromFile().get(name)
	return value or ''

def _host_names_in(text, user=None):
	'''
	(user, name, source) for each host name in a hosts string, ranges expanded, aliases not.

	The string is split as the hosts argument is (, space ; | / &). user is the name's user@
	prefix, else the user given; source is _local_hostname_source(name): 'ip', 'env',
	'env_file', or None when only DNS or the ssh config could confirm the name.
	'''
	for token in _split_host_str(text):
		token_user = user
		if '@' in token:
			token_user, token = token.split('@', 1)
			token_user = token_user.strip() or user
		token = token.strip()
		if not token:
			continue
		if _IPV4_RANGE_RE.match(token):
			for address in __expandIPv4Address(frozenset([token])):
				yield token_user, address, 'ip'
			continue
		# sorted: which name closes an alias loop must not depend on the order of a set
		for name in sorted(__expand_hostname(token, validate=False)):
			name = name.strip().strip('$')
			if name:
				yield token_user, name, _local_hostname_source(name)

def _alias_members(alias, source, user=None):
	'''
	The host names an alias stands for, with the aliases inside it expanded, without DNS.

	An alias met again inside its own expansion (directly or through other aliases) is not
	expanded again: there it names the host of that name, as bash does with an alias inside its
	own definition, so web="web,web-b" stands for the host web and web-b. When no such host
	exists, mssh reports an alias loop. Each alias is walked once per user, so aliases that are
	shared or fan out (AA='BB,BB', BB='AA,AA') cost no more than one walk each.

	Args:
		alias (str): The alias name
		source (str): 'env' or 'env_file', as _local_hostname_source gives it
		user (str, optional): The user@ the alias was given with

	Returns:
		list: (user, name, source, loop) per member. source is 'ip' (an IP address or hosts file
			name) or None (only DNS or the ssh config could confirm it); loop is the aliases walked
			to reach a member that is an alias met inside itself (web -> app -> web), else None.
	'''
	members = []
	walked = {(alias, user)}
	path = [alias]
	# a stack instead of recursion: a long chain of aliases cannot reach the recursion limit
	walks = [_host_names_in(_alias_value(alias, source), user)]
	while walks:
		item = next(walks[-1], None)
		if item is None:
			walks.pop()
			path.pop()
			continue
		name_user, name, name_source = item
		if name_source not in ('env', 'env_file'):
			members.append((name_user, name, name_source, None))
		elif name in path:
			members.append((name_user, name, None, tuple(path) + (name,)))
		elif (name, name_user) not in walked:
			walked.add((name, name_user))
			path.append(name)
			walks.append(_host_names_in(_alias_value(name, name_source), name_user))
	return members

def _expand_alias(alias, source):
	'''The valid host names (user@ kept) an alias stands for; the members mssh rejects are reported.'''
	members = _alias_members(alias, source)
	_prefetch_ips([name for _, name, _, loop in members if not loop])
	hosts = []
	for user, name, _, loop in members:
		# other members through the cache, as if typed: each is looked up and reported once
		if not (_validate_host(name, loop) if loop else __validate_expand_hostname(name)):
			continue
		if user:
			hosts.extend(f'{each}@{name}' for each in sorted(__expand_hostname(user, validate=False)))
		else:
			hosts.append(name)
	return hosts

@cache_decorator
def __expandIPv4Address(hosts):
	'''
	Expand the IP address range in the hosts list

	Args:
		hosts (list): A list of IP addresses or IP address ranges

	Returns:
		list: A list of expanded IP addresses
	'''
	expandedHosts = []
	expandedHost = []
	for host in hosts:
		host = host.replace('[','').replace(']','').strip()
		octets = host.split('.')
		expandedOctets = []
		for octet in octets:
			if '-' in octet:
				# Handle wildcards
				octetRange = octet.split('-')
				for i in range(len(octetRange)):
					if not octetRange[i] or octetRange[i] in __wildCharacters:
						if i == 0:
							octetRange[i] = '0'
						elif i == 1:
							octetRange[i] = '255'
				
				expandedOctets.append([str(i) for i in range(int(octetRange[0]),int(octetRange[1])+1)])
			elif octet in __wildCharacters:
				expandedOctets.append([str(i) for i in range(0,256)])
			else:
				expandedOctets.append([octet])
		# handle the first and last subnet addresses
		if '0' in expandedOctets[-1]:
			expandedOctets[-1].remove('0')
		if '255' in expandedOctets[-1]:
			expandedOctets[-1].remove('255')
		# Generate the expanded hosts
		for ip in list(product(expandedOctets[0],expandedOctets[1],expandedOctets[2],expandedOctets[3])):
			expandedHost.append('.'.join(ip))
	expandedHosts.extend(expandedHost)
	return expandedHosts

def _has_open_range(text):
	'''Whether a [] group of text holds a range with an end missing: node[1-], node[-3], rack[a-].'''
	for group in re.findall(r'\[(.*?)]', text):
		for part in group.split(','):
			range_start, dash, range_end = part.partition('-')
			if dash and not (range_start.strip() and range_end.strip()):
				return True
	return False

@cache_decorator 
def __expand_hostname(text, validate=True):# -> set:
	'''
	Expand the hostname range in the text.
	Will search the string for a range ( [] enclosed and non-enclosed number ranges).
	Will expand the range, validate them using validate_expand_hostname and return a list of expanded hostnames

	Args:
		text (str): The text to be expanded
		validate (bool, optional): Whether to validate the hostname. Defaults to True.

	Returns:
		set: A set of expanded hostnames

	Notes (intentional behavior):
		- Hex-looking ranges (both ends in hexdigits) expand with format(i, 'x'), so results
		  are lowercase hex (e.g. [A-C] → a,b,c). Prefer [10-12] for decimal when digits alone
		  would also match hexdigits.
		- Mixed alphanumeric ranges walk string.digits + string.ascii_letters in that order
		  (0-9 then A-Z then a-z), so [9-A] yields 9,A and [Z-a] yields Z then a — not a
		  contiguous Unicode range.
		- A range with an end missing (node[1-], node[-3], rack[a-]) makes the name invalid: it
		  is kept whole and unexpanded, so mssh reports it instead of guessing the other end.
	'''
	if _has_open_range(text):
		return set(__validate_expand_hostname(text)) if validate else {text}
	expandinghosts = [text]
	expandedhosts = set()
	# all valid alphanumeric characters
	alphanumeric = string.digits + string.ascii_letters
	while len(expandinghosts) > 0:
		hostname = expandinghosts.pop()
		match = re.search(r'\[(.*?)]', hostname)
		if not match:
			expandedhosts.update(__validate_expand_hostname(hostname) if validate else [hostname])
			continue
		group = match.group(1)
		parts = group.split(',')
		for part in parts:
			part = part.strip()
			if '-' in part:
				range_start, _, range_end = part.partition('-')
				range_start = range_start.strip()
				range_end = range_end.strip()
				if not range_start or not range_end:
					# an open range only an earlier expansion made (a[x,[]1-]): _has_open_range saw none
					expandedhosts.update(__validate_expand_hostname(hostname) if validate else [hostname])
					continue
				if range_start.isdigit() and range_end.isdigit():
					padding_length = min(len(range_start), len(range_end))
					format_str = "{:0" + str(padding_length) + "d}"
					for i in range(int(range_start), int(range_end) + 1):
						formatted_i = format_str.format(i)
						expandinghosts.append(hostname.replace(match.group(0), formatted_i, 1))
				elif all(c in string.hexdigits for c in range_start + range_end):
					for i in range(int(range_start, 16), int(range_end, 16) + 1):
						expandinghosts.append(hostname.replace(match.group(0), format(i, 'x'), 1))
				else:
					try:
						start_index = alphanumeric.index(range_start)
						end_index = alphanumeric.index(range_end)
						for i in range(start_index, end_index + 1):
							expandinghosts.append(hostname.replace(match.group(0), alphanumeric[i], 1))
					except ValueError:
						expandedhosts.update(__validate_expand_hostname(hostname) if validate else [hostname])
			else:
				expandinghosts.append(hostname.replace(match.group(0), part, 1))
	return expandedhosts

# four dot separated octet fields, each a number, a wildcard (x * ?) or a range of them, optionally in []
_IPV4_RANGE_RE = re.compile(r'^((((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?))?\]))(\.((((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|x|\*|\?)(-((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|x|\*|\?))?)|(\[((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|x|\*|\?)(-((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|x|\*|\?))?\]))){2}\.((((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])|x|\*|\?))?\]))$')

def _prefetch_ips(hostnames):
	'''
	Resolve the hostnames that need DNS in parallel, filling the getIP cache.

	Host validation looks names up one at a time, a big range of names that are not in
	/etc/hosts would otherwise wait for every DNS round trip (or resolver timeout) in turn.
	'''
	need_dns = []
	for hostname in hostnames:
		hostname = hostname.strip().strip('$')
		if hostname in _dns_cache or _local_hostname_source(hostname):
			continue
		need_dns.append(hostname)
	# the same name listed for several users is looked up once
	need_dns = list(dict.fromkeys(need_dns))
	if len(need_dns) > 1:
		if 'ssh' in _binPaths:
			# names DNS does not know are compared with this probe, run it once instead of in every worker
			_ssh_config_values(_SSH_CONFIG_PROBE_NAME)
		_run_in_threads(lambda hostname: getIP(hostname,local=False), need_dns)

def _run_in_threads(function, items, max_workers=32):
	'''
	Call function(item) for every item in up to max_workers threads, and wait for them.

	The threads are daemon threads: unlike a ThreadPoolExecutor's workers they are not waited
	for at exit, so the second Ctrl-C ("exiting immediately") does not wait for slow lookups.
	'''
	work = queue.Queue()
	for item in items:
		work.put(item)
	def worker():
		while True:
			try:
				item = work.get_nowait()
			except queue.Empty:
				return
			try:
				function(item)
			except Exception:
				pass
	threads = []
	for _ in range(min(max_workers, len(items))):
		thread = threading.Thread(target=worker, daemon=True)
		try:
			thread.start()
		except RuntimeError:
			# no more threads allowed (pids limit, ulimit -u): the running ones take the rest
			break
		threads.append(thread)
	if not threads:
		# one at a time, as before the parallel lookups
		worker()
	for thread in threads:
		# in slices, so the Ctrl-C handler gets to run
		while thread.is_alive():
			thread.join(0.1)

@cache_decorator
def __expand_hostnames(hosts) -> dict:
	'''
	Expand the hostnames in the hosts into a dictionary

	Args:
		hosts (list): A list of hostnames

	Returns:
		dict: A dictionary of expanded hostnames with key: hostname, value: resolved IP address
	'''
	expandedhosts = {}
	if isinstance(hosts, str):
		hosts = [hosts]
	names_to_resolve = []
	for host in hosts:
		host = host.strip()
		if '@' in host:
			host = host.split('@',1)[1].strip()
		if host and not _IPV4_RANGE_RE.match(host):
			names_to_resolve.extend(__expand_hostname(host, validate=False))
	_prefetch_ips(names_to_resolve)
	for host in hosts:
		host = host.strip()
		if not host:
			continue
		# we seperate the username from the hostname
		username = None
		if '@' in host:
			username, host = host.split('@',1)
			username = username.strip()
			host = host.strip()
		# first we check if the hostname is an range of IP addresses
		# If so, we expand the IP address range
		iplist = []
		if _IPV4_RANGE_RE.match(host):
			hostSetToAdd = sorted(__expandIPv4Address(frozenset([host])),key=ipaddress.IPv4Address)
			iplist = hostSetToAdd
		else:
			# validate the names expanded (and cached) for the prefetch instead of expanding again
			hostSetToAdd = sorted(set(itertools.chain.from_iterable(
				__validate_expand_hostname(name) for name in __expand_hostname(host, validate=False))))
			for host in hostSetToAdd:
				iplist.append(getIP(host,local=False))
		if username:
			# we expand the username
			username = sorted(__expand_hostname(username,validate=False))
			# we combine the username and hostname: the typed user replaces the one an alias member
			# is written with, as the command line wins over ssh config's User
			for user in username:
				[expandedhosts.update({f'{user}@{host.rpartition("@")[2]}':ip}) for host,ip in zip(hostSetToAdd,iplist)]
		else:
			[expandedhosts.update({host:ip}) for host,ip in zip(hostSetToAdd,iplist)]
	return expandedhosts

def expand_hostnames(hosts, hosts_only=False):
	'''
	Expand the hostnames in the hosts into a dictionary

	Args:
		hosts (list): A list of hostnames
		hosts_only (bool): Ignored, kept for callers of 6.32 to 6.38

	Returns:
		dict: A dictionary of expanded hostnames with key: hostname, value: resolved IP address
	'''
	if isinstance(hosts, str):
		hosts = [hosts]
	# change data type to frozenset if it is not hashable
	if not isinstance(hosts, frozenset):
		hosts = frozenset(hosts)
	return __expand_hostnames(hosts)

def expand_hostnames_local(hosts):
	'''
	Expand host strings without DNS or ssh config lookups.

	Ranges, IPv4 ranges and env / env file aliases (recursively, with _alias_members, as
	expand_hostnames does) are expanded. A name that is not an IP address, in the hosts file or
	an alias is kept as it is and also listed as unresolved: only DNS or the ssh config could
	confirm it. So is an alias met inside its own expansion, which there names a host.
	Nothing is printed and no failure is counted.

	Args:
		hosts (str or iterable): Host strings, each may hold several hosts separated by ","

	Returns:
		tuple: (expanded, unresolved), two lists in natural sort order. user@ prefixes are kept.
	'''
	if isinstance(hosts, str):
		hosts = [hosts]
	expanded = set()
	unresolved = set()
	for host in hosts:
		for user, name, source in _host_names_in(str(host)):
			if source in ('env', 'env_file'):
				members = _alias_members(name, source, user)
			else:
				members = [(user, name, source, None)]
			for member_user, member, member_source, _ in members:
				# a typed user replaces a member's own, as in expand_hostnames
				member_user = user or member_user
				full = '{}@{}'.format(member_user, member) if member_user else member
				expanded.add(full)
				if member_source is None:
					unresolved.add(full)
	return sorted(expanded, key=_natural_sort_key), sorted(unresolved, key=_natural_sort_key)

def compact_hostnames_local(names):
	'''
	Compact host names into range strings without DNS.

	Like compact_hostnames, but the result is checked by expanding the ranges only, so names
	are never resolved and nothing is printed. If the compacted form does not expand back to
	exactly the names, the names are returned unchanged.

	Args:
		names (iterable): Host names, no aliases or ranges

	Returns:
		list: Range strings (or names) in natural sort order
	'''
	host_set = frozenset(name.strip() for name in names if name and name.strip())
	if not host_set:
		return []
	compacted = __compact_hostnames(host_set)
	back = set()
	for text in compacted:
		back.update(__expand_hostname(text, validate=False))
	if back != host_set:
		return sorted(host_set, key=_natural_sort_key)
	return sorted(compacted, key=_natural_sort_key)

def _compact_shown(names):
	'''compact_hostnames_local of the hosts names stand for: pre_merge_hosts names a group as it compacts (node[1-3],gpu1).'''
	return compact_hostnames_local(member for name in names for part in name.split(',') for member in __expand_hostname(part, validate=False))

# environment variables host expansion looked up since the last refresh, with the value seen (None: unset)
_consulted_env = {}

def _consult_env(name):
	'''os.environ.get(name), remembering the value so the caches refresh when it changes.'''
	try:
		value = os.environ.get(name)
	except UnicodeEncodeError:
		# a name the locale cannot encode (Python 3.6 in the C locale) cannot be a variable either
		return None
	_consulted_env.setdefault(name, value)
	return value

__expansion_env_state = None
def _refresh_expansion_caches():
	'''
	Drop cached host expansions when anything they were computed from changed.

	Expanding a host name consults os.environ (unless _no_env) and the env files (subject to
	the ownership / permission check), and the results are cached by host string only.
	'''
	global __expansion_env_state
	env_file_signatures = []
	for env_file in (_env_files if _env_files else DEFAULT_ENV_FILES):
		try:
			st = os.stat(os.path.expanduser(os.path.expandvars(env_file)))
			env_file_signatures.append((env_file, st.st_mode, st.st_uid, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
		except OSError:
			env_file_signatures.append((env_file, None))
	state = (_no_env, tuple(env_file_signatures), frozenset(_explicit_env_files))
	# only the variables expansion looked up matter, not e.g. TERM set by the curses fallback
	env_changed = any(os.environ.get(name) != value for name, value in _consulted_env.items())
	if state != __expansion_env_state or env_changed:
		__expansion_env_state = state
		_consulted_env.clear()
		for cached_function in (readEnvFromFile, __validate_expand_hostname, __expand_hostname, __expand_hostnames):
			cached_function.cache_clear()


#%% ------------ Run Command Block ----------------
# bytes the reader treats specially
_READER_SPECIAL_BYTES = re.compile(rb'([\n\r\x08])')
# encodings in which a \n byte is always a character of its own and ends any character before it: lines
# decode as one text just as one at a time. Not e.g. utf-16, or utf-8-sig, which drops a BOM at the start
# of each text it decodes.
_READER_BULK_ENCODINGS = frozenset(('utf-8', 'ascii', 'iso8859-1'))

# One copy of each line that hosts print alike, which their lists share (see _share_lines): a fleet's
# package lists and configuration files took a copy per host. Every _SHARED_LINES_CHECK lines it checks
# that at least half of them were held already: an entry per distinct line costs more than it saves when
# most lines are distinct (logs). Two checks in a row finding fewer stop it for the run (the first lines
# of all are new, and with -m 1 the first host's)
_SHARED_LINES_CHECK = 100000
_shared_lines = {}
# a command's run switches sharing on (processRunOnHosts): run_command or start_run_on_hosts alone does not
_shared_lines_state = {'sharing': False, 'looked_up': 0, 'found': 0, 'failed_checks': 0}
_shared_lines_lock = threading.Lock()

def _reset_shared_lines(sharing=True):
	'''
	Let the shared lines go, and share from now on or not. A command's run starts sharing (unless it returns
	before its hosts end: its readers go on after it), and ends not: readers given up may still read.
	Free-threaded Python never shares: every reader using one dict made them wait for each other (200 hosts
	x 20,000 lines alike took 4.85 s instead of 0.58 s).
	'''
	gil = getattr(sys, '_is_gil_enabled', None)
	with _shared_lines_lock:
		_shared_lines.clear()
		_shared_lines_state.update(sharing=sharing and (gil is None or gil()), looked_up=0, found=0, failed_checks=0)

def _share_lines(lines):
	'''
	lines (a list), each replaced by the copy of it already held, if any; the others are held from now
	on. A line counts as found when the copy returned is another object: other readers' lines do not
	change that. Sharing runs only with the GIL, which may lose a count now and then, no line.
	'''
	state = _shared_lines_state
	if not state['sharing']:
		return lines
	shared = [_shared_lines.setdefault(line, line) for line in lines]
	# counted before it is added: the GIL may switch to another reader while the lines are compared
	found = len(lines) - sum(map(operator.is_, shared, lines))
	state['found'] += found
	state['looked_up'] += len(lines)
	if state['looked_up'] >= _SHARED_LINES_CHECK:
		_check_shared_lines()
	return shared

def _share_line(line):
	'''_share_lines for one line: the reader's line buffer (\\r progress, one line per read) gives one at a time.'''
	state = _shared_lines_state
	if not state['sharing']:
		return line
	shared = _shared_lines.setdefault(line, line)
	state['found'] += shared is not line
	state['looked_up'] += 1
	if state['looked_up'] >= _SHARED_LINES_CHECK:
		_check_shared_lines()
	return shared

def _check_shared_lines():
	'''A check (see _shared_lines): sharing stops after two in a row found fewer than half the lines held.'''
	state = _shared_lines_state
	with _shared_lines_lock:
		if state['looked_up'] < _SHARED_LINES_CHECK:
			# another reader checked meanwhile
			return
		state['failed_checks'] = state['failed_checks'] + 1 if state['found'] * 2 < state['looked_up'] else 0
		if state['failed_checks'] >= 2:
			state['sharing'] = False
			_shared_lines.clear()
		state['looked_up'] = state['found'] = 0

def __handle_reading_stream(stream,target, host,buffer:io.BytesIO):
	'''
	Read the stream and append the lines to the target list

	Output is read in chunks: \n ends a line, \r returns to the line start, backspace deletes the byte
	before. The lines that start and end in a chunk, with no \r (but in \r\n) or backspace, are decoded
	and added at once. This gives the same lines as reading one byte at a time.

	Args:
		stream (io.BufferedReader): The stream to be read
		target (list): The list to append the lines to
		host (Host): The host object
		buffer (io.BytesIO): The current partial line of this stream

	Returns:
		None
	'''
	try:
		bulk_encoding = codecs.lookup(_encoding).name in _READER_BULK_ENCODINGS
	except (LookupError, TypeError):
		# not an encoding (set_global_with_args takes args.encoding as it is): the decode fails as it did before
		bulk_encoding = False
	def add_line():
		line = _share_line(buffer.getvalue().decode(_encoding,errors='backslashreplace'))
		target.append(line)
		host.output.append(line)
		for line_buffer in (buffer, host.output_buffer):
			line_buffer.seek(0)
			line_buffer.truncate(0)
	def add_bytes(data):
		# split keeps the special bytes at the odd indexes
		for index, part in enumerate(_READER_SPECIAL_BYTES.split(data)):
			if index % 2 == 0:
				if part:
					buffer.write(part)
					host.output_buffer.write(part)
			elif part == b'\n':
				add_line()
			else:
				for line_buffer in (buffer, host.output_buffer):
					if part == b'\r':
						line_buffer.seek(0)
					elif line_buffer.tell() > 0:
						line_buffer.seek(line_buffer.tell() - 1)
						line_buffer.truncate()
	read = stream.read1 if hasattr(stream, 'read1') else stream.read
	try:
		while True:
			# read1 returns whatever arrived (up to the size) instead of waiting to fill it
			chunk = read(65536)
			if not chunk:
				break
			host.lastUpdateTime = time.monotonic()
			if bulk_encoding:
				if b'\r' in chunk:
					# \r\n ends a line just as \n does: the \r moves back to the line start, the line is taken whole
					chunk = chunk.replace(b'\r\n', b'\n')
				first_newline = chunk.find(b'\n')
				last_newline = chunk.rfind(b'\n')
				if first_newline < last_newline:
					# the line in the buffer ends at the first \n, the lines after it are whole in the chunk
					whole_lines = chunk[first_newline + 1:last_newline]
					if b'\r' not in whole_lines and b'\x08' not in whole_lines:
						add_bytes(chunk[:first_newline + 1])
						lines = _share_lines(whole_lines.decode(_encoding,errors='backslashreplace').split('\n'))
						target.extend(lines)
						host.output.extend(lines)
						chunk = chunk[last_newline + 1:]
			add_bytes(chunk)
	except ValueError:
		pass
	if buffer.tell() > 0:
		# if there is still some data in the buffer, we add it to the target
		add_line()

def _encode_typed_line(chars):
	'''The bytes a line typed in the TUI sends: bytes typed outside _encoding (surrogates) go out as typed.'''
	text = ''.join(chars)
	try:
		return text.encode(encoding=_encoding, errors='surrogateescape')
	except UnicodeEncodeError:
		return text.encode(encoding=_encoding, errors='backslashreplace')

def _typed_line_for_display(chars):
	'''A typed line as text to show: what _encode_typed_line sends, with bytes outside _encoding as \\xe9.'''
	return _encode_typed_line(chars).decode(encoding=_encoding, errors='backslashreplace')

def __handle_writing_stream(stream,stop_event,host,wake=None):
	'''
	Write the key presses to the stream

	Args:
		stream (io.BytesIO): The stream to be written to
		stop_event (threading.Event): The event to stop the thread
		host (Host): The host object
		wake (threading.Event, optional): Set to wake the thread: by its monitor once stop_event is set,
			and by _typed_lines_changed_notify

	Returns:
		None
	'''
	# __keyPressesIn is a list of lists. 
	# Each list is a list of characters to be sent to the stdin of the process at once. 
	# We do not send the last line as it may be incomplete.
	if wake is None:
		wake = threading.Event()
	sentInputPos = 0
	with _typed_line_waiters_lock:
		_typed_line_waiters.add(wake)
	try:
		while not stop_event.is_set() and host.interactive_stdin:
			if sentInputPos < len(__keyPressesIn) - 1 :
				stream.write(_encode_typed_line(__keyPressesIn[sentInputPos]))
				stream.flush()
				line = '> ' + _typed_line_for_display(__keyPressesIn[sentInputPos]).replace('\n', '↵')
				host.output.append(line)
				host.stdout.append(line)
				sentInputPos += 1
				host.lastUpdateTime = time.monotonic()
			else:
				# until a line is typed or the command stops (see _typed_line_waiters), looking again every second
				# for a change nobody announced. Cleared before looking: a wake set after it is not lost
				wake.wait(1)
				wake.clear()
	finally:
		with _typed_line_waiters_lock:
			_typed_line_waiters.discard(wake)
	if not stop_event.is_set():
		# the TUI ended while the command runs: send the lines already typed, then end of input
		try:
			while sentInputPos < len(__keyPressesIn) - 1:
				stream.write(_encode_typed_line(__keyPressesIn[sentInputPos]))
				sentInputPos += 1
			stream.flush()
		except Exception:
			pass
		try:
			stream.close()
		except Exception:
			pass
	if sentInputPos < len(__keyPressesIn) - 1 :
		eprint(f"Warning: {len(__keyPressesIn)-sentInputPos} lines of key presses are not sent before the process is terminated!")
	return sentInputPos

# once the command ended, at most a pipe's worth of its output is left to read (64 KiB by default, on Linux
# at most 1 MiB without root): a reader that takes in more than this since then reads a process the command
# left behind
_READER_MAX_BYTES_AFTER_EXIT = 4 * 1024 * 1024
# seconds in all a reader may wait for input after the command ended, before it is given up
_READER_WAIT_AFTER_EXIT = 1.0

def _pipe_has_input(fd):
	'''True when a read from fd returns at once: output or end of file is there.'''
	try:
		poller = select.poll()
		poller.register(fd, select.POLLIN)
		return bool(poller.poll(0))
	except Exception:
		return False

class _CommandPipe:
	'''
	One of the command's output pipes, as its reader thread reads it.

	A process the command left in the background can keep the pipe open after the command ended, and
	the reader would wait for it. This tells run_command when the reader waits for input, and lets it
	give the reader up: reads then return end of file. Where the pipe can be polled, the reader waits
	for input before it reads, so a reader given up while it waits takes in nothing more.

	The reader reads 64 KiB at a time with read1, which leaves nothing in the pipe object's own buffer,
	where polling would not see it.
	'''
	def __init__(self, pipe):
		self.pipe = pipe
		self._read = getattr(pipe, 'read1', None) or pipe.read
		self.lock = threading.Lock()
		self.waiting = False # waits for input (where polled: has not read anything yet)
		self.given_up = False
		self.bytes_read = 0
		self.fd = None
		self.poller = None
		try:
			self.fd = pipe.fileno()
			poller = select.poll()
			poller.register(self.fd, select.POLLIN)
			self.poller = poller
		except Exception:
			# no file descriptor (a stand-in in tests) or no poll (Windows): the reader just reads
			pass

	def read1(self, size):
		with self.lock:
			if self.given_up:
				return b''
			self.waiting = True
		try:
			if self.poller is not None:
				try:
					self.poller.poll()
				except OSError:
					pass # the read reports a closed pipe
				with self.lock:
					if self.given_up:
						return b''
					self.waiting = False
			data = self._read(size)
		finally:
			self.waiting = False
		self.bytes_read += len(data)
		return data

# seconds between a running command's checks for -t and Ctrl C (it is woken at once when its output ends)
_MONITOR_WAKE = 0.1

def _wait_for_readers(host, readers):
	'''
	Wait until the reader threads took in what the command wrote, now that it ended or was stopped.

	A reader busy with output is waited for however long it takes: once the command ended, at most a
	pipe's worth of output is left. A reader is given up when a process the command left in the
	background holds its pipe open: once it waited for input _READER_WAIT_AFTER_EXIT seconds in all, or
	took in more than _READER_MAX_BYTES_AFTER_EXIT bytes, more than the command can have left. Its
	unfinished last line is recorded; what that process writes later is not. After Ctrl C, the readers
	get _READER_WAIT_AFTER_EXIT seconds.

	Args:
		host (Host): The host object
		readers (list): (thread, _CommandPipe, target list, line buffer) for stdout and stderr

	Returns:
		bool: True when every reader read its pipe to the end
	'''
	bytes_at_exit = [pipe.bytes_read for _thread, pipe, _target, _buffer in readers]
	waited = [0.0] * len(readers)
	pending = list(range(len(readers)))
	all_read = True
	stop_at = None
	last = time.monotonic()
	while pending:
		readers[pending[0]][0].join(0.05)
		now = time.monotonic()
		elapsed, last = now - last, now
		if _emo and stop_at is None:
			stop_at = now + _READER_WAIT_AFTER_EXIT
		stopping = stop_at is not None and now >= stop_at
		for index in list(pending):
			thread, pipe, target, buffer = readers[index]
			if not thread.is_alive():
				pending.remove(index)
				continue
			with pipe.lock:
				# output or end of file that is there but not taken yet is not waiting: the thread is slow to wake
				idle = pipe.waiting and (pipe.poller is None or not _pipe_has_input(pipe.fd))
				if idle:
					waited[index] += elapsed
				if not pipe.given_up and (stopping or waited[index] >= _READER_WAIT_AFTER_EXIT
						or pipe.bytes_read - bytes_at_exit[index] > _READER_MAX_BYTES_AFTER_EXIT):
					pipe.given_up = True
					all_read = False
				# done with a reader given up while it waits; one given up while busy ends at its next read,
				# after the output in hand
				if pipe.given_up and (idle or stopping):
					if idle and pipe.poller is not None:
						# it waits for input it will not take: record its unfinished last line for it
						__handle_reading_stream(io.BytesIO(), target, host, buffer)
					pending.remove(index)
	return all_read

def _emfile_backoff_seconds(attempt):
	# 0.1, 0.2, 0.4, 0.8, then 1 s; the exponent stops growing, as waiting for processes or threads has no attempt limit
	return min(0.1 * (2 ** min(attempt, 4)), 1.0)

def _start_waiting_thread(function):
	'''
	Start a daemon thread that calls function(*args) once it is given args.

	Returns:
		tuple: (thread, give): give(args) hands the thread its arguments, give(None) ends it without the call
	'''
	given = queue.Queue()
	def run():
		args = given.get()
		if args is not None:
			function(*args)
	thread = threading.Thread(target=run, daemon=True)
	thread.start()
	return thread, given.put

# How many times a host is tried again when the server dropped ssh's connection before login. sshd does
# that past MaxStartups (default 10:30:100: connections not logged in yet), which a ProxyJump bastion
# meets as soon as mssh opens more than 10 connections through it at once.
_LOGIN_DROP_RETRIES = 3

def _login_drop_backoff_seconds(retry):
	'''
	Seconds to wait before the retry-th try (1, 2, ...) of a host dropped before login: random, so the
	hosts dropped together come back spread out, and longer each time (0.2 to 1 s, then up to 2 s, 3 s).
	'''
	return random.uniform(0.2, 1.0) * retry

# ssh's own lines when the server closed or reset its connection before login. The banner exchange is
# the very first step. "Connection closed by ADDRESS port PORT" is an end of file met while connecting
# or logging in (once logged in, ssh says "Connection to HOST closed by remote host."), naming the
# address ssh connected to, or UNKNOWN port 65535 through a ProxyJump / ProxyCommand. A reset reads the
# same before and after login: only the banner exchange line before it tells.
_SSH_BANNER_DROP = re.compile(r'(?:kex|ssh)_exchange_identification: (read: Connection reset by peer|Connection closed by remote host)')
_SSH_CONNECTION_DROP = re.compile(r'Connection (closed|reset) by \S+ port \d+')
_SSH_RESET_BANNER = 'read: Connection reset by peer'
# what scp and rsync print when the ssh they run was dropped. scp's legacy protocol (before OpenSSH 9.0,
# and scp -O) exits with 1; rsync with ssh's 255, or with 12 when it notices the closed stream first
_COPY_TOOL_DROP_LINES = {
	'scp': re.compile(r'(?:\S*/)?scp: Connection closed|lost connection'),
	'rsync': re.compile(r'rsync: connection unexpectedly closed \((\d+) bytes received so far\) \[\w+\]'
		r'|rsync error: (?:unexplained error \(code 255\)|error in rsync protocol data stream \(code 12\)) at io\.c\(\d+\) \[\w+=[^\]]*\]'),
}
_LOGIN_DROP_RETURN_CODES = {'ssh': (255,), 'scp': (255, 1), 'rsync': (255, 12)}

_LoginDrop = namedtuple('_LoginDrop', ['banners', 'drops', 'nothing_received'])
_LoginDrop.__doc__ = '''
A run that ended with the server dropping ssh's connection before login, from _login_drop.

banners holds each banner exchange line's reason ('read: Connection reset by peer' or 'Connection
closed by remote host'); drops 'closed' or 'reset' for each "Connection closed / reset by" line, in
order; nothing_received is True when rsync said it received 0 bytes.
'''

def _login_drop(returncode, stdout, stderr, tool):
	'''
	Read a finished run as one whose connection the server dropped before login.

	It exited with ssh's 255 (or scp's 1, rsync's 12), printed nothing on stdout, and every stderr line
	is ssh's report of the dropped connection (or scp's / rsync's of the ssh they ran).

	Args:
		returncode (int): The run's exit code
		stdout (list): The run's stdout lines
		stderr (list): The run's stderr lines, before ERROR_MESSAGES_TO_IGNORE removed any
		tool (str): 'ssh', 'scp' or 'rsync', the program mssh ran

	Returns:
		_LoginDrop: What the lines say, or None when the run is anything else
	'''
	if returncode not in _LOGIN_DROP_RETURN_CODES.get(tool, ()) or any(line.strip() for line in stdout):
		return None
	tool_lines = _COPY_TOOL_DROP_LINES.get(tool)
	banners = []
	drops = []
	nothing_received = False
	for line in stderr:
		line = line.strip()
		if not line:
			continue
		match = _SSH_BANNER_DROP.fullmatch(line)
		if match:
			banners.append(match.group(1))
			continue
		match = _SSH_CONNECTION_DROP.fullmatch(line)
		if match:
			drops.append(match.group(1))
			continue
		match = tool_lines.fullmatch(line) if tool_lines else None
		if not match:
			return None
		if tool == 'rsync' and match.group(1) == '0':
			nothing_received = True
	if not banners and not drops:
		return None
	return _LoginDrop(banners, drops, nothing_received)

def _shows_dropped_login(drop):
	'''Whether a _login_drop result shows the connection ended before login: a lone reset can come later too.'''
	return bool(drop) and (bool(drop.banners) or 'closed' in drop.drops)

def _dropped_login_hint(count, max_connections):
	'''
	The hint for a run whose failed hosts include count hosts the server dropped before login.

	Args:
		count (int): How many hosts
		max_connections (int): The -m given, 0 or negative for the limits derived from it
	'''
	if isinstance(max_connections, int) and 0 < max_connections <= 10:
		cure = 'try a lower -m'
	else:
		cure = 'try fewer at once, e.g. -m 10'
	return ("Hint: the server dropped {} before login: sshd's MaxStartups (default 10:30:100), on the hosts "
		"or a ProxyJump bastion, turns away connections opened at once; {}".format(
		'1 connection' if count == 1 else '{} connections'.format(count), cure))

def _login_drop_is_safe_to_retry(drop, tool):
	'''
	Whether a run dropped before login (_login_drop) can run again without running anything on the
	host twice: a reset reads the same before and after login, only the banner exchange line before it
	tells. An ssh the remote command ran, turned away before login after the command printed nothing,
	reads the same as mssh's own: the command runs again. rsync is when it received nothing: running it
	again only syncs again.
	'''
	if tool == 'rsync':
		return drop.nothing_received and _shows_dropped_login(drop)
	if 'reset' in drop.drops and _SSH_RESET_BANNER not in drop.banners:
		return False
	return _shows_dropped_login(drop)

def _note(host, line):
	'''A line for the host's output, and its stderr with --debug.'''
	host.output.append(line)
	if __DEBUG_MODE:
		host.stderr.append(line)

def _report(host, line):
	'''A line for the host's output and its stderr.'''
	host.output.append(line)
	host.stderr.append(line)

def _record_host_exception(host, exc):
	'''Record an exception raised while running the host's command as a failure. Call from an except block.'''
	import traceback
	host.stderr.extend(str(exc).split('\n'))
	host.output.extend(str(exc).split('\n'))
	host.stderr.extend(traceback.format_exc().split('\n'))
	host.output.extend(traceback.format_exc().split('\n'))
	host.returncode = -1

def _stopped_command_note(formatedCMD):
	'''
	What mssh stopped when it stopped formatedCMD (-t, Ctrl C), and what that leaves behind.

	Only the local program ends: a command ssh runs on a host gets no signal (it has no terminal), it
	runs on until it ends, or until it writes to the closed connection.
	'''
	# the program under sshpass, also in --copy_id's sh -c line
	name = _sshpass_program(formatedCMD)
	if not name:
		program = str(formatedCMD[0]) if formatedCMD else ''
		# known by the path mssh found it at (ssh.EXE on Windows)
		name = next((known for known in ('ssh', 'rsync', 'scp') if program == _binPaths.get(known)), os.path.basename(program))
	if name == 'ssh':
		return 'ssh was stopped: the command may still run on the host'
	if name in ('rsync', 'scp'):
		return f'{name} was stopped: the copy may be incomplete'
	if name == 'ssh-copy-id':
		# after its clean-up it may say all keys were skipped as already there
		return 'ssh-copy-id was stopped: the key may not be installed'
	return f'{name} was stopped'

def _ipmi_failure_should_wait(host, line_starts=(0, 0, 0)):
	'''Return True when the next IPMI password should wait out retry_lockout_time.

	The wait protects a controller that actually rejected a login. Timeouts, routing
	failures, and a socket that never opened did not reach a BMC, so they skip it.
	An unrecognized BMC error still waits.

	line_starts holds where the failed attempt's lines begin in host.output, host.stdout
	and host.stderr, so messages left over from earlier attempts are not considered.
	'''
	chunks = []
	for attr, start in zip(('output', 'stdout', 'stderr'), line_starts):
		value = getattr(host, attr, None) or []
		chunks.extend(str(line) for line in value[start:])
	text = '\n'.join(chunks).lower()
	auth_markers = (
		'insufficient resources',
		'rakp',
		'unauthorized',
		'authentication failed',
		'invalid password',
		'invalid user',
		'bad password',
		'account locked',
		'user locked',
		'session limit',
		'privilege level',
	)
	if any(marker in text for marker in auth_markers):
		return True
	no_contact_markers = (
		'could not open socket',
		'no route to host',
		'network is unreachable',
		'connection timed out',
		'connection refused',
		'host is down',
		'destination host unreachable',
		'name or service not known',
		'could not resolve',
		'permission denied',
		'unable to establish lan session',
		'unable to establish ipmi v1.5',
		'timeout!',
	)
	if any(marker in text for marker in no_contact_markers):
		return False
	return getattr(host, 'returncode', None) != 124

# how a host without rsync answers: its shell's "not found" (bash and tcsh, dash / busybox / ksh, zsh,
# fish, mksh, a missing --rsync-path, Windows cmd and PowerShell), or rsync's words for exit code 127
_RSYNC_MISSING_MARKERS = (
	'rsync: command not found',
	'rsync: not found',
	'command not found: rsync',
	'unknown command: rsync',
	'rsync: inaccessible or not found',
	'rsync: no such file or directory',
	"'rsync' is not recognized",
	'remote command not found',
)
# how an rsync turns down its command line before copying anything: rsync's popt (macOS's 2.6.9 has
# neither -X nor --info), openrsync's getopt, and rsync's own words for exit code 1
_RSYNC_OPTION_MARKERS = (
	'unknown option',
	'unrecognized option',
	'illegal option',
	'invalid option',
	'syntax or usage error',
)

def _rsync_failure_scp_reason(host, line_starts=(0, 0, 0)):
	'''Return why a failed rsync is worth retrying with scp, or None when rsync's result stands.

	scp helps only when rsync copied nothing: the host has no rsync (127, or its shell's "not found",
	which rsync reports as 12), an rsync here or there turned down mssh's options (1 or 2, e.g. an
	rsync older than 3.1), ssh failed (rsync exits 255), or the host never answered rsync ("0 bytes
	received so far": rsync's own words, which are not translated, unlike the shell's).
	Any other failure is rsync's verdict on a copy it made (23 partial transfer, 24 files vanished,
	a connection lost midway, ...), and scp would copy everything again.

	line_starts holds where the failed attempt's lines begin in host.output, host.stdout
	and host.stderr, so messages left over from earlier attempts are not considered.
	'''
	text = '\n'.join(str(line) for line in host.stderr[line_starts[2]:]).lower()
	if host.returncode == 127 or any(marker in text for marker in _RSYNC_MISSING_MARKERS):
		return 'Rsync is not available on the host!'
	if host.returncode in (1, 2) and any(marker in text for marker in _RSYNC_OPTION_MARKERS):
		return 'Rsync turned down its options!'
	if host.returncode == 255:
		return 'Rsync connection failed!'
	if '(0 bytes received so far)' in text:
		return 'Rsync could not start on the host!'
	return None

def _rsync_xattr_error(host, line_starts=(0, 0, 0)):
	'''Return the failed attempt's first complaint about extended attributes, or None.'''
	for line in host.stderr[line_starts[2]:]:
		if 'xattr' in str(line).lower():
			return str(line).strip()
	return None

def _scp_sources_like_rsync(files, destination):
	'''
	Return (sources, destination) that make scp lay the local files out as rsync does.

	rsync copies only the contents of a directory given with a trailing slash, scp copies the
	directory itself (destination/name). Such a directory is replaced by its entries, hidden ones
	too. A lone directory, or the one entry left, is aimed at destination/. : scp then copies it into
	the destination directory, or fails when there is none, where it would create the destination
	as a copy of it (rsync creates the destination directory and copies into it).

	Raises OSError when a directory cannot be listed.
	'''
	sources = []
	from_directory = False
	for path in files:
		if path.endswith(('/', os.sep)) and os.path.isdir(path):
			from_directory = True
			sources.extend(os.path.join(path, name) for name in sorted(os.listdir(path)))
		else:
			sources.append(path)
	if len(sources) == 1 and (from_directory or os.path.isdir(sources[0])) and destination.rstrip('/'):
		destination = destination.rstrip('/') + '/.'
	return sources, destination

def _rsync_link_sources(files):
	'''
	Return (copy_links, kept) for the local sources of an rsync copy that are symbolic links.

	A source that is a link to a file is meant as that file (as cp and scp read it), but rsync -l
	copies the link, which points elsewhere or nowhere on the host. copy_links is True when rsync
	should copy what the links point to (--copy-links): some source is a link to a file and no
	source is a directory, whose links --copy-links would follow too (rsync then reports a link that
	points nowhere, as scp does). Otherwise kept holds (source, link target, why) for each link
	rsync copies as a link, why being a key of _KEPT_LINK_WARNINGS: one to a directory, one that
	points nowhere, and one copied together with a directory.
	'''
	links = []
	with_directory = False
	for path in files:
		# a trailing slash makes the system follow a link: the source is the directory's contents
		is_link = not path.endswith(('/', os.sep)) and os.path.islink(path)
		is_directory = os.path.isdir(path)
		with_directory = with_directory or is_directory
		if is_link:
			links.append((path, is_directory, os.path.exists(path)))
	copy_links = not with_directory and any(exists for _, _, exists in links)
	kept = []
	for path, is_directory, exists in links:
		if copy_links:
			break
		try:
			target = os.readlink(path)
		except OSError:
			target = '?'
		kept.append((path, target, 'directory' if is_directory else 'nothing' if not exists else 'with_directory'))
	return copy_links, kept

# the ssh options that take a value (ssh(1)): a word after one of them is its value, not an option
_SSH_OPTIONS_WITH_VALUE = frozenset('BbcDEeFIiJLlmOoPpQRSWw')
# those -ea gives ssh in a copy over rsync. rsync has most of these letters as options without one (-o
# owner, -p perms, -i itemize, ...) and took the value for a file to copy; -e and -B take a value in
# rsync as well and stay rsync's
_SSH_OPTIONS_FOR_RSYNC = _SSH_OPTIONS_WITH_VALUE - frozenset('Be')

def _ssh_options_in(words):
	'''
	Split -ea's words into (ssh's options, the rest) for a copy that rsync runs over ssh.

	An option is ssh's when it takes a value in ssh and its value follows as the next word, one
	that does not start with -, or is attached as -oName=value or -pPORT: rsync has no such forms.
	rsync read "-o ConnectTimeout=5" as --owner and a file to copy named ConnectTimeout=5, and
	"-i ~/.ssh/id_ed25519" as --itemize-changes and the private key, which it copied to the hosts.
	'''
	ssh_words, rest = [], []
	i = 0
	while i < len(words):
		word = str(words[i])
		letter = word[1:2] if word.startswith('-') and not word.startswith('--') else ''
		if letter in _SSH_OPTIONS_FOR_RSYNC and len(word) == 2 and i + 1 < len(words) and not str(words[i + 1]).startswith('-'):
			ssh_words += [word, str(words[i + 1])]
			i += 2
			continue
		if (letter == 'o' and '=' in word) or (letter == 'p' and word[2:].isdigit()):
			ssh_words.append(word)
		else:
			rest.append(word)
		i += 1
	return ssh_words, rest

def _scp_port_option(words):
	'''Return -ea's words for scp: ssh's -p PORT becomes -P PORT (scp's -p keeps file times).'''
	out = []
	i = 0
	while i < len(words):
		word = str(words[i])
		if word == '-p' and i + 1 < len(words) and str(words[i + 1]).isdigit():
			out += ['-P', str(words[i + 1])]
			i += 2
			continue
		out.append('-P' + word[2:] if word.startswith('-p') and word[2:].isdigit() else word)
		i += 1
	return out

# what a POSIX shell reads specially in a word, glob characters and a leading ~ aside
_SHELL_SPECIAL_CHARACTERS = frozenset(' \t\'"\\$`;&|<>()#!')
_GLOB_CHARACTERS = frozenset('*?[]{}')

def _scp_shell_quoted(path, keep_globs):
	'''
	Return a remote path for scp with a backslash before each character a shell reads specially.

	scp's legacy protocol (OpenSSH before 9.0, or scp -O) hands remote paths to the host's shell,
	which split '/tmp/dst y/' in two ("scp: ambiguous target"). keep_globs leaves glob characters
	active, for a source: the legacy protocol's shell expands them, and the SFTP protocol reads a
	source as a glob in which a backslash quotes the next character, so a quoted source serves
	both protocols. A leading ~ stays the home directory.
	'''
	special = _SHELL_SPECIAL_CHARACTERS if keep_globs else _SHELL_SPECIAL_CHARACTERS | _GLOB_CHARACTERS
	return ''.join('\\' + char if char in special else char for char in path)

_scp_protocol_cache = {}
_scp_protocol_lock = threading.Lock()

def _scp_uses_remote_shell(scp_argv):
	'''
	Return True when scp, run with these options, hands remote paths to the host's shell: its legacy
	protocol, the default before OpenSSH 9.0 or with -O. The SFTP protocol takes a destination as
	written. The OpenSSH version alone does not tell: -O and -s choose, and distributions may
	backport the SFTP default (RHEL 9's 8.7 is said to).

	scp -v names the protocol it starts before it connects ("command scp -t" or "command sftp");
	with a stand-in for ssh that exits at once, nothing is connected to. Asked once per command
	line; False when scp names neither.
	'''
	key = tuple(scp_argv)
	with _scp_protocol_lock:
		if key not in _scp_protocol_cache:
			legacy = False
			stand_in = shutil.which('false') or shutil.which('true')
			if stand_in:
				try:
					ran = subprocess.run(list(scp_argv) + ['-v', '-S', stand_in, '--', os.devnull, 'mssh-scp-protocol.invalid:/'],
						stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
					legacy = b', command scp ' in ran.stderr
				except Exception:
					legacy = False
			_scp_protocol_cache[key] = legacy
		return _scp_protocol_cache[key]

_KEPT_LINK_WARNINGS = {
	'directory': '{path} is a symbolic link to a directory, rsync copies the link (-> {target}), not the directory.',
	'nothing': '{path} is a symbolic link to nothing here, rsync copies the link (-> {target}).',
	'with_directory': '{path} is a symbolic link, rsync copies the link (-> {target}), not the file, as a directory is copied with it. Copy the link on its own to copy the file.',
}

def _gather_copy_paths(host):
	'''
	Return (source, local path of its copy) for each source of a gather that rsync copies to one
	path of its own, worked out before rsync runs.

	A source goes into the destination directory under its name, or becomes the destination when
	it is alone and the destination is no directory. Left out: a source with a trailing slash (its
	contents) or a glob, and every source when the destination is a symbolic link, which rsync
	follows: copying again there with --copy-links could write anywhere it points.
	'''
	destination = host.command
	if not destination or os.path.islink(destination.rstrip('/' + os.sep) or destination):
		return []
	into_directory = len(host.files) > 1 or destination.endswith(('/', os.sep)) or os.path.isdir(destination)
	copies = []
	for source in host.files:
		name = source.rsplit('/', 1)[-1]
		if name in ('', '.', '..') or glob.has_magic(source):
			continue
		copies.append((source, os.path.join(destination, name) if into_directory else destination))
	return copies

def _put_back_gathered_links(host, links):
	'''
	Put back, as the link rsync copied first, each gathered (source, copy, link target) that the copy
	with --copy-links --no-recursive did not replace: a link to a directory, which it skips, or a link
	it could not follow. A warning on host.stderr says which.
	'''
	for source, copy, target in links:
		if os.path.lexists(copy):
			continue
		try:
			os.symlink(target, copy)
		except OSError:
			continue
		if any(str(line).strip() == 'skipping directory ' + source.rsplit('/', 1)[-1] for line in host.stdout):
			host.stderr.append(f'Warning: {source} is a symbolic link to a directory on the host, copied as the link (-> {target}).')
		else:
			host.stderr.append(f'Warning: {source} is a symbolic link on the host (-> {target}), copying what it points to failed: copied as the link.')

# bytes the entries of a dir/ may take on scp's command line: half of Linux's usual 2 MiB argument
# limit (macOS has 1 MiB), the environment and the rest of the command line need their share
_SCP_ARGV_BUDGET = 1 << 20

def _scp_cannot_copy_like_rsync(host):
	'''Return why scp cannot copy host.files as rsync would have, or None when it can.'''
	if host.gatherMode:
		# a remote dir/ cannot be listed from here; scp copies it whole, which is only its contents
		# when scp creates the local destination as that copy
		for path in host.files:
			if path.endswith('/') and (len(host.files) > 1 or os.path.lexists(host.command)):
				return f'it would copy {path} whole into {host.command}, rsync copies only its contents (trailing slash).'
		return None
	try:
		sources, _ = _scp_sources_like_rsync(host.files, host.command)
	except OSError as e:
		return f'cannot list the directory to copy: {e}'
	if not sources:
		return f'{" ".join(host.files)} is empty, it has nothing to copy.'
	# each argument also takes a pointer and its terminating NUL
	if sum(len(os.fsencode(path)) + 9 for path in sources) > _SCP_ARGV_BUDGET:
		directories = ' '.join(path for path in host.files if path.endswith(('/', os.sep)))
		return f'it would have to list the {len(sources)} entries of {directories} on its command line, more than a command line holds.'
	return None

# the fields that make up one IPMI attempt: definitions equal in these are the same login
_IPMI_ATTEMPT_KEYS = ('ipmi_method', 'interface_ip_prefix', 'username', 'password', 'args')

def _ipmi_default_definitions():
	'''
	Return (the DEFAULT_IPMI_* definition with the command line's IPMI options, the definitions that stand for it).

	A definition in DEFAULT_IPMI_DEFINITIONS with every key equal to the built-in values or to the
	DEFAULT_IPMI_* ones is what mssh itself puts there (the list it starts with, --generate_config_file,
	--store_config_file): it marks where the DEFAULT_IPMI_* definition goes, it is not a login of its own.
	'''
	configured = get_default_ipmi_definition()
	default = dict(configured)
	default.update(_ipmi_command_line)
	return default, (_BUILTIN_IPMI_DEFINITION, configured, default)

def _ipmi_definitions_for_host(hostname):
	'''
	The IPMI definitions to try on a host, in order, with every key filled in.

	The DEFAULT_IPMI_DEFINITIONS whose hostname_keyword is in hostname (keys they leave out come from
	the DEFAULT_IPMI_* values, as the command line's IPMI options change them), and the DEFAULT_IPMI_*
	definition itself: first when the command line gives IPMI options, else where the list marks it,
	else last. Every wrong login can count towards the BMC locking the account, so:
	- when a listed definition applies to the host, the DEFAULT_IPMI_* one is only added with -iu / -ip,
	  or when DEFAULT_IPMI_PASSWORD was set (by a config file, or to something else than the built-in
	  one) and the login is not admin / admin (mssh writes the built-in login into the config files it
	  makes): else nobody gave it as a login
	- a login is tried once, however many definitions hold it

	Args:
		hostname (str): The host's name as given (hostname_keyword is looked for in it)

	Returns:
		list: The definitions (dicts), first to try first
	'''
	default, marks = _ipmi_default_definitions()
	listed = []
	default_at = None
	for definition in DEFAULT_IPMI_DEFINITIONS:
		if definition in marks:
			if default_at is None:
				default_at = len(listed)
			continue
		keyword = definition.get('hostname_keyword')
		if keyword and str(keyword).strip() not in hostname:
			continue
		listed.append(dict(ChainMap(definition, default)))
	login_given = 'username' in _ipmi_command_line or 'password' in _ipmi_command_line
	builtin_login = all(str(default.get(key)) == str(_BUILTIN_IPMI_DEFINITION[key]) for key in ('username', 'password'))
	# a password configured as 'admin' is still a login of the user's (root / admin on some boards);
	# one that is not 'admin' was set by someone (a config file, or a program importing mssh)
	password_configured = 'DEFAULT_IPMI_PASSWORD' in __configs_from_file or str(default.get('password')) != str(_BUILTIN_IPMI_DEFINITION['password'])
	login_configured = password_configured and not builtin_login
	if listed and not login_given and not login_configured:
		candidates = listed
	elif _ipmi_command_line:
		candidates = [default] + listed
	elif default_at is not None:
		candidates = listed[:default_at] + [default] + listed[default_at:]
	else:
		candidates = listed + [default]
	definitions = []
	logins = set()
	for definition in candidates:
		login = tuple(str(definition.get(key)) for key in _IPMI_ATTEMPT_KEYS)
		if login not in logins:
			logins.add(login)
			definitions.append(definition)
	return definitions

def _ipmi_definitions_to_store(args):
	'''
	DEFAULT_IPMI_DEFINITIONS for a config file that stores args' IPMI options as the DEFAULT_IPMI_* values.

	The list as loaded, with the definition of the stored values marking where it is tried: first
	when the command line gives IPMI options (as in this run), else where the list marked it. mssh
	6.31 and earlier add that definition again unless the list ends with it.
	'''
	stored = {
		'interface_ip_prefix': args.ipmi_interface_ip_prefix,
		'username': args.ipmi_username,
		'password': args.ipmi_password,
		'args': args.ipmi_args,
		'ipmi_method': args.ipmi_method,
		'hostname_keyword': '',
		'retry_lockout_time': args.ipmi_retry_lockout_time,
	}
	marks = _ipmi_default_definitions()[1] + (stored,)
	definitions = [stored] if _ipmi_command_line else []
	for definition in DEFAULT_IPMI_DEFINITIONS:
		if definition not in marks:
			definitions.append(definition)
		elif stored not in definitions:
			definitions.append(stored)
	return definitions

class _CommandLine(list):
	'''
	A command's argv, with env: the variables its process gets on top of mssh's environment.

	They carry the passwords sshpass -e and ipmitool -E read: ps shows every process's command line
	to every user of the machine, its environment only to the same user and root.
	'''
	def __init__(self, argv, env=None):
		super().__init__(argv)
		self.env = dict(env or {})

def _sshpass_command(argv, password):
	'''argv run under sshpass, which reads the password from SSHPASS.'''
	return _CommandLine([_binPaths['sshpass'], '-e'] + list(argv), {'SSHPASS': str(password)})

def _ipmitool_password_env(password):
	'''The environment that gives ipmitool -E the password: 1.8.19 and later read IPMITOOL_PASSWORD first.'''
	return {'IPMI_PASSWORD': str(password), 'IPMITOOL_PASSWORD': str(password)}

_CommandAttempt = namedtuple('_CommandAttempt', ['action', 'argv', 'ipmi_definition', 'username', 'passwds', 'useScp', 'ipmi_definitions_list'])
_CommandAttempt.__doc__ = '''
What _build_command decided for one attempt.

action is 'run' (run argv), 'rebuild' (build again right away, e.g. ipmitool is missing so the
next attempt uses ssh_ipmitool) or 'stop' (host.returncode is set). The other fields carry the
attempt's state into the retry decisions and the next attempt.
'''

def _split_extra_args(text):
	'''
	Split the -ea string into arguments as a shell would: -ea "-o ProxyCommand='ssh -W %h:%p bastion'"
	is two arguments. On Windows a backslash is a path separator, not an escape: C:\\keys\\id stays.
	An unclosed quote splits on spaces, as before quotes were understood.
	'''
	lexer = shlex.shlex(text, posix=True)
	lexer.whitespace_split = True
	lexer.commenters = ''
	if os.name == 'nt':
		lexer.escape = ''
	try:
		return list(lexer)
	except ValueError:
		return text.split()

def _build_command(host, passwds, ipmi_definitions_list, scp_like_rsync=False, rsync_xattrs=True, gather_links=None):
	'''
	Build the command line for one attempt to run host.command, without running it.

	Picks the IPMI definition (popped from ipmi_definitions_list), fills in the magic strings and
	formats the ipmitool / redfish / shell / scp / rsync / ssh command. Warnings and errors are
	recorded on the host.

	Args:
		host (Host): The host object
		passwds (str): The password for the host
		ipmi_definitions_list (list): The IPMI definitions left to try, ... for the matching defaults
		scp_like_rsync (bool): scp stands in for a failed rsync, so it copies what rsync would have
		rsync_xattrs (bool): rsync copies extended attributes (-X)
		gather_links (list): gather only these sources, links on the host, as what they point to

	Returns:
		_CommandAttempt: What to do next
	'''
	ipmi_definition =  {}
	username = None
	sshLocalExtraArgs = []
	ip_prefix = None
	useScp = False
	def attempt(action, argv=None):
		# carries the state as it is when the attempt is returned
		return _CommandAttempt(action, argv, ipmi_definition, username, passwds, useScp, ipmi_definitions_list)
	try:
		if not SSH_STRICT_HOST_KEY_CHECKING:
			sshLocalExtraArgs = ['-o StrictHostKeyChecking=no','-o UserKnownHostsFile=/dev/null']
		if _ssh_cannot_ask(host, passwds):
			# it would send the passwords it cannot ask for empty, each a failed login in the host's auth log (fail2ban)
			sshLocalExtraArgs += ['-o NumberOfPasswordPrompts=0']
		if host.identity_file and os.path.exists(os.path.expanduser(host.identity_file)):
			# log in with this key only: ssh offers every ssh-agent key before it, and sshd ends the login
			# after MaxAuthTries (6) failures. A key file that is not there leaves ssh the agent's keys
			sshLocalExtraArgs += ['-o','IdentitiesOnly=yes']
		if host.identity_file:
			sshLocalExtraArgs += ['-i',host.identity_file]
		# rsync splits --rsh on spaces and honours quotes: quoted, an identity path with a space stays one argument
		rsyncLocalExtraArgs = ['--rsh',' '.join(shlex.quote(arg) for arg in [_binPaths.get('ssh', 'ssh')] + sshLocalExtraArgs)]
		host.address = host.name
		if '@' in host.name:
			username, host.address = host.name.rsplit('@',1)
		if host.ipmi:
			if ipmi_definitions_list is ...:
				ipmi_definitions_list = _ipmi_definitions_for_host(host.name)
			if not ipmi_definitions_list:
				_report(host, 'Error: Exhausted all matching ipmi definitions!')
				host.returncode = 1
				return attempt('stop')
			ipmi_definition = dict(ChainMap(ipmi_definitions_list.pop(0),get_default_ipmi_definition()))
			if ipmi_definition.get('ipmi_method') == 'ssh_ipmitool':
				if not host.command:
					host.command = 'ipmitool power status'
				else:
					host.command = 'ipmitool '+host.command if not host.command.startswith('ipmitool ') else host.command
				if username:
					_note(host, f'Warning:-u SSH_USERNAME {username} is provided in the host name! Using the username from the ipmi definition if provided: {ipmi_definition.get("username")}')
				username = ipmi_definition.get('username',username)
				if passwds:
					# not the passwords themselves: the TUI shows this line
					_note(host, 'Warning: -p SSH_PASSWORD is provided! Using the password from the ipmi definition if provided.')
				passwds = ipmi_definition.get('password',passwds)
				if ipmi_definition.get('interface_ip_prefix') and ipmi_definition.get('interface_ip_prefix') == DEFAULT_IPMI_INTERFACE_IP_PREFIX:
					_note(host, 'Warning: ipmi_interface_ip_prefix that is the same as the DEFAULT_IPMI_INTERFACE_IP_PREFIX is ignored in ssh_ipmitool mode.')
			else:
				ip_prefix = ipmi_definition.get('interface_ip_prefix')
		host.command = replace_magic_strings(host.command,['#HOST#','#HOSTNAME#'],host.address,case_sensitive=False)
		if username:
			host.command = replace_magic_strings(host.command,['#USER#','#USERNAME#'],username,case_sensitive=False)
		else:
			current_user = getpass.getuser()
			host.command = replace_magic_strings(host.command,['#USER#','#USERNAME#'],current_user,case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#ID#'],str(id(host)),case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#I#'],str(host.i),case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#UUID#'],str(host.uuid),case_sensitive=False)
		# hosts reachable only through the ssh config have no local IP: use the address ssh connects to
		host.command = replace_magic_strings(host.command,['#IP#'],str(host.ip) if host.ip else host.address,case_sensitive=False)
		formatedCMD = []
		if host.extraargs and isinstance(host.extraargs, str):
			extraargs = _split_extra_args(host.extraargs)
		elif host.extraargs and isinstance(host.extraargs, list):
			extraargs = [str(arg) for arg in host.extraargs]
		else:
			extraargs = []
		if not ip_prefix:
			ip_prefix = host.interface_ip_prefix
		if ip_prefix:
			if _interface_prefix_applies(host.ip):
				hostOctets = str(host.ip).split('.')
				# '172.30.' means the same as '172.30', not an empty third octet
				prefixOctets = str(ip_prefix).rstrip('.').split('.')
				host.address = '.'.join(prefixOctets[:3]+hostOctets[min(3,len(prefixOctets)):])
			else:
				# run_command_on_hosts said so before the run too, outside the TUI
				warning = _interface_prefix_warning(ip_prefix, [host.name])
				_note(host, warning)
		if username:
			host.resolvedName = username + '@' + host.address
		else:
			host.resolvedName = host.address
		if host.resolvedName:
			host.command = replace_magic_strings(host.command,['#RESOLVEDNAME#','#RESOLVED#'],host.resolvedName,case_sensitive=False)
			if __DEBUG_MODE:
				host.stderr.append(f'Resolved name: {host.resolvedName}')
		if host.ipmi and ipmi_definition.get('ipmi_method') != 'ssh_ipmitool':
			#{interface_ip_prefix,username,password,args,ipmi_method,hostname_keyword,retry_lockout_time}
			if ipmi_definition.get('ipmi_method') == 'ipmitool':
				if 'ipmitool' not in _binPaths:
					_note(host, 'Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
					if ipmi_definition.get('interface_ip_prefix') == DEFAULT_IPMI_INTERFACE_IP_PREFIX:
						ipmi_definition['interface_ip_prefix'] = DEFAULT_INTERFACE_IP_PREFIX
					ipmi_definition['username'] = username
					ipmi_definition['password'] = passwds
					ipmi_definition['ipmi_method'] = 'ssh_ipmitool'
					ipmi_definitions_list.insert(0,ipmi_definition)
					return attempt('rebuild')
				if host.command.startswith('ipmitool '):
					host.command = host.command.replace('ipmitool ','')
				elif host.command.startswith(_binPaths['ipmitool']):
					host.command = host.command.replace(_binPaths['ipmitool'],'')
				if not host.command:
					host.command = 'power status'
				# Compatibility note: the unusual shell/direct IPMI argument forms may work around
				# ipmitool behavior on deployed machines. Verify on real IPMI hardware before changing.
				ipmi_args = ipmi_definition.get('args','')
				if 'sh' in _binPaths:
					# quote the credentials so the shell does not split or expand them, ipmi_args and the command stay raw on purpose
					formatedCMD = _CommandLine([_binPaths['sh'],'-c',f'ipmitool -H {shlex.quote(str(host.address))} -U {shlex.quote(str(ipmi_definition.get("username",username)))} -E {ipmi_args} {host.command}'],
						_ipmitool_password_env(ipmi_definition.get("password",passwds)))
				else:
					formatedCMD = _CommandLine([_binPaths['ipmitool'],f'-H {host.address}',f'-U {ipmi_definition.get("username",username)}','-E'] + [f'-{s}' for s in ipmi_args.split('-') if s] + [host.command],
						_ipmitool_password_env(ipmi_definition.get("password",passwds)))
			elif ipmi_definition.get('ipmi_method') == 'redfish':
				if 'redfishtool' not in _binPaths:
					# this definition cannot run on this machine: the next one may
					host.output.append('Error: redfishtool not found on the local machine!')
					if not ipmi_definitions_list:
						host.stderr.append('Error: redfishtool not found on the local machine!')
						host.returncode = 1
						return attempt('stop')
					host.output.append('Trying the next ipmi definition...')
					if __DEBUG_MODE:
						host.stderr.append('Error: redfishtool not found on the local machine! Trying the next ipmi definition...')
					return attempt('rebuild')
				if host.command.startswith('redfishtool '):
					host.command = host.command.replace('redfishtool ','')
				elif host.command.startswith(_binPaths['redfishtool']):
					host.command = host.command.replace(_binPaths['redfishtool'],'')
				if not host.command:
					host.command = 'Systems'
				ipmi_args = ipmi_definition.get('args','')
				if 'sh' in _binPaths:
					formatedCMD = [_binPaths['sh'],'-c',f'redfishtool -S Always -a -r {shlex.quote(str(host.address))} -u {shlex.quote(str(ipmi_definition.get("username",username)))} -p {shlex.quote(str(ipmi_definition.get("password",passwds)))} {ipmi_args} {host.command}']
				else:
					formatedCMD = [_binPaths['redfishtool'],'-S', 'Always','-a','-r',host.address,'-u',ipmi_definition.get("username",username),'-p',ipmi_definition.get("password",passwds)] + [f'-{s}' for s in ipmi_args.split('-') if s] + [host.command]
			else:
				_report(host, f'IPMI method {ipmi_definition.get("ipmi_method","None")} not supported!')
				host.returncode = 1
				return attempt('stop')
		elif host.shell:
			if 'sh' in _binPaths:
				_note(host, 'Running command in shell mode, ignoring the hosts...')
				shellCommand = host.command
				if passwds and 'sshpass' in _binPaths:
					# for the password prompts of the command (ssh-copy-id). Not in host.command: mssh shows that,
					# and replaces the magic strings in it
					shellCommand = f"{shlex.quote(_binPaths['sshpass'])} -e {shellCommand}"
					formatedCMD = _CommandLine([_binPaths['sh'],'-c',shellCommand], {'SSHPASS': str(passwds)})
				else:
					formatedCMD = [_binPaths['sh'],'-c',shellCommand]
			else:
				_note(host, 'shell not found on the local machine! Using ssh localhost instead...')
				host.shell = False
				host.name = 'localhost'
				return attempt('rebuild')
		else:
			# ssh, scp and rsync's ssh give up on a host that does not answer, or stops answering. They
			# come after -ea's options, which ssh takes first. An -o in -ea is ssh's for rsync too:
			# rsync's own -o takes no value
			timeoutOptions = _ssh_timeout_options()
			if host.files:
				if host.scp:
					if 'scp' in _binPaths:
						useScp = True
					elif 'rsync' in _binPaths:
						_note(host, 'scp not found on the local machine! Trying to use rsync...')
						useScp = False
					else:
						_report(host, 'scp not found on the local machine! Please install scp or rsync to use file sync mode.')
						host.returncode = 1
						return attempt('stop')
				elif 'rsync' in _binPaths:
					useScp = False
				elif 'scp' in _binPaths:
					_note(host, 'rsync not found on the local machine! Trying to use scp...')
					useScp = True
				else:
					_report(host, 'rsync not found on the local machine! Please install rsync or scp to use file sync mode.')
					host.returncode = 1
					return attempt('stop')
				# rsync and scp end the host at the first colon, an IPv6 address goes in brackets
				remoteName = host.resolvedName
				if ':' in host.address and not host.address.startswith('['):
					remoteName = f'{username}@[{host.address}]' if username else f'[{host.address}]'
				scpOptions = [_binPaths['scp'],'-rp'] + sshLocalExtraArgs + _scp_port_option(extraargs) + timeoutOptions if useScp else []
				if host.gatherMode:
					sources = gather_links or host.files
					if useScp:
						# a quoted source serves both of scp's protocols (see _scp_shell_quoted)
						sources = [_scp_shell_quoted(path, keep_globs=True) for path in sources]
					fileArgs = [f'{remoteName}:{file}' for file in sources] + [host.command]
				else:
					if useScp and scp_like_rsync:
						sources, destination = _scp_sources_like_rsync(host.files, host.command)
					else:
						sources, destination = host.files, host.command
					# a quoted destination only serves scp's legacy protocol, SFTP takes it as written
					if useScp and _scp_shell_quoted(destination, keep_globs=False) != destination and _scp_uses_remote_shell(scpOptions):
						destination = _scp_shell_quoted(destination, keep_globs=False)
					fileArgs = sources + [f'{remoteName}:{destination}']
				if useScp:
					formatedCMD = scpOptions +['--']+fileArgs
				else:
					# no --inplace: rsync writes a new file and renames it over the old one, so a running
					# binary can be replaced and no reader sees a file half written. A copy that is stopped
					# keeps its part in .rsync-partial/ for the next one to continue (--partial would rename
					# it over the destination, a truncated file in place of the old one)
					formatedCMD = [_binPaths['rsync'],'-ahlX' if rsync_xattrs else '-ahl','--partial-dir=.rsync-partial', '--info=name']
					# a source that is a link to a file is copied as that file: a gather finds out after
					# copying (see run_command), a push before (see _rsync_link_sources)
					if host.gatherMode:
						copy_links = bool(gather_links)
					else:
						copy_links = _rsync_link_sources(host.files)[0]
					if copy_links:
						formatedCMD.append('--copy-links')
					if gather_links:
						# a link to a directory is skipped, rather than its links followed (see run_command)
						formatedCMD.append('--no-recursive')
					# -ea's ssh options go to ssh, after mssh's own as for a command
					ssh_words, rsync_words = _ssh_options_in(extraargs)
					rsh = ' '.join([rsyncLocalExtraArgs[1]] + [shlex.quote(word) for word in ssh_words] + timeoutOptions)
					formatedCMD += ['--rsh', rsh] + rsync_words +['--']+fileArgs
			else:
				formatedCMD = [_binPaths['ssh']] + sshLocalExtraArgs + extraargs + timeoutOptions +['--']+ [host.resolvedName, host.command]
			if passwds and 'sshpass' in _binPaths:
				formatedCMD = _sshpass_command(formatedCMD, passwds)
			elif passwds:
				_note(host, 'Warning: sshpass is not available. Please install sshpass to use password authentication.')
				host.output.append('Please provide password via live input or use ssh key authentication.')
	except Exception as e:
		_report(host, f'Error occurred while formatting the command : {host.command}!')
		_record_host_exception(host, e)
		return attempt('stop')
	return attempt('run', formatedCMD)

def _interface_prefix_applies(ip):
	'''Whether an interface IP prefix (-pre, -mpre) can rewrite ip: it replaces the leading octets of IPv4 addresses.'''
	return bool(ip) and ':' not in str(ip)

def _interface_prefix_warning(prefix, names):
	'''The warning for hosts an interface IP prefix cannot apply to: mssh connects to them by name.'''
	return f"Warning: interface IP prefix {prefix} not applied to {','.join(compact_hostnames_local(names))}: no IPv4 address, connecting by name"

def _shown_command(argv, passwords=()):
	'''
	argv as the line the TUI and --debug show, each password in it shown as ***.

	A password is the word after -p or -P (sshpass, ipmitool, redfishtool, also inside the sh -c line
	they run in) that is one of passwords or a configured password. Other words stay, ssh's -p port too.
	'''
	known = list(passwords) + [DEFAULT_PASSWORD, DEFAULT_IPMI_PASSWORD]
	known += [definition.get('password') for definition in DEFAULT_IPMI_DEFINITIONS if isinstance(definition, dict)]
	# longest first, so a password inside another one does not leave the rest of that one
	secrets = sorted({str(password) for password in known if password is not None and str(password)}, key=len, reverse=True)
	words = [str(word) for word in argv]
	for index, word in enumerate(words):
		if index and words[index - 1] in ('-p', '-P') and word in secrets:
			words[index] = '***'
			continue
		# '-P password' as one argument, or inside an sh -c line, where it is shell-quoted
		for secret in secrets:
			for form in (shlex.quote(secret), secret):
				for flag in ('-p ', '-P '):
					word = word.replace(flag + form, flag + '***')
		words[index] = word
	return ' '.join(words)

def _cut_output(host, output_len, stdout_len=None, stderr_len=None):
	'''
	Drop the lines host's output, stdout and stderr got past these lengths (an attempt not run, a warning
	said again). The TUI may have drawn the output lines dropped: the lines added next take their
	places, so it draws those places again. Marked once they are gone: a frame between taking the marks
	and the deletion would count the old lines as drawn, and never draw the new ones in their places.
	'''
	dropped = range(output_len, len(host.output))
	del host.output[output_len:]
	host.lineNumToPrintSet.update(dropped)
	if stdout_len is not None:
		del host.stdout[stdout_len:]
	if stderr_len is not None:
		del host.stderr[stderr_len:]

def _execute_command(host, formatedCMD, sem, timeout, retry_limit, passwords=(), tool=None):
	'''
	Run one built command, retrying (within retry_limit) while too many files are open, or no process or
	thread can be started, and up to _LOGIN_DROP_RETRIES times when the server dropped ssh's connection
	before login. Waiting for processes or threads uses no retries while other commands run: they give
	theirs back when they end.

	Args:
		host (Host): The host object
		formatedCMD (list): The command line from _build_command
		sem (threading.Semaphore): The semaphore to limit the number of concurrent SSH sessions
		timeout (int): Seconds without output before the command is stopped, 0 for no limit
		retry_limit (int): Retries left
		passwords (tuple): The passwords in formatedCMD, shown as *** (configured ones are anyway)
		tool (str): 'ssh', 'scp' or 'rsync' when the command is mssh's own connection to the host,
			None for local and IPMI commands, which are never tried again for a dropped login

	Returns:
		tuple: (stop, retry_limit, attempt_line_starts). stop is True when the retries ran out
			and run_command must not try anything else.
	'''
	# where this attempt's lines start, earlier ipmi attempts must not affect the lockout decision
	attempt_line_starts = (len(host.output), len(host.stdout), len(host.stderr))
	emfile_attempt = 0
	retry_reason = None
	login_drop_retries = 0
	while True:
		previous_reason, retry_reason = retry_reason, None
		retry_after_login_drop = False
		dropped_lines = []
		proc = None
		lines_before = (len(host.output), len(host.stderr))
		give_streams = []
		with sem:
			if _stopping:
				# mssh is exiting (SIGTERM, SIGHUP, a second Ctrl C): a host waiting for its turn does not start
				host.output.append('Not started: mssh is exiting')
				host.returncode = -1
				return True, retry_limit, attempt_line_starts
			if _emo:
				# the first Ctrl C stops the running commands; a host still waiting for its turn does not
				# start either: it would only be one more login attempt on that host
				_report(host, 'Not started: Ctrl C')
				host.returncode = 130
				return True, retry_limit, attempt_line_starts
			try:
				shown = 'Running command: ' + _shown_command(formatedCMD, passwords)
				_note(host, shown)
				# this try's lines, to tell whether the server dropped the connection before login
				run_stdout_start, run_stderr_start = len(host.stdout), len(host.stderr)
				host.dropped_before_login = False
				# without the TUI nobody can type, an open stdin pipe would leave commands reading it waiting forever
				# read once: the TUI can end (clearing the flag) at any time, a pipe must always get a writer that closes it
				interactive_stdin = host.interactive_stdin
				stdin = subprocess.PIPE if interactive_stdin else subprocess.DEVNULL
				# the threads handling stdout, stderr and stdin start before the command: when the system allows
				# no more threads (ulimit -u, pids limit), the command has not run yet and can be tried again
				stdout_thread, give_stdout = _start_waiting_thread(__handle_reading_stream)
				give_streams.append(give_stdout)
				stderr_thread, give_stderr = _start_waiting_thread(__handle_reading_stream)
				give_streams.append(give_stderr)
				stdin_stop_event = threading.Event()
				# wakes the thread forwarding typed lines (see _typed_line_waiters)
				stdin_wake = threading.Event()
				stdin_thread = None
				if interactive_stdin:
					stdin_thread, give_stdin = _start_waiting_thread(__handle_writing_stream)
					give_streams.append(give_stdin)
				# a session of its own has no controlling terminal: ssh cannot ask there and fails with its reason
				own_session = os.name == 'posix' and not host.use_terminal
				# the passwords sshpass and ipmitool read (see _CommandLine)
				env = dict(os.environ, **formatedCMD.env) if getattr(formatedCMD, 'env', None) else None
				proc = subprocess.Popen(formatedCMD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=stdin,start_new_session=own_session,env=env)
				__running_procs.add(proc)
				# the readers read through _CommandPipe: one can be given up when a background process holds its pipe
				stdout_pipe = _CommandPipe(proc.stdout)
				stderr_pipe = _CommandPipe(proc.stderr)
				give_stdout((stdout_pipe,host.stdout, host,host.stdout_buffer))
				give_stderr((stderr_pipe,host.stderr, host,host.stderr_buffer))
				if interactive_stdin:
					give_stdin((proc.stdin,stdin_stop_event, host, stdin_wake))
				give_streams = []
				# Monitor the subprocess and terminate it after the timeout
				host.lastUpdateTime = time.monotonic()
				timeoutLineAppended = False
				# how long to wait for the process once its output ended (see below)
				sleep_interval = 1.0e-4
				timed_out = False
				stopped_by_ctrl_c = False
				while proc.poll() is None:  # while the process is still running
					if timeout > 0:
						if time.monotonic() - host.lastUpdateTime > timeout:
							timed_out = True
							_report(host, 'Timeout!')
							# -t counts the time since the last output, not since the start
							stopped = f'No output for {timeout} s, so {_stopped_command_note(formatedCMD)}.'
							_report(host, stopped)
							_stop_command(proc)
							break
						elif time.monotonic() - host.lastUpdateTime >  max(1, timeout // 2):
							timeoutLine = f'Timeout in [{timeout - int(time.monotonic() - host.lastUpdateTime)}] seconds!'
							if host.output and not host.output[-1].strip().startswith(timeoutLine):
								# remove last line if it is a countdown
								if host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
									host.output.pop()
								host.output.append(timeoutLine)
								host.lineNumToPrintSet.add(len(host.output)-1)
								timeoutLineAppended = True
						elif host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
							host.output.pop()
							host.output.append('')
							host.lineNumToPrintSet.add(len(host.output)-1)
							timeoutLineAppended = False
					if _emo:
						_report(host, 'Ctrl C detected, Emergency Stop!')
						stopped_by_ctrl_c = True
						_stop_command(proc)
						break
					# until the command's output ends, which it does as it exits, waking _MONITOR_WAKE for -t and
					# Ctrl C. Once it ended, the process is looked at more and more slowly: it may run on with its
					# output closed. Polling every 10 ms cost 0.44 CPU cores per 1000 waiting hosts
					reader = stdout_thread if stdout_thread.is_alive() else stderr_thread if stderr_thread.is_alive() else None
					if reader is not None:
						reader.join(_MONITOR_WAKE)
					else:
						time.sleep(sleep_interval)
						sleep_interval = min(sleep_interval * 2, _MONITOR_WAKE)
				stdin_stop_event.set()
				stdin_wake.set()
				# Wait for output processing to complete
				all_read = _wait_for_readers(host, [(stdout_thread, stdout_pipe, host.stdout, host.stdout_buffer),
					(stderr_thread, stderr_pipe, host.stderr, host.stderr_buffer)])
				if stdin_thread:
					stdin_thread.join(timeout=1)
				if proc.stdin is not None and proc.stdin.closed:
					# communicate() would flush the closed pipe and raise
					proc.stdin = None
				# communicate() reads the pipes too, only once no reader does: it closes them and collects the exit status
				if not _emo and all_read:
					try:
						proc.communicate(timeout=1)
					except subprocess.TimeoutExpired:
						pass
				# the return code is set last: a host with one looks finished, and may be tried again before that
				returncode = proc.poll()
				if timed_out:
					returncode = 124
				elif stopped_by_ctrl_c or _emo:
					# Ctrl C. The terminal's reaches the command too, which may end before mssh stops it: ssh then
					# says only "Killed by signal 2." (hidden), sshpass exits 0. Either way it did not finish
					if not stopped_by_ctrl_c:
						_report(host, 'Ctrl C detected, Emergency Stop!')
					stopped = _stopped_command_note(formatedCMD) + '.'
					_report(host, stopped)
					returncode = 130
				host.output.append(f'Command finished with return code {returncode}')
				# read before the ignored messages are filtered out, they may hold ssh's lines about the drop
				login_drop = None
				if tool and not timed_out and not _emo:
					login_drop = _login_drop(returncode, host.stdout[run_stdout_start:], host.stderr[run_stderr_start:], tool)
				if login_drop and login_drop_retries < _LOGIN_DROP_RETRIES and retry_limit > 0 and _login_drop_is_safe_to_retry(login_drop, tool):
					retry_after_login_drop = True
					if not __DEBUG_MODE:
						# the next try's lines take their place
						dropped_lines = host.stderr[run_stderr_start:]
						del host.stderr[run_stderr_start:]
				else:
					host.dropped_before_login = _shows_dropped_login(login_drop)
				if host.stderr:
					# filter out the error messages that we want to ignore, in the list itself: a reader still
					# running (after Ctrl C, or where pipes cannot be polled) appends to it, and those lines stay
					count = len(host.stderr)
					host.stderr[:count] = [line for line in host.stderr[:count] if not __ERROR_MESSAGES_TO_IGNORE_REGEX.search(line)]
				if not retry_after_login_drop:
					host.returncode = returncode
			except OSError as e:
				if e.errno == errno.EMFILE and proc is None:
					retry_reason = 'open files'
					host.returncode = None
				elif e.errno == errno.EAGAIN and proc is None:
					# fork failed: the process limit is reached
					retry_reason = 'processes or threads'
					host.returncode = None
				else:
					_record_host_exception(host, e)
			except RuntimeError as e:
				if proc is None:
					# a thread for the command's streams could not start
					retry_reason = 'processes or threads'
					host.returncode = None
				else:
					_record_host_exception(host, e)
			except Exception as e:
				_record_host_exception(host, e)
			finally:
				__running_procs.discard(proc)
				for give in give_streams:
					# the command did not start: end the threads started for it
					give(None)
		if retry_after_login_drop:
			login_drop_retries += 1
			retry_limit -= 1
			delay = _login_drop_backoff_seconds(login_drop_retries)
			message = f'Warning: The server dropped the connection before login (sshd MaxStartups?), retrying in {delay:.1f} s...'
			_note(host, message)
			time.sleep(delay)
			if _emo:
				# Ctrl-C while waiting: the host ends as the dropped try left it
				host.stderr.extend(line for line in dropped_lines if not __ERROR_MESSAGES_TO_IGNORE_REGEX.search(line))
				host.dropped_before_login = True
				host.returncode = 255
				return True, retry_limit, attempt_line_starts
			continue
		if not retry_reason:
			break
		waiting_for_others = retry_reason == 'processes or threads' and bool(__running_procs)
		if retry_limit <= 0 and not waiting_for_others:
			_report(host, f"Error: Retry limit reached after too many {retry_reason}!")
			host.returncode = 1
			return True, retry_limit, attempt_line_starts
		if retry_reason == previous_reason == 'processes or threads':
			# still waiting: one warning however long it takes
			_cut_output(host, lines_before[0], stderr_len=lines_before[1])
		else:
			host.output.append(f"Warning: Too many {retry_reason}. retrying...")
		time.sleep(_emfile_backoff_seconds(emfile_attempt))
		emfile_attempt += 1
		if not waiting_for_others:
			retry_limit -= 1
	return False, retry_limit, attempt_line_starts

def _stop_command(proc):
	'''Stop a command mssh gives up on (-t, Ctrl C) as Ctrl C would, then for good.'''
	if proc.poll() is None:
		proc.send_signal(signal.SIGINT)
		time.sleep(0.1)
		proc.terminate()

# sshpass's own exit codes: 5 ssh asked for the password again, 6 ssh asked whether to trust a host key it
# does not know, 7 ssh warned that the key known for the host's IP address differs and asked whether to go on
_SSHPASS_EXIT_CODES = (5, 6, 7)
# programs that never exit with those codes themselves (0, 1 or ssh's 255): the code is sshpass's
_NEVER_EXIT_LIKE_SSHPASS = ('scp', 'ssh-copy-id')

def _sshpass_program(formatedCMD):
	'''
	The name of the program formatedCMD runs under sshpass (ssh, scp, rsync, ssh-copy-id, ...), or None.

	A shell host (--copy_id) runs sshpass inside its sh -c line.
	'''
	sshpass = _binPaths.get('sshpass')
	words = [str(word) for word in formatedCMD or ()]
	if sshpass and len(words) == 3 and words[0] == _binPaths.get('sh') and words[1] == '-c':
		try:
			words = shlex.split(words[2])
		except ValueError:
			return None
	if not sshpass or len(words) < 3 or words[0] != sshpass:
		return None
	return os.path.basename(words[2]) if words[1] == '-e' else None

def _may_go_through_a_proxy(host):
	'''
	Whether ssh may reach host through another host (ProxyJump, ProxyCommand), whose key mssh's host
	key options do not cover. True when mssh cannot tell: no ssh -G, or -ea given (it may name one).
	'''
	if host.extraargs or 'ssh' not in _binPaths:
		return True
	config = _ssh_config_values(getattr(host, 'address', None) or host.name)
	if config is None:
		return True
	return any(config.get(key, 'none').lower() != 'none' for key in ('proxyjump', 'proxycommand'))

def _sshpass_failure(host, formatedCMD, line_starts=(0, 0, 0)):
	'''
	The lines saying why sshpass stopped host's command, or [] when it did not.

	sshpass answers ssh's password prompt and no other question. When ssh asks for the password again
	or asks about a host key, sshpass exits with its own code without a word: ssh asked on sshpass's
	terminal, so the host showed only the code. ssh passes on the remote command's exit code and rsync
	has codes 5 and 6 of its own: a host that printed on stdout got past ssh's questions, otherwise the
	lines say that the code may be theirs. Without SSH_STRICT_HOST_KEY_CHECKING ssh does not check
	the host's key, so 6 and 7 can only be about a host on the way. line_starts holds where the
	attempt's lines begin in host.output, host.stdout and host.stderr.
	'''
	code = host.returncode
	if code not in _SSHPASS_EXIT_CODES or host.stdout[line_starts[1]:]:
		return []
	program = _sshpass_program(formatedCMD)
	if not program:
		return []
	if program in _NEVER_EXIT_LIKE_SSHPASS:
		doubt = ''
	elif code != 5 and not SSH_STRICT_HOST_KEY_CHECKING and not _may_go_through_a_proxy(host):
		# no host key was checked: the code is the command's (curl -s exits 6 and 7, ...)
		return []
	elif program == 'ssh':
		doubt = ', unless the command itself exited with {}'.format(code)
	else:
		doubt = ', unless {} itself exited with {}'.format(program, code)
	address = getattr(host, 'address', None) or host.name
	ip = host.ip or address
	if code == 5:
		return [f'sshpass: the password was not accepted, ssh asked for it again (exit code 5{doubt}). Check it, and that the host takes passwords for this user.']
	if code == 6:
		said = f'sshpass: ssh asked whether to trust a host key that is not in known_hosts, which sshpass does not answer (exit code 6{doubt}).'
	else:
		said = f"sshpass: ssh warned that known_hosts has a different key for the host's IP address and asked whether to go on, which sshpass does not answer (exit code 7{doubt})."
	if not SSH_STRICT_HOST_KEY_CHECKING:
		return [said, f"mssh does not check the key of {address} (SSH_STRICT_HOST_KEY_CHECKING is false), so the key is another host's, such as a ProxyJump host's: connect to that host once with ssh to {'accept its key' if code == 6 else 'see the warning'}."]
	if code == 6:
		return [said, f"SSH_STRICT_HOST_KEY_CHECKING is true, so ssh checks the key of {address} (and of any ProxyJump host): accept it by connecting once with ssh, or check it and add it with ssh-keyscan {address} >> ~/.ssh/known_hosts. StrictHostKeyChecking accept-new in ~/.ssh/config accepts new hosts' keys."]
	return [said, f'If {address} is the host you expect (reinstalled, or {ip} belonged to another host before), remove the old key with ssh-keygen -R {ip}.']

def _copy_id_extra_args(extraargs):
	'''
	The words of -ea that every ssh-copy-id takes, read as ssh reads them: -o and -p, and ssh's -J as
	-o ProxyJump=. ssh-copy-id's -i names the key to install, so ssh's -i (a key to log in with) is
	left out, as is -F (the ssh-copy-id of OpenSSH 7.4 and 8.0 fails on it: "invalid option") and every word
	ssh-copy-id has no option for (ssh's flags, rsync's options).
	'''
	# as a shell splits them: -ea "-o ProxyCommand='ssh -W %h:%p bastion'" is two words
	words = _split_extra_args(extraargs) if isinstance(extraargs, str) else [str(word) for word in extraargs or ()]
	taken = []
	index = 0
	while index < len(words):
		word = words[index]
		index += 1
		if len(word) < 2 or word[0] != '-' or word[1] not in _SSH_OPTIONS_WITH_VALUE:
			continue
		# -p 2222 or -p2222
		value = word[2:]
		if not value and index < len(words):
			value = words[index]
			index += 1
		if not value:
			continue
		if word[1] == 'J':
			taken += ['-o', 'ProxyJump=' + value]
		elif word[1] in 'op':
			taken += ['-' + word[1], value]
	return taken

def _copy_id_command(host, identity_file=None, extraargs=None):
	'''
	The ssh-copy-id line (for sh) that installs the public key on host ([user@]host).

	ssh-copy-id gets what mssh gives ssh, as far as it takes it: the host key options every ssh mssh runs
	gets (none with SSH_STRICT_HOST_KEY_CHECKING), the key from -k as the key to install, and the words
	of -ea it takes (_copy_id_extra_args). The ssh-copy-id of OpenSSH 7.4 (CentOS 7), 8.0 (EL8) and
	later takes -o and -p, before the host.
	'''
	words = [_binPaths['ssh-copy-id']]
	if identity_file:
		words += ['-i', os.path.expanduser(identity_file)]
	if not SSH_STRICT_HOST_KEY_CHECKING:
		words += ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
	# a host that does not answer must not hold up the others (without -p they run one by one); the
	# operator's options are the ones ssh-copy-id gets (it drops -F)
	words += _copy_id_extra_args(extraargs)
	words += _ssh_timeout_options()
	words.append(host)
	return ' '.join(shlex.quote(word) for word in words)

def _wait_status_return_code(status):
	'''os.system's wait status as Popen gives a return code: the exit status, or -N when signal N ended it.'''
	if hasattr(os, 'WIFSIGNALED') and os.WIFSIGNALED(status):
		return -os.WTERMSIG(status)
	if hasattr(os, 'WIFEXITED') and os.WIFEXITED(status):
		return os.WEXITSTATUS(status)
	# Windows: os.system returns the exit status itself
	return status

def _count_failed_copies(copied):
	'''
	Count each host ssh-copy-id failed on (--copy_id with a command) once towards the exit code, as a
	failed host. main() leaves the hosts counted here out when it counts the command's failures.
	'''
	global __mainReturnCode
	global __failedHosts
	for host in copied:
		# as main() counts: a host still running (None) has not failed
		if host.returncode and host.name not in __failedHosts:
			__mainReturnCode += 1
			__failedHosts.add(host.name)

def run_command(host, sem, timeout=60,passwds=None, retry_limit = ...,ipmi_definitions_list = ...):
	'''
	Run the command on the host. Main execution function.

	Builds the command (_build_command), runs it (_execute_command) and retries on failure: the
	next IPMI definition, rsync without -X when the destination cannot keep extended attributes, or
	scp when rsync could not run on the host (see _rsync_failure_scp_reason). A gather copies again,
	with --copy-links, the sources that came back as symbolic links to files. Every retry uses up one
	of retry_limit.

	Args:
		host (Host): The host object
		sem (threading.Semaphore): The semaphore to limit the number of concurrent SSH sessions
		timeout (int, optional): The timeout for the command. Defaults to 60.
		passwds (str, optional): The password for the host. Defaults to None.

	Returns:
		None
	'''
	if retry_limit is ...:
		# resolved at call time, the CLI and config files can add ipmi definitions after import
		retry_limit = 7 + len(DEFAULT_IPMI_DEFINITIONS)
	scp_like_rsync = False
	rsync_xattrs = True
	# the IPMI command lines run on this host: one again (the ssh fallback every failed definition
	# adds, or two definitions that end up the same) would only repeat a failed login
	ran = set()
	gather_copies = None
	gather_links = None
	gather_link_copies = []
	while True:
		if retry_limit < 0:
			_report(host, 'Error: Retry limit reached!')
			host.returncode = 1
			return
		line_counts = (len(host.output), len(host.stdout), len(host.stderr))
		action, formatedCMD, ipmi_definition, username, passwds, useScp, ipmi_definitions_list = _build_command(host, passwds, ipmi_definitions_list, scp_like_rsync, rsync_xattrs, gather_links)
		if action == 'stop':
			return
		if action == 'run' and gather_copies is None and host.files and host.gatherMode and not useScp:
			# where rsync puts each source, worked out before it runs
			gather_copies = _gather_copy_paths(host)
		if action == 'rebuild':
			retry_limit -= 1
			continue
		if host.ipmi:
			# the password is in the environment, not the command line
			attempt = (tuple(str(arg) for arg in formatedCMD), tuple(sorted(getattr(formatedCMD, 'env', {}).items())))
			if attempt in ran:
				# not run: drop what building it said, it was said when it ran
				_cut_output(host, *line_counts)
				continue
			ran.add(attempt)
		# mssh's own ssh, scp or rsync to the host: tried again when the server drops it before login
		tool = None
		if not host.shell and (not host.ipmi or ipmi_definition.get('ipmi_method') == 'ssh_ipmitool'):
			tool = ('scp' if useScp else 'rsync') if host.files else 'ssh'
		stop, retry_limit, attempt_line_starts = _execute_command(host, formatedCMD, sem, timeout, retry_limit, (passwds, ipmi_definition.get('password')), tool)
		if gather_links:
			# the links' second copy is the host's last attempt
			_put_back_gathered_links(host, gather_link_copies)
		if stop:
			return
		sshpass_failure = _sshpass_failure(host, formatedCMD, attempt_line_starts)
		host.output.extend(sshpass_failure)
		host.stderr.extend(sshpass_failure)
		if sshpass_failure and not host.ipmi:
			# ssh stopped at its question before the command ran: scp after rsync would stop there too
			return
		# If using ipmi, we will try again using next ipmi definition if ipmi connection is not successful
		if host.ipmi and host.returncode != 0:
			should_wait = _ipmi_failure_should_wait(host, attempt_line_starts)
			host.returncode = None
			host.output.append('IPMI connection failed! Trying next ipmi definition...')
			if __DEBUG_MODE:
				host.stderr.append('IPMI connection failed! Trying next ipmi definition...')
			else:
				host.stdout = []
				host.stderr = []
			if ipmi_definition.get('retry_lockout_time'):
				try:
					sleep_seconds = int(ipmi_definition.get('retry_lockout_time'))
					if sleep_seconds >= 0 and should_wait:
						_note(host, f'Sleeping for {sleep_seconds} seconds...')
						time.sleep(sleep_seconds)
					elif sleep_seconds >= 0:
						host.output.append('Skipping IPMI lockout wait; the controller was not reached.')
				except Exception as e:
					_note(host, f'Error: Failed to sleep for {ipmi_definition.get("retry_lockout_time")} seconds! {e}')
					# fall back to the default lockout time, which is -1 (disabled) unless configured
					try:
						fallback_seconds = float(DEFAULT_IPMI_RETRY_LOCKOUT_TIME)
					except (TypeError, ValueError):
						fallback_seconds = -1
					if fallback_seconds > 0 and should_wait:
						time.sleep(fallback_seconds)
			if ipmi_definition.get('ipmi_method') == 'ipmitool':
				if ipmi_definition.get('interface_ip_prefix') == DEFAULT_IPMI_INTERFACE_IP_PREFIX:
					ipmi_definition['interface_ip_prefix'] = DEFAULT_INTERFACE_IP_PREFIX
				ipmi_definition['username'] = username
				ipmi_definition['password'] = passwds
				ipmi_definition['ipmi_method'] = 'ssh_ipmitool'
				ipmi_definitions_list.append(ipmi_definition)
			retry_limit -= 1
			continue
		# mssh asks rsync for extended attributes on its own: where the destination cannot keep them
		# (NFSv3, vfat, ...), rsync copies the data and exits 23. Copying again without -X is a quick
		# pass that ends with the result of the copy itself.
		elif host.files and not useScp and rsync_xattrs and host.returncode == 23:
			xattr_error = _rsync_xattr_error(host, attempt_line_starts)
			if not xattr_error:
				return
			host.returncode = None
			host.output.append('Rsync could not set extended attributes! Copying again without them...')
			if __DEBUG_MODE:
				host.stderr.append('Rsync could not set extended attributes! Copying again without them...')
			else:
				host.stderr = []
			host.stderr.append(f'Warning: copied without extended attributes, rsync could not set them: {xattr_error}')
			rsync_xattrs = False
			retry_limit -= 1
			continue
		# rsync could not run on the host: try scp, if it can copy what rsync would have. Not after a
		# gather copied links again: the destination may hold links rsync made, which scp writes through
		elif host.files and not host.scp and not useScp and host.returncode != 0 and gather_links is None:
			reason = _rsync_failure_scp_reason(host, attempt_line_starts)
			if not reason:
				return
			problem = _scp_cannot_copy_like_rsync(host)
			if problem:
				_report(host, f'{reason} Not trying scp: {problem}')
				return
			host.returncode = None
			host.output.append(f'{reason} Trying SCP connection...')
			if __DEBUG_MODE:
				host.stderr.append(f'{reason} Trying SCP connection...')
			else:
				host.stdout = []
				host.stderr = []
			host.scp = True
			scp_like_rsync = True
			retry_limit -= 1
			continue
		# rsync -l brought a gathered source back as the link it is on the host, which points into this
		# machine, or nowhere: copy again what a link to a file points to. --no-recursive skips a link to
		# a directory: --copy-links would follow every link inside it, and the next gather could not
		# replace the directory with the link. The links are removed first, rsync --copy-links would
		# follow them here as well, and put back if not replaced. No -X: no retry then follows, which
		# would find the links put back (the base copied no attributes for these, only links).
		elif host.files and host.gatherMode and not useScp and host.returncode == 0 and gather_links is None and gather_copies:
			for source, copy in gather_copies:
				try:
					if os.path.islink(copy):
						target = os.readlink(copy)
						os.unlink(copy)
						gather_link_copies.append((source, copy, target))
				except OSError:
					continue
			gather_links = [source for source, _, _ in gather_link_copies]
			if not gather_links:
				return
			rsync_xattrs = False
			host.returncode = None
			message = f'{", ".join(gather_links)}: a symbolic link on the host, copying what it points to...'
			host.output.append(message)
			if __DEBUG_MODE:
				host.stderr.append(message)
			else:
				host.stdout = []
				host.stderr = []
			retry_limit -= 1
			continue
		return


def _ssh_cannot_ask(host, passwds):
	'''
	True when the host's ssh runs without a terminal (see Host.use_terminal) and nothing answers its
	password questions in its place: not sshpass (-p), not an askpass program the user asked for with
	SSH_ASKPASS_REQUIRE. IPMI hosts are left alone: ssh_ipmitool takes its password later.
	'''
	if host.use_terminal or os.name != 'posix' or host.ipmi:
		return False
	if passwds and 'sshpass' in _binPaths:
		return False
	return os.environ.get('SSH_ASKPASS_REQUIRE', '').lower() not in ('force', 'prefer')

#%% ------------ Start Threading Block ----------------
def _run_command_thread(host, sem, timeout, passwds):
	'''
	Thread entry point for run_command. Guarantees the host ends with a return code,
	callers wait for every host's returncode to be set and would otherwise wait forever.
	'''
	try:
		run_command(host, sem, timeout, passwds)
	except Exception as e:
		_record_host_exception(host, e)
	finally:
		if host.returncode is None:
			_report(host, 'Error: Command thread exited without a return code!')
			host.returncode = -1

def start_run_on_hosts(hosts, timeout=60,password=None,max_connections=4 * _cpu_count()):
	'''
	Start running the command on the hosts. Wrapper function for run_command

	Up to max_connections worker threads run the hosts in the given order (IPMI hosts: one each), so
	the number of threads does not grow with the number of hosts: a process / thread limit (ulimit -u,
	a container's pids limit) counts every thread. When the system allows fewer threads, the ones
	started run all the hosts; when none can start, every host fails with a message saying why.

	Args:
		hosts (list): A list of Host objects
		timeout (int, optional): The timeout for the command. Defaults to 60.
		password (str, optional): The password for the hosts. Defaults to None.
		max_connections (int, optional): The maximum number of concurrent SSH sessions. Defaults to 4 * os.cpu_count().

	Returns:
		list: The worker threads started, they end once no host is left to start. Hosts skipped as
			unreachable are not started.
	'''
	hosts = [host for host in hosts if not host.skipped]
	if len(hosts) == 0:
		return []
	sem = threading.Semaphore(max_connections)  # Limit concurrent SSH sessions
	waiting = deque(hosts)
	lock = threading.Lock()
	# between two IPMI passwords a host waits out retry_lockout_time running nothing, outside the
	# semaphore: IPMI hosts keep a thread each, as before, so their waits overlap
	wanted = len(hosts) if any(host.ipmi for host in hosts) else min(max_connections, len(hosts))
	# workers: how many may take hosts (lowered when no more threads can start), alive: how many run
	pool = {'workers': max(1, wanted), 'alive': 0}
	def worker():
		while True:
			with lock:
				if not waiting or pool['alive'] > pool['workers']:
					pool['alive'] -= 1
					return
				host = waiting.popleft()
			host.thread = threading.current_thread()
			try:
				_run_command_thread(host, sem, timeout, password)
			except BaseException:
				# e.g. SystemExit: it would end this worker, and the hosts left could wait forever
				pass
	threads = []
	back_offs = 0
	while len(threads) < pool['workers']:
		thread = threading.Thread(target=worker, daemon=True)
		with lock:
			pool['alive'] += 1
		try:
			thread.start()
		except RuntimeError:
			# no more threads allowed (ulimit -u, pids limit)
			with lock:
				pool['alive'] -= 1
				if threads:
					# the workers started took what was left, and each command they run needs more (ssh,
					# the threads reading its output): half of them stop before taking another host
					pool['workers'] = max(1, len(threads) // 2)
			if threads or _emo or back_offs >= 6:
				break
			# none started yet: wait for processes to end, as for too many open files
			time.sleep(_emfile_backoff_seconds(back_offs))
			back_offs += 1
			continue
		threads.append(thread)
		time.sleep(__thread_start_delay)
	if not threads:
		message = 'Error: No thread could be started to run the command, the system allows no more processes or threads (ulimit -u, pids limit)!'
		for host in waiting:
			_report(host, message)
			host.returncode = 1
	elif pool['workers'] < min(max_connections, len(hosts)) and not __global_suppress_printout:
		eprint(f"Warning: The system allows no more threads (ulimit -u, pids limit), running the hosts at most {pool['workers']} at a time.")
	return threads

#%% ------------ Display Block ----------------
# printable ASCII, one column per character: text that needs no closer look
_NOT_PRINTABLE_ASCII = re.compile('[^ -~]')
_ANSI_ESCAPE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

@functools.lru_cache(maxsize=8192)
def _char_columns(char):
	'''
	Terminal columns a printable character takes, as the C library's wcwidth() counts them (curses uses it).

	East Asian wide and fullwidth characters (CJK, kana, hangul, most emoji) take 2. Combining marks,
	format characters (zero width space, joiner) and the vowels and final consonants of conjoining
	hangul take 0: they join the character before. Everything else takes 1, the East Asian ambiguous
	width characters (box drawing, arrows, Greek, Cyrillic) too, as terminals count them outside CJK
	locales: the display's own borders are made of them.
	'''
	if char < '\u0300':
		return 1
	category = unicodedata.category(char)
	if category in ('Mn', 'Me', 'Cf') or '\u1160' <= char <= '\u11ff':
		return 0
	return 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1

def _text_columns(text):
	'''Columns text takes on a terminal (see _char_columns): color and other escape sequences take none.'''
	if '\x1b' in text:
		text = _ANSI_ESCAPE.sub('', text)
	if not _NOT_PRINTABLE_ASCII.search(text):
		return len(text)
	return sum(map(_char_columns, text))

def _wrap_columns(text, width, tabsize = 4, initial_indent = '', subsequent_indent = '', **options):
	'''
	textwrap.wrap(text, width, ...) with the width in terminal columns (see _text_columns).

	Text holding no wide or zero width character is wrapped by textwrap itself. Other text is wrapped
	as mssh's wrappers do it (drop_whitespace and replace_whitespace False, no breaking on hyphens):
	whole words while they fit, then a word wider than a line split where the line ends. A wide
	character never straddles two lines; one wider than the whole width gets a line of its own.
	'''
	text = text.expandtabs(tabsize)
	if _text_columns(text) == len(text):
		return textwrap.wrap(text, width, tabsize=tabsize, initial_indent=initial_indent,
			subsequent_indent=subsequent_indent, **options)
	lines = []
	# words and the whitespace between them, as textwrap splits them without hyphens
	chunks = [chunk for chunk in re.split(r'(\s+)', text) if chunk]
	chunks.reverse()
	while chunks:
		indent = subsequent_indent if lines else initial_indent
		room = width - _text_columns(indent)
		line, used = [], 0
		while chunks and used + _text_columns(chunks[-1]) <= room:
			used += _text_columns(chunks[-1])
			line.append(chunks.pop())
		if chunks and _text_columns(chunks[-1]) > room:
			# a word wider than a line: as much of it as fits here, at least a character
			word = chunks.pop()
			cut = 0
			while cut < len(word) and used + _char_columns(word[cut]) <= room:
				used += _char_columns(word[cut])
				cut += 1
			if not cut and not line:
				cut = 1
			line.append(word[:cut])
			if word[cut:]:
				chunks.append(word[cut:])
		lines.append(indent + ''.join(line))
	return lines

def _curses_fit(text, columns, column = 0):
	'''
	text as curses should draw it in at most columns columns.

	A character that does not fit whole is left out, with the rest of text: curses would wrap it onto
	the next line, or scroll the window from its last line. A tab becomes spaces up to the next
	multiple of 8 columns from the start of the line's text (column is where text starts in it), as
	on the host's terminal: curses would count from the window's edge, and wrap a tab that passes its
	side. Another control character becomes its ^X form, which curses would draw in two columns (or,
	for a backspace, act on).

	Returns:
		(str, int, bool): the text to draw, the columns it takes, and whether all of text fits
	'''
	if columns <= 0:
		return '', 0, not text
	if not _NOT_PRINTABLE_ASCII.search(text):
		return text[:columns], min(len(text), columns), len(text) <= columns
	pieces = []
	used = 0
	for char in text:
		if char < ' ' or char == '\x7f':
			piece = ' ' * (8 - (column + used) % 8) if char == '\t' else '^' + chr(ord(char) ^ 0x40)
			size = len(piece)
		else:
			piece = char
			size = _char_columns(char)
		if used + size > columns:
			return ''.join(pieces), used, False
		pieces.append(piece)
		used += size
	return ''.join(pieces), used, True

def __approximate_color_8bit(color):
	"""
	Approximate an 8-bit color (0-255) to the nearest curses color.

	Args:
		color: 8-bit color code

	Returns:
		Curses color code
	"""
	if color < 8:  # Standard and bright colors
		return ANSI_TO_CURSES_COLOR.get(color % 8 + 30, curses.COLOR_WHITE)
	elif 8 <= color < 16:  # Bright colors
		return ANSI_TO_CURSES_COLOR.get(color % 8 + 90, curses.COLOR_WHITE)
	elif 16 <= color <= 231:  # Color cube
		# Convert 216-color cube index to RGB
		color -= 16
		r = (color // 36) % 6 * 51
		g = (color // 6) % 6 * 51
		b = color % 6 * 51
		return __approximate_color_24bit(r, g, b)  # Map to the closest curses color
	elif 232 <= color <= 255:  # Grayscale
		gray = (color - 232) * 10 + 8
		return __approximate_color_24bit(gray, gray, gray)
	else:
		return curses.COLOR_WHITE  # Fallback to white for unexpected values

def __approximate_color_24bit(r, g, b):
	"""
	Approximate a 24-bit RGB color to the nearest curses color.
	Will initiate a curses color if curses.can_change_color() is True.

	Globals:
		__curses_color_table: Dictionary of RGB color to curses color code
		__curses_current_color_index: Current index of the

	Args:
		r: Red component (0-255)
		g: Green component (0-255)
		b: Blue component (0-255)

	Returns:
		Curses color code
	"""
	if curses.can_change_color():
		global __curses_color_table,__curses_current_color_index
		# Initiate a new color if it does not exist
		if (r, g, b) not in __curses_color_table:
			if __curses_current_color_index >= curses.COLORS:
				__curses_current_color_index = 10
			curses.init_color(__curses_current_color_index, int(r/255*1000), int(g/255*1000), int(b/255*1000))
			__curses_color_table[(r, g, b)] = __curses_current_color_index
			__curses_current_color_index += 1
		return __curses_color_table[(r, g, b)]
	# Fallback to 8-bit color approximation
	colors = {
		curses.COLOR_BLACK: (0, 0, 0),
		curses.COLOR_RED: (255, 0, 0),
		curses.COLOR_GREEN: (0, 255, 0),
		curses.COLOR_YELLOW: (255, 255, 0),
		curses.COLOR_BLUE: (0, 0, 255),
		curses.COLOR_MAGENTA: (255, 0, 255),
		curses.COLOR_CYAN: (0, 255, 255),
		curses.COLOR_WHITE: (255, 255, 255),
	}
	best_match = curses.COLOR_WHITE
	min_distance = float("inf")
	for color, (cr, cg, cb) in colors.items():
		distance = math.sqrt((r - cr) ** 2 + (g - cg) ** 2 + (b - cb) ** 2)
		if distance < min_distance:
			min_distance = distance
			best_match = color
	return best_match

def __get_curses_color_pair(fg, bg):
	"""
	Use curses color int values to create a curses color pair.

	Globals:
		__curses_global_color_pairs: Dictionary of color pairs
		__curses_current_color_pair_index: Current index of the color pair

	Args:
		fg: Foreground color code
		bg: Background color code

	Returns:
		Curses color pair code
	"""
	global __curses_global_color_pairs, __curses_current_color_pair_index
	if (fg, bg) not in __curses_global_color_pairs:
		if __curses_current_color_pair_index >= curses.COLOR_PAIRS:
			__curses_current_color_pair_index = 1
		curses.init_pair(__curses_current_color_pair_index, fg, bg)
		__curses_global_color_pairs[(fg, bg)] = __curses_current_color_pair_index
		__curses_current_color_pair_index += 1
	return curses.color_pair(__curses_global_color_pairs[(fg, bg)])

def __parse_ansi_escape_sequence_to_curses_attr(escape_code,color_pair_list = None):
	"""
	Parse ANSI escape codes to extract foreground and background colors.

	Args:
		escape_code: ANSI escape sequence for color
		color_pair_list: List of [foreground, background, color_pair] curses color pair values

	Returns:
		Curses color pair / attribute code
	"""
	if not escape_code:
		return 1
	if not color_pair_list:
		color_pair_list = [-1,-1,1]
	color_match = escape_code.lstrip("\x1b[").rstrip("m").split(";")
	color_match = [x if x else '0' for x in color_match]  # Replace empty strings with '0' (reset)
	if color_match:
		processed_index = -1
		for i, param in enumerate(color_match):
			if processed_index >= i:
				# if the index has been processed, skip
				continue
			if param.isdigit():
				if int(param) == 0:
					color_pair_list[0] = -1
					color_pair_list[1] = -1
					color_pair_list[2] = 1
				elif int(param) == 38:
					if i + 1 >= len(color_match):
						# Invalid color code, skip
						continue
					if color_match[i + 1] == "5":
						# 8-bit foreground color
						if i + 2 >= len(color_match) or not color_match[i + 2].isdigit():
							# Invalid color code, skip
							processed_index = i + 1
							continue
						color_pair_list[0] = __approximate_color_8bit(int(color_match[i + 2]))
						color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
						processed_index = i + 2
					elif color_match[i + 1] == "2":
						# 24-bit foreground color
						if i + 4 >= len(color_match) or not all(x.isdigit() for x in color_match[i + 2:i + 5]):
							# Invalid color code, skip
							processed_index = i + 1
							continue
						color_pair_list[0] = __approximate_color_24bit(int(color_match[i + 2]), int(color_match[i + 3]), int(color_match[i + 4]))
						color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
						processed_index = i + 4
				elif int(param) == 48:
					if i + 1 >= len(color_match):
						# Invalid color code, skip
						continue
					if color_match[i + 1] == "5":
						# 8-bit background color
						if i + 2 >= len(color_match) or not color_match[i + 2].isdigit():
							# Invalid color code, skip
							processed_index = i + 1
							continue
						color_pair_list[1] = __approximate_color_8bit(int(color_match[i + 2]))
						color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
						processed_index = i + 2
					elif color_match[i + 1] == "2":
						# 24-bit background color
						if i + 4 >= len(color_match) or not all(x.isdigit() for x in color_match[i + 2:i + 5]):
							# Invalid color code, skip
							processed_index = i + 1
							continue
						color_pair_list[1] = __approximate_color_24bit(int(color_match[i + 2]), int(color_match[i + 3]), int(color_match[i + 4]))
						color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
						processed_index = i + 4
				elif 30 <= int(param) <= 37 or 90 <= int(param) <= 97:
					# 4-bit foreground color
					color_pair_list[0] = ANSI_TO_CURSES_COLOR.get(int(param), curses.COLOR_WHITE)
					color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
				elif 40 <= int(param) <= 47 or 100 <= int(param) <= 107:
					# 4-bit background color
					color_pair_list[1] = ANSI_TO_CURSES_COLOR.get(int(param)-10, curses.COLOR_BLACK)
					color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
				elif int(param) == 1:
					color_pair_list[2] = color_pair_list[2] | curses.A_BOLD
				elif int(param) == 2:
					color_pair_list[2] = color_pair_list[2] | curses.A_DIM
				elif int(param) == 4:
					color_pair_list[2] = color_pair_list[2] | curses.A_UNDERLINE
				elif int(param) == 5:
					color_pair_list[2] = color_pair_list[2] | curses.A_BLINK
				elif int(param) == 7:
					color_pair_list[2] = color_pair_list[2] | curses.A_REVERSE
				elif int(param) == 8:
					color_pair_list[2] = color_pair_list[2] | curses.A_INVIS
				elif int(param) == 21:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_BOLD
				elif int(param) == 22:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_DIM
				elif int(param) == 24:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_UNDERLINE
				elif int(param) == 25:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_BLINK
				elif int(param) == 27:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_REVERSE
				elif int(param) == 28:
					color_pair_list[2] = color_pair_list[2] & ~curses.A_INVIS
				elif int(param) == 39:
					color_pair_list[0] = -1
					color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
				elif int(param) == 49:
					color_pair_list[1] = -1
					color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
	else:
		color_pair_list[0] = -1
		color_pair_list[1] = -1
		color_pair_list[2] = 1
	return color_pair_list[2]

def _curses_add_string_to_window(window, line = '', y = 0, x = 0, number_of_char_to_write = -1, color_pair_list = None,fill_char=' ',parse_ansi_colors = True,centered = False,lead_str = '', trail_str = '',box_ansi_color = None, keep_top_n_lines = 0,leave_space_for_cursor = False):
	"""
	Add a string to a curses window with / without ANSI color escape sequences translated to curses color pairs.

	Args:
		window: curses window object
		line: The line to add
		y: Line position in the window. Use -1 to scroll the window up 1 line and add the line at the bottom
		x: Column position in the window
		number_of_char_to_write: Number of terminal columns to write. -1 for all remaining space in line, 0 for no characters, and a positive integer for a specific number of columns.
		color_pair_list: List of [foreground, background, color_pair] curses color pair values
		fill_char: Character to fill the remaining space in the line, one column wide
		parse_ansi_colors: Parse ASCII color codes
		centered: Center the text in the window
		lead_str: Leading string to add to the line
		trail_str: Trailing string to add to the line
		box_ansi_color: ANSI color escape sequence for the box color
		keep_top_n_lines: Number of lines to keep at the top of the window
		leave_space_for_cursor: Leave space for the cursor at the end of the line

	Returns:
		None
	"""
	if color_pair_list is None:
		color_pair_list = [-1,-1,1]
	maxY, maxX = window.getmaxyx()
	if leave_space_for_cursor:
		maxX -= 1
	if maxY == 0 or maxX <= 0 or x >= maxX:
		return
	if x < 0:
		x = maxX + x
	if number_of_char_to_write == -1:
		numChar = maxX - x -1
	elif number_of_char_to_write == 0:
		return
	else:
		numChar = min(number_of_char_to_write,maxX - x -1)
	if numChar < 0:
		return
	if y < 0 or  y >= maxY:
		if keep_top_n_lines > maxY -1:
			keep_top_n_lines = maxY -1
		if keep_top_n_lines < 0:
			keep_top_n_lines = 0
		window.move(keep_top_n_lines,0)
		window.deleteln()
		y = maxY - 1
	# curses draws the other control characters as ^A, ^[ ... but refuses a NUL (ValueError): show it as ^@
	line = line.replace('\n', ' ').replace('\r', ' ').replace('\0', '^@')
	if parse_ansi_colors:
		segments = re.split(r"(\x1b\[[\d;]*m)", line)  # Split line by ANSI escape codes
	else:
		segments = [line]
	# Positions count terminal columns, not characters: a wide character (CJK, most emoji) takes two, a combining
	# mark none. Each piece is cut to the columns left before it is drawn (_curses_fit): curses would wrap the rest
	# onto the next line, or scroll the window when it is the last one
	columnsWritten = 0
	boxAttr = __parse_ansi_escape_sequence_to_curses_attr(box_ansi_color)
	# first add the lead_str
	if lead_str:
		lead, columnsWritten, _ = _curses_fit(lead_str, numChar)
		window.addnstr(y, x, lead, len(lead), boxAttr)
	trail_columns = _curses_fit(trail_str, numChar)[1]
	# process centering
	if centered:
		text_columns = 0
		for segment in segments:
			if segment and not (parse_ansi_colors and segment.startswith("\x1b[")):
				text_columns += _curses_fit(segment, numChar, text_columns)[1]
		fill_length = numChar - columnsWritten - trail_columns - text_columns
		leading_fill_length = fill_length // 2
		if leading_fill_length > 0:
			window.addnstr(y, x + columnsWritten, fill_char * (leading_fill_length // len(fill_char) + 1), leading_fill_length, boxAttr)
			columnsWritten += leading_fill_length
	# add the segments
	text_columns = 0
	text_cut = False
	for segment in segments:
		if not segment:
			continue
		if parse_ansi_colors and segment.startswith("\x1b["):
			# Parse ANSI escape sequence, also after the text is cut: the color goes on to the next lines
			_ = __parse_ansi_escape_sequence_to_curses_attr(segment,color_pair_list)
		elif not text_cut and columnsWritten < numChar:
			# Add text with current color, as much as fits. Nothing after a cut: it would not follow what is shown
			text, columns, text_fits = _curses_fit(segment, numChar - columnsWritten, text_columns)
			if text:
				window.addnstr(y, x + columnsWritten, text, len(text), color_pair_list[2])
			columnsWritten += columns
			text_columns += columns
			text_cut = not text_fits
	# if we have finished printing segments but we still have space, we will fill it with fill_char (one column wide)
	trail_fill_length = numChar - columnsWritten - trail_columns
	if trail_fill_length > 0 and fill_char:
		window.addnstr(y, x + columnsWritten,fill_char * (trail_fill_length // len(fill_char) + 1), trail_fill_length , boxAttr)
		columnsWritten += trail_fill_length
	if trail_str and columnsWritten < numChar:
		trail, columns, _ = _curses_fit(trail_str, numChar - columnsWritten)
		window.addnstr(y, x + columnsWritten, trail, len(trail), boxAttr)
		columnsWritten += columns

# ssh's notices are short; a longer line is the command's output. Searching all of a line that can be
# megabytes long, with patterns like "Connection to .* closed", could take minutes
_TUI_NOTICE_MAX_LENGTH = 1024

def _tui_leaves_out(line):
	'''
	Whether a host's window leaves line out: ssh's own notices, which the output at the end leaves out too
	(ERROR_MESSAGES_TO_IGNORE). "Warning: Permanently added ..." comes with every connection (mssh keeps no
	known hosts), and was all a quiet command's window showed.
	'''
	return len(line) <= _TUI_NOTICE_MAX_LENGTH and bool(__ERROR_MESSAGES_TO_IGNORE_REGEX.search(line))

def _tui_first_shown_line(output, rows):
	'''The index in output from which a window of rows rows shows the lines it does not leave out.'''
	index = len(output)
	shown = 0
	while index > 0 and shown < rows:
		index -= 1
		if not _tui_leaves_out(output[index]):
			shown += 1
	return index

def _get_hosts_to_display (hosts, max_num_hosts, hosts_to_display = None, indexOffset = 0):
	'''
	Generate a list for the hosts to be displayed on the screen. This is used to display as much relevant information as possible.

	Args:
		hosts (list): A list of Host objects
		max_num_hosts (int): The maximum number of hosts to be displayed
		hosts_to_display (list, optional): The hosts that are currently displayed. Defaults to None.

	Returns:
		list: A list of Host objects to be displayed
	'''
	# We will sort the hosts by running -> failed -> finished -> waiting
	# running: returncode is None and output is not empty (output will be appened immediately after the command is run)
	# failed: returncode is not None and returncode is not 0
	# finished: returncode is not None and returncode is 0
	# waiting: returncode is None and output is empty
	running_hosts = [host for host in hosts if host.returncode is None and host.output]
	failed_hosts = [host for host in hosts if host.returncode is not None and host.returncode != 0]
	finished_hosts = [host for host in hosts if host.returncode is not None and host.returncode == 0]
	waiting_hosts = [host for host in hosts if host.returncode is None and not host.output]
	new_hosts_to_display = (running_hosts + failed_hosts + finished_hosts + waiting_hosts)
	new_hosts_to_display = new_hosts_to_display[indexOffset:] + new_hosts_to_display[:indexOffset]
	new_hosts_to_display = new_hosts_to_display[:max_num_hosts]
	if not hosts_to_display:
		return new_hosts_to_display , {'running':len(running_hosts), 'failed':len(failed_hosts), 'finished':len(finished_hosts), 'waiting':len(waiting_hosts)}, set(new_hosts_to_display)
	# we will compare the new_hosts_to_display with the old one, if some hosts are not in their original position, we will reprint all lines
	rearrangedHosts = set()
	for i, host in enumerate(new_hosts_to_display):
		if host not in hosts_to_display or i != hosts_to_display.index(host):
			rearrangedHosts.add(host)
	return new_hosts_to_display , {'running':len(running_hosts), 'failed':len(failed_hosts), 'finished':len(finished_hosts), 'waiting':len(waiting_hosts)}, rearrangedHosts

def _tui_typed_keys(key, decoder):
	'''
	The key presses one getch() result completes, in the order they were typed.

	getch() returns a character typed as several bytes (UTF-8 é is c3 a9) one byte at a time. Those
	bytes go through decoder (incremental, errors='surrogateescape') and come back as one str once
	the character is complete. Any other key comes back as its int code, after the bytes of a
	sequence it cut short: those come back as surrogates, which _encode_typed_line sends unchanged.
	'''
	if key == -1:
		return ()
	if 128 <= key <= 255:
		text = decoder.decode(bytes((key,)))
		return (text,) if text else ()
	cut_short = decoder.decode(b'', True)
	decoder.reset()
	return (cut_short, key) if cut_short else (key,)

def __generate_display(stdscr, hosts, lineToDisplay = -1,curserPosition = 0, min_char_len = DEFAULT_WINDOW_WIDTH, min_line_len = DEFAULT_WINDOW_HEIGHT,single_window=DEFAULT_SINGLE_WINDOW,help_shown = False):
	try:
		box_ansi_color = None
		refresh_all = True
		org_dim = stdscr.getmaxyx()
		# To do this, first we need to know the size of the terminal
		max_y, max_x = org_dim
		# we will use one line to print the aggregated stats for the hosts.
		max_y -= 1
		# bound the min_char_len and min_line_len to between 1 and the max_x -1 and max_y -1
		min_char_len_local = min(max(1,min_char_len),max_x-1)
		min_line_len_local = min(max(1,min_line_len),max_y-1)
		if single_window:
			min_char_len_local = max_x-1
			min_line_len_local = max_y-1
		# return True if the terminal is too small
		if max_x < 2 or max_y < 2:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal too small')
		# We need to figure out how many hosts we can fit in the terminal
		# We will need at least 2 lines per host, one for its name, one for its output
		# Each line will be at least 61 characters long (60 for the output, 1 for the borders)
		max_num_hosts_x = max_x // (min_char_len_local + 1)
		max_num_hosts_y = max_y // (min_line_len_local + 1)
		max_num_hosts = max_num_hosts_x * max_num_hosts_y
		hosts_to_display , host_stats, rearrangedHosts = _get_hosts_to_display(hosts, max_num_hosts)
		# Now we calculate the actual number of hosts we will display for x and y
		optimal_len_x = max(min_char_len_local, 80)
		num_hosts_x = min(max(min(max_num_hosts_x, max_x // optimal_len_x),1),len(hosts_to_display))
		num_hosts_y = len(hosts_to_display) // num_hosts_x + (len(hosts_to_display) % num_hosts_x > 0)
		while num_hosts_y > max_num_hosts_y:
			num_hosts_x += 1
			# round up for num_hosts_y
			num_hosts_y = len(hosts_to_display) // num_hosts_x + (len(hosts_to_display) % num_hosts_x > 0)
			if num_hosts_x > max_num_hosts_x:
				num_hosts_x = 1
				num_hosts_y = len(hosts_to_display)
				while num_hosts_y > max_num_hosts_y:
					num_hosts_x += 1
					num_hosts_y = len(hosts_to_display) // num_hosts_x + (len(hosts_to_display) % num_hosts_x > 0)
				break
		num_hosts_y = max(num_hosts_y,1)
		# We calculate the size of each window
		host_window_height = max_y // num_hosts_y
		host_window_width = max_x // num_hosts_x

		old_stat = ''
		old_bottom_stat = ''
		# we refresh the screen every 0.1 seconds
		last_refresh_time = time.perf_counter()
		stdscr.clear()
		global __keyPressesIn
		stdscr.nodelay(True)
		# we generate a stats window at the top of the screen
		stat_window = curses.newwin(1, max_x+1, 0, 0)
		stat_window.leaveok(True)
		# We create a window for each host
		host_windows = []
		for i, host in enumerate(hosts_to_display):
			# We calculate the coordinates of the window
			# We need to add 1 to y for the stats line
			y = (i // num_hosts_x) * host_window_height +1
			x = (i % num_hosts_x) * host_window_width
			# We create the window
			host_window = curses.newwin(host_window_height, host_window_width + 1, y, x)
			host_window.idlok(True)
			host_window.scrollok(True)
			host_window.leaveok(True)
			host_windows.append(host_window)
		# If there is space left, we will draw the bottom border
		bottom_border = None
		if y + host_window_height  < org_dim[0]:
			bottom_border = curses.newwin(1, max_x + 1, y + host_window_height, 0)
			bottom_border.leaveok(True)
			_curses_add_string_to_window(window=bottom_border, y=0, line='-' * (max_x - 1),fill_char='-',box_ansi_color=box_ansi_color)
			bottom_border.refresh()
		help_window_hight = min(14, max_y)
		help_window_width = min(31, max_x)
		# Create a centered help window
		help_window_y = (max_y - help_window_hight) // 2
		help_window_x = (max_x - help_window_width) // 2
		help_window = curses.newwin(help_window_hight, help_window_width, help_window_y, help_window_x)
		help_window.leaveok(True)
		help_window.scrollok(True)
		help_window.idlok(True)
		help_window.box()
		_curses_add_string_to_window(window=help_window,y=0,line='Help', color_pair_list=[-1,-1,1], centered=True, fill_char='─', lead_str='┌', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=1,line='? or F1 : Toggle Help Menu', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=2,line='_ or +  : Change window hight', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=3,line='{ or }  : Change window width', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=4,line='< or >  : Change host index', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=5,line='|(pipe) : Toggle single host', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=6,line='Ctrl+D  : Exit', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=7,line='Ctrl+R  : Force refresh', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=8,line='↑ or ↓  : Navigate history', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=9,line='← or →  : Move cursor', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=10,line='PgUp/Dn : Scroll history by 5', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=11,line='Home/End: Jump cursor', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		_curses_add_string_to_window(window=help_window,y=12,line='Esc     : Clear / hide view', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
		help_panel = curses.panel.new_panel(help_window)
		help_panel.hide()
		curses.panel.update_panels()
		indexOffset = 0
		# collects the bytes of a character typed in several bytes, see _tui_typed_keys
		key_decoder = codecs.getincrementaldecoder(_encoding)(errors='surrogateescape')
		while host_stats['running'] > 0 or host_stats['waiting'] > 0:
			# Check for keypress: an int key code, or a str for a character typed in several bytes (UTF-8)
			for key in _tui_typed_keys(stdscr.getch(), key_decoder):
				# we store the keypresses in a list of lists.
				# Each list is a list of characters to be sent to the stdin of the process at once.
				# When we encounter a newline, we add a new list to the list of lists. ( a new line of input )
				if key == 410 or key == curses.KEY_RESIZE: # 410 is the key code for resize
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal resize requested')    
				# if the user pressed ctrl + d and the last line is empty, we will exit by adding 'exit\n' to the last line
				elif key == 4 and not __keyPressesIn[-1]:
					__keyPressesIn[-1].extend('exit\n')
					__keyPressesIn.append([])
					_typed_lines_changed_notify()
				elif key == 95 and not __keyPressesIn[-1]: # 95 is the key code for _
					# if last line is empty, we will reconfigure the wh to be smaller
					if min_line_len != 1:
						return (lineToDisplay,curserPosition , min_char_len , max(min_line_len -1,1), single_window,help_shown, 'Decrease line length')
				elif key == 43 and not __keyPressesIn[-1]: # 43 is the key code for +
					# if last line is empty, we will reconfigure the wh to be larger
					return (lineToDisplay,curserPosition , min_char_len , min_line_len +1, single_window,help_shown, 'Increase line length')
				elif key == 123 and not __keyPressesIn[-1]: # 123 is the key code for {
					# if last line is empty, we will reconfigure the ww to be smaller
					if min_char_len != 1:
						return (lineToDisplay,curserPosition , max(min_char_len -1,1), min_line_len, single_window,help_shown, 'Decrease character length')
				elif key == 124 and not __keyPressesIn[-1]: # 124 is the key code for |
					# if last line is empty, we will toggle the single window mode
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, not single_window,help_shown, 'Toggle single window mode')
				elif key == 125 and not __keyPressesIn[-1]: # 125 is the key code for }
					# if last line is empty, we will reconfigure the ww to be larger
					return (lineToDisplay,curserPosition , min_char_len +1, min_line_len, single_window,help_shown, 'Increase character length')
				elif key == 60 and not __keyPressesIn[-1]: # 60 is the key code for <
					indexOffset = (indexOffset - 1 ) % len(hosts)
				elif key == 62 and not __keyPressesIn[-1]: # 62 is the key code for >
					indexOffset  = (indexOffset +1 ) % len(hosts)
				# We handle positional keys
				# if the key is up arrow, we will move the line to display up
				elif key == 259: # 259 is the key code for up arrow
					# also scroll curserPosition to last if it is currently at the last line and curserPosition is at 0
					lineToDisplay = max(lineToDisplay - 1, -len(__keyPressesIn))
					if lineToDisplay == -2 and not __keyPressesIn[-1]:
						curserPosition = len(__keyPressesIn[lineToDisplay])
				# if the key is down arrow, we will move the line to display down
				elif key == 258: # 258 is the key code for down arrow
					lineToDisplay = min(lineToDisplay + 1, -1)
				# if the key is left arrow, we will move the cursor left
				elif key == 260: # 260 is the key code for left arrow
					curserPosition = min(max(curserPosition - 1, 0), len(__keyPressesIn[lineToDisplay]) -1)
				# if the key is right arrow, we will move the cursor right
				elif key == 261: # 261 is the key code for right arrow
					curserPosition = max(min(curserPosition + 1, len(__keyPressesIn[lineToDisplay])), 0)
				# if the key is page up, we will move the line to display up by 5 lines
				elif key == 339: # 339 is the key code for page up
					lineToDisplay = max(lineToDisplay - 5, -len(__keyPressesIn))
				# if the key is page down, we will move the line to display down by 5 lines
				elif key == 338: # 338 is the key code for page down
					lineToDisplay = min(lineToDisplay + 5, -1)
				# if the key is home, we will move the cursor to the beginning of the line
				elif key == 262: # 262 is the key code for home
					curserPosition = 0
				# if the key is end, we will move the cursor to the end of the line
				elif key == 360: # 360 is the key code for end
					curserPosition = len(__keyPressesIn[lineToDisplay])
				elif key == curses.KEY_REFRESH or key == curses.KEY_F5 or key == 18: # 18 is the key code for ctrl + R
					# if the key is refresh, we will refresh the screen
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Refresh requested')
				elif key == curses.KEY_EXIT or (key == 27 and lineToDisplay == -1 and not __keyPressesIn[-1]): # 27 is the key code for ESC
					# exit the display on KEY_EXIT, or on ESC when the input line is empty. ESC with input clears the line below
					return
				elif key == curses.KEY_HELP or (key == 63 and not __keyPressesIn[-1]) or key == curses.KEY_F1: # 63 is the key code for ?
					# if the key is help, we will display the help message. Like the other one-character keys, ? toggles
					# it only on an empty input line: after text it is typed (a prompt's answer may need it). F1 always works
					if not help_shown:
						help_panel.show()
						help_shown = True
					else:
						help_panel.hide()
						help_shown = False
						refresh_all = True
					curses.panel.update_panels()
				elif not isinstance(key, str) and key > 255 and key not in (263, 330, curses.KEY_ENTER):
					# a function key without a binding (F2, Insert, ...; 263 Backspace, 330 Delete and KEY_ENTER are handled below):
					# chr() of its code would type an unrelated letter
					pass
			# We are left with these are keys that mofidy the current line.
				else:
					# This means the user have done scrolling and is committing to modify the current line.
					if lineToDisplay  < -1:
						# We overwrite the last line (current working line) with the line to display, removing the newline at the end
						__keyPressesIn[-1] = __keyPressesIn[lineToDisplay][:-1]
						lineToDisplay = -1
					curserPosition = max(0, min(curserPosition, len(__keyPressesIn[lineToDisplay])))
					if key == 10 or key == curses.KEY_ENTER: # 10 is the key code for newline, KEY_ENTER the keypad's Enter
						__keyPressesIn[-1].append('\n')
						__keyPressesIn.append([])
						_typed_lines_changed_notify()
						lineToDisplay = -1
						curserPosition = 0
					# if the key is backspace, we will remove the last character from the last list
					elif key in [8,263]: # 8 is the key code for backspace
						if curserPosition > 0:
							__keyPressesIn[lineToDisplay].pop(curserPosition - 1)
							curserPosition -= 1
					# if the key is ESC, we will clear the last list
					elif key == 27: # 27 is the key code for ESC
						__keyPressesIn[-1] = []
						curserPosition = 0
					elif key in [127, 330]: # 330 is the key code for delete key
						# delete the character at the cursor position
						if curserPosition < len(__keyPressesIn[lineToDisplay]):
							__keyPressesIn[lineToDisplay].pop(curserPosition)
					else:
						# if the key is not a special key, we will add it, one list item per character
						typed = key if isinstance(key, str) else chr(key)
						__keyPressesIn[lineToDisplay][curserPosition:curserPosition] = list(typed)
						curserPosition += len(typed)
			# reconfigure when the terminal size changes
			if org_dim != stdscr.getmaxyx():
				return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal resize detected')
			# We generate the aggregated stats if user did not input anything
			if not __keyPressesIn[lineToDisplay]:
				stats = f"Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} i:{indexOffset} "
			else:
				# we use the stat bar to display the key presses
				encodedLine = _typed_line_for_display(__keyPressesIn[lineToDisplay]).strip('\n') + ' '
				# format the stats line with chracter at curser position inverted using ansi escape sequence
				# displayCurserPosition is needed as the curserPosition can be larger than the length of the encodedLine. This is wanted to keep scrolling through the history less painful
				# it counts the shown text before the cursor: a byte outside the encoding shows as 4 characters (\xe9)
				displayCurserPosition = min(len(_typed_line_for_display(__keyPressesIn[lineToDisplay][:curserPosition])),len(encodedLine) -1)
				stats = f'Send CMD: {encodedLine[:displayCurserPosition]}\x1b[7m{encodedLine[displayCurserPosition]}\x1b[0m{encodedLine[displayCurserPosition + 1:]}'
			if stats != old_stat or refresh_all:
				old_stat = stats
				_curses_add_string_to_window(window=stat_window, y=0, line=stats, color_pair_list=[-1, -1, 1],centered=True,fill_char='━',lead_str='┍',box_ansi_color=box_ansi_color)
				stat_window.refresh()
			if bottom_border:
				bottom_stats = f" Total: {len(hosts)} Running: \x1b[33m{host_stats['running']}\x1b[0m Failed: \x1b[31m{host_stats['failed']}\x1b[0m Finished: \x1b[32m{host_stats['finished']}\x1b[0m Waiting: {host_stats['waiting']} "
				if bottom_stats != old_bottom_stat or refresh_all:
					old_bottom_stat = bottom_stats
					_curses_add_string_to_window(window=bottom_border, y=0, line=bottom_stats,fill_char='─',centered=True,lead_str='└',box_ansi_color=box_ansi_color)
					bottom_border.refresh()
			# set the maximum refresh rate to 100 Hz
			if time.perf_counter() - last_refresh_time < 0.01:
				time.sleep(max(0,0.01 - time.perf_counter() + last_refresh_time))
			if refresh_all:
				rearrangedHosts = set(hosts_to_display)
				refresh_all = False
			hostWindowUpdated = False
			for host_window, host in zip(host_windows, hosts_to_display):
				# we will only update the window if there is new output or the window is not fully printed
				if host in rearrangedHosts:
					linePrintOut = f'{host.name}:[{host.command}]'.replace('\n', ' ').replace('\r', ' ').strip()
					_curses_add_string_to_window(window=host_window, y=0, line=linePrintOut, color_pair_list=[-1, -1, 1],centered=True,fill_char='─',lead_str='┼',box_ansi_color=box_ansi_color)
					# clear the window
					for i in range(host_window_height - 1):
						_curses_add_string_to_window(window=host_window, color_pair_list=[-1, -1, 1], y=i + 1,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
					# drawn whole
					host.printedLines = 0
					host.lastPrintedUpdateTime = 0
					hostWindowUpdated = True
				# the lines added since the last frame, and the lines drawn before that changed. The readers
				# only append: noting each new line's number cost 136 MB per million lines when output came
				# faster than frames
				line_count = len(host.output)
				# output cut since the last frame: the lines added next take the places of drawn ones
				host.printedLines = min(host.printedLines, line_count)
				if host.printedLines < line_count or host.lineNumToPrintSet:
					changed, host.lineNumToPrintSet = host.lineNumToPrintSet, set()
					# visible range: the last host_window_height - 1 lines the window does not leave out
					visibleLowerBound = _tui_first_shown_line(host.output, host_window_height - 1)
					added = range(max(host.printedLines, visibleLowerBound), line_count)
					host.printedLines = line_count
					for lineNumToReprint in sorted(changed.union(added)):
						# if the line is visible, we will reprint it
						if visibleLowerBound <= lineNumToReprint < line_count:
							try:
								line = host.output[lineNumToReprint]
							except IndexError:
								# cut since it was counted (see _cut_output, the -t countdown): the next frame draws
								# what takes its place
								host.lineNumToPrintSet.add(lineNumToReprint)
								continue
							if _tui_leaves_out(line):
								continue
							# each line on its own: one line curses cannot draw must not leave the lines after it blank
							try:
								_curses_add_string_to_window(window=host_window, y=lineNumToReprint + 1, line=line, color_pair_list=host.current_color_pair,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color,fill_char='')
								hostWindowUpdated = True
							except Exception:
								if org_dim != stdscr.getmaxyx():
									return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal resize detected')
				if host.lastPrintedUpdateTime != host.lastUpdateTime and host.output_buffer.tell() > 0:
					# this means there is still output in the buffer, we will print it
					# we will print the output in the window
					_curses_add_string_to_window(window=host_window, y=len(host.output) + 1, line=host.output_buffer.getvalue().decode(_encoding,errors='backslashreplace'), color_pair_list=host.current_color_pair,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color,fill_char='')
					hostWindowUpdated = True
				if hostWindowUpdated:
					maxY, _ = host_window.getmaxyx()
					host_window.vline(1, 0, curses.ACS_VLINE, maxY - 1)
				host_window.noutrefresh()
				host.lastPrintedUpdateTime = host.lastUpdateTime
			hosts_to_display, host_stats,rearrangedHosts = _get_hosts_to_display(hosts, max_num_hosts,hosts_to_display, indexOffset)
			# a host coming into a window is drawn whole: the lines noted for hosts without one would only
			# pile up, one entry per line of their output
			shown = set(hosts_to_display)
			for host in hosts:
				if host.lineNumToPrintSet and host not in shown:
					host.lineNumToPrintSet = set()
			if help_shown:
				help_window.touchwin()
				help_window.noutrefresh()
			curses.doupdate()
			hostWindowUpdated = False
			last_refresh_time = time.perf_counter()
	except Exception as e:
		import traceback
		return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, f'Error: {str(e)}',traceback.format_exc())
	return None

def curses_print(stdscr, hosts, threads, min_char_len = DEFAULT_WINDOW_WIDTH, min_line_len = DEFAULT_WINDOW_HEIGHT,single_window = DEFAULT_SINGLE_WINDOW):
	'''
	Print the output of the hosts on the screen

	Args:
		stdscr (curses.window): The curses window to print the output
		hosts (list): A list of Host objects
		threads (list): A list of threads that are running the commands

	Returns:
		None
	'''
	# We create all the windows we need
	# We initialize the color pair
	curses.curs_set(0)
	curses.start_color()
	curses.use_default_colors()
	curses.init_pair(1, -1, -1)
	# do not generate display if the output window have a size of zero
	if stdscr.getmaxyx()[0] < 2 or stdscr.getmaxyx()[1] < 2:
		return
	stdscr.idlok(True)
	stdscr.scrollok(True)
	stdscr.leaveok(True)
	# generate some debug information before display initialization
	try:
		stdscr.clear()
		_curses_add_string_to_window(window=stdscr, y=0, line='Initializing display...', number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the size
		_curses_add_string_to_window(window=stdscr, y=1, line=f"Terminal size: {stdscr.getmaxyx()}",number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the number of hosts
		_curses_add_string_to_window(window=stdscr, y=2, line=f"Number of hosts: {len(hosts)}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the number of threads
		_curses_add_string_to_window(window=stdscr, y=3, line=f"Number of threads: {len(threads)}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the minimum character length
		_curses_add_string_to_window(window=stdscr, y=4, line=f"Minimum character length: {min_char_len}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the minimum line length
		_curses_add_string_to_window(window=stdscr, y=5, line=f"Minimum line length: {min_line_len}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print the single window mode
		_curses_add_string_to_window(window=stdscr, y=6, line=f"Single window mode: {single_window}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print COLORS and COLOR_PAIRS count
		_curses_add_string_to_window(window=stdscr, y=7, line=f"len(COLORS): {curses.COLORS} len(COLOR_PAIRS): {curses.COLOR_PAIRS}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		# print if can change color
		_curses_add_string_to_window(window=stdscr, y=8, line=f"Real color capability: {curses.can_change_color()}", number_of_char_to_write=stdscr.getmaxyx()[1] - 1)
		stdscr.refresh()
	except Exception:
		pass
	params = (-1,0 , min_char_len, min_line_len, single_window,False)
	while params:
		params = __generate_display(stdscr, hosts, *params)
		if not params:
			break
		if not any([host.returncode is None for host in hosts]):
			# this means no hosts are running
			break
		# print the current configuration
		stdscr.clear()
		try:
			stdscr.addstr(0, 0, f"{params[6]}, Reloading Configuration: min_char_len={params[2]}, min_line_len={params[3]}, single_window={params[4]} with window size {stdscr.getmaxyx()} and {len(hosts)} hosts...")
			if len(params) > 7:
				# traceback is available, print it
				i = 1
				for line in params[7].split('\n'):
					stdscr.addstr(i, 0, line)
					i += 1
			stdscr.refresh()
		except Exception:
			pass
		params = params[:6]
		time.sleep(0.01)

#%% ------------ Generate Output Block ----------------
def can_merge(line_bag1, line_bag2, threshold):
	if threshold > 0.5:
		# quick reject when none of a few items of the smaller bag is in the other. Taking one item more
		# than the smaller bag may lack and still merge, the answer is always the count's below, whichever
		# items the set yields first (an order that changes from run to run)
		smaller, larger = (line_bag1, line_bag2) if len(line_bag1) <= len(line_bag2) else (line_bag2, line_bag1)
		sample_count = len(smaller) - math.ceil(len(smaller) * threshold) + 1
		if not larger.intersection(itertools.islice(smaller, sample_count)):
			return False
	return len(line_bag1.intersection(line_bag2)) >= min(len(line_bag1),len(line_bag2)) * threshold

def mergeOutput(merging_hostnames,outputs_by_hostname,output,diff_display_threshold,line_length,longest_output = None):
	# indexes keeps the hosts in natural order: min() below takes the first of the hosts furthest
	# behind, so lines only some hosts printed come in host order, not in the random order of a set
	merging_hostnames = sorted(merging_hostnames, key=_natural_sort_key)
	indexes = Counter({hostname: 0 for hostname in merging_hostnames})
	working_index_keys = set(merging_hostnames)
	previousBuddies = set()
	hostnameWrapper = textwrap.TextWrapper(width=line_length -1, tabsize=4, replace_whitespace=False, drop_whitespace=False, break_on_hyphens=False,initial_indent=' ', subsequent_indent='- ')
	hostnameWrapper.wordsep_simple_re = re.compile(r'([,]+)')
	# the look ahead is a share of the longest output of all hosts: longest_output (its number of lines) when
	# outputs_by_hostname holds only the merging hosts'
	if longest_output is None:
		longest_output = max(map(len, outputs_by_hostname.values()))
	diff_display_item_count = max(1,int(longest_output * (1 - diff_display_threshold)))
	def get_multiset_index_for_hostname(hostname):
		index = indexes[hostname]
		tracking_index = min(index + diff_display_item_count,len(outputs_by_hostname[hostname]))
		tracking_iter = itertools.islice(outputs_by_hostname[hostname], tracking_index)
		return [deque(outputs_by_hostname[hostname][index:tracking_index],maxlen=diff_display_item_count),tracking_iter]
	def advance(dict,key):
		try:
			value = dict[key]
			value[0].append(next(value[1]))
		except StopIteration:
			try:
				value[0].popleft()
			except IndexError:
				pass
		except KeyError:
			pass
	futures = {hostname: get_multiset_index_for_hostname(hostname) for hostname in merging_hostnames}
	currentLines = defaultdict(set)
	color_cap = get_terminal_color_capability()
	if color_cap == 'None':
		green_str = ''
		underline_bold_str = ''
		reset_str = ''
	else:
		green_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('green', __DEFAULT_COLOR_PALETTE['green']))
		underline_bold_str = '\033[4m\033[1m'
		reset_str = '\033[0m'
	for hostname in merging_hostnames:
		currentLines[outputs_by_hostname[hostname][0]].add(hostname)
	while indexes:
		defer = False
		if len(working_index_keys) == len(indexes):
			golden_hostname = min(indexes, key=indexes.get)
		else:
			golden_hostname = min(filter(working_index_keys.__contains__, indexes), key=indexes.get)
		golden_index = indexes[golden_hostname]
		lineToAdd = outputs_by_hostname[golden_hostname][golden_index]
		buddy = currentLines[lineToAdd].copy()
		if len(buddy) < len(working_index_keys):
			# we need to check the futures then
			if any(lineToAdd in futures[hostname][0] for hostname in working_index_keys - buddy):
				defer = True
				working_index_keys -= buddy
		if not defer:
			if buddy != previousBuddies:
				hostnameStr = ','.join(_compact_shown(buddy))
				hostnameLines = hostnameWrapper.wrap(hostnameStr)
				if len(buddy) < len(merging_hostnames):
					color = int_to_unique_ansi_color(hash(hostnameStr))
					hostnameLines[0] = f"{color}■{hostnameLines[0]}"
				else:
					hostnameLines[0] = f"{green_str}{underline_bold_str}■{hostnameLines[0]}"
				hostnameLines[-1] += reset_str
				output.extend(hostnameLines)
				previousBuddies = buddy
			output.append(lineToAdd)
			currentLines[lineToAdd].difference_update(buddy)
			if not currentLines[lineToAdd]:
				del currentLines[lineToAdd]
			indexes.update(buddy)
			for hostname in buddy:
				try:
					currentLines[outputs_by_hostname[hostname][indexes[hostname]]].add(hostname)
				except IndexError:
					indexes.pop(hostname, None)
					futures.pop(hostname, None)
					continue
				#advance futures
				advance(futures, hostname)
			working_index_keys = set(indexes.keys())

def mergeOutputs(outputs_by_hostname, merge_groups, remaining_hostnames, diff_display_threshold, line_length):
	pieces_by_hostname = {hostname: [('', lines)] for hostname, lines in outputs_by_hostname.items()}
	return _host_lines(_merged_output_pieces(pieces_by_hostname, merge_groups, remaining_hostnames, diff_display_threshold, line_length))

def _merged_output_pieces(pieces_by_hostname, merge_groups, remaining_hostnames, diff_display_threshold, line_length):
	'''
	mergeOutputs' lines as pieces of (prefix, lines), made as they are read, from the hosts' pieces (see
	_host_output_pieces): the lines of a host that merged with none are its own, not a copy.
	'''
	color_cap = get_terminal_color_capability()
	if color_cap == 'None':
		color_line = ''
		color_reset = ''
		green_str = ''
		underline_bold_str = ''
	else:
		color_line =  rgb_to_ansi_color_string(*COLOR_PALETTE.get('white', __DEFAULT_COLOR_PALETTE['white']))
		color_reset = '\033[0m'
		green_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('green', __DEFAULT_COLOR_PALETTE['green']))
		underline_bold_str = '\033[4m\033[1m'
	# before each group or host, none after the last
	divider = ('', [color_line+'─'*(line_length)+color_reset])
	hostnameWrapper = textwrap.TextWrapper(width=line_length - 1, tabsize=4, replace_whitespace=False, drop_whitespace=False, break_on_hyphens=False,initial_indent=' ', subsequent_indent='- ')
	hostnameWrapper.wordsep_simple_re = re.compile(r'([,]+)')
	if merge_groups:
		longest_output = max(sum(len(lines) for _prefix, lines in pieces) for pieces in pieces_by_hostname.values())
	# groups, then the hosts that merged with none, each in natural host order (node2 before node10)
	for merging_hostnames in sorted(merge_groups, key=lambda group: min(map(_natural_sort_key, group))):
		output = []
		# mergeOutput compares the lines as they print: only the group's hosts' are copied with their indent
		mergeOutput(merging_hostnames, {hostname: _host_lines(pieces_by_hostname[hostname]) for hostname in merging_hostnames},
			output, diff_display_threshold, line_length, longest_output)
		yield divider
		yield ('', output)
	for hostname in sorted(remaining_hostnames, key=_natural_sort_key):
		hostnameLines = hostnameWrapper.wrap(hostname)
		hostnameLines[0] = f"{green_str}{underline_bold_str}■{hostnameLines[0]}"
		hostnameLines[-1] += color_reset
		yield divider
		yield ('', hostnameLines)
		yield from pieces_by_hostname[hostname]

def pre_merge_hosts(hosts):
	'''
	Merge hosts with identical outputs.

	Note: After merging, the surviving host's `.name` is rewritten to a comma-joined
	`compact_hostnames_local(...)` summary of the group (e.g. `node[1-3]`). Callers that need
	per-host identity after merge should snapshot names beforehand; this rewrite is
	intentional for compact human-readable summaries.
	'''
	output_groups = defaultdict(list)
	# Group hosts by their output identity
	for host in hosts:
		identity = host.get_output_hash()
		output_groups[identity].append(host)
	for group in output_groups.values():
		group[0].name = ','.join(compact_hostnames_local(host.name for host in group))
		for i in range(1,len(group)):
			hosts.remove(group[i])
	return hosts

_SSH_CONNECT_ERROR = re.compile(r'ssh: connect to host (\S+) port (\S+): (.+)')
# ssh's reason: the summary the pretty output shows for it
_SSH_CONNECT_ERROR_SUMMARIES = {
	'Connection refused': 'SSH not reachable!',
	'Connection timed out': 'SSH connection timed out!',
	'No route to host': 'Cannot find host!',
}

def _ssh_connect_error(line):
	'''
	Split ssh's own "ssh: connect to host HOST port PORT: REASON" line into (host, port, reason).

	Returns None for any other line, such as a remote program's error ending with the same reason.
	'''
	match = _SSH_CONNECT_ERROR.fullmatch(line.strip())
	return match.groups() if match else None

def _displayed_stderr(host):
	'''
	The stderr lines the pretty output shows for host.

	When ssh could not connect (it exits 255 right after saying why), its line is shown as a summary
	without the host name, so unreachable hosts merge into one block: "SSH connection timed out!
	(port 22: Connection timed out)". host.stderr keeps ssh's line for JSON and greppable output.
	'''
	if host.returncode != 255 or not host.stderr:
		return host.stderr
	connect_error = _ssh_connect_error(host.stderr[-1])
	if not connect_error or connect_error[2] not in _SSH_CONNECT_ERROR_SUMMARIES:
		return host.stderr
	_address, port, reason = connect_error
	summary = '{} (port {}: {})'.format(_SSH_CONNECT_ERROR_SUMMARIES[reason], port, reason)
	return host.stderr[:-1] + [summary]

def get_host_raw_output(hosts, terminal_width):
	'''
	Each host's lines in the pretty output, as _host_output_pieces makes them but as one list per host
	(its stdout and stderr lines copied with their indent), and what goes with them.
	'''
	pieces_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, line_bag_lens, line_length = _host_output_pieces(hosts, terminal_width)
	outputs_by_hostname = {hostname: _host_lines(pieces) for hostname, pieces in pieces_by_hostname.items()}
	return outputs_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, line_bag_lens, line_length

def _host_lines(pieces):
	'''The lines of pieces of (prefix, lines) (see _host_output_pieces) as one list, each with its prefix.'''
	lines = []
	for prefix, piece in pieces:
		if prefix:
			lines.extend(prefix + line for line in piece)
		else:
			lines.extend(piece)
	return lines

def _line_chunks(pieces, batch_lines = 1000):
	'''
	The text of pieces of (prefix, lines), each line with its prefix in front and a newline after, in chunks of
	up to batch_lines lines: written one after the other, they never take the memory of the whole text.
	'''
	for prefix, lines in pieces:
		separator = '\n' + prefix
		for start in range(0, len(lines), batch_lines):
			yield prefix + separator.join(lines[start:start + batch_lines]) + '\n'

def _host_output_pieces(hosts, terminal_width):
	'''
	Each host's lines in the pretty output, its line bag for merging, the host names by the size of their
	line bags, those sizes in order, and the width of the output's dividers.

	A host's lines are pieces of (prefix, lines): its stdout and stderr lines are pieces of their own, with
	the one space indent as their prefix, so they are written as they are (_line_chunks) instead of copied
	with the indent in front of each (as much memory again as the output).
	'''
	pieces_by_hostname = {}
	line_bag_by_hostname = {}
	hostnames_by_line_bag_len = {}
	# a narrower terminal gets a 20 column layout and wraps its lines itself: the headers ('█ EXECUTED COMMAND:')
	# need 19, and textwrap fails below 2 columns and never returns at 2 (the '- ' host name indent of mergeOutputs)
	terminal_width = max(terminal_width, 20)
	wrap = functools.partial(_wrap_columns, width=terminal_width - 1, tabsize=4, replace_whitespace=False,
		drop_whitespace=False, initial_indent=' ', subsequent_indent='-')
	max_length = 20
	color_cap = get_terminal_color_capability()
	if color_cap == 'None':
		color_reset_str = ''
		blue_str = ''
		cyan_str = ''
		green_str = ''
		red_str = ''
	else:
		color_reset_str = '\033[0m'
		blue_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('blue', __DEFAULT_COLOR_PALETTE['blue']))
		cyan_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('bright_cyan', __DEFAULT_COLOR_PALETTE['bright_cyan']))
		green_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('bright_green', __DEFAULT_COLOR_PALETTE['bright_green']))
		red_str = rgb_to_ansi_color_string(*COLOR_PALETTE.get('bright_red', __DEFAULT_COLOR_PALETTE['bright_red']))
	for host in hosts:
		max_length = max(max_length, len(max(host.name.split(','), key=len)) + 3)
		commandLines = [f"{cyan_str}█{color_reset_str} EXECUTED COMMAND:"]
		for line in host.command.splitlines():
			commandLines.extend(wrap(line))
		hostPrintOut = [('', commandLines)]
		lineBag = {(0,host.command)}
		prevLine = host.command
		if host.stdout:
			hostPrintOut.append(('', [f'{blue_str}▓{color_reset_str} STDOUT:']))
			hostPrintOut.append((' ', host.stdout))
			# in terminal columns: the dividers between host blocks are as wide as the widest line
			max_length = max(max_length, max(map(_text_columns, host.stdout)))
			lineBag.add((prevLine,1))
			lineBag.add((1,host.stdout[0]))
			if len(host.stdout) > 1:
				lineBag.update(zip(host.stdout, host.stdout[1:]))
			lineBag.update(host.stdout)
			prevLine = host.stdout[-1]
		stderr = _displayed_stderr(host)
		if stderr:
			hostPrintOut.append(('', [f'{red_str}▒{color_reset_str} STDERR:']))
			hostPrintOut.append((' ', stderr))
			max_length = max(max_length, max(map(_text_columns, stderr)))
			lineBag.add((prevLine,2))
			lineBag.add((2,stderr[0]))
			lineBag.update(stderr)
			if len(stderr) > 1:
				lineBag.update(zip(stderr, stderr[1:]))
			prevLine = stderr[-1]
		if host.returncode != 0:
			codeColor = red_str
		else:
			codeColor = green_str
		hostPrintOut.append(('', [f"{codeColor}░{color_reset_str} RETURN CODE: {host.returncode}"]))
		lineBag.add((prevLine,f"{host.returncode}"))
		pieces_by_hostname[host.name] = hostPrintOut
		line_bag_by_hostname[host.name] = lineBag
		hostnames_by_line_bag_len.setdefault(len(lineBag), set()).add(host.name)
	return pieces_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, sorted(hostnames_by_line_bag_len), min(max_length+2,terminal_width)

def form_merge_groups(hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_bag_by_hostname, diff_display_threshold):
	merge_groups = []
	remaining_hostnames = set()
	for lbl_i, line_bag_len in enumerate(sorted_hostnames_by_line_bag_len_keys):
		# in natural order, not a set's: which hosts form a group depends on the host it starts from
		for this_hostname in sorted(hostnames_by_line_bag_len.get(line_bag_len, ()), key=_natural_sort_key):
			try:
				this_line_bag = line_bag_by_hostname.pop(this_hostname)
				hostnames_by_line_bag_len.get(line_bag_len, set()).discard(this_hostname)
			except KeyError:
				continue
			target_threshold = line_bag_len * (2 - diff_display_threshold)
			merge_group = []
			for other_line_bag_len in sorted_hostnames_by_line_bag_len_keys[lbl_i:]:
				if other_line_bag_len > target_threshold:
					break
				for other_hostname in hostnames_by_line_bag_len.get(other_line_bag_len, set()).copy():
					if other_hostname in line_bag_by_hostname and can_merge(this_line_bag, line_bag_by_hostname[other_hostname], diff_display_threshold):
						merge_group.append(other_hostname)
						hostnames_by_line_bag_len[other_line_bag_len].remove(other_hostname)
						if not hostnames_by_line_bag_len[other_line_bag_len]:
							del hostnames_by_line_bag_len[other_line_bag_len]
						del line_bag_by_hostname[other_hostname]
			if merge_group:
				merge_group.append(this_hostname)
				merge_groups.append(merge_group)
			else:
				remaining_hostnames.add(this_hostname)
	return merge_groups, remaining_hostnames

def generate_output(hosts, usejson = False, greppable = False,quiet = False,encoding = _encoding,keyPressesIn = None, errors_only = None):
	'''
	Format Host results for display / return.

	Args:
		hosts: Host objects to format
		usejson: Emit JSON list of host dicts
		greppable: Emit a greppable table
		quiet: Historical alias for errors_only — when True (and errors_only is
			None), drop hosts with returncode==0. Kept for API stability; prefer
			errors_only. Not the same as CLI `--quiet` / suppressing printouts.
		encoding: Output encoding for user-input display
		keyPressesIn: Recorded keypress sequences for greppable footers
		errors_only: When True, drop hosts with returncode==0 and emit only
			failures (or a short "Success" if none failed). When None (default),
			defer to quiet. Matches CLI `--error_only` semantics for formatting.
	'''
	return ''.join(_output_chunks(hosts, usejson, greppable, quiet, encoding, keyPressesIn, errors_only))

def _output_chunks(hosts, usejson, greppable, quiet, encoding, keyPressesIn, errors_only):
	'''
	generate_output's text in chunks, each made when it is asked for: mssh writes them as they come
	(_stream_output), and the whole text is never in memory at once.
	'''
	if errors_only is None:
		errors_only = quiet
	if keyPressesIn is None:
		keyPressesIn = [[]]
	color_cap = get_terminal_color_capability()
	if errors_only:
		# remove hosts with returncode 0
		hosts = [host for host in hosts if host.returncode != 0]
		if not hosts:
			if usejson:
				yield '{"Success": true}'
			else:
				if color_cap == 'None':
					yield 'Success'
				else:
					yield '\033[32mSuccess\033[0m'
			return
	if usejson:
		# json.dumps of the list of host dicts, a host at a time: in the list, a host's text is indented 4 more
		# spaces after each newline (a JSON string holds no newline of its own)
		empty = True
		for host in hosts:
			yield '[\n    ' if empty else ',\n    '
			yield json.dumps(dict(host),indent=4).replace('\n', '\n    ')
			empty = False
		yield '[]' if empty else '\n]'
	elif greppable:
		yield '*'*80+'\n'
		# the table pads the first three columns only: padded to the longest output line, every other line
		# and divider was written out to its length (seq 1 10000 and one 5000 character line: 50 MB of spaces).
		# All lines of a host's stdout (or stderr) have the same first three cells: a row for each is enough to
		# have pretty_format_table pad them as it would in the table of every line
		rtnList = [['host_name','return_code','output_type','output']]
		outputs = []
		for host in hosts:
			if host.stdout:
				rtnList.append([host.name,f"rc: {host.returncode}",'stdout',''])
				outputs.append(host.stdout)
			if host.stderr:
				rtnList.append([host.name,f"rc: {host.returncode}",'stderr',''])
				outputs.append(host.stderr)
			if not host.stdout and not host.stderr:
				rtnList.append([host.name,f"rc: {host.returncode}",'N/A',''])
				outputs.append(['<EMPTY>'])
			rtnList.append(['','','',''])
			outputs.append(None)
		table = pretty_format_table(rtnList).split('\n')
		yield table[0] + '\n' + table[1] + '\n'
		for line, lines in zip(table[2:], outputs):
			if lines is None:
				# a divider row stays as it is
				yield line + '\n'
			else:
				yield from _line_chunks([(line.rstrip(' ') + ' ', lines)])
		yield '*'*80+'\n'
		if keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode(encoding=encoding,errors='backslashreplace').decode(encoding=encoding,errors='backslashreplace').replace('\\n', '↵') for cmd in keyPressesIn if cmd]
			yield 'User Inputs: '+ '\nUser Inputs: '.join(CMDsOut)
	else:
		try:
			diff_display_threshold = float(DEFAULT_DIFF_DISPLAY_THRESHOLD)
			if diff_display_threshold < 0 or diff_display_threshold > 1:
				raise ValueError
		except Exception:
			eprint("Warning: diff_display_threshold should be a float between 0 and 1. Setting to default value of 0.9")
			diff_display_threshold = 0.9
		
		color_reset_str = '' if color_cap == 'None' else '\033[0m'
		white_str = '' if color_cap == 'None' else rgb_to_ansi_color_string(*COLOR_PALETTE.get('white', __DEFAULT_COLOR_PALETTE['white']))
		terminal_length = get_terminal_size()[0]
		pieces_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_length = _host_output_pieces(hosts,terminal_length)
		merge_groups ,remaining_hostnames = form_merge_groups(hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_bag_by_hostname, diff_display_threshold)
		# the typed keys, after the hosts' lines
		cmdOut = []
		if keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode(encoding=encoding,errors='backslashreplace').decode(encoding=encoding,errors='backslashreplace').replace('\\n', '↵') for cmd in keyPressesIn if cmd]
			cmdOut.append(color_reset_str + "░ User Inputs:".ljust(line_length,'─'))
			for line in CMDsOut:
				cmdOut.extend(_wrap_columns(line, width=line_length-1, tabsize=4, replace_whitespace=False, drop_whitespace=False,
									 initial_indent=' ', subsequent_indent='-'))
			keyPressesIn[-1].clear()
		if not merge_groups and not remaining_hostnames and not cmdOut:
			if errors_only:
				if color_cap == 'None':
					yield 'Success'
				else:
					yield '\033[32mSuccess\033[0m'
			return
		outputs = _merged_output_pieces(pieces_by_hostname, merge_groups, remaining_hostnames, diff_display_threshold, line_length)
		yield from _line_chunks(itertools.chain(outputs, [('', cmdOut)]))
		yield white_str + '─' * (line_length) + color_reset_str

# ssh's own last word when no login method worked: "bob@node1: Permission denied (publickey,password)."
# Remote output can hold any line: no part may match an '@' or the ':', so a long line of them costs linear
# time (a user name with an '@' in it gets no note). Use it anchored (fullmatch / match): search() retries at
# every start and rescans a long word each time, seconds for one 100 kB line
_SSH_PERMISSION_DENIED = re.compile(r'([^\s@]+)@([^\s@:]+): Permission denied \(([^)]*)\)\.')

def _note_unasked_passwords(hosts, password):
	'''
	After the output, say once which hosts' ssh wanted a password it had no terminal to ask for (see
	Host.use_terminal), and what to do instead.

	Only when ssh's line names the host itself: an ssh run by the command, or a jump host, is not the
	one mssh started. Not with -p, where sshpass answered and the password was wrong.
	'''
	if os.name != 'posix' or (password and 'sshpass' in _binPaths):
		return
	names = []
	for host in hosts:
		if host.use_terminal or host.ipmi or host.shell or not host.returncode:
			continue
		target = host.name.rsplit('@', 1)[-1].lower()
		for line in host.stderr:
			denied = 'Permission denied (' in line and _SSH_PERMISSION_DENIED.fullmatch(line.strip())
			if denied and denied.group(2).lower() == target and {'password', 'keyboard-interactive'} & set(denied.group(3).split(',')):
				names.append(host.name)
				break
	if names:
		# a key's passphrase it could not ask for leaves the same line: the key is skipped, password is next
		eprint('Note: ssh could not ask for the password (or key passphrase) of {}: it may ask only when one command '
			'runs at a time without the curses display. Use -p, an ssh key (ssh-agent), or -nw -m 1 to type each one.'.format(
			','.join(compact_hostnames(names))))

def print_output(hosts,usejson = False,quiet = False,greppable = False):
	'''
	Print / generate the output of the hosts to the terminal

	Args:
		hosts (list): A list of Host objects
		usejson (bool, optional): Whether to print the output in JSON format. Defaults to False.
		quiet (bool, optional): Whether to print the output. Defaults to False.

	Returns:
		str: The pretty output generated 
	'''
	global __global_suppress_printout
	global _encoding
	global __keyPressesIn
	for host in hosts:
		host.output.clear()
	rtnStr = generate_output(hosts,usejson,greppable,encoding=_encoding,keyPressesIn=__keyPressesIn,errors_only=__global_suppress_printout)
	if not quiet:
		try:
			# flushed now: a reader that is gone fails here, not in the flush at exit
			print(rtnStr, flush=True)
		except BrokenPipeError:
			_output_reader_gone()
	return rtnStr

def _stream_output(hosts,usejson = False,greppable = False):
	'''
	print_output for mssh's own run: the output goes to stdout a chunk at a time as it is made, instead of
	being made into one string first, then encoded whole to print (more memory than the hosts' output itself
	takes, several times over). Prints the same text, returns nothing.
	'''
	for host in hosts:
		host.output.clear()
	chunks = _output_chunks(hosts,usejson,greppable,False,_encoding,__keyPressesIn,__global_suppress_printout)
	try:
		for chunk in chunks:
			# stdout closed when mssh started (>&-): as print, write nothing
			if sys.stdout is not None:
				sys.stdout.write(chunk)
		# print's newline, flushed now: a reader that is gone fails here, not in the flush at exit
		print(flush=True)
	except BrokenPipeError:
		# what is left is not made: nobody would read it
		_output_reader_gone()

def _output_reader_gone():
	'''
	Stop quietly when whatever reads our output has gone (mssh ... | head, or q in less).

	Like a program SIGPIPE ends: no traceback, and no more commands or repeats start. What ran
	still counts towards the exit code, as after a Ctrl-C between runs. stdout, and stderr when
	it is the same pipe (2>&1), are pointed at devnull as the Python docs suggest, so later
	writes and the flush at exit do not fail again.
	'''
	global _emo
	_emo = True
	try:
		stdout_fd = sys.stdout.fileno()
		fds = [stdout_fd]
		try:
			if os.path.sameopenfile(stdout_fd, sys.stderr.fileno()):
				fds.append(sys.stderr.fileno())
		except (OSError, ValueError, AttributeError):
			pass
		devnull = os.open(os.devnull, os.O_WRONLY)
		try:
			for fd in fds:
				os.dup2(devnull, fd)
		finally:
			os.close(devnull)
	except (OSError, ValueError, AttributeError):
		# not a file descriptor (an embedding program's stream): nothing to redirect
		pass

#%% ------------ Run / Process Hosts Block ----------------
def _private_dir(path):
	'''
	Return True if path is a directory only we control, creating it (mode 0700).

	A directory in a shared place like /tmp could have been created by someone else first,
	so it must not be a symlink, must be owned by us and must not be accessible to others.
	'''
	try:
		os.mkdir(path, 0o700)
	except FileExistsError:
		pass
	except OSError:
		return False
	try:
		st = os.lstat(path)
	except OSError:
		return False
	if not stat.S_ISDIR(st.st_mode):
		return False
	if not hasattr(os, 'getuid'):
		return True
	if st.st_uid != os.getuid():
		return False
	if st.st_mode & 0o022:
		# others could already have put files in it
		return False
	if st.st_mode & 0o077:
		# ours but readable by others (an older tool or the user made it), tighten it
		try:
			os.chmod(path, 0o700)
			st = os.lstat(path)
		except OSError:
			return False
	return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077

def _owned_and_not_writable_by_others(path):
	'''Whether path exists, is owned by us and only we can write to it.'''
	if not hasattr(os, 'getuid'):
		return True
	try:
		st = os.stat(path)
	except OSError:
		return False
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

# where logind makes per-user runtime directories, and the tmpfs every Linux mounts (tests point them elsewhere)
_RUN_USER_ROOT = '/run/user'
_SHM_DIR = '/dev/shm'

def runtime_dir(create=True):
	'''
	mssh's private directory for state that must not outlive a reboot, or None to run without it.

	Reading and writing set it up alike, so a read never finds a later place (an older session's
	state, or this machine's own when $XDG_RUNTIME_DIR is set to a new directory). create is ignored:
	callers written for 6.38, when a read could ask for no change on disk, still work.

	The first of these that is a directory only we control (_private_dir):
	1. $XDG_RUNTIME_DIR/multiSSH3, when $XDG_RUNTIME_DIR is ours and only we can write to it
	2. /run/user/<uid>/multiSSH3, the same place when su, sudo -u or cron leave $XDG_RUNTIME_DIR unset
	3. /dev/shm/multiSSH3-<uid>: tmpfs, so local and cleared at reboot, and there without a login session
	4. <tempdir>/multiSSH3-<uid>: may survive a reboot, so state with a time in it carries the boot id
	The home directory is avoided so mssh keeps working when it is full or read-only.
	mssh_complete.cache_dir picks the same directory.
	'''
	user_id = os.getuid() if hasattr(os, 'getuid') else getpass.getuser()
	candidates = []
	xdg_runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
	# with another user's environment (sudo -E, su) the runtime dir is theirs, they could swap our subdirectory
	if xdg_runtime_dir and _owned_and_not_writable_by_others(xdg_runtime_dir):
		candidates.append(os.path.join(xdg_runtime_dir, 'multiSSH3'))
	if hasattr(os, 'getuid'):
		run_user = os.path.join(_RUN_USER_ROOT, str(user_id))
		if _owned_and_not_writable_by_others(run_user):
			candidates.append(os.path.join(run_user, 'multiSSH3'))
		if os.path.isdir(_SHM_DIR):
			candidates.append(os.path.join(_SHM_DIR, 'multiSSH3-{}'.format(user_id)))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
		if _private_dir(directory):
			return directory
	return None

def _unavailable_hosts_file_path(create=True):
	'''
	Where unavailable hosts are cached between runs (in runtime_dir), or None to run without the cache.
	create is ignored: callers written for 6.38 still work.
	'''
	directory = runtime_dir()
	return os.path.join(directory, 'unavailable_hosts.csv') if directory else None


def _get_boot_id():
	'''
	Get an identifier unique to the current boot

	Expiry times in the unavailable hosts file come from time.monotonic(), which restarts
	at every boot, so they only mean something within the boot that wrote them.

	Returns:
		str: The boot id, or None if the platform does not provide one
	'''
	try:
		with open('/proc/sys/kernel/random/boot_id', 'r') as f:
			return f.read().strip() or None
	except Exception:
		return None


def _read_unavailable_hosts_file(path, now=None, max_ttl=None):
	'''
	Read the unavailable hosts file, discarding it if it was written during a previous boot.

	A file whose '#boot_id' header does not match the current boot is from a previous boot.
	Without a boot id to compare, an entry with more than max_ttl seconds left can only come
	from a monotonic clock that has since restarted, so the file is treated as stale.
	'''
	current_time = time.monotonic() if now is None else now
	result = {}
	file_boot_id = None
	exceeds_ttl = False
	try:
		with open(path, "r") as handle:
			for raw_line in handle:
				parts = raw_line.strip().split(",")
				if len(parts) == 2 and parts[0] == "#boot_id":
					file_boot_id = parts[1]
					continue
				if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
					continue
				expiry = int(parts[1])
				if max_ttl and max_ttl > 0 and expiry - current_time > max_ttl:
					exceeds_ttl = True
				if expiry > current_time:
					result[parts[0]] = expiry
	except FileNotFoundError:
		return {}
	except Exception as exc:
		eprint("Warning: Unable to read unavailable hosts from {!r}: {}".format(path, exc))
	current_boot_id = _get_boot_id()
	if current_boot_id and file_boot_id:
		stale = file_boot_id != current_boot_id
	else:
		stale = exceeds_ttl
	if stale:
		try:
			os.unlink(path)
		except OSError:
			pass
		return {}
	return result


def _write_unavailable_hosts_file(path, unavailable_hosts, available_hosts=(), now=None):
	current_time = time.monotonic() if now is None else now
	available = set(available_hosts)
	clean = {
		host: int(expiry)
		for host, expiry in unavailable_hosts.items()
		if host not in available and int(expiry) > current_time
	}
	if not path:
		# no private place for the cache, keep the state in memory only
		return clean
	boot_id = _get_boot_id()
	temporary_path = "{}.{}".format(path, uuid4().hex)
	try:
		with open(temporary_path, "w") as handle:
			if boot_id:
				handle.write("#boot_id,{}\n".format(boot_id))
			for host in sorted(clean):
				handle.write("{},{}\n".format(host, clean[host]))
			handle.flush()
			os.fsync(handle.fileno())
		os.replace(temporary_path, path)
	except Exception as exc:
		# the cache is optional, a full or read-only disk must not warn on every run
		if __DEBUG_MODE:
			eprint("Error writing unavailable hosts to {!r}: {}".format(path, exc))
		try:
			if os.path.exists(temporary_path):
				os.unlink(temporary_path)
		except OSError:
			pass
	return clean


# reasons in ssh's connect error that mean nothing answered (Connection refused: the host did)
_SSH_UNREACHABLE_REASONS = ('No route to host', 'Connection timed out')
# older OpenSSH's message when a ProxyJump host cannot reach the target
_SSH_JUMP_UNREACHABLE = re.compile(r'channel \d+: open failed: connect failed: (?:No route to host|Connection timed out)')
# OpenSSH 8.2+ when ssh's ConnectTimeout runs out after the host took the connection but before its
# sshd said a word; the next line names the address (UNKNOWN through a ProxyJump)
_SSH_BANNER_TIMEOUT = 'Connection timed out during banner exchange'
_SSH_TIMED_OUT_ADDRESS = re.compile(r'Connection to (\S+) port \S+ timed out')

def _last_run_stderr(host):
	'''
	The stderr lines the host's last command run printed.

	With --debug, mssh writes its own lines to stderr too (Resolved name: ..., Running command: ...)
	and keeps a failed attempt's lines before the retry's: the last "Running command: " line, written
	just before the command starts, is where the last run's lines begin.
	'''
	if not __DEBUG_MODE:
		return host.stderr
	for index in range(len(host.stderr) - 1, -1, -1):
		if host.stderr[index].startswith('Running command: '):
			return host.stderr[index + 1:]
	return host.stderr

def _connect_error_names_host(host, connect_host):
	'''
	Whether connect_host, the host or address ssh's error names, is the one mssh had ssh connect to,
	not another host the remote command tried with an ssh of its own (mssh hostA 'ssh backup ...').

	ssh names, lowercased, the HostName it connects to: the address mssh gave it (or its FQDN when
	ssh canonicalizes names), or the HostName the ssh config gives it. Only that last case asks
	ssh -G, which is cached and was already asked for names that only the ssh config knows.
	'''
	connect_host = connect_host.lower()
	address = (getattr(host, 'address', None) or host.name.rsplit('@', 1)[-1]).strip().lower()
	if connect_host == address or connect_host.startswith(address + '.'):
		return True
	if host.ip and connect_host == str(host.ip).lower():
		return True
	if 'ssh' not in _binPaths or not address or address.startswith('-'):
		return False
	config = _ssh_config_values(address)
	return bool(config) and config.get('hostname', '').lower() == connect_host

def _found_unreachable(host):
	'''
	Whether a finished host's run shows it to be unreachable, so later runs skip it for a while.

	ssh, and scp / rsync running it, exit with 255 and print the connect error first when the host
	cannot be reached, or that its sshd never answered within ssh's ConnectTimeout (scp's legacy
	protocol exits with 1); a remote command printing the same words (curl: ... No route to host)
	did reach its host, and so did one whose own ssh could not reach another host, as ssh's error
	names that host. A command stopped by the timeout (-t) counts too if nothing at all came
	back before it: a host that never answers looks like that, but so does a command that was
	quiet from the start, which mssh cannot tell apart. Output means the host answered.
	'''
	stderr = _last_run_stderr(host)
	# scp's legacy protocol (the default before OpenSSH 9.0, and scp -O) exits with 1, not 255
	ssh_failed = host.returncode == 255 or (bool(host.files) and host.returncode == 1)
	if ssh_failed and stderr:
		first_line = stderr[0].strip()
		connect_error = _ssh_connect_error(first_line)
		if connect_error and connect_error[2] in _SSH_UNREACHABLE_REASONS:
			return _connect_error_names_host(host, connect_error[0])
		if _SSH_JUMP_UNREACHABLE.fullmatch(first_line):
			return True
		if first_line == _SSH_BANNER_TIMEOUT and len(stderr) > 1:
			timed_out = _SSH_TIMED_OUT_ADDRESS.fullmatch(stderr[1].strip())
			if timed_out:
				# a remote command's own ssh names the address it tried
				return timed_out.group(1) == 'UNKNOWN' or _connect_error_names_host(host, timed_out.group(1))
	if host.returncode != 124 or host.stdout or not stderr:
		return False
	# a stderr line before the timeout's means the host answered, lines after it come from stopping the command
	return stderr[0].strip().startswith('Timeout!')

def _stream_is_terminal(stream):
	'''True when stream is an open terminal: False when it is redirected, closed, or None (its fd was closed at start).'''
	try:
		return bool(stream is not None and stream.isatty())
	except (AttributeError, ValueError, OSError):
		return False


def processRunOnHosts(timeout, password, max_connections, hosts, return_unfinished, no_watch, json, no_output, greppable,
					  unavailableHosts:dict,will_update_unreachable_hosts,window_width = DEFAULT_WINDOW_WIDTH, 
					  window_height = DEFAULT_WINDOW_HEIGHT,single_window = DEFAULT_SINGLE_WINDOW,
					  unavailable_host_expiry = DEFAULT_UNAVAILABLE_HOST_EXPIRY,pre_merge = True):
	global __globalUnavailableHosts
	global _no_env
	sleep_interval =  1.0e-7 # 0.1 microseconds
	# hosts skipped as unreachable are not run, only reported with the others
	skipped_hosts = [host for host in hosts if host.skipped]
	hosts = [host for host in hosts if not host.skipped]
	# The TUI needs a screen and a keyboard. When stdin is not a terminal (< file, a pipe, a while-read loop,
	# xargs) nobody can type: commands would wait forever on a stdin pipe, and curses would read what stdin
	# holds (the loop's next lines) as key presses. Without the TUI, commands get /dev/null as stdin.
	use_tui = bool(__curses_available and not no_watch and not return_unfinished and _stream_is_terminal(sys.stdout) and _stream_is_terminal(sys.stdin) and os.get_terminal_size() and os.get_terminal_size().columns > 10)
	for host in hosts:
		host.interactive_stdin = use_tui
		# ssh asks for passwords, passphrases and new host keys on the terminal. With the TUI on it, or several
		# commands asking at once, the questions hide behind the TUI or mix, and a typed password can echo.
		# Only a command running alone without the TUI (one host, or -m 1) may ask; the others fail at once.
		host.use_terminal = not use_tui and not return_unfinished and (len(hosts) == 1 or max_connections == 1)
	global _commands_started
	_commands_started = True
	# each command's run shares its lines, the end of the one before switched it off (see _reset_shared_lines)
	_reset_shared_lines(sharing=not return_unfinished)
	threads = start_run_on_hosts(hosts, timeout=timeout,password=password,max_connections=max_connections)
	if use_tui and threads:
		try:
			total_sleeped = 0
			while any([host.returncode is None for host in hosts]):
				time.sleep(sleep_interval)  # avoid busy-waiting
				total_sleeped += sleep_interval
				if sleep_interval < 0.001:
					sleep_interval *= 2
				elif sleep_interval < 0.01:
					sleep_interval *= 1.1
				if total_sleeped > 0.1:
					break
			if any([host.returncode is None for host in hosts]):
				try:
					curses.wrapper(curses_print, hosts, threads, min_char_len = window_width, min_line_len = window_height, single_window = single_window)
				except Exception as error:
					exiting = _exit_replaced_by(error)
					if exiting is not None:
						# mssh was exiting (SIGHUP, SIGTERM) and curses failed to restore the terminal, which
						# hung up: exit as asked, drawing on it again would fail the same way
						raise exiting
					try:
						os.environ['TERM'] = 'xterm-256color'
						curses.wrapper(curses_print, hosts, threads, min_char_len = window_width, min_line_len = window_height, single_window = single_window)
					except Exception as e:
						eprint(f"Curses print error: {e}")
						import traceback
						print(traceback.format_exc())
		finally:
			# the TUI is gone (finished, ESC, or failed): commands still running get end of input
			for host in hosts:
				host.interactive_stdin = False
			_typed_lines_changed_notify()
	if not return_unfinished:
		# wait until all hosts have a return code: a worker ending wakes this at once, and it looks again
		# every 0.1 s. Polling every 10 ms went through all the hosts a hundred times a second
		while any(host.returncode is None for host in hosts):
			worker = next((thread for thread in threads if thread.is_alive()), None)
			if worker is None:
				time.sleep(0.01)
			else:
				worker.join(0.1)
		for thread in threads:
			thread.join(timeout=3)
		# update the unavailable hosts and global unavailable hosts
		if will_update_unreachable_hosts:
			availableHosts = set()
			for host in hosts:
				if _found_unreachable(host):
					unavailableHosts[host.name] =  int(time.monotonic() + unavailable_host_expiry)
					__globalUnavailableHosts[host.name] =  int(time.monotonic() + unavailable_host_expiry)
				else:
					availableHosts.add(host.name)
					if host.name in unavailableHosts:
						del unavailableHosts[host.name]
					if host.name in __globalUnavailableHosts:
						del __globalUnavailableHosts[host.name]
			unavailable_to_persist = dict(__globalUnavailableHosts)
			unavailable_to_persist.update(unavailableHosts)
			canonical_unavailable = _write_unavailable_hosts_file(
				_unavailable_hosts_file_path(), unavailable_to_persist, availableHosts
			)
			unavailableHosts.clear()
			unavailableHosts.update(canonical_unavailable)
			__globalUnavailableHosts.clear()
			__globalUnavailableHosts.update(canonical_unavailable)
			if __DEBUG_MODE:
				print(f'Unreachable hosts: {unavailableHosts}')
		hosts = skipped_hosts + hosts
		if pre_merge and not json and not greppable:
			# only the default output merges: json and greppable output name each host, scripts grep and parse them.
			# merge copies, the caller's hosts must keep one entry per real host for failure counts
			hosts = pre_merge_hosts([host.copy() for host in hosts])
		if not no_output:
			_stream_output(hosts,json,greppable=greppable)
			_note_unasked_passwords(hosts, password)
		# every reader has ended: the hosts hold their lines, the pool would keep them past the hosts
		_reset_shared_lines(sharing=False)
	else:
		__running_threads.update(threads)


#%% ------------ Stringfy Block ----------------
def _shell_quote(text):
	'''
	Quote text so a shell reads it back unchanged.

	Text with newlines or other control characters uses bash / zsh $'...' quoting,
	keeping it on one line (one history entry per line).
	'''
	text = str(text)
	if not any(ord(char) < 32 or ord(char) == 127 for char in text):
		return shlex.quote(text)
	escapes = {'\\': '\\\\', "'": "\\'", '\n': '\\n', '\t': '\\t', '\r': '\\r'}
	quoted = []
	for char in text:
		if char in escapes:
			quoted.append(escapes[char])
		elif ord(char) < 32 or ord(char) == 127:
			quoted.append('\\x{:02x}'.format(ord(char)))
		else:
			quoted.append(char)
	return "$'" + ''.join(quoted) + "'"

def formHostStr(host) -> str:
	"""
	Forms a comma-separated string of hosts.

	Args:
		host: A string or a set of hosts.

	Returns:
		A string representing the hosts, separated by commas.
	"""
	if not host or len(host) == 0:
		return 'EMPTY_HOSTS'
	if isinstance(host, str):
		host = set(_split_host_str(host))
	else:
		host = set(host)
	if 'local_shell' in host:
		host.remove('local_shell')
		host.add('localhost')
	return ','.join(compact_hostnames(host))

def _split_host_str(text):
	'''Split a hosts string on the separators accepted between hosts.'''
	return text.replace(',',' ').replace('\n',' ').replace('\r',' ').replace('\t',' ').replace(';', ' ').replace('|', ' ').replace('/', ' ').replace('&',' ').split()

def _natural_sort_key(text):
	'''Sort key that compares the numbers inside a string numerically (node2 before node10).'''
	return tuple((0, int(part), '') if part.isdigit() else (1, 0, part) for part in re.split(r'(\d+)', text) if part)

def _host_tokens_in_order(hosts):
	'''
	Split the hosts argument into host tokens, keeping the order they were given in.

	Args:
		hosts: A hosts string, or an iterable of host strings. Sets have no order and are sorted.

	Returns:
		list: The host tokens, with local_shell mapped to localhost like formHostStr
	'''
	if isinstance(hosts, str):
		items = [hosts]
	elif isinstance(hosts, (set, frozenset)):
		items = sorted(hosts)
	else:
		items = list(hosts)
	tokens = []
	for item in items:
		for token in _split_host_str(str(item)):
			tokens.append('localhost' if token == 'local_shell' else token)
	return tokens

def _order_target_hosts(host_tokens, target_host_dic, username=None):
	'''
	Order the expanded target hosts by the order their tokens were given in.

	Hosts expanded from one token (a range or an env variable) are in natural sort order.
	Hosts in target_host_dic that no token produced are appended in natural sort order.

	Args:
		host_tokens (list): The host tokens from _host_tokens_in_order
		target_host_dic (dict): The expanded target hosts
		username (str, optional): Username prefixed to tokens without one, like run_command_on_hosts does

	Returns:
		list: The keys of target_host_dic in order
	'''
	ordered = []
	seen = set()
	for token in host_tokens:
		if username and '@' not in token:
			token = f'{username.strip()}@{token}'
		for host in sorted(expand_hostnames([token]), key=_natural_sort_key):
			if host in target_host_dic and host not in seen:
				seen.add(host)
				ordered.append(host)
	ordered.extend(sorted((host for host in target_host_dic if host not in seen), key=_natural_sort_key))
	return ordered

# The CLI default of each option (dest -> value) of the parser process_args built, config files applied:
# what a replayed command line gets for an option it leaves out. main() overwrites some DEFAULT_*
# globals with the options given (set_global_with_args), so those cannot tell.
__cli_option_defaults = {}

def _parser_defaults(parser):
	'''The default of each option of an argparse parser by dest: what a line without the option gets.'''
	return {action.dest: parser.get_default(action.dest) for action in parser._actions}

def _cli_option_defaults():
	'''The CLI's option defaults: those of the parser this run's options were read with, else a new one's.'''
	return __cli_option_defaults or _parser_defaults(get_parser())

def __formCommandArgStr(shortend = False, **kwargs) -> str:
	'''
	The options of a run as mssh command line options.

	The "> mssh ..." echo and the history file show them, and both are replayed (the Ctrl-R picker,
	mssh-complete): every option that changes what runs, where, or what is shown is listed, a flag
	when it is on, a value when it is not the CLI's default (the parser's, config files applied: a
	replay gets the same one). Values are attached with "=", so none is read as a host or command.

	A -p password other than the default (MSSH_PASSWORD, else DEFAULT_PASSWORD) is listed as -p -,
	never itself: a replay asks for it (a placeholder replayed as the password would fail a login on
	every host).
	Not listed: -ip (an IPMI password is not spread further) and, when it is given, the other IPMI options, the options that do something besides the run (--generate_config_file, --store_config_file,
	--add_control_master_config), and those main() folds into others: -T into -t, -uk and -k DIR into
	-k FILE, --script into its options, -s PATH into -f PATH -fs.
	'''
	defaults = _cli_option_defaults()
	argsList = []
	def flag(dest, long_name, short_name=None):
		value = kwargs.get(dest)
		# run_command_on_hosts' no_output is ... for "its default"
		if value and value is not ...:
			argsList.append(short_name if shortend and short_name else long_name)
	def option(dest, long_name, short_name=None):
		default = defaults.get(dest)
		value = kwargs.get(dest, default)
		# 0 and '' are values too: -t 0 means no timeout when the configured default is another
		if value is not None and value != default:
			argsList.append('{}={}'.format(short_name if shortend and short_name else long_name, _shell_quote(value)))
	def options(dest, long_name, short_name=None):
		for value in kwargs.get(dest) or ():
			argsList.append('{}={}'.format(short_name if shortend and short_name else long_name, _shell_quote(value)))
	flag('oneonone', '--oneonone', '-11')
	option('timeout', '--timeout', '-t')
	option('repeat', '--repeat', '-r')
	option('interval', '--interval', '-i')
	password = kwargs.get('password', defaults.get('password'))
	if password is not None and password != defaults.get('password'):
		# '' is no password, not a secret
		argsList.append('{}={}'.format('-p' if shortend else '--password', '-' if password else "''"))
	option('identity_file', '--key', '-k')
	flag('copy_id', '--copy_id', '-ci')
	flag('no_watch', '--no_watch', '-q')
	flag('json', '--json', '-j')
	option('max_connections', '--max_connections', '-m')
	options('file', '--file', '-f')
	# -fs takes an optional path: listed last it would take the hosts that follow for one. -su / -nsu,
	# always listed, comes after it
	flag('file_sync', '--file_sync', '-fs')
	flag('ipmi', '--ipmi')
	if kwargs.get('ipmi_password', defaults.get('ipmi_password')) == defaults.get('ipmi_password'):
		# with -ip, left out, these would make with the configured password a login nobody gave, tried
		# first on every BMC: a failed login each, towards locking the account. A replay without them
		# tries the configured logins, as a plain --ipmi run
		option('ipmi_interface_ip_prefix', '--ipmi_interface_ip_prefix', '-mpre')
		option('ipmi_username', '--ipmi_username', '-iu')
		option('ipmi_args', '--ipmi_args', '-ia')
		option('ipmi_method', '--ipmi_method', '-im')
		option('ipmi_retry_lockout_time', '--ipmi_retry_lockout_time', '-irlt')
	option('interface_ip_prefix', '--interface_ip_prefix', '-pre')
	flag('scp', '--scp')
	flag('gather_mode', '--gather_mode', '-gm')
	option('username', '--username', '-u')
	option('extraargs', '--extraargs', '-ea')
	if kwargs.get('skip_unreachable', DEFAULT_SKIP_UNREACHABLE):
		argsList.append('--skip_unreachable' if not shortend else '-su')
	else:
		argsList.append('--no_skip_unreachable' if not shortend else '-nsu')
	option('unavailable_host_expiry', '--unavailable_host_expiry', '-uhe')
	flag('no_env', '--no_env')
	option('env_file', '--env_file', '-ef')
	# only env files given explicitly: listing the defaults would make a replayed line trust them all
	options('env_files', '--env_files', '-efs')
	host_file = kwargs.get('host_file')
	if host_file is not None and host_file != defaults.get('host_file'):
		# absolute (mssh does not expand ~ in it): a replay in another directory reads the same hosts
		argsList.append('--host_file={}'.format(_shell_quote(os.path.abspath(host_file) if host_file else host_file)))
	if kwargs.get('config_file'):
		# a config file can set any global (even the ssh binary): a replay elsewhere must load this one,
		# not one a relative path finds in the directory it runs in
		argsList.append('--config_file={}'.format(_shell_quote(os.path.abspath(os.path.expanduser(kwargs['config_file'])))))
	flag('no_history', '--no_history', '-nh')
	option('history_file', '--history_file', '-hf')
	flag('greppable', '--greppable', '-g')
	flag('error_only', '--error_only', '-eo')
	option('skip_hosts', '--skip_hosts', '-sh')
	option('window_width', '--window_width', '-ww')
	option('window_height', '--window_height', '-wh')
	flag('single_window', '--single_window', '-sw')
	flag('no_output', '--no_output', '-no')
	flag('success_hosts', '--success_hosts', '-w')
	flag('return_zero', '--return_zero', '-rz')
	option('encoding', '--encoding', '-e')
	option('diff_display_threshold', '--diff_display_threshold', '-dt')
	flag('force_truecolor', '--force_truecolor')
	flag('debug', '--debug')
	return ' '.join(argsList)

def _typed_host_str(hosts):
	'''The hosts argument as given, without expanding, validating or sorting it (sets are sorted).'''
	if isinstance(hosts, str):
		return hosts
	if isinstance(hosts, (set, frozenset)):
		hosts = sorted(hosts)
	return ','.join(str(host) for host in hosts)

def getStrCommand(hosts = DEFAULT_HOSTS,commands = None,shortend = False,tabSeperated = False,typed_hosts = False,**kwargs) -> str:
	if typed_hosts:
		# the history keeps what was typed: aliases and ranges unexpanded, unresolvable names kept
		hostStr = _typed_host_str(hosts) or 'EMPTY_HOSTS'
	else:
		hosts = hosts if isinstance(hosts,str) else frozenset(hosts)
		hostStr = formHostStr(hosts)
	commandArgKwargs = dict(kwargs)
	# run_command_on_hosts' deprecated files= adds to file=
	if commandArgKwargs.get('files'):
		commandArgKwargs['file'] = list(commandArgKwargs.get('file') or []) + list(commandArgKwargs['files'])
	argsStr = __formCommandArgStr(shortend = shortend, **commandArgKwargs)
	commands = format_commands(commands)
	commandStr = ' '.join(_shell_quote(command) for command in commands)
	hostStr = _shell_quote(hostStr)
	if any(command.startswith('-') for command in commands):
		# else read as an mssh option. After the hosts, where it is typed: every Python's argparse reads
		# "HOSTS -- -x" so, while 3.11 and older read -x as an option in "-- HOSTS -x"
		hostStr += ' --'
	filePath = os.path.abspath(__file__)
	programName = _shell_quote(filePath) if filePath else 'mssh'
	if tabSeperated:
		return f'{programName}\t{argsStr}\t{hostStr}\t{commandStr}'
	else:
		return f'{programName} {argsStr} {hostStr} {commandStr}'

#%% ------------ Record History Block ----------------
def record_command_history(kwargs):
	'''
	Record the command history to a file

	Args:
		args (str): The command arguments to record

	Returns:
		None
	'''
	global __global_suppress_printout
	global __DEBUG_MODE
	try:
		historyKwargs = dict(kwargs)
		# run_command_on_hosts passes its locals(): options it does not name (repeat, env_files, ...) sit in its **kwargs
		historyKwargs.update(historyKwargs.pop('kwargs', None) or {})
		historyKwargs['shortend'] = True
		historyKwargs['tabSeperated'] = True
		historyKwargs['typed_hosts'] = True
		history_file = os.path.expanduser(historyKwargs.get('history_file', DEFAULT_HISTORY_FILE))
		strCommand = getStrCommand(**historyKwargs)
		# the commands run can be private too: readable by the owner only
		with os.fdopen(os.open(history_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), 'a') as f:
			# it follows <timestamp>\t<strCommand>\n
			f.write(f'{int(time.time())}\t{strCommand}\n')
			f.flush()
			os.fsync(f.fileno())
		if __DEBUG_MODE:
			eprint(f'Command history recorded to {history_file}')
	except Exception as e:
		eprint(f'Error recording command history: {e!r}')
		if __DEBUG_MODE:
			import traceback
			eprint(traceback.format_exc().strip())

#%% ------------ Main Block ----------------
def _normalize_max_connections(max_connections):
	cpu_default = 4 * _cpu_count()
	safe_limit = __max_connections_nofile_limit_supported
	if max_connections is None:
		normalized = cpu_default
	elif max_connections == 0:
		normalized = safe_limit if safe_limit > 0 else cpu_default
	elif max_connections < 0:
		normalized = (-max_connections) * _cpu_count()
	else:
		normalized = max_connections
	if safe_limit > 0 and normalized > safe_limit:
		eprint(
			"Warning: The number of maximum connections {} is larger than estimated limit {} "
			"from ulimit nofile limit {}, setting the maximum connections to {}.".format(
				normalized, safe_limit, __system_nofile_limit, safe_limit
			)
		)
		normalized = safe_limit
	return normalized

def _why_names_no_hosts(token):
	'''Why a host token names no host, for the error message, or None when that is not clear.'''
	name = token.rsplit('@', 1)[-1].strip().strip('$')
	if _IPV4_RANGE_RE.match(name):
		for octet in name.split('.'):
			start, _, end = octet.strip('[]').partition('-')
			if start.isdigit() and end.isdigit() and int(start) > int(end):
				return 'the range {}-{} counts down'.format(start, end)
	else:
		for group in re.findall(r'\[(.*?)]', name):
			for part in group.split(','):
				part = part.strip()
				# expanded alone, so the range is read exactly as __expand_hostname reads it
				if '-' in part and not __expand_hostname('[{}]'.format(part), validate=False):
					return 'the range [{}] counts down'.format(part)
	source = _local_hostname_source(name)
	if source == 'env':
		return 'the environment variable {} is {!r}'.format(name, os.environ.get(name))
	if source == 'env_file':
		return '{} is {!r} in the env files'.format(name, readEnvFromFile().get(name))
	return None

def _names_a_host(token):
	'''
	Whether a host token names at least one host, without DNS (like expand_hostnames_local).

	Stops at the first member that is not an alias, and reuses the range expansions expanding
	the hosts cached, so a large range costs next to nothing.
	'''
	name = token.rsplit('@', 1)[-1].strip()
	if _IPV4_RANGE_RE.match(name):
		return bool(__expandIPv4Address(frozenset([name])))
	for member in __expand_hostname(name, validate=False):
		member = member.strip().strip('$')
		if not member:
			continue
		if _local_hostname_source(member) not in ('env', 'env_file') or expand_hostnames_local(member)[0]:
			return True
	return False

def _report_tokens_naming_no_hosts(tokens):
	'''
	Report each host token that names no host at all, e.g. a range counting down or an empty alias.

	Like a name that does not resolve, each counts once towards the exit code and is listed with
	the failed hosts. Empty groups inside an alias are fine (README's env file example has them):
	only the tokens given are checked.

	Args:
		tokens (list): The host tokens as given, from _host_tokens_in_order
	'''
	global __mainReturnCode
	global __failedHosts
	for token in tokens:
		if token in __failedHosts or _names_a_host(token):
			continue
		reason = _why_names_no_hosts(token)
		eprint('Error: {!r} names no hosts{}'.format(token, ': ' + reason if reason else ''))
		__mainReturnCode += 1
		__failedHosts.add(token)

# what a host skipped as unreachable returns: ssh's code for a host it could not connect to
_SKIPPED_HOST_RETURN_CODE = 255

def _mark_skipped_unreachable(host, expiry, this_run_only=False):
	'''
	Mark host as not run because it was unreachable in a recent run, which counts as a failure.

	Args:
		host (Host): The host, not started
		expiry (int): When the host stops being skipped, in time.monotonic() seconds
		this_run_only (bool): Only this run's earlier commands are used (-a, --no_skip_unreachable)

	Returns:
		Host: host, finished with _SKIPPED_HOST_RETURN_CODE and a stderr line saying why
	'''
	if this_run_only:
		message = 'Skipped: unreachable in an earlier command of this run'
	else:
		message = ('Skipped: unreachable in a recent run, not tried again for another {} s '
			'(-a, --no_skip_unreachable tries it now)'.format(max(0, int(expiry - time.monotonic()))))
	host.skipped = True
	host.stderr.append(message)
	host.output.append(message)
	host.returncode = _SKIPPED_HOST_RETURN_CODE
	return host


def run_command_on_hosts(hosts = DEFAULT_HOSTS,commands = None,oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,
						 no_watch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = ...,max_connections=DEFAULT_MAX_CONNECTIONS,
						 file = None,files = None, ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,return_unfinished = ...,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skip_unreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,will_update_unreachable_hosts=...,no_start=...,
						 skip_hosts = DEFAULT_SKIP_HOSTS, window_width = DEFAULT_WINDOW_WIDTH, window_height = DEFAULT_WINDOW_HEIGHT,
						 single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY,quiet = False,identity_file = DEFAULT_IDENTITY_FILE,
						 copy_id = False, unavailable_host_expiry = DEFAULT_UNAVAILABLE_HOST_EXPIRY,no_history = True,
						 history_file = DEFAULT_HISTORY_FILE, pre_merge_hosts = ..., no_output = ..., **kwargs
						 ):
	"""
	Run commands on multiple hosts via SSH or IPMI.

	Parameters:
		hosts (str or iterable): Hosts to run the command on. Can be a string (comma/space-separated) or iterable. Default: DEFAULT_HOSTS.
		commands (list or None): List of commands to run on the hosts. If files are used, defines the destination. Default: None.
		oneonone (bool): If True, run each command on the corresponding host (1:1 mapping). Default: DEFAULT_ONE_ON_ONE.
		timeout (int): Idle timeout: stop a host's command after this many seconds without output. Default: DEFAULT_TIMEOUT.
		password (str): Password for SSH/IPMI authentication. Default: DEFAULT_PASSWORD.
		no_watch (bool): If True, do not use curses TUI; just print output. Default: DEFAULT_NO_WATCH.
		json (bool): If True, output results in JSON format. Default: DEFAULT_JSON_MODE.
		called (bool): If True, function is called programmatically (not CLI). Default: _DEFAULT_CALLED.
		max_connections (int): Maximum concurrent SSH sessions. Default: 4 * os.cpu_count().
		file (list or None): Files to copy to hosts. Default: None.
		files (list or None): Deprecated: Files to copy to hosts. Default: None.
		ipmi (bool): Use IPMI instead of SSH. Default: DEFAULT_IPMI.
		interface_ip_prefix (str or None): Override IP prefix for host connection. Default: DEFAULT_INTERFACE_IP_PREFIX.
		return_unfinished (bool): If True, return hosts even if not finished. Default: _DEFAULT_RETURN_UNFINISHED.
		scp (bool): Use scp for file transfer (instead of rsync). Default: DEFAULT_SCP.
		gather_mode (bool): Gather files from hosts (pull mode). Default: False.
		username (str or None): Username for SSH/IPMI. Default: DEFAULT_USERNAME.
		extraargs (str or list or None): Extra args for SSH/SCP/rsync. Default: DEFAULT_EXTRA_ARGS.
		skip_unreachable (bool): Skip hosts marked as unreachable (they fail with 255). Default: DEFAULT_SKIP_UNREACHABLE.
		no_env (bool): Do not load environment variables from shell. Default: DEFAULT_NO_ENV.
		greppable (bool): Output in greppable table format. Default: DEFAULT_GREPPABLE_MODE.
		will_update_unreachable_hosts (bool): Update global unreachable hosts file. Default: _DEFAULT_UPDATE_UNREACHABLE_HOSTS.
		no_start (bool): If True, return Host objects without running commands. Default: _DEFAULT_NO_START.
		skip_hosts (str or None): Hosts to skip. Default: DEFAULT_SKIP_HOSTS.
		window_width (int): Minimum width per curses window. Default: DEFAULT_WINDOW_WIDTH.
		window_height (int): Minimum height per curses window. Default: DEFAULT_WINDOW_HEIGHT.
		single_window (bool): Use a single curses window for all hosts. Default: DEFAULT_SINGLE_WINDOW.
		file_sync (bool): Enable file sync mode (sync directories). Default: DEFAULT_FILE_SYNC.
		error_only (bool): Only print error output. Default: DEFAULT_ERROR_ONLY.
		quiet (bool): Suppress all output (overrides other output options). Default: False.
		identity_file (str or None): SSH identity file. Default: DEFAULT_IDENTITY_FILE.
		copy_id (bool): Use ssh-copy-id to copy public key to hosts first. Without commands, the ssh-copy-id runs are returned as the hosts. Default: False.
		unavailable_host_expiry (int): Seconds to keep hosts marked as unavailable. Default: DEFAULT_UNAVAILABLE_HOST_EXPIRY.
		no_history (bool): Do not record command history. Default: True.
		history_file (str): File to store command history. Default: DEFAULT_HISTORY_FILE.
		pre_merge_hosts (bool): In the printed default output, show hosts with identical outputs once (json and greppable output list every host). Default: not called.
		no_output (bool): If True, do not print output after execution. Default: called.

	Returns:
		list: List of Host objects representing each host/command run. A host skipped because it was
			unreachable in a recent run is in the list too, not run: its skipped is True, its
			returncode 255 and its stderr says why.
	"""
	global __globalUnavailableHosts
	global __global_suppress_printout
	global _no_env
	global _emo
	global _stopping
	global __DEBUG_MODE
	global __thread_start_delay
	global __max_connections_nofile_limit_supported
	global __keyPressesIn
	# the _DEFAULT_ settings as they are now: a config file read after the import (--config_file), or a
	# script, may have changed them
	if called is ...:
		called = _DEFAULT_CALLED
	if return_unfinished is ...:
		return_unfinished = _DEFAULT_RETURN_UNFINISHED
	if will_update_unreachable_hosts is ...:
		will_update_unreachable_hosts = _DEFAULT_UPDATE_UNREACHABLE_HOSTS
	if no_start is ...:
		no_start = _DEFAULT_NO_START
	if called:
		# a library call starts fresh; on the CLI a Ctrl-C (e.g. in an earlier --repeat run) stands
		_emo = False
		_stopping = False
	_no_env = no_env
	_reported_invalid_hosts.clear()
	_refresh_expansion_caches()
	# processRunOnHosts switches sharing on for each command: not here, as no_start runs none
	_reset_shared_lines(sharing=False)
	if not no_history:
		record_command_history(locals())
	if error_only:
		__global_suppress_printout = True
	unavailable_path = _unavailable_hosts_file_path()
	if unavailable_path and os.path.exists(unavailable_path):
		loaded_unavailable = _read_unavailable_hosts_file(unavailable_path, max_ttl=unavailable_host_expiry)
		__globalUnavailableHosts.update(loaded_unavailable)
		if loaded_unavailable and not __global_suppress_printout:
			eprint("Read unavailable hosts from the file {}".format(unavailable_path))
	max_connections = _normalize_max_connections(max_connections)
	commands = format_commands(commands)
	this_run_only = False
	if called and skip_unreachable is None:
		skip_unreachable = True
	# the hosts found unreachable in recent runs, else none: a library call then skips none, the command
	# line (-a) those that this run's earlier commands found
	unavailableHosts = __globalUnavailableHosts if skip_unreachable else {}
	if called:
		__keyPressesIn = [[]]
		__global_suppress_printout = True
	elif not skip_unreachable:
		skip_unreachable = this_run_only = True
	if pre_merge_hosts is ...:
		pre_merge_hosts = not called
	if no_output is ...:
		no_output = called
	if quiet:
		__global_suppress_printout = True
	# We create the hosts
	if hosts is None:
		# the default hosts as a config file set them, not as they were when mssh was imported
		hosts = DEFAULT_HOSTS
	# the hosts as given: one on one mode pairs commands with them in this order
	hostTokens = _host_tokens_in_order(hosts)
	if isinstance(hosts, list):
		hosts = frozenset(hosts)
	elif isinstance(hosts, dict):
		hosts = frozenset(hosts.keys())
	# no hosts: none to look up (formHostStr's EMPTY_HOSTS is a name for the echoed command only)
	hostStr = formHostStr(hosts) if hostTokens else ''
	skipHostStr = formHostStr(skip_hosts) if skip_hosts else ''
	if files:
		if not file:
			file = files
		else:
			file = list(file) + list(files)
	if username and hostStr:
		userStr = f'{username.strip()}@'
		# we also append this userStr to all hostStr which does not have username already defined
		hostStr = hostStr.split(',')
		for i, host in enumerate(hostStr):
			if '@' not in host:
				hostStr[i] = userStr + host
		hostStr = ','.join(hostStr)
		if skipHostStr:
			skipHostStr = skipHostStr.split(',')
			for i, host in enumerate(skipHostStr):
				if '@' not in host:
					skipHostStr[i] = userStr + host
			skipHostStr = ','.join(skipHostStr)
	targetHostDic = expand_hostnames(hostStr.split(',')) if hostStr else {}
	if __DEBUG_MODE:
		eprint(f"Target hosts: {targetHostDic!r}")
	skipHostsDic = expand_hostnames(skipHostStr.split(','))
	if _emo:
		_abort(1, 'Ctrl C caught, not starting the command', called=called)
	# hosts reachable only through the ssh config have no IP (None), which must not match other such hosts
	skipHostSet = set(skipHostsDic).union(ip for ip in skipHostsDic.values() if ip)
	if skipHostSet:
		eprint(f"Skipping hosts: \"{' '.join(compact_hostnames_local(skipHostSet))}\"")
	if not called:
		_report_tokens_naming_no_hosts(hostTokens)
		if not targetHostDic:
			# every host is a name that does not resolve or names no host: nothing would run
			_abort(max(1, __mainReturnCode), 'no hosts to run on', called=called)
		if all(host in skipHostSet or targetHostDic[host] in skipHostSet for host in targetHostDic):
			eprint('Warning: -X, --skip_hosts leaves no hosts to run on')
	if interface_ip_prefix and not __global_suppress_printout:
		# said once here: run_command's own warning only reaches the TUI
		unprefixed = [host for host, ip in targetHostDic.items()
			if not _interface_prefix_applies(ip) and host not in skipHostSet and ip not in skipHostSet]
		if unprefixed:
			eprint(_interface_prefix_warning(interface_ip_prefix, unprefixed))
	def run(hosts):
		processRunOnHosts(timeout=timeout, password=password, max_connections=max_connections, hosts=hosts,
			return_unfinished=return_unfinished, no_watch=no_watch, json=json, no_output=no_output, greppable=greppable,
			unavailableHosts=unavailableHosts, will_update_unreachable_hosts=will_update_unreachable_hosts,
			window_width=window_width, window_height=window_height, single_window=single_window,
			unavailable_host_expiry=unavailable_host_expiry, pre_merge=pre_merge_hosts)
	if copy_id:
		if 'ssh-copy-id' in _binPaths:
			# we will copy the id to the hosts
			hosts = []
			# the ssh-copy-id runs: their results are the hosts' results, a failed one is a failed host
			copied = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet:
					continue
				# host already carries user@ when username is set, see hostStr above
				command = _copy_id_command(host, identity_file, extraargs)
				if password and 'sshpass' in _binPaths:
					# _build_command puts sshpass in front: the password stays out of the command mssh shows
					hosts.append(Host(host, command,identity_file=identity_file,shell=True,ip = targetHostDic[host]))
				else:
					# ssh-copy-id asks for the password on the terminal, one host after the other. Every word of
					# command is quoted; os.system, not Popen, so a Ctrl-C reaches only ssh-copy-id (see below)
					eprint(f"> {command}")
					typed = Host(host, command, identity_file=identity_file, shell=True, ip=targetHostDic[host])
					typed.returncode = _wait_status_return_code(os.system(command))
					copied.append(typed)
					if typed.returncode == -signal.SIGINT:
						# os.system ignores Ctrl-C, the ssh-copy-id it ran got it: stop, as a shell loop does
						eprint('Ctrl C caught, not copying the id to the other hosts')
						_emo = True
						break
			if hosts:
				run(hosts)
				copied += hosts
			if not commands:
				# main() counts the hosts ssh-copy-id failed on, as for any command
				return copied
			if not called:
				_count_failed_copies(copied)
			if _emo:
				_abort(1, 'Ctrl C caught, not starting the command', called=called)
		else:
			eprint(f"Warning: ssh-copy-id not found in {_binPaths} , skipping copy id to the hosts")
			if not commands:
				# 127: the shell's code for a command it cannot find
				_abort(127, "ssh-copy-id not found, no id copied", called=called)
	if file and not commands:
		# if files are specified but not target dir, we default to file sync mode
		file_sync = True
	if file_sync:
		# set the files to the union of files and commands
		file = set(file+commands) if file else set(commands)
	if file:
		# try to resolve files first (like * etc)
		if not gather_mode:
			pathSet = set()
			for pattern in file:
				# a path that exists is meant as written: the shell expanded the user's globs already,
				# and glob would read report[1].txt as report1.txt
				if os.path.lexists(pattern):
					pathSet.add(pattern)
					continue
				try:
					pathSet.update(glob.glob(pattern,include_hidden=True,recursive=True))
				except Exception:
					pathSet.update(glob.glob(pattern,recursive=True))
			if not pathSet:
				_abort(66, f'No source files at {sorted(file)!r} are found after resolving globs!', called=called)
		else:
			pathSet = set(file)
		if file_sync:
			# use abosolute path for file sync
			commands = [os.path.abspath(file) for file in pathSet]
			file = []
		else:
			file = list(pathSet)
		if not gather_mode and not __global_suppress_printout and 'rsync' in _binPaths and not (scp and 'scp' in _binPaths):
			# -s copies each path on its own, -f all files together
			for sources in ([[path] for path in commands] if file_sync else [file]):
				for path, target, why in _rsync_link_sources(sources)[1]:
					eprint('Warning: ' + _KEPT_LINK_WARNINGS[why].format(path=path, target=target))
		if __DEBUG_MODE:
			eprint(f"Files: {file!r}")
	def new_host(host, command):
		'''The Host running command on host: skipped (not run, a failure) if it was unreachable in a recent run.'''
		if file_sync:
			command, files = os.path.dirname(command) + os.path.sep, [command]
		else:
			files = file
		new = Host(host, command, files=files, ipmi=ipmi, interface_ip_prefix=interface_ip_prefix, scp=scp, extraargs=extraargs,
			gatherMode=gather_mode, identity_file=identity_file, ip=targetHostDic[host])
		if not ipmi and skip_unreachable and host in unavailableHosts and unavailableHosts[host] > time.monotonic():
			if not __global_suppress_printout:
				eprint(f"Skipping unavailable host: {host}")
			_mark_skipped_unreachable(new, unavailableHosts[host], this_run_only)
		return new
	if oneonone:
		hosts = []
		# skipped hosts get no command, unreachable hosts keep their command slot and are skipped below
		orderedHosts = [host for host in _order_target_hosts(hostTokens, targetHostDic, username)
						if host not in skipHostSet and targetHostDic[host] not in skipHostSet]
		if len(commands) != len(orderedHosts):
			eprint("Error: the number of commands must be the same as the number of hosts")
			eprint(f"Number of commands: {len(commands)}")
			eprint(f"Number of hosts: {len(orderedHosts)}")
			_abort(255, "Number of commands and hosts do not match", called=called)
		if not __global_suppress_printout:
			eprint('-'*80)
			eprint("Running in one on one mode")
		for host, command in zip(orderedHosts, commands):
			hosts.append(new_host(host, command))
			if not hosts[-1].skipped and not __global_suppress_printout:
				eprint(f"Running command: {command!r} on host: {host!r}")
		if not __global_suppress_printout:
			eprint('-'*80)
		if not no_start: 
			run(hosts)
		return hosts
	else:
		allHosts = []
		if not commands:
			# run in interactive mode ssh mode
			hosts = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet:
					continue
				if file_sync:
					eprint("Error: file sync mode need to be specified with at least one path to sync.")
					return []
				elif file:
					eprint("Error: files need to be specified with at least one path to sync")
				else:
					hosts.append(new_host(host, ''))
			if not __global_suppress_printout:
				eprint('-'*80)
				eprint(f"Running in interactive mode on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if no_start:
				eprint("Warning: no_start is set, the command will not be started. As we are in interactive mode, no action will be done.")
			else:
				run(hosts)
			return hosts
		for command in commands:
			if _emo:
				# Ctrl-C during an earlier command: run no more
				break
			hosts = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet:
					continue
				hosts.append(new_host(host, command))
			if not __global_suppress_printout and len(commands) > 1:
				eprint('-'*80)
				eprint(f"Running command: {command} on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if not no_start: 
				run(hosts)
			allHosts += hosts
		return allHosts

#%% ------------ Default Config Functions ----------------
def generate_default_config(args):
	'''
	Get the default config

	Args:
		args (argparse.Namespace): The arguments

	Returns:
		dict: The default config
	'''
	return {
		'AUTHOR': AUTHOR,
		'AUTHOR_EMAIL': AUTHOR_EMAIL,
		'DEFAULT_HOSTS': args.hosts,
		'DEFAULT_USERNAME': args.username,
		# MSSH_PASSWORD stays in the environment it was set in
		'DEFAULT_PASSWORD': DEFAULT_PASSWORD if os.environ.get('MSSH_PASSWORD') and args.password == os.environ.get('MSSH_PASSWORD') else args.password,
		'DEFAULT_IDENTITY_FILE': args.identity_file if args.identity_file and not os.path.isdir(args.identity_file) else DEFAULT_IDENTITY_FILE,
		'DEFAULT_SSH_KEY_SEARCH_PATH': args.identity_file if args.identity_file and os.path.isdir(args.identity_file) else DEFAULT_SSH_KEY_SEARCH_PATH,
		'DEFAULT_USE_KEY': args.use_key,
		'DEFAULT_EXTRA_ARGS': args.extraargs,
		'DEFAULT_ONE_ON_ONE': args.oneonone,
		'DEFAULT_SCP': args.scp,
		'DEFAULT_FILE_SYNC': args.file_sync,
		'DEFAULT_TIMEOUT': DEFAULT_TIMEOUT,
		'DEFAULT_CLI_TIMEOUT': args.timeout,
		'DEFAULT_SSH_CONNECT_TIMEOUT': DEFAULT_SSH_CONNECT_TIMEOUT,
		'DEFAULT_SSH_SERVER_ALIVE_INTERVAL': DEFAULT_SSH_SERVER_ALIVE_INTERVAL,
		'DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX': DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX,
		'DEFAULT_UNAVAILABLE_HOST_EXPIRY': args.unavailable_host_expiry,
		'DEFAULT_REPEAT': args.repeat,
		'DEFAULT_INTERVAL': args.interval,
		'DEFAULT_IPMI': args.ipmi,
		'DEFAULT_IPMI_INTERFACE_IP_PREFIX': args.ipmi_interface_ip_prefix,
		'DEFAULT_IPMI_USERNAME': args.ipmi_username,
		'DEFAULT_IPMI_PASSWORD': args.ipmi_password,
		'DEFAULT_IPMI_ARGS': args.ipmi_args,
		'DEFAULT_IPMI_METHOD': args.ipmi_method,
		'DEFAULT_IPMI_RETRY_LOCKOUT_TIME': args.ipmi_retry_lockout_time,
		'DEFAULT_INTERFACE_IP_PREFIX': args.interface_ip_prefix,
		'DEFAULT_IPMI_DEFINITIONS': _ipmi_definitions_to_store(args),
		'DEFAULT_NO_WATCH': args.no_watch,
		'DEFAULT_WINDOW_WIDTH': args.window_width,
		'DEFAULT_WINDOW_HEIGHT': args.window_height,
		'DEFAULT_SINGLE_WINDOW': args.single_window,
		'DEFAULT_ERROR_ONLY': args.error_only,
		'DEFAULT_NO_OUTPUT': args.no_output,
		'DEFAULT_RETURN_ZERO': args.return_zero,
		'DEFAULT_NO_ENV': args.no_env,
		'DEFAULT_ENV_FILES': DEFAULT_ENV_FILES + args.env_files,
		'DEFAULT_NO_HISTORY': args.no_history,
		'DEFAULT_HISTORY_FILE': args.history_file,
		'DEFAULT_MAX_CONNECTIONS': args.max_connections if args.max_connections != 4 * _cpu_count() else None,
		'DEFAULT_JSON_MODE': args.json,
		'DEFAULT_PRINT_SUCCESS_HOSTS': args.success_hosts,
		'DEFAULT_GREPPABLE_MODE': args.greppable,
		'DEFAULT_SKIP_UNREACHABLE': args.skip_unreachable,
		'DEFAULT_SKIP_HOSTS': args.skip_hosts,
		'DEFAULT_HOST_FILE': args.host_file,
		'DEFAULT_ENCODING': args.encoding,
		'DEFAULT_DIFF_DISPLAY_THRESHOLD': args.diff_display_threshold,
		'FORCE_TRUECOLOR': args.force_truecolor,
	}

def _is_system_config_path(path):
	'''Whether path is one of the absolute (system-wide) locations in CONFIG_FILE_CHAIN.'''
	target = os.path.abspath(os.path.expanduser(path))
	return any(
		os.path.abspath(entry) == target
		for entry in CONFIG_FILE_CHAIN
		if os.path.isabs(entry)
	)

def _own_symlink(path):
	'''Whether path is a symlink of our own (or root's), one write_default_config writes through.'''
	if not os.path.islink(path):
		return False
	return not hasattr(os, 'getuid') or os.lstat(path).st_uid in (os.getuid(), 0)

def write_default_config(args,CONFIG_FILE = None, force = False):
	global __configs_from_file
	default_config = generate_default_config(args)
	# apply the updated defualt_config to __configs_from_file and write that to file
	__configs_from_file.update(default_config)
	if not CONFIG_FILE:
		print(json.dumps(__configs_from_file, indent=4))
		return
	backup = not force
	if not force and os.path.exists(CONFIG_FILE):
		eprint(f"Warning: {CONFIG_FILE!r} already exists, what to do? (o/b/n)")
		eprint("o:  Overwrite the file")
		eprint(f"b:  Back up the current config file to {CONFIG_FILE + '.bak'!r} and write the new config file (default)")
		eprint("n:  Do nothing")
		inStr = input_with_timeout_and_countdown(10)
		if (not inStr) or inStr.lower().strip().startswith('b'):
			backup = True
		elif inStr.lower().strip().startswith('o'):
			backup = False
		else:
			_exit_with_code(0, "Aborted by user, no config file written")
	# neither the new file nor the backup may end up more open than the old file was
	try:
		previous = os.stat(CONFIG_FILE)
		previous_mode = stat.S_IMODE(previous.st_mode)
	except OSError:
		previous = previous_mode = None
	try:
		if backup and os.path.exists(CONFIG_FILE) and _own_symlink(CONFIG_FILE):
			# the new config is written through the link below (e.g. into a dotfiles repo): moving the
			# link aside would leave the file it points to as it was, copy that file instead
			with open(CONFIG_FILE, 'rb') as f:
				_replace_file(CONFIG_FILE + '.bak', f.read(), 0o600 if previous_mode is None else previous_mode & 0o600, follow=False, owner=False)
		elif backup and os.path.exists(CONFIG_FILE):
			os.rename(CONFIG_FILE,CONFIG_FILE+'.bak')
			# the backup holds the old passwords: owner only
			if previous_mode is not None and not os.path.islink(CONFIG_FILE+'.bak'):
				try:
					os.chmod(CONFIG_FILE+'.bak', previous_mode & 0o600)
				except OSError:
					pass
	except Exception as e:
		eprint(f"Error: Unable to backup the config file: {e!r}")
		eprint(f"Do you want to continue writing the new config file to {CONFIG_FILE!r}? (y/n)")
		inStr = input_with_timeout_and_countdown(10)
		if not inStr or not inStr.lower().strip().startswith('y'):
			_exit_with_code(0, "Aborted by user, no config file written")
	try:
		# write through a symlinked config (e.g. into a dotfiles repo) instead of replacing the link, but
		# only a link of our own (or root's): one planted by someone else (e.g. in /tmp) could point anywhere
		if os.path.islink(CONFIG_FILE) and not _own_symlink(CONFIG_FILE):
			raise PermissionError('{!r} is a symlink owned by someone else, not writing through it'.format(CONFIG_FILE))
		# configs can hold passwords: owner only, except the system-wide locations every user reads, and
		# never more open than the old file was (an admin may have locked it down further)
		mode = 0o644 if _is_system_config_path(CONFIG_FILE) else 0o600
		_replace_file(CONFIG_FILE, json.dumps(__configs_from_file, indent=4).encode(), mode if previous_mode is None else previous_mode & mode, owner=previous)
		eprint(f"Config file written to {CONFIG_FILE!r}")
		return True
	except Exception as e:
		eprint(f"Error: Unable to write to the config file: {e!r}")
		eprint('Printing the config file to stdout:')
		print(json.dumps(__configs_from_file, indent=4))
		return False

#%% ------------ Argument Processing -----------------
def _positive_int(value):
	parsed = int(value)
	if parsed < 1:
		raise argparse.ArgumentTypeError("must be at least 1")
	return parsed


# Option combinations main() ignores, for the warnings mssh-complete shows while a line is typed
# (it reads them through its index). Each entry is (option, kind, others, why):
#   'with': the option does nothing when one of others is on the line
#   'without': the option does nothing unless one of others is on the line or on by default
# tests/test_option_no_effect.py proves every entry.
_IPMI_OR_STORED = ('--ipmi', '--store_config_file', '--generate_config_file')
OPTION_NO_EFFECT = (
	('--no_skip_unreachable', 'with', ('--script',), '--script skips unreachable hosts anyway'),
	('--ipmi_interface_ip_prefix', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_username', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_password', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_args', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_method', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_retry_lockout_time', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
)

def _plain_help(text):
	'''
	text as an argparse help string. argparse %-formats help (Python 3.14+ already when the option is
	added), and the defaults written into mssh's help can hold a % (ssh's ControlPath=~/.ssh/cm-%r@%h:%p).
	'''
	return text.replace('%', '%%')

def _default_password():
	'''What -p defaults to: MSSH_PASSWORD, a password kept off the command line (ps, shell history), else DEFAULT_PASSWORD.'''
	return os.environ.get('MSSH_PASSWORD') or DEFAULT_PASSWORD

def _password_shown(password):
	'''What -h says about a default password: whether there is one, never the password.'''
	return 'set, not shown' if password else 'none'

REMOTE_OPTIONS_HINT = ("mssh reads words starting with '-' as its own options, also after the hosts. "
	"To pass options to the remote command, quote the whole command: mssh web1 'ls -la'")

# the options passing options on to another program, and what mssh says when one is given no value
_PASSED_ON_OPTIONS = ('-ea', '--extraargs', '-ia', '--ipmi_args')
_PASSED_ON_HINTS = {
	'extraargs': "Give -ea the options for ssh, rsync and scp: -ea='-p 2222'",
	'ipmi_args': "Give -ia the options for ipmitool: -ia='-I lanplus'",
}

# the letters of the options needing a value of their own, by where -ea / -ia pass them: ssh (scp's and
# rsync's -e read the same), and ipmitool
_PASSED_ON_BARE_VALUE_LETTERS = {
	'extraargs': frozenset('BbcDEeFIiJLlmOoPpQRSWw'),
	'ipmi_args': frozenset('AbBCdefHIklLmNoOpPRtTUyz'),
}

def _takes_passed_on_value(option, word, actions=None):
	'''
	Whether -ea or -ia (option, as written) takes word, the word after it, as its value: always, except a
	bare option needing a value of its own (ssh's -p, ipmitool's -I) and a word giving mssh's password
	(-p, -ip, --password=...). There the quotes were forgotten ("-ea -p 2222 web1" ran on a host named
	2222), or -ea was given no value: mssh stops, as before 6.35, before it echoes or records the line.
	actions: the parser's _option_string_actions (default: get_parser()'s).
	'''
	dest = 'extraargs' if option in ('-ea', '--extraargs') else 'ipmi_args'
	if not word.startswith('-') or ' ' in word:
		# no option, or options quoted together for -ea
		return True
	if len(word) == 2 and word[1] in _PASSED_ON_BARE_VALUE_LETTERS[dest]:
		return False
	if word.startswith('-ip'):
		# mssh's -ip with the password attached (argparse reads "-ipx" as -i px, an error)
		return False
	if word[:2] == '-p' and word[2:].isdigit():
		# ssh's or ipmitool's port
		return True
	read = _option_word_actions(word, actions if actions is not None else get_parser()._option_string_actions)
	return not (read and any(action.dest in ('password', 'ipmi_password') for action in read[0]))

def _with_passed_on_values(argv, actions=None):
	'''
	argv with each option passing options on to another program (-ea to ssh, rsync and scp, -ia to
	ipmitool) written together with the word after it ("-ea=-v"): that word is its value, as getopt reads
	ssh's own -o (except as _takes_passed_on_value says). argparse took a word starting with '-' for an
	option: "-ea -v" stopped with an error, and in "-ea '-p 2222'" it read mssh's -p. The words after
	"--" are the command's.
	'''
	words = []
	index = 0
	while index < len(argv):
		word = argv[index]
		index += 1
		if word == '--':
			words.extend(argv[index - 1:])
			break
		if word in _PASSED_ON_OPTIONS and index < len(argv) and _takes_passed_on_value(word, argv[index], actions):
			word = '{}={}'.format(word, argv[index])
			index += 1
		words.append(word)
	return words

def _spaces_hidden(word):
	'''
	word for the --config_file pre-parser, which knows no other option: it reads a word holding a space
	as the file given with --config_file, "-ea=-p 2222" too. The spaces of a value given to -ea or -ia
	are hidden from it as NULs, which no argument holds.
	'''
	name, equals, _ = word.partition('=')
	return word.replace(' ', '\0') if equals and name in _PASSED_ON_OPTIONS else word

class _MsshArgumentParser(argparse.ArgumentParser):
	'''
	argparse, taking option names in full only: a word is an mssh option by its name ('-u',
	'--username', '-u=root'), or as a short option with its value or more short flags in the same
	word ('-uroot', '-qj'), never as an abbreviation. mssh reads options among the remote command's
	words too, where an abbreviation turned "bash -c" into -ci (ssh-copy-id) and "--user x" into
	--username. allow_abbrev=False is no fix: before Python 3.12 it keeps single-dash abbreviations
	("-c" still means -ci), and on 3.6 and 3.7 it also stops "-qj" from meaning "-q -j" (bpo-26967).
	'''
	def _get_option_tuples(self, option_string):
		# argparse's readings of a word that is no option name, as (action, option string, ...):
		# abbreviations alone do not count, and with a full-name reading argparse's answer stands
		# ("-pr" is "-p r" or "-pre": ambiguous, an error as it always was)
		readings = super(_MsshArgumentParser, self)._get_option_tuples(option_string)
		name = option_string.partition('=')[0]
		if any(reading[1] in (name, option_string[:2]) for reading in readings):
			return readings
		return []

	def error(self, message):
		hint = REMOTE_OPTIONS_HINT
		for action in self._actions:
			# -ea or -ia as the line's last word: the hint about the remote command does not fit
			if action.dest in _PASSED_ON_HINTS and message.startswith('argument {}:'.format('/'.join(action.option_strings))):
				hint = _PASSED_ON_HINTS[action.dest]
		super(_MsshArgumentParser, self).error('{}\n{}'.format(message, hint))

def get_parser():
	parser = _MsshArgumentParser(
		description='Run a command on multiple hosts, Use #HOST# or #HOSTNAME# to replace the host name in the command.',
		epilog=(
			f"Terminal color capability: {get_terminal_color_capability()}\n"
			f"Found bins: \n{pformat(set(_binPaths.values()))}\n"
			f"Missing bins: \n{pformat(_binCalled - set(_binPaths.keys()))}\n"
			f"Config file chain: \n{pformat(CONFIG_FILE_CHAIN)}\n"
			f"Hosts Env files searched:\n{pformat(DEFAULT_ENV_FILES)}\n\n"
			f"{REMOTE_OPTIONS_HINT}"
		),
		formatter_class=argparse.RawTextHelpFormatter,
	)
	parser.add_argument('hosts', metavar='hosts', type=str, nargs='?', help=_plain_help(f'Hosts to run the command on, use "," to seperate hosts. (default: {DEFAULT_HOSTS})'),default=DEFAULT_HOSTS)
	parser.add_argument('commands', metavar='commands', type=str, nargs='*',default=None,help='the command to run on the hosts / the destination of the files #HOST# or #HOSTNAME# will be replaced with the host name.')
	parser.add_argument('-u','--username', type=str,help=_plain_help(f'The general username to use to connect to the hosts via ssh. Will get overwrote by individual username@host if specified. (default: {DEFAULT_USERNAME})'),default=DEFAULT_USERNAME)
	parser.add_argument('-p', '--password', type=str,help=_plain_help(f'The password to use to connect to the hosts via ssh, "-p -" to be asked for it, or set MSSH_PASSWORD. (default: {_password_shown(_default_password())})'),default=_default_password())
	parser.add_argument('-k','--identity_file','--key','--identity',nargs='?', type=str,help=_plain_help(f'The identity file to use to connect to the hosts. Implies --use_key. Specify a folder for program to search for a key. Use option without value to use {DEFAULT_SSH_KEY_SEARCH_PATH} (default: {DEFAULT_IDENTITY_FILE})'),const=DEFAULT_SSH_KEY_SEARCH_PATH,default=DEFAULT_IDENTITY_FILE)
	parser.add_argument('-uk','--use_key', action='store_true', help=_plain_help(f'Attempt to use public key file to connect to the hosts. (default: {DEFAULT_USE_KEY})'), default=DEFAULT_USE_KEY)
	parser.add_argument('-ea','--extraargs',type=str,help=_plain_help(f'Extra arguments to pass to the ssh / rsync / scp command. (Use -ia for ipmi arguments) Put in one string for multiple arguments. The word after -ea is its value, also when it starts with "-": quote an option with its value. Ex. -ea "-p 2222 -A" (default: {DEFAULT_EXTRA_ARGS})'),default=DEFAULT_EXTRA_ARGS)
	parser.add_argument("-11",'--oneonone', action='store_true', help=_plain_help(f"Run one corresponding command on each host. (default: {DEFAULT_ONE_ON_ONE})"), default=DEFAULT_ONE_ON_ONE)
	parser.add_argument("-f","--file", action='append', help="The file to be copied to the hosts. Use -f multiple times to copy multiple files")
	parser.add_argument('-s','-fs','--file_sync',nargs='?', action='append', help=_plain_help(f'Operate in file sync mode, sync path in <COMMANDS> from this machine to <HOSTS>. Treat --file <FILE> and <COMMANDS> both as source and source and destination will be the same in this mode. Infer destination from source path. (default: {DEFAULT_FILE_SYNC})'),const=True, default=[DEFAULT_FILE_SYNC])
	parser.add_argument('-W','--scp', action='store_true', help=_plain_help(f'Use scp for copying files instead of rsync. Need to use this on windows. (default: {DEFAULT_SCP})'), default=DEFAULT_SCP)
	parser.add_argument('-G','-gm','--gather_mode', action='store_true', help='Gather files from the hosts instead of sending files to the hosts. Will send remote files specified in <FILE> to local path specified in <COMMANDS>  (default: False)', default=False)
	parser.add_argument("-t","--timeout", type=int, help=_plain_help(f"Idle timeout in seconds: stop a host's command after this long without output. Set default value via DEFAULT_CLI_TIMEOUT in config file. Use 0 for disabling timeout. (default: {DEFAULT_CLI_TIMEOUT})"), default=DEFAULT_CLI_TIMEOUT)
	parser.add_argument('-T','--use_script_timeout',action='store_true', help=_plain_help(f'Use shortened timeout suitable to use in a script. Set value via DEFAULT_TIMEOUT field in config file. (current: {DEFAULT_TIMEOUT})'), default=False)
	parser.add_argument("-r","--repeat", type=_positive_int, help=_plain_help(f"Repeat the command for a number of times (default: {DEFAULT_REPEAT})"), default=DEFAULT_REPEAT)
	parser.add_argument("-i","--interval", type=int, help=_plain_help(f"Interval between repeats in seconds (default: {DEFAULT_INTERVAL})"), default=DEFAULT_INTERVAL)
	parser.add_argument('-M',"--ipmi", action='store_true', help=_plain_help(f"Use ipmitool to run the command. (default: {DEFAULT_IPMI})"), default=DEFAULT_IPMI)
	parser.add_argument("-mpre","--ipmi_interface_ip_prefix", type=str, help=_plain_help(f"The prefix of the IPMI interfaces (default: {DEFAULT_IPMI_INTERFACE_IP_PREFIX})"), default=DEFAULT_IPMI_INTERFACE_IP_PREFIX)
	parser.add_argument("-pre","--interface_ip_prefix", type=str, help=_plain_help(f"The prefix of the for the interfaces (default: {DEFAULT_INTERFACE_IP_PREFIX})"), default=DEFAULT_INTERFACE_IP_PREFIX)
	parser.add_argument('-iu','--ipmi_username', type=str,help=_plain_help(f'The username to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_USERNAME})'),default=DEFAULT_IPMI_USERNAME)
	parser.add_argument('-ip','--ipmi_password', type=str,help=_plain_help(f'The password to use to connect to the hosts via ipmi. (default: {_password_shown(DEFAULT_IPMI_PASSWORD)})'),default=DEFAULT_IPMI_PASSWORD)
	parser.add_argument('-ia','--ipmi_args',type=str,help=_plain_help(f'The arguments passed to ipmitool to use to connect to the hosts via ipmi. The word after -ia is its value, also when it starts with "-": quote an option with its value. Ex. -ia "-I lanplus" (default: {DEFAULT_IPMI_ARGS})'),default=DEFAULT_IPMI_ARGS)
	parser.add_argument('-im','--ipmi_method', type=str,help=_plain_help(f'The method to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_METHOD})'),default=DEFAULT_IPMI_METHOD)
	parser.add_argument('-irlt','--ipmi_retry_lockout_time', type=int,help=_plain_help(f'The time in seconds to retry the lockout of the hosts via ipmi. (default: {DEFAULT_IPMI_RETRY_LOCKOUT_TIME})'),default=DEFAULT_IPMI_RETRY_LOCKOUT_TIME)
	parser.add_argument('-S',"-q","-nw","--no_watch", action='store_true', help=_plain_help(f"Quiet mode, no curses watch, only print the output. (default: {DEFAULT_NO_WATCH})"), default=DEFAULT_NO_WATCH)
	parser.add_argument("-ww",'--window_width', type=int, help=_plain_help(f"The minimum character length of the curses window. (default: {DEFAULT_WINDOW_WIDTH})"), default=DEFAULT_WINDOW_WIDTH)
	parser.add_argument("-wh",'--window_height', type=int, help=_plain_help(f"The minimum line height of the curses window. (default: {DEFAULT_WINDOW_HEIGHT})"), default=DEFAULT_WINDOW_HEIGHT)
	parser.add_argument('-B','-sw','--single_window', action='store_true', help=_plain_help(f'Use a single window for all hosts. (default: {DEFAULT_SINGLE_WINDOW})'), default=DEFAULT_SINGLE_WINDOW)
	parser.add_argument('-R','-eo','--error_only', action='store_true', help=_plain_help(f'Only print the error output. (default: {DEFAULT_ERROR_ONLY})'), default=DEFAULT_ERROR_ONLY)
	parser.add_argument('-Q',"-no","--no_output","--quiet", action='store_true', help=_plain_help(f"Do not print the output. (default: {DEFAULT_NO_OUTPUT})"), default=DEFAULT_NO_OUTPUT)
	parser.add_argument('-Z','-rz','--return_zero', action='store_true', help=_plain_help(f"Return 0 even if there are errors. (default: {DEFAULT_RETURN_ZERO})"), default=DEFAULT_RETURN_ZERO)
	parser.add_argument('-C','--no_env', action='store_true', help=_plain_help(f'Do not load the command line environment variables. (default: {DEFAULT_NO_ENV})'), default=DEFAULT_NO_ENV)
	parser.add_argument('-ef',"--env_file", type=str, help="Replace the env file look up chain with this env_file. ( Still work with --no_env ) (default: None)", default='')
	parser.add_argument('-efs',"--env_files", action='append', help="The files to load the mssh file based environment variables from. Can specify multiple. Load first to last. ( Still work with --no_env ) (default: [])", default=[])
	parser.add_argument("-m","--max_connections", type=int, help="Max number of connections to use (default: 4 * cpu_count)", default=DEFAULT_MAX_CONNECTIONS)
	parser.add_argument("-j","--json", action='store_true', help=_plain_help(f"Output in json format. (default: {DEFAULT_JSON_MODE})"), default=DEFAULT_JSON_MODE)
	parser.add_argument('-w',"--success_hosts", action='store_true', help=_plain_help(f"Output the hosts that succeeded in summary as well. (default: {DEFAULT_PRINT_SUCCESS_HOSTS})"), default=DEFAULT_PRINT_SUCCESS_HOSTS)
	parser.add_argument('-P',"-g","--greppable",'--table', action='store_true', help=_plain_help(f"Output in greppable table. (default: {DEFAULT_GREPPABLE_MODE})"), default=DEFAULT_GREPPABLE_MODE)
	su_group = parser.add_mutually_exclusive_group()
	su_group.add_argument('-x',"-su","--skip_unreachable", action='store_true', help=_plain_help(f"Skip unreachable hosts. Note: Hosts that time out before printing anything are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {DEFAULT_SKIP_UNREACHABLE})"), default=DEFAULT_SKIP_UNREACHABLE)
	su_group.add_argument('-a',"-nsu","--no_skip_unreachable",dest = 'skip_unreachable', action='store_false', help=_plain_help(f"Do not skip unreachable hosts. Note: Hosts that time out before printing anything are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {not DEFAULT_SKIP_UNREACHABLE})"), default=not DEFAULT_SKIP_UNREACHABLE)
	parser.add_argument('-uhe','--unavailable_host_expiry', type=int, help=_plain_help(f"Time in seconds to expire the unavailable hosts (default: {DEFAULT_UNAVAILABLE_HOST_EXPIRY})"), default=DEFAULT_UNAVAILABLE_HOST_EXPIRY)
	parser.add_argument('-X',"-sh","--skip_hosts", type=str, help=_plain_help(f"Skip the hosts in the list. (default: {DEFAULT_SKIP_HOSTS if DEFAULT_SKIP_HOSTS else 'None'})"), default=DEFAULT_SKIP_HOSTS)
	parser.add_argument('--generate_config_file', action='store_true', help='Restore / generate using the build-in default configs with default config file chain and command line argument to write to --store_config_file / stdout')
	parser.add_argument('--config_file', type=str,nargs='?', help='Load additional config file to apply, Warning: will over write CLI options. Use without a path will use multiSSH3.config.json',const='multiSSH3.config.json',default=None)
	parser.add_argument('--store_config_file',type = str,nargs='?',help=_plain_help(f'Refresh / store the specified config file with new params and command line args into the config file. Defaults to the first config file found in search path: {__working_config_file}'),const=...)
	parser.add_argument('--debug', action='store_true', help='Print debug information')
	parser.add_argument('-ci','--copy_id', action='store_true', help='Copy the ssh id to the hosts')
	parser.add_argument('-I','-nh','--no_history', action='store_true', help=_plain_help(f'Do not record the command to history. Default: {DEFAULT_NO_HISTORY}'), default=DEFAULT_NO_HISTORY)
	parser.add_argument('-hf','--history_file', type=str, help=_plain_help(f'The file to store the history. (default: {DEFAULT_HISTORY_FILE})'), default=DEFAULT_HISTORY_FILE)
	parser.add_argument('--script', action='store_true', help='Run the command in script mode, short for -SCRIPT or --no_watch --skip_unreachable --no_env --no_history --greppable --error_only')
	parser.add_argument('-e','--encoding', type=_text_encoding, help=_plain_help(f'The encoding to use for the output. (default: {DEFAULT_ENCODING})'), default=DEFAULT_ENCODING)
	parser.add_argument('-dt','--diff_display_threshold', type=float, help=_plain_help(f'The threshold of lines to display the diff when files differ. {{0-1}} Set to 0 to always display the diff. Set to 1 to disable diff. (Only merge same) (default: {DEFAULT_DIFF_DISPLAY_THRESHOLD})'), default=DEFAULT_DIFF_DISPLAY_THRESHOLD)
	parser.add_argument('--force_truecolor', action='store_true', help=_plain_help(f'Force truecolor output even when not in a truecolor terminal. (default: {FORCE_TRUECOLOR})'), default=FORCE_TRUECOLOR)
	parser.add_argument('--add_control_master_config', action='store_true', help='Add ControlMaster configuration to ~/.ssh/config to speed up multiple connections to the same host.')
	parser.add_argument('--host_file', type=str,help=_plain_help(f'The hosts file mssh looks host names up in before DNS, in the format of {_SYSTEM_HOST_FILE} (an IP address, then names, per line). Not a list of hosts to run on. Default: {DEFAULT_HOST_FILE}'), default=DEFAULT_HOST_FILE)
	parser.add_argument('--completion', nargs='+', metavar='ARG', help='Shell autocomplete: print the glue for bash, zsh or fish, or "install [SHELL] [editor]" / "uninstall [SHELL]" it for the current user ("editor": the plain-bash mssh line editor)')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} @ {COMMIT_DATE} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	return parser

def _parse_command_line(parser, argv = None):
	'''Parse argv with mssh's parser as Python 3.12.8+ argparse does, on every Python.

	Options and positionals mix freely. The first "--" ends the options: the word after it is the hosts
	unless they came before it, and every later word is a command word, dash words and a later "--"
	included. Older argparse read the options again after a "--" in front of the hosts ("mssh -- h -u y"
	set the username) and dropped every "--"; Python 3.6 kept it in the commands after an option. So only
	the words before the "--" go to argparse, and the words after it are placed here.
	'''
	argv = list(sys.argv[1:] if argv is None else argv)
	after = None
	if '--' in argv:
		cut = argv.index('--')
		argv, after = argv[:cut], argv[cut + 1:]
		default_hosts = parser.get_default('hosts')
		# tells "no hosts before the --" from hosts typed as the default's value
		no_hosts = object()
		parser.set_defaults(hosts=no_hosts)
	try:
		try:
			namespace, leftovers = parser.parse_intermixed_args(argv), []
		except Exception:
			# Python 3.6 has no parse_intermixed_args: what parse_known_args cannot place becomes commands
			namespace, leftovers = parser.parse_known_args(argv)
	finally:
		if after is not None:
			parser.set_defaults(hosts=default_hosts)
	commands = namespace.commands or []
	if after is not None:
		before = ([] if namespace.hosts is no_hosts else [namespace.hosts]) + commands
		words = before + after
		namespace.hosts = words[0] if words else default_hosts
		commands = words[1:]
		# leftovers come from before the "--", so they go in front of the words after it
		at = max(len(before) - 1, 0)
		commands[at:at] = leftovers
	elif leftovers:
		commands += leftovers
	if leftovers:
		eprint(f"Warning: Unknown arguments, treating all as commands: {leftovers!r}\n{REMOTE_OPTIONS_HINT}")
	namespace.commands = commands
	return namespace

def _option_word_actions(word, actions):
	'''
	The actions of mssh's parser a word starting with '-' names, as _MsshArgumentParser reads it, and
	whether the last of them takes the next word as its value; None for a word that names none (argparse
	then stops with an error). Full names only: '-u', '--username', '-u=root', '-uroot', '-qj'.
	'''
	name, equals, _ = word.partition('=')
	if name in actions:
		action = actions[name]
		return [action], action.nargs != 0 and not equals
	if word.startswith('--'):
		return None
	readings = []
	rest = word[1:]
	while rest:
		action = actions.get('-' + rest[0])
		if action is None:
			return None
		readings.append(action)
		if action.nargs != 0:
			# the rest of the word is its value
			return readings, len(rest) == 1
		rest = rest[1:]
	return readings, False

def _shown_option_word(word, readings):
	'''The word as a note shows it: without a value attached to it ('-uroot' as '-u', '--password=x' as '--password').'''
	if word.partition('=')[0] in {name for action in readings for name in action.option_strings}:
		return word.partition('=')[0]
	if readings and readings[-1].nargs != 0:
		# short options written together, the last one with its value attached: one letter each
		return word[:1 + len(readings)]
	return word

def _looks_like_option(word):
	'''Whether argparse takes word for an option, not a positional or a value: a word holding a space never is.'''
	return word.startswith('-') and word != '-' and ' ' not in word

# characters the shell takes for itself: a word holding one (or a space) reached mssh from quotes
_SHELL_CHARACTERS = frozenset(' \t\n|&;<>()$`\'"\\')
# flags that only change how mssh shows its output: at the end of a line, most likely mssh's own
# (mssh web1 uptime -q), and taking one wrongly costs only the look of the output
_DISPLAY_FLAGS = frozenset(('no_watch', 'json', 'greppable', 'no_output', 'error_only', 'success_hosts',
	'single_window', 'return_zero', 'no_history', 'debug', 'force_truecolor'))

def _options_after_the_command_note(argv, parser=None):
	'''
	A note for the words of argv mssh reads as its own options after the first word of the remote
	command, or None. mssh reads its options anywhere on the line, so a remote command typed
	unquoted loses them: `mssh all df -h` prints mssh's help, `mssh all uname -a` runs uname without
	-a. Words after "--" are the command's. A password given there is never repeated.

	The shell has removed the quotes, so `mssh web1 'uptime' -q` reads as `mssh web1 uptime -q`.
	Nothing is noted where the line shows the option was meant for mssh: after a command word the
	shell could not have given unquoted (one holding a space or a shell character), and for display
	flags (_DISPLAY_FLAGS) at the end of the line. The note says what to type in case it was not.
	'''
	parser = parser or get_parser()
	actions = parser._option_string_actions
	words = list(argv)
	positionals = []
	found = []
	quoted = False
	index = 0
	while index < len(words):
		word = words[index]
		index += 1
		if word == '--':
			words = words[:index - 1]
			break
		if not _looks_like_option(word):
			positionals.append(index - 1)
			if len(positionals) >= 2 and _SHELL_CHARACTERS.intersection(word):
				# a quoted command: the options after it are mssh's, as meant
				quoted = True
			continue
		read = _option_word_actions(word, actions)
		if read is None:
			continue
		readings, takes_next = read
		if takes_next and index < len(words) and ((word in _PASSED_ON_OPTIONS and _takes_passed_on_value(word, words[index], actions))
				or not _looks_like_option(words[index])):
			# its value (the word after -ea or -ia even when it starts with '-': _with_passed_on_values)
			index += 1
		if len(positionals) >= 2 and not quoted:
			found.append((index, word, readings, takes_next or readings[-1].nargs != 0))
	# a display flag is noted only among the command's words, not after the last of them
	last = positionals[-1] if positionals else -1
	found = [(word, readings) for at, word, readings, takes_value in found
		if takes_value or at <= last or not all(action.dest in _DISPLAY_FLAGS for action in readings)]
	if not found:
		return None
	start = positionals[1]
	command = words[start]
	names = []
	for _, readings in found:
		for action in readings:
			long_name = max(action.option_strings, key=len)
			if action.dest == 'help':
				long_name += ': mssh prints its help and runs nothing'
			elif action.dest == 'version':
				long_name += ': mssh prints its version and runs nothing'
			if long_name not in names:
				names.append(long_name)
	several = len(found) > 1
	text = "Note: mssh read {} after the command '{}' as its own option{} ({}). If {} meant for {}, quote the command".format(
		', '.join(_shown_option_word(word, readings) for word, readings in found), command, 's' if several else '',
		', '.join(names), 'they were' if several else 'it was', command)
	if any(action.dest in ('password', 'ipmi_password') for _, readings in found for action in readings):
		return text + '.'
	return '{}: mssh {} {}'.format(text, shlex.quote(words[positionals[0]]), shlex.quote(' '.join(words[start:])))

# the IPMI options: argparse dest -> IPMI definition key
_IPMI_OPTIONS = (
	('ipmi_interface_ip_prefix', 'interface_ip_prefix'),
	('ipmi_username', 'username'),
	('ipmi_password', 'password'),
	('ipmi_args', 'args'),
	('ipmi_method', 'ipmi_method'),
	('ipmi_retry_lockout_time', 'retry_lockout_time'),
)
# the default of an option process_args needs to know was given
_NOT_GIVEN = object()

def process_args(args = None):
	global __configs_from_file
	global _ipmi_command_line
	global __cli_option_defaults
	args = _with_passed_on_values(sys.argv[1:] if args is None else args)
	cfp = 	parser = _MsshArgumentParser(add_help=False)
	cfp.add_argument('--config_file', type=str,nargs='?',const='multiSSH3.config.json',default=None)
	try:
		cfpa, args = cfp.parse_known_args([_spaces_hidden(word) for word in args])
		args = [word.replace('\0', ' ') for word in args]
		if cfpa.config_file:
			# expanded here: the shell leaves a ~ after --config_file= as it is
			config_file = os.path.expanduser(cfpa.config_file)
			if os.path.exists(config_file):
				configs = load_config_file(config_file, check_trust=False)
				__configs_from_file.update(configs)
				_apply_config(configs)
				# the program paths were looked up at import, before this file was read
				_find_programs()
			else:
				eprint("Warning: Config file {!r} not found, ignoring it.".format(cfpa.config_file))
	except Exception:
		pass
	parser = get_parser()
	# before main() sets globals from the options: what a replay of the echoed / recorded line gets
	__cli_option_defaults = _parser_defaults(parser)
	# the IPMI options the command line gives, also when they repeat a default: _ipmi_definitions_for_host
	ipmi_option_defaults = {dest: parser.get_default(dest) for dest, _ in _IPMI_OPTIONS}
	parser.set_defaults(**{dest: _NOT_GIVEN for dest in ipmi_option_defaults})
	_install_signal_handlers()
	args = _parse_command_line(parser, args)
	for dest in ('extraargs', 'ipmi_args'):
		# argparse before Python 3.11 drops a "--" given as an option's value (the echo said --extraargs='[]')
		if getattr(args, dest, None) == []:
			setattr(args, dest, '--')
	try:
		args.config_file = cfpa.config_file
	except Exception:
		pass
	try:
		args.repeat = _positive_int(args.repeat)
	except (TypeError, ValueError, argparse.ArgumentTypeError) as exc:
		parser.error("argument -r/--repeat: {}".format(exc))
	if args.script:
		args.no_watch = True
		args.skip_unreachable = True
		args.no_env = True
		args.no_history = True
		args.greppable = True
		args.error_only = True
	
	if args.file_sync:
		for path in args.file_sync:
			if path and isinstance(path, str):
				if args.file:
					if path not in args.file:
						args.file.append(path)
				else:
					args.file = [path]
		args.file_sync = any(args.file_sync)
	else:
		args.file_sync = False
	if args.unavailable_host_expiry <= 0:
		eprint(f"Warning: The unavailable host expiry time {args.unavailable_host_expiry} is less than 0, setting it to 10 seconds.")
		args.unavailable_host_expiry = 10
	# DEFAULT_IPMI_DEFINITIONS stays as the config files set it (--store_config_file writes it back),
	# each host's list is made from it when the host runs
	_ipmi_command_line = {}
	for dest, key in _IPMI_OPTIONS:
		if getattr(args, dest) is _NOT_GIVEN:
			setattr(args, dest, ipmi_option_defaults[dest])
		else:
			_ipmi_command_line[key] = getattr(args, dest)
	return args

def process_config_file(args):
	global __configs_from_file
	global __working_config_file
	if args.generate_config_file or args.store_config_file:
		if args.store_config_file:
			if args.store_config_file is ...:
				configFileToWriteTo = __working_config_file
			else:
				# the shell leaves a ~ after --store_config_file= as it is
				configFileToWriteTo = os.path.expanduser(args.store_config_file)
		else:
			configFileToWriteTo = None
		written = write_default_config(args,configFileToWriteTo,force=args.generate_config_file)
		if not args.commands and not args.file:
			# a failed write already printed the new config, the file holds the old one (or nothing)
			if configFileToWriteTo and written:
				with open(configFileToWriteTo,'r') as f:
					eprint(f"Config file {configFileToWriteTo} content: \n{f.read()}")
			_exit_with_code(0)
	return args

	# if there are more than 1 commands, and every command only consists of one word,
	# we will ask the user to confirm if they want to run multiple commands or just one command.

def process_commands(args):
	if not args.file and len(args.commands) > 1 and all([len(command.split()) == 1 for command in args.commands]):
		eprint("Multiple one word command detected, what to do? (1/m/n)")
		eprint(f"1:  Run 1 command [{' '.join(args.commands)}] on all hosts ( default )")
		eprint(f"m:  Run multiple commands [{', '.join(args.commands)}] on all hosts")
		eprint("n:  Exit")
		inStr = input_with_timeout_and_countdown(3)
		if (not inStr) or inStr.lower().strip().startswith('1'):
			args.commands = [" ".join(args.commands)]
			eprint(f"\nRunning 1 command: {args.commands[0]!r} on all hosts")
		elif inStr.lower().strip().startswith('m'):
			eprint(f"\nRunning multiple commands: {', '.join(args.commands)!r} on all hosts")
		else:
			_exit_with_code(0, "Aborted by user, no commands to run")
	return args

def process_keys(args):
	if args.identity_file or args.use_key:
		if not args.identity_file:
			args.identity_file = find_ssh_key_file()
		else:
			if os.path.isdir(os.path.expanduser(args.identity_file)):
				args.identity_file = find_ssh_key_file(args.identity_file)
			elif not os.path.exists(os.path.expanduser(args.identity_file)):
				eprint(f"Warning: Identity file {args.identity_file!r} not found. Passing to ssh anyway. Proceed with caution.")
	return args

# The block --add_control_master_config keeps in ~/.ssh/config, for every ssh the user runs.
# ssh exits with 255 and runs nothing when the directory of its ControlPath is missing, so each
# place is used only when a Match exec check finds it usable: logind's /run/user/<uid> (gone
# without a login session: su, sudo, cron, containers), else /dev/shm/multiSSH3-<uid>, steps 2 and
# 3 of runtime_dir, made 0700 by the check when missing. That one must be ours and writable by us
# alone: ssh trusts whatever listens where it looks for its master and hands it the terminal.
# With neither, no ControlPath is set and ssh connects without sharing. Not ~/.ssh: unix sockets
# may not work on an NFS, GPFS or Lustre home. The checks run in /bin/sh whatever the login shell
# (csh, fish) and find the uid themselves: OpenSSH 7.4 (RHEL 7) has no %i in Match exec, and an
# unknown token there stops every ssh. Ends in "Host *" so lines added after it stay global.
_CONTROL_MASTER_BLOCK = '''# Added by multiSSH3.py to speed up subsequent connections (mssh --add_control_master_config).
# ssh keeps one connection per host open for an hour after its last use and shares it. Its socket
# goes in {run_user}/<uid> while you have a login session, else in {shm}/multiSSH3-<uid> when that
# is a directory only you can write to (su, sudo, cron, containers); with neither, ssh does not share.
Match exec "/bin/sh -c 'u=$(id -u) || exit 1; test -O {run_user}/$u -a -w {run_user}/$u'"
  ControlPath {run_user}/%i/ssh_sockets_%C
Match exec "/bin/sh -c 'u=$(id -u) || exit 1; test -O {run_user}/$u -a -w {run_user}/$u && exit 1; d={shm}/multiSSH3-$u; test -d $d || mkdir -m 700 $d 2>/dev/null; test -O $d || exit 1; case $(ls -ld $d) in drwx?-??-*) ;; *) exit 1;; esac'"
  ControlPath {shm}/multiSSH3-%i/ssh_sockets_%C
Host *
  ControlMaster auto
  ControlPersist 3600
# End of the block added by multiSSH3.py
'''
# what --add_control_master_config wrote up to 6.31 (the comment only when it appended to a config)
_OLD_CONTROL_MASTER_COMMENT = b'# Added by multiSSH3.py to speed up subsequent connections'
_OLD_CONTROL_MASTER_LINES = [b'Host *', b'ControlMaster auto', b'ControlPath /run/user/%i/ssh_sockets_%C', b'ControlPersist 3600']

def _control_master_block():
	'''The ControlMaster block for ~/.ssh/config, its places those of runtime_dir.'''
	return _CONTROL_MASTER_BLOCK.format(run_user=_RUN_USER_ROOT, shm=_SHM_DIR)

def _find_lines(stripped, wanted, start=0):
	'''Index of the first run of lines equal to wanted in stripped, from start, or -1.'''
	for index in range(start, len(stripped) - len(wanted) + 1):
		if stripped[index:index + len(wanted)] == wanted:
			return index
	return -1

def _with_control_master_block(content):
	'''
	The ssh config content (bytes) with mssh's ControlMaster block in it.

	The block mssh wrote up to 6.31 is replaced by the current one, a second copy dropped; without
	it, the block is added at the end unless it is there already. Lines compare without the
	whitespace around them, and every other byte stays as it was.

	Returns:
		tuple: (the new content, 'replaced', 'added' or 'unchanged')
	'''
	newline = b'\r\n' if b'\r\n' in content else b'\n'
	block = newline.join(_control_master_block().encode().splitlines()) + newline
	lines = content.splitlines(True)
	stripped = [line.strip() for line in lines]
	has_block = _find_lines(stripped, [line.strip() for line in block.splitlines()]) >= 0
	spans = []
	index = _find_lines(stripped, _OLD_CONTROL_MASTER_LINES)
	while index >= 0:
		start = index - 1 if index and stripped[index - 1] == _OLD_CONTROL_MASTER_COMMENT else index
		spans.append((start, index + len(_OLD_CONTROL_MASTER_LINES)))
		index = _find_lines(stripped, _OLD_CONTROL_MASTER_LINES, spans[-1][1])
	if spans:
		pieces = []
		position = 0
		for start, end in spans:
			pieces.extend(lines[position:start])
			if not has_block:
				pieces.append(block)
				has_block = True
			position = end
		pieces.extend(lines[position:])
		return b''.join(pieces), 'replaced'
	if has_block:
		return content, 'unchanged'
	if content and not content.endswith(b'\n'):
		content += newline
	if content:
		# a blank line between the user's config and the block, as before
		content += newline
	return content + block, 'added'

def _old_control_paths(content):
	'''Line numbers of the old block's ControlPath left in content (a copy of it someone changed).'''
	stripped = [line.strip() for line in content.splitlines()]
	block_lines = [line.strip() for line in _control_master_block().encode().splitlines()]
	# the current block's first Match has the same line, with the real /run/user
	start = _find_lines(stripped, block_lines)
	ours = range(start, start + len(block_lines)) if start >= 0 else ()
	return [index + 1 for index, line in enumerate(stripped) if line == _OLD_CONTROL_MASTER_LINES[2] and index not in ours]

def _replace_file(path, content, mode=None, follow=True, owner=True):
	'''
	Write content (bytes) to the file at path, never leaving it half written: a temporary copy with mode
	(default: the old file's, else 0644) and the old file's owner and group is renamed over it, so a full
	disk or quota keeps the old one. A symlink is written through (into a dotfiles repository), unless
	follow is False. A file of another user (sudo keeping HOME) is only replaced if we can keep its owner,
	unless owner is False.
	owner: True keeps the old file's, a stat result gives that owner and group (the old file was moved
	aside; failing to give them is not an error), False leaves the file the writer's own.
	'''
	target = os.path.realpath(path) if follow else path
	try:
		st = os.stat(target) if follow else os.lstat(target)
	except FileNotFoundError:
		st = None
	if mode is None:
		mode = stat.S_IMODE(st.st_mode) if st is not None else 0o644
	if owner is True:
		owner = st
	temporary = '{}.{}.tmp'.format(target, uuid4().hex)
	fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), mode)
	try:
		with os.fdopen(fd, 'wb') as f:
			if hasattr(os, 'fchmod'):
				# O_CREAT's mode is reduced by the umask, set it exactly
				os.fchmod(f.fileno(), mode)
			if owner and hasattr(os, 'chown'):
				try:
					os.chown(temporary, owner.st_uid, owner.st_gid)
				except OSError:
					if st is not None and st.st_uid != os.getuid():
						raise
					# ours (or no file left to keep): only the owner or group could not be given
			f.write(content)
			f.flush()
			os.fsync(f.fileno())
		os.replace(temporary, target)
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

def process_control_master_config(args):
	if args.add_control_master_config:
		try:
			if not os.path.exists(os.path.expanduser('~/.ssh')):
				os.makedirs(os.path.expanduser('~/.ssh'),mode=0o700)
			ssh_config_file = os.path.expanduser('~/.ssh/config')
			try:
				with open(ssh_config_file,'rb') as f:
					content = f.read()
			except FileNotFoundError:
				content = b''
			new_content, change = _with_control_master_block(content)
			if change == 'unchanged':
				eprint("ControlMaster configuration already in ~/.ssh/config, nothing changed.")
			else:
				_replace_file(ssh_config_file, new_content)
				if change == 'replaced':
					eprint("Replaced the ControlMaster configuration mssh added to ~/.ssh/config before (ssh failed without /run/user/<uid>) with:")
				else:
					eprint("ControlMaster configuration added to ~/.ssh/config:")
				eprint(_control_master_block())
			for number in _old_control_paths(new_content):
				eprint("Warning: ~/.ssh/config line {} still has mssh's old {!r}, in a block changed since mssh added it, so left alone: with it every ssh fails where /run/user/<uid> is missing (su, sudo, cron, containers). Remove that block; mssh's new one is in place.".format(number, _OLD_CONTROL_MASTER_LINES[2].decode()))
		except Exception as e:
			eprint(f"Error adding ControlMaster configuration: {e}")
			import traceback
			traceback.print_exc()
		if not args.commands and not args.file:
			_exit_with_code(0, "Done configuring ControlMaster.")
	return args

def set_global_with_args(args):
	global _emo
	global _stopping
	global _no_env
	global _env_files
	global _explicit_env_files
	global __DEBUG_MODE
	global _encoding
	global __returnZero
	global DEFAULT_DIFF_DISPLAY_THRESHOLD
	global FORCE_TRUECOLOR
	global DEFAULT_HOST_FILE
	_emo = False
	_stopping = False
	if args.env_file:
		_env_files = [args.env_file]
	else:
		_env_files = DEFAULT_ENV_FILES + args.env_files if args.env_files else DEFAULT_ENV_FILES
	_explicit_env_files = {
		os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
		for path in ([args.env_file] if args.env_file else []) + list(args.env_files or [])
	}
	# set before main() echoes the command, which already expands the hosts
	_no_env = args.no_env
	_refresh_expansion_caches()
	__DEBUG_MODE = args.debug
	_encoding = args.encoding
	if args.return_zero:
		__returnZero = True
	DEFAULT_DIFF_DISPLAY_THRESHOLD = args.diff_display_threshold
	FORCE_TRUECOLOR = args.force_truecolor
	if args.host_file:
		DEFAULT_HOST_FILE = args.host_file

#%% ------------ Wrapper Block ----------------
def _import_mssh_complete():
	'''
	Import mssh_complete, which ships next to this file, or None when there is none.

	The mssh_complete.py beside this file is loaded from its path and registered as mssh_complete, which
	puts that directory on no sys.path: a file in it named as a standard module (bisect.py) would hide that
	module from mssh_complete's own imports. With no such file beside this one, mssh_complete is imported as
	installed.
	'''
	if 'mssh_complete' in sys.modules:
		return sys.modules['mssh_complete']
	path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mssh_complete.py')
	if not os.path.isfile(path):
		try:
			import mssh_complete
		except ModuleNotFoundError as error:
			# only a missing mssh_complete is that; an import it makes itself failing is the real error
			if error.name != 'mssh_complete':
				raise
			return None
		return mssh_complete
	import importlib.util
	spec = importlib.util.spec_from_file_location('mssh_complete', path)
	module = importlib.util.module_from_spec(spec)
	sys.modules['mssh_complete'] = module
	try:
		spec.loader.exec_module(module)
	except BaseException:
		sys.modules.pop('mssh_complete', None)
		raise
	return module

def _completion_command(values):
	'''Run `mssh --completion ...` with mssh_complete, which ships next to this file.'''
	mssh_complete = _import_mssh_complete()
	if mssh_complete is None:
		eprint('Error: autocomplete needs mssh_complete.py next to {} (it ships with the multiSSH3 package)'.format(os.path.abspath(__file__)))
		return 1
	return mssh_complete.completion_command(values)

def _summary_host_list(names):
	'''
	The hosts for a summary line, compacted into ranges without DNS.

	Names are not validated again: names that did not resolve stay listed, and their errors are
	not printed a second time. Host tokens that name no host (node[10-1]) are listed as given.
	'''
	names = set(names)
	as_given = sorted((name for name in names if __expand_hostname(name, validate=False) != {name}), key=_natural_sort_key)
	return ','.join(compact_hostnames_local(names.difference(as_given)) + as_given)

def _escape_or_restore_bytes(error):
	'''
	Encoding error handler for our output: what came in as undecodable bytes (an argument or path read
	with surrogateescape, as Python does in the C locale) goes out as those bytes, anything else the
	encoding lacks as a backslash escape (\\u2713).
	'''
	try:
		return codecs.lookup_error('surrogateescape')(error)
	except UnicodeError:
		return codecs.lookup_error('backslashreplace')(error)

_OUTPUT_ERRORS = 'multissh3-escape'

def _escape_unencodable_output():
	'''
	Make stdout and stderr print what their encoding lacks as escapes instead of failing.

	With an ASCII stdout (the C locale on Python 3.6, e.g. cron on CentOS 7) or PYTHONIOENCODING=latin-1,
	printing the results raised UnicodeEncodeError after the commands had run, and their output was lost.
	Python's stderr already escapes; streams set to another lenient handler are left alone.
	'''
	codecs.register_error(_OUTPUT_ERRORS, _escape_or_restore_bytes)
	for name in ('stdout', 'stderr'):
		stream = getattr(sys, name, None)
		if getattr(stream, 'errors', None) not in ('strict', 'surrogateescape'):
			continue
		try:
			if hasattr(stream, 'reconfigure'):
				stream.reconfigure(errors=_OUTPUT_ERRORS)
			elif isinstance(stream, io.TextIOWrapper) and stream is getattr(sys, '__{}__'.format(name), None):
				# Python 3.6 has no reconfigure: a new wrapper on the same buffer. The old one stays
				# referenced as sys.__stdout__, so it is never collected (which would close the buffer)
				stream.flush()
				setattr(sys, name, io.TextIOWrapper(stream.buffer, encoding=stream.encoding, errors=_OUTPUT_ERRORS,
					line_buffering=stream.line_buffering))
		except (AttributeError, OSError, ValueError):
			pass

def _terminal_to_ask_on():
	'''Whether there is a terminal to ask for a password on: getpass asks on /dev/tty.'''
	try:
		with open('/dev/tty'):
			return True
	except OSError:
		return False

def _ask_for_password(args):
	'''
	-p -: ask for the ssh password on the terminal, nothing echoed, before anything runs.

	Without a terminal, or without an answer, nothing runs: an empty password would be a failed login
	on every host (fail2ban).
	'''
	if args.password != '-':
		return args
	if not _terminal_to_ask_on():
		_exit_with_code(2, '-p - asks for the password on the terminal, and there is none: set MSSH_PASSWORD, or DEFAULT_PASSWORD in a config file')
	# Ctrl C stops mssh here: its own handler would wait for the hosts, and none has started
	handler = signal.getsignal(signal.SIGINT)
	try:
		signal.signal(signal.SIGINT, signal.default_int_handler)
		password = getpass.getpass('ssh password for mssh: ')
	except KeyboardInterrupt:
		eprint('')
		_exit_with_code(130, 'no password given: nothing was run')
	except EOFError:
		eprint('')
		password = ''
	finally:
		if handler is not None:
			signal.signal(signal.SIGINT, handler)
	if not password:
		_exit_with_code(1, 'no password given: nothing was run')
	args.password = password
	return args

def _closed_output_to_devnull():
	'''
	mssh started with stdout or stderr closed (>&-): Python gives None for the stream. What mssh would
	write there goes nowhere, as print does with None, without failing where a stream is asked
	whether it is a terminal, or print sending stderr's lines to stdout.
	'''
	for name in ('stdout', 'stderr'):
		if getattr(sys, name) is None:
			try:
				setattr(sys, name, open(os.devnull, 'w'))
			except OSError:
				pass

def main(args = None):
	global __global_suppress_printout
	global __mainReturnCode
	global __failedHosts
	_closed_output_to_devnull()
	_escape_unencodable_output()
	# until the commands start, a reader of our output that is gone ends mssh as SIGPIPE ends other tools
	# (status 141): -h, -V, usage errors, --generate_config_file, the prompts. The disposition is put back for
	# the run, whose status stands (_output_reader_gone) and whose writes to the commands' pipes must not kill mssh
	sigpipe = getattr(signal, 'SIGPIPE', None) if threading.current_thread() is threading.main_thread() else None
	if sigpipe is not None:
		previous_sigpipe = signal.signal(sigpipe, signal.SIG_DFL)
	try:
		try:
			# before the parse: -h there prints mssh's help and exits
			note = _options_after_the_command_note(sys.argv[1:] if args is None else args)
		except Exception as e:
			note = None
			if __DEBUG_MODE:
				eprint(f"Warning: cannot check the options after the command: {e!r}")
		if note:
			eprint(note)
		args = process_args(args)
		if args.completion:
			_exit_with_code(_completion_command(args.completion))
		args = _ask_for_password(args)
		args = process_config_file(args)
		args = process_commands(args)
		args = process_keys(args)
		args = process_control_master_config(args)
	finally:
		if sigpipe is not None:
			# what an exit (-h, -V, a usage error) printed reaches the reader while SIGPIPE still ends mssh
			for stream in (sys.stdout, sys.stderr):
				try:
					stream.flush()
				except Exception:
					pass
			signal.signal(sigpipe, previous_sigpipe)
	set_global_with_args(args)
	
	if args.use_script_timeout:
		# set timeout to the default script timeout if timeout is not set
		if args.timeout == DEFAULT_CLI_TIMEOUT:
			args.timeout = DEFAULT_TIMEOUT
	
	if args.no_output:
		__global_suppress_printout = True
	if not __global_suppress_printout:
		# before the echo, whose host lookups may already fail because of it
		host_file_warning = _host_file_warning()
		if host_file_warning:
			eprint(host_file_warning)
		cmdStr = getStrCommand(**vars(args))
		eprint('> ' + cmdStr)
		# read from the current directory before 6.27
		if os.path.isfile('multiSSH3.config.json') and not (args.config_file and os.path.abspath(os.path.expanduser(args.config_file)) == os.path.abspath('multiSSH3.config.json')):
			eprint("Note: ./multiSSH3.config.json is no longer read automatically; use --config_file multiSSH3.config.json")
	if args.error_only:
		__global_suppress_printout = True

	# failures in every repeat count towards the exit code, not only the last run. Only names are kept
	# between runs, a long --repeat loop must not hold every run's output
	failedHostNames = set()
	succeededHosts = set()
	# hosts not run because they were unreachable in a recent run, they are failed hosts too
	skippedHostNames = set()
	# failed hosts whose server dropped the connection before login: they get a hint
	droppedHostNames = set()
	# record the command once: a line per repeat, each saying --repeat, would replay it repeat^2 times
	if not args.no_history:
		record_command_history(vars(args))
	# the command line runs its hosts and waits for them, whatever a config file sets for scripts
	runArgs = dict(vars(args), no_history=True, return_unfinished=False, no_start=False)
	for i in range(args.repeat):
		if _emo:
			# Ctrl-C during an earlier run: no more repeats
			break
		if i > 0 and args.interval > 0:
			eprint(f"Sleeping for {args.interval} seconds")
			time.sleep(args.interval)

		if not __global_suppress_printout: 
			eprint(f"Running the {i+1}/{args.repeat} time") if args.repeat > 1 else None
		for host in run_command_on_hosts(**runArgs,called=False):
			if host.returncode and host.returncode != 0:
				failedHostNames.add(host.name)
				if host.skipped:
					skippedHostNames.add(host.name)
				if getattr(host, 'dropped_before_login', False):
					droppedHostNames.add(host.name)
			else:
				succeededHosts.add(host.name)
	# each failing host counts once, however many runs or commands it failed (or its --copy_id)
	__mainReturnCode += len(failedHostNames - __failedHosts)
	__failedHosts |= failedHostNames
	succeededHosts -= __failedHosts
	# sort the failed hosts and succeeded hosts
	if __mainReturnCode > 0:
		if not __global_suppress_printout: 
			eprint(f'Complete. Failed hosts (Return Code not 0) count: {__mainReturnCode}')
			eprint(f'failed_hosts: {_summary_host_list(__failedHosts)}')
			if skippedHostNames:
				eprint('Skipped {} unreachable in a recent run, without trying {}: {}'.format(
					'1 host' if len(skippedHostNames) == 1 else '{} hosts'.format(len(skippedHostNames)),
					'it' if len(skippedHostNames) == 1 else 'them',
					_summary_host_list(skippedHostNames)))
			if droppedHostNames:
				eprint(_dropped_login_hint(len(droppedHostNames), args.max_connections))
	else:
		if not __global_suppress_printout: 
			eprint('Complete. All hosts returned 0.')
	
	if args.success_hosts and not __global_suppress_printout:
		eprint(f'succeeded_hosts: {_summary_host_list(succeededHosts)}')

	if threading.active_count() > 1 and not __global_suppress_printout: 
		eprint(f'Remaining active thread: {threading.active_count()}')
	
	_exit_with_code(__mainReturnCode)

if __name__ == "__main__":
	main()
