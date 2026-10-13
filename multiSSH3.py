#!/usr/bin/env python3
# /// script
# requires-python = ">=3.6"
# dependencies = []
# ///
import argparse
import errno
import functools
import getpass
import glob
import io
import ipaddress
import itertools
import json
import math
import os
import queue
import re
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
from uuid import uuid4
from collections import Counter, defaultdict, deque, ChainMap, namedtuple
from itertools import count, product
from pprint import pformat


version = '6.31'
VERSION = version
__version__ = version
COMMIT_DATE = '2026-10-13'
# TODO: Add terminal TUI

# no current-directory entry: a cloned repo or unpacked archive could set any global (e.g. _sshPath),
# use --config_file to load one
CONFIG_FILE_CHAIN = ['~/multiSSH3.config.json',
					 '~/.multiSSH3.config.json',
					 '~/.config/multiSSH3/multiSSH3.config.json',
					 '/etc/multiSSH3.d/multiSSH3.config.json',
					 '/etc/multiSSH3.config.json'] # The first one has the highest priority

ERRORS = []

#%% ------------ User Defined Global Variables ----------------
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
DEFAULT_HOST_FILE = '/etc/hosts'
DEFAULT_ENCODING = 'utf-8'
DEFAULT_DIFF_DISPLAY_THRESHOLD = 0.9
SSH_STRICT_HOST_KEY_CHECKING = False
FORCE_TRUECOLOR = False
ERROR_MESSAGES_TO_IGNORE = [
	'Pseudo-terminal will not be allocated because stdin is not a terminal',
	'Connection to .* closed',
	'Warning: Permanently added',
	'mux_client_request_session',
	'disabling multiplexing',
	'Killed by signal',
	'Connection reset by peer',
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
__ERROR_MESSAGES_TO_IGNORE_REGEX =None
__DEBUG_MODE = False

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
	global ERRORS
	try:
		if 'file' in kwargs:
			print(*args, **kwargs)
		else:
			print(*args, file=sys.stderr, **kwargs)
	except Exception as e:
		print(f"Error: Cannot print to stderr: {e}")
		print(*args, **kwargs)
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
		# only kill the subprocesses this process started
		for proc in list(__running_procs):
			try:
				proc.kill()
			except Exception:
				pass
		_exit_with_code(1, 'Exiting immediately due to Ctrl C')

def input_with_timeout_and_countdown(timeout, prompt='Please enter your selection'):
	"""
	Read input from the user with a timeout (cross-platform).
	If the user does not enter any input within `timeout` seconds, return None.
	Otherwise, return the input string.
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
	if not _etc_hosts and os.path.exists(DEFAULT_HOST_FILE):
		with open(DEFAULT_HOST_FILE,'r') as f:
			for line in f:
				if line.startswith('#') or not line.strip():
					continue
				#ip, host = line.split()[:2]
				chunks = line.split()
				if len(chunks) < 2:
					continue
				ip = chunks[0]
				for host in chunks[1:]:
					_etc_hosts[host] = ip
	if hostname in _etc_hosts:
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
	for cached_function in (_ssh_config_values, _ssh_config_target):
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
def _ssh_config_target(hostname):
	'''
	The host ssh really connects to for hostname, when the ssh config maps it.

	Returns:
		str: The HostName ssh would use, when the config gives hostname another HostName or a
			ProxyJump / ProxyCommand (hosts behind a bastion may only resolve on its far side).
			None for names the config does not single out, so typos are still caught.
	'''
	if 'ssh' not in _binPaths or not hostname or hostname.startswith('-'):
		return None
	config = _ssh_config_values(hostname)
	if not config or not config.get('hostname'):
		return None
	target = config['hostname']
	proxies = [config.get(key, 'none').lower() for key in ('proxyjump', 'proxycommand')]
	# for a name it does not know, ssh -G prints the name back (lowercased) as the hostname
	if target.lower() == hostname.lower() and all(proxy == 'none' for proxy in proxies):
		return None
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
			if target.lower() != hostname.lower() and (getIP(target,local=True) or _resolve_dns(target)):
				return target
			return None
	return target


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
	fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
	try:
		f = os.fdopen(fd, 'r', errors=errors)
	except Exception:
		# e.g. a directory: os.open works, fdopen does not
		os.close(fd)
		raise
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

def load_config_file(config_file, check_trust=True):
	global __working_config_file
	'''
	Load the config file to global variables

	Args:
		config_file (str): The config file
		check_trust (bool): Skip the file unless _untrusted_file_reason accepts it. False for
			files the user named explicitly.

	Returns:
		dict: The config
	'''
	if not os.path.exists(config_file) or os.path.isdir(config_file):
		return {}
	try:
		f = _open_trusted_file(config_file, '--config_file') if check_trust else open(config_file,'r')
		if f is None:
			return {}
		with f:
			config = json.load(f)
		__working_config_file = config_file
	except Exception as e:
		eprint(f"Error: Cannot load config file {config_file!r}: {e}")
		return {}
	return config


def apply_config_key_compat(configs):
	'''
	Normalize legacy / misspelled config keys in-place.

	Configs written before 6.24 used DEAFULT_IPMI_ARGS (typo). Map it to
	DEFAULT_IPMI_ARGS when the correct key is absent.
	'''
	if not configs:
		return configs
	if 'DEAFULT_IPMI_ARGS' in configs and 'DEFAULT_IPMI_ARGS' not in configs:
		configs['DEFAULT_IPMI_ARGS'] = configs['DEAFULT_IPMI_ARGS']
	return configs

#%% Load Config Based Default Global variables
__configs_from_file = {}
# where --store_config_file writes without a path, unless a config file was loaded: one mssh reads by default
__working_config_file = os.path.expanduser('~/.multiSSH3.config.json')
for config_file in reversed(CONFIG_FILE_CHAIN.copy()):
	__configs_from_file.update(load_config_file(os.path.expanduser(config_file)))
apply_config_key_compat(__configs_from_file)
globals().update(__configs_from_file)
# form the regex from the list
if __ERROR_MESSAGES_TO_IGNORE_REGEX:
	eprint('Using __ERROR_MESSAGES_TO_IGNORE_REGEX, ignoring ERROR_MESSAGES_TO_IGNORE')
	__ERROR_MESSAGES_TO_IGNORE_REGEX = re.compile(__ERROR_MESSAGES_TO_IGNORE_REGEX)
else:
	__ERROR_MESSAGES_TO_IGNORE_REGEX =  re.compile('|'.join(ERROR_MESSAGES_TO_IGNORE))
if DEFAULT_ENV_FILE:
	if DEFAULT_ENV_FILE not in DEFAULT_ENV_FILES:
		DEFAULT_ENV_FILES.append(DEFAULT_ENV_FILE)

#%% Load mssh Functional Global Variables
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
_emo = False
# set once the first command starts: before that, Ctrl-C has nothing to stop and exits
_commands_started = False
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
__control_master_string = '''Host *
  ControlMaster auto
  ControlPath /run/user/%i/ssh_sockets_%C
  ControlPersist 3600
'''
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

[check_path(program) for program in _binCalled]

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
		self.lineNumToPrintSet = set() # line numbers to reprint
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
		self.identity_file = identity_file
		self.ip = ip if ip else getIP(name)
		self.current_color_pair = [-1, -1, 1]
		self.output_buffer = io.BytesIO()
		self.stdout_buffer = io.BytesIO()
		self.stderr_buffer = io.BytesIO()
		self.thread = None
		self.interactive_stdin = False # forward the curses TUI key presses to stdin (set while the TUI runs), else /dev/null
		self.skipped = False # True when mssh did not run the command: the host was unreachable in a recent run

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
		newHost.lastUpdateTime = self.lastUpdateTime
		newHost.lastPrintedUpdateTime = self.lastPrintedUpdateTime
		newHost.current_color_pair = self.current_color_pair.copy()
		newHost.interactive_stdin = self.interactive_stdin
		newHost.skipped = self.skipped
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
							if key and values and key != values:
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
					if not ref_value and not _no_env:
						ref_value = _consult_env(ref_key)
					if ref_value:
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
	Get the terminal size

	@params:
		None

	@returns:
		(int,int): the number of columns and rows of the terminal
	'''
	try:
		import os
		_tsize = os.get_terminal_size()
	except Exception:
		try:
			import fcntl
			import struct
			import termios
			packed = fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
			rows, columns = struct.unpack('HHHH', packed)[:2]
			_tsize = (columns, rows)
		except Exception:
			import shutil
			_tsize = shutil.get_terminal_size(fallback=(120, 30))
	return _tsize

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
							#(diffIndex:=findDiffIndex(hostnameTokens, lastHostnameTokens)) != -1 and \
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

def compact_hostnames(Hostnames,verify = True):
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
	global __global_suppress_printout
	# if not isinstance(Hostnames, frozenset):
	# 	hostSet = frozenset(Hostnames)
	# else:
	# 	hostSet = Hostnames
	hostSet = frozenset(expand_hostnames(
		hostname.strip()
		for hostnames_str in Hostnames
		for hostname in hostnames_str.split(',')
	))
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
	than timeout seconds, or an ssh -G that fails, makes it 'unsure'. This does not connect to the
	host, but ssh -G runs the commands of Match exec lines in the ssh config, which may.

	Args:
		hostname (str): One host name, user@ allowed
		timeout (float): Seconds the DNS lookup may take
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
		if _ssh_config_target(hostname):
			return 'valid'
	return 'invalid' if answer == 'no' else 'unsure'

@cache_decorator
def __validate_expand_hostname(hostname):
	'''
	Validate the hostname and expand it if it is a range of IP addresses

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
	elif source == 'env':
		# we will expand these hostnames again
		return expand_hostnames(os.environ[hostname].split(','))
	elif source == 'env_file':
		# we will expand these hostnames again
		return expand_hostnames(readEnvFromFile()[hostname].split(','))
	elif getIP(hostname,local=False):
		return [hostname]
	elif _ssh_config_target(hostname):
		# ssh reaches it through the ssh config, e.g. a host behind a ProxyJump
		return [hostname]
	else:
		global __mainReturnCode
		global __failedHosts
		# validated again after the caches refresh: report once per run_command_on_hosts call
		if hostname not in _reported_invalid_hosts:
			eprint(f"Error: {hostname!r} is not a valid hostname or IP address!")
			defined_in = _current_dir_env_file_defining(hostname)
			if defined_in:
				eprint(f"Note: {hostname!r} is defined in ./{defined_in}, which is no longer read automatically; use --env_files {defined_in}")
			_reported_invalid_hosts.add(hostname)
		# and count once towards the exit code
		if hostname not in __failedHosts:
			__mainReturnCode += 1
			__failedHosts.add(hostname)
		return []

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
		#print(expandedOctets)
		# Generate the expanded hosts
		for ip in list(product(expandedOctets[0],expandedOctets[1],expandedOctets[2],expandedOctets[3])):
			expandedHost.append('.'.join(ip))
	expandedHosts.extend(expandedHost)
	return expandedHosts

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
	'''
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
				try:
					range_start,_, range_end = part.partition('-')
				except ValueError:
					expandedhosts.update(__validate_expand_hostname(hostname) if validate else [hostname])
					continue
				range_start = range_start.strip()
				range_end = range_end.strip()
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
		# This is done by checking if the hostname follows four fields of 
		# "(((\d{1,3}|x|\*|\?)(-(\d{1,3}|x|\*|\?))?)|(\[(\d{1,3}|x|\*|\?)(-(\d{1,3}|x|\*|\?))?\]))" 
		# seperated by .
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
			# we combine the username and hostname
			for user in username:
				[expandedhosts.update({f'{user}@{host}':ip}) for host,ip in zip(hostSetToAdd,iplist)]
		else:
			[expandedhosts.update({host:ip}) for host,ip in zip(hostSetToAdd,iplist)]
	return expandedhosts

def expand_hostnames(hosts):
	'''
	Expand the hostnames in the hosts into a dictionary

	Args:
		hosts (list): A list of hostnames

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

	Ranges, IPv4 ranges and env / env file aliases (recursively) are expanded like
	expand_hostnames does. A name that is not an IP address, in the hosts file or an alias
	is kept as it is and also listed as unresolved: only DNS or the ssh config could confirm it.
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
	# each alias is expanded once per user: shared and looping aliases cannot multiply the work
	walked = set()
	def walk(text, user, depth):
		for token in _split_host_str(text):
			token_user = user
			if '@' in token:
				token_user, token = token.split('@', 1)
				token_user = token_user.strip() or user
			token = token.strip()
			if not token:
				continue
			if _IPV4_RANGE_RE.match(token):
				names = __expandIPv4Address(frozenset([token]))
			else:
				names = __expand_hostname(token, validate=False)
			for name in names:
				name = name.strip().strip('$')
				if not name:
					continue
				source = _local_hostname_source(name)
				if source in ('env', 'env_file'):
					# an alias loop expands to nothing
					if depth < 32 and (name, token_user) not in walked:
						walked.add((name, token_user))
						value = os.environ.get(name) if source == 'env' else readEnvFromFile().get(name)
						walk(value or '', token_user, depth + 1)
					continue
				full = '{}@{}'.format(token_user, name) if token_user else name
				expanded.add(full)
				if source is None:
					unresolved.add(full)
	for host in hosts:
		walk(str(host), None, 0)
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

# environment variables host expansion looked up since the last refresh, with the value seen (None: unset)
_consulted_env = {}

def _consult_env(name):
	'''os.environ.get(name), remembering the value so the caches refresh when it changes.'''
	value = os.environ.get(name)
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
# bytes the reader treats specially, and the unicode line breaks str.splitlines() also splits on
_READER_SPECIAL_BYTES = re.compile(rb'([\n\r\x08])')
_UNICODE_LINE_BREAK = re.compile('[\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]')

def __handle_reading_stream(stream,target, host,buffer:io.BytesIO):
	'''
	Read the stream and append the lines to the target list

	Output is read in chunks. \n, \r and backspace bytes, and runs of other bytes that may hold a
	unicode line break, go through add_byte, which processes one byte at a time (\r returns to
	the line start, backspace deletes, unicode line breaks split lines that grow past each 100
	bytes). Other runs are appended at once, which gives the same result.

	Args:
		stream (io.BufferedReader): The stream to be read
		target (list): The list to append the lines to
		host (Host): The host object
		buffer (io.BytesIO): The current partial line of this stream

	Returns:
		None
	'''
	global _encoding
	def add_line(buffer,target, host):
		current_line_str = buffer.getvalue().decode(_encoding,errors='backslashreplace')
		target.append(current_line_str)
		host.output.append(current_line_str)
		host.lineNumToPrintSet.add(len(host.output)-1)
		buffer.seek(0)
		buffer.truncate(0)
		host.output_buffer.seek(0)
		host.output_buffer.truncate(0)
	def add_byte(char):
		if char == b'\n':
			add_line(buffer,target, host)
			return
		elif char == b'\r':
			buffer.seek(0)
			host.output_buffer.seek(0)
		elif char == b'\x08':
			# backspace
			if buffer.tell() > 0:
				buffer.seek(buffer.tell() - 1)
				buffer.truncate()
			if host.output_buffer.tell() > 0:
				host.output_buffer.seek(host.output_buffer.tell() - 1)
				host.output_buffer.truncate()
		else:
			# normal character
			buffer.write(char)
			host.output_buffer.write(char)
		# every 100 bytes, split the line on unicode line breaks
		if buffer.tell() % 100 == 0 and buffer.tell() > 0:
			decodedLine = buffer.getvalue().decode(_encoding,errors='backslashreplace')
			lines = decodedLine.splitlines()
			if len(lines) > 1:
				# if there are multiple lines, we add them to the target
				for line in lines[:-1]:
					# for all lines except the last one, we add them to the target
					target.append(line)
					host.output.append(line)
					host.lineNumToPrintSet.add(len(host.output)-1)
				# we keep the last line in the buffer
				buffer.seek(0)
				buffer.truncate(0)
				buffer.write(lines[-1].encode(_encoding,errors='backslashreplace'))
				host.output_buffer.seek(0)
				host.output_buffer.truncate(0)
				host.output_buffer.write(lines[-1].encode(_encoding,errors='backslashreplace'))
	def add_run(run, clean):
		'''
		Add bytes that hold no \n, \r or backspace.

		clean: the buffer is known to hold no unicode line break. Returns the same for after.
		'''
		position = buffer.tell()
		end = buffer.seek(0, io.SEEK_END)
		buffer.seek(position)
		# appending (not overwriting after a \r) with no line break around: no 100 byte split can happen
		if position == end:
			if clean:
				# a line break started in the buffer ends within its last 3 bytes
				buffer.seek(max(0, end - 3))
				text = (buffer.read() + run).decode(_encoding,errors='backslashreplace')
			else:
				text = (buffer.getvalue() + run).decode(_encoding,errors='backslashreplace')
			if not _UNICODE_LINE_BREAK.search(text):
				buffer.write(run)
				host.output_buffer.write(run)
				return True
		for i in range(len(run)):
			add_byte(run[i:i + 1])
		return False
	read = stream.read1 if hasattr(stream, 'read1') else stream.read
	clean = False
	try:
		while True:
			# read1 returns whatever arrived (up to the size) instead of waiting to fill it
			chunk = read(65536)
			if not chunk:
				break
			host.lastUpdateTime = time.monotonic()
			# split keeps the special bytes at the odd indexes
			for index, part in enumerate(_READER_SPECIAL_BYTES.split(chunk)):
				if index % 2 == 0:
					if part:
						clean = add_run(part, clean)
				elif part == b'\n':
					add_line(buffer,target, host)
					clean = True
				else:
					add_byte(part)
	except ValueError:
		pass
	if buffer.tell() > 0:
		# if there is still some data in the buffer, we add it to the target
		add_line(buffer,target, host)

def __handle_writing_stream(stream,stop_event,host):
	'''
	Write the key presses to the stream

	Args:
		stream (io.BytesIO): The stream to be written to
		stop_event (threading.Event): The event to stop the thread
		host (Host): The host object

	Returns:
		None
	'''
	global __keyPressesIn
	global _encoding
	# __keyPressesIn is a list of lists. 
	# Each list is a list of characters to be sent to the stdin of the process at once. 
	# We do not send the last line as it may be incomplete.
	sentInputPos = 0
	while not stop_event.is_set() and host.interactive_stdin:
		if sentInputPos < len(__keyPressesIn) - 1 :
			stream.write(''.join(__keyPressesIn[sentInputPos]).encode(encoding=_encoding,errors='backslashreplace'))
			stream.flush()
			line = '> ' + ''.join(__keyPressesIn[sentInputPos]).encode(encoding=_encoding,errors='backslashreplace').decode(encoding=_encoding,errors='backslashreplace').replace('\n', '↵')
			host.output.append(line)
			host.stdout.append(line)
			host.lineNumToPrintSet.add(len(host.output)-1)
			sentInputPos += 1
			host.lastUpdateTime = time.monotonic()
		else:
			time.sleep(0.01) # sleep for 10ms
	if not stop_event.is_set():
		# the TUI ended while the command runs: send the lines already typed, then end of input
		try:
			while sentInputPos < len(__keyPressesIn) - 1:
				stream.write(''.join(__keyPressesIn[sentInputPos]).encode(encoding=_encoding,errors='backslashreplace'))
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
	# # send the last line
	# if __keyPressesIn and __keyPressesIn[-1]:
	#     stream.write(''.join(__keyPressesIn[-1]).encode())
	#     stream.flush()
	#     host.output.append(' $ ' + ''.join(__keyPressesIn[-1]).encode().decode().replace('\n', '↵'))
	#     host.stdout.append(' $ ' + ''.join(__keyPressesIn[-1]).encode().decode().replace('\n', '↵'))
	return sentInputPos

def _emfile_backoff_seconds(attempt):
	return min(0.1 * (2 ** attempt), 1.0)

def _record_host_exception(host, exc):
	'''Record an exception raised while running the host's command as a failure. Call from an except block.'''
	import traceback
	host.stderr.extend(str(exc).split('\n'))
	host.output.extend(str(exc).split('\n'))
	host.stderr.extend(traceback.format_exc().split('\n'))
	host.output.extend(traceback.format_exc().split('\n'))
	host.returncode = -1

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
	if getattr(host, 'returncode', None) == 124:
		return False
	if 'unable to establish ipmi v2' in text or 'rmcp+' in text:
		return True
	return True

_CommandAttempt = namedtuple('_CommandAttempt', ['action', 'argv', 'ipmi_definition', 'username', 'passwds', 'useScp', 'ipmi_definitions_list'])
_CommandAttempt.__doc__ = '''
What _build_command decided for one attempt.

action is 'run' (run argv), 'rebuild' (build again right away, e.g. ipmitool is missing so the
next attempt uses ssh_ipmitool) or 'stop' (host.returncode is set). The other fields carry the
attempt's state into the retry decisions and the next attempt.
'''

def _build_command(host, passwds, ipmi_definitions_list):
	'''
	Build the command line for one attempt to run host.command, without running it.

	Picks the IPMI definition (popped from ipmi_definitions_list), fills in the magic strings and
	formats the ipmitool / redfish / shell / scp / rsync / ssh command. Warnings and errors are
	recorded on the host.

	Args:
		host (Host): The host object
		passwds (str): The password for the host
		ipmi_definitions_list (list): The IPMI definitions left to try, ... for the matching defaults

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
		if host.identity_file:
			sshLocalExtraArgs += ['-i',host.identity_file]
		rsyncLocalExtraArgs = ['--rsh','ssh ' + ' '.join(sshLocalExtraArgs)]
		host.address = host.name
		if '@' in host.name:
			username, host.address = host.name.rsplit('@',1)
		if host.ipmi:
			if ipmi_definitions_list is ...:
				ipmi_definitions_list = [ipmi_definition for ipmi_definition in DEFAULT_IPMI_DEFINITIONS if not ipmi_definition.get('hostname_keyword') or str(ipmi_definition.get('hostname_keyword')).strip() in host.name]
			if not ipmi_definitions_list:
				host.output.append('Error: Exhausted all matching ipmi definitions!')
				host.stderr.append('Error: Exhausted all matching ipmi definitions!')
				host.returncode = 1
				return attempt('stop')
			ipmi_definition = dict(ChainMap(ipmi_definitions_list.pop(0),get_default_ipmi_definition()))
			if ipmi_definition.get('ipmi_method') == 'ssh_ipmitool':
				if not host.command:
					host.command = 'ipmitool power status'
				else:
					host.command = 'ipmitool '+host.command if not host.command.startswith('ipmitool ') else host.command
				if username:
					host.output.append(f'Warning:-u SSH_USERNAME {username} is provided in the host name! Using the username from the ipmi definition if provided: {ipmi_definition.get("username")}')
					if __DEBUG_MODE:
						host.stderr.append(f'Warning:-u SSH_USERNAME {username} is provided in the host name! Using the username from the ipmi definition if provided: {ipmi_definition.get("username")}')
				username = ipmi_definition.get('username',username)
				if passwds:
					host.output.append(f'Warning: -p SSH_PASSWORD {passwds} is provided! Using the password from the ipmi definition if provided: {ipmi_definition.get("password")}')
					if __DEBUG_MODE:
						host.stderr.append(f'Warning: -p SSH_PASSWORD  {passwds} is provided! Using the password from the ipmi definition if provided: {ipmi_definition.get("password")}')
				passwds = ipmi_definition.get('password',passwds)
				if ipmi_definition.get('interface_ip_prefix') and ipmi_definition.get('interface_ip_prefix') == DEFAULT_IPMI_INTERFACE_IP_PREFIX:
					host.output.append('Warning: ipmi_interface_ip_prefix that is the same as the DEFAULT_IPMI_INTERFACE_IP_PREFIX is ignored in ssh_ipmitool mode.')
					if __DEBUG_MODE:
						host.stderr.append('Warning: ipmi_interface_ip_prefix that is the same as the DEFAULT_IPMI_INTERFACE_IP_PREFIX is ignored in ssh_ipmitool mode.')
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
			extraargs = host.extraargs.split()
		elif host.extraargs and isinstance(host.extraargs, list):
			extraargs = [str(arg) for arg in host.extraargs]
		else:
			extraargs = []
		if not ip_prefix:
			ip_prefix = host.interface_ip_prefix
		if ip_prefix:
			try:
				if ':' in str(host.ip):
					raise ValueError('interface_ip_prefix only applies to IPv4 addresses')
				hostOctets = host.ip.split('.')
				prefixOctets = ip_prefix.split('.')
				host.address = '.'.join(prefixOctets[:3]+hostOctets[min(3,len(prefixOctets)):])
			except Exception:
				host.output.append(f'Warning: Failed to resolve the IP address for the host {host.name}. Unable to resolve ip_prefix {ip_prefix}!')
				if __DEBUG_MODE:
					host.stderr.append(f'Warning: Failed to resolve the IP address for the host {host.name}. Unable to resolve ip_prefix {ip_prefix}!')
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
					host.output.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
					if __DEBUG_MODE:
						host.stderr.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
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
					formatedCMD = [_binPaths['sh'],'-c',f'ipmitool -H {shlex.quote(str(host.address))} -U {shlex.quote(str(ipmi_definition.get("username",username)))} -P {shlex.quote(str(ipmi_definition.get("password",passwds)))} {ipmi_args} {host.command}']
				else:
					formatedCMD = [_binPaths['ipmitool'],f'-H {host.address}',f'-U {ipmi_definition.get("username",username)}',f'-P {ipmi_definition.get("password",passwds)}'] + [f'-{s}' for s in ipmi_args.split('-') if s] + [host.command]
			elif ipmi_definition.get('ipmi_method') == 'redfish':
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
				host.output.append(f'IPMI method {ipmi_definition.get("ipmi_method","None")} not supported!')
				host.stderr.append(f'IPMI method {ipmi_definition.get("ipmi_method","None")} not supported!')
				host.returncode = 1
				return attempt('stop')
		elif host.shell:
			if 'sh' in _binPaths:
				host.output.append('Running command in shell mode, ignoring the hosts...')
				if __DEBUG_MODE:
					host.stderr.append('Running command in shell mode, ignoring the hosts...')
				formatedCMD = [_binPaths['sh'],'-c',host.command]
			else:
				host.output.append('shell not found on the local machine! Using ssh localhost instead...')
				if __DEBUG_MODE:
					host.stderr.append('shell not found on the local machine! Using ssh localhost instead...')
				host.shell = False
				host.name = 'localhost'
				return attempt('rebuild')
		else:
			if host.files:
				if host.scp:
					if 'scp' in _binPaths:
						useScp = True
					elif 'rsync' in _binPaths:
						host.output.append('scp not found on the local machine! Trying to use rsync...')
						if __DEBUG_MODE:
							host.stderr.append('scp not found on the local machine! Trying to use rsync...')
						useScp = False
					else:
						host.output.append('scp not found on the local machine! Please install scp or rsync to use file sync mode.')
						host.stderr.append('scp not found on the local machine! Please install scp or rsync to use file sync mode.')
						host.returncode = 1
						return attempt('stop')
				elif 'rsync' in _binPaths:
					useScp = False
				elif 'scp' in _binPaths:
					host.output.append('rsync not found on the local machine! Trying to use scp...')
					if __DEBUG_MODE:
						host.stderr.append('rsync not found on the local machine! Trying to use scp...')
					useScp = True
				else:
					host.output.append('rsync not found on the local machine! Please install rsync or scp to use file sync mode.')
					host.stderr.append('rsync not found on the local machine! Please install rsync or scp to use file sync mode.')
					host.returncode = 1
					return attempt('stop')
				if host.gatherMode:
					fileArgs = [f'{host.resolvedName}:{file}' for file in host.files] + [host.command]
				else:
					fileArgs = host.files + [f'{host.resolvedName}:{host.command}']
				if useScp:
					formatedCMD = [_binPaths['scp'],'-rp'] + sshLocalExtraArgs + extraargs +['--']+fileArgs
				else:
					formatedCMD = [_binPaths['rsync'],'-ahlX','--partial','--inplace', '--info=name'] + rsyncLocalExtraArgs + extraargs +['--']+fileArgs	
			else:
				formatedCMD = [_binPaths['ssh']] + sshLocalExtraArgs + extraargs +['--']+ [host.resolvedName, host.command]
			if passwds and 'sshpass' in _binPaths:
				formatedCMD = [_binPaths['sshpass'], '-p', passwds] + formatedCMD
			elif passwds:
				host.output.append('Warning: sshpass is not available. Please install sshpass to use password authentication.')
				if __DEBUG_MODE:
					host.stderr.append('Warning: sshpass is not available. Please install sshpass to use password authentication.')
				host.output.append('Please provide password via live input or use ssh key authentication.')
				# # try to send the password via __keyPressesIn
				# __keyPressesIn[-1] = list(passwds) + ['\n']
				# __keyPressesIn.append([])
	except Exception as e:
		import traceback
		host.output.append(f'Error occurred while formatting the command : {host.command}!')
		host.stderr.append(f'Error occurred while formatting the command : {host.command}!')
		host.stderr.extend(str(e).split('\n'))
		host.output.extend(str(e).split('\n'))
		host.stderr.extend(traceback.format_exc().split('\n'))
		host.output.extend(traceback.format_exc().split('\n'))
		host.returncode = -1
		return attempt('stop')
	return attempt('run', formatedCMD)

def _execute_command(host, formatedCMD, sem, timeout, retry_limit):
	'''
	Run one built command, retrying (within retry_limit) while too many files are open.

	Args:
		host (Host): The host object
		formatedCMD (list): The command line from _build_command
		sem (threading.Semaphore): The semaphore to limit the number of concurrent SSH sessions
		timeout (int): Seconds without output before the command is stopped, 0 for no limit
		retry_limit (int): Retries left

	Returns:
		tuple: (stop, retry_limit, attempt_line_starts). stop is True when the retries ran out
			and run_command must not try anything else.
	'''
	# where this attempt's lines start, earlier ipmi attempts must not affect the lockout decision
	attempt_line_starts = (len(host.output), len(host.stdout), len(host.stderr))
	emfile_attempt = 0
	while True:
		retry_after_emfile = False
		proc = None
		with sem:
			try:
				host.output.append('Running command: '+' '.join(formatedCMD))
				if __DEBUG_MODE:
					host.stderr.append('Running command: '+' '.join(formatedCMD))
				#host.stdout = []
				# without the TUI nobody can type, an open stdin pipe would leave commands reading it waiting forever
				# read once: the TUI can end (clearing the flag) at any time, a pipe must always get a writer that closes it
				interactive_stdin = host.interactive_stdin
				stdin = subprocess.PIPE if interactive_stdin else subprocess.DEVNULL
				proc = subprocess.Popen(formatedCMD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=stdin)
				__running_procs.add(proc)
				# create a thread to handle stdout
				stdout_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stdout,host.stdout, host,host.stdout_buffer), daemon=True)
				stdout_thread.start()
				# create a thread to handle stderr
				#host.stderr = []
				stderr_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stderr,host.stderr, host,host.stderr_buffer), daemon=True)
				stderr_thread.start()
				# create a thread to handle stdin
				stdin_stop_event = threading.Event()
				stdin_thread = None
				if interactive_stdin:
					stdin_thread = threading.Thread(target=__handle_writing_stream, args=(proc.stdin,stdin_stop_event, host), daemon=True)
					stdin_thread.start()
				# Monitor the subprocess and terminate it after the timeout
				host.lastUpdateTime = time.monotonic()
				timeoutLineAppended = False
				sleep_interval = 1.0e-7 # 100 nanoseconds
				timed_out = False
				while proc.poll() is None:  # while the process is still running
					if timeout > 0:
						if time.monotonic() - host.lastUpdateTime > timeout:
							timed_out = True
							host.stderr.append('Timeout!')
							host.output.append('Timeout!')
							proc.send_signal(signal.SIGINT)
							time.sleep(0.1)
							proc.terminate()
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
						host.stderr.append('Ctrl C detected, Emergency Stop!')
						host.output.append('Ctrl C detected, Emergency Stop!')
						proc.send_signal(signal.SIGINT)
						time.sleep(0.1)
						proc.terminate()
						break
					time.sleep(sleep_interval)  # avoid busy-waiting
					if sleep_interval < 0.001:
						sleep_interval *= 2
					elif sleep_interval < 0.01:
						sleep_interval *= 1.1
				stdin_stop_event.set()
				# Wait for output processing to complete
				stdout_thread.join(timeout=1)
				stderr_thread.join(timeout=1)
				if stdin_thread:
					stdin_thread.join(timeout=1)
				if proc.stdin is not None and proc.stdin.closed:
					# communicate() would flush the closed pipe and raise
					proc.stdin = None
				if not _emo:
					stdout = None
					stderr = None
					try:
						stdout, stderr = proc.communicate(timeout=1)
					except subprocess.TimeoutExpired:
						pass
					if stdout:
						host.output.append('Trying to read the rest of the stdout...')
						__handle_reading_stream(io.BytesIO(stdout),host.stdout, host,host.stdout_buffer)
					if stderr:
						host.output.append('Trying to read the rest of the stderr...')
						__handle_reading_stream(io.BytesIO(stderr),host.stderr, host,host.stderr_buffer)
					# if the last line in host.stderr is Connection to * closed., we will remove it
				host.returncode = proc.poll()
				if timed_out:
					host.returncode = 124
				elif host.returncode is None:
					# process been killed via timeout or sigkill
					if host.stderr and host.stderr[-1].strip().startswith('Ctrl C detected, Emergency Stop!'):
						host.returncode = 137
					else:
						host.returncode = -1
				host.output.append(f'Command finished with return code {host.returncode}')
				if host.stderr:
					# filter out the error messages that we want to ignore
					host.stderr = [line for line in host.stderr if not __ERROR_MESSAGES_TO_IGNORE_REGEX.search(line)]
			except OSError as e:
				if e.errno == errno.EMFILE and proc is None:
					retry_after_emfile = True
					host.returncode = None
				else:
					_record_host_exception(host, e)
			except Exception as e:
				_record_host_exception(host, e)
			finally:
				__running_procs.discard(proc)
		if not retry_after_emfile:
			break
		if retry_limit <= 0:
			host.output.append("Error: Retry limit reached after too many open files!")
			host.stderr.append("Error: Retry limit reached after too many open files!")
			host.returncode = 1
			return True, retry_limit, attempt_line_starts
		host.output.append("Warning: Too many open files. retrying...")
		time.sleep(_emfile_backoff_seconds(emfile_attempt))
		emfile_attempt += 1
		retry_limit -= 1
	return False, retry_limit, attempt_line_starts

def run_command(host, sem, timeout=60,passwds=None, retry_limit = ...,ipmi_definitions_list = ...):
	'''
	Run the command on the host. Main execution function.

	Builds the command (_build_command), runs it (_execute_command) and retries on failure: the
	next IPMI definition, or scp after rsync failed. Every retry uses up one of retry_limit.

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
	while True:
		if retry_limit < 0:
			host.output.append('Error: Retry limit reached!')
			host.stderr.append('Error: Retry limit reached!')
			host.returncode = 1
			return
		action, formatedCMD, ipmi_definition, username, passwds, useScp, ipmi_definitions_list = _build_command(host, passwds, ipmi_definitions_list)
		if action == 'stop':
			return
		if action == 'rebuild':
			retry_limit -= 1
			continue
		stop, retry_limit, attempt_line_starts = _execute_command(host, formatedCMD, sem, timeout, retry_limit)
		if stop:
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
						host.output.append(f'Sleeping for {sleep_seconds} seconds...')
						if __DEBUG_MODE:
							host.stderr.append(f'Sleeping for {sleep_seconds} seconds...')
						time.sleep(sleep_seconds)
					elif sleep_seconds >= 0:
						host.output.append('Skipping IPMI lockout wait; the controller was not reached.')
				except Exception as e:
					host.output.append(f'Error: Failed to sleep for {ipmi_definition.get("retry_lockout_time")} seconds! {e}')
					if __DEBUG_MODE:
						host.stderr.append(f'Error: Failed to sleep for {ipmi_definition.get("retry_lockout_time")} seconds! {e}')
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
		# If transfering files, we will try again using scp if rsync connection is not successful
		elif host.files and not host.scp and not useScp and host.returncode != 0 and host.stderr:
			host.returncode = None
			host.output.append('Rsync connection failed! Trying SCP connection...')
			if __DEBUG_MODE:
				host.stderr.append('Rsync connection failed! Trying SCP connection...')
			else:
				host.stdout = []
				host.stderr = []
			host.scp = True
			retry_limit -= 1
			continue
		return


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
			host.output.append('Error: Command thread exited without a return code!')
			host.stderr.append('Error: Command thread exited without a return code!')
			host.returncode = -1

def start_run_on_hosts(hosts, timeout=60,password=None,max_connections=4 * _cpu_count()):
	'''
	Start running the command on the hosts. Wrapper function for run_command

	Args:
		hosts (list): A list of Host objects
		timeout (int, optional): The timeout for the command. Defaults to 60.
		password (str, optional): The password for the hosts. Defaults to None.
		max_connections (int, optional): The maximum number of concurrent SSH sessions. Defaults to 4 * os.cpu_count().

	Returns:
		list: A list of threads that get started. Hosts skipped as unreachable are not started.
	'''
	global __thread_start_delay
	hosts = [host for host in hosts if not host.skipped]
	if len(hosts) == 0:
		return []
	sem = threading.Semaphore(max_connections)  # Limit concurrent SSH sessions
	threads = [threading.Thread(target=_run_command_thread, args=(host, sem,timeout,password), daemon=True) for host in hosts]
	for thread, host in zip(threads, hosts):
		thread.start()
		host.thread = thread
		time.sleep(__thread_start_delay)
	return threads

#%% ------------ Display Block ----------------
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
				eprint("Warning: Maximum number of colors reached. Wrapping around.")
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
			print("Warning: Maximum number of color pairs reached, wrapping around.")
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
		number_of_char_to_write: Number of characters to write. -1 for all remaining space in line, 0 for no characters, and a positive integer for a specific number of characters.
		color_pair_list: List of [foreground, background, color_pair] curses color pair values
		fill_char: Character to fill the remaining space in the line
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
	line = line.replace('\n', ' ').replace('\r', ' ')
	if parse_ansi_colors:
		segments = re.split(r"(\x1b\[[\d;]*m)", line)  # Split line by ANSI escape codes
	else:
		segments = [line]
	charsWritten = 0
	boxAttr = __parse_ansi_escape_sequence_to_curses_attr(box_ansi_color)
	# first add the lead_str
	if len(lead_str) > 0:
		window.addnstr(y, x, lead_str, numChar, boxAttr)
		charsWritten = min(len(lead_str), numChar)
	# process centering
	if centered:
		fill_length = numChar - len(lead_str) - len(trail_str) - sum([len(segment) for segment in segments if not segment.startswith("\x1b[")])
		leading_fill_length = fill_length // 2
		if leading_fill_length > 0:
			window.addnstr(y, x + charsWritten, fill_char * (leading_fill_length // len(fill_char) + 1), leading_fill_length, boxAttr)
			charsWritten += leading_fill_length
	# add the segments
	for segment in segments:
		if not segment:
			continue
		if parse_ansi_colors and segment.startswith("\x1b["):
			# Parse ANSI escape sequence
			_ = __parse_ansi_escape_sequence_to_curses_attr(segment,color_pair_list)
		else:
			# Add text with current color
			if charsWritten < numChar and len(segment) > 0:
				window.addnstr(y, x + charsWritten, segment, numChar - charsWritten, color_pair_list[2])
				charsWritten += min(len(segment), numChar - charsWritten)
	# if we have finished printing segments but we still have space, we will fill it with fill_char
	trail_fill_length = numChar - charsWritten - len(trail_str)
	if trail_fill_length > 0 and fill_char:
		window.addnstr(y, x + charsWritten,fill_char * (trail_fill_length // len(fill_char) + 1), trail_fill_length , boxAttr)
		charsWritten += trail_fill_length
	if len(trail_str) > 0 and charsWritten < numChar:
		window.addnstr(y, x + charsWritten, trail_str, numChar - charsWritten, boxAttr)
		charsWritten += min(len(trail_str), numChar - charsWritten)

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

def __generate_display(stdscr, hosts, lineToDisplay = -1,curserPosition = 0, min_char_len = DEFAULT_WINDOW_WIDTH, min_line_len = DEFAULT_WINDOW_HEIGHT,single_window=DEFAULT_SINGLE_WINDOW,help_shown = False, config_reason = 'New Configuration'):
	global _encoding
	_ = config_reason
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
		if min_char_len_local < 1 or min_line_len_local < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Minimum character or line length too small')
		# We need to figure out how many hosts we can fit in the terminal
		# We will need at least 2 lines per host, one for its name, one for its output
		# Each line will be at least 61 characters long (60 for the output, 1 for the borders)
		max_num_hosts_x = max_x // (min_char_len_local + 1)
		max_num_hosts_y = max_y // (min_line_len_local + 1)
		max_num_hosts = max_num_hosts_x * max_num_hosts_y
		if max_num_hosts < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal too small to display any hosts')
		hosts_to_display , host_stats, rearrangedHosts = _get_hosts_to_display(hosts, max_num_hosts)
		if len(hosts_to_display) == 0:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'No hosts to display')
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
		if host_window_height < 1 or host_window_width < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Host window too small')

		old_stat = ''
		old_bottom_stat = ''
		# we refresh the screen every 0.1 seconds
		last_refresh_time = time.perf_counter()
		stdscr.clear()
		#host_window.refresh()
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
			#print(f"Creating a window at {y},{x}")
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
			#bottom_border.clear()
			#bottom_border.addnstr(0, 0, '-' * (max_x - 1), max_x - 1)
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
		_curses_add_string_to_window(window=help_window,y=1,line='?       : Toggle Help Menu', color_pair_list=[-1,-1,1], lead_str='│', box_ansi_color=box_ansi_color)
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
		while host_stats['running'] > 0 or host_stats['waiting'] > 0:
			# Check for keypress
			key = stdscr.getch()
			if key != -1:  # -1 means no keypress
				# we store the keypresses in a list of lists.
				# Each list is a list of characters to be sent to the stdin of the process at once.
				# When we encounter a newline, we add a new list to the list of lists. ( a new line of input )
				# with open('keylog.txt','a') as f:
				#     f.write(str(key)+'\n')
				if key == 410 or key == curses.KEY_RESIZE: # 410 is the key code for resize
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal resize requested')    
				# if the user pressed ctrl + d and the last line is empty, we will exit by adding 'exit\n' to the last line
				elif key == 4 and not __keyPressesIn[-1]:
					__keyPressesIn[-1].extend('exit\n')
					__keyPressesIn.append([])
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
				elif key == curses.KEY_HELP or key == 63 or key == curses.KEY_F1: # 63 is the key code for ?
					# if the key is help, we will display the help message
					if not help_shown:
						help_panel.show()
						help_shown = True
					else:
						help_panel.hide()
						help_shown = False
						refresh_all = True
						#return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Help closed')
					curses.panel.update_panels()
			# We are left with these are keys that mofidy the current line.
				else:
					# This means the user have done scrolling and is committing to modify the current line.
					if lineToDisplay  < -1:
						# We overwrite the last line (current working line) with the line to display, removing the newline at the end
						__keyPressesIn[-1] = __keyPressesIn[lineToDisplay][:-1]
						lineToDisplay = -1
					curserPosition = max(0, min(curserPosition, len(__keyPressesIn[lineToDisplay])))
					if key == 10: # 10 is the key code for newline
						__keyPressesIn[-1].append(chr(key))
						__keyPressesIn.append([])
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
						# if the key is not a special key, we will add it
						__keyPressesIn[lineToDisplay].insert(curserPosition, chr(key))
						curserPosition += 1
			# reconfigure when the terminal size changes
			if org_dim != stdscr.getmaxyx():
				return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window,help_shown, 'Terminal resize detected')
			# We generate the aggregated stats if user did not input anything
			if not __keyPressesIn[lineToDisplay]:
				#stats = '┍'+ f" Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} "[:max_x - 2].center(max_x - 2, "━")
				stats = f"Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} i:{indexOffset} "
			else:
				# we use the stat bar to display the key presses
				encodedLine = ''.join(__keyPressesIn[lineToDisplay]).encode(encoding=_encoding,errors='backslashreplace').decode(encoding=_encoding,errors='backslashreplace').strip('\n') + ' '
				#stats = '┍'+ f"Send CMD: {encodedLine}"[:max_x - 2].center(max_x - 2, "━")
				# format the stats line with chracter at curser position inverted using ansi escape sequence
				# displayCurserPosition is needed as the curserPosition can be larger than the length of the encodedLine. This is wanted to keep scrolling through the history less painful
				displayCurserPosition = min(curserPosition,len(encodedLine) -1)
				stats = f'Send CMD: {encodedLine[:displayCurserPosition]}\x1b[7m{encodedLine[displayCurserPosition]}\x1b[0m{encodedLine[displayCurserPosition + 1:]}'
			if stats != old_stat or refresh_all:
				old_stat = stats
				# calculate the real curser position in stats as we centered the stats
				# if 'Send CMD: ' in stats:
				# 	curserPositionStats = min(min(curserPosition,len(encodedLine) -1) + stats.find('Send CMD: ')+len('Send CMD: '), max_x -2)
				# else:
				# 	curserPositionStats = max_x -2
				#stat_window.clear()
				#stat_window.addstr(0, 0, stats)
				# add the line with curser that inverses the color at the curser position
				# stat_window.addstr(0, 0, stats[:curserPositionStats])
				# stat_window.addch(0,curserPositionStats, stats[curserPositionStats], curses.A_REVERSE)
				# stat_window.addnstr(0, curserPositionStats + 1, stats[curserPositionStats + 1:], max_x - 1 - curserPositionStats)
				# stat_window.refresh()
				_curses_add_string_to_window(window=stat_window, y=0, line=stats, color_pair_list=[-1, -1, 1],centered=True,fill_char='━',lead_str='┍',box_ansi_color=box_ansi_color)
				stat_window.refresh()
			if bottom_border:
				#target_length = max_x - 2 + len('\x1b[33m\x1b[0m\x1b[31m\x1b[0m\x1b[32m\x1b[0m')
				#bottom_stats = '└'+ f" Total: {len(hosts)} Running: \x1b[33m{host_stats['running']}\x1b[0m Failed: \x1b[31m{host_stats['failed']}\x1b[0m Finished: \x1b[32m{host_stats['finished']}\x1b[0m Waiting: {host_stats['waiting']} "[:target_length].center(target_length, "─")
				bottom_stats = f" Total: {len(hosts)} Running: \x1b[33m{host_stats['running']}\x1b[0m Failed: \x1b[31m{host_stats['failed']}\x1b[0m Finished: \x1b[32m{host_stats['finished']}\x1b[0m Waiting: {host_stats['waiting']} "
				if bottom_stats != old_bottom_stat or refresh_all:
					old_bottom_stat = bottom_stats
					#bottom_border.clear()
					#bottom_border.addnstr(0, 0, bottom_stats, max_x - 1)
					_curses_add_string_to_window(window=bottom_border, y=0, line=bottom_stats,fill_char='─',centered=True,lead_str='└',box_ansi_color=box_ansi_color)
					bottom_border.refresh()
			# set the maximum refresh rate to 100 Hz
			if time.perf_counter() - last_refresh_time < 0.01:
				time.sleep(max(0,0.01 - time.perf_counter() + last_refresh_time))
			if refresh_all:
				rearrangedHosts = set(hosts_to_display)
				refresh_all = False
			#stdscr.clear()
			hostWindowUpdated = False
			for host_window, host in zip(host_windows, hosts_to_display):
				# we will only update the window if there is new output or the window is not fully printed
				if host in rearrangedHosts:
					linePrintOut = f'{host.name}:[{host.command}]'.replace('\n', ' ').replace('\r', ' ').strip()
					_curses_add_string_to_window(window=host_window, y=0, line=linePrintOut, color_pair_list=[-1, -1, 1],centered=True,fill_char='─',lead_str='┼',box_ansi_color=box_ansi_color)
					# clear the window
					for i in range(host_window_height - 1):
						_curses_add_string_to_window(window=host_window, color_pair_list=[-1, -1, 1], y=i + 1,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
					host.lineNumToPrintSet.update(range(len(host.output)))
					host.lastPrintedUpdateTime = 0
					hostWindowUpdated = True
				# for i in range(host.printedLines, len(host.output)):
				# 	_curses_add_string_to_window(window=host_window, y=i + 1, line=host.output[i], color_pair_list=host.current_color_pair,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
				# host.printedLines = len(host.output)
				if host.lineNumToPrintSet:
					try:
						# visible range is from len(host.output) - host_window_height + 1 to len(host.output)
						visibleLowerBound = max(0, len(host.output) - host_window_height + 1)
						lineNumToPrintSet = host.lineNumToPrintSet.copy()
						host.lineNumToPrintSet = set()
						for lineNumToReprint in sorted(lineNumToPrintSet):
							# if the line is visible, we will reprint it
							if visibleLowerBound <= lineNumToReprint <= len(host.output):
								_curses_add_string_to_window(window=host_window, y=lineNumToReprint + 1, line=host.output[lineNumToReprint], color_pair_list=host.current_color_pair,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color,fill_char='')
								hostWindowUpdated = True
					except Exception:
						# import traceback
						# print(str(e).strip())
						# print(traceback.format_exc().strip())
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
	params = (-1,0 , min_char_len, min_line_len, single_window,False,'new config')
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
		params = params[:6] + ('new config',)
		time.sleep(0.01)
		#time.sleep(0.25)

#%% ------------ Generate Output Block ----------------
def can_merge(line_bag1, line_bag2, threshold):
	if threshold > 0.5:
		samples = itertools.islice(line_bag1, max(int(len(line_bag1) * (1 - threshold)),1))
		if not line_bag2.intersection(samples):
			return False
	return len(line_bag1.intersection(line_bag2)) >= min(len(line_bag1),len(line_bag2)) * threshold

def mergeOutput(merging_hostnames,outputs_by_hostname,output,diff_display_threshold,line_length):
	indexes = Counter({hostname: 0 for hostname in merging_hostnames})
	working_index_keys = set(merging_hostnames)
	previousBuddies = set()
	hostnameWrapper = textwrap.TextWrapper(width=line_length -1, tabsize=4, replace_whitespace=False, drop_whitespace=False, break_on_hyphens=False,initial_indent=' ', subsequent_indent='- ')
	hostnameWrapper.wordsep_simple_re = re.compile(r'([,]+)')
	diff_display_item_count = max(1,int(max(map(len, outputs_by_hostname.values())) * (1 - diff_display_threshold)))
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
		golden_hostname = min(working_index_keys, key=indexes.get)
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
				hostnameStr = ','.join(compact_hostnames(buddy))
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
	output = []
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
	output.append(color_line+'─'*(line_length)+color_reset)
	hostnameWrapper = textwrap.TextWrapper(width=line_length - 1, tabsize=4, replace_whitespace=False, drop_whitespace=False, break_on_hyphens=False,initial_indent=' ', subsequent_indent='- ')
	hostnameWrapper.wordsep_simple_re = re.compile(r'([,]+)')
	for merging_hostnames in merge_groups:
		mergeOutput(merging_hostnames, outputs_by_hostname, output, diff_display_threshold,line_length)
		output.append(color_line+'─'*(line_length)+color_reset)
	for hostname in remaining_hostnames:
		hostnameLines = hostnameWrapper.wrap(','.join(compact_hostnames([hostname])))
		hostnameLines[0] = f"{green_str}{underline_bold_str}■{hostnameLines[0]}"
		hostnameLines[-1] += color_reset
		output.extend(hostnameLines)
		output.extend(outputs_by_hostname[hostname])
		output.append(color_line+'─'*(line_length)+color_reset)
	if output:
		output.pop()
	# if output and output[0] and output[0].startswith('├'):
	# 	output[0] = '┌' + output[0][1:]
	return output

def pre_merge_hosts(hosts):
	'''
	Merge hosts with identical outputs.

	Note: After merging, the surviving host's `.name` is rewritten to a comma-joined
	`compact_hostnames(...)` summary of the group (e.g. `node[1-3]`). Callers that need
	per-host identity after merge should snapshot names beforehand; this rewrite is
	intentional for compact human-readable summaries.
	'''
	output_groups = defaultdict(list)
	# Group hosts by their output identity
	for host in hosts:
		identity = host.get_output_hash()
		output_groups[identity].append(host)
	for group in output_groups.values():
		group[0].name = ','.join(compact_hostnames(host.name for host in group))
		for i in range(1,len(group)):
			hosts.remove(group[i])
	return hosts

def get_host_raw_output(hosts, terminal_width):
	outputs_by_hostname = {}
	line_bag_by_hostname = {}
	hostnames_by_line_bag_len = {}
	text_wrapper = textwrap.TextWrapper(width=terminal_width - 1, tabsize=4, replace_whitespace=False, drop_whitespace=False, 
									 initial_indent=' ', subsequent_indent='-')
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
		hostPrintOut = [f"{cyan_str}█{color_reset_str} EXECUTED COMMAND:"]
		for line in host.command.splitlines():
			hostPrintOut.extend(text_wrapper.wrap(line))
		# hostPrintOut.extend(itertools.chain.from_iterable(text_wrapper.wrap(line) for line in host['command'].splitlines()))
		lineBag = {(0,host.command)}
		prevLine = host.command
		if host.stdout:
			hostPrintOut.append(f'{blue_str}▓{color_reset_str} STDOUT:')
			# for line in host.stdout:
			# 	if len(line) < terminal_width - 2:
			# 		hostPrintOut.append(f" {line}")
			# 	else:
			# 		hostPrintOut.extend(text_wrapper.wrap(line))
			hostPrintOut.extend(f" {line}" for line in host.stdout)
			max_length = max(max_length, max(map(len, host.stdout)))
			# hostPrintOut.extend(text_wrapper.wrap(line) for line in host.stdout)
			lineBag.add((prevLine,1))
			lineBag.add((1,host.stdout[0]))
			if len(host.stdout) > 1:
				lineBag.update(zip(host.stdout, host.stdout[1:]))
			lineBag.update(host.stdout)
			prevLine = host.stdout[-1]
		if host.stderr:
			if host.stderr[0].strip().startswith('ssh: connect to host ') and host.stderr[0].strip().endswith('Connection refused'):
				host.stderr[0] = 'SSH not reachable!'
			elif host.stderr[-1].strip().endswith('Connection timed out'):
				host.stderr[-1] = 'SSH connection timed out!'
			elif host.stderr[-1].strip().endswith('No route to host'):
				host.stderr[-1] = 'Cannot find host!'
			if host.stderr:
				hostPrintOut.append(f'{red_str}▒{color_reset_str} STDERR:')
				# for line in host.stderr:
				# 	if len(line) < terminal_width - 2:
				# 		hostPrintOut.append(f" {line}")
				# 	else:
				# 		hostPrintOut.extend(text_wrapper.wrap(line))
				hostPrintOut.extend(f" {line}" for line in host.stderr)
				max_length = max(max_length, max(map(len, host.stderr)))
				lineBag.add((prevLine,2))
				lineBag.add((2,host.stderr[0]))
				lineBag.update(host.stderr)
				if len(host.stderr) > 1:
					lineBag.update(zip(host.stderr, host.stderr[1:]))
				prevLine = host.stderr[-1]
		if host.returncode != 0:
			codeColor = red_str
		else:
			codeColor = green_str
		hostPrintOut.append(f"{codeColor}░{color_reset_str} RETURN CODE: {host.returncode}")
		lineBag.add((prevLine,f"{host.returncode}"))
		outputs_by_hostname[host.name] = hostPrintOut
		line_bag_by_hostname[host.name] = lineBag
		hostnames_by_line_bag_len.setdefault(len(lineBag), set()).add(host.name)
	return outputs_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, sorted(hostnames_by_line_bag_len), min(max_length+2,terminal_width)

def form_merge_groups(hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_bag_by_hostname, diff_display_threshold):
	merge_groups = []
	remaining_hostnames = set()
	for lbl_i, line_bag_len in enumerate(sorted_hostnames_by_line_bag_len_keys):
		for this_hostname in hostnames_by_line_bag_len.get(line_bag_len, set()).copy():
			# if this_hostname not in hostnames_by_line_bag_len.get(line_bag_len, set()):
			# 	continue
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
				# if other_line_bag_len < line_bag_len:
				# 	continue
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
				# del line_bag_by_hostname[this_hostname]
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
				return '{"Success": true}'
			else:
				if color_cap == 'None':
					return 'Success'
				else:
					return '\033[32mSuccess\033[0m'
	if usejson:
		# [print(dict(host)) for host in hosts]
		#print(json.dumps([dict(host) for host in hosts],indent=4))
		rtnStr = json.dumps([dict(host) for host in hosts],indent=4)
	elif greppable:
		# transform hosts to a 2d list
		rtnStr = '*'*80+'\n'
		rtnList = [['host_name','return_code','output_type','output']]
		for host in hosts:
			#header = f"{host['name']} | rc: {host['returncode']} | "
			hostAdded = False
			for line in host.stdout:
				rtnList.append([host.name,f"rc: {host.returncode}",'stdout',line])
				hostAdded = True
			for line in host.stderr:
				rtnList.append([host.name,f"rc: {host.returncode}",'stderr',line])
				hostAdded = True
			if not hostAdded:
				rtnList.append([host.name,f"rc: {host.returncode}",'N/A','<EMPTY>'])
			rtnList.append(['','','',''])
		rtnStr += pretty_format_table(rtnList)
		rtnStr += '*'*80+'\n'
		if keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode(encoding=encoding,errors='backslashreplace').decode(encoding=encoding,errors='backslashreplace').replace('\\n', '↵') for cmd in keyPressesIn if cmd]
			rtnStr += 'User Inputs: '+ '\nUser Inputs: '.join(CMDsOut)
			#rtnStr += '\n'
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
		outputs_by_hostname, line_bag_by_hostname, hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_length = get_host_raw_output(hosts,terminal_length)
		merge_groups ,remaining_hostnames = form_merge_groups(hostnames_by_line_bag_len, sorted_hostnames_by_line_bag_len_keys, line_bag_by_hostname, diff_display_threshold)
		outputs = mergeOutputs(outputs_by_hostname, merge_groups,remaining_hostnames, diff_display_threshold,line_length)
		if keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode(encoding=encoding,errors='backslashreplace').decode(encoding=encoding,errors='backslashreplace').replace('\\n', '↵') for cmd in keyPressesIn if cmd]
			outputs.append(color_reset_str + "░ User Inputs:".ljust(line_length,'─'))
			cmdOut = []
			for line in CMDsOut:
				cmdOut.extend(textwrap.wrap(line, width=line_length-1, tabsize=4, replace_whitespace=False, drop_whitespace=False, 
									 initial_indent=' ', subsequent_indent='-'))
			outputs.extend(cmdOut)
			keyPressesIn[-1].clear()
		if not outputs:
			if errors_only:
				if color_cap == 'None':
					return 'Success'
				else:
					return '\033[32mSuccess\033[0m'
			else:
				rtnStr = ''
		else:
			rtnStr = '\n'.join(outputs + [white_str + '─' * (line_length) + color_reset_str])
	return rtnStr

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
		print(rtnStr)
	return rtnStr

#%% ------------ Run / Process Hosts Block ----------------
def _private_dir(path, create=True):
	'''
	Return True if path is a directory only we control, creating it (mode 0700) if create.

	A directory in a shared place like /tmp could have been created by someone else first,
	so it must not be a symlink, must be owned by us and must not be accessible to others.
	Without create, nothing is changed on disk.
	'''
	if create:
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
		if not create:
			return False
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

	create: set up the directory (for writing). Without it only an existing one is used, so
	reading changes nothing on disk.

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
		if _private_dir(directory, create):
			return directory
	return None

def _unavailable_hosts_file_path(create=True):
	'''
	Where unavailable hosts are cached between runs (in runtime_dir), or None to run without the cache.

	create: set up the runtime directory (for writing). Without it only an existing one is used,
	so reading the cache changes nothing on disk.
	'''
	directory = runtime_dir(create)
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


# ssh's own message for a host it could not reach, directly or through a ProxyJump host (older OpenSSH).
# A remote command printing the same words (curl: ... No route to host) did reach its host.
_SSH_UNREACHABLE_RE = re.compile(r'^(?:ssh: connect to host \S+ port \S+|channel \d+: open failed: connect failed): (?:No route to host|Connection timed out)$')

def _found_unreachable(host):
	'''
	Whether a finished host's run shows it to be unreachable, so later runs skip it for a while.

	ssh, and scp / rsync running it, exit with 255 and print the connect error first when the host
	cannot be reached. A command stopped by the timeout (-t) counts too: a host that never
	answers looks like that.
	'''
	if host.returncode == 255 and host.stderr and _SSH_UNREACHABLE_RE.match(host.stderr[0].strip()):
		return True
	return host.returncode == 124 and any(line.strip().startswith('Timeout!') for line in host.stderr)

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
	use_tui = bool(__curses_available and not no_watch and not return_unfinished and sys.stdout.isatty() and os.get_terminal_size() and os.get_terminal_size().columns > 10)
	for host in hosts:
		host.interactive_stdin = use_tui
	global _commands_started
	_commands_started = True
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
				except Exception:
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
	if not return_unfinished:
		# wait until all hosts have a return code
		while any([host.returncode is None for host in hosts]):
			time.sleep(sleep_interval)  # avoid busy-waiting
			if sleep_interval < 0.01:
				sleep_interval *= 1.1
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
		if pre_merge:
			# merge copies, the caller's hosts must keep one entry per real host for failure counts
			hosts = pre_merge_hosts([host.copy() for host in hosts])
		if not no_output:
			print_output(hosts,json,greppable=greppable)
	else:
		__running_threads.update(threads)
	# print the output, if the output of multiple hosts are the same, we aggragate them


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

@cache_decorator
def __formCommandArgStr(shortend = False, **kwargs) -> str:
	oneonone = kwargs.get('oneonone', DEFAULT_ONE_ON_ONE)
	timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
	password = kwargs.get('password', DEFAULT_PASSWORD)
	no_watch = kwargs.get('no_watch', DEFAULT_NO_WATCH)
	json = kwargs.get('json', DEFAULT_JSON_MODE)
	max_connections = kwargs.get('max_connections', DEFAULT_MAX_CONNECTIONS)
	file = kwargs.get('file', None)
	ipmi = kwargs.get('ipmi', DEFAULT_IPMI)
	interface_ip_prefix = kwargs.get('interface_ip_prefix', DEFAULT_INTERFACE_IP_PREFIX)
	scp = kwargs.get('scp', DEFAULT_SCP)
	gather_mode = kwargs.get('gather_mode', False)
	username = kwargs.get('username', DEFAULT_USERNAME)
	extraargs = kwargs.get('extraargs', DEFAULT_EXTRA_ARGS)
	skip_unreachable = kwargs.get('skip_unreachable', DEFAULT_SKIP_UNREACHABLE)
	no_env = kwargs.get('no_env', DEFAULT_NO_ENV)
	greppable = kwargs.get('greppable', DEFAULT_GREPPABLE_MODE)
	skip_hosts = kwargs.get('skip_hosts', DEFAULT_SKIP_HOSTS)
	file_sync = kwargs.get('file_sync', False)
	error_only = kwargs.get('error_only', DEFAULT_ERROR_ONLY)
	identity_file = kwargs.get('identity_file', DEFAULT_IDENTITY_FILE)
	copy_id = kwargs.get('copy_id', False)
	unavailable_host_expiry = kwargs.get('unavailable_host_expiry', DEFAULT_UNAVAILABLE_HOST_EXPIRY)
	no_history = kwargs.get('no_history', DEFAULT_NO_HISTORY)
	history_file = kwargs.get('history_file', DEFAULT_HISTORY_FILE)
	env_file = kwargs.get('env_file', '')
	# only env files given explicitly: listing the defaults would make a replayed line trust them all
	env_files = kwargs.get('env_files', ())
	repeat = kwargs.get('repeat', DEFAULT_REPEAT)
	interval = kwargs.get('interval', DEFAULT_INTERVAL)
	argsList = []
	if oneonone:
		argsList.append('--oneonone' if not shortend else '-11')
	if timeout and timeout != DEFAULT_TIMEOUT:
		argsList.append(f'--timeout={timeout}' if not shortend else f'-t={timeout}')
	if repeat and repeat != DEFAULT_REPEAT:
		argsList.append(f'--repeat={repeat}' if not shortend else f'-r={repeat}')
	if interval and interval != DEFAULT_INTERVAL:
		argsList.append(f'--interval={interval}' if not shortend else f'-i={interval}')
	if password and password != DEFAULT_PASSWORD:
		argsList.append(f'--password={_shell_quote(password)}' if not shortend else f'-p={_shell_quote(password)}')
	if identity_file and identity_file != DEFAULT_IDENTITY_FILE:
		argsList.append(f'--key={_shell_quote(identity_file)}' if not shortend else f'-k={_shell_quote(identity_file)}')
	if copy_id:
		argsList.append('--copy_id' if not shortend else '-ci')
	if no_watch:
		argsList.append('--no_watch' if not shortend else '-q')
	if json:
		argsList.append('--json' if not shortend else '-j')
	if max_connections and max_connections != DEFAULT_MAX_CONNECTIONS:
		argsList.append(f'--max_connections={max_connections}' if not shortend else f'-m={max_connections}')
	if file:
		argsList.extend([f'--file={_shell_quote(file)}' for file in file] if not shortend else [f'-f={_shell_quote(file)}' for file in file])
	if ipmi:
		argsList.append('--ipmi')
	if interface_ip_prefix and interface_ip_prefix != DEFAULT_INTERFACE_IP_PREFIX:
		argsList.append(f'--interface_ip_prefix={_shell_quote(interface_ip_prefix)}' if not shortend else f'-pre={_shell_quote(interface_ip_prefix)}')
	if scp:
		argsList.append('--scp')
	if gather_mode:
		argsList.append('--gather_mode' if not shortend else '-gm')
	if username and username != DEFAULT_USERNAME:
		argsList.append(f'--username={_shell_quote(username)}' if not shortend else f'-u={_shell_quote(username)}')
	if extraargs and extraargs != DEFAULT_EXTRA_ARGS:
		argsList.append(f'--extraargs={_shell_quote(extraargs)}' if not shortend else f'-ea={_shell_quote(extraargs)}')
	if skip_unreachable:
		argsList.append('--skip_unreachable' if not shortend else '-su')
	else:
		argsList.append('--no_skip_unreachable' if not shortend else '-nsu')
	if unavailable_host_expiry and unavailable_host_expiry != DEFAULT_UNAVAILABLE_HOST_EXPIRY:
		argsList.append(f'--unavailable_host_expiry={unavailable_host_expiry}' if not shortend else f'-uhe={unavailable_host_expiry}')
	if no_env:
		argsList.append('--no_env')
	if env_file:
		argsList.append(f'--env_file={_shell_quote(env_file)}' if not shortend else f'-ef={_shell_quote(env_file)}')
	if env_files:
		argsList.extend([f'--env_files={_shell_quote(ef)}' for ef in env_files] if not shortend else [f'-efs={_shell_quote(ef)}' for ef in env_files])
	if no_history:
		argsList.append('--no_history' if not shortend else '-nh')
	if history_file and history_file != DEFAULT_HISTORY_FILE:
		argsList.append(f'--history_file={_shell_quote(history_file)}' if not shortend else f'-hf={_shell_quote(history_file)}')
	if greppable:
		argsList.append('--greppable' if not shortend else '-g')
	if error_only:
		argsList.append('--error_only' if not shortend else '-eo')
	if skip_hosts and skip_hosts != DEFAULT_SKIP_HOSTS:
		argsList.append(f'--skip_hosts={_shell_quote(skip_hosts)}' if not shortend else f'-sh={_shell_quote(skip_hosts)}')
	if file_sync:
		argsList.append('--file_sync' if not shortend else '-fs')
	return ' '.join(argsList)

def _typed_host_str(hosts):
	'''The hosts argument as given, without expanding, validating or sorting it (sets are sorted).'''
	if isinstance(hosts, str):
		return hosts
	if isinstance(hosts, (set, frozenset)):
		hosts = sorted(hosts)
	return ','.join(str(host) for host in hosts)

def getStrCommand(hosts = DEFAULT_HOSTS,commands = None,shortend = False,tabSeperated = False,typed_hosts = False,**kwargs) -> str:
	# Allow explicit kwargs to override base parameters when forwarding dicts.
	hosts = kwargs.get('hosts', hosts)
	commands = kwargs.get('commands', commands)
	shortend = kwargs.get('shortend', shortend)
	tabSeperated = kwargs.get('tabSeperated', tabSeperated)
	typed_hosts = kwargs.get('typed_hosts', typed_hosts)
	if typed_hosts:
		# the history keeps what was typed: aliases and ranges unexpanded, unresolvable names kept
		hostStr = _typed_host_str(hosts) or 'EMPTY_HOSTS'
	else:
		hosts = hosts if isinstance(hosts,str) else frozenset(hosts)
		hostStr = formHostStr(hosts)
	commandArgKwargs = dict(kwargs)
	commandArgKwargs.pop('hosts', None)
	commandArgKwargs.pop('commands', None)
	commandArgKwargs.pop('shortend', None)
	commandArgKwargs.pop('tabSeperated', None)
	commandArgKwargs.pop('typed_hosts', None)
	if commandArgKwargs.get('file'):
		commandArgKwargs['file'] = frozenset(commandArgKwargs['file'])
	argsStr = __formCommandArgStr(shortend = shortend, **commandArgKwargs)
	commandStr = ' '.join(_shell_quote(command) for command in format_commands(commands))
	hostStr = _shell_quote(hostStr)
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
		# history can hold -p passwords, create it readable by the owner only
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
						 no_watch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = _DEFAULT_CALLED,max_connections=DEFAULT_MAX_CONNECTIONS,
						 file = None,files = None, ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,return_unfinished = _DEFAULT_RETURN_UNFINISHED,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skip_unreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,will_update_unreachable_hosts=_DEFAULT_UPDATE_UNREACHABLE_HOSTS,no_start=_DEFAULT_NO_START,
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
		timeout (int): Timeout for each command in seconds. Default: DEFAULT_TIMEOUT.
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
		copy_id (bool): Use ssh-copy-id to copy public key to hosts. Default: False.
		unavailable_host_expiry (int): Seconds to keep hosts marked as unavailable. Default: DEFAULT_UNAVAILABLE_HOST_EXPIRY.
		no_history (bool): Do not record command history. Default: True.
		history_file (str): File to store command history. Default: DEFAULT_HISTORY_FILE.
		pre_merge_hosts (bool): Pre-merge all hosts with identical outputs. Default: not called.
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
	global __DEBUG_MODE
	global __thread_start_delay
	global __max_connections_nofile_limit_supported
	global __keyPressesIn
	if called:
		# a library call starts fresh; on the CLI a Ctrl-C (e.g. in an earlier --repeat run) stands
		_emo = False
	_no_env = no_env
	_reported_invalid_hosts.clear()
	_refresh_expansion_caches()
	if not no_history:
		_ = history_file
		record_command_history(locals())
	if error_only:
		__global_suppress_printout = True
	unavailable_path = _unavailable_hosts_file_path(create=False)
	if unavailable_path and os.path.exists(unavailable_path):
		loaded_unavailable = _read_unavailable_hosts_file(unavailable_path, max_ttl=unavailable_host_expiry)
		__globalUnavailableHosts.update(loaded_unavailable)
		if loaded_unavailable and not __global_suppress_printout:
			eprint("Read unavailable hosts from the file {}".format(unavailable_path))
	elif "__multiSSH3_UNAVAILABLE_HOSTS" in readEnvFromFile():
		__globalUnavailableHosts.update({
			host: int(time.monotonic() + unavailable_host_expiry)
			for host in readEnvFromFile()["__multiSSH3_UNAVAILABLE_HOSTS"].split(",")
			if host
		})
	max_connections = _normalize_max_connections(max_connections)
	commands = format_commands(commands)
	this_run_only = False
	#verify_ssh_config()
	# load global unavailable hosts only if the function is called (so using --repeat will not load the unavailable hosts again)
	if called:
		# if called,
		# if skip_unreachable is not set, we default to skip unreachable hosts within one command call
		if skip_unreachable is None:
			skip_unreachable = True
		if skip_unreachable:
			unavailableHosts = __globalUnavailableHosts
		else:
			unavailableHosts = dict()
		# set global input to empty
		__keyPressesIn = [[]]
		__global_suppress_printout = True
	else:
		# if run in command line ( or emulating running in command line, we default to skip unreachable hosts within one command call )
		if skip_unreachable:
			unavailableHosts = __globalUnavailableHosts
		else:
			unavailableHosts = dict()
			skip_unreachable = True
			# -a: only hosts found unreachable by this run's earlier commands are skipped
			this_run_only = True
	if pre_merge_hosts is ...:
		pre_merge_hosts = not called
	if no_output is ...:
		no_output = called
	if quiet:
		__global_suppress_printout = True
	# We create the hosts
	# the hosts as given: one on one mode pairs commands with them in this order
	hostTokens = _host_tokens_in_order(hosts)
	if isinstance(hosts, list):
		hosts = frozenset(hosts)
	elif isinstance(hosts, dict):
		hosts = frozenset(hosts.keys())
	hostStr = formHostStr(hosts)
	skipHostStr = formHostStr(skip_hosts) if skip_hosts else ''
	if files:
		if not file:
			file = files
		else:
			file = list(file) + list(files)
	if username:
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
	targetHostDic = expand_hostnames(hostStr.split(','))
	if __DEBUG_MODE:
		eprint(f"Target hosts: {targetHostDic!r}")
	skipHostsDic = expand_hostnames(skipHostStr.split(','))
	if _emo:
		_abort(1, 'Ctrl C caught, not starting the command', called=called)
	# hosts reachable only through the ssh config have no IP (None), which must not match other such hosts
	skipHostSet = set(skipHostsDic).union(ip for ip in skipHostsDic.values() if ip)
	if skipHostSet:
		eprint(f"Skipping hosts: \"{' '.join(compact_hostnames(skipHostSet))}\"")
	if not called:
		_report_tokens_naming_no_hosts(hostTokens)
		if not targetHostDic:
			# every host is a name that does not resolve or names no host: nothing would run
			_abort(max(1, __mainReturnCode), 'no hosts to run on', called=called)
		if all(host in skipHostSet or targetHostDic[host] in skipHostSet for host in targetHostDic):
			eprint('Warning: -X, --skip_hosts leaves no hosts to run on')
	if copy_id:
		if 'ssh-copy-id' in _binPaths:
			# we will copy the id to the hosts
			hosts = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet:
					continue
				# host already carries user@ when username is set, see hostStr above
				command = f"{shlex.quote(_binPaths['ssh-copy-id'])} "
				if identity_file:
					command = f"{command}-i {shlex.quote(os.path.expanduser(identity_file))} "
				command = f"{command}{shlex.quote(host)}"
				if password and 'sshpass' in _binPaths:
					command = f"{shlex.quote(_binPaths['sshpass'])} -p {shlex.quote(password)} {command}"
					hosts.append(Host(host, command,identity_file=identity_file,shell=True,ip = targetHostDic[host]))
				else:
					eprint(f"> {command}")
					os.system(command)
			if hosts:
				processRunOnHosts(timeout=timeout, password=password, max_connections=max_connections, hosts=hosts,
					   return_unfinished=return_unfinished, no_watch=no_watch, json=json, no_output=no_output, greppable=greppable,
					   unavailableHosts=unavailableHosts,will_update_unreachable_hosts=will_update_unreachable_hosts,
					   window_width = window_width, window_height = window_height,
					   single_window=single_window,unavailable_host_expiry=unavailable_host_expiry, pre_merge=pre_merge_hosts)
		else:
			eprint(f"Warning: ssh-copy-id not found in {_binPaths} , skipping copy id to the hosts")
		if not commands:
			_abort(0, "Copy id finished, no commands to run", called=called)
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
		if __DEBUG_MODE:
			eprint(f"Files: {file!r}")
	def recently_unreachable(host):
		'''Whether host is skipped (not run, a failure) because it was unreachable in a recent run.'''
		return not ipmi and skip_unreachable and host in unavailableHosts and unavailableHosts[host] > time.monotonic()
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
			if file_sync:
				new_host = Host(host, os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip = targetHostDic[host])
			else:
				new_host = Host(host, command, files = file,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host])
			hosts.append(new_host)
			if recently_unreachable(host):
				eprint(f"Skipping unavailable host: {host}")
				_mark_skipped_unreachable(new_host, unavailableHosts[host], this_run_only)
			elif not __global_suppress_printout: 
				eprint(f"Running command: {command!r} on host: {host!r}")
		if not __global_suppress_printout:
			eprint('-'*80)
		if not no_start: 
			processRunOnHosts(timeout=timeout, password=password, max_connections=max_connections, hosts=hosts,
					  return_unfinished=return_unfinished, no_watch=no_watch, json=json, no_output=no_output, greppable=greppable,
					  unavailableHosts=unavailableHosts,will_update_unreachable_hosts=will_update_unreachable_hosts,
					  window_width = window_width, window_height = window_height,
					  single_window=single_window,unavailable_host_expiry=unavailable_host_expiry,pre_merge=pre_merge_hosts)
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
					new_host = Host(host, '', files = file,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,identity_file=identity_file,ip=targetHostDic[host])
					hosts.append(new_host)
					if recently_unreachable(host):
						if not __global_suppress_printout:
							eprint(f"Skipping unavailable host: {host}")
						_mark_skipped_unreachable(new_host, unavailableHosts[host], this_run_only)
			if not __global_suppress_printout:
				eprint('-'*80)
				eprint(f"Running in interactive mode on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if no_start:
				eprint("Warning: no_start is set, the command will not be started. As we are in interactive mode, no action will be done.")
			else:
				processRunOnHosts(timeout=timeout, password=password, max_connections=max_connections, hosts=hosts,
					   return_unfinished=return_unfinished, no_watch=no_watch, json=json, no_output=no_output, greppable=greppable,
					   unavailableHosts=unavailableHosts,will_update_unreachable_hosts=will_update_unreachable_hosts,
					   window_width = window_width, window_height = window_height,
					   single_window=single_window,unavailable_host_expiry=unavailable_host_expiry,pre_merge=pre_merge_hosts)
			return hosts
		for command in commands:
			if _emo:
				# Ctrl-C during an earlier command: run no more
				break
			hosts = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet:
					continue
				if file_sync:
					new_host = Host(host, os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host])
				else:
					new_host = Host(host, command, files = file,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host])
				hosts.append(new_host)
				if recently_unreachable(host):
					if not __global_suppress_printout:
						eprint(f"Skipping unavailable host: {host}")
					_mark_skipped_unreachable(new_host, unavailableHosts[host], this_run_only)
			if not __global_suppress_printout and len(commands) > 1:
				eprint('-'*80)
				eprint(f"Running command: {command} on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if not no_start: 
				processRunOnHosts(timeout=timeout, password=password, max_connections=max_connections, hosts=hosts,
					   return_unfinished=return_unfinished, no_watch=no_watch, json=json, no_output=no_output, greppable=greppable,
					   unavailableHosts=unavailableHosts,will_update_unreachable_hosts=will_update_unreachable_hosts,
					   window_width = window_width, window_height = window_height,
					   single_window=single_window,unavailable_host_expiry=unavailable_host_expiry,pre_merge=pre_merge_hosts)
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
		'DEFAULT_PASSWORD': args.password,
		'DEFAULT_IDENTITY_FILE': args.identity_file if args.identity_file and not os.path.isdir(args.identity_file) else DEFAULT_IDENTITY_FILE,
		'DEFAULT_SSH_KEY_SEARCH_PATH': args.identity_file if args.identity_file and os.path.isdir(args.identity_file) else DEFAULT_SSH_KEY_SEARCH_PATH,
		'DEFAULT_USE_KEY': args.use_key,
		'DEFAULT_EXTRA_ARGS': args.extraargs,
		'DEFAULT_ONE_ON_ONE': args.oneonone,
		'DEFAULT_SCP': args.scp,
		'DEFAULT_FILE_SYNC': args.file_sync,
		'DEFAULT_TIMEOUT': DEFAULT_TIMEOUT,
		'DEFAULT_CLI_TIMEOUT': args.timeout,
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
		'DEFAULT_IPMI_DEFINITIONS': DEFAULT_IPMI_DEFINITIONS,
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
		eprint(f"b:  Rename the current config file at {CONFIG_FILE!r}.bak forcefully and write the new config file (default)")
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
		previous_mode = stat.S_IMODE(os.stat(CONFIG_FILE).st_mode)
	except OSError:
		previous_mode = None
	try:
		if backup and os.path.exists(CONFIG_FILE):
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
		# configs can hold passwords: owner only, except the system-wide locations every user reads
		mode = 0o644 if _is_system_config_path(CONFIG_FILE) else 0o600
		# write through a symlinked config (e.g. into a dotfiles repo) instead of replacing the link, but
		# only a link of our own (or root's): one planted by someone else (e.g. in /tmp) could point anywhere
		if os.path.islink(CONFIG_FILE) and hasattr(os, 'getuid') and os.lstat(CONFIG_FILE).st_uid not in (os.getuid(), 0):
			raise PermissionError('{!r} is a symlink owned by someone else, not writing through it'.format(CONFIG_FILE))
		target = os.path.realpath(CONFIG_FILE)
		try:
			st = os.stat(target)
		except FileNotFoundError:
			st = None
		if st is None or not hasattr(os, 'getuid') or st.st_uid == os.getuid():
			# new or ours: write a temporary file and rename it over, a failure never empties the old config
			if st is not None:
				# only tighten an existing file, an admin may have locked it down further
				new_mode = stat.S_IMODE(st.st_mode) & mode
			else:
				# a file replacing a backed up one keeps its tighter mode
				new_mode = mode if previous_mode is None else previous_mode & mode
			temporary = '{}.{}.tmp'.format(target, uuid4().hex)
			fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, new_mode)
			try:
				with os.fdopen(fd, 'w') as f:
					if hasattr(os, 'fchmod'):
						# O_CREAT's mode is reduced by the umask, set it exactly
						os.fchmod(f.fileno(), new_mode)
					if st is not None and hasattr(os, 'chown'):
						try:
							os.chown(temporary, -1, st.st_gid)
						except OSError:
							pass
					json.dump(__configs_from_file,f,indent=4)
					f.flush()
					os.fsync(f.fileno())
				os.replace(temporary, target)
			except BaseException:
				try:
					os.unlink(temporary)
				except OSError:
					pass
				raise
		else:
			# someone else's file we can write to: renaming over it would take it over, write it in place
			new_mode = stat.S_IMODE(st.st_mode) & mode
			fd = os.open(target, os.O_WRONLY)
			with os.fdopen(fd, 'w') as f:
				if hasattr(os, 'fchmod'):
					try:
						os.fchmod(fd, new_mode)
					except OSError:
						pass
				# only write the passwords if it is no more open than new_mode
				if stat.S_IMODE(os.fstat(fd).st_mode) & ~new_mode:
					raise PermissionError('cannot restrict the permissions of {!r} to {:o}, not writing passwords to it'.format(CONFIG_FILE, new_mode))
				f.truncate()
				json.dump(__configs_from_file,f,indent=4)
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

def get_parser():
	parser = argparse.ArgumentParser(
		description='Run a command on multiple hosts, Use #HOST# or #HOSTNAME# to replace the host name in the command.',
		epilog=(
			f"Terminal color capability: {get_terminal_color_capability()}\n"
			f"Found bins: \n{pformat(set(_binPaths.values()))}\n"
			f"Missing bins: \n{pformat(_binCalled - set(_binPaths.keys()))}\n"
			f"Config file chain: \n{pformat(CONFIG_FILE_CHAIN)}\n"
			f"Hosts Env files searched:\n{pformat(DEFAULT_ENV_FILES)}"
		),
		formatter_class=argparse.RawTextHelpFormatter,
	)
	parser.add_argument('hosts', metavar='hosts', type=str, nargs='?', help=f'Hosts to run the command on, use "," to seperate hosts. (default: {DEFAULT_HOSTS})',default=DEFAULT_HOSTS)
	parser.add_argument('commands', metavar='commands', type=str, nargs='*',default=None,help='the command to run on the hosts / the destination of the files #HOST# or #HOSTNAME# will be replaced with the host name.')
	parser.add_argument('-u','--username', type=str,help=f'The general username to use to connect to the hosts via ssh. Will get overwrote by individual username@host if specified. (default: {DEFAULT_USERNAME})',default=DEFAULT_USERNAME)
	parser.add_argument('-p', '--password', type=str,help=f'The password to use to connect to the hosts via ssh, (default: {DEFAULT_PASSWORD})',default=DEFAULT_PASSWORD)
	parser.add_argument('-k','--identity_file','--key','--identity',nargs='?', type=str,help=f'The identity file to use to connect to the hosts. Implies --use_key. Specify a folder for program to search for a key. Use option without value to use {DEFAULT_SSH_KEY_SEARCH_PATH} (default: {DEFAULT_IDENTITY_FILE})',const=DEFAULT_SSH_KEY_SEARCH_PATH,default=DEFAULT_IDENTITY_FILE)
	parser.add_argument('-uk','--use_key', action='store_true', help=f'Attempt to use public key file to connect to the hosts. (default: {DEFAULT_USE_KEY})', default=DEFAULT_USE_KEY)
	parser.add_argument('-ea','--extraargs',type=str,help=f'Extra arguments to pass to the ssh / rsync / scp command. (Use -ia for ipmi arguments) Put in one string for multiple arguments.Use "=" ! Ex. -ea="--delete" (default: {DEFAULT_EXTRA_ARGS})',default=DEFAULT_EXTRA_ARGS)
	parser.add_argument("-11",'--oneonone', action='store_true', help=f"Run one corresponding command on each host. (default: {DEFAULT_ONE_ON_ONE})", default=DEFAULT_ONE_ON_ONE)
	parser.add_argument("-f","--file", action='append', help="The file to be copied to the hosts. Use -f multiple times to copy multiple files")
	parser.add_argument('-s','-fs','--file_sync',nargs='?', action='append', help=f'Operate in file sync mode, sync path in <COMMANDS> from this machine to <HOSTS>. Treat --file <FILE> and <COMMANDS> both as source and source and destination will be the same in this mode. Infer destination from source path. (default: {DEFAULT_FILE_SYNC})',const=True, default=[DEFAULT_FILE_SYNC])
	parser.add_argument('-W','--scp', action='store_true', help=f'Use scp for copying files instead of rsync. Need to use this on windows. (default: {DEFAULT_SCP})', default=DEFAULT_SCP)
	parser.add_argument('-G','-gm','--gather_mode', action='store_true', help='Gather files from the hosts instead of sending files to the hosts. Will send remote files specified in <FILE> to local path specified in <COMMANDS>  (default: False)', default=False)
	#parser.add_argument("-d",'-c',"--destination", type=str, help="The destination of the files. Same as specify with commands. Added for compatibility. Use #HOST# or #HOSTNAME# to replace the host name in the destination")
	parser.add_argument("-t","--timeout", type=int, help=f"Timeout for each command in seconds. Set default value via DEFAULT_CLI_TIMEOUT in config file. Use 0 for disabling timeout. (default: {DEFAULT_CLI_TIMEOUT})", default=DEFAULT_CLI_TIMEOUT)
	parser.add_argument('-T','--use_script_timeout',action='store_true', help=f'Use shortened timeout suitable to use in a script. Set value via DEFAULT_TIMEOUT field in config file. (current: {DEFAULT_TIMEOUT})', default=False)
	parser.add_argument("-r","--repeat", type=_positive_int, help=f"Repeat the command for a number of times (default: {DEFAULT_REPEAT})", default=DEFAULT_REPEAT)
	parser.add_argument("-i","--interval", type=int, help=f"Interval between repeats in seconds (default: {DEFAULT_INTERVAL})", default=DEFAULT_INTERVAL)
	parser.add_argument('-M',"--ipmi", action='store_true', help=f"Use ipmitool to run the command. (default: {DEFAULT_IPMI})", default=DEFAULT_IPMI)
	parser.add_argument("-mpre","--ipmi_interface_ip_prefix", type=str, help=f"The prefix of the IPMI interfaces (default: {DEFAULT_IPMI_INTERFACE_IP_PREFIX})", default=DEFAULT_IPMI_INTERFACE_IP_PREFIX)
	parser.add_argument("-pre","--interface_ip_prefix", type=str, help=f"The prefix of the for the interfaces (default: {DEFAULT_INTERFACE_IP_PREFIX})", default=DEFAULT_INTERFACE_IP_PREFIX)
	parser.add_argument('-iu','--ipmi_username', type=str,help=f'The username to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_USERNAME})',default=DEFAULT_IPMI_USERNAME)
	parser.add_argument('-ip','--ipmi_password', type=str,help=f'The password to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_PASSWORD})',default=DEFAULT_IPMI_PASSWORD)
	parser.add_argument('-ia','--ipmi_args',type=str,help=f'The arguments passed to ipmitool to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_ARGS})',default=DEFAULT_IPMI_ARGS)
	parser.add_argument('-im','--ipmi_method', type=str,help=f'The method to use to connect to the hosts via ipmi. (default: {DEFAULT_IPMI_METHOD})',default=DEFAULT_IPMI_METHOD)
	parser.add_argument('-irlt','--ipmi_retry_lockout_time', type=int,help=f'The time in seconds to retry the lockout of the hosts via ipmi. (default: {DEFAULT_IPMI_RETRY_LOCKOUT_TIME})',default=DEFAULT_IPMI_RETRY_LOCKOUT_TIME)
	parser.add_argument('-S',"-q","-nw","--no_watch", action='store_true', help=f"Quiet mode, no curses watch, only print the output. (default: {DEFAULT_NO_WATCH})", default=DEFAULT_NO_WATCH)
	parser.add_argument("-ww",'--window_width', type=int, help=f"The minimum character length of the curses window. (default: {DEFAULT_WINDOW_WIDTH})", default=DEFAULT_WINDOW_WIDTH)
	parser.add_argument("-wh",'--window_height', type=int, help=f"The minimum line height of the curses window. (default: {DEFAULT_WINDOW_HEIGHT})", default=DEFAULT_WINDOW_HEIGHT)
	parser.add_argument('-B','-sw','--single_window', action='store_true', help=f'Use a single window for all hosts. (default: {DEFAULT_SINGLE_WINDOW})', default=DEFAULT_SINGLE_WINDOW)
	parser.add_argument('-R','-eo','--error_only', action='store_true', help=f'Only print the error output. (default: {DEFAULT_ERROR_ONLY})', default=DEFAULT_ERROR_ONLY)
	parser.add_argument('-Q',"-no","--no_output","--quiet", action='store_true', help=f"Do not print the output. (default: {DEFAULT_NO_OUTPUT})", default=DEFAULT_NO_OUTPUT)
	parser.add_argument('-Z','-rz','--return_zero', action='store_true', help=f"Return 0 even if there are errors. (default: {DEFAULT_RETURN_ZERO})", default=DEFAULT_RETURN_ZERO)
	parser.add_argument('-C','--no_env', action='store_true', help=f'Do not load the command line environment variables. (default: {DEFAULT_NO_ENV})', default=DEFAULT_NO_ENV)
	parser.add_argument('-ef',"--env_file", type=str, help="Replace the env file look up chain with this env_file. ( Still work with --no_env ) (default: None)", default='')
	parser.add_argument('-efs',"--env_files", action='append', help="The files to load the mssh file based environment variables from. Can specify multiple. Load first to last. ( Still work with --no_env ) (default: [])", default=[])
	parser.add_argument("-m","--max_connections", type=int, help="Max number of connections to use (default: 4 * cpu_count)", default=DEFAULT_MAX_CONNECTIONS)
	parser.add_argument("-j","--json", action='store_true', help=F"Output in json format. (default: {DEFAULT_JSON_MODE})", default=DEFAULT_JSON_MODE)
	parser.add_argument('-w',"--success_hosts", action='store_true', help=f"Output the hosts that succeeded in summary as well. (default: {DEFAULT_PRINT_SUCCESS_HOSTS})", default=DEFAULT_PRINT_SUCCESS_HOSTS)
	parser.add_argument('-P',"-g","--greppable",'--table', action='store_true', help=f"Output in greppable table. (default: {DEFAULT_GREPPABLE_MODE})", default=DEFAULT_GREPPABLE_MODE)
	su_group = parser.add_mutually_exclusive_group()
	su_group.add_argument('-x',"-su","--skip_unreachable", action='store_true', help=f"Skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {DEFAULT_SKIP_UNREACHABLE})", default=DEFAULT_SKIP_UNREACHABLE)
	su_group.add_argument('-a',"-nsu","--no_skip_unreachable",dest = 'skip_unreachable', action='store_false', help=f"Do not skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {not DEFAULT_SKIP_UNREACHABLE})", default=not DEFAULT_SKIP_UNREACHABLE)
	parser.add_argument('-uhe','--unavailable_host_expiry', type=int, help=f"Time in seconds to expire the unavailable hosts (default: {DEFAULT_UNAVAILABLE_HOST_EXPIRY})", default=DEFAULT_UNAVAILABLE_HOST_EXPIRY)
	parser.add_argument('-X',"-sh","--skip_hosts", type=str, help=f"Skip the hosts in the list. (default: {DEFAULT_SKIP_HOSTS if DEFAULT_SKIP_HOSTS else 'None'})", default=DEFAULT_SKIP_HOSTS)
	parser.add_argument('--generate_config_file', action='store_true', help='Restore / generate using the build-in default configs with default config file chain and command line argument to write to --store_config_file / stdout')
	parser.add_argument('--config_file', type=str,nargs='?', help='Load additional config file to apply, Warning: will over write CLI options. Use without a path will use multiSSH3.config.json',const='multiSSH3.config.json',default=None)
	parser.add_argument('--store_config_file',type = str,nargs='?',help=f'Refresh / store the specified config file with new params and command line args into the config file. Defaults to the first config file found in search path: {__working_config_file}',const=...)
	parser.add_argument('--debug', action='store_true', help='Print debug information')
	parser.add_argument('-ci','--copy_id', action='store_true', help='Copy the ssh id to the hosts')
	parser.add_argument('-I','-nh','--no_history', action='store_true', help=f'Do not record the command to history. Default: {DEFAULT_NO_HISTORY}', default=DEFAULT_NO_HISTORY)
	parser.add_argument('-hf','--history_file', type=str, help=f'The file to store the history. (default: {DEFAULT_HISTORY_FILE})', default=DEFAULT_HISTORY_FILE)
	parser.add_argument('--script', action='store_true', help='Run the command in script mode, short for -SCRIPT or --no_watch --skip_unreachable --no_env --no_history --greppable --error_only')
	parser.add_argument('-e','--encoding', type=str, help=f'The encoding to use for the output. (default: {DEFAULT_ENCODING})', default=DEFAULT_ENCODING)
	parser.add_argument('-dt','--diff_display_threshold', type=float, help=f'The threshold of lines to display the diff when files differ. {{0-1}} Set to 0 to always display the diff. Set to 1 to disable diff. (Only merge same) (default: {DEFAULT_DIFF_DISPLAY_THRESHOLD})', default=DEFAULT_DIFF_DISPLAY_THRESHOLD)
	parser.add_argument('--force_truecolor', action='store_true', help=f'Force truecolor output even when not in a truecolor terminal. (default: {FORCE_TRUECOLOR})', default=FORCE_TRUECOLOR)
	parser.add_argument('--add_control_master_config', action='store_true', help='Add ControlMaster configuration to ~/.ssh/config to speed up multiple connections to the same host.')
	parser.add_argument('--host_file', type=str,help=f'File containing list of hosts to run the command on, one host per line. Default:{DEFAULT_HOST_FILE}', default=DEFAULT_HOST_FILE)
	parser.add_argument('--completion', nargs='+', metavar='ARG', help='Shell autocomplete: print the glue for bash, zsh or fish, or "install [SHELL] [editor]" / "uninstall [SHELL]" it for the current user ("editor": the plain-bash mssh line editor)')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} @ {COMMIT_DATE} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	return parser

def process_args(args = None):
	global __configs_from_file
	cfp = 	parser = argparse.ArgumentParser(add_help=False)
	cfp.add_argument('--config_file', type=str,nargs='?',const='multiSSH3.config.json',default=None)
	try:
		cfpa, args = cfp.parse_known_args(args)
		if cfpa.config_file:
			if os.path.exists(cfpa.config_file):
				configs = load_config_file(os.path.expanduser(cfpa.config_file), check_trust=False)
				apply_config_key_compat(configs)
				globals().update(configs)
				__configs_from_file.update(configs)
			else:
				eprint("Warning: Config file {!r} not found, ignoring it.".format(cfpa.config_file))
	except Exception:
		pass
	parser = get_parser()
	# We handle the signal
	signal.signal(signal.SIGINT, signal_handler)
	# We parse the arguments
	# if python version is 3.7 or higher, use parse_intermixed_args
	try:
		args = parser.parse_intermixed_args(args)
	except Exception :
		#eprint(f"Error while parsing arguments: {e!r}")
		# try to parse the arguments using parse_known_args
		args, unknown = parser.parse_known_args(args)
		# if there are unknown arguments, we will try to parse them again using parse_args
		if unknown:
			eprint(f"Warning: Unknown arguments, treating all as commands: {unknown!r}")
			args.commands += unknown
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
	default_ipmi_definition = get_default_ipmi_definition()
	while DEFAULT_IPMI_DEFINITIONS:
		last_definition = DEFAULT_IPMI_DEFINITIONS.pop()
		if last_definition != default_ipmi_definition:
			DEFAULT_IPMI_DEFINITIONS.append(last_definition)
			break
	fields = [
		('interface_ip_prefix', args.ipmi_interface_ip_prefix),
		('username', args.ipmi_username),
		('password', args.ipmi_password),
		('args', args.ipmi_args),
		('ipmi_method', args.ipmi_method),
		('retry_lockout_time', args.ipmi_retry_lockout_time),
	]
	modified = any(val != default_ipmi_definition[key] for key, val in fields)
	for key, val in fields:
		default_ipmi_definition[key] = val
	if modified:
		DEFAULT_IPMI_DEFINITIONS.insert(0, default_ipmi_definition)
	else:
		DEFAULT_IPMI_DEFINITIONS.append(default_ipmi_definition)
	return args

def process_config_file(args):
	global __configs_from_file
	global __working_config_file
	if args.generate_config_file or args.store_config_file:
		if args.store_config_file:
			if args.store_config_file is ...:
				configFileToWriteTo = __working_config_file
			else:
				configFileToWriteTo = args.store_config_file
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
			elif not os.path.exists(args.identity_file):
				eprint(f"Warning: Identity file {args.identity_file!r} not found. Passing to ssh anyway. Proceed with caution.")
	return args

def process_control_master_config(args):
	global __control_master_string
	if args.add_control_master_config:
		try:
			if not os.path.exists(os.path.expanduser('~/.ssh')):
				os.makedirs(os.path.expanduser('~/.ssh'),mode=0o700)
			ssh_config_file = os.path.expanduser('~/.ssh/config')
			if not os.path.exists(ssh_config_file):
				with open(ssh_config_file,'w') as f:
					f.write(__control_master_string)
				os.chmod(ssh_config_file,0o644)
			else:
				with open(ssh_config_file,'r') as f:
					ssh_config_content = f.readlines()
				if set(map(str.strip,ssh_config_content)).issuperset(set(map(str.strip,__control_master_string.splitlines()))):
					eprint("ControlMaster configuration already exists in ~/.ssh/config, skipping adding:")
					eprint(__control_master_string)
				else:
					with open(ssh_config_file,'a') as f:
						f.write('\n# Added by multiSSH3.py to speed up subsequent connections\n')
						f.write(__control_master_string)
					eprint("ControlMaster configuration added to ~/.ssh/config.")
		except Exception as e:
			eprint(f"Error adding ControlMaster configuration: {e}")
			import traceback
			traceback.print_exc()
		if not args.commands and not args.file:
			_exit_with_code(0, "Done configuring ControlMaster.")
	return args

def set_global_with_args(args):
	global _emo
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
def _completion_command(values):
	'''Run `mssh --completion ...` with mssh_complete, which ships next to this file.'''
	try:
		import mssh_complete
	except ImportError:
		here = os.path.dirname(os.path.abspath(__file__))
		if here not in sys.path:
			sys.path.insert(0, here)
		try:
			import mssh_complete
		except ImportError:
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

def main(args = None):
	global __global_suppress_printout
	global __mainReturnCode
	global __failedHosts
	args = process_args(args)
	if args.completion:
		_exit_with_code(_completion_command(args.completion))
	args = process_config_file(args)
	args = process_commands(args)
	args = process_keys(args)
	args = process_control_master_config(args)
	set_global_with_args(args)
	
	if args.use_script_timeout:
		# set timeout to the default script timeout if timeout is not set
		if args.timeout == DEFAULT_CLI_TIMEOUT:
			args.timeout = DEFAULT_TIMEOUT
	
	if args.no_output:
		__global_suppress_printout = True
	if not __global_suppress_printout:
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
	# record the command once: a line per repeat, each saying --repeat, would replay it repeat^2 times
	if not args.no_history:
		record_command_history(vars(args))
	runArgs = dict(vars(args), no_history=True)
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
			else:
				succeededHosts.add(host.name)
	# each failing host counts once, however many runs or commands it failed
	__mainReturnCode += len(failedHostNames)
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
	else:
		if not __global_suppress_printout: 
			eprint('Complete. All hosts returned 0.')
	
	if args.success_hosts and not __global_suppress_printout:
		eprint(f'succeeded_hosts: {_summary_host_list(succeededHosts)}')

	if threading.active_count() > 1 and not __global_suppress_printout: 
		eprint(f'Remaining active thread: {threading.active_count()}')
		# os.system(f'pkill -ef  {os.path.basename(__file__)}')
		# os._exit(mainReturnCode)
	
	_exit_with_code(__mainReturnCode)

if __name__ == "__main__":
	main()
