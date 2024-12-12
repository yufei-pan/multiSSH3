#!/usr/bin/env python3
__curses_available = False
try:
	import curses
	__curses_available = True
except ImportError:
	pass
import subprocess
import threading
import time,os
import argparse
from itertools import product
import re
import string
import ipaddress
import sys
import json
import socket
import io
import signal
import functools
import glob
import shutil
import getpass
import uuid
import tempfile
import math

try:
	# Check if functiools.cache is available
	cache_decorator = functools.cache
except AttributeError:
	try:
		# Check if functools.lru_cache is available
		cache_decorator = functools.lru_cache(maxsize=None)
	except AttributeError:
		# If neither is available, use a dummy decorator
		def cache_decorator(func):
			return func
version = '5.38'
VERSION = version

CONFIG_FILE = '/etc/multiSSH3.config.json'	

# ------------ Pre Helper Functions ----------------
def eprint(*args, **kwargs):
	try:
		print(*args, file=sys.stderr, **kwargs)
	except Exception as e:
		print(f"Error: Cannot print to stderr: {e}")
		print(*args, **kwargs)

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
	if not _emo:
		eprint('Ctrl C caught, exiting...')
		_emo = True
	else:
		eprint('Ctrl C caught again, exiting immediately!')
		# wait for 0.1 seconds to allow the threads to exit
		time.sleep(0.1)
		os.system(f'pkill -ef {os.path.basename(__file__)}')
		sys.exit(0)

def input_with_timeout_and_countdown(timeout, prompt='Please enter your selection'):
	"""
	Read an input from the user with a timeout and a countdown.

	Parameters:
	timeout (int): The timeout value in seconds.
	prompt (str): The prompt message to display to the user. Default is 'Please enter your selection'.

	Returns:
	str or None: The user input if received within the timeout, or None if no input is received.
	"""
	import select
	# Print the initial prompt with the countdown
	eprint(f"{prompt} [{timeout}s]: ", end='', flush=True)
	# Loop until the timeout
	for remaining in range(timeout, 0, -1):
		# If there is an input, return it
		if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
			return input().strip()
		# Print the remaining time
		eprint(f"\r{prompt} [{remaining}s]: ", end='', flush=True)
		# Wait a second
		time.sleep(1)
	# If there is no input, return None
	return None

@cache_decorator
def getIP(hostname: str,local=False):
	'''
	Get the IP address of the hostname

	Args:
		hostname (str): The hostname

	Returns:
		str: The IP address of the hostname
	'''
	global _etc_hosts
	if '@' in hostname:
		_, hostname = hostname.rsplit('@',1)
	# First we check if the hostname is an IP address
	try:
		ipaddress.ip_address(hostname)
		return hostname
	except ValueError:
		pass
	# Then we check /etc/hosts
	if not _etc_hosts and os.path.exists('/etc/hosts'):
		with open('/etc/hosts','r') as f:
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
	try:
		return socket.gethostbyname(hostname)
	except:
		return None

__host_i_lock = threading.Lock()
__host_i_counter = -1
def _get_i():
	'''
	Get the global counter for the host objects

	Returns:
	int: The global counter for the host objects
	'''
	global __host_i_counter
	global __host_i_lock
	with __host_i_lock:
		__host_i_counter += 1
		return __host_i_counter

# ------------ Host Object ----------------
class Host:
	def __init__(self, name, command, files = None,ipmi = False,interface_ip_prefix = None,scp=False,extraargs=None,gatherMode=False,identity_file=None,shell=False,i = _get_i(),uuid=uuid.uuid4(),ip = None):
		self.name = name # the name of the host (hostname or IP address)
		self.command = command # the command to run on the host
		self.returncode = None # the return code of the command
		self.output = [] # the output of the command for curses
		self.stdout = [] # the stdout of the command
		self.stderr = [] # the stderr of the command
		self.printedLines = -1 # the number of lines printed on the screen
		self.lineNumToReprintSet = set() # whether to reprint the last line
		self.lastUpdateTime = time.time() # the last time the output was updated
		self.files = files # the files to be copied to the host
		self.ipmi = ipmi # whether to use ipmi to connect to the host
		self.shell = shell # whether to use shell to run the command
		self.interface_ip_prefix = interface_ip_prefix # the prefix of the ip address of the interface to be used to connect to the host
		self.scp = scp # whether to use scp to copy files to the host
		self.gatherMode = gatherMode # whether the host is in gather mode
		self.extraargs = extraargs # extra arguments to be passed to ssh
		self.resolvedName = None # the resolved IP address of the host
		# also store a globally unique integer i from 0
		self.i = i
		self.uuid = uuid
		self.identity_file = identity_file
		self.ip = ip if ip else getIP(name)
		self.current_color_pair = [-1, -1, 1]

	def __iter__(self):
		return zip(['name', 'command', 'returncode', 'stdout', 'stderr'], [self.name, self.command, self.returncode, self.stdout, self.stderr])
	def __repr__(self):
		# return the complete data structure
		return f"Host(name={self.name}, command={self.command}, returncode={self.returncode}, stdout={self.stdout}, stderr={self.stderr}, \
output={self.output}, printedLines={self.printedLines}, lineNumToReprintSet={self.lineNumToReprintSet}, files={self.files}, ipmi={self.ipmi}, \
interface_ip_prefix={self.interface_ip_prefix}, scp={self.scp}, gatherMode={self.gatherMode}, \
extraargs={self.extraargs}, resolvedName={self.resolvedName}, i={self.i}, uuid={self.uuid}), \
identity_file={self.identity_file}, ip={self.ip}, current_color_pair={self.current_color_pair}"
	def __str__(self):
		return f"Host(name={self.name}, command={self.command}, returncode={self.returncode}, stdout={self.stdout}, stderr={self.stderr})"

# ------------ Load Defaults ( Config ) File ----------------
def load_config_file(config_file):
	'''
	Load the config file to global variables

	Args:
		config_file (str): The config file

	Returns:
		dict: The config
	'''
	if not os.path.exists(config_file):
		return {}
	try:
		with open(config_file,'r') as f:
			config = json.load(f)
	except:
		eprint(f"Error: Cannot load config file {config_file!r}")
		return {}
	return config

__configs_from_file = load_config_file(CONFIG_FILE)

__build_in_default_config = {
	'AUTHOR': 'Yufei Pan',
	'AUTHOR_EMAIL': 'pan@zopyr.us',
	'DEFAULT_HOSTS': 'all',
	'DEFAULT_USERNAME': None,
	'DEFAULT_PASSWORD': '',
	'DEFAULT_IDENTITY_FILE': None,
	'DEDAULT_SSH_KEY_SEARCH_PATH': '~/.ssh/',
	'DEFAULT_USE_KEY': False,
	'DEFAULT_EXTRA_ARGS': None,
	'DEFAULT_ONE_ON_ONE': False,
	'DEFAULT_SCP': False,
	'DEFAULT_FILE_SYNC': False,
	'DEFAULT_TIMEOUT': 50,
	'DEFAULT_CLI_TIMEOUT': 0,
	'DEFAULT_REPEAT': 1,
	'DEFAULT_INTERVAL': 0,
	'DEFAULT_IPMI': False,
	'DEFAULT_IPMI_INTERFACE_IP_PREFIX': '',
	'DEFAULT_INTERFACE_IP_PREFIX': None,
	'DEFAULT_NO_WATCH': False,
	'DEFAULT_CURSES_MINIMUM_CHAR_LEN': 40,
	'DEFAULT_CURSES_MINIMUM_LINE_LEN': 1,
	'DEFAULT_SINGLE_WINDOW': False,
	'DEFAULT_ERROR_ONLY': False,
	'DEFAULT_NO_OUTPUT': False,
	'DEFAULT_NO_ENV': False,
	'DEFAULT_ENV_FILE': '/etc/profile.d/hosts.sh',
	'DEFAULT_MAX_CONNECTIONS': 4 * os.cpu_count(),
	'DEFAULT_JSON_MODE': False,
	'DEFAULT_PRINT_SUCCESS_HOSTS': False,
	'DEFAULT_GREPPABLE_MODE': False,
	'DEFAULT_SKIP_UNREACHABLE': True,
	'DEFAULT_SKIP_HOSTS': '',
	'SSH_STRICT_HOST_KEY_CHECKING': False,
	'ERROR_MESSAGES_TO_IGNORE': [
		'Pseudo-terminal will not be allocated because stdin is not a terminal',
		'Connection to .* closed',
		'Warning: Permanently added',
		'mux_client_request_session',
		'disabling multiplexing',
		'Killed by signal',
		'Connection reset by peer',
	],
	'_DEFAULT_CALLED': True,
	'_DEFAULT_RETURN_UNFINISHED': False,
	'_DEFAULT_UPDATE_UNREACHABLE_HOSTS': True,
	'_DEFAULT_NO_START': False,
	'_etc_hosts': {},
	'_sshpassPath': None,
	'_sshPath': None,
	'_scpPath': None,
	'_ipmitoolPath': None,
	'_rsyncPath': None,
	'_shellPath': None,
	'__ERROR_MESSAGES_TO_IGNORE_REGEX':None,
	'__DEBUG_MODE': False,
}

# Load Config Based Default Global variables
if True:
	AUTHOR = __configs_from_file.get('AUTHOR', __build_in_default_config['AUTHOR'])
	AUTHOR_EMAIL = __configs_from_file.get('AUTHOR_EMAIL', __build_in_default_config['AUTHOR_EMAIL'])

	DEFAULT_HOSTS = __configs_from_file.get('DEFAULT_HOSTS', __build_in_default_config['DEFAULT_HOSTS'])
	DEFAULT_ENV_FILE = __configs_from_file.get('DEFAULT_ENV_FILE', __build_in_default_config['DEFAULT_ENV_FILE'])
	DEFAULT_USERNAME = __configs_from_file.get('DEFAULT_USERNAME', __build_in_default_config['DEFAULT_USERNAME'])
	DEFAULT_PASSWORD = __configs_from_file.get('DEFAULT_PASSWORD', __build_in_default_config['DEFAULT_PASSWORD'])
	DEFAULT_IDENTITY_FILE = __configs_from_file.get('DEFAULT_IDENTITY_FILE', __build_in_default_config['DEFAULT_IDENTITY_FILE'])
	DEDAULT_SSH_KEY_SEARCH_PATH = __configs_from_file.get('DEDAULT_SSH_KEY_SEARCH_PATH', __build_in_default_config['DEDAULT_SSH_KEY_SEARCH_PATH'])
	DEFAULT_USE_KEY = __configs_from_file.get('DEFAULT_USE_KEY', __build_in_default_config['DEFAULT_USE_KEY'])
	DEFAULT_EXTRA_ARGS = __configs_from_file.get('DEFAULT_EXTRA_ARGS', __build_in_default_config['DEFAULT_EXTRA_ARGS'])
	DEFAULT_ONE_ON_ONE = __configs_from_file.get('DEFAULT_ONE_ON_ONE', __build_in_default_config['DEFAULT_ONE_ON_ONE'])
	DEFAULT_SCP = __configs_from_file.get('DEFAULT_SCP', __build_in_default_config['DEFAULT_SCP'])
	DEFAULT_FILE_SYNC = __configs_from_file.get('DEFAULT_FILE_SYNC', __build_in_default_config['DEFAULT_FILE_SYNC'])
	DEFAULT_TIMEOUT = __configs_from_file.get('DEFAULT_TIMEOUT', __build_in_default_config['DEFAULT_TIMEOUT'])
	DEFAULT_CLI_TIMEOUT = __configs_from_file.get('DEFAULT_CLI_TIMEOUT', __build_in_default_config['DEFAULT_CLI_TIMEOUT'])
	DEFAULT_REPEAT = __configs_from_file.get('DEFAULT_REPEAT', __build_in_default_config['DEFAULT_REPEAT'])
	DEFAULT_INTERVAL = __configs_from_file.get('DEFAULT_INTERVAL', __build_in_default_config['DEFAULT_INTERVAL'])
	DEFAULT_IPMI = __configs_from_file.get('DEFAULT_IPMI', __build_in_default_config['DEFAULT_IPMI'])
	DEFAULT_IPMI_INTERFACE_IP_PREFIX = __configs_from_file.get('DEFAULT_IPMI_INTERFACE_IP_PREFIX', __build_in_default_config['DEFAULT_IPMI_INTERFACE_IP_PREFIX'])
	DEFAULT_INTERFACE_IP_PREFIX = __configs_from_file.get('DEFAULT_INTERFACE_IP_PREFIX', __build_in_default_config['DEFAULT_INTERFACE_IP_PREFIX'])
	DEFAULT_NO_WATCH = __configs_from_file.get('DEFAULT_NO_WATCH', __build_in_default_config['DEFAULT_NO_WATCH'])
	DEFAULT_CURSES_MINIMUM_CHAR_LEN = __configs_from_file.get('DEFAULT_CURSES_MINIMUM_CHAR_LEN', __build_in_default_config['DEFAULT_CURSES_MINIMUM_CHAR_LEN'])
	DEFAULT_CURSES_MINIMUM_LINE_LEN = __configs_from_file.get('DEFAULT_CURSES_MINIMUM_LINE_LEN', __build_in_default_config['DEFAULT_CURSES_MINIMUM_LINE_LEN'])
	DEFAULT_SINGLE_WINDOW = __configs_from_file.get('DEFAULT_SINGLE_WINDOW', __build_in_default_config['DEFAULT_SINGLE_WINDOW'])
	DEFAULT_ERROR_ONLY = __configs_from_file.get('DEFAULT_ERROR_ONLY', __build_in_default_config['DEFAULT_ERROR_ONLY'])
	DEFAULT_NO_OUTPUT = __configs_from_file.get('DEFAULT_NO_OUTPUT', __build_in_default_config['DEFAULT_NO_OUTPUT'])
	DEFAULT_NO_ENV = __configs_from_file.get('DEFAULT_NO_ENV', __build_in_default_config['DEFAULT_NO_ENV'])
	DEFAULT_MAX_CONNECTIONS = __configs_from_file.get('DEFAULT_MAX_CONNECTIONS', __build_in_default_config['DEFAULT_MAX_CONNECTIONS'])
	if not DEFAULT_MAX_CONNECTIONS:
		DEFAULT_MAX_CONNECTIONS = 4 * os.cpu_count()
	DEFAULT_JSON_MODE = __configs_from_file.get('DEFAULT_JSON_MODE', __build_in_default_config['DEFAULT_JSON_MODE'])
	DEFAULT_PRINT_SUCCESS_HOSTS = __configs_from_file.get('DEFAULT_PRINT_SUCCESS_HOSTS', __build_in_default_config['DEFAULT_PRINT_SUCCESS_HOSTS'])
	DEFAULT_GREPPABLE_MODE = __configs_from_file.get('DEFAULT_GREPPABLE_MODE', __build_in_default_config['DEFAULT_GREPPABLE_MODE'])
	DEFAULT_SKIP_UNREACHABLE = __configs_from_file.get('DEFAULT_SKIP_UNREACHABLE', __build_in_default_config['DEFAULT_SKIP_UNREACHABLE'])
	DEFAULT_SKIP_HOSTS = __configs_from_file.get('DEFAULT_SKIP_HOSTS', __build_in_default_config['DEFAULT_SKIP_HOSTS'])

	SSH_STRICT_HOST_KEY_CHECKING = __configs_from_file.get('SSH_STRICT_HOST_KEY_CHECKING', __build_in_default_config['SSH_STRICT_HOST_KEY_CHECKING'])

	ERROR_MESSAGES_TO_IGNORE = __configs_from_file.get('ERROR_MESSAGES_TO_IGNORE', __build_in_default_config['ERROR_MESSAGES_TO_IGNORE'])

	_DEFAULT_CALLED = __configs_from_file.get('_DEFAULT_CALLED', __build_in_default_config['_DEFAULT_CALLED'])
	_DEFAULT_RETURN_UNFINISHED = __configs_from_file.get('_DEFAULT_RETURN_UNFINISHED', __build_in_default_config['_DEFAULT_RETURN_UNFINISHED'])
	_DEFAULT_UPDATE_UNREACHABLE_HOSTS = __configs_from_file.get('_DEFAULT_UPDATE_UNREACHABLE_HOSTS', __build_in_default_config['_DEFAULT_UPDATE_UNREACHABLE_HOSTS'])
	_DEFAULT_NO_START = __configs_from_file.get('_DEFAULT_NO_START', __build_in_default_config['_DEFAULT_NO_START'])

	# form the regex from the list
	__ERROR_MESSAGES_TO_IGNORE_REGEX = __configs_from_file.get('__ERROR_MESSAGES_TO_IGNORE_REGEX', __build_in_default_config['__ERROR_MESSAGES_TO_IGNORE_REGEX'])
	if __ERROR_MESSAGES_TO_IGNORE_REGEX:
		eprint('Using __ERROR_MESSAGES_TO_IGNORE_REGEX from config file, ignoring ERROR_MESSAGES_TO_IGNORE')
		__ERROR_MESSAGES_TO_IGNORE_REGEX = re.compile(__configs_from_file['__ERROR_MESSAGES_TO_IGNORE_REGEX'])
	else:
		__ERROR_MESSAGES_TO_IGNORE_REGEX =  re.compile('|'.join(ERROR_MESSAGES_TO_IGNORE))

	__DEBUG_MODE = __configs_from_file.get('__DEBUG_MODE', __build_in_default_config['__DEBUG_MODE'])

# Load mssh Functional Global Variables
if True:
	__global_suppress_printout = False
	__mainReturnCode = 0
	__failedHosts = set()
	__wildCharacters = ['*','?','x']
	_no_env = DEFAULT_NO_ENV
	_env_file = DEFAULT_ENV_FILE
	__globalUnavailableHosts = set()
	__ipmiiInterfaceIPPrefix = DEFAULT_IPMI_INTERFACE_IP_PREFIX
	__keyPressesIn = [[]]
	_emo = False
	_etc_hosts = __configs_from_file.get('_etc_hosts', __build_in_default_config['_etc_hosts'])
	__curses_global_color_pairs = {(-1,-1):1}
	__curses_current_color_pair_index = 2  # Start from 1, as 0 is the default color pair
	__curses_color_table = {}
	__curses_current_color_index = 10

# Mapping of ANSI 4-bit colors to curses colors
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
# ------------ Exportable Help Functions ----------------
# check if command sshpass is available
_binPaths = {}
def check_path(program_name):
	global __configs_from_file
	global __build_in_default_config
	global _binPaths
	config_key = f'_{program_name}Path'
	program_path = (
		__configs_from_file.get(config_key) or
		__build_in_default_config.get(config_key) or
		shutil.which(program_name)
	)
	if program_path:
		_binPaths[program_name] = program_path
		return True
	return False

[check_path(program) for program in ['sshpass', 'ssh', 'scp', 'ipmitool','rsync','sh','ssh-copy-id']]

def find_ssh_key_file(searchPath = DEDAULT_SSH_KEY_SEARCH_PATH):
	'''
	Find the ssh public key file

	Args:
		searchPath (str, optional): The path to search. Defaults to DEDAULT_SSH_KEY_SEARCH_PATH.

	Returns:
		str: The path to the ssh key file
	'''
	if searchPath:
		sshKeyPath = searchPath
	else:
		sshKeyPath ='~/.ssh'
	possibleSshKeyFiles = ['id_ed25519','id_ed25519_sk','id_ecdsa','id_ecdsa_sk','id_rsa','id_dsa']
	for sshKeyFile in possibleSshKeyFiles:
		if os.path.exists(os.path.expanduser(os.path.join(sshKeyPath,sshKeyFile))):
			return os.path.join(sshKeyPath,sshKeyFile)
	return None

@cache_decorator
def readEnvFromFile(environemnt_file = ''):
	'''
	Read the environment variables from env_file
	Returns:
		dict: A dictionary of environment variables
	'''
	global env
	try:
		if env:
			return env
	except:
		env = {}
	global _env_file
	if environemnt_file:
		envf = environemnt_file
	else:
		envf = _env_file if _env_file else DEFAULT_ENV_FILE
	if os.path.exists(envf):
		with open(envf,'r') as f:
			for line in f:
				if line.startswith('#') or not line.strip():
					continue
				key, value = line.replace('export ', '', 1).strip().split('=', 1)
				key = key.strip().strip('"').strip("'")
				value = value.strip().strip('"').strip("'")
				# avoid infinite recursion
				if key != value:
					env[key] = value.strip('"').strip("'")
	return env

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
			string = re.sub(re.escape(key),value,string,flags=re.IGNORECASE)
	return string

def pretty_format_table(data):
	version = 1.0
	if not data:
		return ''
	if type(data) == str:
		data = data.strip('\n').split('\n')
		data = [line.split('\t') for line in data]
	elif isinstance(data, dict):
		# flatten the 2D dict to a list of lists
		if isinstance(next(iter(data.values())), dict):
			tempData = [['key'] + list(next(iter(data.values())).keys())]
			tempData.extend( [[key] + list(value.values()) for key, value in data.items()])
			data = tempData
		else:
			# it is a dict of lists
			data = [[key] + list(value) for key, value in data.items()]
	elif type(data) != list:
		data = list(data)
	# format the list into 2d list of list of strings
	if isinstance(data[0], dict):
		tempData = [data[0].keys()]
		tempData.extend([list(item.values()) for item in data])
		data = tempData
	data = [[str(item) for item in row] for row in data]
	num_cols = len(data[0])
	col_widths = [0] * num_cols
	# Calculate the maximum width of each column
	for c in range(num_cols):
		col_widths[c] = max(len(row[c]) for row in data)
	# Build the row format string
	row_format = ' | '.join('{{:<{}}}'.format(width) for width in col_widths)
	# Print the header
	header = data[0]
	outTable = []
	outTable.append(row_format.format(*header))
	outTable.append('-+-'.join('-' * width for width in col_widths))
	for row in data[1:]:
		# if the row is empty, print an divider
		if not any(row):
			outTable.append('-+-'.join('-' * width for width in col_widths))
		else:
			outTable.append(row_format.format(*row))
	return '\n'.join(outTable) + '\n'

# ------------ Compacting Hostnames ----------------
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

def compact_hostnames(Hostnames):
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
	if not isinstance(Hostnames, frozenset):
		hostSet = frozenset(Hostnames)
	else:
		hostSet = Hostnames
	compact_hosts = __compact_hostnames(hostSet)
	if set(expand_hostnames(compact_hosts)) != set(expand_hostnames(hostSet)):
		if not __global_suppress_printout:
			eprint(f"Error compacting hostnames: {hostSet} -> {compact_hosts}")
		compact_hosts = hostSet
	return compact_hosts

# ------------ Expanding Hostnames ----------------
@cache_decorator
def __validate_expand_hostname(hostname):
	'''
	Validate the hostname and expand it if it is a range of IP addresses

	Args:
		hostname (str): The hostname to be validated and expanded

	Returns:
		list: A list of valid hostnames
	'''
	global _no_env
	# we will try to get the valid host name from the environment
	hostname = hostname.strip().strip('$')
	if getIP(hostname,local=True):
		return [hostname]
	elif not _no_env and hostname in os.environ:
		# we will expand these hostnames again
		return expand_hostnames(os.environ[hostname].split(','))
	elif hostname in readEnvFromFile():
		# we will expand these hostnames again
		return expand_hostnames(readEnvFromFile()[hostname].split(','))
	elif getIP(hostname,local=False):
		return [hostname]
	else:
		eprint(f"Error: {hostname!r} is not a valid hostname or IP address!")
		global __mainReturnCode
		__mainReturnCode += 1
		global __failedHosts
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
		if re.match(r'^((((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])}|x|\*|\?))?\]))(\.((((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?)(-((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?))?)|(\[((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?)(-((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?))?\]))){2}(\.(((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])}|x|\*|\?))?\]))$', host):
			hostSetToAdd = sorted(__expandIPv4Address(frozenset([host])),key=ipaddress.IPv4Address)
			iplist = hostSetToAdd
		else:
			hostSetToAdd = sorted(__expand_hostname(host))
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


# ------------ Run Command Block ----------------
def __handle_reading_stream(stream,target, host):
	'''
	Read the stream and append the lines to the target list

	Args:
		stream (io.BytesIO): The stream to be read
		target (list): The list to append the lines to
		host (Host): The host object

	Returns:
		None
	'''
	def add_line(current_line,target, host, keepLastLine=True):
		if not keepLastLine:
			target.pop()
			host.output.pop()
		current_line_str = current_line.decode('utf-8',errors='backslashreplace')
		target.append(current_line_str)
		host.output.append(current_line_str)
		host.lineNumToReprintSet.add(len(host.output)-1)
		host.lastUpdateTime = time.time()
	current_line = bytearray()
	lastLineCommited = True
	for char in iter(lambda:stream.read(1), b''):
		if char == b'\n':
			if (not lastLineCommited) and current_line:
				add_line(current_line,target, host, keepLastLine=False)
			elif lastLineCommited:
				add_line(current_line,target, host, keepLastLine=True)
			current_line = bytearray()
			lastLineCommited = True
		elif char == b'\r':
			add_line(current_line,target, host, keepLastLine=lastLineCommited)
			current_line = bytearray()
			lastLineCommited = False
		else:
			current_line.extend(char)
	if current_line:
		add_line(current_line,target, host, keepLastLine=lastLineCommited)

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
	# __keyPressesIn is a list of lists. 
	# Each list is a list of characters to be sent to the stdin of the process at once. 
	# We do not send the last line as it may be incomplete.
	sentInput = 0
	while not stop_event.is_set():
		if sentInput < len(__keyPressesIn) - 1 :
			stream.write(''.join(__keyPressesIn[sentInput]).encode())
			stream.flush()
			line = '> ' + ''.join(__keyPressesIn[sentInput]).encode().decode().replace('\n', '↵')
			host.output.append(line)
			host.stdout.append(line)
			sentInput += 1
			host.lastUpdateTime = time.time()
		else:
			time.sleep(0.1)
	if sentInput < len(__keyPressesIn) - 1 :
		eprint(f"Warning: {len(__keyPressesIn)-sentInput} key presses are not sent before the process is terminated!")
	# # send the last line
	# if __keyPressesIn and __keyPressesIn[-1]:
	#     stream.write(''.join(__keyPressesIn[-1]).encode())
	#     stream.flush()
	#     host.output.append(' $ ' + ''.join(__keyPressesIn[-1]).encode().decode().replace('\n', '↵'))
	#     host.stdout.append(' $ ' + ''.join(__keyPressesIn[-1]).encode().decode().replace('\n', '↵'))
	return sentInput
	
def run_command(host, sem, timeout=60,passwds=None):
	'''
	Run the command on the host. Will format the commands accordingly. Main execution function.

	Args:
		host (Host): The host object
		sem (threading.Semaphore): The semaphore to limit the number of concurrent SSH sessions
		timeout (int, optional): The timeout for the command. Defaults to 60.
		passwds (str, optional): The password for the host. Defaults to None.

	Returns:
		None
	'''
	global _emo
	global __ERROR_MESSAGES_TO_IGNORE_REGEX
	global __ipmiiInterfaceIPPrefix
	global _binPaths
	global __DEBUG_MODE
	try:
		localExtraArgs = []
		
		if not SSH_STRICT_HOST_KEY_CHECKING:
			localExtraArgs = ['-o StrictHostKeyChecking=no','-o UserKnownHostsFile=/dev/null']
		if host.identity_file:
			localExtraArgs += ['-i',host.identity_file]
		rsyncLocalExtraArgs = ['--rsh','ssh ' + ' '.join(localExtraArgs)]
		host.username = None
		host.address = host.name
		if '@' in host.name:
			host.username, host.address = host.name.rsplit('@',1)
		host.command = replace_magic_strings(host.command,['#HOST#','#HOSTNAME#'],host.address,case_sensitive=False)
		if host.username:
			host.command = replace_magic_strings(host.command,['#USER#','#USERNAME#'],host.username,case_sensitive=False)
		else:
			current_user = getpass.getuser()
			host.command = replace_magic_strings(host.command,['#USER#','#USERNAME#'],current_user,case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#ID#'],str(id(host)),case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#I#'],str(host.i),case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#PASSWD#','#PASSWORD#'],passwds,case_sensitive=False)
		host.command = replace_magic_strings(host.command,['#UUID#'],str(host.uuid),case_sensitive=False)
		formatedCMD = []
		if host.extraargs and type(host.extraargs) == str:
			extraargs = host.extraargs.split()
		elif host.extraargs and type(host.extraargs) == list:
			extraargs = [str(arg) for arg in host.extraargs]
		else:
			extraargs = []
		if __ipmiiInterfaceIPPrefix:
			host.interface_ip_prefix = __ipmiiInterfaceIPPrefix if host.ipmi and not host.interface_ip_prefix else host.interface_ip_prefix
		if host.interface_ip_prefix:
			try:
				hostOctets = host.ip.split('.')
				prefixOctets = host.interface_ip_prefix.split('.')
				host.address = '.'.join(prefixOctets[:3]+hostOctets[min(3,len(prefixOctets)):])
				host.resolvedName = host.username + '@' if host.username else ''
				host.resolvedName += host.address
			except:
				host.resolvedName = host.name
		else:
			host.resolvedName = host.name
		if host.resolvedName:
			host.command = replace_magic_strings(host.command,['#RESOLVEDNAME#','#RESOLVED#'],host.resolvedName,case_sensitive=False)
		if host.ipmi:
			if 'ipmitool' in _binPaths:
				if host.command.startswith('ipmitool '):
					host.command = host.command.replace('ipmitool ','')
				elif host.command.startswith(_binPaths['ipmitool']):
					host.command = host.command.replace(_binPaths['ipmitool'],'')
				if not host.username:
					host.username = 'admin'
				if not host.command:
					host.command = 'power status'
				if 'sh' in _binPaths:
					if passwds:
						formatedCMD = [_binPaths['sh'],'-c',f'ipmitool -H {host.address} -U {host.username} -P {passwds} {" ".join(extraargs)} {host.command}']
					else:
						host.output.append('Warning: Password not provided for ipmi! Using a default password `admin`.')
						formatedCMD = [_binPaths['sh'],'-c',f'ipmitool -H {host.address} -U {host.username} -P admin {" ".join(extraargs)} {host.command}']
				else:
					if passwds:
						formatedCMD = [_binPaths['ipmitool'],f'-H {host.address}',f'-U {host.username}',f'-P {passwds}'] + extraargs + [host.command]
					else:
						host.output.append('Warning: Password not provided for ipmi! Using a default password `admin`.')
						formatedCMD = [_binPaths['ipmitool'],f'-H {host.address}',f'-U {host.username}',f'-P admin'] + extraargs + [host.command]
			elif 'ssh' in _binPaths:
				host.output.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
				if __DEBUG_MODE:
					host.stderr.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
				host.ipmi = False
				host.interface_ip_prefix = None
				if not host.command:
					host.command = 'ipmitool power status'
				else:
					host.command = 'ipmitool '+host.command if not host.command.startswith('ipmitool ') else host.command
				run_command(host,sem,timeout,passwds)
				return
			else:
				host.output.append('Ipmitool not found on the local machine! Please install ipmitool to use ipmi mode.')
				host.stderr.append('Ipmitool not found on the local machine! Please install ipmitool to use ipmi mode.')
				host.returncode = 1
				return
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
				run_command(host,sem,timeout,passwds)
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
						return
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
					return
				if host.gatherMode:
					fileArgs = [f'{host.resolvedName}:{file}' for file in host.files] + [host.command]
				else:
					fileArgs = host.files + [f'{host.resolvedName}:{host.command}']
				if useScp:
					formatedCMD = [_binPaths['scp'],'-rpB'] + localExtraArgs + extraargs +['--']+fileArgs
				else:
					formatedCMD = [_binPaths['rsync'],'-ahlX','--partial','--inplace', '--info=name'] + rsyncLocalExtraArgs + extraargs +['--']+fileArgs	
			else:
				formatedCMD = [_binPaths['ssh']] + localExtraArgs + extraargs +['--']+ [host.resolvedName, host.command]
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
		return
	with sem:
		try:
			host.output.append('Running command: '+' '.join(formatedCMD))
			if __DEBUG_MODE:
				host.stderr.append('Running command: '+' '.join(formatedCMD))
			#host.stdout = []
			proc = subprocess.Popen(formatedCMD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
			# create a thread to handle stdout
			stdout_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stdout,host.stdout, host), daemon=True)
			stdout_thread.start()
			# create a thread to handle stderr
			#host.stderr = []
			stderr_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stderr,host.stderr, host), daemon=True)
			stderr_thread.start()
			# create a thread to handle stdin
			stdin_stop_event = threading.Event()
			stdin_thread = threading.Thread(target=__handle_writing_stream, args=(proc.stdin,stdin_stop_event, host), daemon=True)
			stdin_thread.start()
			# Monitor the subprocess and terminate it after the timeout
			host.lastUpdateTime = time.time()
			timeoutLineAppended = False
			while proc.poll() is None:  # while the process is still running
				if timeout > 0:
					if time.time() - host.lastUpdateTime > timeout:
						host.stderr.append('Timeout!')
						host.output.append('Timeout!')
						proc.send_signal(signal.SIGINT)
						time.sleep(0.1)

						proc.terminate()
						break
					elif time.time() - host.lastUpdateTime >  max(1, timeout // 2):
						timeoutLine = f'Timeout in [{timeout - int(time.time() - host.lastUpdateTime)}] seconds!'
						if host.output and not host.output[-1].strip().startswith(timeoutLine):
							# remove last line if it is a countdown
							if host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
								host.output.pop()
							host.output.append(timeoutLine)
							host.lineNumToReprintSet.add(len(host.output)-1)
							timeoutLineAppended = True
					elif host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
						host.output.pop()
						host.output.append('')
						host.lineNumToReprintSet.add(len(host.output)-1)
						timeoutLineAppended = False
				if _emo:
					host.stderr.append('Ctrl C detected, Emergency Stop!')
					host.output.append('Ctrl C detected, Emergency Stop!')
					proc.send_signal(signal.SIGINT)
					time.sleep(0.1)
					proc.terminate()
					break
				time.sleep(0.1)  # avoid busy-waiting
			stdin_stop_event.set()
			# Wait for output processing to complete
			stdout_thread.join(timeout=1)
			stderr_thread.join(timeout=1)
			stdin_thread.join(timeout=1)
			# here we handle the rest of the stdout after the subprocess returns
			host.output.append(f'Pipe Closed. Trying to read the rest of the stdout...')
			if not _emo:
				stdout = None
				stderr = None
				try:
					stdout, stderr = proc.communicate(timeout=1)
				except subprocess.TimeoutExpired:
					pass
				if stdout:
					__handle_reading_stream(io.BytesIO(stdout),host.stdout, host)
				if stderr:
					__handle_reading_stream(io.BytesIO(stderr),host.stderr, host)
				# if the last line in host.stderr is Connection to * closed., we will remove it
			host.returncode = proc.poll()
			if not host.returncode:
				# process been killed via timeout or sigkill
				if host.stderr and host.stderr[-1].strip().startswith('Timeout!'):
					host.returncode = 124
				elif host.stderr and host.stderr[-1].strip().startswith('Ctrl C detected, Emergency Stop!'):
					host.returncode = 137
			host.output.append(f'Command finished with return code {host.returncode}')
			if host.stderr:
				# filter out the error messages that we want to ignore
				host.stderr = [line for line in host.stderr if not __ERROR_MESSAGES_TO_IGNORE_REGEX.search(line)]
		except Exception as e:
			import traceback
			host.stderr.extend(str(e).split('\n'))
			host.output.extend(str(e).split('\n'))
			host.stderr.extend(traceback.format_exc().split('\n'))
			host.output.extend(traceback.format_exc().split('\n'))
			host.returncode = -1
	# If using ipmi, we will try again using ssh if ipmi connection is not successful
	if host.ipmi and host.returncode != 0 and any(['Unable to establish IPMI' in line for line in host.stderr]):
		host.stderr = []
		host.output.append('IPMI connection failed! Trying SSH connection...')
		if __DEBUG_MODE:
			host.stderr.append('IPMI connection failed! Trying SSH connection...')
		host.ipmi = False
		host.interface_ip_prefix = None
		host.command = 'ipmitool '+host.command if not host.command.startswith('ipmitool ') else host.command
		run_command(host,sem,timeout,passwds)
	# If transfering files, we will try again using scp if rsync connection is not successful
	if host.files and not host.scp and not useScp and host.returncode != 0 and host.stderr:
		host.stderr = []
		host.stdout = []
		host.output.append('Rsync connection failed! Trying SCP connection...')
		if __DEBUG_MODE:
			host.stderr.append('Rsync connection failed! Trying SCP connection...')
		host.scp = True
		run_command(host,sem,timeout,passwds)

# ------------ Start Threading Block ----------------
def start_run_on_hosts(hosts, timeout=60,password=None,max_connections=4 * os.cpu_count()):
	'''
	Start running the command on the hosts. Wrapper function for run_command

	Args:
		hosts (list): A list of Host objects
		timeout (int, optional): The timeout for the command. Defaults to 60.
		password (str, optional): The password for the hosts. Defaults to None.
		max_connections (int, optional): The maximum number of concurrent SSH sessions. Defaults to 4 * os.cpu_count().

	Returns:
		list: A list of threads that get started
	'''
	if len(hosts) == 0:
		return []
	sem = threading.Semaphore(max_connections)  # Limit concurrent SSH sessions
	threads = [threading.Thread(target=run_command, args=(host, sem,timeout,password), daemon=True) for host in hosts]
	for thread in threads:
		thread.start()
	return threads

# ------------ Display Block ----------------
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

def _curses_add_string_to_window(window, line = '', y = 0, x = 0, number_of_char_to_write = -1, color_pair_list = [-1,-1,1],fill_char=' ',parse_ansi_colors = True,centered = False,lead_str = '', trail_str = '',box_ansi_color = None, keep_top_n_lines = 0):
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
	
	Returns:
		None
	"""
	if window.getmaxyx()[0] == 0 or window.getmaxyx()[1] == 0 or x >= window.getmaxyx()[1]:
		return
	if x < 0:
		x = window.getmaxyx()[1] + x
	if number_of_char_to_write == -1:
		numChar = window.getmaxyx()[1] - x -1
	elif number_of_char_to_write == 0:
		return
	elif number_of_char_to_write + x > window.getmaxyx()[1]:
		numChar = window.getmaxyx()[1] - x -1
	else:
		numChar = number_of_char_to_write
	if numChar < 0:
		return
	if y < 0 or  y >= window.getmaxyx()[0]:
		if keep_top_n_lines > window.getmaxyx()[0] -1:
			keep_top_n_lines = window.getmaxyx()[0] -1
		if keep_top_n_lines < 0:
			keep_top_n_lines = 0
		window.move(keep_top_n_lines,0)
		window.deleteln()
		y = window.getmaxyx()[0] - 1
	line = line.replace('\n', ' ').replace('\r', ' ')
	if parse_ansi_colors:
		segments = re.split(r"(\x1b\[[\d;]*m)", line)  # Split line by ANSI escape codes
	else:
		segments = [line]
	charsWritten = 0
	boxAttr = __parse_ansi_escape_sequence_to_curses_attr(box_ansi_color)
	# first add the lead_str
	window.addnstr(y, x, lead_str, numChar, boxAttr)
	charsWritten = min(len(lead_str), numChar)
	# process centering
	if centered:
		fill_length = numChar - len(lead_str) - len(trail_str) - sum([len(segment) for segment in segments if not segment.startswith("\x1b[")])
		window.addnstr(y, x + charsWritten, fill_char * (fill_length // 2), numChar - charsWritten, boxAttr)
		charsWritten += min(fill_length // 2, numChar - charsWritten)
	# add the segments
	for segment in segments:
		if not segment:
			continue
		if parse_ansi_colors and segment.startswith("\x1b["):
			# Parse ANSI escape sequence
			newAttr = __parse_ansi_escape_sequence_to_curses_attr(segment,color_pair_list)
		else:
			# Add text with current color
			if charsWritten < numChar:
				window.addnstr(y, x + charsWritten, segment, numChar - charsWritten, color_pair_list[2])
				charsWritten += min(len(segment), numChar - charsWritten)
	# if we have finished printing segments but we still have space, we will fill it with fill_char
	if charsWritten + len(trail_str) < numChar:
		fillStr = fill_char * (numChar - charsWritten - len(trail_str))
		#fillStr = f'{color_pair_list}'
		window.addnstr(y, x + charsWritten, fillStr + trail_str, numChar - charsWritten, boxAttr)
		charsWritten += numChar - charsWritten
	else:
		window.addnstr(y, x + charsWritten, trail_str, numChar - charsWritten, boxAttr)

def _get_hosts_to_display (hosts, max_num_hosts, hosts_to_display = None):
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
	new_hosts_to_display = (running_hosts + failed_hosts + finished_hosts + waiting_hosts)[:max_num_hosts]
	if not hosts_to_display:
		return new_hosts_to_display , {'running':len(running_hosts), 'failed':len(failed_hosts), 'finished':len(finished_hosts), 'waiting':len(waiting_hosts)}
	# we will compare the new_hosts_to_display with the old one, if some hosts are not in their original position, we will change its printedLines to 0
	for i, host in enumerate(new_hosts_to_display):
		if host not in hosts_to_display:
			host.printedLines = 0
		elif i != hosts_to_display.index(host):
			host.printedLines = 0
	return new_hosts_to_display , {'running':len(running_hosts), 'failed':len(failed_hosts), 'finished':len(finished_hosts), 'waiting':len(waiting_hosts)}

def __generate_display(stdscr, hosts, lineToDisplay = -1,curserPosition = 0, min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,single_window=DEFAULT_SINGLE_WINDOW, config_reason= 'New Configuration'):
	try:
		box_ansi_color = None
		org_dim = stdscr.getmaxyx()
		new_configured = True
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
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Terminal too small')
		if min_char_len_local < 1 or min_line_len_local < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Minimum character or line length too small')
		# We need to figure out how many hosts we can fit in the terminal
		# We will need at least 2 lines per host, one for its name, one for its output
		# Each line will be at least 61 characters long (60 for the output, 1 for the borders)
		max_num_hosts_x = max_x // (min_char_len_local + 1)
		max_num_hosts_y = max_y // (min_line_len_local + 1)
		max_num_hosts = max_num_hosts_x * max_num_hosts_y
		if max_num_hosts < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Terminal too small to display any hosts')
		hosts_to_display , host_stats = _get_hosts_to_display(hosts, max_num_hosts)
		if len(hosts_to_display) == 0:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'No hosts to display')
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
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Host window too small')

		old_stat = ''
		old_bottom_stat = ''
		# we refresh the screen every 0.1 seconds
		last_refresh_time = time.perf_counter()
		stdscr.clear()
		#host_window.refresh()
		global __keyPressesIn
		stdscr.nodelay(True)
		# we generate a stats window at the top of the screen
		stat_window = curses.newwin(1, max_x, 0, 0)
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
			host_window = curses.newwin(host_window_height, host_window_width, y, x)
			host_window.idlok(True)
			host_window.scrollok(True)
			host_window.leaveok(True)
			host_windows.append(host_window)
		# If there is space left, we will draw the bottom border
		bottom_border = None
		if y + host_window_height  < org_dim[0]:
			bottom_border = curses.newwin(1, max_x, y + host_window_height, 0)
			bottom_border.leaveok(True)
			#bottom_border.clear()
			#bottom_border.addnstr(0, 0, '-' * (max_x - 1), max_x - 1)
			_curses_add_string_to_window(window=bottom_border, y=0, line='-' * (max_x - 1),fill_char='-',box_ansi_color=box_ansi_color)
			bottom_border.refresh()
		while host_stats['running'] > 0 or host_stats['waiting'] > 0:
			# Check for keypress
			key = stdscr.getch()
			if key != -1:  # -1 means no keypress
				# we store the keypresses in a list of lists.
				# Each list is a list of characters to be sent to the stdin of the process at once.
				# When we encounter a newline, we add a new list to the list of lists. ( a new line of input )
				# with open('keylog.txt','a') as f:
				#     f.write(str(key)+'\n')
				if key == 410: # 410 is the key code for resize
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Terminal resize requested')      
				elif key == 95 and not __keyPressesIn[-1]: # 95 is the key code for _
					# if last line is empty, we will reconfigure the wh to be smaller
					if min_line_len != 1:
						return (lineToDisplay,curserPosition , min_char_len , max(min_line_len -1,1), single_window, 'Decrease line length')
				elif key == 43 and not __keyPressesIn[-1]: # 43 is the key code for +
					# if last line is empty, we will reconfigure the wh to be larger
					return (lineToDisplay,curserPosition , min_char_len , min_line_len +1, single_window, 'Increase line length')
				elif key == 123 and not __keyPressesIn[-1]: # 123 is the key code for {
					# if last line is empty, we will reconfigure the ww to be smaller
					if min_char_len != 1:
						return (lineToDisplay,curserPosition , max(min_char_len -1,1), min_line_len, single_window, 'Decrease character length')
				elif key == 124 and not __keyPressesIn[-1]: # 124 is the key code for |
					# if last line is empty, we will toggle the single window mode
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, not single_window, 'Toggle single window mode')
				elif key == 125 and not __keyPressesIn[-1]: # 125 is the key code for }
					# if last line is empty, we will reconfigure the ww to be larger
					return (lineToDisplay,curserPosition , min_char_len +1, min_line_len, single_window, 'Increase character length')
				# We handle positional keys
				# if the key is up arrow, we will move the line to display up
				elif key == 259: # 259 is the key code for up arrow
					lineToDisplay = max(lineToDisplay - 1, -len(__keyPressesIn))
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
				return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Terminal resize detected')
			# We generate the aggregated stats if user did not input anything
			if not __keyPressesIn[lineToDisplay]:
				#stats = '┍'+ f" Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} "[:max_x - 2].center(max_x - 2, "━")
				stats = f"Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} "
			else:
				# we use the stat bar to display the key presses
				encodedLine = ''.join(__keyPressesIn[lineToDisplay]).encode().decode().strip('\n') + ' '
				#stats = '┍'+ f"Send CMD: {encodedLine}"[:max_x - 2].center(max_x - 2, "━")
				# format the stats line with chracter at curser position inverted using ansi escape sequence
				# displayCurserPosition is needed as the curserPosition can be larger than the length of the encodedLine. This is wanted to keep scrolling through the history less painful
				displayCurserPosition = min(curserPosition,len(encodedLine) -1)
				stats = f'Send CMD: {encodedLine[:displayCurserPosition]}\x1b[7m{encodedLine[displayCurserPosition]}\x1b[0m{encodedLine[displayCurserPosition + 1:]}'
			if stats != old_stat :
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
				if bottom_stats != old_bottom_stat:
					old_bottom_stat = bottom_stats
					#bottom_border.clear()
					#bottom_border.addnstr(0, 0, bottom_stats, max_x - 1)
					_curses_add_string_to_window(window=bottom_border, y=0, line=bottom_stats,fill_char='─',centered=True,lead_str='└',box_ansi_color=box_ansi_color)
					bottom_border.refresh()
			# set the maximum refresh rate to 100 Hz
			if time.perf_counter() - last_refresh_time < 0.01:
				time.sleep(max(0,0.01 - time.perf_counter() + last_refresh_time))
			#stdscr.clear()
			hosts_to_display, host_stats = _get_hosts_to_display(hosts, max_num_hosts,hosts_to_display)
			for host_window, host in zip(host_windows, hosts_to_display):
				# we will only update the window if there is new output or the window is not fully printed
				if new_configured or host.printedLines < len(host.output):
					try:
						if new_configured:
							host.printedLines = 0
						#host_window.clear()
						# we will try to center the name of the host with ┼ at the beginning and end and ─ in between
						#linePrintOut = f'┼{(host.name+":["+host.command+"]")[:host_window_width - 2].center(host_window_width - 1, "─")}'.replace('\n', ' ').replace('\r', ' ').strip()
						#linePrintOut = f'┼{(host.name+":["+host.command+"]")[:host_window_width - 2].center(host_window_width - 1, "─")}'.replace('\n', ' ').replace('\r', ' ').strip()
						#host_window.addnstr(0, 0, linePrintOut, host_window_width - 1)
						linePrintOut = f'{host.name}:[{host.command}]'.replace('\n', ' ').replace('\r', ' ').strip()
						_curses_add_string_to_window(window=host_window, y=0, line=linePrintOut, color_pair_list=[-1, -1, 1],centered=True,fill_char='─',lead_str='┼',box_ansi_color=box_ansi_color)
						#_add_line_with_ansi_colors(window=host_window, y=0, x=0, line=linePrintOut, n=host_window_width - 1, color_pair_list = host.current_color_pair)
						# we will display the latest outputs of the host as much as we can
						#for i, line in enumerate(host.output[-(host_window_height - 1):]):
							# print(f"Printng a line at {i + 1} with length of {len('│'+line[:host_window_width - 1])}")
							# time.sleep(10)
							#linePrintOut = ('│'+line[:host_window_width - 2].replace('\n', ' ').replace('\r', ' ')).strip()
							#host_window.addnstr(i + 1, 0, linePrintOut, host_window_width - 1)
							#_curses_add_string_to_window(window=host_window, y=i + 1, line=line, color_pair_list=host.current_color_pair,lead_str='│')
						# we draw the rest of the available lines
						# for i in range(len(host.output), host_window_height - 1):
						# 	# print(f"Printng a line at {i + 1} with length of {len('│')}")
						# 	host_window.addnstr(i + 1, 0, '│'.ljust(host_window_width - 1, ' '), host_window_width - 1)
						for i in range(host.printedLines, len(host.output)):
							_curses_add_string_to_window(window=host_window, y=i + 1, line=host.output[i], color_pair_list=host.current_color_pair,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
						for i in range(len(host.output), host_window_height - 1):
							_curses_add_string_to_window(window=host_window, y=i + 1,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
						host.printedLines = len(host.output)
						host_window.refresh()
					except Exception as e:
						# import traceback
						# print(str(e).strip())
						# print(traceback.format_exc().strip())
						if org_dim != stdscr.getmaxyx():
							return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, 'Terminal resize detected')
				if host.lineNumToReprintSet:
					# visible range is from host.printedLines - host_window_height + 1 to host.printedLines
					visibleLowerBound = host.printedLines - host_window_height + 1
					for lineNumToReprint in host.lineNumToReprintSet:
						# if the line is visible, we will reprint it
						if visibleLowerBound <= lineNumToReprint <= host.printedLines:
							if visibleLowerBound <= 0:
								# this means all lines are visible
								linePos = lineNumToReprint
							else:
								# calculate the position of the line to reprint
								linePos = lineNumToReprint - visibleLowerBound
							# Note: color can be incorrect if repainting an old line with new colors already initialized,
							# 	 Thus we will not use any presistent color pair for old lines
							cpl = host.current_color_pair if lineNumToReprint == host.printedLines else [-1,-1,1]
							_curses_add_string_to_window(window=host_window, y=linePos + 1, line=host.output[lineNumToReprint], color_pair_list=cpl,lead_str='│',keep_top_n_lines=1,box_ansi_color=box_ansi_color)
					host.lineNumToReprintSet = set()
					host_window.refresh()
			new_configured = False
			last_refresh_time = time.perf_counter()
	except Exception as e:
		import traceback
		return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window, f'Error: {str(e)}',traceback.format_exc())
	return None

def curses_print(stdscr, hosts, threads, min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,single_window = DEFAULT_SINGLE_WINDOW):
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
		_curses_add_string_to_window(window=stdscr, y=0, line='Initializing display...', n=stdscr.getmaxyx()[1] - 1)
		# print the size
		_curses_add_string_to_window(window=stdscr, y=1, line=f"Terminal size: {stdscr.getmaxyx()}", n=stdscr.getmaxyx()[1] - 1)
		# print the number of hosts
		_curses_add_string_to_window(window=stdscr, y=2, line=f"Number of hosts: {len(hosts)}", n=stdscr.getmaxyx()[1] - 1)
		# print the number of threads
		_curses_add_string_to_window(window=stdscr, y=3, line=f"Number of threads: {len(threads)}", n=stdscr.getmaxyx()[1] - 1)
		# print the minimum character length
		_curses_add_string_to_window(window=stdscr, y=4, line=f"Minimum character length: {min_char_len}", n=stdscr.getmaxyx()[1] - 1)
		# print the minimum line length
		_curses_add_string_to_window(window=stdscr, y=5, line=f"Minimum line length: {min_line_len}", n=stdscr.getmaxyx()[1] - 1)
		# print the single window mode
		_curses_add_string_to_window(window=stdscr, y=6, line=f"Single window mode: {single_window}", n=stdscr.getmaxyx()[1] - 1)
		# print COLORS and COLOR_PAIRS count
		_curses_add_string_to_window(window=stdscr, y=7, line=f"len(COLORS): {curses.COLORS} len(COLOR_PAIRS): {curses.COLOR_PAIRS}", n=stdscr.getmaxyx()[1] - 1)
		# print if can change color
		_curses_add_string_to_window(window=stdscr, y=8, line=f"Real color capability: {curses.can_change_color()}", n=stdscr.getmaxyx()[1] - 1)
		stdscr.refresh()
	except:
		pass
	params = (-1,0 , min_char_len, min_line_len, single_window,'new config')
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
			stdscr.addstr(0, 0, f"{params[5]}, Reloading Configuration: min_char_len={params[2]}, min_line_len={params[3]}, single_window={params[4]} with window size {stdscr.getmaxyx()} and {len(hosts)} hosts...")
			if len(params) > 6:
				# traceback is available, print it
				i = 1
				for line in params[6].split('\n'):
					stdscr.addstr(i, 0, line)
					i += 1
			stdscr.refresh()
		except:
			pass
		params = params[:5] + ('new config',)
		time.sleep(0.01)
		#time.sleep(0.25)

# ------------ Generate Output Block ----------------
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
	global __keyPressesIn
	global __global_suppress_printout
	hosts = [dict(host) for host in hosts]
	if usejson:
		# [print(dict(host)) for host in hosts]
		#print(json.dumps([dict(host) for host in hosts],indent=4))
		rtnStr = json.dumps(hosts,indent=4)
	elif greppable:
		# transform hosts to a 2d list
		rtnStr = '*'*80+'\n'
		rtnList = [['host_name','return_code','output_type','output']]
		for host in hosts:
			#header = f"{host['name']} | rc: {host['returncode']} | "
			for line in host['stdout']:
				rtnList.append([host['name'],f"rc: {host['returncode']}",'stdout',line])
			for line in host['stderr']:
				rtnList.append([host['name'],f"rc: {host['returncode']}",'stderr',line])
			rtnList.append(['','','',''])
		rtnStr += pretty_format_table(rtnList)
		rtnStr += '*'*80+'\n'
		if __keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode('unicode_escape').decode().replace('\\n', '↵') for cmd in __keyPressesIn if cmd]
			rtnStr += 'User Inputs: '+ '\nUser Inputs: '.join(CMDsOut)
			#rtnStr += '\n'
	else:
		outputs = {}
		for host in hosts:
			if __global_suppress_printout:
				if host['returncode'] == 0:
					continue
			hostPrintOut = f"  Command:\n    {host['command']}\n"
			hostPrintOut += "  stdout:\n    "+'\n    '.join(host['stdout'])
			if host['stderr']:
				if host['stderr'][0].strip().startswith('ssh: connect to host '):
					host['stderr'][0] = 'SSH not reachable!'
				elif host['stderr'][-1].strip().endswith('Connection timed out'):
					host['stderr'][-1] = 'SSH connection timed out!'
				elif host['stderr'][-1].strip().endswith('No route to host'):
					host['stderr'][-1] = 'Cannot find host!'
				hostPrintOut += "\n  stderr:\n  "+'\n    '.join(host['stderr'])
			hostPrintOut += f"\n  return_code: {host['returncode']}"
			outputs.setdefault(hostPrintOut, set()).add(host['name'])
		rtnStr = ''
		for output, hostSet in outputs.items():
			compact_hosts = sorted(compact_hostnames(hostSet))
			if __global_suppress_printout:
				rtnStr += f'Abnormal returncode produced by {",".join(compact_hosts)}:\n'
				rtnStr += output+'\n'
			else:
				rtnStr += '*'*80+'\n'
				rtnStr += f'These hosts: "{",".join(compact_hosts)}" have a response of:\n'
				rtnStr += output+'\n'
		if not __global_suppress_printout or outputs:
			rtnStr += '*'*80+'\n'
		if __keyPressesIn[-1]:
			CMDsOut = [''.join(cmd).encode('unicode_escape').decode().replace('\\n', '↵') for cmd in __keyPressesIn if cmd]
			#rtnStr += f"Key presses: {''.join(__keyPressesIn).encode('unicode_escape').decode()}\n"
			#rtnStr += f"Key presses: {__keyPressesIn}\n"
			rtnStr += "User Inputs: \n  "
			rtnStr += '\n  '.join(CMDsOut)
			rtnStr += '\n'
			__keyPressesIn = [[]]
		if __global_suppress_printout and not outputs:
			rtnStr += 'Success'
	if not quiet:
		print(rtnStr)
	return rtnStr

# ------------ Run / Process Hosts Block ----------------
def processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, curses_min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,single_window = DEFAULT_SINGLE_WINDOW):
	global __globalUnavailableHosts
	global _no_env
	threads = start_run_on_hosts(hosts, timeout=timeout,password=password,max_connections=max_connections)
	if __curses_available and not nowatch and threads and not returnUnfinished and any([thread.is_alive() for thread in threads]) and sys.stdout.isatty() and os.get_terminal_size() and os.get_terminal_size().columns > 10:
		curses.wrapper(curses_print, hosts, threads, min_char_len = curses_min_char_len, min_line_len = curses_min_line_len, single_window = single_window)
	if not returnUnfinished:
		# wait until all hosts have a return code
		while any([host.returncode is None for host in hosts]):
			time.sleep(0.1)
		for thread in threads:
			thread.join(timeout=3)
	# update the unavailable hosts and global unavailable hosts
	if willUpdateUnreachableHosts:
		unavailableHosts = set(unavailableHosts)
		unavailableHosts.update([host.name for host in hosts if host.stderr and ('No route to host' in host.stderr[0].strip() or (host.stderr[-1].strip().startswith('Timeout!') and host.returncode == 124))])
		# reachable hosts = all hosts - unreachable hosts
		reachableHosts = set([host.name for host in hosts]) - unavailableHosts
		if __DEBUG_MODE:
			print(f'Unreachable hosts: {unavailableHosts}')
		__globalUnavailableHosts.update(unavailableHosts)

		# os.environ['__multiSSH3_UNAVAILABLE_HOSTS'] = ','.join(unavailableHosts)
		# create a temporary file to store the unavailable hosts
		try:
			# check for the old content, only update if the new content is different
			if not os.path.exists(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv')):
				with open(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv'),'w') as f:
					f.write(f',{int(time.time())}\n'.join(unavailableHosts) + f',{int(time.time())}\n')
			else:
				oldDic = {}
				try:
					with open(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv'),'r') as f:
						for line in f:
							line = line.strip()
							if line and ',' in line and len(line.split(',')) >= 2 and line.split(',')[0] and line.split(',')[1].isdigit():
								oldDic[line.split(',')[0]] = int(line.split(',')[1])
				except:
					pass
				# remove entries that are either available now or older than min(timeout,3600) seconds
				for key in list(oldDic.keys()):
					if key in reachableHosts or time.time() - oldDic[key] > min(timeout,3600):
						del oldDic[key]
				# add new entries
				for host in unavailableHosts:
					oldDic[host] = int(time.time())
				with open(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv.new'),'w') as f:
					for key, value in oldDic.items():
						f.write(f'{key},{value}\n')
				os.replace(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv.new'),os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv'))
				
		except Exception as e:
			eprint(f'Error writing to temporary file: {e!r}')

	# print the output, if the output of multiple hosts are the same, we aggragate them
	if not called:
		print_output(hosts,json,greppable=greppable)

# ------------ Stringfy Block ----------------
@cache_decorator
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
	if type(host) is str:
		host = set(host.replace(',',' ').replace('\n',' ').replace('\r',' ').replace('\t',' ').replace(';', ' ').replace('|', ' ').replace('/', ' ').replace('&',' ').split())
	else:
		host = set(host)
	if 'local_shell' in host:
		host.remove('local_shell')
		host.add('localhost')
	host = ','.join(host)
	return host

@cache_decorator
def __formCommandArgStr(oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,
						 nowatch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,max_connections=DEFAULT_MAX_CONNECTIONS,
						 files = None,ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skipUnreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,skip_hosts = DEFAULT_SKIP_HOSTS,
						 file_sync = False, error_only = DEFAULT_ERROR_ONLY, identity_file = DEFAULT_IDENTITY_FILE,
						 copy_id = False,
						 shortend = False) -> str:
	argsList = []
	if oneonone: argsList.append('--oneonone' if not shortend else '-11')
	if timeout and timeout != DEFAULT_TIMEOUT: argsList.append(f'--timeout={timeout}' if not shortend else f'-t={timeout}')
	if password and password != DEFAULT_PASSWORD: argsList.append(f'--password="{password}"' if not shortend else f'-p="{password}"')
	if identity_file and identity_file != DEFAULT_IDENTITY_FILE: argsList.append(f'--key="{identity_file}"' if not shortend else f'-k="{identity_file}"')
	if copy_id: argsList.append('--copy_id' if not shortend else '-ci')
	if nowatch: argsList.append('--nowatch' if not shortend else '-q')
	if json: argsList.append('--json' if not shortend else '-j')
	if max_connections and max_connections != DEFAULT_MAX_CONNECTIONS: argsList.append(f'--max_connections={max_connections}' if not shortend else f'-m={max_connections}')
	if files: argsList.extend([f'--file="{file}"' for file in files] if not shortend else [f'-f="{file}"' for file in files])
	if ipmi: argsList.append('--ipmi')
	if interface_ip_prefix and interface_ip_prefix != DEFAULT_INTERFACE_IP_PREFIX: argsList.append(f'--interface_ip_prefix="{interface_ip_prefix}"' if not shortend else f'-pre="{interface_ip_prefix}"')
	if scp: argsList.append('--scp')
	if gather_mode: argsList.append('--gather_mode' if not shortend else '-gm')
	if username and username != DEFAULT_USERNAME: argsList.append(f'--username="{username}"' if not shortend else f'-u="{username}"')
	if extraargs and extraargs != DEFAULT_EXTRA_ARGS: argsList.append(f'--extraargs="{extraargs}"' if not shortend else f'-ea="{extraargs}"')
	if skipUnreachable: argsList.append('--skip_unreachable' if not shortend else '-su')
	if no_env: argsList.append('--no_env')
	if greppable: argsList.append('--greppable' if not shortend else '-g')
	if error_only: argsList.append('--error_only' if not shortend else '-eo')
	if skip_hosts and skip_hosts != DEFAULT_SKIP_HOSTS: argsList.append(f'--skip_hosts="{skip_hosts}"' if not shortend else f'-sh="{skip_hosts}"')
	if file_sync: argsList.append('--file_sync' if not shortend else '-fs')
	return ' '.join(argsList)

def getStrCommand(hosts = DEFAULT_HOSTS,commands = None,oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,
						 nowatch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = _DEFAULT_CALLED,max_connections=DEFAULT_MAX_CONNECTIONS,
						 files = None,ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,returnUnfinished = _DEFAULT_RETURN_UNFINISHED,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skipUnreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,willUpdateUnreachableHosts=_DEFAULT_UPDATE_UNREACHABLE_HOSTS,no_start=_DEFAULT_NO_START,
						 skip_hosts = DEFAULT_SKIP_HOSTS, curses_min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, curses_min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,
						 single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY, identity_file = DEFAULT_IDENTITY_FILE,
						 copy_id = False,
						 shortend = False):
	hosts = hosts if type(hosts) == str else frozenset(hosts)
	hostStr = formHostStr(hosts)
	files = frozenset(files) if files else None
	argsStr = __formCommandArgStr(oneonone = oneonone, timeout = timeout,password = password,
						 nowatch = nowatch,json = json,max_connections=max_connections,
						 files = files,ipmi = ipmi,interface_ip_prefix = interface_ip_prefix,scp=scp,gather_mode = gather_mode,
						 username=username,extraargs=extraargs,skipUnreachable=skipUnreachable,no_env=no_env,
						 greppable=greppable,skip_hosts = skip_hosts, file_sync = file_sync,error_only = error_only, identity_file = identity_file,
						 copy_id = copy_id,
						 shortend = shortend)
	commandStr = '"' + '" "'.join(commands) + '"' if commands else ''
	return f'multissh {argsStr} {hostStr} {commandStr}'

# ------------ Main Block ----------------
def run_command_on_hosts(hosts = DEFAULT_HOSTS,commands = None,oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,
						 nowatch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = _DEFAULT_CALLED,max_connections=DEFAULT_MAX_CONNECTIONS,
						 files = None,ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,returnUnfinished = _DEFAULT_RETURN_UNFINISHED,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skipUnreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,willUpdateUnreachableHosts=_DEFAULT_UPDATE_UNREACHABLE_HOSTS,no_start=_DEFAULT_NO_START,
						 skip_hosts = DEFAULT_SKIP_HOSTS, curses_min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, curses_min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,
						 single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY,quiet = False,identity_file = DEFAULT_IDENTITY_FILE,
						 copy_id = False):
	f'''
	Run the command on the hosts, aka multissh. main function

	Args:
		hosts (str/iterable): A string of hosts seperated by space or comma / iterable of hosts. Default to {DEFAULT_HOSTS}.
		commands (list): A list of commands to run on the hosts. When using files, defines the destination of the files. Defaults to None.
		oneonone (bool, optional): Whether to run the commands one on one. Defaults to {DEFAULT_ONE_ON_ONE}.
		timeout (int, optional): The timeout for the command. Defaults to {DEFAULT_TIMEOUT}.
		password (str, optional): The password for the hosts. Defaults to {DEFAULT_PASSWORD}.
		nowatch (bool, optional): Whether to print the output. Defaults to {DEFAULT_NO_WATCH}.
		json (bool, optional): Whether to print the output in JSON format. Defaults to {DEFAULT_JSON_MODE}.
		called (bool, optional): Whether the function is called by another function. Defaults to {_DEFAULT_CALLED}.
		max_connections (int, optional): The maximum number of concurrent SSH sessions. Defaults to 4 * os.cpu_count().
		files (list, optional): A list of files to be copied to the hosts. Defaults to None.
		ipmi (bool, optional): Whether to use IPMI to connect to the hosts. Defaults to {DEFAULT_IPMI}.
		interface_ip_prefix (str, optional): The prefix of the IPMI interface. Defaults to {DEFAULT_INTERFACE_IP_PREFIX}.
		returnUnfinished (bool, optional): Whether to return the unfinished hosts. Defaults to {_DEFAULT_RETURN_UNFINISHED}.
		scp (bool, optional): Whether to use scp instead of rsync. Defaults to {DEFAULT_SCP}.
		gather_mode (bool, optional): Whether to use gather mode. Defaults to False.
		username (str, optional): The username to use to connect to the hosts. Defaults to {DEFAULT_USERNAME}.
		extraargs (str, optional): Extra arguments to pass to the ssh / rsync / scp command. Defaults to {DEFAULT_EXTRA_ARGS}.
		skipUnreachable (bool, optional): Whether to skip unreachable hosts. Defaults to {DEFAULT_SKIP_UNREACHABLE}.
		no_env (bool, optional): Whether to not read the current sat system environment variables. (Will still read from files) Defaults to {DEFAULT_NO_ENV}.
		greppable (bool, optional): Whether to print the output in greppable format. Defaults to {DEFAULT_GREPPABLE_MODE}.
		willUpdateUnreachableHosts (bool, optional): Whether to update the global unavailable hosts. Defaults to {_DEFAULT_UPDATE_UNREACHABLE_HOSTS}.
		no_start (bool, optional): Whether to return the hosts without starting the command. Defaults to {_DEFAULT_NO_START}.
		skip_hosts (str, optional): The hosts to skip. Defaults to {DEFAULT_SKIP_HOSTS}.
		min_char_len (int, optional): The minimum character per line of the curses output. Defaults to {DEFAULT_CURSES_MINIMUM_CHAR_LEN}.
		min_line_len (int, optional): The minimum line number for each window of the curses output. Defaults to {DEFAULT_CURSES_MINIMUM_LINE_LEN}.
		single_window (bool, optional): Whether to use a single window for the curses output. Defaults to {DEFAULT_SINGLE_WINDOW}.
		file_sync (bool, optional): Whether to use file sync mode to sync directories. Defaults to {DEFAULT_FILE_SYNC}.
		error_only (bool, optional): Whether to only print the error output. Defaults to {DEFAULT_ERROR_ONLY}.
		quiet (bool, optional): Whether to suppress all verbose printout, added for compatibility, avoid using. Defaults to False.
		identity_file (str, optional): The identity file to use for the ssh connection. Defaults to {DEFAULT_IDENTITY_FILE}.
		copy_id (bool, optional): Whether to copy the id to the hosts. Defaults to False.

	Returns:
		list: A list of Host objects
	'''
	global __globalUnavailableHosts
	global __global_suppress_printout
	global _no_env
	global _emo
	global __DEBUG_MODE
	_emo = False
	_no_env = no_env
	if os.path.exists(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv')):
		if timeout <= 0:
			checkTime = DEFAULT_TIMEOUT
		else:
			checkTime = timeout
		if checkTime <= 0:
			checkTime = 60
		elif checkTime > 3600:
			checkTime = 3600
		try:
			readed = False
			if 0 < time.time() - os.path.getmtime(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv')) < checkTime:

				with open(os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv'),'r') as f:
					for line in f:
						line = line.strip()
						if line and ',' in line and len(line.split(',')) >= 2 and line.split(',')[0] and line.split(',')[1].isdigit():
							if int(line.split(',')[1]) > time.time() - checkTime:
								__globalUnavailableHosts.add(line.split(',')[0])
								readed = True
			if readed and not __global_suppress_printout:
				eprint(f"Read unavailable hosts from the file {os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv')}")
		except Exception as e:
			eprint(f"Warning: Unable to read the unavailable hosts from the file {os.path.join(tempfile.gettempdir(),'__multiSSH3_UNAVAILABLE_HOSTS.csv')!r}")
			eprint(str(e))
	elif '__multiSSH3_UNAVAILABLE_HOSTS' in readEnvFromFile():
		__globalUnavailableHosts.update(readEnvFromFile()['__multiSSH3_UNAVAILABLE_HOSTS'].split(','))
	if not max_connections:
		max_connections = 4 * os.cpu_count()
	elif max_connections == 0:
		max_connections = 1048576
	elif max_connections < 0:
		max_connections = (-max_connections) * os.cpu_count()
	if not commands:
		commands = []
	else:
		commands = [commands] if type(commands) == str else commands
		# reformat commands into a list of strings, join the iterables if they are not strings
		try:
			commands = [' '.join(command) if not type(command) == str else command for command in commands]
		except:
			pass
			eprint(f"Warning: commands should ideally be a list of strings. Now mssh had failed to convert {commands!r} to a list of strings. Continuing anyway but expect failures.")
	#verify_ssh_config()
	# load global unavailable hosts only if the function is called (so using --repeat will not load the unavailable hosts again)
	if called:
		# if called,
		# if skipUnreachable is not set, we default to skip unreachable hosts within one command call
		if skipUnreachable is None:
			skipUnreachable = True
		if skipUnreachable:
			unavailableHosts = __globalUnavailableHosts
		else:
			unavailableHosts = set()
	else:
		# if run in command line ( or emulating running in command line, we default to skip unreachable hosts within one command call )
		if skipUnreachable:
			unavailableHosts = __globalUnavailableHosts
		else:
			unavailableHosts = set()
			skipUnreachable = True
	if quiet:
		__global_suppress_printout = True
	# We create the hosts
	hostStr = formHostStr(hosts)
	skipHostStr = formHostStr(skip_hosts) if skip_hosts else ''

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
	skipHostSet = set(skipHostsDic).union(skipHostsDic.values())
	if skipHostSet:
		eprint(f"Skipping hosts: \"{' '.join(sorted(compact_hostnames(skipHostSet)))}\"")
	if copy_id:
		if 'ssh-copy-id' in _binPaths:
			# we will copy the id to the hosts
			hosts = []
			for host in targetHostDic:
				if host in skipHostSet or targetHostDic[host] in skipHostSet: continue
				command = f"{_binPaths['ssh-copy-id']} "
				if identity_file:
					command = f"{command}-i {identity_file} "
				if username:
					command =  f"{command} {username}@"
				command = f"{command}{host}"
				if password and 'sshpass' in _binPaths:
					command = f"{_binPaths['sshpass']} -p {password} {command}"
					hosts.append(Host(host, command,identity_file=identity_file,shell=True,ip = targetHostDic[host]))
				else:
					eprint(f"> {command}")
					os.system(command)
			if hosts:
				processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
		else:
			eprint(f"Warning: ssh-copy-id not found in {_binPaths} , skipping copy id to the hosts")
		if not commands:
			sys.exit(0)
	if files and not commands:
		# if files are specified but not target dir, we default to file sync mode
		file_sync = True
	if file_sync:
		# set the files to the union of files and commands
		files = set(files+commands) if files else set(commands)
	if files:
		# try to resolve files first (like * etc)
		if not gather_mode:
			pathSet = set()
			for file in files:
				try:
					pathSet.update(glob.glob(file,include_hidden=True,recursive=True))
				except:
					pathSet.update(glob.glob(file,recursive=True))
			if not pathSet:
				eprint(f'Warning: No source files at {files!r} are found after resolving globs!')
				sys.exit(66)
		else:
			pathSet = set(files)
		if file_sync:
			# use abosolute path for file sync
			commands = [os.path.abspath(file) for file in pathSet]
			files = []
		else:
			files = list(pathSet)
		if __DEBUG_MODE:
			eprint(f"Files: {files!r}")
	if oneonone:
		hosts = []
		if len(commands) != len(set(targetHostDic) - set(skipHostSet)):
			eprint("Error: the number of commands must be the same as the number of hosts")
			eprint(f"Number of commands: {len(commands)}")
			eprint(f"Number of hosts: {len(set(targetHostDic) - set(skipHostSet))}")
			sys.exit(255)
		if not __global_suppress_printout:
			eprint('-'*80)
			eprint("Running in one on one mode")
		for host, command in zip(targetHostDic, commands):
			if not ipmi and skipUnreachable and host in unavailableHosts:
				eprint(f"Skipping unavailable host: {host}")
				continue
			if host in skipHostSet or targetHostDic[host] in skipHostSet: continue
			if file_sync:
				hosts.append(Host(host, os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip = targetHostDic[host]))
			else:
				hosts.append(Host(host, command, files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host]))
			if not __global_suppress_printout: 
				eprint(f"Running command: {command!r} on host: {host!r}")
		if not __global_suppress_printout: eprint('-'*80)
		if not no_start: processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
		return hosts
	else:
		allHosts = []
		if not commands:
			# run in interactive mode ssh mode
			hosts = []
			for host in targetHostDic:
				if not ipmi and skipUnreachable and host in unavailableHosts:
					if not __global_suppress_printout: print(f"Skipping unavailable host: {host}")
					continue
				if host in skipHostSet or targetHostDic[host] in skipHostSet: continue
				# TODO: use ip to determine if we skip the host or not, also for unavailable hosts
				if file_sync:
					eprint(f"Error: file sync mode need to be specified with at least one path to sync.")
					return []
				elif files:
					eprint(f"Error: files need to be specified with at least one path to sync")
				else:
					hosts.append(Host(host, '', files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,identity_file=identity_file,ip=targetHostDic[host]))
			if not __global_suppress_printout:
				eprint('-'*80)
				eprint(f"Running in interactive mode on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if no_start:
				eprint(f"Warning: no_start is set, the command will not be started. As we are in interactive mode, no action will be done.")
			else:
				processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
			return hosts
		for command in commands:
			hosts = []
			for host in targetHostDic:
				if not ipmi and skipUnreachable and host in unavailableHosts:
					if not __global_suppress_printout: print(f"Skipping unavailable host: {host}")
					continue
				if host in skipHostSet or targetHostDic[host] in skipHostSet: continue
				if file_sync:
					hosts.append(Host(host, os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host]))
				else:
					hosts.append(Host(host, command, files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode,identity_file=identity_file,ip=targetHostDic[host]))
			if not __global_suppress_printout and len(commands) > 1:
				eprint('-'*80)
				eprint(f"Running command: {command} on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if not no_start: processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
			allHosts += hosts
		return allHosts

# ------------ Default Config Functions ----------------
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
		'DEFAULT_IDENTITY_FILE': args.key if args.key and not os.path.isdir(args.key) else DEFAULT_IDENTITY_FILE,
		'DEDAULT_SSH_KEY_SEARCH_PATH': args.key if args.key and os.path.isdir(args.key) else DEDAULT_SSH_KEY_SEARCH_PATH,
		'DEFAULT_USE_KEY': args.use_key,
		'DEFAULT_EXTRA_ARGS': args.extraargs,
		'DEFAULT_ONE_ON_ONE': args.oneonone,
		'DEFAULT_SCP': args.scp,
		'DEFAULT_FILE_SYNC': args.file_sync,
		'DEFAULT_TIMEOUT': DEFAULT_TIMEOUT,
		'DEFAULT_CLI_TIMEOUT': args.timeout,
		'DEFAULT_REPEAT': args.repeat,
		'DEFAULT_INTERVAL': args.interval,
		'DEFAULT_IPMI': args.ipmi,
		'DEFAULT_IPMI_INTERFACE_IP_PREFIX': args.ipmi_interface_ip_prefix,
		'DEFAULT_INTERFACE_IP_PREFIX': args.interface_ip_prefix,
		'DEFAULT_NO_WATCH': args.nowatch,
		'DEFAULT_CURSES_MINIMUM_CHAR_LEN': args.window_width,
		'DEFAULT_CURSES_MINIMUM_LINE_LEN': args.window_height,
		'DEFAULT_SINGLE_WINDOW': args.single_window,
		'DEFAULT_ERROR_ONLY': args.error_only,
		'DEFAULT_NO_OUTPUT': args.no_output,
		'DEFAULT_NO_ENV': args.no_env,
		'DEFAULT_ENV_FILE': args.env_file,
		'DEFAULT_MAX_CONNECTIONS': args.max_connections if args.max_connections != 4 * os.cpu_count() else None,
		'DEFAULT_JSON_MODE': args.json,
		'DEFAULT_PRINT_SUCCESS_HOSTS': args.success_hosts,
		'DEFAULT_GREPPABLE_MODE': args.greppable,
		'DEFAULT_SKIP_UNREACHABLE': args.skip_unreachable,
		'DEFAULT_SKIP_HOSTS': args.skip_hosts,
		'SSH_STRICT_HOST_KEY_CHECKING': SSH_STRICT_HOST_KEY_CHECKING,
		'ERROR_MESSAGES_TO_IGNORE': ERROR_MESSAGES_TO_IGNORE,
	}

def write_default_config(args,CONFIG_FILE,backup = True):
	if backup and os.path.exists(CONFIG_FILE):
		os.rename(CONFIG_FILE,CONFIG_FILE+'.bak')
	default_config = generate_default_config(args)
	# apply the updated defualt_config to __configs_from_file and write that to file
	__configs_from_file.update(default_config)
	with open(CONFIG_FILE,'w') as f:
		json.dump(__configs_from_file,f,indent=4)

# ------------ Wrapper Block ----------------
def main():
	global _emo
	global __global_suppress_printout
	global __mainReturnCode
	global __failedHosts
	global __ipmiiInterfaceIPPrefix
	global _binPaths
	global _env_file
	global __DEBUG_MODE
	_emo = False
	# We handle the signal
	signal.signal(signal.SIGINT, signal_handler)
	# We parse the arguments
	parser = argparse.ArgumentParser(description=f'Run a command on multiple hosts, Use #HOST# or #HOSTNAME# to replace the host name in the command. Config file: {CONFIG_FILE}')
	parser.add_argument('hosts', metavar='hosts', type=str, nargs='?', help=f'Hosts to run the command on, use "," to seperate hosts. (default: {DEFAULT_HOSTS})',default=DEFAULT_HOSTS)
	parser.add_argument('commands', metavar='commands', type=str, nargs='*',default=None,help='the command to run on the hosts / the destination of the files #HOST# or #HOSTNAME# will be replaced with the host name.')
	parser.add_argument('-u','--username', type=str,help=f'The general username to use to connect to the hosts. Will get overwrote by individual username@host if specified. (default: {DEFAULT_USERNAME})',default=DEFAULT_USERNAME)
	parser.add_argument('-p', '--password', type=str,help=f'The password to use to connect to the hosts, (default: {DEFAULT_PASSWORD})',default=DEFAULT_PASSWORD)
	parser.add_argument('-k','--key','--identity',nargs='?', type=str,help=f'The identity file to use to connect to the hosts. Implies --use_key. Specify a folder for program to search for a key. Use option without value to use {DEDAULT_SSH_KEY_SEARCH_PATH} (default: {DEFAULT_IDENTITY_FILE})',const=DEDAULT_SSH_KEY_SEARCH_PATH,default=DEFAULT_IDENTITY_FILE)
	parser.add_argument('-uk','--use_key', action='store_true', help=f'Attempt to use public key file to connect to the hosts. (default: {DEFAULT_USE_KEY})', default=DEFAULT_USE_KEY)
	parser.add_argument('-ea','--extraargs',type=str,help=f'Extra arguments to pass to the ssh / rsync / scp command. Put in one string for multiple arguments.Use "=" ! Ex. -ea="--delete" (default: {DEFAULT_EXTRA_ARGS})',default=DEFAULT_EXTRA_ARGS)
	parser.add_argument("-11",'--oneonone', action='store_true', help=f"Run one corresponding command on each host. (default: {DEFAULT_ONE_ON_ONE})", default=DEFAULT_ONE_ON_ONE)
	parser.add_argument("-f","--file", action='append', help="The file to be copied to the hosts. Use -f multiple times to copy multiple files")
	parser.add_argument('-fs','--file_sync', action='store_true', help=f'Operate in file sync mode, sync path in <COMMANDS> from this machine to <HOSTS>. Treat --file <FILE> and <COMMANDS> both as source as source and destination will be the same in this mode. (default: {DEFAULT_FILE_SYNC})', default=DEFAULT_FILE_SYNC)
	parser.add_argument('--scp', action='store_true', help=f'Use scp for copying files instead of rsync. Need to use this on windows. (default: {DEFAULT_SCP})', default=DEFAULT_SCP)
	parser.add_argument('-gm','--gather_mode', action='store_true', help=f'Gather files from the hosts instead of sending files to the hosts. Will send remote files specified in <FILE> to local path specified in <COMMANDS>  (default: False)', default=False)
	#parser.add_argument("-d",'-c',"--destination", type=str, help="The destination of the files. Same as specify with commands. Added for compatibility. Use #HOST# or #HOSTNAME# to replace the host name in the destination")
	parser.add_argument("-t","--timeout", type=int, help=f"Timeout for each command in seconds (default: {DEFAULT_CLI_TIMEOUT} (disabled))", default=DEFAULT_CLI_TIMEOUT)
	parser.add_argument("-r","--repeat", type=int, help=f"Repeat the command for a number of times (default: {DEFAULT_REPEAT})", default=DEFAULT_REPEAT)
	parser.add_argument("-i","--interval", type=int, help=f"Interval between repeats in seconds (default: {DEFAULT_INTERVAL})", default=DEFAULT_INTERVAL)
	parser.add_argument("--ipmi", action='store_true', help=f"Use ipmitool to run the command. (default: {DEFAULT_IPMI})", default=DEFAULT_IPMI)
	parser.add_argument("-mpre","--ipmi_interface_ip_prefix", type=str, help=f"The prefix of the IPMI interfaces (default: {DEFAULT_IPMI_INTERFACE_IP_PREFIX})", default=DEFAULT_IPMI_INTERFACE_IP_PREFIX)
	parser.add_argument("-pre","--interface_ip_prefix", type=str, help=f"The prefix of the for the interfaces (default: {DEFAULT_INTERFACE_IP_PREFIX})", default=DEFAULT_INTERFACE_IP_PREFIX)
	parser.add_argument("-q","-nw","--nowatch","--quiet", action='store_true', help=f"Quiet mode, no curses watch, only print the output. (default: {DEFAULT_NO_WATCH})", default=DEFAULT_NO_WATCH)
	parser.add_argument("-ww",'--window_width', type=int, help=f"The minimum character length of the curses window. (default: {DEFAULT_CURSES_MINIMUM_CHAR_LEN})", default=DEFAULT_CURSES_MINIMUM_CHAR_LEN)
	parser.add_argument("-wh",'--window_height', type=int, help=f"The minimum line height of the curses window. (default: {DEFAULT_CURSES_MINIMUM_LINE_LEN})", default=DEFAULT_CURSES_MINIMUM_LINE_LEN)
	parser.add_argument('-sw','--single_window', action='store_true', help=f'Use a single window for all hosts. (default: {DEFAULT_SINGLE_WINDOW})', default=DEFAULT_SINGLE_WINDOW)
	parser.add_argument('-eo','--error_only', action='store_true', help=f'Only print the error output. (default: {DEFAULT_ERROR_ONLY})', default=DEFAULT_ERROR_ONLY)
	parser.add_argument("-no","--no_output", action='store_true', help=f"Do not print the output. (default: {DEFAULT_NO_OUTPUT})", default=DEFAULT_NO_OUTPUT)
	parser.add_argument('--no_env', action='store_true', help=f'Do not load the command line environment variables. (default: {DEFAULT_NO_ENV})', default=DEFAULT_NO_ENV)
	parser.add_argument("--env_file", type=str, help=f"The file to load the mssh file based environment variables from. ( Still work with --no_env ) (default: {DEFAULT_ENV_FILE})", default=DEFAULT_ENV_FILE)
	parser.add_argument("-m","--max_connections", type=int, help=f"Max number of connections to use (default: 4 * cpu_count)", default=DEFAULT_MAX_CONNECTIONS)
	parser.add_argument("-j","--json", action='store_true', help=F"Output in json format. (default: {DEFAULT_JSON_MODE})", default=DEFAULT_JSON_MODE)
	parser.add_argument("--success_hosts", action='store_true', help=f"Output the hosts that succeeded in summary as wells. (default: {DEFAULT_PRINT_SUCCESS_HOSTS})", default=DEFAULT_PRINT_SUCCESS_HOSTS)
	parser.add_argument("-g","--greppable",'--table', action='store_true', help=f"Output in greppable format. (default: {DEFAULT_GREPPABLE_MODE})", default=DEFAULT_GREPPABLE_MODE)
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-su","--skip_unreachable", action='store_true', help=f"Skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {DEFAULT_SKIP_UNREACHABLE})", default=DEFAULT_SKIP_UNREACHABLE)
	group.add_argument("-nsu","--no_skip_unreachable",dest = 'skip_unreachable', action='store_false', help=f"Do not skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {not DEFAULT_SKIP_UNREACHABLE})", default=not DEFAULT_SKIP_UNREACHABLE)

	parser.add_argument("-sh","--skip_hosts", type=str, help=f"Skip the hosts in the list. (default: {DEFAULT_SKIP_HOSTS if DEFAULT_SKIP_HOSTS else 'None'})", default=DEFAULT_SKIP_HOSTS)
	parser.add_argument('--store_config_file', action='store_true', help=f'Store / generate the default config file from command line argument and current config at {CONFIG_FILE}')
	parser.add_argument('--debug', action='store_true', help='Print debug information')
	parser.add_argument('-ci','--copy_id', action='store_true', help='Copy the ssh id to the hosts')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	
	# parser.add_argument('-u', '--user', metavar='user', type=str, nargs=1,
	#                     help='the user to use to connect to the hosts')
	#args = parser.parse_args()

	# if python version is 3.7 or higher, use parse_intermixed_args
	try:
		args = parser.parse_intermixed_args()
	except Exception as e:
		#eprint(f"Error while parsing arguments: {e!r}")
		# try to parse the arguments using parse_known_args
		args, unknown = parser.parse_known_args()
		# if there are unknown arguments, we will try to parse them again using parse_args
		if unknown:
			eprint(f"Warning: Unknown arguments, treating all as commands: {unknown!r}")
			args.commands += unknown
			
			

	if args.store_config_file:
		try:
			if os.path.exists(CONFIG_FILE):
				eprint(f"Warning: {CONFIG_FILE!r} already exists, what to do? (o/b/n)")
				eprint(f"o:  Overwrite the file")
				eprint(f"b:  Rename the current config file at {CONFIG_FILE!r}.bak forcefully and write the new config file (default)")
				eprint(f"n:  Do nothing")
				inStr = input_with_timeout_and_countdown(10)
				if (not inStr) or inStr.lower().strip().startswith('b'):
					write_default_config(args,CONFIG_FILE,backup = True)
					eprint(f"Config file written to {CONFIG_FILE!r}")
				elif inStr.lower().strip().startswith('o'):
					write_default_config(args,CONFIG_FILE,backup = False)
					eprint(f"Config file written to {CONFIG_FILE!r}")
			else:
				write_default_config(args,CONFIG_FILE,backup = True)
				eprint(f"Config file written to {CONFIG_FILE!r}")
		except Exception as e:
			eprint(f"Error while writing config file: {e!r}")
			import traceback
			eprint(traceback.format_exc())
		if not args.commands:
			with open(CONFIG_FILE,'r') as f:
				eprint(f"Config file content: \n{f.read()}")
			sys.exit(0)

	_env_file = args.env_file
	__DEBUG_MODE = args.debug
	# if there are more than 1 commands, and every command only consists of one word,
	# we will ask the user to confirm if they want to run multiple commands or just one command.
	if not args.file and len(args.commands) > 1 and all([len(command.split()) == 1 for command in args.commands]):
		eprint(f"Multiple one word command detected, what to do? (1/m/n)")
		eprint(f"1:  Run 1 command [{' '.join(args.commands)}] on all hosts ( default )")
		eprint(f"m:  Run multiple commands [{', '.join(args.commands)}] on all hosts")
		eprint(f"n:  Exit")
		inStr = input_with_timeout_and_countdown(3)
		if (not inStr) or inStr.lower().strip().startswith('1'):
			args.commands = [" ".join(args.commands)]
			eprint(f"\nRunning 1 command: {args.commands[0]!r} on all hosts")
		elif inStr.lower().strip().startswith('m'):
			eprint(f"\nRunning multiple commands: {', '.join(args.commands)!r} on all hosts")
		else:
			sys.exit(0)

	if args.key or args.use_key:
		if not args.key:
			args.key = find_ssh_key_file()
		else:
			if os.path.isdir(os.path.expanduser(args.key)):
				args.key = find_ssh_key_file(args.key)
			elif not os.path.exists(args.key):
				eprint(f"Warning: Identity file {args.key!r} not found. Passing to ssh anyway. Proceed with caution.")

	__ipmiiInterfaceIPPrefix = args.ipmi_interface_ip_prefix

	if args.no_output:
		__global_suppress_printout = True

	if not __global_suppress_printout:
		cmdStr = getStrCommand(args.hosts,args.commands,oneonone=args.oneonone,timeout=args.timeout,password=args.password,
						 nowatch=args.nowatch,json=args.json,called=args.no_output,max_connections=args.max_connections,
						 files=args.file,file_sync=args.file_sync,ipmi=args.ipmi,interface_ip_prefix=args.interface_ip_prefix,scp=args.scp,gather_mode = args.gather_mode,username=args.username,
						 extraargs=args.extraargs,skipUnreachable=args.skip_unreachable,no_env=args.no_env,greppable=args.greppable,skip_hosts = args.skip_hosts,
						 curses_min_char_len = args.window_width, curses_min_line_len = args.window_height,single_window=args.single_window,error_only=args.error_only,identity_file=args.key,
						 copy_id=args.copy_id)
		eprint('> ' + cmdStr)
	if args.error_only:
		__global_suppress_printout = True

	for i in range(args.repeat):
		if args.interval > 0 and i < args.repeat - 1:
			eprint(f"Sleeping for {args.interval} seconds")
			time.sleep(args.interval)

		if not __global_suppress_printout: eprint(f"Running the {i+1}/{args.repeat} time") if args.repeat > 1 else None
		hosts = run_command_on_hosts(args.hosts,args.commands,
							 oneonone=args.oneonone,timeout=args.timeout,password=args.password,
							 nowatch=args.nowatch,json=args.json,called=args.no_output,max_connections=args.max_connections,
							 files=args.file,file_sync=args.file_sync,ipmi=args.ipmi,interface_ip_prefix=args.interface_ip_prefix,scp=args.scp,gather_mode = args.gather_mode,username=args.username,
							 extraargs=args.extraargs,skipUnreachable=args.skip_unreachable,no_env=args.no_env,greppable=args.greppable,skip_hosts = args.skip_hosts,
							 curses_min_char_len = args.window_width, curses_min_line_len = args.window_height,single_window=args.single_window,error_only=args.error_only,identity_file=args.key,
							 copy_id=args.copy_id)
		#print('*'*80)

		#if not __global_suppress_printout: eprint('-'*80)
	
	succeededHosts = set()
	for host in hosts:
		if host.returncode and host.returncode != 0:
			__mainReturnCode += 1
			__failedHosts.add(host.name)
		else:
			succeededHosts.add(host.name)
	succeededHosts -= __failedHosts
	# sort the failed hosts and succeeded hosts
	if __mainReturnCode > 0:
		if not __global_suppress_printout: 
			eprint(f'Complete. Failed hosts (Return Code not 0) count: {__mainReturnCode}')
			eprint(f'failed_hosts: {",".join(sorted(compact_hostnames(__failedHosts)))}')
	else:
		if not __global_suppress_printout: eprint('Complete. All hosts returned 0.')
	
	if args.success_hosts and not __global_suppress_printout:
		eprint(f'succeeded_hosts: {",".join(sorted(compact_hostnames(succeededHosts)))}')

	if threading.active_count() > 1:
		if not __global_suppress_printout: eprint(f'Remaining active thread: {threading.active_count()}')
		# os.system(f'pkill -ef  {os.path.basename(__file__)}')
		# os._exit(mainReturnCode)
	
	sys.exit(__mainReturnCode)

if __name__ == "__main__":
	main()
