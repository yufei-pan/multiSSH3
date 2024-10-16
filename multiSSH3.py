#!/usr/bin/env python3
import curses
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
version = '4.98'
VERSION = version

CONFIG_FILE = '/etc/multiSSH3.config.json'	

import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

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
		eprint(f"Error: Cannot load config file {config_file}")
		return {}
	return config

__configs_from_file = load_config_file(CONFIG_FILE)

__build_in_default_config = {
	'AUTHOR': 'Yufei Pan',
	'AUTHOR_EMAIL': 'pan@zopyr.us',
	'DEFAULT_HOSTS': 'all',
	'DEFAULT_USERNAME': None,
	'DEFAULT_PASSWORD': '',
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
	'DEFAULT_SKIP_UNREACHABLE': False,
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
	'_bashPath': None,
	'__ERROR_MESSAGES_TO_IGNORE_REGEX':None,
	'__DEBUG_MODE': False,
}

AUTHOR = __configs_from_file.get('AUTHOR', __build_in_default_config['AUTHOR'])
AUTHOR_EMAIL = __configs_from_file.get('AUTHOR_EMAIL', __build_in_default_config['AUTHOR_EMAIL'])

DEFAULT_HOSTS = __configs_from_file.get('DEFAULT_HOSTS', __build_in_default_config['DEFAULT_HOSTS'])
DEFAULT_ENV_FILE = __configs_from_file.get('DEFAULT_ENV_FILE', __build_in_default_config['DEFAULT_ENV_FILE'])
DEFAULT_USERNAME = __configs_from_file.get('DEFAULT_USERNAME', __build_in_default_config['DEFAULT_USERNAME'])
DEFAULT_PASSWORD = __configs_from_file.get('DEFAULT_PASSWORD', __build_in_default_config['DEFAULT_PASSWORD'])
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



__global_suppress_printout = True

__mainReturnCode = 0
__failedHosts = set()
__host_i_lock = threading.Lock()
__host_i_counter = -1
def get_i():
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
	
class Host:
	def __init__(self, name, command, files = None,ipmi = False,interface_ip_prefix = None,scp=False,extraargs=None,gatherMode=False):
		self.name = name # the name of the host (hostname or IP address)
		self.command = command # the command to run on the host
		self.returncode = None # the return code of the command
		self.output = [] # the output of the command for curses
		self.stdout = [] # the stdout of the command
		self.stderr = [] # the stderr of the command
		self.printedLines = -1 # the number of lines printed on the screen
		self.lastUpdateTime = time.time() # the last time the output was updated
		self.files = files # the files to be copied to the host
		self.ipmi = ipmi # whether to use ipmi to connect to the host
		self.interface_ip_prefix = interface_ip_prefix # the prefix of the ip address of the interface to be used to connect to the host
		self.scp = scp # whether to use scp to copy files to the host
		self.gatherMode = gatherMode # whether the host is in gather mode
		self.extraargs = extraargs # extra arguments to be passed to ssh
		self.resolvedName = None # the resolved IP address of the host
		# also store a globally unique integer i from 0
		self.i = get_i()
		self.uuid = uuid.uuid4()

	def __iter__(self):
		return zip(['name', 'command', 'returncode', 'stdout', 'stderr'], [self.name, self.command, self.returncode, self.stdout, self.stderr])
	def __repr__(self):
		# return the complete data structure
		return f"Host(name={self.name}, command={self.command}, returncode={self.returncode}, stdout={self.stdout}, stderr={self.stderr}, output={self.output}, printedLines={self.printedLines}, files={self.files}, ipmi={self.ipmi}, interface_ip_prefix={self.interface_ip_prefix}, scp={self.scp}, gatherMode={self.gatherMode}, extraargs={self.extraargs}, resolvedName={self.resolvedName}, i={self.i}, uuid={self.uuid})"
	def __str__(self):
		return f"Host(name={self.name}, command={self.command}, returncode={self.returncode}, stdout={self.stdout}, stderr={self.stderr})"

__wildCharacters = ['*','?','x']

_no_env = DEFAULT_NO_ENV

_env_file = DEFAULT_ENV_FILE

__globalUnavailableHosts = set()

__ipmiiInterfaceIPPrefix = DEFAULT_IPMI_INTERFACE_IP_PREFIX

__keyPressesIn = [[]]

_emo = False

_etc_hosts = __configs_from_file.get('_etc_hosts', __build_in_default_config['_etc_hosts'])


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

[check_path(program) for program in ['sshpass', 'ssh', 'scp', 'ipmitool','rsync','bash']]



@cache_decorator
def expandIPv4Address(hosts):
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
		host = host.replace('[','').replace(']','')
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
def getIP(hostname,local=False):
	'''
	Get the IP address of the hostname

	Args:
		hostname (str): The hostname

	Returns:
		str: The IP address of the hostname
	'''
	global _etc_hosts
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

@cache_decorator 
def expand_hostname(text,validate=True):
	'''
	Expand the hostname range in the text.
	Will search the string for a range ( [] encloused and non enclosed number ranges).
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
		match = re.search(r'\[(.*?-.*?)\]', hostname)
		if not match:
			expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
			continue
		try:
			range_start, range_end = match.group(1).split('-')
		except ValueError:
			expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
			continue
		range_start = range_start.strip()
		range_end = range_end.strip()
		if not range_end:
			if range_start.isdigit():
				range_end = '9'
			elif range_start.isalpha() and range_start.islower():
				range_end = 'z'
			elif range_start.isalpha() and range_start.isupper():
				range_end = 'Z'
			else:
				expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
				continue
		if not range_start:
			if range_end.isdigit():
				range_start = '0'
			elif range_end.isalpha() and range_end.islower():
				range_start = 'a'
			elif range_end.isalpha() and range_end.isupper():
				range_start = 'A'
			else:
				expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
				continue
		if range_start.isdigit() and range_end.isdigit():
			padding_length = min(len(range_start), len(range_end))
			format_str = "{:0" + str(padding_length) + "d}"
			for i in range(int(range_start), int(range_end) + 1):
				formatted_i = format_str.format(i)
				if '[' in hostname:
					expandinghosts.append(hostname.replace(match.group(0), formatted_i, 1))
				else:
					expandedhosts.update(validate_expand_hostname(hostname.replace(match.group(0), formatted_i, 1)) if validate else [hostname])
		else:
			if all(c in string.hexdigits for c in range_start + range_end):
				for i in range(int(range_start, 16), int(range_end, 16)+1):
					if '[' in hostname:
						expandinghosts.append(hostname.replace(match.group(0), format(i, 'x'), 1))
					else:
						expandedhosts.update(validate_expand_hostname(hostname.replace(match.group(0), format(i, 'x'), 1)) if validate else [hostname])
			else:
				try:
					start_index = alphanumeric.index(range_start)
					end_index = alphanumeric.index(range_end)
					for i in range(start_index, end_index + 1):
						if '[' in hostname:
							expandinghosts.append(hostname.replace(match.group(0), alphanumeric[i], 1))
						else:
							expandedhosts.update(validate_expand_hostname(hostname.replace(match.group(0), alphanumeric[i], 1)) if validate else [hostname])
				except ValueError:
					expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
	return expandedhosts

@cache_decorator
def expand_hostnames(hosts):
	'''
	Expand the hostnames in the hosts list

	Args:
		hosts (list): A list of hostnames

	Returns:
		list: A list of expanded hostnames
	'''
	expandedhosts = []
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
		# first we check if the hostname is an range of IP addresses
		# This is done by checking if the hostname follows four fields of 
		# "(((\d{1,3}|x|\*|\?)(-(\d{1,3}|x|\*|\?))?)|(\[(\d{1,3}|x|\*|\?)(-(\d{1,3}|x|\*|\?))?\]))" 
		# seperated by .
		# If so, we expand the IP address range
		if re.match(r'^((((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])}|x|\*|\?))?\]))(\.((((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?)(-((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?))?)|(\[((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?)(-((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|x|\*|\?))?\]))){2}(\.(((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?))?)|(\[((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])|x|\*|\?)(-((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])}|x|\*|\?))?\]))$', host):
			hostSetToAdd = sorted(expandIPv4Address(frozenset([host])),key=ipaddress.IPv4Address)
		else:
			hostSetToAdd = sorted(expand_hostname(host))
		if username:
			# we expand the username
			username = sorted(expand_hostname(username,validate=False))
			# we combine the username and hostname
			hostSetToAdd = [u+'@'+h for u,h in product(username,hostSetToAdd)]
		expandedhosts.extend(hostSetToAdd)
	return expandedhosts

@cache_decorator
def validate_expand_hostname(hostname):
	'''
	Validate the hostname and expand it if it is a range of IP addresses

	Args:
		hostname (str): The hostname to be validated and expanded

	Returns:
		list: A list of valid hostnames
	'''
	global _no_env
	# maybe it is just defined in ./target_files/hosts.sh and exported to the environment
	# we will try to get the valid host name from the environment
	hostname = hostname.strip('$')
	if getIP(hostname,local=True):
		return [hostname]
	elif not _no_env and hostname in os.environ:
		# we will expand these hostnames again
		return expand_hostnames(frozenset(os.environ[hostname].split(',')))
	elif hostname in readEnvFromFile():
		# we will expand these hostnames again
		return expand_hostnames(frozenset(readEnvFromFile()[hostname].split(',')))
	elif getIP(hostname,local=False):
		return [hostname]
	else:
		eprint(f"Error: {hostname} is not a valid hostname or IP address!")
		global __mainReturnCode
		__mainReturnCode += 1
		global __failedHosts
		__failedHosts.add(hostname)
		return []

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

def handle_reading_stream(stream,target, host):
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
			host.printedLines -= 1
		current_line_str = current_line.decode('utf-8',errors='backslashreplace')
		target.append(current_line_str)
		host.output.append(current_line_str)
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

def handle_writing_stream(stream,stop_event,host):
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
			host.output.append(' $ ' + ''.join(__keyPressesIn[sentInput]).encode().decode().replace('\n', '↵'))
			host.stdout.append(' $ ' + ''.join(__keyPressesIn[sentInput]).encode().decode().replace('\n', '↵'))
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

def ssh_command(host, sem, timeout=60,passwds=None):
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
		keyCheckArgs = []
		rsyncKeyCheckArgs = []
		if not SSH_STRICT_HOST_KEY_CHECKING:
			keyCheckArgs = ['-o StrictHostKeyChecking=no','-o UserKnownHostsFile=/dev/null']
			rsyncKeyCheckArgs = ['--rsh','ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null']
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
		if host.resolvedName:
			host.command = replace_magic_strings(host.command,['#RESOLVEDNAME#','#RESOLVED#'],host.resolvedName,case_sensitive=False)
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
				hostOctets = getIP(host.address,local=False).split('.')
				prefixOctets = host.interface_ip_prefix.split('.')
				host.address = '.'.join(prefixOctets[:3]+hostOctets[min(3,len(prefixOctets)):])
				host.resolvedName = host.username + '@' if host.username else ''
				host.resolvedName += host.address
			except:
				host.resolvedName = host.name
		else:
			host.resolvedName = host.name
		if host.ipmi:
			if 'ipmitool' in _binPaths:
				if host.command.startswith('ipmitool '):
					host.command = host.command.replace('ipmitool ','')
				elif host.command.startswith(_binPaths['ipmitool']):
					host.command = host.command.replace(_binPaths['ipmitool'],'')
				if not host.username:
					host.username = 'admin'
				if 'bash' in _binPaths:
					if passwds:
						formatedCMD = [_binPaths['bash'],'-c',f'ipmitool -H {host.address} -U {host.username} -P {passwds} {" ".join(extraargs)} {host.command}']
					else:
						formatedCMD = [_binPaths['bash'],'-c',f'ipmitool -H {host.address} -U {host.username} {" ".join(extraargs)} {host.command}']
				else:
					if passwds:
						formatedCMD = [_binPaths['ipmitool'],f'-H {host.address}',f'-U {host.username}',f'-P {passwds}'] + extraargs + [host.command]
					else:
						formatedCMD = [_binPaths['ipmitool'],f'-H {host.address}',f'-U {host.username}'] + extraargs + [host.command]
			elif 'ssh' in _binPaths:
				host.output.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
				if __DEBUG_MODE:
					host.stderr.append('Ipmitool not found on the local machine! Trying ipmitool on the remote machine...')
				host.ipmi = False
				host.interface_ip_prefix = None
				host.command = 'ipmitool '+host.command if not host.command.startswith('ipmitool ') else host.command
				ssh_command(host,sem,timeout,passwds)
				return
			else:
				host.output.append('Ipmitool not found on the local machine! Please install ipmitool to use ipmi mode.')
				host.stderr.append('Ipmitool not found on the local machine! Please install ipmitool to use ipmi mode.')
				host.returncode = 1
				return
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
					formatedCMD = [_binPaths['scp'],'-rpB'] + keyCheckArgs + extraargs +['--']+fileArgs
				else:
					formatedCMD = [_binPaths['rsync'],'-ahlX','--partial','--inplace', '--info=name'] + rsyncKeyCheckArgs + extraargs +['--']+fileArgs	
			else:
				formatedCMD = [_binPaths['ssh']] + keyCheckArgs + extraargs +['--']+ [host.resolvedName, host.command]
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
			stdout_thread = threading.Thread(target=handle_reading_stream, args=(proc.stdout,host.stdout, host), daemon=True)
			stdout_thread.start()
			# create a thread to handle stderr
			#host.stderr = []
			stderr_thread = threading.Thread(target=handle_reading_stream, args=(proc.stderr,host.stderr, host), daemon=True)
			stderr_thread.start()
			# create a thread to handle stdin
			stdin_stop_event = threading.Event()
			stdin_thread = threading.Thread(target=handle_writing_stream, args=(proc.stdin,stdin_stop_event, host), daemon=True)
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
					elif time.time() - host.lastUpdateTime >  min(30, timeout // 2):
						timeoutLine = f'Timeout in [{timeout - int(time.time() - host.lastUpdateTime)}] seconds!'
						if host.output and not host.output[-1].strip().startswith(timeoutLine):
							# remove last line if it is a countdown
							if host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
								host.output.pop()
								host.printedLines -= 1
							host.output.append(timeoutLine)
							timeoutLineAppended = True
					elif host.output and timeoutLineAppended and host.output[-1].strip().endswith('] seconds!') and host.output[-1].strip().startswith('Timeout in ['):
						host.output.pop()
						host.printedLines -= 1
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
					handle_reading_stream(io.BytesIO(stdout),host.stdout, host)
				if stderr:
					handle_reading_stream(io.BytesIO(stderr),host.stderr, host)
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
		ssh_command(host,sem,timeout,passwds)
	# If transfering files, we will try again using scp if rsync connection is not successful
	if host.files and not host.scp and not useScp and host.returncode != 0 and host.stderr:
		host.stderr = []
		host.stdout = []
		host.output.append('Rsync connection failed! Trying SCP connection...')
		if __DEBUG_MODE:
			host.stderr.append('Rsync connection failed! Trying SCP connection...')
		host.scp = True
		ssh_command(host,sem,timeout,passwds)

def start_run_on_hosts(hosts, timeout=60,password=None,max_connections=4 * os.cpu_count()):
	'''
	Start running the command on the hosts. Wrapper function for ssh_command

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
	threads = [threading.Thread(target=ssh_command, args=(host, sem,timeout,password), daemon=True) for host in hosts]
	for thread in threads:
		thread.start()
	return threads

def get_hosts_to_display (hosts, max_num_hosts, hosts_to_display = None):
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

def generate_display(stdscr, hosts, lineToDisplay = -1,curserPosition = 0, min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,single_window=DEFAULT_SINGLE_WINDOW):
	try:
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
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
		if min_char_len_local < 1 or min_line_len_local < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
		# We need to figure out how many hosts we can fit in the terminal
		# We will need at least 2 lines per host, one for its name, one for its output
		# Each line will be at least 61 characters long (60 for the output, 1 for the borders)
		max_num_hosts_x = max_x // (min_char_len_local + 1)
		max_num_hosts_y = max_y // (min_line_len_local + 1)
		max_num_hosts = max_num_hosts_x * max_num_hosts_y
		if max_num_hosts < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
		hosts_to_display , host_stats = get_hosts_to_display(hosts, max_num_hosts)
		if len(hosts_to_display) == 0:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
		# Now we calculate the actual number of hosts we will display for x and y
		optimal_len_x = max(min_char_len_local, 80)
		num_hosts_x = max(min(max_num_hosts_x, max_x // optimal_len_x),1)
		num_hosts_y = len(hosts_to_display) // num_hosts_x
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

		# We calculate the size of each window
		host_window_height = max_y // num_hosts_y
		host_window_width = max_x // num_hosts_x
		if host_window_height < 1 or host_window_width < 1:
			return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)

		old_stat = ''
		old_bottom_stat = ''
		old_cursor_position = -1
		# we refresh the screen every 0.1 seconds
		last_refresh_time = time.perf_counter()
		stdscr.clear()
		#host_window.refresh()
		global __keyPressesIn
		stdscr.nodelay(True)
		# we generate a stats window at the top of the screen
		stat_window = curses.newwin(1, max_x, 0, 0)
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
			host_windows.append(host_window)
		# If there is space left, we will draw the bottom border
		bottom_border = None
		if y + host_window_height  < org_dim[0]:
			bottom_border = curses.newwin(1, max_x, y + host_window_height, 0)
			#bottom_border.clear()
			bottom_border.addstr(0, 0, '-' * (max_x - 1))
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
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)         
				elif key == 95 and not __keyPressesIn[-1]: # 95 is the key code for _
					# if last line is empty, we will reconfigure the wh to be smaller
					if min_line_len != 1:
						return (lineToDisplay,curserPosition , min_char_len , max(min_line_len -1,1), single_window)
				elif key == 43 and not __keyPressesIn[-1]: # 43 is the key code for +
					# if last line is empty, we will reconfigure the wh to be larger
					return (lineToDisplay,curserPosition , min_char_len , min_line_len +1, single_window)
				elif key == 123 and not __keyPressesIn[-1]: # 123 is the key code for {
					# if last line is empty, we will reconfigure the ww to be smaller
					if min_char_len != 1:
						return (lineToDisplay,curserPosition , max(min_char_len -1,1), min_line_len, single_window)
				elif key == 124 and not __keyPressesIn[-1]: # 124 is the key code for |
					# if last line is empty, we will toggle the single window mode
					return (lineToDisplay,curserPosition , min_char_len, min_line_len, not single_window)
				elif key == 125 and not __keyPressesIn[-1]: # 125 is the key code for }
					# if last line is empty, we will reconfigure the ww to be larger
					return (lineToDisplay,curserPosition , min_char_len +1, min_line_len, single_window)
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
					# ignore delete key
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
				return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
			# We generate the aggregated stats if user did not input anything
			if not __keyPressesIn[lineToDisplay]:
				stats = '┍'+ f" Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']}  ww: {min_char_len} wh:{min_line_len} "[:max_x - 2].center(max_x - 2, "━")
			else:
				# we use the stat bar to display the key presses
				encodedLine = ''.join(__keyPressesIn[lineToDisplay]).encode().decode().strip('\n') + ' '
				# # add the flashing indicator at the curse position
				# if time.perf_counter() % 1 > 0.5:
				#     encodedLine = encodedLine[:curserPosition] + '█' + encodedLine[curserPosition:]
				# else:
				#     encodedLine = encodedLine[:curserPosition] + ' ' + encodedLine[curserPosition:]
				stats = '┍'+ f"Send CMD: {encodedLine}"[:max_x - 2].center(max_x - 2, "━")
			if bottom_border:
				bottom_stats = '└'+ f" Total: {len(hosts)} Running: {host_stats['running']} Failed: {host_stats['failed']} Finished: {host_stats['finished']} Waiting: {host_stats['waiting']} "[:max_x - 2].center(max_x - 2, "─")
				if bottom_stats != old_bottom_stat:
					old_bottom_stat = bottom_stats
					#bottom_border.clear()
					bottom_border.addstr(0, 0, bottom_stats)
					bottom_border.refresh()
			if stats != old_stat or curserPosition != old_cursor_position:
				old_stat = stats
				old_cursor_position = curserPosition
				# calculate the real curser position in stats as we centered the stats
				if 'Send CMD: ' in stats:
					curserPositionStats = min(min(curserPosition,len(encodedLine) -1) + stats.find('Send CMD: ')+len('Send CMD: '), max_x -2)
				else:
					curserPositionStats = max_x -2
				#stat_window.clear()
				#stat_window.addstr(0, 0, stats)
				# add the line with curser that inverses the color at the curser position
				stat_window.addstr(0, 0, stats[:curserPositionStats], curses.color_pair(1))
				stat_window.addstr(0, curserPositionStats, stats[curserPositionStats], curses.color_pair(2))
				stat_window.addstr(0, curserPositionStats + 1, stats[curserPositionStats + 1:], curses.color_pair(1))
				stat_window.refresh()
			# set the maximum refresh rate to 100 Hz
			if time.perf_counter() - last_refresh_time < 0.01:
				time.sleep(max(0,0.01 - time.perf_counter() + last_refresh_time))
			#stdscr.clear()
			hosts_to_display, host_stats = get_hosts_to_display(hosts, max_num_hosts,hosts_to_display)
			for host_window, host in zip(host_windows, hosts_to_display):
				# we will only update the window if there is new output or the window is not fully printed
				if new_configured or host.printedLines < len(host.output):
					try:
						#host_window.clear()
						# we will try to center the name of the host with ┼ at the beginning and end and ─ in between
						linePrintOut = f'┼{(host.name+":["+host.command+"]")[:host_window_width - 2].center(host_window_width - 1, "─")}'.replace('\n', ' ').replace('\r', ' ').strip()
						host_window.addstr(0, 0, linePrintOut)
						# we will display the latest outputs of the host as much as we can
						for i, line in enumerate(host.output[-(host_window_height - 1):]):
							# print(f"Printng a line at {i + 1} with length of {len('│'+line[:host_window_width - 1])}")
							# time.sleep(10)
							linePrintOut = ('│'+line[:host_window_width - 2].replace('\n', ' ').replace('\r', ' ')).strip().ljust(host_window_width - 1, ' ')
							host_window.addstr(i + 1, 0, linePrintOut)
						# we draw the rest of the available lines
						for i in range(len(host.output), host_window_height - 1):
							# print(f"Printng a line at {i + 1} with length of {len('│')}")
							host_window.addstr(i + 1, 0, '│'.ljust(host_window_width - 1, ' '))
						host.printedLines = len(host.output)
						host_window.refresh()
					except Exception as e:
						# import traceback
						# print(str(e).strip())
						# print(traceback.format_exc().strip())
						if org_dim != stdscr.getmaxyx():
							return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
			new_configured = False
			last_refresh_time = time.perf_counter()
	except Exception as e:
		return (lineToDisplay,curserPosition , min_char_len, min_line_len, single_window)
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
	curses.start_color()
	curses.curs_set(0)
	curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
	curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
	curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
	curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)
	curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK)
	curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)
	curses.init_pair(7, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
	curses.init_pair(8, curses.COLOR_CYAN, curses.COLOR_BLACK)
	curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_RED)
	curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_GREEN)
	curses.init_pair(11, curses.COLOR_WHITE, curses.COLOR_YELLOW)
	curses.init_pair(12, curses.COLOR_WHITE, curses.COLOR_BLUE)
	curses.init_pair(13, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
	curses.init_pair(14, curses.COLOR_WHITE, curses.COLOR_CYAN)
	curses.init_pair(15, curses.COLOR_BLACK, curses.COLOR_RED)
	curses.init_pair(16, curses.COLOR_BLACK, curses.COLOR_GREEN)
	curses.init_pair(17, curses.COLOR_BLACK, curses.COLOR_YELLOW)
	curses.init_pair(18, curses.COLOR_BLACK, curses.COLOR_BLUE)
	curses.init_pair(19, curses.COLOR_BLACK, curses.COLOR_MAGENTA)
	curses.init_pair(20, curses.COLOR_BLACK, curses.COLOR_CYAN)
	params = (-1,0 , min_char_len, min_line_len, single_window)
	while params:
		params = generate_display(stdscr, hosts, *params)
		if not params:
			break
		if not any([host.returncode is None for host in hosts]):
			# this means no hosts are running
			break
		# print the current configuration
		stdscr.clear()
		stdscr.addstr(0, 0, f"Loading Configuration: min_char_len={params[2]}, min_line_len={params[3]}, single_window={params[4]}")
		stdscr.refresh()
		#time.sleep(0.25)


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
		outputs = {}
		# transform hosts to dictionaries
		for host in hosts:
			hostPrintOut = f" | cmd: {host['command']} | stdout: "+'↵ '.join(host['stdout'])
			if host['stderr']:
				if host['stderr'][0].strip().startswith('ssh: connect to host '):
					host['stderr'][0] = 'SSH not reachable!'
				hostPrintOut += " | stderr: "+'↵ '.join(host['stderr'])
			hostPrintOut += f" | return_code: {host['returncode']}"
			if hostPrintOut not in outputs:
				outputs[hostPrintOut] = [host['name']]
			else:
				outputs[hostPrintOut].append(host['name'])
		rtnStr = ''
		for output, hosts in outputs.items():
			rtnStr += f"{','.join(hosts)}{output}\n"
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
				hostPrintOut += "\n  stderr:\n  "+'\n    '.join(host['stderr'])
			hostPrintOut += f"\n  return_code: {host['returncode']}"
			if hostPrintOut not in outputs:
				outputs[hostPrintOut] = [host['name']]
			else:
				outputs[hostPrintOut].append(host['name'])
		rtnStr = ''
		for output, hosts in outputs.items():
			if __global_suppress_printout:
				rtnStr += f'Abnormal returncode produced by {hosts}:\n'
				rtnStr += output+'\n'
			else:
				rtnStr += '*'*80+'\n'
				rtnStr += f"These hosts: {hosts} have a response of:\n"
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

# sshConfigged = False
# def verify_ssh_config():
# 	'''
# 	Verify that ~/.ssh/config exists and contains the line "StrictHostKeyChecking no"

# 	Args:
# 		None

# 	Returns:
# 		None
# 	'''
# 	global sshConfigged
# 	if not sshConfigged:
# 		# first we make sure ~/.ssh/config exists
# 		config = ''
# 		if not os.path.exists(os.path.expanduser('~/.ssh')):
# 			os.makedirs(os.path.expanduser('~/.ssh'))
# 		if os.path.exists(os.path.expanduser('~/.ssh/config')):
# 			with open(os.path.expanduser('~/.ssh/config'),'r') as f:
# 				config = f.read()
# 		if config:
# 			if 'StrictHostKeyChecking no' not in config:
# 				with open(os.path.expanduser('~/.ssh/config'),'a') as f:
# 					f.write('\nHost *\n\tStrictHostKeyChecking no\n')
# 		else:
# 			with open(os.path.expanduser('~/.ssh/config'),'w') as f:
# 				f.write('Host *\n\tStrictHostKeyChecking no\n')
# 		sshConfigged = True

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

def processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, curses_min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,single_window = DEFAULT_SINGLE_WINDOW):
	global __globalUnavailableHosts
	global _no_env
	threads = start_run_on_hosts(hosts, timeout=timeout,password=password,max_connections=max_connections)
	if not nowatch and threads and not returnUnfinished and any([thread.is_alive() for thread in threads]) and sys.stdout.isatty() and os.get_terminal_size() and os.get_terminal_size().columns > 10:
		curses.wrapper(curses_print, hosts, threads, min_char_len = curses_min_char_len, min_line_len = curses_min_line_len, single_window = single_window)
	if not returnUnfinished:
		# wait until all hosts have a return code
		while any([host.returncode is None for host in hosts]):
			time.sleep(0.1)
		for thread in threads:
			thread.join(timeout=3)
	# update the unavailable hosts and global unavailable hosts
	if willUpdateUnreachableHosts:
		unavailableHosts.update([host.name for host in hosts if host.stderr and ('No route to host' in host.stderr[0].strip() or host.stderr[0].strip().startswith('Timeout!'))])
		if __DEBUG_MODE:
			print(f'Unreachable hosts: {unavailableHosts}')
		__globalUnavailableHosts.update(unavailableHosts)
		# update the os environment variable if not _no_env
		if not _no_env:
			os.environ['__multiSSH3_UNAVAILABLE_HOSTS'] = ','.join(unavailableHosts)

	# print the output, if the output of multiple hosts are the same, we aggragate them
	if not called:
		print_output(hosts,json,greppable=greppable)

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
						 file_sync = False, error_only = DEFAULT_ERROR_ONLY,
						 shortend = False) -> str:
	argsList = []
	if oneonone: argsList.append('--oneonone' if not shortend else '-11')
	if timeout and timeout != DEFAULT_TIMEOUT: argsList.append(f'--timeout={timeout}' if not shortend else f'-t={timeout}')
	if password and password != DEFAULT_PASSWORD: argsList.append(f'--password="{password}"' if not shortend else f'-p="{password}"')
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
	if skipUnreachable: argsList.append('--skipUnreachable' if not shortend else '-su')
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
						 single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY,
						 shortend = False):
	hosts = hosts if type(hosts) == str else frozenset(hosts)
	hostStr = formHostStr(hosts)
	files = frozenset(files) if files else None
	argsStr = __formCommandArgStr(oneonone = oneonone, timeout = timeout,password = password,
						 nowatch = nowatch,json = json,max_connections=max_connections,
						 files = files,ipmi = ipmi,interface_ip_prefix = interface_ip_prefix,scp=scp,gather_mode = gather_mode,
						 username=username,extraargs=extraargs,skipUnreachable=skipUnreachable,no_env=no_env,
						 greppable=greppable,skip_hosts = skip_hosts, file_sync = file_sync,error_only = error_only, shortend = shortend)
	commandStr = '"' + '" "'.join(commands) + '"' if commands else ''
	return f'multissh {argsStr} {hostStr} {commandStr}'

def run_command_on_hosts(hosts = DEFAULT_HOSTS,commands = None,oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,
						 nowatch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = _DEFAULT_CALLED,max_connections=DEFAULT_MAX_CONNECTIONS,
						 files = None,ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,returnUnfinished = _DEFAULT_RETURN_UNFINISHED,
						 scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skipUnreachable=DEFAULT_SKIP_UNREACHABLE,
						 no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,willUpdateUnreachableHosts=_DEFAULT_UPDATE_UNREACHABLE_HOSTS,no_start=_DEFAULT_NO_START,
						 skip_hosts = DEFAULT_SKIP_HOSTS, curses_min_char_len = DEFAULT_CURSES_MINIMUM_CHAR_LEN, curses_min_line_len = DEFAULT_CURSES_MINIMUM_LINE_LEN,
						 single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY,quiet = False):
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
	if not no_env and '__multiSSH3_UNAVAILABLE_HOSTS' in os.environ:
		__globalUnavailableHosts = set(os.environ['__multiSSH3_UNAVAILABLE_HOSTS'].split(','))
	elif '__multiSSH3_UNAVAILABLE_HOSTS' in readEnvFromFile():
		__globalUnavailableHosts = set(readEnvFromFile()['__multiSSH3_UNAVAILABLE_HOSTS'].split(','))
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
			eprint(f"Warning: commands should ideally be a list of strings. Now mssh had failed to convert {commands} to a list of strings. Continuing anyway but expect failures.")
	#verify_ssh_config()
	# load global unavailable hosts only if the function is called (so using --repeat will not load the unavailable hosts again)
	if called:
		# if called,
		# if skipUnreachable is not set, we default to skip unreachable hosts within one command call
		__global_suppress_printout = True
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
	targetHostsList = expand_hostnames(frozenset(hostStr.split(',')))
	if __DEBUG_MODE:
		eprint(f"Target hosts: {targetHostsList}")
	skipHostsList = expand_hostnames(frozenset(skipHostStr.split(',')))
	if skipHostsList:
		eprint(f"Skipping hosts: {skipHostsList}")
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
				eprint(f'Warning: No source files at {files} are found after resolving globs!')
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
			eprint(f"Files: {files}")
	if oneonone:
		hosts = []
		if len(commands) != len(targetHostsList) - len(skipHostsList):
			eprint("Error: the number of commands must be the same as the number of hosts")
			eprint(f"Number of commands: {len(commands)}")
			eprint(f"Number of hosts: {len(targetHostsList - skipHostsList)}")
			sys.exit(255)
		if not __global_suppress_printout:
			eprint('-'*80)
			eprint("Running in one on one mode")
		for host, command in zip(targetHostsList, commands):
			if not ipmi and skipUnreachable and host.strip() in unavailableHosts:
				eprint(f"Skipping unavailable host: {host}")
				continue
			if host.strip() in skipHostsList: continue
			if file_sync:
				hosts.append(Host(host.strip(), os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode))
			else:
				hosts.append(Host(host.strip(), command, files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode))
			if not __global_suppress_printout: 
				eprint(f"Running command: {command} on host: {host}")
		if not __global_suppress_printout: print('-'*80)
		if not no_start: processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
		return hosts
	else:
		allHosts = []
		if not commands:
			# run in interactive mode ssh mode
			hosts = []
			for host in targetHostsList:
				if not ipmi and skipUnreachable and host.strip() in unavailableHosts:
					if not __global_suppress_printout: print(f"Skipping unavailable host: {host}")
					continue
				if host.strip() in skipHostsList: continue
				if file_sync:
					eprint(f"Error: file sync mode need to be specified with at least one path to sync.")
					return []
				elif files:
					eprint(f"Error: files need to be specified with at least one path to sync")
				elif ipmi:
					eprint(f"Error: ipmi mode is not supported in interactive mode")
				else:
					hosts.append(Host(host.strip(), '', files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs))
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
			for host in targetHostsList:
				if not ipmi and skipUnreachable and host.strip() in unavailableHosts:
					if not __global_suppress_printout: print(f"Skipping unavailable host: {host}")
					continue
				if host.strip() in skipHostsList: continue
				if file_sync:
					hosts.append(Host(host.strip(), os.path.dirname(command)+os.path.sep, files = [command],ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode))
				else:
					hosts.append(Host(host.strip(), command, files = files,ipmi=ipmi,interface_ip_prefix=interface_ip_prefix,scp=scp,extraargs=extraargs,gatherMode=gather_mode))
			if not __global_suppress_printout and len(commands) > 1:
				eprint('-'*80)
				eprint(f"Running command: {command} on hosts: {hostStr}" + (f"; skipping: {skipHostStr}" if skipHostStr else ''))
				eprint('-'*80)
			if not no_start: processRunOnHosts(timeout, password, max_connections, hosts, returnUnfinished, nowatch, json, called, greppable,unavailableHosts,willUpdateUnreachableHosts,curses_min_char_len = curses_min_char_len, curses_min_line_len = curses_min_line_len,single_window=single_window)
			allHosts += hosts
		return allHosts

def get_default_config(args):
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
	default_config = get_default_config(args)
	# apply the updated defualt_config to __configs_from_file and write that to file
	__configs_from_file.update(default_config)
	with open(CONFIG_FILE,'w') as f:
		json.dump(__configs_from_file,f,indent=4)


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
	parser.add_argument("-g","--greppable", action='store_true', help=f"Output in greppable format. (default: {DEFAULT_GREPPABLE_MODE})", default=DEFAULT_GREPPABLE_MODE)
	parser.add_argument("-su","--skip_unreachable", action='store_true', help=f"Skip unreachable hosts while using --repeat. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: {DEFAULT_SKIP_UNREACHABLE})", default=DEFAULT_SKIP_UNREACHABLE)
	parser.add_argument("-sh","--skip_hosts", type=str, help=f"Skip the hosts in the list. (default: {DEFAULT_SKIP_HOSTS if DEFAULT_SKIP_HOSTS else 'None'})", default=DEFAULT_SKIP_HOSTS)
	parser.add_argument('--store_config_file', action='store_true', help=f'Store / generate the default config file from command line argument and current config at {CONFIG_FILE}')
	parser.add_argument('--debug', action='store_true', help='Print debug information')
	parser.add_argument('--copy-id', action='store_true', help='Copy the ssh id to the hosts')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	
	# parser.add_argument('-u', '--user', metavar='user', type=str, nargs=1,
	#                     help='the user to use to connect to the hosts')
	#args = parser.parse_args()

	# if python version is 3.7 or higher, use parse_intermixed_args
	if sys.version_info >= (3,7):
		args = parser.parse_intermixed_args()
	else:
		# try to parse the arguments using parse_known_args
		args, unknown = parser.parse_known_args()
		# if there are unknown arguments, we will try to parse them again using parse_args
		if unknown:
			eprint(f"Warning: Unknown arguments, treating all as commands: {unknown}")
			args.commands += unknown
			
			

	if args.store_config_file:
		try:
			if os.path.exists(CONFIG_FILE):
				eprint(f"Warning: {CONFIG_FILE} already exists, what to do? (o/b/n)")
				eprint(f"o:  Overwrite the file")
				eprint(f"b:  Rename the current config file at {CONFIG_FILE}.bak forcefully and write the new config file (default)")
				eprint(f"n:  Do nothing")
				inStr = input_with_timeout_and_countdown(10)
				if (not inStr) or inStr.lower().strip().startswith('b'):
					write_default_config(args,CONFIG_FILE,backup = True)
					eprint(f"Config file written to {CONFIG_FILE}")
				elif inStr.lower().strip().startswith('o'):
					write_default_config(args,CONFIG_FILE,backup = False)
					eprint(f"Config file written to {CONFIG_FILE}")
			else:
				write_default_config(args,CONFIG_FILE,backup = True)
				eprint(f"Config file written to {CONFIG_FILE}")
		except Exception as e:
			eprint(f"Error while writing config file: {e}")
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
			eprint(f"\nRunning 1 command: {args.commands[0]} on all hosts")
		elif inStr.lower().strip().startswith('m'):
			eprint(f"\nRunning multiple commands: {', '.join(args.commands)} on all hosts")
		else:
			sys.exit(0)
	
	__ipmiiInterfaceIPPrefix = args.ipmi_interface_ip_prefix

	if not args.greppable and not args.json and not args.no_output:
		__global_suppress_printout = False

	if not __global_suppress_printout:
		eprint('> ' + getStrCommand(args.hosts,args.commands,oneonone=args.oneonone,timeout=args.timeout,password=args.password,
						 nowatch=args.nowatch,json=args.json,called=args.no_output,max_connections=args.max_connections,
						 files=args.file,file_sync=args.file_sync,ipmi=args.ipmi,interface_ip_prefix=args.interface_ip_prefix,scp=args.scp,gather_mode = args.gather_mode,username=args.username,
						 extraargs=args.extraargs,skipUnreachable=args.skip_unreachable,no_env=args.no_env,greppable=args.greppable,skip_hosts = args.skip_hosts,
						 curses_min_char_len = args.window_width, curses_min_line_len = args.window_height,single_window=args.single_window,error_only=args.error_only))
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
							 curses_min_char_len = args.window_width, curses_min_line_len = args.window_height,single_window=args.single_window,error_only=args.error_only)
		#print('*'*80)

		if not __global_suppress_printout: eprint('-'*80)
	
	succeededHosts = set()
	for host in hosts:
		if host.returncode and host.returncode != 0:
			__mainReturnCode += 1
			__failedHosts.add(host.name)
		else:
			succeededHosts.add(host.name)
	succeededHosts -= __failedHosts
	# sort the failed hosts and succeeded hosts
	__failedHosts = sorted(__failedHosts)
	succeededHosts = sorted(succeededHosts)
	if __mainReturnCode > 0:
		if not __global_suppress_printout: eprint(f'Complete. Failed hosts (Return Code not 0) count: {__mainReturnCode}')
		# with open('/tmp/bashcmd.stdin','w') as f:
		#     f.write(f"export failed_hosts={__failedHosts}\n")
		if not __global_suppress_printout: eprint(f'failed_hosts: {",".join(__failedHosts)}')
	else:
		if not __global_suppress_printout: eprint('Complete. All hosts returned 0.')
	
	if args.success_hosts and not __global_suppress_printout:
		eprint(f'succeeded_hosts: {",".join(succeededHosts)}')

	if threading.active_count() > 1:
		if not __global_suppress_printout: eprint(f'Remaining active thread: {threading.active_count()}')
		# os.system(f'pkill -ef  {os.path.basename(__file__)}')
		# os._exit(mainReturnCode)
	
	sys.exit(__mainReturnCode)

if __name__ == "__main__":
	main()
