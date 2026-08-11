import re
import string

def validate_expand_hostname(hostname):
	# Assuming this function is already implemented.
	return [hostname]


def old_expand_hostname(text,validate=True):
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

def expand_hostname(text, validate=True):
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
			expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
			continue
		group = match.group(1)
		parts = group.split(',')
		for part in parts:
			part = part.strip()
			if '-' in part:
				try:
					range_start,_, range_end = part.partition('-')
				except ValueError:
					expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
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
						expandedhosts.update(validate_expand_hostname(hostname) if validate else [hostname])
			else:
				expandinghosts.append(hostname.replace(match.group(0), part, 1))
	return expandedhosts

# Example usage
# text = "test[2-1c]"
# print(expand_hostname(text))
# print(old_expand_hostname(text))

# Test cases for expand_hostname and old_expand_hostname functions

def run_tests():
	test_cases = [
		# Simple numeric range
		("test[1-3]", {"test1", "test2", "test3"}),

		# Simple letter range
		("host[a-c]", {"hosta", "hostb", "hostc"}),

		# Simple hexadecimal range
		("hex[0-3]", {"hex0", "hex1", "hex2", "hex3"}),

		# Numeric range with padding
		("server[001-003]", {"server001", "server002", "server003"}),

		# Letter and numeric mixed ranges
		("mixed[a-b,1-2]", {"mixeda", "mixedb", "mixed1", "mixed2"}),

		# Multiple ranges with different characters
		("complex[a-c,1-2,x]", {"complexa", "complexb", "complexc", "complex1", "complex2", "complexx"}),

		# Hexadecimal range with uppercase letters
		("hexrange[A-C]", {"hexrangea", "hexrangeb", "hexrangec"}),

		# Multiple numeric ranges
		("num[1-2,5-6]", {"num1", "num2", "num5", "num6"}),

		# Overlapping numeric range
		("overlap[3-6,5-8]", {"overlap3", "overlap4", "overlap5", "overlap6", "overlap7", "overlap8"}),

		# Invalid input without range brackets
		("invalid_host", {"invalid_host"}),

		# No content inside brackets
		("empty[]", {"empty"}),

		# Invalid range format with non-numeric or non-alphanumeric character
		("invalid[@-%]", {"invalid[@-%]"}),

		# No valid starting character for range
		#("start[0-9A-Z]", {"start0", "start1", "start2", "start3", "start4", "start5", "start6", "start7", "start8", "start9"}),

		# Empty input
		("", {""}),

		# Simple hostname without any ranges
		("hostname", {"hostname"}),
		("hostname[x-z]", {"hostnamex","hostnamey","hostnamez"}),

		# Mixed valid and invalid ranges
		#("mix[1-3, x-]", {"mix1", "mix2", "mix3", "mix[ x-]"}),

		# Single digit to single letter range
		("combo[5-a]", {'combo8', 'combo6', 'combo9', 'comboa', 'combo5', 'combo7'}),
	]

	for idx, (input_str, expected) in enumerate(test_cases):
		result = expand_hostname(input_str, validate=False)
		#old_result = old_expand_hostname(input_str, validate=False)
		assert result == expected, f"Test {idx + 1} failed in expand_hostname(). Expected: {expected}, Got: {result}"
		#assert old_result == expected, f"Test {idx + 1} failed in old_expand_hostname(). Expected: {expected}, Got: {old_result}"
		print(f"Test {idx + 1} passed.")
		
import re

def tokenize_hostname(hostname):
	"""
	Tokenize the hostname into a list of tokens.
	Tokens will be seperated by symbols or numbers.

	Args:
		hostname (str): The hostname to tokenize.

	Returns:
		list: A list of tokens (hashed).
	"""
	# Split the hostname into tokens
	tokens = re.findall(r"([a-zA-Z]+|\d+)", hostname)
	# Hash the tokens
	return [hash(token) for token in tokens]



def compact_hostnames(hostnames):
	patterns = defaultdict(list)
	for hostname in hostnames:
		parts = parse_hostname(hostname)
		pattern = get_pattern(parts)
		patterns[pattern].append(parts)
	
	# Function to compact a list of numbers
	def compact_numbers(numbers):
		sorted_nums = sorted(set(numbers))
		if len(sorted_nums) == 1:
			return str(sorted_nums[0])
		ranges = []
		start = prev = sorted_nums[0]
		for number in sorted_nums[1:]:
			if number != prev + 1:
				if start == prev:
					ranges.append(str(start))
				else:
					ranges.append(f"{start}-{prev}")
				start = number
			prev = number
		if start == prev:
			ranges.append(str(start))
		else:
			ranges.append(f"{start}-{prev}")
		return "[" + ",".join(ranges) + "]"

	results = []
	for pattern, parts_list in patterns.items():
		segment_lists = OrderedDict()
		for parts in parts_list:
			for i, part in enumerate(parts):
				if part.isdigit():
					if i not in segment_lists:
						segment_lists[i] = []
					segment_lists[i].append(int(part))
		
		# Construct the resulting compacted hostname
		result_parts = []
		last_index = 0
		for index, num_list in segment_lists.items():
			# Add the preceding static text
			result_parts.append("".join(pattern[last_index:index]))
			last_index = index + 1
			# Add the compacted number range
			result_parts.append(compact_numbers(num_list))
		# Add any trailing static text
		result_parts.append("".join(pattern[last_index:]))
		results.append("".join(result_parts))
	
	return ",".join(results)

# Test this updated function with your test cases.


# Run the tests
run_tests()

# servera,serverb,serverc=server[a-c]
# server15,server16,server17=server[15-17]
# server-1,server-2,server-3=server-[1-3]
# server-1-2,server-1-1,server-2-1,server-2-2=server-[1-2]-[1-2]
# server-1-2,server-1-1,server-2-2=server-1-[1-2],server-2-2
# test1-a,test2-a=test[1-2]-a

# Test cases
test_cases = [
	(['server15', 'server16', 'server17'], 'server[15-17]'),
	(['server-1', 'server-2', 'server-3'], 'server-[1-3]'),
	(['server-1-2', 'server-1-1', 'server-2-1', 'server-2-2'], 'server-[1-2]-[1-2]'),
	(['server-1-2', 'server-1-1', 'server-2-2'], 'server-1-[1-2],server-2-2'),
	(['test1-a', 'test2-a'], 'test[1-2]-a'),
	(['sub-s1', 'sub-s2'], 'sub-s[1-2]'),
]

for hostnames, expected in test_cases:
	result = compact_hostnames(hostnames)
	print(f"Hostnames: {hostnames}")
	print(f"Compacted: {result}")
	print(f"Expected:  {expected}")
	print(f"Pass: {result == expected}\n")


