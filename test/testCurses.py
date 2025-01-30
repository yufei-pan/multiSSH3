import curses
import re
import math
import sys

# Global dictionary to store color pairs
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
		window.addnstr(y, x + charsWritten, fill_char * (fill_length // 2 // len(fill_char)), numChar - charsWritten, boxAttr)
		charsWritten += min(len(fill_char * (fill_length // 2)), numChar - charsWritten)
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
		fillStr = fill_char * ((numChar - charsWritten - len(trail_str))//len(fill_char))
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

TEST_LINE = (
		"Standard \x1b[31m          Red\x1b[0m, ",
		"Bold \x1b[91m            \x1b[1mRed\x1b[0m, ",
		"Standard \x1b[32m        Green\x1b[0m, ",
		"Bright \x1b[92m          Green\x1b[0m, ",
		"Standard \x1b[33m       Yellow\x1b[0m, ",
		"Bright \x1b[93m          Yellow\x1b[0m, ",
		"Standard \x1b[34m          Blue\x1b[0m, ",
		"Bright \x1b[94m          Blue\x1b[0m, ",
		"Standard \x1b[35m          Magenta\x1b[0m, ",
		"Bright \x1b[95m          Magenta\x1b[0m, ",
		"Standard \x1b[36m          Cyan\x1b[0m, ",
		"Bright \x1b[96m          Cyan\x1b[0m, ",
		"Standard \x1b[37m          White\x1b[0m, ",
		"Bright \x1b[97m          White\x1b[0m, ",
		"8-bit \x1b[38;5;196m          Red\x1b[0m, ",
		"8-bit \x1b[38;5;82m          Green\x1b[0m, ",
		"8-bit \x1b[38;5;27m          Blue\x1b[0m, ",
		"8-bit \x1b[38;5;226m          Yellow\x1b[0m, ",
		"8-bit \x1b[38;5;201m          Magenta\x1b[0m, ",
		"8-bit \x1b[38;5;51m          Cyan\x1b[0m, ",
		"8-bit \x1b[38;5;15m          White\x1b[0m, ",
		"8-bit \x1b[38;5;0m          Black\x1b[0m, ",
		"8-bit \x1b[38;5;4m          Blue\x1b[0m, ",
		"24-bit \x1b[38;2;128;128;128m          Gray\x1b[0m.",
		"24-bit \x1b[38;2;255;165;0m          Orange\x1b[0m.",
		"24-bit \x1b[38;2;255;0;255m          Pink\x1b[0m.",
		"24-bit \x1b[38;2;0;255;255m          Cyan\x1b[0m.",
		"24-bit \x1b[38;2;255;255;255m          White\x1b[0m.",
		"24-bit \x1b[38;2;0;0;0m          Black\x1b[0m.",
		"24-bit \x1b[38;2;128;128;128m          Gray\x1b[0m.",
		"24-bit \x1b[38;2;255;0;0m          Red\x1b[0m.",
		"24-bit \x1b[38;2;0;255;0m          Green\x1b[0m.",
		"24-bit \x1b[38;2;0;0;255m          Blue\x1b[0m.",
		"24-bit \x1b[38;2;255;255;0m          Yellow\x1b[0m.",
		"24-bit \x1b[38;2;255;0;255m          Magenta\x1b[0m.",
		"24-bit \x1b[38;2;0;255;255m          Cyan colored dot.",
		"Following string without reset color.",
		"Following string with \x1b[31m          Red color.",
		"Following string with \x1b[31m          Red color and \x1b[32m          Green color.",
		"Reset color. \x1b[0m          Following string with default color.",
		"Bold \x1b[1m          Following string with bold text.\x1b[0m",
		"Dim \x1b[2m          Following string with dim text.\x1b[0m",
		"Underline \x1b[4m          Following string with underline text.\x1b[0m",
		"Blink \x1b[5m          Following string with blink text.\x1b[0m",
		"Reverse \x1b[7m          Following string with reverse text.\x1b[0m",
		"Invisible \x1b[8m          Following string with invisible text.\x1b[0m",
		"Reset color. \x1b[0m          Following string with default color.\x1b[0m",
		"Bold \x1b[1m          Following string with \x1b[22m not bold text.\x1b[0m",
		"RedGreen \x1b[31;32m          Green\x1b[0m, ",
	)
# Example usage in a curses application
def main(stdscr):
	curses.start_color()
	curses.use_default_colors()
	curses.init_pair(1, -1, -1)
	parsed_attr = __parse_ansi_escape_sequence_to_curses_attr('\x1b[31m')
	stdscr.addnstr(0, 0, f'{parsed_attr}',stdscr.getmaxyx()[1], parsed_attr)
	# get curses.A_BOLD
	stdscr.addnstr(1, 0, f'{curses.A_BOLD}',stdscr.getmaxyx()[1], curses.A_BOLD)
	stdscr.addnstr(2, 0, f'{parsed_attr | curses.A_BOLD}',stdscr.getmaxyx()[1], parsed_attr | curses.A_BOLD)
	stdscr.addnstr(3, 0, f'{curses.A_DIM}',stdscr.getmaxyx()[1], parsed_attr | curses.A_DIM)
	stdscr.addnstr(4, 0, f'{parsed_attr | curses.A_BOLD | curses.A_DIM}',stdscr.getmaxyx()[1], parsed_attr | curses.A_BOLD| curses.A_DIM)
	stdscr.refresh()
	stdscr.getch()
	stdscr.clear()
	#stdscr.idlok(True)
	#stdscr.scrollok(True)
	screen_size = stdscr.getmaxyx()

	# Example line with ANSI color escape codes (including 8-bit and 24-bit colors)
	color_pair_list = [-1,-1,1]
	for i, line in enumerate(TEST_LINE):
		_curses_add_string_to_window(window=stdscr, line=line, y = i,color_pair_list=color_pair_list,fill_char='-',centered=True,lead_str='|',trail_str='?|',box_ansi_color='\x1b[43;31;5m',keep_top_n_lines=2)
	
	#stdscr.addnstr(i+ 1, 0, 'test',10, 4)
	stdscr.refresh()
	stdscr.getch()
	#stdscr.scroll(1)
	stdscr.move(0,0)
	stdscr.deleteln()
	stdscr.refresh()
	stdscr.getch()

if __name__ == "__main__":
	for i, color in enumerate(TEST_LINE):
		print(f'{i}: {color}')
	curses.wrapper(main)

	#print(__curses_color_table)
	#print(__curses_global_color_pairs)
	for color in __curses_color_table:
		print(f'{color}: {__curses_color_table[color]}, {curses.color_content(__curses_color_table[color])}')
	for color_pair in __curses_global_color_pairs:
		print(f'{color_pair}: {__curses_global_color_pairs[color_pair]}')
	# for i in range(curses.COLORS):
	# 	print(f'{i}: {curses.color_content(i)}')
