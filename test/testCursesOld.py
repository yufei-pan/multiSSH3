import curses
import re
import math

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

def __parse_ansi_escape_sequence_to_curses_color(escape_code):
	"""
	Parse ANSI escape codes to extract foreground and background colors.

	Args:
		escape_code: ANSI escape sequence for color

	Returns:
		Tuple of (foreground, background) curses color pairs. 
		If the escape code is a reset code, return (-1, -1).
		None values indicate that the color should not be changed.
	"""
	if not escape_code:
		return None, None
	color_match = re.match(r"\x1b\[(\d+)(?:;(\d+))?(?:;(\d+))?(?:;(\d+);(\d+);(\d+))?m", escape_code)
	if color_match:
		params = color_match.groups()
		if params[0] == "0" and not any(params[1:]):  # Reset code
			return -1, -1
		if params[0] == "38" and params[1] == "5":  # 8-bit foreground
			return __approximate_color_8bit(int(params[2])), None
		elif params[0] == "38" and params[1] == "2":  # 24-bit foreground
			return __approximate_color_24bit(int(params[3]), int(params[4]), int(params[5])), None
		elif params[0] == "48" and params[1] == "5":  # 8-bit background
			return None , __approximate_color_8bit(int(params[2]))
		elif params[0] == "48" and params[1] == "2":  # 24-bit background
			return None, __approximate_color_24bit(int(params[3]), int(params[4]), int(params[5]))
		else:
			fg = None
			bg = None
			if params[0] and params[0].isdigit():  # 4-bit color
				fg = ANSI_TO_CURSES_COLOR.get(int(params[0]), curses.COLOR_WHITE)
			if params[1] and params[1].isdigit():
				bg = ANSI_TO_CURSES_COLOR.get(int(params[1]), curses.COLOR_BLACK)
			return fg, bg
	return None, None

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
	return __curses_global_color_pairs[(fg, bg)]

def _add_line_with_ascii_colors(window, y, x, line, n, color_pair_list = [-1,-1,1]):
	"""
	Add a line to a curses window with ANSI escape sequences translated to curses color pairs.

	Args:
		window: curses window object
		y: Line position in the window
		x: Column position in the window
		line: The string containing ANSI escape sequences for color
		n: Maximum number of characters to write
		host: The host object
	
	Returns:
		None
	"""
	segments = re.split(r"(\x1b\[[\d;]*m)", line)  # Split line by ANSI escape codes
	current_x = x
	for segment in segments:
		if segment.startswith("\x1b["):
			# Parse ANSI escape sequence
			newFrontColor, newBackColor = __parse_ansi_escape_sequence_to_curses_color(segment)
			if newFrontColor is not None:
				color_pair_list[0] = newFrontColor
			if newBackColor is not None:
				color_pair_list[1] = newBackColor
			color_pair_list[2] = __get_curses_color_pair(color_pair_list[0], color_pair_list[1])
			pair = str(color_pair_list[2])
			window.addstr(y, current_x, pair)
			current_x += len(pair)
		else:
			# Add text with current color
			if current_x < x + n:
				#eprint(f"\ny: {y}, x: {current_x}, segment: {segment}, n: {n}, color_pair: {color_pair_list[2]}\n")
				window.addnstr(y, current_x, segment, n - (current_x - x), curses.color_pair(color_pair_list[2]))
				current_x += len(segment)


TEST_LINE = (
		"Standard \x1b[31mRed\x1b[0m, ",
		"Bright \x1b[91mRed\x1b[0m, ",
		"Standard \x1b[32mGreen\x1b[0m, ",
		"Bright \x1b[92mGreen\x1b[0m, ",
		"Standard \x1b[33mYellow\x1b[0m, ",
		"Bright \x1b[93mYellow\x1b[0m, ",
		"Standard \x1b[34mBlue\x1b[0m, ",
		"Bright \x1b[94mBlue\x1b[0m, ",
		"Standard \x1b[35mMagenta\x1b[0m, ",
		"Bright \x1b[95mMagenta\x1b[0m, ",
		"Standard \x1b[36mCyan\x1b[0m, ",
		"Bright \x1b[96mCyan\x1b[0m, ",
		"Standard \x1b[37mWhite\x1b[0m, ",
		"Bright \x1b[97mWhite\x1b[0m, ",
		"8-bit \x1b[38;5;196mRed\x1b[0m, ",
		"8-bit \x1b[38;5;82mGreen\x1b[0m, ",
		"8-bit \x1b[38;5;27mBlue\x1b[0m, ",
		"8-bit \x1b[38;5;226mYellow\x1b[0m, ",
		"8-bit \x1b[38;5;201mMagenta\x1b[0m, ",
		"8-bit \x1b[38;5;51mCyan\x1b[0m, ",
		"8-bit \x1b[38;5;15mWhite\x1b[0m, ",
		"8-bit \x1b[38;5;0mBlack\x1b[0m, ",
		"8-bit \x1b[38;5;4mBlue\x1b[0m, ",
		"24-bit \x1b[38;2;128;128;128mGray\x1b[0m.",
		"24-bit \x1b[38;2;255;165;0mOrange\x1b[0m.",
		"24-bit \x1b[38;2;255;0;255mPink\x1b[0m.",
		"24-bit \x1b[38;2;0;255;255mCyan\x1b[0m.",
		"24-bit \x1b[38;2;255;255;255mWhite\x1b[0m.",
		"24-bit \x1b[38;2;0;0;0mBlack\x1b[0m.",
		"24-bit \x1b[38;2;128;128;128mGray\x1b[0m.",
		"24-bit \x1b[38;2;255;0;0mRed\x1b[0m.",
		"24-bit \x1b[38;2;0;255;0mGreen\x1b[0m.",
		"24-bit \x1b[38;2;0;0;255mBlue\x1b[0m.",
		"24-bit \x1b[38;2;255;255;0mYellow\x1b[0m.",
		"24-bit \x1b[38;2;255;0;255mMagenta\x1b[0m.",
		"24-bit \x1b[38;2;0;255;255mCyan colored dot.",
		"Following string without reset color.",
		"Following string with \x1b[31mRed color.",
		"Following string with \x1b[31mRed color and \x1b[32mGreen color.",
		"Reset color. \x1b[0mFollowing string with default color."
	)
# Example usage in a curses application
def main(stdscr):
	curses.start_color()
	curses.use_default_colors()
	curses.init_pair(1, -1, -1)
	frontColor, backColor = __parse_ansi_escape_sequence_to_curses_color('\x1b[31;33m')
	stdscr.addnstr(0, 0, f'frontColor,backColor:{frontColor},{backColor}',stdscr.getmaxyx()[1], 1)
	stdscr.addnstr(1, 0, f'{curses.color_content(frontColor)}, {curses.color_content(backColor)}',stdscr.getmaxyx()[1], 1)
	stdscr.refresh()
	color_pair = __get_curses_color_pair(frontColor, backColor)
	stdscr.addnstr(2, 0, f'color_pair {color_pair}',stdscr.getmaxyx()[1], color_pair)
	stdscr.addnstr(3, 0, f'{curses.color_pair(color_pair)}',stdscr.getmaxyx()[1], color_pair)
	stdscr.refresh()
	stdscr.getch()
	stdscr.clear()
	#stdscr.idlok(True)
	#stdscr.scrollok(True)
	screen_size = stdscr.getmaxyx()

	# Example line with ANSI color escape codes (including 8-bit and 24-bit colors)
	color_pair_list = [-1,-1,1]
	for i, line in enumerate(TEST_LINE):
		_add_line_with_ascii_colors(stdscr, i, 0, line, screen_size[1], color_pair_list)

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
