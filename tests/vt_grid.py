'''
A small in-memory terminal for the drawing tests: the VT100 subset the picker and the editor use.

Printable text (wide characters take two cells, the last column wraps on the next character),
CR, LF (raw mode: no carriage return), BS, CSI A B C D G H J K P m, ESC 7 / ESC 8. Other
sequences are read and ignored. Each cell remembers the SGR parameters it was written with.
'''
import re
import unicodedata

CSI = re.compile(r'\x1b\[([0-9;?<=>]*)([ -/]*)([@-~])')
OTHER = re.compile(r'\x1b(\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[@-Z\\-_=>])')


def width(char):
	if unicodedata.combining(char) or ord(char) < 32:
		return 0
	return 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1


class Grid(object):
	def __init__(self, rows=24, columns=80):
		self.rows = rows
		self.columns = columns
		self.cells = [[(' ', '') for _ in range(columns)] for _ in range(rows)]
		self.row = 0
		self.column = 0
		self.saved = (0, 0)
		self.style = ''
		self.scrolled = 0

	def _line_feed(self):
		if self.row == self.rows - 1:
			self.cells.pop(0)
			self.cells.append([(' ', '') for _ in range(self.columns)])
			self.scrolled += 1
		else:
			self.row += 1

	def _put(self, char):
		size = width(char)
		if size == 0:
			return
		if self.column + size > self.columns:
			self.column = 0
			self._line_feed()
		self.cells[self.row][self.column] = (char, self.style)
		if size == 2:
			self.cells[self.row][self.column + 1] = ('', self.style)
		self.column += size

	def _csi(self, params, final):
		private = params.startswith(('?', '<', '=', '>'))
		numbers = [int(part) if part.isdigit() else 0 for part in params.lstrip('?<=>').split(';')] if params else []
		first = numbers[0] if numbers and numbers[0] else 1
		if private:
			return
		if final == 'A':
			self.row = max(0, self.row - first)
		elif final == 'B':
			self.row = min(self.rows - 1, self.row + first)
		elif final == 'C':
			self.column = min(self.columns - 1, self.column + first)
		elif final == 'D':
			self.column = max(0, min(self.column, self.columns - 1) - first)
		elif final == 'G':
			self.column = min(self.columns - 1, first - 1)
		elif final in 'Hf':
			self.row = min(self.rows - 1, first - 1)
			self.column = min(self.columns - 1, (numbers[1] if len(numbers) > 1 and numbers[1] else 1) - 1)
		elif final == 'K':
			mode = numbers[0] if numbers else 0
			start, end = {0: (self.column, self.columns), 1: (0, self.column + 1), 2: (0, self.columns)}[mode]
			for column in range(start, min(end, self.columns)):
				self.cells[self.row][column] = (' ', '')
		elif final == 'J':
			mode = numbers[0] if numbers else 0
			if mode == 0:
				self._csi('', 'K')
				for row in range(self.row + 1, self.rows):
					self.cells[row] = [(' ', '') for _ in range(self.columns)]
			elif mode == 2:
				self.cells = [[(' ', '') for _ in range(self.columns)] for _ in range(self.rows)]
		elif final == 'P':
			line = self.cells[self.row]
			column = min(self.column, self.columns - 1)
			del line[column:column + first]
			line.extend([(' ', '')] * (self.columns - len(line)))
		elif final == 'm':
			self.style = '' if params in ('', '0') else (self.style + ';' + params).lstrip(';')
			if params in ('27', '22', '39'):
				self.style = ''

	def feed(self, text):
		index = 0
		while index < len(text):
			char = text[index]
			if char == '\x1b':
				match = CSI.match(text, index)
				if match:
					self._csi(match.group(1), match.group(3))
					index = match.end()
					continue
				if text.startswith('\x1b7', index):
					self.saved = (self.row, min(self.column, self.columns - 1))
					index += 2
					continue
				if text.startswith('\x1b8', index):
					self.row, self.column = self.saved
					index += 2
					continue
				match = OTHER.match(text, index)
				index = match.end() if match else index + 1
				continue
			if char == '\r':
				self.column = 0
			elif char == '\n':
				self._line_feed()
			elif char == '\b':
				self.column = max(0, min(self.column, self.columns - 1) - 1)
			elif char >= ' ':
				self._put(char)
			index += 1

	def line(self, row):
		return ''.join(char for char, _ in self.cells[row]).rstrip()

	def lines(self):
		return [self.line(row) for row in range(self.rows)]

	def styles(self, row):
		'''The SGR parameters of each cell of row, wide characters' second cells left out.'''
		return [style for char, style in self.cells[row] if char != '']

	@property
	def cursor(self):
		return self.row, min(self.column, self.columns - 1)


class FakeTerminal(object):
	'''
	What the picker and the editor need from a Terminal, drawing into a Grid. Keys come in scripted
	bursts (what the operator typed at once), one key per read; queue holds the burst's unread keys.
	'''
	def __init__(self, bursts, rows=24, columns=80, grid=None):
		self.grid = grid or Grid(rows, columns)
		self.bursts = list(bursts)
		self.queue = []

	def size(self):
		return self.grid.rows, self.grid.columns

	def write(self, text):
		self.grid.feed(text)

	def read_key(self, timeout=None):
		import mssh_complete as mc
		if not self.queue:
			if not self.bursts:
				raise AssertionError('the program read more keys than the test scripted')
			burst = self.bursts.pop(0)
			self.queue = mc.decode_keys(burst.encode('utf-8') if isinstance(burst, str) else burst)
		return self.queue.pop(0)

	def has_input(self):
		return bool(self.queue)
