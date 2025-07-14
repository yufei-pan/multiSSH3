import collections
import multiSSH3

SEPERATING_MARKS= '`[]\\;\'!#$%^&()+{}|"<>\n\t\r\v\f'
FUNCTIONAL_MARKS = '~-=,./@_*:?'
IGNORE_CLI_MARKS_TRANSLATION = str.maketrans('', '', SEPERATING_MARKS)
CONVERT_SPACE_TRANSLATION = str.maketrans({c: ' ' for c in SEPERATING_MARKS})
CONVERT_SPACE_TRANSLATION_FUNCTIONAL = str.maketrans({c: ' ' for c in FUNCTIONAL_MARKS})

class CommandSearcher:
	def __init__(self, commands, k=3):
		self.commands = collections.Counter(commands)
		self.k = k
		self.commands_indexed_by_word = collections.defaultdict(collections.Counter)
		self.words_indexed_by_kgram = collections.defaultdict(collections.Counter)
		self._build_index()

	def _build_index(self):
		for command, count in self.commands.items():
			words = command.lower().translate(CONVERT_SPACE_TRANSLATION).split()
			for word in words:
				if not word:
					continue
				self.commands_indexed_by_word[word][command] += count
				# if len(word) >= self.k:
				# 	head = word[:self.k]
				# 	tail = word[-self.k:]
				# 	self.words_indexed_by_kgram[head][word] += count
				# 	if head != tail:
				# 		self.words_indexed_by_kgram[tail][word] += count
				for i in range(len(word) - self.k + 1):
					kgram = word[i:i+self.k]
					self.words_indexed_by_kgram[kgram][word] += count
				smallWords = word.translate(CONVERT_SPACE_TRANSLATION_FUNCTIONAL)
				if word != smallWords:
					smallWords = smallWords.split()
					for smallWord in smallWords:
						if not smallWord:
							continue
						self.commands_indexed_by_word[smallWord][command] += count
						for i in range(len(smallWord) - self.k + 1):
							kgram = smallWord[i:i+self.k]
							self.words_indexed_by_kgram[kgram][smallWord] += count

	def search_commands(self, query, n=10):
		query = query.lower().translate(CONVERT_SPACE_TRANSLATION).split()
		if not query:
			return []
		results = collections.Counter()
		for word in query:
			if not word:
				continue
			if not results:
				results = self.commands_indexed_by_word[word].copy()
			else:
				# restrict results to only those that match all words in the query
				results &= self.commands_indexed_by_word[word]
		return results.most_common(n)

	def search_words(self, query, n=10):
		query = query.lower().translate(IGNORE_CLI_MARKS_TRANSLATION)
		if not query:
			return []
		results = collections.Counter()
		# head = query[:self.k]
		# tail = query[-self.k:]
		# if head in self.words_indexed_by_kgram:
		# 	results += self.words_indexed_by_kgram[head]
		# if tail in self.words_indexed_by_kgram and head != tail:
		# 	results += self.words_indexed_by_kgram[tail]
		for i in range(len(query) - self.k + 1):
			kgram = query[i:i+self.k]
			if kgram in self.words_indexed_by_kgram:
				results += self.words_indexed_by_kgram[kgram]
		if not results:
			return []
		return results.most_common(n)

def load_command_history(file_path):
	with open(file_path, 'r') as f:
		commands = ['\t'.join(line.strip().split('\t')[2:]) for line in f if line.strip()]
	return commands

class ArgumentSearcher:
	def __init__(self, k=2):
		self.options = [opt for actions in multiSSH3.get_parser()._actions for opt in actions.option_strings]
		self.k = k
		self.options_indexed_by_kgram = collections.defaultdict(set)
		self._build_index()

	def _build_index(self):
		for option in self.options:
			shortOption = option[1:].lower()
			for i in range(len(shortOption) - self.k + 1):
				kgram = shortOption[i:i+self.k]
				self.options_indexed_by_kgram[kgram].add(option)

	def search_options(self, query, n=5):
		# we assume the query already have one '-' truncated.
		query = query.lower().translate(IGNORE_CLI_MARKS_TRANSLATION)
		if not query:
			return []
		results = collections.Counter()
		for i in range(len(query) - self.k + 1):
			kgram = query[i:i+self.k]
			if kgram in self.options_indexed_by_kgram:
				results.update(self.options_indexed_by_kgram[kgram])
		return results.most_common(n)
