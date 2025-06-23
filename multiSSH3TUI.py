import collections

IGNORE_CLI_MARKS_TRANSLATION = str.maketrans('', '', f'-"\'$()[]|<>&#!;_')

class CommandSearcher:
	def __init__(self, commands, k=3):
		self.commands = collections.Counter(commands)
		self.k = k
		self.commands_indexed_by_word = collections.defaultdict(collections.Counter)
		self.words_indexed_by_kgram = collections.defaultdict(collections.Counter)
		self._build_index()

	def _build_index(self):
		for command, count in self.commands.items():
			words = command.lower().translate(IGNORE_CLI_MARKS_TRANSLATION).replace('/',' ').split()
			for word in words:
				if not word:
					continue
				self.commands_indexed_by_word[word][command] += count
				if len(word) >= self.k:
					head = word[:self.k]
					tail = word[-self.k:]
					self.words_indexed_by_kgram[head][word] += count
					if head != tail:
						self.words_indexed_by_kgram[tail][word] += count
	
	def search_commands(self, query, n=10):
		query = query.lower().translate(IGNORE_CLI_MARKS_TRANSLATION).replace('/',' ').split()
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
		query = query.lower().translate(IGNORE_CLI_MARKS_TRANSLATION).replace('/',' ')
		if not query:
			return []
		head = query[:self.k]
		tail = query[-self.k:]
		results = collections.Counter()
		if head in self.words_indexed_by_kgram:
			results += self.words_indexed_by_kgram[head]
		if tail in self.words_indexed_by_kgram and head != tail:
			results += self.words_indexed_by_kgram[tail]
		return results.most_common(n)




