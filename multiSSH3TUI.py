from collections import defaultdict
from typing import List, Set, Dict

class CommandSearcher:
    """
    Efficiently search through a list of shell-history commands for any containing a given substring.
    Uses a fixed-length k-gram inverted index for fast candidate lookup.
    """
    def __init__(self, commands, k=3):
        """
        :param commands: List[str] of history commands to index
        :param k: length of k-grams to build index on (trade-off between index size and search speed)
        """
        self.commands = list(commands)
        self.k = k
        self.index = {}  # maps k-gram -> set of command indices
        for idx, cmd in enumerate(self.commands):
            seen = set()
            for i in range(len(cmd) - k + 1):
                gram = cmd[i:i+k]
                if gram not in seen:
                    self.index.setdefault(gram, set()).add(idx)
                    seen.add(gram)

    def search(self, query):
        """
        Return all commands containing the substring `query`.
        :param query: substring to search for
        :return: List[str] of matching commands
        """
        # For very short queries, fallback to scanning
        if len(query) < self.k:
            return [cmd for cmd in self.commands if query in cmd]

        # Collect candidate sets via k-gram index
        grams = [query[i:i+self.k] for i in range(len(query) - self.k + 1)]
        # If any gram not in index, no match
        if any(g not in self.index for g in grams):
            return []
        # Intersect candidate index sets
        candidates = set.intersection(*(self.index[g] for g in grams))
        # Verify actual substring presence
        return [self.commands[i] for i in candidates if query in self.commands[i]]


