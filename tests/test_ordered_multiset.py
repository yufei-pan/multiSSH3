import multiSSH3


def test_append_pop_and_put():
	s = multiSSH3.OrderedMultiSet(maxlen=3)
	s.append("a")
	s.append("b")
	s.appendleft("z")
	assert list(s) == ["z", "a", "b"]
	assert s.pop() == "b"
	assert s.popleft() == "z"
	s.extend(["x", "y"])
	removed = s.put("w")
	assert removed is not None or len(s) <= 3
	assert "w" in s


def test_remove_clear_count_copy_eq():
	s = multiSSH3.OrderedMultiSet(["a", "b", "a"])
	assert s.count("a") == 2
	s.remove("b")
	assert "b" not in s
	c = s.copy()
	assert c == s
	assert list(c) == list(s)
	s.clear()
	assert len(s) == 0


def test_truncate_and_peek():
	s = multiSSH3.OrderedMultiSet(["a", "b", "c", "d"])
	s.truncate(2)
	assert list(s) == ["a", "b"]
	s.extend(["c", "d"])
	s.truncateright(2)
	assert list(s) == ["c", "d"]
	assert s.peek() == "c"
	assert s.peek_right() == "d"


def test_extend_respects_maxlen():
	s = multiSSH3.OrderedMultiSet(maxlen=2)
	s.extend(["a", "b", "c"])
	assert len(s) == 2
	assert list(s)[-1] == "c"
