import multiSSH3


def test_host_defaults(fake_host):
	h = fake_host("127.0.0.1", "echo hi")
	assert h.name == "127.0.0.1"
	assert h.command == "echo hi"
	assert h.returncode is None
	assert h.uuid is not None
	assert h.i >= 0


def test_host_copy_preserves_outputs(fake_host):
	h = fake_host("127.0.0.1", "true")
	h.stdout = ["a"]
	h.stderr = ["b"]
	h.returncode = 0
	c = h.copy()
	assert c.stdout == ["a"]
	assert c.stderr == ["b"]
	assert c.returncode == 0
	assert c.uuid == h.uuid


def test_replace_magic_strings_host():
	s = multiSSH3.replace_magic_strings("run on #HOST#", ["#HOST#", "#HOSTNAME#"], "node1")
	assert s == "run on node1"


def test_ordered_multiset_count_and_contains():
	# OrderedMultiSet is a deque+Counter helper used in mergeOutput streaming;
	# line bags passed to can_merge are plain set objects (see get_host_raw_output).
	a = multiSSH3.OrderedMultiSet(["x", "y", "y"])
	assert a.count("y") == 2
	assert "x" in a
	assert list(a) == ["x", "y", "y"]
