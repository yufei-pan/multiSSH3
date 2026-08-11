import multiSSH3


def test_can_merge_identical_bags():
	# Production line bags are set objects (get_host_raw_output)
	bag = {"line1", "line2", "line3"}
	assert multiSSH3.can_merge(bag, bag, 0.9) is True


def test_can_merge_divergent_bags():
	a = {"a", "b", "c"}
	b = {"x", "y", "z"}
	assert multiSSH3.can_merge(a, b, 0.9) is False


def test_form_merge_groups_identical_hosts(fake_host):
	h1 = fake_host("127.0.0.1", "echo hi")
	h1.stdout = ["hi"]
	h1.returncode = 0
	h2 = fake_host("127.0.0.2", "echo hi")
	h2.stdout = ["hi"]
	h2.returncode = 0
	outputs, line_bags, by_len, sorted_keys, _width = multiSSH3.get_host_raw_output(
		[h1, h2], terminal_width=80
	)
	# Copy structures because form_merge_groups mutates them
	merge_groups, remaining = multiSSH3.form_merge_groups(
		{k: set(v) for k, v in by_len.items()},
		list(sorted_keys),
		dict(line_bags),
		0.9,
	)
	assert remaining == set()
	assert len(merge_groups) == 1
	assert set(merge_groups[0]) == {"127.0.0.1", "127.0.0.2"}


def test_generate_output_json(fake_host):
	h = fake_host("127.0.0.1", "echo")
	h.stdout = ["hello"]
	h.returncode = 0
	# quiet=True filters out returncode==0 hosts — use quiet=False for success path
	out = multiSSH3.generate_output([h], usejson=True, quiet=False)
	assert "hello" in out
	assert "127.0.0.1" in out


def test_generate_output_greppable(fake_host):
	h = fake_host("127.0.0.1", "echo")
	h.stdout = ["hello"]
	h.returncode = 0
	out = multiSSH3.generate_output([h], greppable=True, quiet=False)
	assert "hello" in out
