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


def test_merge_outputs_includes_group_and_remaining(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	h1 = fake_host("127.0.0.1", "echo hi")
	h1.stdout = ["hi"]
	h1.returncode = 0
	h2 = fake_host("127.0.0.2", "echo hi")
	h2.stdout = ["hi"]
	h2.returncode = 0
	h3 = fake_host("127.0.0.3", "echo other")
	h3.stdout = ["other"]
	h3.returncode = 0
	outputs, line_bags, by_len, sorted_keys, width = multiSSH3.get_host_raw_output(
		[h1, h2, h3], terminal_width=80
	)
	merge_groups, remaining = multiSSH3.form_merge_groups(
		{k: set(v) for k, v in by_len.items()},
		list(sorted_keys),
		dict(line_bags),
		0.9,
	)
	merged = multiSSH3.mergeOutputs(
		outputs, merge_groups, remaining, 0.9, width
	)
	text = "\n".join(merged)
	assert "hi" in text
	assert "127.0.0.3" in text or "other" in text


def test_pre_merge_hosts_collapses_identical(fake_host):
	h1 = fake_host("127.0.0.1", "echo hi")
	h1.stdout = ["hi"]
	h1.stderr = []
	h1.returncode = 0
	h2 = fake_host("127.0.0.2", "echo hi")
	h2.stdout = ["hi"]
	h2.stderr = []
	h2.returncode = 0
	hosts = [h1, h2]
	out = multiSSH3.pre_merge_hosts(hosts)
	assert len(out) == 1
	# compact_hostnames may rewrite the joined name to a range form
	assert "127.0.0." in out[0].name
	assert "1" in out[0].name and "2" in out[0].name


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


def test_generate_output_quiet_filters_success(fake_host):
	ok = fake_host("127.0.0.1", "echo")
	ok.stdout = ["ok"]
	ok.returncode = 0
	bad = fake_host("127.0.0.2", "false")
	bad.stdout = ["fail"]
	bad.returncode = 1
	out = multiSSH3.generate_output([ok, bad], greppable=True, quiet=True)
	assert "fail" in out
	assert "127.0.0.1" not in out
