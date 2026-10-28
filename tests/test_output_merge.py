import json

import pytest

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


def test_generate_output_errors_only_alias(fake_host):
	ok = fake_host("127.0.0.1", "echo")
	ok.stdout = ["ok"]
	ok.returncode = 0
	bad = fake_host("127.0.0.2", "false")
	bad.stdout = ["fail"]
	bad.returncode = 1
	out = multiSSH3.generate_output([ok, bad], greppable=True, errors_only=True)
	assert "fail" in out
	assert "127.0.0.1" not in out


def test_generate_output_quiet_still_works_with_errors_only_default(fake_host):
	"""Existing quiet= callers must keep filtering; errors_only=None defers to quiet."""
	ok = fake_host("127.0.0.1", "echo")
	ok.stdout = ["ok"]
	ok.returncode = 0
	out = multiSSH3.generate_output([ok], usejson=True, quiet=True)
	assert "Success" in out


def test_generate_output_errors_only_false_overrides_quiet_false(fake_host):
	ok = fake_host("127.0.0.1", "echo")
	ok.stdout = ["ok"]
	ok.returncode = 0
	out = multiSSH3.generate_output([ok], usejson=True, quiet=False, errors_only=False)
	assert "ok" in out
	assert "127.0.0.1" in out


def _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys, args):
	'''Run main() with an ssh that runs the command here; return the exit code and stdout.'''
	ssh = tmp_path / "ssh"
	# options up to --, then the host, then the command
	ssh.write_text('#!/bin/sh\nwhile [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done\nshift 2\nexec sh -c "$*"\n')
	ssh.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", str(ssh))
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda create=True: str(tmp_path / "unavailable.csv"))
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	monkeypatch.setattr(multiSSH3, "__mainReturnCode", 0)
	monkeypatch.setattr(multiSSH3, "__failedHosts", set())
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(args + ["--no_history"])
	return exc_info.value.code, capsys.readouterr().out


def _greppable_rows(out):
	'''The (host_name, output) cells of every output row of a greppable table.'''
	rows = []
	for line in out.splitlines():
		cells = [cell.strip() for cell in line.split("|")]
		if len(cells) == 4 and cells[0] and cells[0] != "host_name":
			rows.append((cells[0], cells[3]))
	return rows


def test_greppable_output_has_a_line_per_host_when_outputs_match(monkeypatch, tmp_path, capsys):
	code, out = _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys,
		["--greppable", "--no_watch", "127.0.0.[1-3]", "echo hi"])

	assert code == 0
	# grep 127.0.0.2 finds its line: the hosts are not merged into 127.0.0.[1-3]
	assert sorted(_greppable_rows(out)) == [("127.0.0.1", "hi"), ("127.0.0.2", "hi"), ("127.0.0.3", "hi")]


def test_script_output_names_every_failed_host(monkeypatch, tmp_path, capsys):
	code, out = _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys,
		["--script", "127.0.0.[1-6]", "echo flag missing >&2; exit 1"])

	assert code == 6
	assert sorted(_greppable_rows(out)) == [("127.0.0.{}".format(i), "flag missing") for i in range(1, 7)]


def test_json_output_has_an_entry_per_host_when_outputs_match(monkeypatch, tmp_path, capsys):
	code, out = _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys,
		["--json", "--no_watch", "127.0.0.[1-3]", "echo hi"])

	assert code == 0
	entries = json.loads(out)
	assert sorted(entry["name"] for entry in entries) == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
	assert all(entry["stdout"] == ["hi"] for entry in entries)


def test_json_error_only_output_has_an_entry_per_failed_host(monkeypatch, tmp_path, capsys):
	code, out = _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys,
		["--json", "--error_only", "--no_watch", "127.0.0.[1-3]", "exit 3"])

	assert code == 3
	assert sorted(entry["name"] for entry in json.loads(out)) == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_default_output_still_merges_hosts_with_the_same_output(monkeypatch, tmp_path, capsys):
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (80, 24))
	code, out = _run_main_with_fake_ssh(monkeypatch, tmp_path, capsys,
		["--no_watch", "127.0.0.[1-3]", "echo hi"])

	assert code == 0
	assert "127.0.0.[1-3]" in out
	assert "127.0.0.2" not in out


def _hosts_sharing_an_alias_name(fake_host, monkeypatch, tmp_path, outputs):
	'''Hosts web and web-b (DNS knows both) with outputs, and the alias web="web,web-b".'''
	real_getip = multiSSH3.getIP
	hosts = []
	for name, (lines, returncode) in outputs.items():
		host = fake_host(name, "uptime")
		host.stdout, host.stderr, host.returncode = list(lines), [], returncode
		hosts.append(host)
	monkeypatch.setattr(multiSSH3, "getIP", real_getip)  # fake_host makes every name an IP address
	env_file = tmp_path / "hosts.env"
	env_file.write_text('web="web,web-b"\n')
	monkeypatch.setattr(multiSSH3, "_env_files", [str(env_file)])
	monkeypatch.setattr(multiSSH3, "_explicit_env_files", {str(env_file)})
	monkeypatch.setattr(multiSSH3, "_no_env", True)
	monkeypatch.setattr(multiSSH3, "DEFAULT_HOST_FILE", str(tmp_path / "no-hosts"))
	monkeypatch.setattr(multiSSH3, "_etc_hosts", {})
	monkeypatch.setattr(multiSSH3, "_resolve_dns", {"web": "10.0.0.1", "web-b": "10.0.0.2"}.get)
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: None)
	multiSSH3._refresh_expansion_caches()
	assert sorted(multiSSH3.expand_hostnames(["web"])) == ["web", "web-b"]  # typed, web is the alias
	return hosts


def test_a_host_sharing_an_alias_name_is_shown_by_its_own_name(fake_host, monkeypatch, tmp_path):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	hosts = _hosts_sharing_an_alias_name(fake_host, monkeypatch, tmp_path, {"web": (["up 5 days"], 0), "web-b": (["up 1 day"], 0)})

	assert [host.name for host in multiSSH3.pre_merge_hosts(list(hosts))] == ["web", "web-b"]
	outputs, line_bags, by_len, sorted_keys, width = multiSSH3.get_host_raw_output(hosts, terminal_width=80)
	merge_groups, remaining = multiSSH3.form_merge_groups({k: set(v) for k, v in by_len.items()}, list(sorted_keys), dict(line_bags), 0.9)
	text = "\n".join(multiSSH3.mergeOutputs(outputs, merge_groups, remaining, 0.9, width))
	assert "web,web-b" not in text and "web-[b]" not in text


def test_failed_hosts_list_a_host_sharing_an_alias_name_alone(fake_host, monkeypatch, tmp_path, capsys):
	import pytest

	hosts = _hosts_sharing_an_alias_name(fake_host, monkeypatch, tmp_path, {"web": (["down"], 1), "web-b": (["up"], 0)})
	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", lambda **kwargs: hosts)

	with pytest.raises(SystemExit):
		multiSSH3.main(["--no_history", "-w", "-ef", str(tmp_path / "hosts.env"), "web", "uptime"])

	err = capsys.readouterr().err
	assert "failed_hosts: web\n" in err and "succeeded_hosts: web-b\n" in err


def _hosts_with_outputs(fake_host, outputs):
	hosts = []
	for name, lines in outputs.items():
		host = fake_host(name, "cat x")
		host.stdout, host.stderr, host.returncode = list(lines), [], 0
		hosts.append(host)
	return hosts


def test_the_header_of_pre_merged_hosts_is_one_range(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (80, 24))
	common = ["line {}".format(i) for i in range(30)]
	# odd and even nodes differ in one line, so the groups pre_merge_hosts names (node[1,3,...]) are merged again
	outputs = {"node{}".format(i): common + ["odd" if i % 2 else "even"] for i in range(1, 13)}
	hosts = multiSSH3.pre_merge_hosts(_hosts_with_outputs(fake_host, outputs))
	assert len(hosts) == 2

	out = multiSSH3.generate_output(hosts, usejson=False, quiet=False, errors_only=False)

	# the block's header (top and bottom) is the whole range, not the two groups it was merged from
	assert out.count("■ node[1-12]") == 2


def test_one_differing_host_leaves_the_rest_as_one_range(fake_host, monkeypatch):
	monkeypatch.setattr(multiSSH3, "get_terminal_color_capability", lambda: "None")
	monkeypatch.setattr(multiSSH3, "get_terminal_size", lambda: (80, 24))
	common = ["line {}".format(i) for i in range(30)]
	outputs = {"node1": common, "node2": common, "node3": common, "node4": common + ["extra"]}
	hosts = multiSSH3.pre_merge_hosts(_hosts_with_outputs(fake_host, outputs))

	out = multiSSH3.generate_output(hosts, usejson=False, quiet=False, errors_only=False)

	assert "node[1-4]" in out
	assert "node4,node[1-3]" not in out
