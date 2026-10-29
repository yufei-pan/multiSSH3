import multiSSH3


def test_compact_numeric_suffix(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server15", "server16", "server17"], verify=True
	) == ["server[15-17]"]


def test_compact_dashed(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server-1", "server-2", "server-3"]
	) == ["server-[1-3]"]


def test_compact_two_segments(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server-1-2", "server-1-1", "server-2-1", "server-2-2"]
	) == ["server-[1-2]-[1-2]"]


def test_round_trip_expand_compact(no_hostname_validation):
	original = {"node1", "node2", "node3"}
	compacted = multiSSH3.compact_hostnames(sorted(original))
	expanded = multiSSH3.__expand_hostname(compacted[0], validate=False)
	assert expanded == original


def test_hosts_only_of_6_32_to_6_38_is_still_accepted(no_hostname_validation):
	assert multiSSH3.compact_hostnames(["node1", "node2"], hosts_only=True) == ["node[1-2]"]
	assert multiSSH3.expand_hostnames(["node1"], hosts_only=True) == multiSSH3.expand_hostnames(["node1"])


def test_shown_names_of_pre_merged_groups_compact_as_one_range():
	assert multiSSH3._compact_shown(["node[1-3]", "node4"]) == ["node[1-4]"]
	assert multiSSH3._compact_shown(["node1,node3", "node2,node4"]) == ["node[1-4]"]
	assert multiSSH3._compact_shown(["node[1-2],gpu1", "gpu2"]) == ["gpu[1-2]", "node[1-2]"]


def test_compact_hostnames_local_takes_names_as_they_are():
	# a public function: names that name no host or are no range come back as they are, as 6.38 gave them
	assert multiSSH3.compact_hostnames_local(["node[10-1]", "node1"]) == ["node1", "node[10-1]"]
	assert multiSSH3.compact_hostnames_local(["node[a]"]) == ["node[a]"]
