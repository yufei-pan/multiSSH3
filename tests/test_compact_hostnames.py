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
