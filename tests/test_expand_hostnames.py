import pytest

import multiSSH3


def test_numeric_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("test[1-3]", validate=False) == {"test1", "test2", "test3"}


def test_letter_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("host[a-c]", validate=False) == {"hosta", "hostb", "hostc"}


def test_padding(no_hostname_validation):
	assert multiSSH3.__expand_hostname("server[001-003]", validate=False) == {
		"server001", "server002", "server003"
	}


def test_comma_mixed(no_hostname_validation):
	assert multiSSH3.__expand_hostname("mixed[a-b,1-2]", validate=False) == {
		"mixeda", "mixedb", "mixed1", "mixed2"
	}


def test_passthrough(no_hostname_validation):
	assert multiSSH3.__expand_hostname("hostname", validate=False) == {"hostname"}
	assert multiSSH3.__expand_hostname("invalid_host", validate=False) == {"invalid_host"}


def test_ipv4_octet_range():
	# Pure IP expand — no DNS validation path
	got = multiSSH3.__expandIPv4Address(["127.0.0.[1-3]"])
	assert got == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_expand_hostnames_loopback_dict():
	d = multiSSH3.expand_hostnames(["127.0.0.1", "127.0.0.2"])
	assert d["127.0.0.1"] == "127.0.0.1"
	assert d["127.0.0.2"] == "127.0.0.2"


def test_hex_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("hex[0-3]", validate=False) == {"hex0", "hex1", "hex2", "hex3"}


def test_complex_mixed_ranges(no_hostname_validation):
	assert multiSSH3.__expand_hostname("complex[a-c,1-2,x]", validate=False) == {
		"complexa", "complexb", "complexc", "complex1", "complex2", "complexx"
	}


def test_hex_uppercase_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("hexrange[A-C]", validate=False) == {
		"hexrangea", "hexrangeb", "hexrangec"
	}


def test_multiple_numeric_ranges(no_hostname_validation):
	assert multiSSH3.__expand_hostname("num[1-2,5-6]", validate=False) == {
		"num1", "num2", "num5", "num6"
	}


def test_overlapping_numeric_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("overlap[3-6,5-8]", validate=False) == {
		"overlap3", "overlap4", "overlap5", "overlap6", "overlap7", "overlap8"
	}


def test_empty_brackets(no_hostname_validation):
	assert multiSSH3.__expand_hostname("empty[]", validate=False) == {"empty"}


def test_invalid_range_passthrough(no_hostname_validation):
	assert multiSSH3.__expand_hostname("invalid[@-%]", validate=False) == {"invalid[@-%]"}


def test_empty_input(no_hostname_validation):
	assert multiSSH3.__expand_hostname("", validate=False) == {""}


def test_hostname_letter_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("hostname[x-z]", validate=False) == {
		"hostnamex", "hostnamey", "hostnamez"
	}


def test_digit_to_letter_combo(no_hostname_validation):
	assert multiSSH3.__expand_hostname("combo[5-a]", validate=False) == {
		"combo8", "combo6", "combo9", "comboa", "combo5", "combo7"
	}


def test_bracketed_first_and_last_octet_ranges_use_ipv4_expansion(monkeypatch):
	def no_validation(hostname):
		raise AssertionError("IPv4 ranges should not go through hostname validation")

	monkeypatch.setattr(multiSSH3, "__validate_expand_hostname", no_validation)

	assert list(multiSSH3.expand_hostnames(["10.0.0.[1-3]"])) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
	assert list(multiSSH3.expand_hostnames(["[10-11].0.0.1"])) == ["10.0.0.1", "11.0.0.1"]


@pytest.fixture
def hermetic_resolution(monkeypatch, tmp_path):
	# no /etc/hosts, env or env file aliases: every name goes to (fake) DNS
	monkeypatch.setattr(multiSSH3, "DEFAULT_HOST_FILE", str(tmp_path / "no-hosts"))
	monkeypatch.setattr(multiSSH3, "_etc_hosts", {})
	monkeypatch.setattr(multiSSH3, "_no_env", True)
	monkeypatch.setattr(multiSSH3, "_env_files", [str(tmp_path / "no-env")])
	multiSSH3.readEnvFromFile.cache_clear()
	multiSSH3.getIP.cache_clear()
	yield
	multiSSH3.getIP.cache_clear()
	multiSSH3.readEnvFromFile.cache_clear()


def test_expanding_a_range_resolves_names_in_parallel(monkeypatch, hermetic_resolution):
	import threading
	import time

	lookups = []
	lock = threading.Lock()

	def slow_dns(hostname):
		time.sleep(0.2)
		with lock:
			lookups.append(hostname)
		return "10.0.0." + hostname[len("node"):]

	monkeypatch.setattr(multiSSH3, "_resolve_dns", slow_dns)
	started = time.monotonic()

	result = multiSSH3.expand_hostnames(["node[1-20]"])

	elapsed = time.monotonic() - started
	assert result == {"node{}".format(i): "10.0.0.{}".format(i) for i in range(1, 21)}
	assert sorted(lookups) == sorted("node{}".format(i) for i in range(1, 21))  # each name once
	assert elapsed < 2  # one after another takes 20 x 0.2 s = 4 s
