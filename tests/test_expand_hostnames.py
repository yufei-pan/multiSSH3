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


def _fake_addrinfo(*addresses):
	import socket

	def getaddrinfo(host, port, *args, **kwargs):
		if host != "mssh-dual.invalid":
			raise socket.gaierror("not found")
		return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]
	return getaddrinfo


def test_ipv6_only_name_resolves(monkeypatch, hermetic_resolution):
	monkeypatch.setattr(multiSSH3.socket, "getaddrinfo", _fake_addrinfo("2001:db8::5"))

	assert multiSSH3.getIP("mssh-dual.invalid") == "2001:db8::5"


def test_ipv4_is_preferred_when_name_has_both(monkeypatch, hermetic_resolution):
	monkeypatch.setattr(multiSSH3.socket, "getaddrinfo", _fake_addrinfo("2001:db8::5", "192.0.2.5"))

	assert multiSSH3.getIP("mssh-dual.invalid") == "192.0.2.5"


def test_ssh_config_aliases_are_valid_hosts(monkeypatch, tmp_path, hermetic_resolution):
	import shutil

	real_ssh = shutil.which("ssh")
	if not real_ssh:
		pytest.skip("ssh not installed")
	config = tmp_path / "ssh_config"
	config.write_text("Host gpu-alias\n  HostName 127.0.0.7\nHost jump-only\n  ProxyJump bastion\n")
	wrapper = tmp_path / "ssh"
	wrapper.write_text('#!/bin/sh\nexec {} -F {} "$@"\n'.format(real_ssh, config))
	wrapper.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", str(wrapper))
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)  # none of these names are in DNS

	result = multiSSH3.expand_hostnames(["gpu-alias", "jump-only", "typo-host"])

	# the alias gets its HostName's address, the jump host is only reachable through ssh, the typo is rejected
	assert result == {"gpu-alias": "127.0.0.7", "jump-only": None}


@pytest.mark.parametrize("catch_all", ["  HostName %h.corp.example", "  ProxyJump bastion"], ids=["hostname_template", "global_proxyjump"])
def test_catch_all_ssh_config_block_does_not_validate_typos(monkeypatch, tmp_path, hermetic_resolution, catch_all):
	import shutil

	real_ssh = shutil.which("ssh")
	if not real_ssh:
		pytest.skip("ssh not installed")
	config = tmp_path / "ssh_config"
	config.write_text("Host gpu-alias\n  HostName 127.0.0.7\nHost jump-*\n  ProxyJump bastion2\nHost *\n" + catch_all + "\n")
	wrapper = tmp_path / "ssh"
	wrapper.write_text('#!/bin/sh\nexec {} -F {} "$@"\n'.format(real_ssh, config))
	wrapper.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", str(wrapper))
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)

	result = multiSSH3.expand_hostnames(["gpu-alias", "jump-a", "nodee1-typo"])

	assert result == {"gpu-alias": "127.0.0.7", "jump-a": None}


def test_names_already_looked_up_start_no_more_thread_pools(monkeypatch, hermetic_resolution):
	import socket

	pools = []
	run_in_threads = multiSSH3._run_in_threads

	def counting_run_in_threads(*args, **kwargs):
		pools.append(1)
		return run_in_threads(*args, **kwargs)

	monkeypatch.setattr(multiSSH3, "_run_in_threads", counting_run_in_threads)
	monkeypatch.setattr(multiSSH3.socket, "getaddrinfo",
		lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))])
	names = ["dnsnode{}".format(i) for i in range(40)]
	multiSSH3.expand_hostnames(names)

	for i in range(20):  # output merging compacts many slightly different host sets
		multiSSH3.compact_hostnames(names + ["extra{}".format(i)])

	assert len(pools) == 1


def test_invalid_host_counts_once_when_caches_refresh(monkeypatch, hermetic_resolution):
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: None)
	before = multiSSH3.__mainReturnCode
	multiSSH3.expand_hostnames(["mssh-typo-host"])
	monkeypatch.setenv("MSSH_UNRELATED", "changed")  # any env change refreshes the expansion caches
	monkeypatch.setattr(multiSSH3, "_no_env", False)
	multiSSH3._refresh_expansion_caches()

	multiSSH3.expand_hostnames(["mssh-typo-host"])

	assert multiSSH3.__mainReturnCode == before + 1


def test_ssh_config_probe_runs_once_per_prefetch(monkeypatch, hermetic_resolution):
	import subprocess
	import threading
	import time

	probes = []
	lock = threading.Lock()

	def fake_ssh_g(argv, **kwargs):
		name = argv[-1]
		if name == multiSSH3._SSH_CONFIG_PROBE_NAME:
			with lock:
				probes.append(name)
		time.sleep(0.05)
		# a catch-all ProxyJump: every name needs the comparison with the probe
		return subprocess.CompletedProcess(argv, 0, stdout="hostname {}\nproxyjump bastion\n".format(name.lower()))

	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "/bin/ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "run", fake_ssh_g)
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: None)

	assert multiSSH3.expand_hostnames(["nx[1-40]"]) == {}  # all rejected: the catch-all says nothing
	assert len(probes) == 1



def test_first_ctrl_c_does_not_slow_host_expansion(monkeypatch, hermetic_resolution):
	import threading
	import time

	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: time.sleep(0.2))
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: None)
	monkeypatch.setattr(multiSSH3, "_emo", False)
	threading.Timer(0.1, setattr, args=(multiSSH3, "_emo", True)).start()  # Ctrl-C while resolving
	started = time.monotonic()

	multiSSH3.expand_hostnames(["slowhost[1-64]"])

	# in parallel: 2 rounds of 0.2 s; redoing cancelled lookups one by one took (64 - 32) x 0.2 s
	assert time.monotonic() - started < 3


def test_second_ctrl_c_exits_without_waiting_for_lookups(tmp_path):
	import signal
	import subprocess
	import sys
	import time
	from pathlib import Path

	script = tmp_path / "resolve.py"
	script.write_text(
		"import signal, sys, time\n"
		"sys.path.insert(0, {!r})\n"
		"import multiSSH3\n"
		"signal.signal(signal.SIGINT, multiSSH3.signal_handler)\n"
		"multiSSH3._commands_started = True\n"  # e.g. a later --repeat run: the first Ctrl-C only sets the stop flag
		"multiSSH3._resolve_dns = lambda hostname: time.sleep(5)\n"
		"multiSSH3._ssh_config_target = lambda hostname: None\n"
		"print('resolving', flush=True)\n"
		"multiSSH3._prefetch_ips(['slow%d' % i for i in range(64)])\n"
		"time.sleep(30)\n".format(str(Path(multiSSH3.__file__).resolve().parent)))
	proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmp_path)
	assert proc.stdout.readline().strip() == b"resolving"
	time.sleep(0.3)
	proc.send_signal(signal.SIGINT)
	time.sleep(0.3)
	started = time.monotonic()
	proc.send_signal(signal.SIGINT)  # "exiting immediately"
	try:
		proc.wait(timeout=10)
	finally:
		proc.kill()

	assert time.monotonic() - started < 2  # not the 5 s lookups still running
	assert proc.returncode == 1


def test_each_name_is_looked_up_once_when_listed_for_several_users(monkeypatch, hermetic_resolution):
	import threading
	import time

	lookups = []
	lock = threading.Lock()

	def slow_dns(hostname):
		time.sleep(0.05)
		with lock:
			lookups.append(hostname)

	monkeypatch.setattr(multiSSH3, "_resolve_dns", slow_dns)
	monkeypatch.setattr(multiSSH3, "_ssh_config_target", lambda hostname: None)

	multiSSH3.expand_hostnames(["alice@zz[1-20].invalid", "bob@zz[1-20].invalid", "carol@zz[1-20].invalid"])

	assert sorted(lookups) == sorted("zz{}.invalid".format(i) for i in range(1, 21))


def test_getip_looks_a_host_up_once_however_it_is_written(monkeypatch, hermetic_resolution):
	lookups = []
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: lookups.append(hostname) or "10.2.3.4")

	results = {multiSSH3.getIP("bob@n1"), multiSSH3.getIP("n1"), multiSSH3.getIP("n1", local=False), multiSSH3.getIP(" n1 ")}

	assert results == {"10.2.3.4"}
	assert lookups == ["n1"]


def test_catch_all_hostname_template_accepts_names_whose_target_resolves(monkeypatch, tmp_path, hermetic_resolution):
	import shutil

	real_ssh = shutil.which("ssh")
	if not real_ssh:
		pytest.skip("ssh not installed")
	config = tmp_path / "ssh_config"
	config.write_text("Host *\n  HostName %h.corp.example\n")
	wrapper = tmp_path / "ssh"
	wrapper.write_text('#!/bin/sh\nexec {} -F {} "$@"\n'.format(real_ssh, config))
	wrapper.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", str(wrapper))
	# only the full name is in DNS, as with a search domain ssh's config adds itself
	monkeypatch.setattr(multiSSH3, "_resolve_dns", lambda hostname: "10.9.9.1" if hostname == "node1.corp.example" else None)

	result = multiSSH3.expand_hostnames(["node1", "nodee1-typo"])

	assert result == {"node1": "10.9.9.1"}
