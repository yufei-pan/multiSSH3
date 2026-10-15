import argparse

import pytest

import multiSSH3


def test_form_command_arg_str_common_flags():
	s = multiSSH3.__formCommandArgStr(
		scp=True,
		ipmi=True,
		json=True,
		no_watch=True,
		no_env=True,
		no_history=True,
		oneonone=True,
		gather_mode=True,
		file=["/tmp/a"],
		timeout=9,
		repeat=2,
		interval=1,
	)
	assert "--scp" in s
	assert "--ipmi" in s
	assert "--json" in s or "-j" in s
	assert "--no_watch" in s or "-q" in s
	assert "--no_env" in s
	assert "--oneonone" in s or "-11" in s
	assert "--timeout=9" in s or "-t=9" in s
	assert "--file=" in s or "-f=" in s


def test_form_command_arg_str_shortend():
	s = multiSSH3.__formCommandArgStr(shortend=True, scp=True, no_watch=True, json=True)
	assert "--scp" in s
	assert "-q" in s
	assert "-j" in s


def test_process_args_basic():
	args = multiSSH3.process_args(["127.0.0.1", "echo", "hi", "-q", "-I"])
	assert args.hosts == "127.0.0.1"
	assert args.commands == ["echo", "hi"]
	assert args.no_watch is True
	assert args.no_history is True


# What Python 3.12.8+ / 3.13.1+ argparse makes of each line (CPython gh-81691, gh-125355), on every Python:
# the first "--" ends the options; the next word is the hosts unless they came before it, and every later
# word is a command word, dash words and a later "--" included. hosts None: the default hosts.
DOUBLE_DASH_LINES = [
	('-- h c', 'h', ['c'], {}),
	('-- h c d', 'h', ['c', 'd'], {}),
	('h -- c', 'h', ['c'], {}),
	('h -- c d', 'h', ['c', 'd'], {}),
	('h -- -x', 'h', ['-x'], {}),
	('h c -- -x', 'h', ['c', '-x'], {}),
	('h c -- -u y', 'h', ['c', '-u', 'y'], {}),
	('h c d -- e -f', 'h', ['c', 'd', 'e', '-f'], {}),
	# a dash word right after it is the hosts, and options after it are command words
	('-- -weirdhost c', '-weirdhost', ['c'], {}),
	('-- -u y', '-u', ['y'], {}),
	('-- h -u y', 'h', ['-u', 'y'], {}),
	('-- h -q', 'h', ['-q'], {}),
	('-- h c -q', 'h', ['c', '-q'], {}),
	('-- h c -u y', 'h', ['c', '-u', 'y'], {}),
	('-- h -zz', 'h', ['-zz'], {}),
	('-u x -- h c', 'h', ['c'], {'username': 'x'}),
	('-u=x -- h c', 'h', ['c'], {'username': 'x'}),
	('-u x -- h -q', 'h', ['-q'], {'username': 'x'}),
	('-q -- h c', 'h', ['c'], {'no_watch': True}),
	('-q -- h -u y', 'h', ['-u', 'y'], {'no_watch': True}),
	('-u y -- -h', '-h', [], {'username': 'y'}),
	('-11 -- h c d', 'h', ['c', 'd'], {'oneonone': True}),
	# only the first "--" is dropped
	('-- h -- c', 'h', ['--', 'c'], {}),
	('-- -- c', '--', ['c'], {}),
	('-- -- --', '--', ['--'], {}),
	('h -- -- c', 'h', ['--', 'c'], {}),
	('-- h -- -- c', 'h', ['--', '--', 'c'], {}),
	('-- h c -- d', 'h', ['c', '--', 'd'], {}),
	('h -- c -- d', 'h', ['c', '--', 'd'], {}),
	('-- h c --', 'h', ['c', '--'], {}),
	('h c -- --', 'h', ['c', '--'], {}),
	# nothing before it or after it
	('--', None, [], {}),
	('-- h', 'h', [], {}),
	('h --', 'h', [], {}),
	('h c --', 'h', ['c'], {}),
	('-u y --', None, [], {'username': 'y'}),
	# options between the hosts, the command words and it
	('h -u y -- c', 'h', ['c'], {'username': 'y'}),
	('h -q -- c', 'h', ['c'], {'no_watch': True}),
	('h c -q -- d', 'h', ['c', 'd'], {'no_watch': True}),
	('-u y h -- -c x', 'h', ['-c', 'x'], {'username': 'y'}),
	# an option whose value is optional stops at it
	('-k -- h c', 'h', ['c'], {'identity_file': multiSSH3.DEFAULT_SSH_KEY_SEARCH_PATH}),
	('-fs -- allServers ./data/', 'allServers', ['./data/'], {'file_sync': True}),
	('h -- --config_file x', 'h', ['--config_file', 'x'], {}),
	# no "--"
	('-q h c', 'h', ['c'], {'no_watch': True}),
	('h c', 'h', ['c'], {}),
]


@pytest.mark.parametrize('line, hosts, commands, options', DOUBLE_DASH_LINES)
def test_double_dash_reads_as_python_3_12_8_does(line, hosts, commands, options, capsys):
	baseline = vars(multiSSH3.process_args([]))
	args = multiSSH3.process_args(line.split())
	expected = dict(baseline, hosts=baseline['hosts'] if hosts is None else hosts, commands=commands, **options)
	assert vars(args) == expected
	assert capsys.readouterr().err == ''


def test_option_without_its_value_before_double_dash(capsys):
	with pytest.raises(SystemExit) as caught:
		multiSSH3.process_args(['-u', '--', 'h', 'c'])
	assert caught.value.code == 2
	assert 'argument -u/--username: expected one argument' in capsys.readouterr().err


def test_unknown_option_before_double_dash(capsys):
	if hasattr(argparse.ArgumentParser, 'parse_intermixed_args'):
		with pytest.raises(SystemExit) as caught:
			multiSSH3.process_args(['-zz', '--', 'h', 'c'])
		assert caught.value.code == 2
		assert 'unrecognized arguments: -zz' in capsys.readouterr().err
	else:
		# Python 3.6 has no intermixed parsing: what it cannot place before the "--" becomes command words,
		# in front of the words after it
		args = multiSSH3.process_args(['-zz', '--', 'h', 'c'])
		assert (args.hosts, args.commands) == ('h', ['-zz', 'c'])
		assert "Unknown arguments, treating all as commands: ['-zz']" in capsys.readouterr().err


@pytest.mark.parametrize('line, commands, username', [
	('h c -q d -- e', ['c', 'd', 'e'], None),
	('-u x h -q c -- d -u z', ['c', 'd', '-u', 'z'], 'x'),
])
def test_words_after_double_dash_follow_the_intermixed_ones(line, commands, username):
	# Python 3.6 has no intermixed parsing: it takes "d" (or "c") after the option as a leftover, with a
	# warning; the words after the "--" still come after it
	args = multiSSH3.process_args(line.split())
	assert (args.hosts, args.commands, args.no_watch, args.username) == ('h', commands, True, username)


def test_process_commands_joins_one_word_default(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "echo", "hi"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *a, **k: "1")
	args = multiSSH3.process_commands(args)
	assert args.commands == ["echo hi"]


def test_process_commands_keeps_multiple(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "echo", "hi"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *a, **k: "m")
	args = multiSSH3.process_commands(args)
	assert args.commands == ["echo", "hi"]


def test_set_global_with_args():
	args = multiSSH3.get_parser().parse_args(
		["127.0.0.1", "true", "--debug", "-e", "latin-1", "-Z", "--force_truecolor", "-dt", "0.5"]
	)
	multiSSH3.set_global_with_args(args)
	assert multiSSH3.__DEBUG_MODE is True
	assert multiSSH3._encoding == "latin-1"
	assert multiSSH3.__returnZero is True
	assert multiSSH3.FORCE_TRUECOLOR is True
	assert multiSSH3.DEFAULT_DIFF_DISPLAY_THRESHOLD == 0.5


def test_generate_default_config_keys():
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true"])
	cfg = multiSSH3.generate_default_config(args)
	assert cfg["DEFAULT_HOSTS"] == "127.0.0.1"
	assert "DEFAULT_TIMEOUT" in cfg
	assert cfg["AUTHOR"] == multiSSH3.AUTHOR
	assert "DEFAULT_IPMI_ARGS" in cfg
	assert "DEAFULT_IPMI_ARGS" not in cfg


def test_echoed_command_round_trips_through_bash(monkeypatch, tmp_path):
	import shutil
	import subprocess

	import pytest

	if not shutil.which("bash"):
		pytest.skip("bash not installed")
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	(tmp_path / "node1").write_text("")  # an unquoted node[1-3] would glob to this file
	commands = ["echo $HOSTNAME `id` it's \\$x !", "line1\nline2\tend"]

	line = multiSSH3.getStrCommand(hosts="node1,node2,node3", commands=commands, password="p$w'd")
	parsed = subprocess.run(["bash", "-c", "printf '%s\\0' " + line], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
		cwd=tmp_path, check=True).stdout.split("\0")[:-1]
	args = multiSSH3.process_args(parsed[1:])

	assert args.hosts == "node[1-3]"
	assert args.commands == commands
	# the password is not echoed: -p - asks for it
	assert args.password == "-" and "p$w" not in line
