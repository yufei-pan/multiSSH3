'''
How mssh reads words starting with '-' (parsing only: nothing here runs a command).

mssh takes its options anywhere on the line, also among the words of the remote command. A word is
an mssh option by its full name ('-u', '--username', '-u=root', '-uroot') or as short flags written
together ('-qj'); an abbreviation of an option name is not one: 'bash -c' must not turn on -ci.
'''
import argparse

import pytest

import multiSSH3

# Python 3.6 has no parse_intermixed_args: mssh then hands the words it does not know to the commands
INTERMIXED = hasattr(argparse.ArgumentParser, 'parse_intermixed_args')


def _process(argv, capsys):
	'''process_args(argv): (namespace, or None when mssh stopped with an error; stderr)'''
	try:
		args = multiSSH3.process_args(list(argv))
	except SystemExit as stop:
		assert stop.code == 2
		args = None
	return args, capsys.readouterr().err


# remote command words, and the mssh option argparse used to read each as by a prefix of its name
ABBREVIATIONS = [
	('-c', 'copy_id'),  # bash -c, python3 -c
	('-1', 'oneonone'),  # ls -1
	('-d', 'diff_display_threshold'),
	('-n', None),  # tail -n: was "ambiguous option"
	('--user', 'username'),  # journalctl --user
	('--user=root', 'username'),
	('--force', 'force_truecolor'),
	('--host', 'host_file'),
	('--gen', 'generate_config_file'),
	('--store', 'store_config_file'),
	('--add', 'add_control_master_config'),
	('--scr', 'script'),
	('--ta', 'greppable'),
	('--no_w', 'no_watch'),
	('--ipmi_p', 'ipmi_password'),
	('--time', 'timeout'),
	('--conf', 'config_file'),
	('--c', 'config_file'),  # only the --config_file pre-parser read this one
]


@pytest.mark.parametrize('word, dest', ABBREVIATIONS)
def test_a_word_is_never_read_as_an_option_it_abbreviates(word, dest, capsys):
	baseline = vars(multiSSH3.process_args(['web1', 'cmd']))
	capsys.readouterr()
	args, err = _process(['web1', 'cmd', word, 'value'], capsys)
	if INTERMIXED:
		assert args is None
		assert 'unrecognized arguments: ' + word in err
	else:
		assert args.commands == ['cmd', word, 'value']
		assert dest is None or getattr(args, dest) == baseline[dest]
		assert 'treating all as commands' in err


def test_bash_dash_c_never_runs_ssh_copy_id(capsys):
	args, err = _process(['web1', 'bash', '-c', 'echo hi'], capsys)
	if INTERMIXED:
		assert args is None
	else:
		assert (args.copy_id, args.commands) == (False, ['bash', '-c', 'echo hi'])


@pytest.mark.parametrize('argv', [
	['web1', 'ls', '-la'],  # not an mssh option
	['web1', 'bash', '-c', 'echo hi'],  # was an abbreviation of -ci
	['web1', 'ss', '-tulpn'],  # -t (timeout) with the value 'ulpn'
	['web1', 'cp', '-pr', 'a', 'b'],  # -p (password) 'r', or -pre
])
def test_errors_for_option_words_say_to_quote_the_remote_command(argv, capsys):
	args, err = _process(argv, capsys)
	assert multiSSH3.REMOTE_OPTIONS_HINT in err
	if not INTERMIXED and args is not None:
		# Python 3.6 ran them as command words, and says how to pass them on as one command
		assert 'treating all as commands' in err


def test_the_hint_names_quoting_as_the_way_to_pass_options():
	assert "quote the whole command" in multiSSH3.REMOTE_OPTIONS_HINT
	assert "mssh web1 'ls -la'" in multiSSH3.REMOTE_OPTIONS_HINT


def test_a_word_read_two_ways_still_stops_mssh(capsys):
	# -pr is -p with the value 'r', or an abbreviation of -pre: argparse always called it ambiguous,
	# and dropping the abbreviation must not make it a password
	args, err = _process(['web1', 'cp', '-pr', 'a', 'b'], capsys)
	assert args is None
	assert 'ambiguous option: -pr' in err


def test_help_says_how_to_pass_options_to_the_remote_command(capsys):
	# mssh web1 df -h: -h is mssh's own help, so the help ends with how to quote the command
	with pytest.raises(SystemExit) as stop:
		multiSSH3.process_args(['web1', 'df', '-h'])
	assert stop.value.code == 0
	out = capsys.readouterr().out
	assert out.rstrip().endswith(multiSSH3.REMOTE_OPTIONS_HINT)


QUIET = {'no_watch': True}
SCRIPT_FLAGS = {'no_watch': True, 'no_env': True, 'error_only': True, 'no_history': True, 'greppable': True, 'use_script_timeout': True}


@pytest.mark.parametrize('words, expected', [
	# short flags written together, as the --script help text says (-SCRIPT)
	(['-qj'], dict(QUIET, json=True)),
	(['-qI'], dict(QUIET, no_history=True)),
	(['-SCRIPT'], SCRIPT_FLAGS),
	(['-xq'], dict(QUIET, skip_unreachable=True)),
	(['-qu', 'root'], dict(QUIET, username='root')),
	(['-qt30'], dict(QUIET, timeout=30)),
	# a short option with its value attached
	(['-uroot'], {'username': 'root'}),
	(['-t30'], {'timeout': 30}),
	(['-pS3c=t'], {'password': 'S3c=t'}),
	# full names, with or without '='
	(['-u=root'], {'username': 'root'}),
	(['--username=root'], {'username': 'root'}),
	(['--username', 'root'], {'username': 'root'}),
	(['-ea=--delete'], {'extraargs': '--delete'}),
	(['-11'], {'oneonone': True}),
	(['-ci'], {'copy_id': True}),
	(['-nsu'], {'skip_unreachable': False}),
	(['--no_watch'], QUIET),
])
def test_option_forms_mssh_reads(words, expected, capsys):
	for argv in (words + ['web1', 'cmd'], ['web1', 'cmd'] + words):
		args = multiSSH3.process_args(argv)
		assert {dest: getattr(args, dest) for dest in expected} == expected, argv
		assert (args.hosts, args.commands) == ('web1', ['cmd']), argv
	assert capsys.readouterr().err == ''


def test_an_option_name_after_the_command_is_still_an_mssh_option():
	# owner decision: an exact option name is mssh's anywhere on the line ("mssh hosts cmd -q"),
	# so "mssh web1 grep -q foo" runs "grep foo" without the curses window
	args = multiSSH3.process_args(['web1', 'grep', '-q', 'foo'])
	assert (args.commands, args.no_watch) == (['grep', 'foo'], True)
