'''
mssh reads its options anywhere on the line, so an option of an unquoted remote command can be read as
mssh's own ("mssh all df -h" prints mssh's help). mssh says so on stderr before it parses the line.
'''
import pytest

import multiSSH3


def note(argv):
	return multiSSH3._options_after_the_command_note(argv)


@pytest.mark.parametrize('argv, expected', [
	(['all', 'df', '-h'],
		"Note: mssh read -h after the command 'df' as its own option (--help: mssh prints its help and runs nothing). To pass it to the command, quote the command: mssh all 'df -h'"),
	(['all', 'uname', '-a'],
		"Note: mssh read -a after the command 'uname' as its own option (--no_skip_unreachable). To pass it to the command, quote the command: mssh all 'uname -a'"),
	(['web1', 'journalctl', '-u', 'slurmd', '-q'],
		"Note: mssh read -u, -q after the command 'journalctl' as its own options (--username, --no_watch). To pass them to the command, quote the command: mssh web1 'journalctl -u slurmd -q'"),
	# short options written together, and one with its value attached (named without it)
	(['web1', 'ps', '-qj'],
		"Note: mssh read -qj after the command 'ps' as its own option (--no_watch, --json). To pass it to the command, quote the command: mssh web1 'ps -qj'"),
	(['web1', 'id', '-uroot'],
		"Note: mssh read -u after the command 'id' as its own option (--username). To pass it to the command, quote the command: mssh web1 'id -uroot'"),
])
def test_an_mssh_option_after_the_command_is_noted(argv, expected):
	assert note(argv) == expected


def test_a_value_starting_with_a_dash_is_the_option_s(argv=['-ea', '-o ConnectTimeout=5', 'web1', 'uptime', '-q']):
	# argparse takes a word holding a space as a value even when it starts with '-'
	assert note(argv) == ("Note: mssh read -q after the command 'uptime' as its own option (--no_watch). "
		"To pass it to the command, quote the command: mssh web1 'uptime -q'")
	assert note(['-ea', '-o ConnectTimeout=5', 'web1', 'uptime']) is None


@pytest.mark.parametrize('argv', [
	['all', 'df -h'],                       # quoted: one command word
	['-u', 'root', 'all', 'uptime'],        # mssh's options before the hosts
	['all', 'uptime'],
	['-h'],                                 # no command: mssh's own help
	['all', '--', 'df', '-h'],              # after "--" every word is the command's
	['all', 'ls', '-la'],                   # no mssh option: mssh stops with an error that says to quote
	['-u', 'root', 'all'],
	[],
])
def test_nothing_is_noted_where_mssh_reads_no_option_of_the_command(argv):
	assert note(argv) is None


@pytest.mark.parametrize('argv, shown', [
	(['web1', 'mysql', '-p', 'secret', 'db'], '-p'),
	# attached to the option: only the option is named
	(['web1', 'mysql', '-psecret', 'db'], '-p'),
	(['web1', 'mysql', '--password=secret', 'db'], '--password'),
	(['web1', 'ps', '-qpsecret'], '-qp'),
	(['web1', 'cmd', '-ip=secret'], '-ip'),
])
def test_a_password_is_never_shown(argv, shown):
	text = note(argv)
	assert text.startswith('Note: mssh read {} after'.format(shown))
	assert 'secret' not in text and text.endswith('quote the command.')


def test_mssh_says_so_before_its_help(capsys):
	with pytest.raises(SystemExit) as exit:
		multiSSH3.main(['all', 'df', '-h'])
	assert exit.value.code == 0
	out, err = capsys.readouterr()
	assert out.startswith('usage:')
	assert "Note: mssh read -h after the command 'df' as its own option" in err
