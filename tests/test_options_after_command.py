'''
mssh reads its options anywhere on the line, so an option of an unquoted remote command can be read as
mssh's own ("mssh all df -h" prints mssh's help). mssh says so on stderr before it parses the line,
unless the line shows the option was meant for mssh: the shell has removed the quotes by then, so a
command word holding a space or a shell character was quoted, and a display flag at the end of the line
(mssh web1 uptime -q) is most likely mssh's.
'''
import pytest

import multiSSH3


def note(argv):
	return multiSSH3._options_after_the_command_note(argv)


@pytest.mark.parametrize('argv, expected', [
	(['all', 'df', '-h'],
		"Note: mssh read -h after the command 'df' as its own option (--help: mssh prints its help and runs nothing). If it was meant for df, quote the command: mssh all 'df -h'"),
	# changes which hosts run
	(['all', 'uname', '-a'],
		"Note: mssh read -a after the command 'uname' as its own option (--no_skip_unreachable). If it was meant for uname, quote the command: mssh all 'uname -a'"),
	# an option taking a value swallows a word of the command; the display flag at the end is mssh's
	(['web1', 'journalctl', '-u', 'slurmd', '-q'],
		"Note: mssh read -u after the command 'journalctl' as its own option (--username). If it was meant for journalctl, quote the command: mssh web1 'journalctl -u slurmd -q'"),
	# a display flag among the command's words
	(['web1', 'ls', '-a', '/tmp', '-q'],
		"Note: mssh read -a after the command 'ls' as its own option (--no_skip_unreachable). If it was meant for ls, quote the command: mssh web1 'ls -a /tmp -q'"),
	# -g, a display flag after the command's last word, is left out; the quoted command keeps it
	(['web1', 'free', '-g', '-h'],
		"Note: mssh read -h after the command 'free' as its own option (--help: mssh prints its help and runs nothing). If it was meant for free, quote the command: mssh web1 'free -g -h'"),
	# two noted: the wording says so
	(['web1', 'tail', '-a', '-f', '/var/log/x'],
		"Note: mssh read -a, -f after the command 'tail' as its own options (--no_skip_unreachable, --file). If they were meant for tail, quote the command: mssh web1 'tail -a -f /var/log/x'"),
	# a value attached: named without it
	(['web1', 'id', '-uroot'],
		"Note: mssh read -u after the command 'id' as its own option (--username). If it was meant for id, quote the command: mssh web1 'id -uroot'"),
	(['web1', 'tail', '-f', '/var/log/x'],
		"Note: mssh read -f after the command 'tail' as its own option (--file). If it was meant for tail, quote the command: mssh web1 'tail -f /var/log/x'"),
])
def test_an_mssh_option_after_the_command_is_noted(argv, expected):
	assert note(argv) == expected


@pytest.mark.parametrize('argv', [
	['all', 'df -h'],                                           # quoted: one command word
	['gpu[01-16]', 'tail -n 50 /var/log/slurmd.log', '-q'],     # the README's own: quoted, then mssh's -q
	['gpu[01-16]', 'tail -n 50 /var/log/slurmd.log', '-t', '30'],
	['web1', 'echo $HOME', '-j'],                              # a shell character: it was quoted
	['web1', 'grep x|wc', '-u', 'root'],
	['web1', 'uptime', '-q'],                                   # display flags at the end: most likely mssh's
	['web1', 'ps', '-qj'],
	['web1', 'uptime', '-q', '-j', '-Z'],
	['-u', 'root', 'all', 'uptime'],                            # mssh's options before the hosts
	['all', 'uptime'],
	['-h'],                                                     # no command: mssh's own help
	['all', '--', 'df', '-h'],                                  # after "--" every word is the command's
	['all', 'ls', '-la'],                                       # no mssh option: mssh stops with an error that says to quote
	['-u', 'root', 'all'],
	[],
])
def test_nothing_is_noted_where_mssh_reads_no_option_of_the_command(argv):
	assert note(argv) is None


def test_a_value_starting_with_a_dash_is_the_option_s(argv=['-ea', '-o ConnectTimeout=5', 'web1', 'uname', '-a']):
	# argparse takes a word holding a space as a value even when it starts with '-'
	assert note(argv) == ("Note: mssh read -a after the command 'uname' as its own option (--no_skip_unreachable). "
		"If it was meant for uname, quote the command: mssh web1 'uname -a'")
	assert note(['-ea', '-o ConnectTimeout=5', 'web1', 'uptime']) is None


def test_the_word_after_ea_is_its_value_not_an_option():
	# -ea takes the next word whatever it looks like: -h there is ssh's, not mssh's help
	assert note(['web1', 'uptime', '-ea', '-h']) == ("Note: mssh read -ea after the command 'uptime' as its own option (--extraargs). "
		"If it was meant for uptime, quote the command: mssh web1 'uptime -ea -h'")
	assert note(['-ea', '-h', 'web1', 'uptime']) is None
	assert note(['-ia', '-a', 'web1', 'uptime']) is None


def test_a_bare_option_needing_a_value_after_ea_is_not_its_value():
	# mssh stops at it (the quotes were forgotten), and a password after it is never shown
	assert note(['web1', 'mysql', '-ea', '-p', 'hunter2', 'db']) == ("Note: mssh read -ea, -p after the command 'mysql' as its "
		"own options (--extraargs, --password). If they were meant for mysql, quote the command.")


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
