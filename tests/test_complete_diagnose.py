'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import argparse
import contextlib
import io
import os
import string
import sys
import types

import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000.0
HOSTS_FILE, HISTORY = mc.SRC_HOSTS_FILE, mc.SRC_HISTORY


def index(tmp_path, hosts, aliases=None):
	'''An index holding hosts (name -> sources) and aliases (name -> members).'''
	names = sorted(hosts)
	number = {name: str(position) for position, name in enumerate(names)}
	aliases = aliases or {}
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {}, [
		('host_names', [names]),
		('host_meta', [[str(hosts[name]), ''] for name in names]),
		('alias_names', [sorted(aliases)]),
		('aliases', [['env'] + [number[member] for member in aliases[name]] for name in sorted(aliases)]),
	])
	return mc.NsvIndex.load(path)


@pytest.fixture
def engine(tmp_path, monkeypatch):
	'''An engine with a runtime directory, a host table and host states; the prober is not started.'''
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)
	started = []
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: started.append(directory) or True)
	directory = tmp_path / 'run'
	directory.mkdir(mode=0o700)
	hosts = {'gpu17': HOSTS_FILE, 'gpu18': HOSTS_FILE, 'login1': HISTORY, 'nodex1': HISTORY, 'nodey1': HISTORY, 'db1': HISTORY, 'ghost1': mc.SRC_ALIAS}
	hosts.update({'node{:02d}'.format(number): HOSTS_FILE for number in range(1, 17)})
	engine = mc.Engine(SPEC, [], mc.HostTable(index(tmp_path, hosts, {'all': ['node01', 'ghost1']})))
	engine.directory = str(directory)
	engine.started = started
	return engine


def seed(engine, **validities):
	mc.write_host_states(engine.directory, {host: mc.HostState(validity, NOW) for host, validity in validities.items()})


def warnings(engine, line, cursor=None, probe=True):
	before, after = line[:cursor], line[cursor:] if cursor is not None else ''
	found, pending = engine.diagnose(mc.Request('bash', before, after, ''), probe=probe, now=NOW)
	return [(line[item.start:item.end], item.kind, item.message) for item in found], pending


def test_an_unknown_host_is_marked_with_the_host_it_was_meant_to_be(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 nvidia-smi') == ([('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')], False)


@pytest.mark.parametrize('options', ['--env_files lab.env ', '-ef lab.env ', '--host_file lab.hosts ', '--config_file lab.json '])
def test_a_line_with_its_own_lookup_files_calls_no_host_unknown(engine, options):
	# mssh reads those files at Enter, from the shell's directory: the prober cannot see what they define
	seed(engine, LABGPUS='invalid', gpu017='invalid')
	assert warnings(engine, 'mssh {}LABGPUS,gpu017 uptime'.format(options))[0] == []


@pytest.mark.parametrize('word', ['LABGPUS', 'root@LABGPUS'])
def test_a_variable_of_the_shell_is_not_an_unknown_host(engine, monkeypatch, word):
	# mssh expands an exported variable named by the hosts word; the prober may run with another environment
	monkeypatch.setenv('LABGPUS', 'node01,node02')
	seed(engine, LABGPUS='invalid')
	assert warnings(engine, 'mssh {} uptime'.format(word))[0] == []


def test_the_word_being_typed_is_left_alone(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017')[0] == []
	# the cursor back inside it: still being edited
	assert warnings(engine, 'mssh gpu017 nvidia-smi', cursor=8)[0] == []


def test_a_host_without_an_answer_yet_is_queued_for_the_prober(engine):
	assert warnings(engine, 'mssh login1,10.0.0.5,gpu17 uptime') == ([], True)
	# all are pinged; an IP address and a hosts-file name need no DNS (they are valid at once)
	assert mc.take_probe_queue(engine.directory) == ['gpu17', '10.0.0.5', 'login1']
	assert engine.started == [engine.directory]


def test_hosts_with_fresh_answers_are_not_queued(engine):
	mc.write_host_states(engine.directory, {
		'login1': mc.HostState('valid', NOW, 'answer', NOW, NOW), 'gpu17': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	assert warnings(engine, 'mssh login1,gpu17 uptime') == ([], False)
	assert mc.take_probe_queue(engine.directory) == []


def test_without_probe_nothing_is_queued(engine):
	assert warnings(engine, 'mssh login1 uptime', probe=False) == ([], True)
	assert mc.take_probe_queue(engine.directory) == [] and engine.started == []


@pytest.mark.parametrize('typed, meant', [
	('gpu017', 'gpu17'),       # zero padding
	('gpu99', None),           # nothing close
	('login2', 'login1'),      # one substitution
	('lgoin1', 'login1'),      # two letters swapped
	('gp17', 'gpu17'),         # one letter left out
	('nodez1', None),          # nodex1 and nodey1 are equally close
	('db2', None),             # too short to guess from one edit
])
def test_did_you_mean_needs_one_clear_candidate(engine, typed, meant):
	seed(engine, **{typed: 'invalid'})
	message = warnings(engine, 'mssh {} uptime'.format(typed))[0][0][2]
	assert message == typed + ': unknown host' + (' — did you mean {}?'.format(meant) if meant else '')


def test_a_host_known_not_to_exist_is_never_suggested(engine):
	seed(engine, gpu017='invalid', gpu17='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host'


def test_each_host_of_a_list_is_marked_on_its_own(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh root@node01,root@gpu017 uptime')[0] == [('root@gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	# inside quotes the whole word is marked
	assert warnings(engine, 'mssh "node01,gpu017" uptime')[0][0][0] == '"node01,gpu017"'


def test_a_range_with_unknown_members_suggests_the_padded_range(engine):
	seed(engine, **{'node{}'.format(number): 'invalid' for number in range(1, 10)})
	assert warnings(engine, 'mssh node[1-16] uptime')[0] == [(
		'node[1-16]', 'range', 'node[1-16]: 9 of 16 hosts unknown (node1, node2, node3, …) — did you mean node[01-16]?')]


def test_a_range_still_being_checked_says_how_far_it_got(engine):
	seed(engine, gpu5='invalid', gpu6='valid')
	assert warnings(engine, 'mssh gpu[1-8] uptime') == ([('gpu[1-8]', 'range', 'gpu[1-8]: 2 of 8 checked, 1 unknown so far')], True)


def test_an_alias_with_unknown_members(engine):
	seed(engine, ghost1='invalid')
	assert warnings(engine, 'mssh all uptime')[0] == [('all', 'range', 'all: 1 of 2 hosts unknown (ghost1)')]


def test_an_ascii_terminal_gets_ascii_messages(engine, monkeypatch):
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: False)
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host - did you mean gpu17?'


def test_a_range_mssh_completion_cannot_expand_says_nothing(engine):
	# letter ranges: nothing is known about their members
	assert warnings(engine, 'mssh node[a-c] uptime') == ([], False)


def test_a_huge_range_is_checked_up_to_the_member_limit(engine, monkeypatch):
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	seed(engine, host1='invalid')
	assert warnings(engine, 'mssh host[1-100000] uptime', probe=False) == ([(
		'host[1-100000]', 'range', 'host[1-100000]: 1 of 100000 checked, 1 unknown so far')], True)


def test_ipv4_ranges_hold_only_addresses(engine):
	# mssh's IPv4 range syntax: ranges, x, * or ? in an octet (found replaying real history)
	assert warnings(engine, 'mssh 127.0.0.1-20,10.0.[1-2].x,10.1.1.* uptime')[0] == []


def test_members_of_an_ipv4_range_are_pinged(engine):
	# addresses need no DNS: they are queued for the prober's ping, as members of other ranges are
	assert warnings(engine, 'mssh 10.0.0.1-3 uptime') == ([], True)
	assert sorted(mc.take_probe_queue(engine.directory)) == ['10.0.0.1', '10.0.0.2', '10.0.0.3']


@pytest.mark.parametrize('pattern', ['192.168.1.1-254', '10.0.[1-2].x', '10.1.1.*', '127.0.0.1-20', '10.0.x-1.?', '[10-11].0.0.5'])
def test_ipv4_ranges_expand_as_mssh_expands_them(pattern):
	members, total = mc._ipv4_members(pattern, limit=100000)
	expanded = getattr(multiSSH3, '__expandIPv4Address')(frozenset([pattern]))
	assert sorted(members) == sorted(expanded) and total == len(expanded)
	# past the limit the total is still counted
	assert mc._ipv4_members(pattern, limit=5) == (members[:5], total)


def test_lines_that_do_not_run_mssh_get_nothing(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'ssh gpu017 uptime') == ([], False)


def test_diag_requests_answer_with_w_records(engine, monkeypatch):
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	seed(engine, gpu017='invalid')
	response = engine.query(mc.Request('bash', 'mssh gpu017,login1 uptime', '', '', flags={'diag': '1'}))
	text = mc.format_response(response, nul=False).decode()
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text
	# the reason line every shell shows under the prompt
	assert 'R ⚠ gpu017: unknown host — did you mean gpu17?\n' in text
	assert '\nR ' not in mc.format_response(mc.Response(None), nul=False).decode()


def unavailable(engine, *hosts, boot='boot-a', left=300):
	'''mssh's unavailable_hosts.csv, as a run that failed on hosts writes it.'''
	expiry = int(mc.time.monotonic()) + left
	with open(os.path.join(engine.directory, 'unavailable_hosts.csv'), 'w') as f:
		f.write('#boot_id,{}\n'.format(boot) + ''.join('{},{}\n'.format(host, expiry) for host in hosts))


@pytest.fixture
def skipping(engine):
	'''Skipping unreachable hosts on by default, as mssh ships.'''
	engine.flag_sets, engine.flag_defaults = mc.flag_settings(multiSSH3.get_parser())
	engine.flag_defaults['skip_unreachable'] = True
	return engine


@pytest.mark.parametrize('options, message', [
	('', 'node05: will be skipped — unreachable in a recent mssh run'),
	('-nsu ', 'node05: unreachable in a recent mssh run'),
	# --script skips unreachable hosts whatever else is given
	('--script -nsu ', 'node05: will be skipped — unreachable in a recent mssh run'),
])
def test_a_host_that_failed_in_a_recent_run(skipping, options, message):
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh {}node05 uptime'.format(options))[0] == [('node05', 'unreachable', message)]


def test_when_skipping_is_off_by_default_only_su_skips(skipping):
	skipping.flag_defaults['skip_unreachable'] = False
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh node05 uptime')[0][0][2] == 'node05: unreachable in a recent mssh run'
	assert warnings(skipping, 'mssh -su node05 uptime')[0][0][2] == 'node05: will be skipped — unreachable in a recent mssh run'


@pytest.mark.parametrize('options', ['--ipmi ', '-su --ipmi ', '--script --ipmi '])
def test_with_ipmi_unreachable_hosts_are_not_skipped(skipping, options):
	# mssh skips them only without --ipmi: powering on a host that is down is what --ipmi is for
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh {}node05 power on'.format(options))[0] == [('node05', 'unreachable', 'node05: unreachable in a recent mssh run')]


def test_with_ipmi_on_by_default_unreachable_hosts_are_not_skipped(skipping):
	skipping.flag_defaults['ipmi'] = True
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh node05 power on')[0][0][2] == 'node05: unreachable in a recent mssh run'


@pytest.mark.parametrize('boot, left', [('boot-b', 300), ('boot-a', -5)], ids=['another_boot', 'expired'])
def test_old_failures_are_forgotten(skipping, boot, left):
	unavailable(skipping, 'node05', boot=boot, left=left)
	assert warnings(skipping, 'mssh node05 uptime')[0] == []


def pinged(engine, host, ping, pinged_ago, answered_ago=None):
	mc.write_host_states(engine.directory, {host: mc.HostState('valid', NOW, ping, NOW - pinged_ago, 0.0 if answered_ago is None else NOW - answered_ago)})


def test_a_host_that_stopped_answering_ping(skipping):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=240)
	assert warnings(skipping, 'mssh login1 uptime') == ([('login1', 'unreachable', 'login1: no answer to ping (answered 4 min ago)')], False)


@pytest.mark.parametrize('pinged_ago, answered_ago', [
	(10, None),   # never answered: ping may be blocked, ssh may still work
	(10, 700),    # answered longer ago than the ping expiry (600 s)
	(90, 120),    # the silent ping is older than a minute: asked again
])
def test_ping_silence_alone_says_nothing(skipping, pinged_ago, answered_ago):
	pinged(skipping, 'login1', 'silent', pinged_ago, answered_ago)
	assert warnings(skipping, 'mssh login1 uptime')[0] == []


def test_the_ping_expiry_follows_mssh_or_the_environment(skipping, monkeypatch):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=700)
	monkeypatch.setenv('MSSH_COMPLETE_PING_TTL', '900')
	assert warnings(skipping, 'mssh login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'
	monkeypatch.delenv('MSSH_COMPLETE_PING_TTL')
	# -uhe on the line is mssh's expiry for this run
	assert warnings(skipping, 'mssh -uhe 900 login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'


def test_unreachable_members_of_a_range(skipping):
	unavailable(skipping, 'node03')
	mc.write_host_states(skipping.directory, {'node07': mc.HostState('valid', NOW, 'silent', NOW - 5, NOW - 60)})
	assert warnings(skipping, 'mssh node[01-08] uptime')[0] == [('node[01-08]', 'unreachable', 'node[01-08]: 2 unreachable (node03, node07)')]


@pytest.mark.parametrize('pattern, down', [
	('192.168.1.1-254', ['192.168.1.5', '192.168.1.9']),
	('10.0.[1-2].x', ['10.0.2.7']),
])
def test_unreachable_members_of_an_ipv4_range(skipping, pattern, down):
	unavailable(skipping, *down)
	assert warnings(skipping, 'mssh {} uptime'.format(pattern))[0] == [
		(pattern, 'unreachable', '{}: {} unreachable ({})'.format(pattern, len(down), ', '.join(down)))]


def test_an_unknown_host_is_not_also_unreachable(skipping):
	seed(skipping, gpu017='invalid')
	unavailable(skipping, 'gpu017')
	assert [kind for _, kind, _ in warnings(skipping, 'mssh gpu017 uptime')[0]] == ['unknown']


def test_options_of_one_exclusive_group(skipping):
	assert warnings(skipping, 'mssh -su -nsu node01 uptime')[0] == [('-nsu', 'options', '-nsu cannot be used with -su (mssh stops with an error)')]
	# the same option twice is allowed
	assert warnings(skipping, 'mssh -su -su node01 uptime')[0] == []


def test_an_option_given_twice(engine):
	assert warnings(engine, 'mssh -u admin -u=root node01 uptime')[0] == [('-u', 'options', '-u given twice: mssh uses root')]
	assert warnings(engine, 'mssh -u root -u root node01 uptime')[0] == []
	# a password never shows
	assert warnings(engine, 'mssh -p one --password=two node01 uptime')[0] == [('-p', 'options', '-p given twice: mssh uses the last one')]
	# the second value is still being typed
	assert warnings(engine, 'mssh -u admin -u ro')[0] == []


@pytest.fixture
def no_effect(skipping):
	skipping.no_effect = [(option, kind, tuple(others), why) for option, kind, others, why in multiSSH3.OPTION_NO_EFFECT]
	skipping.flag_defaults['ipmi'] = False
	return skipping


@pytest.mark.parametrize('line, expected', [
	('mssh --script -nsu node01 true', [('-nsu', 'options', '-nsu does nothing: --script skips unreachable hosts anyway')]),
	('mssh -iu admin node01 true', [('-iu', 'options', '-iu does nothing: only used with --ipmi')]),
	('mssh -M -iu admin node01 true', []),
	('mssh -iu admin --generate_config_file node01 true', []),
	# the message names the option, never the value given with it
	('mssh -ip=secret node01 true', [('-ip=secret', 'options', '-ip does nothing: only used with --ipmi')]),
])
def test_options_that_do_nothing_here(no_effect, line, expected):
	assert warnings(no_effect, line)[0] == expected


def test_settings_used_by_default_are_not_flagged(no_effect):
	# the mssh config turns --ipmi on
	no_effect.flag_defaults['ipmi'] = True
	assert warnings(no_effect, 'mssh -iu admin node01 true')[0] == []


# mssh parses its options among its positionals (parse_intermixed_args): in an unquoted remote command,
# a word naming an mssh option is that option, and any other word starting with '-' stops mssh
STOPS = sys.version_info >= (3, 7)  # Python 3.6 mssh passes unknown options on to the commands


@pytest.mark.parametrize('line, marked, message', [
	('mssh web1 journalctl -u slurmd', '-u', "-u is mssh's --username here — quote the command: 'journalctl -u slurmd'"),
	('mssh web1 tail -f /var/log/x', '-f', "-f is mssh's --file here — quote the command: 'tail -f /var/log/x'"),
	('mssh web1 curl -s http://x/', '-s', "-s is mssh's --file_sync here — quote the command: 'curl -s http://x/'"),
	('mssh web1 hostname -I ', '-I', "-I is mssh's --no_history here — quote the command: 'hostname -I'"),
	('mssh web1 df -h ', '-h', "-h is mssh's --help here — quote the command: 'df -h'"),
	# combined short flags: -aux is -a -u x
	('mssh web1 ps -aux ', '-aux', "-aux is mssh's --no_skip_unreachable and --username here — quote the command: 'ps -aux'"),
	# a short option with its value attached
	('mssh web1 find . -exec cat {} +', '-exec', "-exec is mssh's --encoding here — quote the command: 'find . -exec cat {} +'"),
	# a long name
	('mssh web1 jq --json . f', '--json', "--json is an mssh option here — quote the command: 'jq --json . f'"),
	# options of mssh given after the hosts but before the command are mssh's, as meant
	('mssh web1 -q journalctl -u slurmd', '-u', "-u is mssh's --username here — quote the command: 'journalctl -u slurmd'"),
	# quoting one word does not help: mssh gets the same word
	("mssh web1 ls '-I' /tmp", "'-I'", "-I is mssh's --no_history here — quote the command: \"ls '-I' /tmp\""),
])
def test_a_remote_command_word_mssh_reads_as_its_own_option(engine, line, marked, message):
	assert warnings(engine, line, probe=False)[0] == [(marked, 'command', message)]


@pytest.mark.parametrize('line, marked', [
	('mssh web1 ls -la /tmp', '-la'),
	('mssh web1 head -5 /x', '-5'),
	('mssh web1 ls --color=auto /tmp', '--color=auto'),
	# -q then -n, which mssh does not have
	('mssh web1 foo -qn x', '-qn'),
])
def test_a_remote_command_word_mssh_does_not_know(engine, line, marked):
	name = marked.partition('=')[0]
	expected = [(marked, 'command', '{} is not an mssh option (mssh stops with an error) — quote the command: {!r}'.format(
		name, line[len('mssh web1 '):]))]
	if marked != '-qn' and not STOPS:
		expected = []
	assert warnings(engine, line, probe=False)[0] == expected


def test_an_abbreviation_is_read_as_mssh_reads_it(engine):
	# argparse takes -c for -ci (--copy_id); taking full names only, mssh stops at it with an error
	found = warnings(engine, "mssh web1 bash -c 'echo hi'", probe=False)[0]
	if mc._takes_abbreviations(SPEC):
		assert found == [('-c', 'command', "-c is mssh's --copy_id here — quote the command: \"bash -c 'echo hi'\"")]
	else:
		assert found == ([('-c', 'command', "-c is not an mssh option (mssh stops with an error) — quote the command: \"bash -c 'echo hi'\"")]
			if STOPS else [])


@pytest.mark.parametrize('line', [
	"mssh web1 'journalctl -u slurmd'",
	# after a quoted command, options are mssh's (and the completer offers mssh's)
	"mssh web1 'uptime' -q -u root",
	'mssh -q -u root web1 uptime',
	# after --, every word is a command word
	'mssh web1 -- journalctl -u slurmd',
	'mssh web1 journalctl -- -u slurmd',
	# the shell's: what follows an operator is not mssh's
	'mssh web1 uptime | grep -v load',
	'mssh web1 uptime|grep -v load',
	'mssh web1 uptime; ls -la',
	'mssh web1 uptime && ls -la',
	'mssh web1 uptime > out -la',
	'mssh web1 echo $(date -u)',
	'mssh web1 echo `date -u`',
	'mssh web1 echo #HOST# -u',
	# with -f, -s or -G the commands are paths, and options after them are meant for mssh
	'mssh -f ./data web1 /tmp/ -q',
	'mssh -s=/etc/hosts web1 /etc/ -q',
	'mssh -G web1 ./logs -q',
	# a word with a space in it and no option name is a positional (argparse)
	'mssh web1 echo "-n hello" x',
	# the shell expands it: what mssh gets is not known here
	'mssh web1 ls -$OPTS x',
	'mssh web1 ls -* x',
])
def test_words_mssh_does_not_read_as_options_are_left_alone(engine, line):
	assert warnings(engine, line, probe=False)[0] == []


def test_the_option_being_typed_is_left_alone(engine):
	assert warnings(engine, 'mssh web1 journalctl -u', probe=False)[0] == []
	assert warnings(engine, 'mssh web1 journalctl -u slurmd', cursor=len('mssh web1 journalctl -'), probe=False)[0] == []
	# its value being typed: the option is finished
	assert [marked for marked, _, _ in warnings(engine, 'mssh web1 journalctl -u slu', probe=False)[0]] == ['-u']


@pytest.mark.parametrize('line, marked, message', [
	# -print is -p rint: the warning names -p, never the value, and quotes no command
	('mssh web1 find . -print ', '-print', "-p is mssh's --password here — quote the command"),
	('mssh web1 find . -qprint ', '-qprint', "-qp is mssh's --no_watch and --password here — quote the command"),
	('mssh web1 mysql --password=secret db', '--password=secret', "--password is an mssh option here — quote the command"),
	('mssh web1 sshpass -p secret ssh x', '-p', "-p is mssh's --password here — quote the command"),
])
def test_a_password_is_never_shown(engine, line, marked, message):
	assert warnings(engine, line, probe=False)[0] == [(marked, 'command', message)]


def test_every_other_option_of_a_command_with_a_password_quotes_nothing(engine):
	found = warnings(engine, 'mssh web1 sshpass -p secret ssh -q x', probe=False)[0]
	assert [marked for marked, _, _ in found] == ['-p', '-q']
	assert not any('secret' in message for _, _, message in found)


@pytest.mark.parametrize('line, example', [
	# single quotes inside: the command is shown in double quotes
	("mssh web1 grep -r 'a b' /etc", '"grep -r \'a b\' /etc"'),
	# both kinds of quotes, or a $: no example
	("mssh web1 grep -r 'a b' \"c\" /etc", None),
	("mssh web1 grep -r 'a b' \\$x /etc", None),
	# too long for the reason line
	('mssh web1 grep -r ' + 'x' * 150, None),
])
def test_the_quoted_command_is_shown_when_it_can_be(engine, line, example):
	message = warnings(engine, line, probe=False)[0][0][2]
	assert message == "-r is mssh's --repeat here — quote the command" + (': ' + example if example else '')


def test_a_command_word_read_as_an_option_comes_first(engine):
	seed(engine, gpu017='invalid')
	found = warnings(engine, 'mssh -su -nsu gpu017 journalctl -u slurmd', probe=False)[0]
	assert [kind for _, kind, _ in found] == ['command', 'unknown', 'options']


def test_an_ascii_terminal_gets_an_ascii_dash(engine, monkeypatch):
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: False)
	assert warnings(engine, 'mssh web1 df -h ', probe=False)[0][0][2] == "-h is mssh's --help here - quote the command: 'df -h'"


# words remote commands take, and the forms argparse reads in a way of its own
ORACLE_WORDS = ['-' + letter for letter in string.ascii_letters + string.digits] + [
	'-', '-la', '-al', '-lh', '-ltr', '-rf', '-fr', '-ef', '-aux', '-sh', '-hT', '-nr', '-tulpn', '-name', '-type', '-exec',
	'-print', '-br', '-10', '-11', '-111', '-11x', '-1x', '-1.5', '-.5', '-ci', '-nw', '-no', '-nh', '-su', '-nsu', '-ns', '-qj',
	'-qI', '-Sj', '-xq', '-xa', '-su5', '-pr', '-uh', '-mp', '-ir', '-irl', '-mpr', '-qpr', '-qn', '-qc', '-qu=x', '-a-b', '-Vq',
	'-uroot', '-u=root', '-u=', '-f=', '-q=', '-qj=', '-ipx', '-iux', '-kx', '-ss', '-sx', '-fq', '-Dfoo=bar', '-Xmx2g', '-é',
	'-e hello', '-n hello', '--no pager', '--user x',
	'--help', '--he', '--help=x', '--version', '--ver', '--all', '--color=auto', '--no-pager', '--follow', '--lines=5',
	'--force', '--user', '--user=root', '--user=', '--usernam', '--now', '--quiet', '--json', '--json=x', '--file', '--time',
	'--no', '--s', '--scr', '--host', '--interval', '--in', '--k', '--key', '--ide', '--identity', '--p', '--pass=x',
	'--ipmi', '--ipmi_', '--ipmi_p', '--c', '--co', '--c=y', '--=x', '--conf', '--config', '--config_file', '--config_file=y',
	'--comp', '--completion', '--generate', '--store', '--add', '--table', '--ta', '--max', '--rep', '--no_w', '--single',
	'--skip', '--return', '--enc', '--gather',
]


def mssh_reads(word, parser):
	'''
	What mssh's own parsing makes of `web1 cmd WORD x`: process_args reads --config_file first with a
	parser of its own, then parses the rest intermixed (parse_known_args on Python 3.6). Values are
	not converted and exclusive options are allowed, so only how words are read decides.

	Returns:
		tuple: (the dests of the options argparse took, in order; whether x was an option's value; the
			exit code, None when parsing went through; the words left over (Python 3.6))
	'''
	taken = []

	def recording(parser):
		for action in parser._actions:
			if action.option_strings:
				base = type(action)

				def call(self, parser, namespace, values, option_string=None, base=base):
					taken.append(self.dest)
					return base.__call__(self, parser, namespace, values, option_string)
				action.type = None
				action.__class__ = type(base.__name__, (base,), {'__call__': call})
		parser._mutually_exclusive_groups = []
		return parser

	recording(parser)
	first = type(parser)(add_help=False)
	first.add_argument('--config_file', type=str, nargs='?', const='multiSSH3.config.json', default=None)
	recording(first)
	extras = []
	try:
		with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
			_, rest = first.parse_known_args(['web1', 'cmd', word, 'x'])
			if hasattr(parser, 'parse_intermixed_args'):
				namespace = parser.parse_intermixed_args(rest)
			else:
				namespace, extras = parser.parse_known_args(rest)
	except SystemExit as e:
		return taken, None, e.code, extras
	except Exception:
		# older Pythons crash on some words ("-q="): mssh stops all the same
		return taken, None, 'crash', extras
	return taken, 'x' not in namespace.commands and 'x' not in extras, None, extras


def agrees(word, verdict, readings, outcome):
	'''Whether the engine's reading of a word is what argparse did with it.'''
	taken, took_x, code, extras = outcome
	if verdict == 'positional':
		return (taken, took_x, code) == ([], False, None)
	if verdict == 'unknown':
		return code == 2 if STOPS else (not taken and code is None and word in extras)
	if verdict == 'error':
		return code in (2, 'crash')
	if verdict == 'unsure':
		return True
	dests = []
	for option, attached, _ in readings:
		dests.append(option.dest)
		if option.dest in ('help', 'version'):
			# mssh prints it and exits: the rest of the word is never acted on
			return taken == dests and code == 0
	option, attached, _ = readings[-1]
	return (taken, took_x, code) == (dests, attached is None and option.nargs != '0', None)


def disagreements(parser_factory, abbreviations):
	found = []
	for word in ORACLE_WORDS:
		verdict, readings = mc.read_option_word(word, SPEC, abbreviations)
		outcome = mssh_reads(word, parser_factory())
		if not agrees(word, verdict, readings, outcome):
			found.append((word, verdict, [(option.dest, attached) for option, attached, _ in readings], outcome))
	return found


def test_words_are_read_as_mssh_reads_them():
	assert disagreements(multiSSH3.get_parser, mc._takes_abbreviations(SPEC)) == []


def test_abbreviations_are_taken_as_mssh_takes_them():
	# the spec looks names up as mssh does: abbreviations are read only when mssh reads them
	assert mc._takes_abbreviations(SPEC) is (mssh_reads('--usernam', multiSSH3.get_parser())[0] == ['username'])


class FullNamesParser(argparse.ArgumentParser):
	'''argparse taking option names in full only, as mssh's parser does on patch/no-option-abbrev.'''
	def _get_option_tuples(self, option_string):
		readings = super(FullNamesParser, self)._get_option_tuples(option_string)
		name = option_string.partition('=')[0]
		if any(reading[1] in (name, option_string[:2]) for reading in readings):
			return readings
		return []


def test_words_are_read_as_mssh_reads_them_when_it_takes_full_names_only(monkeypatch):
	# multiSSH3's argparse with that parser (argparse's own code must keep its own ArgumentParser)
	full_names = types.ModuleType('argparse')
	full_names.__dict__.update(argparse.__dict__)
	full_names.ArgumentParser = FullNamesParser
	monkeypatch.setattr(multiSSH3, 'argparse', full_names)
	assert disagreements(multiSSH3.get_parser, False) == []


@pytest.mark.parametrize('word', ['-q=j', '-h=x', '-hz', '-Vz', '-pr=x', "'-q x'", '-qci'])
def test_words_pythons_read_differently_are_left_alone(engine, word):
	# a flag then "=" (-q=j: -q -j on older Pythons, an error on newer ones), help then a letter mssh does
	# not have (-hz: an error, or the help), a name with "=" that abbreviates another (-pr=x: -p r=x, or
	# ambiguous), what follows a letter mssh does not have read again as a word (3.11: -q, "- x" a
	# positional; -q -ci)
	text = mc.lex(word)[0].text
	assert mc.read_option_word(text, SPEC, True)[0] == mc.read_option_word(text, SPEC, False)[0] == 'unsure'
	assert warnings(engine, 'mssh web1 cmd {} x'.format(word), probe=False)[0] == []


def test_the_oracle_covers_every_reading():
	abbreviations = mc._takes_abbreviations(SPEC)
	verdicts = [mc.read_option_word(word, SPEC, abbreviations)[0] for word in ORACLE_WORDS]
	assert {'positional', 'options', 'unknown', 'error'} <= set(verdicts)
	# -qc: -q then -c, an abbreviation of -ci that Python 3.11 reads again (when mssh takes abbreviations)
	unsure = ['-qc'] if abbreviations else []
	assert [word for word, verdict in zip(ORACLE_WORDS, verdicts) if verdict == 'unsure'] == unsure
