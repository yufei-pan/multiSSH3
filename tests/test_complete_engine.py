import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import multiSSH3
import mssh_complete as mc

ENGINE = [sys.executable, '-I', str(Path(__file__).resolve().parents[1] / 'mssh_complete.py')]

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def memory(lines):
	knowledge = mc.MemoryKnowledge()
	knowledge.add_history(lines, SPEC, NOW)
	return knowledge


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su -u=root', 'gpu[01-16]', '"nvidia-smi"') for number in range(5)]
HISTORY += [line(NOW - 50 * number, '-su', 'login1', '"uptime"') for number in range(9)]
HISTORY += [line(NOW - 30, '-su -u=admin', 'storage1', '"df -h /data"')]


def texts(response):
	return [candidate.text for candidate in response.candidates]


def query(before, after='', word=None, shell='bash', knowledges=None, hosts=None, flags=None):
	if word is None:
		word = '' if before.endswith(' ') else before.split(' ')[-1]
	engine = mc.Engine(SPEC, [memory(HISTORY)] if knowledges is None else knowledges, hosts)
	return engine.query(mc.Request(shell, before, after, word, flags=flags))


def test_context_beats_global_frequency():
	# uptime was run more often overall, but on gpu hosts it is nvidia-smi
	assert texts(query('mssh gpu[01-16] "', word=''))[0] == 'nvidia-smi'
	assert texts(query('mssh login1 "', word=''))[0] == 'uptime'


def test_backtracking_uses_the_command_after_the_cursor():
	assert texts(query('mssh ', " 'nvidia-smi'"))[0] == 'gpu[01-16]'
	assert texts(query('mssh ', " 'df -h /data'"))[0] == 'storage1'


def test_values_ranked_by_context():
	assert texts(query('mssh -u ', ' storage1 "df -h /data"'))[0] == 'admin'
	assert texts(query('mssh -u ', ' gpu[01-16]'))[0] == 'root'


def test_every_bash_candidate_extends_the_word():
	for before in ('mssh ', 'mssh g', 'mssh -', 'mssh --n', 'mssh -u r', 'mssh login1 "u', 'mssh login1 up', 'mssh -f=/et'):
		response = query(before)
		word = '' if before.endswith(' ') else before.split(' ')[-1]
		if '"' in word:
			word = word.split('"', 1)[1]
		if '=' in word:
			word = word.split('=', 1)[1]
		assert all(text.startswith(word) for text in texts(response)), before


def test_bash_options_show_long_forms():
	assert set(texts(query('mssh --no_'))) == {'--no_env', '--no_history', '--no_output', '--no_watch', '--no_skip_unreachable'}
	assert set(texts(query('mssh -n'))) == {'-nw', '-nh', '-nsu', '-no'}
	assert '-nw' in texts(query('mssh -n', shell='zsh'))


def test_used_options_are_hidden():
	assert '--no_watch' not in texts(query('mssh -q --no_'))
	assert '--no_skip_unreachable' not in texts(query('mssh -x --no_'))


def test_a_value_starting_with_a_dash_completes_once_it_holds_a_space():
	# argparse takes "-o StrictHostKeyChecking=no" as -ea's value: it names no option and holds a space
	knowledge = memory([line(NOW, '-su -ea="-o StrictHostKeyChecking=no"', 'h', '"uptime"')])
	assert texts(query('mssh -ea "-o Str', word='-o Str', knowledges=[knowledge])) == ['-o StrictHostKeyChecking=no']


def test_passwords_are_never_completed():
	response = query('mssh -p ')
	assert texts(response) == [] and 'nodefault' in response.directives


def spec_with_config_passwords(monkeypatch):
	'''The spec mssh-complete builds while the config sets both passwords (spaces, quotes and % in them).'''
	monkeypatch.setattr(multiSSH3, 'DEFAULT_PASSWORD', "Hunter2 pa%ss it's")
	monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_PASSWORD', 'Bmc 100% s3cret')
	return mc.spec_from_parser(multiSSH3.get_parser())


def holds_a_password(text):
	return 'Hunter2' in text or 's3cret' in text


def test_option_descriptions_never_show_a_configured_password(monkeypatch):
	spec = spec_with_config_passwords(monkeypatch)
	for shell in mc.SHELLS:
		for before in ('mssh -', 'mssh -p', 'mssh --pass', 'mssh -i', 'mssh --ipmi_p', 'mssh -p '):
			response = mc.Engine(spec, [], None).query(mc.Request(shell, before, '', before.split(' ')[-1]))
			assert not holds_a_password(mc.format_response(response, nul=False).decode('utf-8')), (shell, before)
	descriptions = {candidate.text: candidate.description for candidate in mc.Engine(spec, [], None).query(mc.Request('zsh', 'mssh -', '', '-')).candidates}
	assert descriptions['--password'].endswith('via ssh, (default: set, not shown)')
	assert descriptions['-ip'].endswith('via ipmi. (default: set, not shown)')


def test_the_index_spec_holds_no_configured_password(monkeypatch):
	spec = spec_with_config_passwords(monkeypatch)
	assert not [row for row in spec.to_rows() if any(holds_a_password(field) for field in row)]
	assert [option.default for option in spec.options if option.dest in mc.PASSWORD_DESTS] == ['', '']


def test_index_rows_written_before_lose_their_password():
	# indexes built by 0.4 hold the configured passwords in the spec rows: in the default and the help
	rows = [
		['password', '1', '0', '', "Hunter2 pa%ss it's", "The password to use to connect to the hosts via ssh, (default: Hunter2 pa%ss it's)", '-p', '--password'],
		['ipmi_password', '1', '0', '', 'Bmc 100% s3cret', 'The password to use to connect to the hosts via ipmi. (default: Bmc 100% s3cret)', '-ip', '--ipmi_password'],
		['username', '1', '0', '', 'root', 'The general username to use (default: root)', '-u', '--username'],
	]
	spec = mc.ParserSpec.from_rows(rows)
	assert not [option for option in spec.options if holds_a_password(option.default + option.help)]
	assert spec.options[0].help == 'The password to use to connect to the hosts via ssh, (default: set, not shown)'
	assert (spec.options[2].default, spec.options[2].help) == ('root', 'The general username to use (default: root)')
	for before in ('mssh -', 'mssh -p '):
		response = mc.Engine(spec, [], None).query(mc.Request('zsh', before, '', before.split(' ')[-1]))
		assert not holds_a_password(mc.format_response(response, nul=False).decode('utf-8'))


def test_a_password_left_anywhere_in_a_help_is_never_shown():
	# a help that names the password other than as "(default: ...)" loses its text, not just the password
	option = mc.OptionSpec('password', ['-p'], '1', default='Hunter2', help='The password, Hunter2 by default')
	assert not holds_a_password(option.help) and option.help and option.default == ''


def test_option_descriptions_show_a_percent_once(monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_EXTRA_ARGS', '-o ControlPath=~/.ssh/cm-%r@%h:%p')
	option, _ = mc.spec_from_parser(multiSSH3.get_parser()).lookup('-ea')
	assert option.help.endswith('(default: -o ControlPath=~/.ssh/cm-%r@%h:%p)')


def test_path_options_ask_for_files():
	assert 'files' in query('mssh -f ').directives
	assert 'files' in query('mssh -fs ').directives


def test_hosts_complete_the_last_segment():
	assert texts(query('mssh storage1,root@lo'))[0] == 'storage1,root@login1'


def test_magic_strings():
	assert texts(query('mssh h "echo #HO', word='echo #HO')) == ['echo #HOST#', 'echo #HOSTNAME#']


def test_unquoted_command_words():
	assert texts(query('mssh login1 up')) == ['uptime']
	response = query('mssh login1 systemctl rest')
	assert response.delegate == (1, '', ['systemctl', 'rest'])


def test_double_dash_leaves_the_hosts_first():
	# argparse reads the word after "--" as the hosts, then the command
	assert texts(query('mssh -- lo')) == ['login1']
	assert texts(query('mssh -u root -- login1 up')) == ['uptime']
	assert query('mssh -- login1 systemctl rest').delegate == (1, '', ['systemctl', 'rest'])


def test_quoted_command_delegates_with_prefix():
	assert query('mssh h "cat x | gre', word='cat x | gre').delegate == (0, 'cat x | ', ['gre'])


def test_bash_escapes_unquoted_specials():
	knowledge = memory([line(NOW, '-su', 'h', '"date;"')])
	assert texts(query('mssh h da', knowledges=[knowledge])) == [r'date\;']


def test_bash_drops_candidates_that_would_break_the_quote():
	knowledge = memory([line(NOW, '-su', 'h', "'echo \"x\"'"), line(NOW, '-su', 'h', '"echo y"')])
	assert texts(query('mssh h "ech', word='ech', knowledges=[knowledge])) == ['echo y']


def test_bash_drops_candidates_an_ansi_c_quote_would_change():
	# in $'...' a backslash starts an escape: printf "%s\n" x would become printf "%s<newline>" x
	knowledge = memory([line(NOW, '-su', 'h', '\'printf "%s\\n" x\''), line(NOW, '-su', 'h', '"printf ok"')])
	assert texts(query("mssh h 'pri", word='pri', knowledges=[knowledge])) == ['printf "%s\\n" x', 'printf ok']
	assert texts(query("mssh h $'pri", word='pri', knowledges=[knowledge])) == ['printf ok']
	# and the picker, which inserts the text itself
	assert texts(query("mssh h $'pri", word='pri', knowledges=[knowledge], flags={'insert': '1'})) == ['printf ok']


def test_no_candidate_puts_a_bang_inside_double_quotes_where_the_shell_would_expand_it():
	# bash and zsh expand ! inside double quotes when they read the line (history expansion); in bash a
	# backslash there stays in the word
	knowledge = memory([line(NOW, '-su', 'h', "'echo hi!'"), line(NOW, '-su', 'h', '"echo y"')])
	assert texts(query('mssh h "ech', word='ech', knowledges=[knowledge])) == ['echo y']
	assert texts(query("mssh h 'ech", word='ech', knowledges=[knowledge])) == ['echo hi!', 'echo y']
	# zsh's own TAB quotes it there itself; what the picker inserts nobody quotes
	assert texts(query('mssh h "ech', word='"ech', shell='zsh', knowledges=[knowledge])) == ['echo hi!', 'echo y']
	assert texts(query('mssh h "ech', word='"ech', shell='zsh', knowledges=[knowledge], flags={'insert': '1'})) == ['echo y']
	# fish has no history expansion
	assert texts(query('mssh h "ech', word='"ech', shell='fish', knowledges=[knowledge], flags={'insert': '1'})) == ['echo hi!', 'echo y']


def test_word_that_does_not_end_the_parsed_text_gets_nothing():
	assert texts(query('mssh login1 up', word='zz')) == []


def test_zsh_and_fish_words_are_dequoted():
	assert texts(query('mssh gpu[01-16] "nv', word='"nv', shell='fish')) == ['nvidia-smi']


def _host_table(tmp_path, names, aliases=(), groups=(), unavailable=()):
	path = str(tmp_path / 'hosts.nsv')
	number = {name: index for index, name in enumerate(sorted(names))}
	mc.write_nsv(path, {}, [
		('host_names', [sorted(names)]),
		('alias_names', [sorted(name for name, _ in aliases)]),
		('aliases', [['env_file'] + [str(number[member]) for member in members] for _, members in sorted(aliases)]),
		('groups', [[text] + [str(number[member]) for member in members] for text, members in groups]),
		('unavailable', [list(unavailable)]),
	])
	return mc.HostTable(mc.NsvIndex.load(path))


def test_many_hosts_are_grouped(tmp_path):
	names = ['node{:04d}'.format(number) for number in range(1, 2001)]
	table = _host_table(tmp_path, names)
	assert texts(query('mssh no', knowledges=[], hosts=table)) == ['node[0001-2000]']
	narrowed = texts(query('mssh node00', knowledges=[], hosts=table))
	assert narrowed == ['node00[01-99]']
	assert len(texts(query('mssh node000', knowledges=[], hosts=table))) == 9


def test_build_time_groups_are_used_when_they_fit(tmp_path):
	names = ['rack{}-n{}'.format(rack, node) for rack in (1, 2) for node in range(1, 31)]
	groups = [('rack[1-2]-n[1-30]', names)]
	table = _host_table(tmp_path, names, groups=groups)
	assert texts(query('mssh ra', knowledges=[], hosts=table)) == ['rack[1-2]-n[1-30]']


def test_aliases_and_unavailable_hosts(tmp_path):
	table = _host_table(tmp_path, ['a1', 'a2', 'ab'], aliases=[('abc', ['a1', 'a2'])], unavailable=['ab'])
	candidates = query('mssh a', knowledges=[], hosts=table).candidates
	assert [candidate.text for candidate in candidates][0] == 'abc'
	assert candidates[-1].text == 'ab' and candidates[-1].description == 'unreachable recently'


# mssh records a failure under the name it ran the host as, and so looks it up: user@host when a user
# applies (typed with the host, else -u, else the mssh config's), the bare name otherwise

def unreachable_labels(before, table, spec=SPEC):
	'''{candidate: description} for the host candidates of a line, without history.'''
	engine = mc.Engine(spec, [], table)
	response = engine.query(mc.Request('bash', before, '', before.split(' ')[-1]))
	return {candidate.text: candidate.description for candidate in response.candidates}


def test_unreachable_recently_is_for_the_user_typed_with_the_host(tmp_path):
	table = _host_table(tmp_path, ['node04', 'node05'], unavailable=['root@node05', 'node04'])
	assert unreachable_labels('mssh root@node0', table) == {'root@node04': '', 'root@node05': 'unreachable recently'}
	assert unreachable_labels('mssh admin@node0', table) == {'admin@node04': '', 'admin@node05': ''}
	assert unreachable_labels('mssh db1,node0', table) == {'db1,node04': 'unreachable recently', 'db1,node05': ''}


@pytest.mark.parametrize('options', ['-u root ', '-uroot ', '--username=root ', '-u admin -u root '])
def test_unreachable_recently_is_for_the_user_u_gives(tmp_path, options):
	table = _host_table(tmp_path, ['node04', 'node05'], unavailable=['root@node05', 'node04'])
	assert unreachable_labels('mssh {}node0'.format(options), table) == {'node04': '', 'node05': 'unreachable recently'}
	# a user typed with the host comes first
	assert unreachable_labels('mssh {}admin@node0'.format(options), table) == {'admin@node04': '', 'admin@node05': ''}


def test_unreachable_recently_is_for_the_user_of_the_mssh_config(tmp_path, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_USERNAME', 'root')
	spec = mc.spec_from_parser(multiSSH3.get_parser())
	table = _host_table(tmp_path, ['node04', 'node05'], unavailable=['root@node05', 'node04'])
	assert unreachable_labels('mssh node0', table, spec) == {'node04': '', 'node05': 'unreachable recently'}
	assert unreachable_labels('mssh -u admin node0', table, spec) == {'node04': '', 'node05': ''}


def test_skip_hosts_are_labeled_for_the_user_of_the_line(tmp_path):
	# mssh gives the -X hosts the same user
	table = _host_table(tmp_path, ['node04', 'node05'], unavailable=['root@node05', 'node04'])
	assert unreachable_labels('mssh -u root node[04-05] -X node0', table) == {'node04': '', 'node05': 'unreachable recently'}


def test_hosts_unreachable_recently_for_the_user_of_the_line_rank_last(tmp_path):
	table = _host_table(tmp_path, ['node04', 'node05'], unavailable=['root@node04'])
	assert texts(query('mssh root@node0', knowledges=[], hosts=table)) == ['root@node05', 'root@node04']
	assert texts(query('mssh -u root node0', knowledges=[], hosts=table)) == ['node05', 'node04']
	assert texts(query('mssh node0', knowledges=[], hosts=table)) == ['node04', 'node05']


def test_skip_hosts_prefers_members_of_the_hosts_argument(tmp_path):
	table = _host_table(tmp_path, ['n1', 'n2', 'n3', 'm1'])
	assert texts(query('mssh n[2-3] -X ', knowledges=[], hosts=table))[:2] == ['n2', 'n3']


@pytest.mark.parametrize('hosts', ['n[1-9]', 'nn', 'n[1-3],n[4-9]', 'root@nn'])
def test_skip_hosts_prefers_members_up_to_the_member_limit(tmp_path, monkeypatch, hosts):
	# node[00000-49999] -X, or an alias of 50k hosts, listed all 50k members one by one to keep 200
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	names = ['n{}'.format(number) for number in range(1, 10)]
	table = _host_table(tmp_path, names + ['m1'], aliases=[('nn', names)])
	listed = texts(query('mssh {} -X '.format(hosts), knowledges=[], hosts=table))
	assert listed[:4] == ['n1', 'n2', 'n3', 'n4'] and listed.index('m1') < listed.index('n5')


@pytest.mark.parametrize('hosts', ['node[000-999]', 'all', 'root@all'])
@pytest.mark.parametrize('word', ['node9', 'node000,root@node9'])
def test_skip_hosts_prefers_members_with_the_typed_prefix(tmp_path, monkeypatch, hosts, word):
	# the limit counted members from the first one: node[00000-49999] -X node491 listed none of node491xx
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	names = ['node{:03d}'.format(number) for number in range(1000)]
	table = _host_table(tmp_path, names, aliases=[('all', names)])
	lead = word.rpartition('@')[0] + '@' if '@' in word else ''
	assert texts(query('mssh {} -X {}'.format(hosts, word), knowledges=[], hosts=table)) == [
		lead + text for text in ['node9[00-99]', 'node900', 'node901', 'node902', 'node903']]


def test_skip_hosts_of_a_huge_range_are_not_written_out(tmp_path):
	# past expand_ranges' limit a range names no member (it wrote out ten million names to find that out)
	table = _host_table(tmp_path, ['n1', 'n2', 'm1'])
	assert texts(query('mssh n[1-10000000] -X ', knowledges=[], hosts=table)) == ['m1', 'n1', 'n2']


@pytest.mark.parametrize('hosts', ["'a[[b]c[1-2]]'", 'n[[x]1-2]'])
def test_skip_hosts_of_a_range_holding_a_bracket(tmp_path, hosts):
	# a value holding a [ is read again as a range; listing its members raised, and TAB offered nothing
	table = _host_table(tmp_path, ['n1', 'n2', 'm1'])
	assert texts(query('mssh {} -X '.format(hosts), knowledges=[], hosts=table)) == ['m1', 'n1', 'n2']


def _ranges_typed_before():
	'''n[1-3] typed five times, n[4-6] twice.'''
	return [memory([line(NOW - 10 * number, '-su', 'n[1-3]', '"uptime"') for number in range(5)]
		+ [line(NOW - 7 * number, '-su', 'n[4-6]', '"uptime"') for number in range(2)])]


def test_members_of_ranges_typed_before_are_not_listed_beside_them(tmp_path):
	table = _host_table(tmp_path, ['n{}'.format(number) for number in range(1, 10)])
	assert texts(query('mssh n', knowledges=_ranges_typed_before(), hosts=table)) == ['n[1-3]', 'n[4-6]', 'n7', 'n8', 'n9']


def test_hiding_members_of_ranges_stops_at_its_limit(tmp_path, monkeypatch):
	monkeypatch.setattr(mc, 'HIDDEN_MEMBERS_LIMIT', 3)
	table = _host_table(tmp_path, ['n{}'.format(number) for number in range(1, 10)])
	assert texts(query('mssh n', knowledges=_ranges_typed_before(), hosts=table)) == ['n[1-3]', 'n[4-6]', 'n4', 'n5', 'n6', 'n7', 'n8', 'n9']


def test_past_the_deadline_members_of_ranges_are_still_not_listed(tmp_path):
	# a late query listing every member made one group of all hosts top the list (a slow machine,
	# or a short MSSH_COMPLETE_SOFT_DEADLINE): HIDDEN_MEMBERS_LIMIT bounds the work instead
	import time
	table = _host_table(tmp_path, ['n{}'.format(number) for number in range(1, 10)])
	engine = mc.Engine(SPEC, _ranges_typed_before(), table)
	response = engine.query(mc.Request('bash', 'mssh n', '', 'n'), deadline=time.monotonic() - 1)
	assert texts(response) == ['n[1-3]', 'n[4-6]', 'n7', 'n8', 'n9']


def test_a_long_history_of_wide_ranges_is_not_expanded_whole(tmp_path, monkeypatch):
	# 300 ranges of 4,000 hosts typed before: hiding all their members took 300 ms per TAB, past the shells' wait
	history = [line(NOW - number, '-su', 'node[{:05d}-{:05d}]'.format(start, start + 3999), '"uptime"')
		for number, start in enumerate(range(0, 30000, 100))]
	table = _host_table(tmp_path, ['node{:05d}'.format(number) for number in range(0, 34000, 7)])
	expanded = []
	nested = [0]
	expand = mc.expand_ranges

	def counting(text, limit=100000):
		nested[0] += 1
		try:
			out = expand(text, limit)
		finally:
			nested[0] -= 1
		if not nested[0]:
			expanded.append(len(out))
		return out
	monkeypatch.setattr(mc, 'expand_ranges', counting)
	response = query('mssh ', knowledges=[memory(history)], hosts=table)
	assert sum(expanded) < 100000
	# the most used ranges come first, and their members are still not listed
	assert texts(response)[0] == 'node[00000-03999]'
	assert 'node00007' not in texts(response)


def test_protocol_round_trip():
	request = mc.parse_request(b'MSSHC1\0bash\x005.2\0nosort=1 icase=0\0mssh gp\0 x\0gp\0hist one\nhist two\n')
	assert (request.shell, request.flags, request.before, request.after, request.word, request.history) == ('bash', {'nosort': '1', 'icase': '0'}, 'mssh gp', ' x', 'gp', ['hist one', 'hist two'])
	response = mc.Response()
	response.candidates = [mc.Candidate('gpu1', 'a\tb', 'hosts')]
	response.directives = {'nosort'}
	response.delegate = (0, '', [''])
	assert mc.format_response(response) == b'MSSHC1\nD nosort\nC gpu1\ta b\thosts\nX 0\t\t\nE\n\0'
	assert mc.format_response(response, nul=False).endswith(b'E\n')


@pytest.mark.parametrize('data', [b'', b'MSSHC2\0bash\0\0\0a\0\0\0', b'MSSHC1\0bash'])
def test_bad_requests_are_rejected(data):
	with pytest.raises(ValueError):
		mc.parse_request(data)


def test_query_command_end_to_end(tmp_path):
	runtime = tmp_path / 'runtime'
	runtime.mkdir(mode=0o700)
	(tmp_path / '.mssh_history').write_text(''.join(entry + '\n' for entry in HISTORY))
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime))
	request = b'MSSHC1\0bash\x005.2\0nosort=1\0mssh gpu[01-16] "\0\0\0'
	result = subprocess.run(ENGINE + ['query'], input=request, env=env, stdout=subprocess.PIPE, timeout=60)
	assert result.returncode == 0
	assert result.stdout.startswith(b'MSSHC1\nD nosort\nC nvidia-smi\t')
	assert result.stdout.endswith(b'\nE\n\0')


def test_query_command_rejects_garbage(tmp_path):
	result = subprocess.run(ENGINE + ['query'], input=b'hello', stdout=subprocess.PIPE, timeout=60)
	assert result.returncode == 1 and result.stdout == b''


def test_shell_history_ranks_below_mssh_history():
	shell = mc.shell_history_knowledge(['mssh gpu[01-16] "nvidia-smi -q"', 'ls -la', 'nvim notes'], SPEC)
	ranked = texts(query('mssh gpu[01-16] "nvidia', word='nvidia', knowledges=[memory(HISTORY), shell]))
	assert ranked == ['nvidia-smi', 'nvidia-smi -q']
	assert texts(query('mssh h "nv', word='nv', knowledges=[shell])) == ['nvidia-smi -q', 'nvim notes']


def test_quoted_option_values():
	assert texts(query('mssh -u "ro', word='ro')) == ['root']


def test_degraded_mode_without_an_index():
	response = mc.answer(mc.Request('bash', 'mssh --no_w', '', '--no_w', history=['mssh login9 "uptime"']), directory=None)
	assert texts(response) == ['--no_watch']
	assert texts(mc.answer(mc.Request('bash', 'mssh log', '', 'log', history=['mssh login9 "uptime"']), directory=None)) == ['login9']



def test_passwords_in_shell_history_are_never_offered():
	secret = 'Hunter2pw'
	shell = mc.shell_history_knowledge([
		'mssh -p{} gpu[01-16] uptime'.format(secret),
		'sudo mssh -p {} gpu1 uptime'.format(secret),
		'python3 multiSSH3.py --password={} gpu2 uptime'.format(secret),
		'./multiSSH3.py -p={} gpu3 df'.format(secret),
		'cd /tmp && mssh -ip {} gpu4 uptime'.format(secret),
	], SPEC)
	for before, word in (('mssh gpu[01-16] ', ''), ('mssh ', ''), ('mssh -', '-'), ('mssh h "', ''), ('mssh h "sudo', 'sudo'),
			('mssh h "pyth', 'pyth'), ('mssh h "./mu', './mu'), ('mssh h "cd', 'cd'), ('mssh h ', ''), ('mssh h -', '-')):
		for candidate in query(before, word=word, knowledges=[shell]).candidates:
			assert secret not in candidate.text, (before, candidate.text)


def test_passwords_starting_with_a_dash_are_never_offered():
	# argparse stops at these lines (it reads the password as an option), but the shell's history keeps them
	shell = mc.shell_history_knowledge([
		'mssh -p -Tr0ub4dor web1 uptime',
		'mssh --password -Tr0ub4dor web1 uptime',
		'mssh -ip "-my s3cr3t" -M bmc1 power status',
	] + ['mssh -ip "-my p4ss" node1 "df"'] * 3, SPEC)
	engine = mc.Engine(SPEC, [shell])
	for before, word in (('mssh web1 ', ''), ('mssh -m ', ''), ('mssh ', ''), ('mssh -', '-'), ('mssh -M bmc1 ', ''),
			('mssh node1 ', ''), ('mssh h "', ''), ('mssh h -', '-'), ('mssh -u ', '')):
		shown = [candidate.text for candidate in engine.query(mc.Request('bash', before, '', word)).candidates]
		ghost = engine.suggest(mc.Request('bash', before, '', ''))
		shown.append(ghost.text if ghost else '')
		assert not [text for text in shown if 'Tr0ub4dor' in text or 's3cr3t' in text or 'p4ss' in text], (before, shown)


def test_mssh_behind_a_wrapper_is_read_as_mssh():
	shell = mc.shell_history_knowledge(['sudo mssh -u deploy gpu1 "nvidia-smi"'], SPEC)
	assert texts(query('mssh -u ', ' gpu1', knowledges=[shell]))[0] == 'deploy'


def test_huge_typed_host_lists_are_not_offered():
	hosts = ','.join('node{:04d}'.format(number) for number in range(2000))
	knowledge = memory([line(NOW, '-su', hosts, '"uptime"')])
	offered = texts(query('mssh node', knowledges=[knowledge]))
	assert offered and all(len(text) <= 256 for text in offered)


def test_bash_tab_escapes_command_words_bash_would_expand():
	knowledges = [memory([line(NOW - number, '-su', 'node1', '"echo #HOST# ~"') for number in range(5)])]
	assert texts(query('mssh node1 echo ', knowledges=knowledges)) == ['\\#HOST\\#']
	# host ranges are mssh's: bash leaves them as typed
	assert texts(query('mssh gpu', word='gpu'))[0] == 'gpu[01-16]'


def test_file_names_inserted_as_they_are_get_escaped():
	knowledges = [memory([line(NOW - number, "-su -f='my file.txt'", 'node1', '/tmp') for number in range(3)])]
	# the picker inserts the text itself
	assert texts(query('mssh -f my', knowledges=knowledges, flags={'insert': '1'})) == ['my\\ file.txt']
	# bash's own TAB quotes file names itself
	assert texts(query('mssh -f my', knowledges=knowledges)) == ['my file.txt']


def recorded(ts, hosts, *commands):
	'''A history line as mssh records the run of these commands (each as typed in one word).'''
	return '{}\t{}'.format(ts, multiSSH3.getStrCommand(hosts=hosts, commands=list(commands), shortend=True, tabSeperated=True, typed_hosts=True))


def mssh_runs(line_text, monkeypatch):
	'''The remote commands mssh runs for an mssh line, answering its "one command or several" question with the default.'''
	monkeypatch.setattr(multiSSH3, 'input_with_timeout_and_countdown', lambda *args, **kwargs: None)
	handler = signal.getsignal(signal.SIGINT)
	try:
		return multiSSH3.process_commands(multiSSH3.process_args([token.text for token in mc.lex(line_text)[1:]])).commands
	finally:
		signal.signal(signal.SIGINT, handler)


def test_command_words_never_complete_to_a_word_mssh_would_run_alone(monkeypatch):
	# mssh joins the command words into one command only when none of them holds whitespace:
	# `grep connection\ refused /var/log/syslog` runs grep, `connection refused` and /var/log/syslog
	knowledges = [memory([recorded(NOW - number, 'web1', 'grep "connection refused" /var/log/syslog') for number in range(3)]
		+ [recorded(NOW - 10, 'web1', 'grep root /etc/passwd'), recorded(NOW - 20, 'web1', '"/opt/my tool/run" now')])]
	for shell in ('bash', 'zsh', 'fish'):
		assert texts(query('mssh web1 grep ', shell=shell, knowledges=knowledges)) == ['root'], shell
		assert all(len(text.split()) == 1 for text in texts(query('mssh web1 ', shell=shell, knowledges=knowledges))), shell
	for before in ('mssh web1 ', 'mssh web1 grep '):
		for text in texts(query(before, knowledges=knowledges)):
			assert len(mssh_runs(before + text, monkeypatch)) == 1, before + text


def test_next_command_words_keep_the_quotes_history_ran_them_with(monkeypatch):
	# mssh joins the command words as typed: the quotes of 'ssh*' must reach the remote shell, or it
	# runs `systemctl status ssh*` with * matched against its working directory
	knowledges = [memory([recorded(NOW - number, 'web1', "systemctl status 'ssh*'") for number in range(3)])]
	before = 'mssh web1 systemctl status '
	assert texts(query(before, knowledges=knowledges)) == ["\\'ssh\\*\\'"]
	assert mssh_runs(before + "\\'ssh\\*\\'", monkeypatch) == ["systemctl status 'ssh*'"]
	# zsh and fish quote the word themselves
	for shell in ('zsh', 'fish'):
		assert texts(query(before, shell=shell, knowledges=knowledges)) == ["'ssh*'"], shell
	assert texts(query(before + "\\'ss", word="\\'ss", shell='zsh', knowledges=knowledges)) == ["'ssh*'"]


def test_command_words_after_a_quoted_word_follow_history(monkeypatch):
	knowledges = [memory([recorded(NOW - number, 'web1', "grep '^root:' /etc/passwd") for number in range(3)]
		+ [recorded(NOW - 10 - number, 'web1', '"$HOME/bin/report" daily') for number in range(3)])]
	assert texts(query("mssh web1 grep \\'\\^root:\\' ", knowledges=knowledges)) == ['/etc/passwd']
	# the program itself was quoted
	assert '\\"\\$HOME/bin/report\\"' in texts(query('mssh web1 ', knowledges=knowledges))
	before = 'mssh web1 \\"\\$HOME/bin/report\\" '
	assert texts(query(before, knowledges=knowledges)) == ['daily']
	assert mssh_runs(before + 'daily', monkeypatch) == ['"$HOME/bin/report" daily']


def test_ansi_c_quoted_command_words_are_offered_as_typed(monkeypatch):
	# $'a\tb' holds a tab once dequoted: as typed it is one plain word
	knowledges = [memory([recorded(NOW - number, 'web1', "echo $'a\\tb'") for number in range(3)])]
	assert texts(query('mssh web1 echo ', knowledges=knowledges)) == ["\\$\\'a\\\\tb\\'"]
	assert mssh_runs("mssh web1 echo \\$\\'a\\\\tb\\'", monkeypatch) == ["echo $'a\\tb'"]


def test_blesh_gets_candidates_unescaped():
	# ble.sh quotes what it inserts itself, as zsh and fish do: escaped text would be escaped twice
	knowledges = [memory([recorded(NOW - number, 'web1', "systemctl status 'ssh*'", 'echo $HOME') for number in range(3)])]
	assert texts(query('mssh web1 systemctl status ', knowledges=knowledges, flags={'ble': '1'})) == ["'ssh*'"]
	assert texts(query('mssh web1 echo ', knowledges=knowledges, flags={'ble': '1'})) == ['$HOME']
	assert texts(query('mssh web1 echo ', knowledges=knowledges)) == ['\\$HOME']
