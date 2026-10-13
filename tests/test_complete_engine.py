import os
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


def test_passwords_are_never_completed():
	response = query('mssh -p ')
	assert texts(response) == [] and 'nodefault' in response.directives


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


def test_skip_hosts_prefers_members_of_the_hosts_argument(tmp_path):
	table = _host_table(tmp_path, ['n1', 'n2', 'n3', 'm1'])
	assert texts(query('mssh n[2-3] -X ', knowledges=[], hosts=table))[:2] == ['n2', 'n3']


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
