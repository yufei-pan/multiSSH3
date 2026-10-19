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


def texts_of(candidates):
	return [candidate.text for candidate in candidates]


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
	assert descriptions['--password'].endswith('or set MSSH_PASSWORD. (default: set, not shown)')
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


def _bash_expands_history_in(line):
	"""Whether interactive bash would change line by history expansion (! events), with an event to find."""
	import shutil
	bash = shutil.which('bash')
	if bash is None:
		pytest.skip('needs bash')
	script = 'set -o history -o histexpand; history -s bfoo; history -p -- "$1"'
	result = subprocess.run([bash, '--norc', '--noprofile', '-c', script, 'bash', line], stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, env=dict(os.environ, HISTFILE=os.devnull), universal_newlines=True, timeout=30)
	return result.returncode != 0 or result.stdout.rstrip('\n') != line


def test_a_history_command_word_holding_a_bang_reaches_bash_and_zsh_escaped():
	# quoted-history-args offers history command words with their quotes ("a!b"); bash-glue-minors: no ! the
	# shell would expand. Every way such a word reaches a bash or zsh line escapes the !, inside or outside quotes
	assert _bash_expands_history_in('mssh h grep "a!b" f')  # the oracle sees the danger
	knowledge = memory([line(NOW - number, '-su', 'h', '\'grep "a!b" f\'') for number in range(6)])
	engine = mc.Engine(SPEC, [knowledge])
	inserted = []
	for shell in ('bash', 'zsh'):
		# TAB in bash, and what the picker inserts in both (zsh's own TAB quotes candidates itself)
		for flags in ([None, {'insert': '1'}] if shell == 'bash' else [{'insert': '1'}]):
			inserted += ['mssh h grep ' + text for text in texts(engine.query(mc.Request(shell, 'mssh h grep ', '', '', flags=flags)))]
		# grey text
		for before in ('mssh h gre', 'mssh h grep '):
			ghost = engine.suggest(mc.Request(shell, before, '', ''))
			if ghost is not None:
				inserted.append(before + ghost.text)
	# the bash line editor's TAB
	inserted += ['mssh h grep ' + text for text in mc.editor_completions(engine, 'mssh h grep ')[0]]
	assert any('!' in text for text in inserted)
	assert [text for text in inserted if _bash_expands_history_in(text)] == []

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


# bash with readline's completion-ignore-case on sends icase=1: readline takes a candidate whose case differs
# from the word, so every lookup matches the word in any case, and a candidate keeps its own spelling

# as bash's glue sends it in a UTF-8 locale, with the locale it measured
ICASE = {'icase': '1', 'utf8': '1', 'turkic': '0'}


def test_prefix_ranges_find_every_spelling_differing_only_in_case():
	items = sorted(['AB', 'Ab', 'aB', 'ab', 'abc', 'a', 'b', 'ac'])
	assert mc._prefix_ranges(items, 'ab') == [mc._prefix_range(items, 'ab')]
	assert [text for lo, hi in mc._prefix_ranges(items, 'ab', mc.UNICODE_CASE) for text in items[lo:hi]] == ['AB', 'Ab', 'aB', 'ab', 'abc']
	assert [text for lo, hi in mc._prefix_ranges(items, 'Ab', mc.UNICODE_CASE) for text in items[lo:hi]] == ['AB', 'Ab', 'aB', 'ab', 'abc']
	assert mc._prefix_ranges(items, 'zz', mc.UNICODE_CASE) == []
	assert mc._prefix_ranges(items, '', mc.UNICODE_CASE) == [(0, len(items))]


def test_icase_lookups_and_checks_match_letters_alike():
	# readline compares a character at a time in lower case (towlower): KELVIN SIGN is a k, the I with a dot
	# lowers to an i, the dotless i is no I. The sorted lookups and the checks of single texts agree.
	items = sorted(['\u212aelvin', 'kelvin', 'Kelvin', 'Ix', 'ix', '\u0130stanbul', '\u0131x', 'SS', '\u00df', '\u1e9e'])
	expected = {
		'k': ['Kelvin', 'kelvin', '\u212aelvin'], '\u212a': ['Kelvin', 'kelvin', '\u212aelvin'],
		'i': ['Ix', 'ix', '\u0130stanbul'], '\u0130': ['Ix', 'ix', '\u0130stanbul'], 'I': ['Ix', 'ix', '\u0130stanbul'],
		'\u0131': ['\u0131x'], '\u00df': ['\u00df', '\u1e9e'], 's': ['SS'],
	}
	for prefix, found in expected.items():
		assert sorted(text for lo, hi in mc._prefix_ranges(items, prefix, mc.UNICODE_CASE) for text in items[lo:hi]) == sorted(found), prefix
		assert sorted(text for text in items if mc._starts(text, prefix, mc.UNICODE_CASE)) == sorted(found), prefix


def test_case_variants_are_every_letter_with_the_same_lower_case():
	# what this Python's Unicode data holds: a letter it adds would be matched one way only
	alike = {}
	for point in range(0x110000):
		char = chr(point)
		lower = char.lower()[0]
		if lower != char:
			assert lower.lower()[0] == lower, char
			alike.setdefault(lower, [lower]).append(char)
	assert len(alike) > 1000
	for chars in alike.values():
		for char in chars:
			assert mc.UNICODE_CASE.variants(char) == ''.join(sorted(chars)), (char, chars)


@pytest.mark.parametrize('ascii, turkic', [(False, False), (True, False), (False, True), (True, True)])
def test_text_is_matched_as_its_characters_are(ascii, turkic):
	# CaseFold.same takes a shortcut for ASCII text (upper case): it must agree with the variants
	fold = mc.CaseFold(ascii, turkic)
	chars = [chr(point) for point in range(32, 127)] + ['\u212a', '\u0130', '\u0131', '\u00e9', '\u00c9']
	for typed in chars:
		for char in chars:
			assert mc._starts(char + 'x', typed, fold) == (char in fold.variants(typed)), (char, typed)


@pytest.mark.parametrize('flags, ascii, turkic', [
	({'utf8': '1', 'turkic': '0'}, False, False), ({'utf8': '0', 'turkic': '0'}, True, False),
	({'utf8': '1', 'turkic': '1'}, False, True), ({'utf8': '0', 'turkic': '1'}, True, True)])
def test_case_folds_as_bash_takes_its_locale(flags, ascii, turkic):
	# bash's glue measures how bash counts and lowers characters, which is how readline compares them:
	# towlower in a UTF-8 locale, where a Turkish one lowers I to the dotless i and the I with a dot to i;
	# tolower on bytes elsewhere, where only ASCII letters reach the engine as letters
	fold = mc.case_fold(dict(flags, icase='1'))
	assert (fold.ascii, fold.turkic) == (ascii, turkic)


# how the C library here takes some locale names
OLD_GLUE_CODESETS = {'C.UTF-8': 'UTF-8', 'en_US': 'ISO-8859-1', 'tr_TR.UTF-8': 'UTF-8', 'tr_TR.ISO-8859-9': 'ISO-8859-9',
	'az_AZ.UTF-8': 'UTF-8', 'tt_RU.UTF-8@iqtelif': 'UTF-8', 'tt_RU.UTF-8': 'UTF-8'}


@pytest.fixture
def old_glue_locales(monkeypatch):
	monkeypatch.setattr(mc, '_locale_codeset', lambda name: OLD_GLUE_CODESETS.get(name, 'ANSI_X3.4-1968' if name in ('', 'C', 'POSIX') else None))


@pytest.mark.parametrize('lc, folded, unicode', [
	('C.UTF-8', (False, False), True), ('en_US', (True, False), False), ('C', (True, False), False), ('', (True, False), False),
	('tr_TR.UTF-8', (False, True), True), ('tr_TR.ISO-8859-9', (True, True), False), ('az_AZ.UTF-8', (False, True), True),
	('tt_RU.UTF-8@iqtelif', (False, True), True), ('tt_RU.UTF-8', (False, False), True),
	# a locale the C library has not (macOS's LC_CTYPE=UTF-8 included): bash may run in LANG's, which lc did
	# not say; no matching in any case, as 6.36 did none, and ASCII
	('UTF-8', None, False), ('xx_YY.UTF-8', None, False)])
def test_a_glue_sending_the_locale_name_folds_and_draws_by_it(old_glue_locales, lc, folded, unicode):
	# lc=: the glue of main between 6.36 and its measure (never released), in a shell still running it
	fold = mc.case_fold({'icase': '1', 'lc': lc})
	assert (None if fold is None else (fold.ascii, fold.turkic)) == folded
	# one answer for drawing too: the picker and warnings write ASCII where lc says C or names no locale
	assert mc.engine_for(mc.Request('bash', 'mssh ', flags={'icase': '1', 'lc': lc}), directory=None).unicode is unicode


def test_a_glue_of_6_36_gets_no_matching_in_any_case():
	# 6.36's glue sends icase from a value read once per shell, and nothing of the locale; 6.36's engine
	# matched in the case typed, and so does this one for it (an installed glue file stays until reinstalled)
	assert mc.case_fold({'icase': '1'}) is None
	assert texts(query('mssh LOG', flags={'icase': '1'})) == []
	assert texts(query('mssh LOG', flags=ICASE)) == ['login1']


def test_asking_the_c_library_about_a_locale_leaves_the_process_locale_as_it_was(monkeypatch):
	# _locale_codeset sets LC_CTYPE to the name to ask nl_langinfo, then puts back what it was
	import locale
	monkeypatch.setattr(mc, '_CODESETS', {})
	before = locale.setlocale(locale.LC_CTYPE)
	for name in ('C.UTF-8', 'en_US.UTF-8', 'tr_TR.ISO-8859-9', 'xx_YY.UTF-8', before):
		mc._locale_codeset(name)
		assert locale.setlocale(locale.LC_CTYPE) == before, name
	# the process's own locale is one the C library has; asked once (C, POSIX and '' are not asked)
	assert mc._locale_codeset(before) is not None
	assert before in mc._CODESETS or before in ('C', 'POSIX', '')
	assert mc._locale_codeset('C') == mc._locale_codeset('POSIX') == mc._locale_codeset('')


def test_case_folds_letters_as_ascii_and_turkish_locales_do():
	ascii, turkish, turkish8 = mc.CaseFold(ascii=True), mc.CaseFold(turkic=True), mc.CaseFold(ascii=True, turkic=True)
	assert ascii.variants('a') == 'Aa' and ascii.variants('\u00e9') == '\u00e9' and ascii.variants('\u0130') == '\u0130'
	assert not mc._starts('\u00c9cole', '\u00e9', ascii) and mc._starts('Ecole', 'e', ascii)
	assert turkish.variants('i') == 'i\u0130' and turkish.variants('I') == 'I\u0131' and turkish.variants('\u0131') == 'I\u0131'
	assert turkish.variants('a') == 'Aa'
	assert mc._starts('\u0130stanbul', 'is', turkish) and not mc._starts('Ix', 'i', turkish) and mc._starts('\u0131x', 'I', turkish)
	# in an 8-bit Turkish locale readline lowers I to the dotless i, which is no ASCII letter, and the I with
	# a dot and the dotless i reach it as two UTF-8 bytes it lowers to no i: I and i match only themselves
	assert turkish8.variants('I') == 'I' and turkish8.variants('i') == 'i' and turkish8.variants('a') == 'Aa'
	assert not mc._starts('\u0130stanbul', 'i', turkish8) and not mc._starts('\u0131x', 'I', turkish8)
	assert not mc._starts('Ix', 'i', turkish8) and not mc._starts('ix', 'I', turkish8) and mc._starts('Ax', 'a', turkish8)


def test_icase_matches_letters_as_the_shell_locale_lowers_them(tmp_path):
	table = _host_table(tmp_path, ['\u0130stanbul', 'Ix1', 'ix2', '\u00c9cole', '\u00e9t\u00e91'])
	utf8, ascii, turkish, turkish8 = ({'utf8': '1', 'turkic': '0'}, {'utf8': '0', 'turkic': '0'},
		{'utf8': '1', 'turkic': '1'}, {'utf8': '0', 'turkic': '1'})
	def found(word, flags):
		return sorted(texts(query('mssh ' + word, knowledges=[], hosts=table, flags=dict(flags, icase='1'))))
	assert found('i', utf8) == ['Ix1', 'ix2', '\u0130stanbul'] and found('i', ascii) == ['Ix1', 'ix2']
	assert found('\u00e9', ascii) == ['\u00e9t\u00e91'] and found('\u00e9', utf8) == ['\u00c9cole', '\u00e9t\u00e91']
	assert found('i', turkish) == ['ix2', '\u0130stanbul'] and found('I', turkish) == ['Ix1']
	assert found('i', turkish8) == ['ix2'] and found('I', turkish8) == ['Ix1']


def test_icase_hosts_from_the_index_match_in_any_case(tmp_path):
	table = _host_table(tmp_path, ['Node01', 'node02', 'NODE03', 'login1'], aliases=[('GPUs', ['Node01', 'node02'])])
	assert texts(query('mssh node0', knowledges=[], hosts=table)) == ['node02']
	assert sorted(texts(query('mssh node0', knowledges=[], hosts=table, flags=ICASE))) == ['NODE03', 'Node01', 'node02']
	assert texts(query('mssh gp', knowledges=[], hosts=table, flags=ICASE)) == ['GPUs']
	assert sorted(texts(query('mssh login1,root@no', knowledges=[], hosts=table, flags=ICASE))) == [
		'login1,root@NODE03', 'login1,root@Node01', 'login1,root@node02']


def test_icase_history_matches_in_any_case():
	assert texts(query('mssh LOG')) == []
	assert texts(query('mssh LOG', flags=ICASE)) == ['login1']
	assert texts(query('mssh login1 UP', flags=ICASE)) == ['uptime']
	assert texts(query('mssh login1 "UP', word='UP', flags=ICASE)) == ['uptime']
	assert texts(query('mssh -u ROO', flags=ICASE)) == ['root']
	assert texts(query('mssh h "echo #ho', word='echo #ho', flags=ICASE)) == ['echo #HOST#', 'echo #HOSTNAME#']


CASED_COMMANDS = [line(NOW - number, '-su', 'login1', command) for number, command in enumerate(
	('"systemctl status nginx"', '"systemctl STATUS Nginx"', '"Systemctl Status sshd"'))]


def test_icase_matches_only_the_command_word_being_completed_in_any_case():
	# the words typed before stay as typed, in a quoted command too, where the candidates are whole commands
	knowledges = [memory(CASED_COMMANDS)]
	assert texts(query('mssh login1 systemctl STATUS ', knowledges=knowledges, flags=ICASE)) == ['Nginx']
	assert texts(query('mssh login1 systemctl STATUS NG', knowledges=knowledges, flags=ICASE)) == ['Nginx']
	assert texts(query('mssh login1 "systemctl STATUS ', word='systemctl STATUS ', knowledges=knowledges, flags=ICASE)) == ['systemctl STATUS Nginx']
	assert texts(query('mssh login1 "systemctl STATUS n', word='systemctl STATUS n', knowledges=knowledges, flags=ICASE)) == ['systemctl STATUS Nginx']
	assert sorted(texts(query('mssh login1 "SYSTEMCTL', word='SYSTEMCTL', knowledges=knowledges, flags=ICASE))) == [
		'Systemctl Status sshd', 'systemctl STATUS Nginx', 'systemctl status nginx']
	assert texts(query('mssh login1 "date; systemctl status N', word='date; systemctl status N', knowledges=knowledges, flags=ICASE)) == []


def test_icase_is_answered_back_for_the_words_the_glue_adds():
	# bash's glue adds the words of a command's own completion, and file names: in any case too
	assert 'icase' in query('mssh h nosuchcmd stor', flags=ICASE).directives
	assert 'icase' not in query('mssh h nosuchcmd stor').directives


def test_icase_offers_every_name_differing_only_in_case(monkeypatch):
	# Admin and admin are two accounts: the engine offers both, also when they alone are left; bash's glue,
	# which adds words of its own, puts in one when readline could not tell the words left apart ($USER is
	# offered too)
	monkeypatch.setenv('USER', 'root')
	knowledges = [memory([line(NOW - number, options, 'h', '"grep {} x"'.format(word)) for number, (options, word) in enumerate(
		(('-su -u=Admin', 'Foo'), ('-su -u=admin', 'foo'), ('-su -u=root', 'bar')))])]
	assert sorted(texts(query('mssh -u ', knowledges=knowledges, flags=ICASE))) == ['Admin', 'admin', 'root']
	assert sorted(texts(query('mssh -u a', knowledges=knowledges, flags=ICASE))) == ['Admin', 'admin']
	assert sorted(texts(query('mssh h "grep ', word='grep ', knowledges=knowledges, flags=ICASE))) == ['grep Foo x', 'grep bar x', 'grep foo x']
	assert sorted(texts(query('mssh h "grep F', word='grep F', knowledges=knowledges, flags=ICASE))) == ['grep Foo x', 'grep foo x']


def test_icase_offers_the_candidates_differing_only_in_case_best_first(tmp_path):
	# bash's glue puts in the one in the case typed, else the first: the best
	table = _host_table(tmp_path, ['Storage-East'])
	knowledges = [memory([line(NOW, '-su', 'storage-east', '"uptime"')] + [line(NOW - number, '-su', 'login1', command)
		for number, command in enumerate(('"zzsvc status"', '"zzsvc start"', '"Zzsvc restart"'))])]
	assert texts(query('mssh STORAGE-E', knowledges=knowledges, hosts=table, flags=ICASE)) == ['storage-east', 'Storage-East']
	assert texts(query('mssh STORAGE-E', knowledges=knowledges, hosts=table)) == []
	assert texts(query('mssh login1 ZZ', knowledges=knowledges, flags=ICASE)) == ['zzsvc', 'Zzsvc']


def test_icase_matches_hosts_in_any_case_but_keeps_names_apart(tmp_path):
	# matching in any case decides which names match the word, never that two are one: mssh's aliases (env
	# variables), its list of unreachable hosts (keyed by user@host) and -X compare names exactly
	table = _host_table(tmp_path, ['gpus', 'gpx1', 'Node01', 'node02', 'Web1', 'web2', 'web3', 'm1'],
		aliases=[('GPUs', ['Node01', 'node02'])], unavailable=['web1', 'root@web2'])
	# the host gpus stays the host gpus, the alias GPUs the alias (when only they are left, bash's glue puts in
	# the one in the case typed)
	assert [(candidate.text, candidate.group) for candidate in query('mssh gpus', knowledges=[], hosts=table, flags=ICASE).candidates] == [
		('GPUs', 'aliases'), ('gpus', 'hosts')]
	described = {candidate.text: candidate.description for candidate in query('mssh gp', knowledges=[], hosts=table, flags=ICASE).candidates}
	assert described == {'gpus': '', 'gpx1': '', 'GPUs': 'alias, 2 hosts'}
	# mssh skips web1 and root@web2, not Web1 nor ROOT@web2
	described = {candidate.text: candidate.description for candidate in query('mssh WE', knowledges=[], hosts=table, flags=ICASE).candidates}
	assert described == {'Web1': '', 'web2': '', 'web3': ''}
	described = {candidate.text: candidate.description for candidate in query('mssh ROOT@WE', knowledges=[], hosts=table, flags=ICASE).candidates}
	assert described == {'ROOT@Web1': '', 'ROOT@web2': '', 'ROOT@web3': ''}
	# -X Web1 would not skip web1: for web[1-2] -X prefers web1's and web2's names only
	assert texts(query('mssh web[1-2] -X ', knowledges=[], hosts=table, flags=ICASE))[:1] == ['web2']
	assert 'Web1' in texts(query('mssh web[1-2] -X W', knowledges=[], hosts=table, flags=ICASE))[1:]


def test_icase_aliases_differing_only_in_case_keep_their_own_scores(tmp_path):
	# gpus was used ten times, GPUS never: they shared one score, and GPUS came first by its spelling
	table = _host_table(tmp_path, ['a1', 'a2', 'b1', 'gpx1'], aliases=[('gpus', ['a1', 'a2']), ('GPUS', ['b1'])])
	knowledges = [memory([line(NOW - number, '-su', 'gpus', '"uptime"') for number in range(10)])]
	scored = {candidate.text: candidate.score for candidate in query('mssh gp', knowledges=knowledges, hosts=table, flags=ICASE).candidates}
	assert scored['gpus'] > scored['GPUS'] == pytest.approx(2 * mc.PRIOR)
	# alone, the two are one for readline: bash's glue puts in the first, the best
	table = _host_table(tmp_path, ['a1', 'a2', 'b1'], aliases=[('gpus', ['a1', 'a2']), ('GPUS', ['b1'])])
	assert texts(query('mssh Gp', knowledges=knowledges, hosts=table, flags=ICASE)) == ['gpus', 'GPUS']


def test_icase_range_members_are_the_names_the_range_makes(tmp_path):
	# a range used before hides its members beside it: those it makes, in their case; Web1 is none of web[1-3]'s
	table = _host_table(tmp_path, ['Web1', 'web2', 'web3'])
	knowledges = [memory([line(NOW, '-su', 'web[1-3]', '"uptime"')])]
	assert sorted(texts(query('mssh w', knowledges=knowledges, hosts=table, flags=ICASE))) == ['Web1', 'web[1-3]']
	# Web[1-3] makes Web1, and -X for web[1-2] does not name it (web1 is another name)
	knowledges = [memory([line(NOW, '-su', 'Web[1-3]', '"uptime"')])]
	listed = texts(query('mssh web[1-2] -X W', knowledges=knowledges, hosts=table, flags=ICASE))
	assert 'Web1' not in listed and 'Web[1-3]' in listed and listed[0] == 'web2'


def test_icase_paths_keep_their_directories_as_typed(tmp_path, monkeypatch):
	# readline's own file name completion matches only a path's last part in any case: /Data/pro is no
	# /data/project/b.txt, and readline would replace the directories typed
	knowledges = [memory([line(NOW, '-su -f=/data/project/b.txt', 'h', '"/srv/Data/out"')])]
	assert texts(query('mssh -f /data/pro', knowledges=knowledges, flags=ICASE)) == ['/data/project/b.txt']
	assert texts(query('mssh -f /data/PRO', knowledges=knowledges, flags=ICASE)) == ['/data/project/b.txt']
	assert texts(query('mssh -f /Data/pro', knowledges=knowledges, flags=ICASE)) == []
	assert texts(query('mssh -f /data/project/b.txt h /srv/Data/O', knowledges=knowledges, flags=ICASE)) == ['/srv/Data/out']
	assert texts(query('mssh -f /data/project/b.txt h /srv/data/o', knowledges=knowledges, flags=ICASE)) == []
	(tmp_path / '.ssh').mkdir()
	(tmp_path / '.ssh' / 'id_test').write_text('')
	monkeypatch.setenv('HOME', str(tmp_path))
	assert texts(query('mssh -k ~/.ssh/ID', knowledges=[], flags=ICASE)) == ['~/.ssh/id_test']
	assert texts(query('mssh -k ~/.SSH/id', knowledges=[], flags=ICASE)) == []


def test_icase_command_words_keep_the_directories_of_a_path_as_typed():
	# the word being completed in a remote command is matched as readline matches a file name: only its
	# last part in any case (the directories typed came back in another case)
	knowledges = [memory([line(NOW, '-su', 'h', '"cat /srv/Data/out"'), line(NOW - 1, '-su', 'h', '"/Opt/Tool/run.sh"')])]
	assert texts(query('mssh h cat /srv/data/o', knowledges=knowledges, flags=ICASE)) == []
	assert texts(query('mssh h cat /srv/Data/O', knowledges=knowledges, flags=ICASE)) == ['/srv/Data/out']
	assert texts(query('mssh h "cat /srv/data/o', word='cat /srv/data/o', knowledges=knowledges, flags=ICASE)) == []
	assert texts(query('mssh h "cat /srv/Data/O', word='cat /srv/Data/O', knowledges=knowledges, flags=ICASE)) == ['cat /srv/Data/out']
	assert texts(query('mssh h /opt/tool/r', knowledges=knowledges, flags=ICASE)) == []
	assert texts(query('mssh h /Opt/Tool/R', knowledges=knowledges, flags=ICASE)) == ['/Opt/Tool/run.sh']
	assert texts(query('mssh h CAT /srv', knowledges=knowledges, flags=ICASE)) == []


@pytest.mark.parametrize('before, start', [
	('mssh --no_wa', 0), ('mssh gp', 0), ('mssh a,root@no', len('a,root@')), ('mssh -u ro', 0),
	('mssh web[1-3] -X web1,we', len('web1,')), ('mssh web[1-3] -X=root@we', len('-X=root@')),
	# every separator mssh splits hosts on
	('mssh web[1-3] -X web1/we', len('web1/')), ('mssh web[1-3] -X "web1 root@we', len('web1 root@')),
	('mssh "a;b|c&d\te f', len('a;b|c&d\te ')),
	# every whitespace character str.split() splits on, as mssh splits hosts
	('mssh "a\u00a0b\x0bc\x1fd\x85e\u2003f', len('a\u00a0b\x0bc\x1fd\x85e\u2003')),
	('mssh web[1-3] -X "web1\u00a0root@we', len('web1\u00a0root@')),
	('mssh -f /data/pro', len('/data/')), ('mssh -hf=/etc/ho', len('-hf=/etc/')),
	('mssh h cat /srv/Data/o', len('/srv/Data/')), ('mssh h "cat /srv/Data/o', len('cat /srv/Data/')),
	('mssh h systemctl STATUS ', 0), ('mssh h "systemctl STATUS ', len('systemctl STATUS ')),
	('mssh -f x h /srv/my dir/fi', len('dir/')),
])
def test_where_matching_in_any_case_starts_is_worked_out_once(before, start):
	# the last host after "," and "@", a path's last part, the command word being completed: no earlier text
	assert mc.parse_context(before, '', SPEC).fold_start == start


def test_hosts_split_where_mssh_splits_them():
	text = 'a,b/c;d|e&f g\th\x0bi\x0cj\x1ck\x85l\u00a0m\u2003n'
	assert mc.split_hosts(text) == list('abcdefghijklmn')
	for cut in range(1, len(text)):
		if text[cut - 1] not in 'abcdefghijklmn':
			assert mc._last_host_start(text[:cut] + 'x') == (cut, cut), repr(text[:cut])
	assert mc._last_host_start('a b\u00a0root@we') == (len('a b\u00a0'), len('a b\u00a0root@'))


def test_hosts_are_split_as_mssh_splits_them_at_every_code_point():
	# against mssh's own split: a change of its separators fails here. Each code point between two letters
	everything = ''.join(map(chr, range(0x110000)))
	text = 'x'.join(everything)
	split = multiSSH3._split_host_str(text)
	word, cut = mc._host_patterns()
	assert mc.split_hosts(text) == split and word.findall(text) == split
	# the cut stops after a code point exactly where a host word cannot hold it
	assert [char for char in everything if cut.match('a' + char + 'b')] == [char for char in everything if not word.fullmatch(char)]
	assert len(split) == 35


def test_frame_drops_candidates_matching_earlier_text_in_any_case():
	# whatever a provider found: the text before where matching in any case starts must be as typed
	engine = mc.Engine(SPEC, [], None)
	request = mc.Request('bash', 'mssh web[1-3] -X web1,we', '', 'web1,we', flags=ICASE)
	context = mc.parse_context(request.before, request.after, SPEC)
	context.icase = mc.UNICODE_CASE
	candidates = [mc.Candidate(text, '', 'history', 1.0) for text in ('WEB1,web2', 'web1,WEB3', 'web1,web2')]
	assert texts_of(engine._frame(candidates, context, request)) == ['web1,WEB3', 'web1,web2']


def test_icase_hosts_after_x_match_only_the_host_typed_in_any_case():
	# -X's history matched the whole value in any case: web1,we was offered WEB1,web2, root@we ROOT@web1
	knowledges = [memory([line(NOW, '-su -X=WEB1,web2', 'web[1-3]', '"uptime"'), line(NOW - 1, '-su -X=ROOT@web1', 'web[1-3]', '"uptime"')])]
	assert 'WEB1,web2' not in texts(query('mssh web[1-3] -X web1,we', knowledges=knowledges, flags=ICASE))
	assert 'ROOT@web1' not in texts(query('mssh web[1-3] -X root@we', knowledges=knowledges, flags=ICASE))
	assert 'WEB1,web2' in texts(query('mssh web[1-3] -X WEB1,We', knowledges=knowledges, flags=ICASE))
	# hosts split on "/", ";", "|", "&" and whitespace too
	knowledges = [memory([line(NOW, '-su -X=WEB1/web2', 'web[1-3]', '"uptime"'), line(NOW - 1, '-su', 'WEB1 web2', '"uptime"')])]
	assert 'WEB1/web2' not in texts(query('mssh web[1-3] -X web1/we', knowledges=knowledges, flags=ICASE))
	assert 'WEB1 web2' not in texts(query('mssh "web1 we', word='web1 we', knowledges=knowledges, flags=ICASE))
	assert 'WEB1/web2' in texts(query('mssh web[1-3] -X WEB1/We', knowledges=knowledges, flags=ICASE))


def test_prefix_ranges_match_in_any_case_from_start_on():
	items = sorted(['AB x', 'ab X', 'ab x', 'ab y', 'Ab X'])
	assert [text for lo, hi in mc._prefix_ranges(items, 'ab x', mc.UNICODE_CASE, 3) for text in items[lo:hi]] == ['ab X', 'ab x']
	assert [text for lo, hi in mc._prefix_ranges(items, 'ab ', mc.UNICODE_CASE, 3) for text in items[lo:hi]] == ['ab X', 'ab x', 'ab y']
	assert mc._prefix_ranges(items, 'aB x', mc.UNICODE_CASE, 3) == []


def test_icase_matches_option_names_in_any_case_only_where_the_word_names_none_as_typed():
	# readline, finding no candidate in the case typed, puts in the first one's spelling: -S, which starts an
	# option name as typed (a used one too), must never become -s (-q -S<TAB> gave -s, --file_sync)
	assert texts(query('mssh --NO_WA', flags=ICASE)) == ['--no_watch']
	assert texts(query('mssh -SU', flags=ICASE)) == ['-su']
	assert texts(query('mssh -s', flags=ICASE)) == texts(query('mssh -s'))
	assert texts(query('mssh -S', flags=ICASE)) == ['-S']
	for before in ('mssh -q -S', 'mssh --scp -W', 'mssh -nh -I'):
		assert texts(query(before, flags=ICASE)) == [], before


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
	# no index yet: the query waits for the first build only until just before its deadline (then answers
	# without history), so give it time to wait on a slow machine; that race has tests of its own
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime), MSSH_COMPLETE_SOFT_DEADLINE='5')
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
