import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())


def test_synthetic_history_is_deterministic():
	assert mc.synthetic_history(seed=3, entries=50) == mc.synthetic_history(seed=3, entries=50)
	assert all(mc.parse_history_line(line, SPEC) is not None for line in mc.synthetic_history(entries=200))


def test_tab_never_alters_typed_text():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150)
	assert totals
	assert sum(total['altered'] for total in totals.values()) == 0


def test_bash_tab_never_inserts_the_wrong_thing_on_synthetic_history():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash',))
	assert all(total['divergent'] == 0 for total in totals.values())


def test_completion_saves_typing_on_synthetic_history():
	# a floor that catches ranking regressions; the real numbers are tuned with `mssh-complete eval`
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash',))
	for slot in ('command', 'hosts', 'hosts-back'):
		total = totals[('bash', slot)]
		assert 1 - float(total['keys']) / total['chars'] > 0.5, slot
	assert float(totals[('bash', 'hosts-back')]['top1']) / totals[('bash', 'hosts-back')]['cases'] > 0.85


def test_simulate_slot_counts_keys():
	engine = mc.Engine(SPEC, [])
	result = mc.simulate_slot(engine, 'mssh ', '', 'abc')
	assert (result['keys'], result['chars'], result['rank']) == (3, 3, 0)


def test_an_alias_of_the_option_typed_is_no_miss():
	# the history spells it --skip_unreachable, the replayed entry -su: the engine offering the long
	# string first offers what the operator meant
	lines = ['{}\t/x/multiSSH3.py\t--skip_unreachable\tzz-a.invalid\t"uptime"'.format(1700000000 + number) for number in range(5)]
	lines.append('1700000100\t/x/multiSSH3.py\t-su\tzz-a.invalid\t"uptime"')
	for policy in ('bash', 'ranked'):
		total = mc.evaluate(lines, SPEC, limit=1, policies=(policy,))[(policy, 'option')]
		assert (total['cases'], total['top1'], total['mrr'], total['divergent']) == (1, 1, 1.0, 0), policy
	# one TAB gives --skip_unreachable where typing -su takes two keys
	ranked = mc.evaluate(lines, SPEC, limit=1, policies=('ranked',))[('ranked', 'option')]
	assert (ranked['keys'], ranked['chars']) == (1, 2)


def test_an_option_of_another_action_with_the_same_dest_is_a_miss():
	# -nsu sets the dest -su sets, to the opposite: offering it is no hit
	lines = ['{}\t/x/multiSSH3.py\t-nsu\tzz-a.invalid\t"uptime"'.format(1700000000 + number) for number in range(5)]
	lines.append('1700000100\t/x/multiSSH3.py\t-su\tzz-a.invalid\t"uptime"')
	total = mc.evaluate(lines, SPEC, limit=1, policies=('ranked',))[('ranked', 'option')]
	assert total['top1'] == 0 and total['divergent'] == 1


def test_a_value_attached_to_its_option_is_replayed_apart_from_it():
	# -uroot is -u root to argparse: the option slot is -u, its value root
	entry = mc.parse_history_line('1700000000\t/x/multiSSH3.py\t-uroot -t30 --max_connections=8\tzz-a.invalid\t"uptime"', SPEC)
	assert entry.option_texts == ['-u', '-t', '--max_connections']
	cases = mc.slot_cases(entry)
	assert ('option', 'mssh -t=30 --max_connections=8 -', ' zz-a.invalid "uptime"', 'u', False, '') in cases
	assert ('value', 'mssh -t=30 --max_connections=8 -u ', ' zz-a.invalid "uptime"', 'root', False, ' zz-a.invalid "uptime"') in cases
	assert cases[0][1] == 'mssh -u=root -t=30 --max_connections=8 '


def test_since_skips_older_entries():
	lines = mc.synthetic_history(entries=100)
	cutoff = mc.parse_history_line(lines[90], SPEC).ts
	totals = mc.evaluate(lines, SPEC, since=cutoff, policies=('bash',))
	assert totals[('bash', 'hosts')]['cases'] == 10


def test_report_lists_every_slot():
	report = mc.format_report(mc.evaluate(mc.synthetic_history(entries=200), SPEC, limit=20))
	assert report.splitlines()[0].split()[:3] == ['policy', 'slot', 'cases']
	assert 'hosts-back' in report and 'ranked' in report


def test_ghost_suggestions_are_rarely_wrong_and_save_more_than_tab():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash', 'ghost'))
	ghost = {slot: total for (policy, slot), total in totals.items() if policy == 'ghost'}
	shown = sum(total['shown'] for total in ghost.values())
	assert shown and float(sum(total['divergent'] for total in ghost.values())) / shown <= 0.10
	assert sum(total['altered'] for total in ghost.values()) == 0

	def saved(policy):
		chosen = [totals[(policy, slot)] for slot in ghost]
		return 1 - float(sum(total['keys'] for total in chosen)) / sum(total['chars'] for total in chosen)
	assert saved('ghost') > saved('bash')


def test_report_has_a_ghost_table():
	report = mc.format_report(mc.evaluate(mc.synthetic_history(entries=300), SPEC, limit=50))
	assert 'shown' in report and '\nghost ' in report


# the hosts synthetic history names: the rest does not exist
SYNTHETIC_HOSTS = ['gpu{:02d}'.format(number) for number in range(1, 17)] + ['storage1', 'storage2', 'storage3', 'storage4', 'login1', 'login2', 'us_east']


def synthetic_table(tmp_path):
	path = str(tmp_path / 'index.nsv')
	names = sorted(SYNTHETIC_HOSTS)
	mc.write_nsv(path, {}, [('host_names', [names]), ('host_meta', [[str(mc.SRC_HISTORY), ''] for _ in names])])
	return mc.HostTable(mc.NsvIndex.load(path))


def validity(name):
	return 'valid' if name in SYNTHETIC_HOSTS else 'invalid'


def test_clean_synthetic_history_gets_no_warning(tmp_path):
	report = mc.diagnostics_replay(mc.synthetic_history(entries=300), SPEC, validity, synthetic_table(tmp_path))
	assert report['lines'] == 300 and report['warned'] == {kind: 0 for kind in mc.DIAGNOSTIC_KINDS}


# typos and padding mistakes an operator makes, and the host meant
MISTAKES = {
	'gpu[01-16]': 'gpu[1-16]', 'storage[1-4]': 'storgae[1-4]', 'login[1-2]': 'login[1-3]', 'us_east': 'us_eats',
}


def with_mistake(line):
	import shlex
	fields = line.split('\t')
	hosts = shlex.split(fields[3])[0]
	mistaken = MISTAKES.get(hosts) or 'gpu0' + hosts[3:]
	return '\t'.join(fields[:3] + [shlex.quote(mistaken)] + fields[4:])


def test_mistakes_in_synthetic_history_are_caught(tmp_path):
	lines = [with_mistake(line) for line in mc.synthetic_history(entries=300)]
	report = mc.diagnostics_replay(lines, SPEC, validity, synthetic_table(tmp_path))
	# every line holds one mistake, and every one is caught
	assert report['warned']['unknown'] + report['warned']['range'] == 300
	# a single host is meant to be the one it is a typo of
	assert {name: entry['meant'] for name, entry in report['unknown'].items()} == {
		name: ('us_east' if name == 'us_eats' else 'gpu' + name[4:]) for name in report['unknown']}


def test_the_diagnostics_report(tmp_path):
	lines = [with_mistake(line) for line in mc.synthetic_history(entries=100)]
	text = mc.format_diagnostics_report(mc.diagnostics_replay(lines, SPEC, validity, synthetic_table(tmp_path)))
	assert text.startswith('warnings over 100 history lines (DNS, no ping)\n')
	assert '  hosts mssh would reject:\n' in text and 'did you mean' in text
