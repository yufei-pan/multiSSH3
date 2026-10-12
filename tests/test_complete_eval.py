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


def test_since_skips_older_entries():
	lines = mc.synthetic_history(entries=100)
	cutoff = mc.parse_history_line(lines[90], SPEC).ts
	totals = mc.evaluate(lines, SPEC, since=cutoff, policies=('bash',))
	assert totals[('bash', 'hosts')]['cases'] == 10


def test_report_lists_every_slot():
	report = mc.format_report(mc.evaluate(mc.synthetic_history(entries=200), SPEC, limit=20))
	assert report.splitlines()[0].split()[:3] == ['policy', 'slot', 'cases']
	assert 'hosts-back' in report and 'ranked' in report
