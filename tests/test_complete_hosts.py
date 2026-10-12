import multiSSH3
import mssh_complete as mc


def test_compact_names_round_trip_through_mssh_expansion():
	expand = getattr(multiSSH3, '__expand_hostname')
	names = ['node{:05d}'.format(number) for number in range(9000)] + ['n1', 'n2', 'n10', 'n11', 'x-1-a', 'x-2-a', 'plain']
	for prefix in ('', 'n', 'node0', 'node08', 'node0899', 'n1', 'x'):
		subset = [name for name in names if name.startswith(prefix)]
		groups = mc.compact_names(subset)
		assert all(group.startswith(prefix) for group in groups)
		back = set()
		for group in groups:
			back.update(expand(group, validate=False))
		assert back == set(subset), prefix


def test_expand_ranges():
	assert mc.expand_ranges('n[1-3]-[a,b]') == ['n1-a', 'n1-b', 'n2-a', 'n2-b', 'n3-a', 'n3-b']
	assert mc.expand_ranges('n[01-02]') == ['n01', 'n02']
	assert mc.expand_ranges('x[a-c]') == ['x[a-c]']
	assert mc.expand_ranges('n[1-9]', limit=3) == ['n[1-9]']

