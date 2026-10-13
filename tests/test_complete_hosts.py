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


def test_expand_ranges_gives_up_before_writing_out_a_range_past_its_limit():
	# node[1-10000000] typed once made every hosts TAB write out ten million names (1.5 s) to give the range back whole
	import tracemalloc
	tracemalloc.start()
	try:
		assert mc.expand_ranges('n[1-1000000]', limit=3) == ['n[1-1000000]']
		assert mc.expand_ranges('n[1-2,5-1000000]', limit=3) == ['n[1-2,5-1000000]']
		peak = tracemalloc.get_traced_memory()[1]
	finally:
		tracemalloc.stop()
	assert peak < 100000
	# up to the limit nothing changes, empty parts included
	assert mc.expand_ranges('n[1-2,9-8,4]', limit=3) == ['n1', 'n2', 'n4']


def test_range_union_is_what_expand_ranges_gives_each_range():
	import random
	pieces = ['n', 'gpu', 'r1-', '', '-a', '.x', '[', ']', ',', '-', ' ', 'a-b', '1-3', '01-12', '7-5', '0-0', '9', '003-1', '1-4100', '1-2]x[3-4']
	for seed in range(300):
		rng = random.Random(seed)
		texts = []
		for _ in range(rng.randint(1, 12)):
			if rng.random() < 0.7:
				parts = []
				for _ in range(rng.randint(1, 3)):
					low = rng.randrange(60)
					parts.append(rng.choice(['{}-{}', '{:02d}-{:02d}', '{}', '{:03d}-{}']).format(low, low + rng.randrange(-2, 40)))
				texts.append(rng.choice(['n', 'node', 'r2n', '']) + '[' + ','.join(parts) + ']' + rng.choice(['', '-ib', '.lan']))
			else:
				texts.append(''.join(rng.choice(pieces) for _ in range(rng.randint(1, 6))))
		limit = rng.choice([3, 50, 4096])
		expected = set()
		for text in texts:
			expected.update(mc.expand_ranges(text, limit))
		assert mc.range_union(texts, limit, budget=10 ** 9) == expected, (texts, limit)


def test_range_union_writes_up_to_its_budget():
	texts = ['node[{:05d}-{:05d}]'.format(start, start + 3999) for start in range(0, 30000, 100)]
	assert len(mc.range_union(texts, 4096, budget=10 ** 9)) == 33900
	assert mc.range_union(texts, 4096, budget=1000) == {'node{:05d}'.format(number) for number in range(1000)}
	assert len(mc.range_union(['a[1-5]b[1-5]', 'c[1-5]d[1-5]'], 4096, budget=20)) == 25
	# a range past the limit comes back whole after writing out about the limit's worth of names:
	# that counts against the budget too
	texts = ['x{}[1-100][1-100]'.format(number) for number in range(10)]
	assert mc.range_union(texts, 4096, budget=5000) == set(texts[:2])
