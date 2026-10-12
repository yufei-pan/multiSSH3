import os
import stat

import pytest

import mssh_complete as mc


def test_nsv_round_trip(tmp_path):
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {'built': '1'}, [('one', [['a', 'b']]), ('many', [['1'], [], ['x', '', 'y']])])
	index = mc.NsvIndex.load(path)
	assert index.header == {'built': '1'}
	assert index.single('one') == ['a', 'b']
	assert [index.row('many', number) for number in range(3)] == [['1'], [], ['x', '', 'y']]
	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_nsv_rejects_unsafe_fields(tmp_path):
	with pytest.raises(ValueError):
		mc.write_nsv(str(tmp_path / 'index.nsv'), {}, [('bad', [['a\nb']])])
	assert os.listdir(str(tmp_path)) == []


@pytest.mark.parametrize('damage', [
	lambda data: data + 'junk',
	lambda data: data[:-5],
	lambda data: data.replace(mc.INDEX_MAGIC, 'NOTMAGIC', 1),
	lambda data: data.replace('\0' + mc.INDEX_FORMAT + '\0', '\x0099\0', 1),
	lambda data: '',
])
def test_damaged_index_is_rejected(tmp_path, damage):
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {}, [('one', [['a']])])
	with open(path) as f:
		data = f.read()
	with open(path, 'w') as f:
		f.write(damage(data))
	with pytest.raises(mc.IndexCorrupt):
		mc.NsvIndex.load(path)


def memory(records):
	knowledge = mc.MemoryKnowledge()
	for features, weight in records:
		knowledge.add(features, weight)
	return knowledge


def test_identical_invocations_share_a_record():
	knowledge = memory([(['c:uptime', 'h:a'], 1.0), (['c:uptime', 'h:a'], 0.5), (['c:df', 'h:a'], 1.0)])
	assert knowledge.record_count() == 2
	assert knowledge.feature_weight('h:a') == 2.5
	assert knowledge.feature_range('c:') == [('c:df', 'c:df'), ('c:uptime', 'c:uptime')]


def test_use_weight_keeps_a_floor():
	assert mc.use_weight(0) == pytest.approx(1 + mc.USE_FLOOR)
	assert mc.use_weight(mc.HALF_LIFE) == pytest.approx(0.5 + mc.USE_FLOOR)
	assert mc.use_weight(1000 * mc.HALF_LIFE) == pytest.approx(mc.USE_FLOOR)


def test_scores_without_context_are_frecency():
	knowledge = memory([(['c:uptime'], 3.0), (['c:df'], 1.0)])
	scores = mc.score_features([knowledge], 'c:', [])
	assert scores == {'c:uptime': pytest.approx(0.3), 'c:df': pytest.approx(0.1)}


def test_matching_the_line_beats_being_used_often():
	knowledge = memory([
		(['c:uptime', 'h:login1', 'm:plain'], 9.0),
		(['c:df -h /data', 'h:storage1', 'm:plain'], 1.0),
		(['c:free', 'h:other', 'm:plain'], 1.0),
	])
	scores = mc.score_features([knowledge], 'h:', ['c:df -h /data', 'm:plain'])
	assert max(scores, key=scores.get) == 'h:storage1'


def test_features_in_most_records_carry_no_context():
	knowledge = memory([(['c:a', 'm:plain'], 1.0), (['c:b', 'm:plain'], 1.0), (['c:c', 'm:sync'], 1.0)])
	with_common = mc.score_features([knowledge], 'c:', ['m:plain'])
	assert with_common == mc.score_features([knowledge], 'c:', [])
	assert max(mc.score_features([knowledge], 'c:', ['m:sync']).items(), key=lambda item: item[1])[0] == 'c:c'


def test_scores_add_up_across_knowledge():
	first = memory([(['c:a', 'h:x'], 1.0)])
	second = memory([(['c:a', 'h:x'], 1.0), (['c:b', 'h:y'], 1.0)])
	assert mc.score_features([first, second], 'c:', [])['c:a'] == pytest.approx(0.2)
