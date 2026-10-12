import os
import subprocess
import time

import pytest

import multiSSH3
import mssh_complete as mc

NOW = 1790000000.0
HISTORY = [
	'1789990000\t/x/multiSSH3.py\t-su -u=root -p=topsecret\tgpu[01-16]\t"nvidia-smi"',
	'1789990100\t/x/multiSSH3.py\t-su -u=root\tgpu[01-16]\t"systemctl restart slurmd"',
	'1789990200\t/x/multiSSH3.py\t-su -u=admin\tstorage1,storage2\t"df -h /data"',
	'1789990300\t/x/multiSSH3.py\t-su\tracks\t"uptime"',
]


@pytest.fixture
def home(tmp_path, monkeypatch):
	'''A HOME with mssh history, ssh config, known_hosts and an env file; a private runtime dir.'''
	home = tmp_path / 'home'
	(home / '.ssh').mkdir(parents=True)
	runtime = tmp_path / 'runtime'
	runtime.mkdir(mode=0o700)
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in HISTORY))
	(home / '.ssh' / 'config').write_text('Host jump1 jump2 *.corp\n  User ops\nInclude extra.conf\n')
	(home / '.ssh' / 'extra.conf').write_text('Host bastion\n')
	(home / '.ssh' / 'known_hosts').write_text('kh1,10.9.9.9 ssh-ed25519 AAAA\n|1|hashed= ssh-rsa AAAA\n[kh2]:2222 ssh-rsa AAAA\n')
	env_file = home / 'hosts.env'
	env_file.write_text("racks='rack[1-3]'\nPATH=/usr/bin:/bin\nEDITOR=vim\n")
	monkeypatch.setenv('HOME', str(home))
	monkeypatch.setenv('XDG_RUNTIME_DIR', str(runtime))
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HISTORY_FILE', '~/.mssh_history')
	monkeypatch.setattr(multiSSH3, '_env_files', [str(env_file)])
	monkeypatch.setattr(multiSSH3, '_explicit_env_files', {str(env_file)})
	return home


def build(now=NOW):
	directory = mc.cache_dir()
	return mc.NsvIndex.load(mc.build_index(directory, now=now, mssh=multiSSH3)), directory


def test_cache_dir_matches_multissh3(home):
	assert mc.cache_dir() == os.path.dirname(multiSSH3._unavailable_hosts_file_path())


def test_build_index_collects_every_source(home):
	index, _ = build()
	hosts = mc.HostTable(index)
	names = set(hosts.names)
	assert {'jump1', 'jump2', 'bastion', 'kh1', '10.9.9.9', 'kh2', 'rack1', 'rack2', 'rack3', 'storage1', 'storage2'} <= names
	assert '*.corp' not in names and 'gpu[01-16]' not in names
	assert hosts.alias_names == ['racks']
	assert hosts.alias_members(0) == ['rack1', 'rack2', 'rack3']
	assert ('rack[1-3]', ['rack1', 'rack2', 'rack3']) in hosts.groups()
	assert index.row('config', 0) == ['users', 'ops']
	assert index.header['history_offset'] == str(os.path.getsize(str(home / '.mssh_history')))


def test_index_never_holds_passwords(home):
	index, directory = build()
	with open(os.path.join(directory, mc.INDEX_NAME), 'rb') as f:
		assert b'topsecret' not in f.read()


def test_snapshot_and_memory_knowledge_agree(home):
	index, _ = build()
	snapshot = mc.SnapshotKnowledge(index, NOW)
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, mc.spec_from_parser(multiSSH3.get_parser()), NOW)
	for prefix in ('c:', 't:', 'v:username='):
		assert [text for _, text in snapshot.feature_range(prefix)] == [text for _, text in memory.feature_range(prefix)]
	key = snapshot.feature_key('c:nvidia-smi')
	assert snapshot.feature_weight(key) == pytest.approx(memory.feature_weight('c:nvidia-smi'), rel=1e-5)


def test_snapshot_weights_decay_with_age(home):
	index, _ = build()
	key = mc.SnapshotKnowledge(index, NOW).feature_key('c:uptime')
	fresh = mc.SnapshotKnowledge(index, NOW).feature_weight(key)
	week_later = mc.SnapshotKnowledge(index, NOW + mc.HALF_LIFE).feature_weight(key)
	assert week_later == pytest.approx(fresh / 2)


def test_fresh_index(home):
	index, _ = build(now=time.time())
	assert mc.check_freshness(index, time.time()) == ('fresh', [])


def test_appended_history_is_a_tail(home):
	index, _ = build(now=time.time())
	line = '1790000500\t/x/multiSSH3.py\t-su\tgpu07\t"nvidia-smi -q"'
	with open(str(home / '.mssh_history'), 'a') as f:
		f.write(line + '\n')
	assert mc.check_freshness(index, time.time()) == ('tail', [line])


def test_long_tail_needs_a_rebuild(home):
	index, _ = build(now=time.time())
	with open(str(home / '.mssh_history'), 'a') as f:
		for number in range(mc.TAIL_LIMIT_ENTRIES + 1):
			f.write('1790000500\t/x/multiSSH3.py\t-su\th{}\t"uptime"\n'.format(number))
	assert mc.check_freshness(index, time.time()) == ('rebuild', [])


@pytest.mark.parametrize('change', ['shrink', 'source', 'arp'])
def test_rebuild_needed(home, change):
	index, _ = build(now=time.time())
	now = time.time()
	if change == 'shrink':
		(home / '.mssh_history').write_text(HISTORY[0] + '\n')
	elif change == 'source':
		(home / '.ssh' / 'config').write_text('Host other\n')
	else:
		now += mc.ARP_TTL + 1
	assert mc.check_freshness(index, now)[0] == 'rebuild'


def test_lock_blocks_a_second_rebuild_until_stale(tmp_path):
	lock = str(tmp_path / mc.LOCK_NAME)
	assert mc.take_lock(lock, now=time.time())
	assert not mc.take_lock(lock, now=time.time())
	assert mc.take_lock(lock, now=time.time() + mc.LOCK_STALE + 1)


def test_first_query_builds_the_index(home):
	directory = mc.cache_dir()
	index, tail = mc.load_for_query(directory, time.time())
	assert index is not None and tail == []
	assert not os.path.exists(os.path.join(directory, mc.LOCK_NAME))



def test_history_with_garbage_lines_still_builds(home):
	with open(str(home / '.mssh_history'), 'ab') as f:
		f.write(b'\xff\xfe not utf-8 \x00 at all\n')
		f.write(b'1790000900\t/x/multiSSH3.py\t-su\t\xe9t\xe9\t"echo \xff"\n')
		f.write(b'old style line without tabs\n')
		f.write(b'1790000901\t/x/multiSSH3.py\t-su\tEMPTY_HOSTS\t"uptime"\n')
	index, _ = build()
	features = mc.SnapshotKnowledge(index, NOW).features
	assert 'c:uptime' in features and 'c:nvidia-smi' in features
	assert not any(feature == 'h:EMPTY_HOSTS' for feature in features)


def test_concurrent_first_query_waits_for_the_running_build(home, monkeypatch):
	directory = mc.cache_dir()
	assert mc.take_lock(os.path.join(directory, mc.LOCK_NAME))
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: started.append(args))
	monkeypatch.setattr(mc, 'FIRST_BUILD_BUDGET', 0.2)
	assert mc.load_for_query(directory, time.time()) == (None, [])
	assert started == []



def test_history_with_absurd_timestamps_still_builds(home):
	with open(str(home / '.mssh_history'), 'a') as f:
		f.write('9' * 400 + '\t/x/multiSSH3.py\t-su\th1\t"uptime"\n')
		f.write('-' + '9' * 400 + '\t/x/multiSSH3.py\t-su\th2\t"uptime"\n')
	index, _ = build()
	assert 'c:nvidia-smi' in mc.SnapshotKnowledge(index, NOW).features


def test_history_ranges_add_their_members(home):
	index, _ = build()
	names = set(mc.HostTable(index).names)
	assert {'gpu{:02d}'.format(number) for number in range(1, 17)} <= names


def test_skip_hosts_offers_members_of_a_range_typed_before(home):
	build()
	response = mc.answer(mc.Request('bash', 'mssh gpu[01-16] -X ', '', ''), directory=mc.cache_dir(), now=NOW)
	singles = [candidate.text for candidate in response.candidates if '[' not in candidate.text and ',' not in candidate.text]
	assert singles[:2] == ['gpu01', 'gpu02']
