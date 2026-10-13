import errno
import os
import subprocess
import sys
import threading
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


def test_the_index_holds_the_hosts_file_names_mssh_resolves(home, tmp_path, monkeypatch):
	# the names marked as from the hosts file are valid without DNS: exactly the ones mssh finds there
	hosts = tmp_path / 'hosts'
	hosts.write_bytes(b'10.0.0.5 node5 # old rack, ask Jos\xe9\nnode1 node2\nfd00::5 node5 node5-v6\n10.0.0.300 node3\n')
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(hosts))
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
	multiSSH3.getIP.cache_clear()
	index, _ = build()
	table = mc.HostTable(index)
	from_hosts_file = {name for name in table.names if table.sources(name) & mc.SRC_HOSTS_FILE}
	candidates = ('node1', 'node2', 'node3', 'node5', 'node5-v6', 'old', 'rack', '#')
	assert from_hosts_file == {name for name in candidates if multiSSH3.getIP(name, local=True)} == {'node5', 'node5-v6'}
	multiSSH3.getIP.cache_clear()


def test_alias_members_keep_their_users(home):
	# mssh runs postgres@db1 for dbs, and records its failures under that name
	with open(str(home / 'hosts.env'), 'a') as f:
		f.write('dbs=postgres@db1,db2\n')
	hosts = mc.HostTable(build()[0])
	dbs = hosts.alias_index('dbs')
	assert sorted(zip(hosts.alias_members(dbs), hosts.alias_member_users(dbs))) == [('db1', 'postgres'), ('db2', '')]
	assert hosts.alias_member_users(hosts.alias_index('racks')) == ['', '', '']


def test_index_never_holds_passwords(home):
	index, directory = build()
	with open(os.path.join(directory, mc.INDEX_NAME), 'rb') as f:
		assert b'topsecret' not in f.read()


def test_index_never_holds_configured_passwords(home, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_PASSWORD', "Hunter2 pa%ss it's")
	monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_PASSWORD', 'Bmc 100% s3cret')
	index, directory = build()
	with open(os.path.join(directory, mc.INDEX_NAME), 'rb') as f:
		data = f.read()
	assert b'Hunter2' not in data and b's3cret' not in data
	assert mc.ParserSpec.from_rows([index.row('spec', number) for number in range(index.count('spec'))]).lookup('-p')[0]


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


def test_a_rebuild_leaves_a_lock_taken_over_from_it(home, monkeypatch):
	# a rebuild that ran past LOCK_STALE has lost its lock to the next one: it must not remove that one
	directory = mc.cache_dir()
	lock = os.path.join(directory, mc.LOCK_NAME)
	assert mc.take_lock(lock)
	successor = []

	def overtaken_build(directory):
		stale = time.time() - mc.LOCK_STALE - 1
		os.utime(lock, (stale, stale))
		assert mc.take_lock(lock)
		with open(lock) as f:
			successor.append(f.read())
		return os.path.join(directory, mc.INDEX_NAME)
	monkeypatch.setattr(mc, 'build_index', overtaken_build)
	assert mc.main(['rebuild', '--lock', lock]) == 0
	with open(lock) as f:
		assert f.read() == successor[0]


def failing_build(directory, now=None, mssh=None):
	# as when the runtime directory is full, or a file size limit is lower than the index
	raise OSError(errno.EFBIG, 'File too large')


def test_a_failed_rebuild_is_tried_again_once_its_lock_is_stale(home, monkeypatch):
	# a failure that repeats would otherwise cost a full rebuild on every query
	directory = mc.cache_dir()
	lock = os.path.join(directory, mc.LOCK_NAME)
	monkeypatch.setattr(mc, 'build_index', failing_build)
	assert mc.take_lock(lock)
	assert mc.main(['rebuild', '--lock', lock]) == 1
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda argv, **kwargs: started.append(argv))
	assert mc.spawn_rebuild(directory) is False
	stale = time.time() - mc.LOCK_STALE - 1
	os.utime(lock, (stale, stale))
	assert mc.spawn_rebuild(directory) is True
	assert len(started) == 1


def test_queries_do_not_wait_for_a_rebuild_that_failed(home, monkeypatch):
	directory = mc.cache_dir()
	lock = os.path.join(directory, mc.LOCK_NAME)
	monkeypatch.setattr(mc, 'build_index', failing_build)
	assert mc.take_lock(lock)
	mc.main(['rebuild', '--lock', lock])
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda argv, **kwargs: started.append(argv))
	began = time.monotonic()
	assert mc.load_for_query(directory, time.time()) == (None, [])
	assert time.monotonic() - began < 0.5
	assert started == []


def test_the_first_query_stops_waiting_when_the_build_fails(home, monkeypatch):
	directory = mc.cache_dir()
	monkeypatch.setattr(mc, 'build_index', failing_build)
	runs = []

	def popen(argv, **kwargs):
		# the detached rebuild, failing a moment after it starts
		run = threading.Timer(0.1, mc.main, args=(argv[-3:],))
		run.start()
		runs.append(run)
	monkeypatch.setattr(subprocess, 'Popen', popen)
	began = time.monotonic()
	assert mc.load_for_query(directory, time.time()) == (None, [])
	assert time.monotonic() - began < 1
	runs[0].join()


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


def test_a_query_answers_before_its_deadline_while_the_first_build_runs(home, monkeypatch):
	# the shell gives up at its deadline: a first build that takes longer must not cost the answer
	directory = mc.cache_dir()
	assert mc.take_lock(os.path.join(directory, mc.LOCK_NAME))
	monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: pytest.fail('started a second build'))
	# a wide reserve, so a loaded machine cannot make the answer late
	monkeypatch.setattr(mc, 'FIRST_BUILD_RESERVE', 0.4)
	started = time.monotonic()
	response = mc.answer(mc.Request('bash', 'mssh --no_wa', '', '--no_wa'), started + 0.6, directory=directory)
	assert time.monotonic() - started < 0.6
	# without the index: options from mssh's parser
	assert [candidate.text for candidate in response.candidates] == ['--no_watch']


def test_a_query_still_waits_for_a_first_build_that_ends_in_time(home, monkeypatch):
	directory = mc.cache_dir()
	assert mc.take_lock(os.path.join(directory, mc.LOCK_NAME))
	monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: pytest.fail('started a second build'))
	# the running build: done shortly after the query starts
	other = os.path.join(str(home), 'other')
	os.mkdir(other)
	built = mc.build_index(other, mssh=multiSSH3)
	finish = threading.Timer(0.02, os.replace, (built, os.path.join(directory, mc.INDEX_NAME)))
	finish.start()
	try:
		response = mc.answer(mc.Request('bash', 'mssh jum', '', 'jum'), time.monotonic() + 2.0, directory=directory)
	finally:
		finish.join()
	assert [candidate.text for candidate in response.candidates] == ['jump1', 'jump2']


def test_the_query_command_answers_in_time_while_the_first_build_runs(home):
	directory = mc.cache_dir()
	assert mc.take_lock(os.path.join(directory, mc.LOCK_NAME))
	request = '\0'.join([mc.PROTOCOL, 'bash', '5.2', '', 'mssh --no_wa', '', '--no_wa']) + '\0'
	started = time.monotonic()
	result = subprocess.run([sys.executable, '-I', mc.__file__, 'query'], input=request.encode(), stdout=subprocess.PIPE, timeout=30)
	took = time.monotonic() - started
	assert 'C --no_watch\t' in result.stdout.decode()
	# the shells wait 0.3 s by default; the answer used to come after the 2 s first-build budget
	assert took < 1.0



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


def test_index_counts_uses_and_last_use_of_each_feature(home):
	index, _ = build()
	snapshot = mc.SnapshotKnowledge(index, NOW)
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, mc.spec_from_parser(multiSSH3.get_parser()), NOW)
	for feature, uses in (('h:gpu[01-16]', (2, 1789990100)), ('v:username=admin', (1, 1789990200)), ('c:uptime', (1, 1789990300))):
		assert snapshot.feature_uses(snapshot.feature_key(feature)) == uses
		assert memory.feature_uses(feature) == uses


def test_an_index_of_the_previous_format_is_not_read(home):
	_, directory = build()
	path = os.path.join(directory, mc.INDEX_NAME)
	with open(path, encoding='utf-8') as f:
		data = f.read()
	assert data.startswith(mc.INDEX_MAGIC + '\0' + mc.INDEX_FORMAT + '\0')
	with open(path, 'w', encoding='utf-8') as f:
		f.write(mc.INDEX_MAGIC + '\0' + '1' + data[len(mc.INDEX_MAGIC) + 1 + len(mc.INDEX_FORMAT):])
	with pytest.raises(mc.IndexCorrupt):
		mc.NsvIndex.load(path)


def test_the_index_records_what_flags_do_and_their_defaults(home, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_SKIP_UNREACHABLE', False)
	index, directory = build()
	engine = mc.engine_for(mc.Request('bash', 'mssh ', '', ''), directory, NOW)
	assert engine.flag_sets['--no_skip_unreachable'] is False and engine.flag_sets['--skip_unreachable'] is True
	assert engine.flag_defaults['skip_unreachable'] is False and engine.flag_defaults['ipmi'] is multiSSH3.DEFAULT_IPMI


def test_the_index_records_option_combinations_with_no_effect(home):
	_, directory = build()
	engine = mc.engine_for(mc.Request('bash', 'mssh ', '', ''), directory, NOW)
	assert engine.no_effect == [(option, kind, tuple(others), why) for option, kind, others, why in multiSSH3.OPTION_NO_EFFECT]
