'''mssh's runtime directory: the chain of private, reboot-cleared places mssh and mssh-complete agree on.'''
import os
import tempfile

import pytest

import multiSSH3
import mssh_complete as mc

posix_only = pytest.mark.skipif(not hasattr(os, 'getuid'), reason='needs POSIX ownership')


@pytest.fixture
def places(tmp_path, monkeypatch):
	'''Stand-ins for $XDG_RUNTIME_DIR, /run/user, /dev/shm and the temp dir, all usable.'''
	uid = str(os.getuid())
	xdg = tmp_path / 'xdg'
	run_user = tmp_path / 'run-user'
	shm = tmp_path / 'shm'
	temp = tmp_path / 'tmp'
	xdg.mkdir(mode=0o700)
	(run_user / uid).mkdir(parents=True, mode=0o700)
	shm.mkdir()
	shm.chmod(0o1777)
	temp.mkdir()
	temp.chmod(0o1777)
	monkeypatch.setenv('XDG_RUNTIME_DIR', str(xdg))
	for module in (multiSSH3, mc):
		monkeypatch.setattr(module, '_RUN_USER_ROOT', str(run_user))
		monkeypatch.setattr(module, '_SHM_DIR', str(shm))
	monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(temp))
	return {
		'xdg': xdg / 'multiSSH3', 'run_user': run_user / uid / 'multiSSH3',
		'shm': shm / ('multiSSH3-' + uid), 'temp': temp / ('multiSSH3-' + uid),
		'roots': {'xdg': xdg, 'run_user': run_user / uid, 'shm': shm, 'temp': temp},
	}


@posix_only
@pytest.mark.parametrize('missing, expected', [
	((), 'xdg'),
	# su, sudo -u and cron leave $XDG_RUNTIME_DIR unset while logind's directory exists
	(('xdg',), 'run_user'),
	# no login session at all (broken PAM profile, root filesystem trouble)
	(('xdg', 'run_user'), 'shm'),
	(('xdg', 'run_user', 'shm'), 'temp'),
])
def test_the_first_usable_place_wins_in_both_modules(places, missing, expected):
	for name in missing:
		os.rmdir(str(places['roots'][name]))
	directory = multiSSH3.runtime_dir()
	assert directory == str(places[expected])
	assert mc.cache_dir() == directory
	assert multiSSH3._unavailable_hosts_file_path() == os.path.join(directory, 'unavailable_hosts.csv')


@posix_only
def test_xdg_runtime_dir_unset_uses_loginds_directory(places, monkeypatch):
	monkeypatch.delenv('XDG_RUNTIME_DIR')
	assert multiSSH3.runtime_dir() == mc.cache_dir() == str(places['run_user'])


@posix_only
@pytest.mark.parametrize('planted', ['symlink', 'open_mode'])
def test_a_place_someone_else_controls_is_skipped(places, monkeypatch, planted):
	monkeypatch.delenv('XDG_RUNTIME_DIR')
	os.rmdir(str(places['roots']['run_user']))
	if planted == 'symlink':
		target = places['roots']['shm'] / 'attacker'
		target.mkdir(mode=0o700)
		places['shm'].symlink_to(target)
	else:
		# /run/user/<uid> others can write to
		places['roots']['run_user'].mkdir(mode=0o777)
		places['roots']['run_user'].chmod(0o777)
		places['shm'].mkdir(mode=0o700)
		places['shm'].chmod(0o777)
	assert multiSSH3.runtime_dir() == mc.cache_dir() == str(places['temp'])


@posix_only
@pytest.mark.parametrize('holding', ['run_user', 'shm', 'temp'])
def test_reading_goes_where_a_write_goes(places, holding):
	# a later place's state (an older session's, or this machine's own while a test or a script sets
	# $XDG_RUNTIME_DIR to a new directory) is not read: the place a write goes to is set up, and read
	places[holding].mkdir(mode=0o700)
	(places[holding] / 'unavailable_hosts.csv').write_text('#boot_id,x\n')

	assert multiSSH3._unavailable_hosts_file_path() == os.path.join(str(places['xdg']), 'unavailable_hosts.csv')
	assert places['xdg'].is_dir() and places['xdg'].stat().st_mode & 0o777 == 0o700
	# callers written for 6.38 still pass create
	assert multiSSH3.runtime_dir(create=False) == mc.cache_dir() == str(places['xdg'])


@posix_only
def test_a_place_of_ours_readable_by_others_is_tightened_by_a_read(places):
	places['xdg'].mkdir(mode=0o700)
	places['xdg'].chmod(0o755)

	assert multiSSH3.runtime_dir() == mc.cache_dir() == str(places['xdg'])
	assert places['xdg'].stat().st_mode & 0o777 == 0o700


@posix_only
def test_without_any_usable_place_there_is_no_runtime_dir(places, monkeypatch):
	monkeypatch.delenv('XDG_RUNTIME_DIR')
	for name in ('run_user', 'shm', 'temp'):
		os.rmdir(str(places['roots'][name]))
	assert multiSSH3.runtime_dir() is None and mc.cache_dir() is None
	assert multiSSH3._unavailable_hosts_file_path() is None
