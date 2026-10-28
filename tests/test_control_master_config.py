'''mssh --add_control_master_config: the ControlMaster block it keeps in ~/.ssh/config.'''
import os
import shutil
import stat
import subprocess

import pytest

import multiSSH3

posix_only = pytest.mark.skipif(not hasattr(os, 'getuid'), reason='needs POSIX ownership')

# what mssh up to 6.31 appended to an existing ~/.ssh/config: every ssh fails without /run/user/<uid>
OLD_BLOCK = (
	b'Host *\n'
	b'  ControlMaster auto\n'
	b'  ControlPath /run/user/%i/ssh_sockets_%C\n'
	b'  ControlPersist 3600\n'
)
OLD_APPENDED = b'\n# Added by multiSSH3.py to speed up subsequent connections\n' + OLD_BLOCK


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
	'''A home directory of the test's own: nothing here may touch the real ~/.ssh.'''
	home = tmp_path / 'home'
	home.mkdir()
	monkeypatch.setenv('HOME', str(home))
	monkeypatch.setenv('USERPROFILE', str(home))
	assert os.path.expanduser('~/.ssh/config') == str(home / '.ssh' / 'config')
	return home


def add_control_master_config(monkeypatch):
	'''Run mssh --add_control_master_config, return its exit code.'''
	exits = []

	def fake_exit(code, message=None):
		exits.append(code)
		raise SystemExit(code)

	monkeypatch.setattr(multiSSH3, '_exit_with_code', fake_exit)
	args = multiSSH3.get_parser().parse_args(['--add_control_master_config'])
	with pytest.raises(SystemExit):
		multiSSH3.process_control_master_config(args)
	return exits[0]


def write_config(home, content, mode=0o600):
	ssh_dir = home / '.ssh'
	ssh_dir.mkdir(mode=0o700, exist_ok=True)
	config = ssh_dir / 'config'
	config.write_bytes(content)
	config.chmod(mode)
	return config


def block():
	return multiSSH3._control_master_block().encode()


def test_a_missing_config_gets_the_block(home, monkeypatch):
	assert add_control_master_config(monkeypatch) == 0
	config = home / '.ssh' / 'config'
	assert config.read_bytes() == block()
	if hasattr(os, 'getuid'):
		assert stat.S_IMODE((home / '.ssh').stat().st_mode) == 0o700
		assert stat.S_IMODE(config.stat().st_mode) == 0o644


def test_the_block_is_added_after_the_users_config(home, monkeypatch):
	# not UTF-8 and no newline at the end: still kept byte for byte
	mine = b'Host gw\n  User me\n# caf\xe9\nHost *\n  ServerAliveInterval 30'
	config = write_config(home, mine)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == mine + b'\n\n' + block()


def test_the_old_block_is_replaced_and_the_rest_kept(home, monkeypatch):
	before = b'Host gw\n  User me\n'
	after = b'Host build\n  HostName 10.0.0.5\n'
	config = write_config(home, before + OLD_APPENDED + after)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == before + b'\n' + block() + after


def test_the_old_block_of_a_config_mssh_created_is_replaced(home, monkeypatch):
	config = write_config(home, OLD_BLOCK, mode=0o644)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == block()


def test_lines_after_the_old_block_stay_in_a_host_star_section(home, monkeypatch):
	'''Options a user appended under mssh's old "Host *" must still apply to every host.'''
	config = write_config(home, OLD_APPENDED + b'  ForwardAgent yes\n')
	add_control_master_config(monkeypatch)
	lines = config.read_bytes().splitlines()
	sections = [line.strip() for line in lines if line.strip().split(b' ')[0] in (b'Host', b'Match')]
	assert sections[-1] == b'Host *'
	assert lines.index(sections[-1]) < lines.index(b'  ForwardAgent yes')


def test_running_it_again_changes_nothing(home, monkeypatch, capsys):
	config = write_config(home, b'Host gw\n  User me\n' + OLD_APPENDED)
	add_control_master_config(monkeypatch)
	once = config.read_bytes()
	inode = config.stat().st_ino
	capsys.readouterr()
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == once
	# not even rewritten
	assert config.stat().st_ino == inode
	assert 'already' in capsys.readouterr().err


@posix_only
@pytest.mark.parametrize('mode', [0o600, 0o640, 0o644])
def test_the_files_mode_is_kept(home, monkeypatch, mode):
	config = write_config(home, b'Host gw\n  User me\n' + OLD_APPENDED, mode=mode)
	add_control_master_config(monkeypatch)
	assert stat.S_IMODE(config.stat().st_mode) == mode


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0, reason='needs root to own a file as another user')
def test_a_config_of_another_user_keeps_its_owner(home, monkeypatch):
	'''sudo keeping HOME: ssh refuses a ~/.ssh/config that belongs to someone else (root).'''
	config = write_config(home, b'Host gw\n  User me\n' + OLD_APPENDED)
	os.chown(str(config), 65534, 65534)
	add_control_master_config(monkeypatch)
	st = config.stat()
	assert (st.st_uid, st.st_gid) == (65534, 65534)
	assert block() in config.read_bytes()


@posix_only
def test_a_symlinked_config_is_written_through(home, monkeypatch, tmp_path):
	dotfiles = tmp_path / 'dotfiles'
	dotfiles.mkdir()
	real = dotfiles / 'ssh_config'
	real.write_bytes(OLD_BLOCK)
	(home / '.ssh').mkdir(mode=0o700)
	link = home / '.ssh' / 'config'
	link.symlink_to(real)
	add_control_master_config(monkeypatch)
	assert link.is_symlink()
	assert real.read_bytes() == block()


def test_crlf_line_ends_are_kept(home, monkeypatch):
	before = b'Host gw\r\n  User me\r\n'
	config = write_config(home, before + OLD_APPENDED.replace(b'\n', b'\r\n'))
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == before + b'\r\n' + block().replace(b'\n', b'\r\n')


def test_only_mssh_blocks_are_replaced(home, monkeypatch, capsys):
	'''A ControlMaster setup of the user's own, even one like mssh's old block, is not touched.'''
	mine = (
		b'Host *\n'
		b'  ControlMaster auto\n'
		b'  ControlPath ~/.cm/%C\n'
		b'  ControlPersist 3600\n'
		b'# Added by multiSSH3.py to speed up subsequent connections\n'
		b'Host *\n'
		b'  ControlMaster auto\n'
		b'  ControlPath /run/user/%i/ssh_sockets_%C\n'
		b'  ControlPersist 600\n'
	)
	config = write_config(home, mine)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == mine + b'\n' + block()
	# the edited copy of the old block still breaks ssh without /run/user/<uid>, and comes first
	assert 'line 8' in capsys.readouterr().err


def test_the_real_block_is_not_taken_for_the_old_one(home, monkeypatch, capsys):
	'''With the real places the new block has the old ControlPath line too, in its first Match.'''
	monkeypatch.setattr(multiSSH3, '_RUN_USER_ROOT', '/run/user')
	monkeypatch.setattr(multiSSH3, '_SHM_DIR', '/dev/shm')
	config = write_config(home, b'Host gw\n  User me\n' + OLD_APPENDED)
	add_control_master_config(monkeypatch)
	once = config.read_bytes()
	assert 'Replaced' in capsys.readouterr().err
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == once
	err = capsys.readouterr().err
	assert 'already' in err and 'Warning' not in err


def test_a_second_copy_of_the_old_block_is_removed(home, monkeypatch):
	config = write_config(home, OLD_BLOCK + b'Host gw\n  User me\n' + OLD_APPENDED)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == block() + b'Host gw\n  User me\n\n'


def test_the_old_block_goes_when_the_new_one_is_already_there(home, monkeypatch):
	config = write_config(home, OLD_BLOCK + b'\n' + block())
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == b'\n' + block()


def test_a_failed_write_leaves_the_config_as_it_was(home, monkeypatch, capsys):
	config = write_config(home, b'Host gw\n  User me\n' + OLD_APPENDED)
	before = config.read_bytes()

	def full_disk(*args, **kwargs):
		raise OSError(28, 'No space left on device')

	monkeypatch.setattr(multiSSH3.os, 'fsync', full_disk)
	add_control_master_config(monkeypatch)
	assert config.read_bytes() == before
	assert sorted(os.listdir(str(home / '.ssh'))) == ['config']
	assert 'No space left' in capsys.readouterr().err


def test_the_block_works_on_old_openssh_and_never_in_home(monkeypatch):
	'''
	OpenSSH 7.4 (RHEL 7) knows no %i or %C in Match exec and stops every ssh on it, and
	sockets in the home directory fail on NFS, GPFS or Lustre.
	'''
	monkeypatch.setattr(multiSSH3, '_RUN_USER_ROOT', '/run/user')
	monkeypatch.setattr(multiSSH3, '_SHM_DIR', '/dev/shm')
	text = multiSSH3._control_master_block()
	lines = [line.strip() for line in text.splitlines()]
	execs = [line for line in lines if line.startswith('Match exec')]
	paths = [line.split(' ', 1)[1] for line in lines if line.startswith('ControlPath')]
	assert len(execs) == 2
	assert not any('%' in line for line in execs)
	assert paths == ['/run/user/%i/ssh_sockets_%C', '/dev/shm/multiSSH3-%i/ssh_sockets_%C']
	assert '~' not in text and '%d' not in text
	# ssh binds <ControlPath>.<16 random characters>; sun_path holds 107 bytes (103 on BSD)
	for path in paths:
		longest = path.replace('%i', '4294967294').replace('%C', 'f' * 40) + '.' + 'x' * 16
		assert len(longest) <= 103


def test_the_readme_shows_the_block(monkeypatch):
	monkeypatch.setattr(multiSSH3, '_RUN_USER_ROOT', '/run/user')
	monkeypatch.setattr(multiSSH3, '_SHM_DIR', '/dev/shm')
	readme = os.path.join(os.path.dirname(os.path.abspath(multiSSH3.__file__)), 'README.md')
	with open(readme, encoding='utf-8') as f:
		assert '```config\n' + multiSSH3._control_master_block() + '```' in f.read()


def ssh_controlpath(config, host='example.invalid'):
	'''The ControlPath ssh -G sees for host with this config (ssh -G connects to nothing).'''
	env = dict(os.environ, SHELL='/bin/sh')
	result = subprocess.run(['ssh', '-G', '-F', str(config), host], stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, universal_newlines=True, env=env, timeout=30)
	assert result.returncode == 0, result.stderr
	for line in result.stdout.splitlines():
		key, _, value = line.partition(' ')
		if key == 'controlpath':
			return value if value != 'none' else None
	return None


@pytest.fixture
def places(tmp_path, monkeypatch):
	'''Stand-ins for /run/user and /dev/shm, and an ssh config holding just the block.'''
	if not shutil.which('ssh') or not os.path.exists('/bin/sh') or not hasattr(os, 'getuid'):
		pytest.skip('needs ssh and /bin/sh')
	uid = str(os.getuid())
	run_user = tmp_path / 'run-user'
	shm = tmp_path / 'shm'
	(run_user / uid).mkdir(parents=True, mode=0o700)
	shm.mkdir()
	shm.chmod(0o1777)
	monkeypatch.setattr(multiSSH3, '_RUN_USER_ROOT', str(run_user))
	monkeypatch.setattr(multiSSH3, '_SHM_DIR', str(shm))
	config = tmp_path / 'ssh_config'
	config.write_text(multiSSH3._control_master_block())
	return {
		'config': config, 'run_user': run_user / uid, 'shm': shm,
		'fallback': shm / ('multiSSH3-' + uid),
	}


def test_ssh_uses_run_user_while_it_exists(places):
	assert ssh_controlpath(places['config']).startswith(str(places['run_user']) + '/ssh_sockets_')
	# nothing made in the fallback place
	assert os.listdir(str(places['shm'])) == []


def test_without_run_user_ssh_uses_a_private_directory_it_makes(places, monkeypatch):
	places['run_user'].rmdir()
	assert ssh_controlpath(places['config']).startswith(str(places['fallback']) + '/ssh_sockets_')
	assert stat.S_IMODE(places['fallback'].stat().st_mode) == 0o700
	# the same directory mssh keeps its runtime state in, there
	monkeypatch.delenv('XDG_RUNTIME_DIR', raising=False)
	assert multiSSH3.runtime_dir() == str(places['fallback'])


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() == 0, reason='root can write anywhere')
def test_a_run_user_directory_we_cannot_write_to_is_passed_over(places):
	places['run_user'].chmod(0o500)
	try:
		assert ssh_controlpath(places['config']).startswith(str(places['fallback']) + '/')
	finally:
		places['run_user'].chmod(0o700)


@pytest.mark.parametrize('planted', ['open_mode', 'symlink', 'file'])
def test_ssh_does_not_share_through_a_place_others_could_write_to(places, planted, tmp_path):
	'''Whoever can put a socket where ssh looks for its master gets the user's terminal.'''
	places['run_user'].rmdir()
	fallback = places['fallback']
	if planted == 'open_mode':
		fallback.mkdir()
		fallback.chmod(0o777)
	elif planted == 'symlink':
		elsewhere = tmp_path / 'elsewhere'
		elsewhere.mkdir(mode=0o700)
		fallback.symlink_to(elsewhere)
	else:
		fallback.write_text('')
	assert ssh_controlpath(places['config']) is None


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0, reason='needs root to make a directory of another user')
def test_ssh_does_not_share_through_a_directory_someone_else_made_first(places):
	places['run_user'].rmdir()
	places['fallback'].mkdir(mode=0o700)
	os.chown(str(places['fallback']), 65534, 65534)
	assert ssh_controlpath(places['config']) is None


def test_with_no_usable_place_ssh_does_not_share(places):
	places['run_user'].rmdir()
	places['shm'].rmdir()
	assert ssh_controlpath(places['config']) is None
	assert not places['shm'].exists()
