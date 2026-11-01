import json
import os
import stat
from pathlib import Path

import pytest

import multiSSH3
from conftest import run_cli


def test_version_flag():
	r = run_cli(["--version"])
	assert r.returncode == 0
	assert multiSSH3.version in (r.stdout + r.stderr)


def test_load_config_file_roundtrip(tmp_path):
	cfg = tmp_path / "multiSSH3.config.json"
	data = {"DEFAULT_TIMEOUT": 12, "DEFAULT_HOSTS": "127.0.0.1"}
	cfg.write_text(json.dumps(data))
	loaded = multiSSH3.load_config_file(str(cfg))
	assert loaded == data


def test_cli_rejects_nonpositive_repeat_from_numeric_config_default(tmp_path):
	cfg = tmp_path / "multiSSH3.config.json"
	cfg.write_text(json.dumps({"DEFAULT_REPEAT": 0}))

	result = run_cli(["--config_file", str(cfg), "127.0.0.1", "true"])

	assert result.returncode == 2


def test_parser_hosts_and_command():
	parser = multiSSH3.get_parser()
	args = parser.parse_args(["127.0.0.1", "echo", "ok"])
	assert args.hosts == "127.0.0.1"
	assert args.commands == ["echo", "ok"]


# a config can hold anything: passwords with spaces, quotes and %, ssh's ControlPath with %r@%h:%p
SECRET_CONFIG = {
	"DEFAULT_PASSWORD": "Hunter2 pa%ss it's %(prog)s",
	"DEFAULT_IPMI_PASSWORD": "Bmc 100% s3cret",
	"DEFAULT_EXTRA_ARGS": "-o ControlPath=~/.ssh/cm-%r@%h:%p",
}


def test_help_never_shows_a_configured_password(tmp_path):
	cfg = tmp_path / "multiSSH3.config.json"
	cfg.write_text(json.dumps(SECRET_CONFIG))

	r = run_cli(["--config_file", str(cfg), "-h"])

	assert r.returncode == 0, r.stderr
	assert "Hunter2" not in r.stdout + r.stderr and "s3cret" not in r.stdout + r.stderr
	assert "or set MSSH_PASSWORD. (default: set, not shown)" in r.stdout
	assert "via ipmi. (default: set, not shown)" in r.stdout
	# the other defaults are still shown, % and all
	assert "(default: -o ControlPath=~/.ssh/cm-%r@%h:%p)" in r.stdout


def test_help_says_when_no_password_is_set(monkeypatch):
	monkeypatch.setattr(multiSSH3, "DEFAULT_PASSWORD", "")
	assert "or set MSSH_PASSWORD. (default: none)" in multiSSH3.get_parser().format_help()


def test_a_percent_in_a_config_default_does_not_stop_mssh(tmp_path):
	# Python 3.14+ rejects a help string argparse cannot %-format when the option is added: every run failed
	cfg = tmp_path / "multiSSH3.config.json"
	cfg.write_text(json.dumps(SECRET_CONFIG))

	r = run_cli(["--config_file", str(cfg), "--version"])

	assert r.returncode == 0, r.stderr


def test_help_shows_every_default_as_it_is(monkeypatch):
	# any config value can hold a %: shown once, never formatted (%(prog)s, %s), never doubled
	value = " 100% %s %(prog)s"
	for name in dir(multiSSH3):
		if name.startswith("DEFAULT_") and isinstance(getattr(multiSSH3, name), (str, int, float, type(None))):
			monkeypatch.setattr(multiSSH3, name, name + value)
	monkeypatch.setattr(multiSSH3, "FORCE_TRUECOLOR", "FORCE_TRUECOLOR" + value)
	monkeypatch.setattr(multiSSH3, "__working_config_file", "__working_config_file" + value)

	text = multiSSH3.get_parser().format_help()

	for name in ("DEFAULT_HOSTS", "DEFAULT_USERNAME", "DEFAULT_EXTRA_ARGS", "DEFAULT_IPMI_ARGS", "DEFAULT_SKIP_HOSTS",
			"DEFAULT_HISTORY_FILE", "DEFAULT_ENCODING", "DEFAULT_HOST_FILE", "FORCE_TRUECOLOR", "__working_config_file"):
		assert name + value in text, name
	assert "%%" not in text
	assert "DEFAULT_PASSWORD" not in text and "DEFAULT_IPMI_PASSWORD" not in text


def test_malformed_config_returns_empty(tmp_path, capsys):
	cfg = tmp_path / "bad.json"
	cfg.write_text("{not-json")
	assert multiSSH3.load_config_file(str(cfg)) == {}


def test_missing_config_returns_empty(tmp_path):
	assert multiSSH3.load_config_file(str(tmp_path / "nope.json")) == {}


def test_apply_config_key_compat_deafult_ipmi_args():
	cfg = {"DEAFULT_IPMI_ARGS": "-I lanplus"}
	multiSSH3.apply_config_key_compat(cfg)
	assert cfg["DEFAULT_IPMI_ARGS"] == "-I lanplus"
	assert cfg["DEAFULT_IPMI_ARGS"] == "-I lanplus"


def test_apply_config_key_compat_prefers_correct_key():
	cfg = {"DEAFULT_IPMI_ARGS": "old", "DEFAULT_IPMI_ARGS": "new"}
	multiSSH3.apply_config_key_compat(cfg)
	assert cfg["DEFAULT_IPMI_ARGS"] == "new"


@pytest.fixture
def umask_002():
	# user-private-group accounts get umask 002, so plain open() makes 0664 files
	old = os.umask(0o002)
	yield
	os.umask(old)


def _store_config(monkeypatch, path):
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(path), force=True)
	assert json.loads(path.read_text())["DEFAULT_PASSWORD"] == "secret"
	return stat.S_IMODE(path.stat().st_mode)


def test_store_config_file_is_owner_only(monkeypatch, tmp_path, umask_002):
	assert _store_config(monkeypatch, tmp_path / "new.json") == 0o600

	existing = tmp_path / "existing.json"
	existing.write_text("{}")
	existing.chmod(0o664)
	assert _store_config(monkeypatch, existing) == 0o600


def test_store_config_file_keeps_system_wide_location_readable(monkeypatch, tmp_path, umask_002):
	system_config = tmp_path / "etc" / "multiSSH3.config.json"
	system_config.parent.mkdir()
	monkeypatch.setattr(multiSSH3, "CONFIG_FILE_CHAIN", ["~/.multiSSH3.config.json", str(system_config)])

	assert _store_config(monkeypatch, system_config) == 0o644


def test_store_config_file_refuses_file_it_cannot_make_private(monkeypatch, tmp_path, capsys):
	shared = tmp_path / "team.json"
	shared.write_text('{"DEFAULT_TIMEOUT": 5}')
	shared.chmod(0o666)  # someone else's file we can write but not chmod

	def not_our_file(fd, mode):
		raise PermissionError(1, "Operation not permitted")

	monkeypatch.setattr(multiSSH3.os, "fchmod", not_our_file)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(shared), force=True)

	# the passwords must not land in a file others can read, and the file must not be emptied
	assert shared.read_text() == '{"DEFAULT_TIMEOUT": 5}'
	assert '"DEFAULT_PASSWORD": "secret"' in capsys.readouterr().out


def test_store_config_file_keeps_locked_down_system_config_locked(monkeypatch, tmp_path, umask_002):
	system_config = tmp_path / "etc" / "multiSSH3.config.json"
	system_config.parent.mkdir()
	system_config.write_text("{}")
	system_config.chmod(0o600)
	monkeypatch.setattr(multiSSH3, "CONFIG_FILE_CHAIN", [str(system_config)])

	assert _store_config(monkeypatch, system_config) == 0o600


def test_failed_store_does_not_show_old_content_or_crash(monkeypatch, tmp_path, capsys):
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["--store_config_file", str(tmp_path / "missing-dir" / "cfg.json")])

	with pytest.raises(SystemExit):
		multiSSH3.process_config_file(args)

	err = capsys.readouterr().err
	assert "Unable to write" in err
	assert "content:" not in err


def _store_with_backup(monkeypatch, path):
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *args, **kwargs: None)  # default: back up
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(path), force=False)
	backup = Path(str(path) + ".bak")
	return stat.S_IMODE(path.stat().st_mode), stat.S_IMODE(backup.stat().st_mode)


def test_backed_up_locked_down_system_config_stays_locked(monkeypatch, tmp_path, umask_002):
	system_config = tmp_path / "etc" / "multiSSH3.config.json"
	system_config.parent.mkdir()
	system_config.write_text('{"DEFAULT_PASSWORD": "old"}')
	system_config.chmod(0o600)
	monkeypatch.setattr(multiSSH3, "CONFIG_FILE_CHAIN", [str(system_config)])

	assert _store_with_backup(monkeypatch, system_config) == (0o600, 0o600)


def test_backup_of_world_readable_config_is_made_private(monkeypatch, tmp_path, umask_002):
	old = tmp_path / "multiSSH3.config.json"
	old.write_text('{"DEFAULT_PASSWORD": "old"}')
	old.chmod(0o644)  # as 6.26 wrote it

	assert _store_with_backup(monkeypatch, old) == (0o600, 0o600)


def test_failed_overwrite_keeps_the_old_config(monkeypatch, tmp_path):
	import errno

	config = tmp_path / "multiSSH3.config.json"
	config.write_text('{"DEFAULT_PASSWORD": "old"}')

	def disk_full(*args, **kwargs):
		raise OSError(errno.ENOSPC, "No space left on device")

	monkeypatch.setattr(multiSSH3.os, "fsync", disk_full)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "new"])
	multiSSH3.write_default_config(args, str(config), force=True)

	assert config.read_text() == '{"DEFAULT_PASSWORD": "old"}'
	assert [p.name for p in tmp_path.iterdir()] == ["multiSSH3.config.json"]  # no temporary file left


def test_storing_through_a_symlinked_config_keeps_the_link(monkeypatch, tmp_path):
	dotfiles = tmp_path / "dotfiles"
	dotfiles.mkdir()
	real = dotfiles / "multiSSH3.config.json"
	real.write_text("{}")
	link = tmp_path / ".multiSSH3.config.json"
	link.symlink_to(real)

	_store_config(monkeypatch, link)

	assert link.is_symlink()
	assert json.loads(real.read_text())["DEFAULT_PASSWORD"] == "secret"


@pytest.mark.parametrize("stale_backup", [False, True], ids=["no_backup_yet", "backup_link_left_by_6_31"])
def test_backing_up_a_symlinked_config_keeps_the_link(monkeypatch, tmp_path, umask_002, stale_backup):
	dotfiles = tmp_path / "dotfiles"
	dotfiles.mkdir()
	real = dotfiles / "multiSSH3.config.json"
	real.write_text('{"DEFAULT_PASSWORD": "old"}')
	real.chmod(0o600)
	link = tmp_path / ".multiSSH3.config.json"
	link.symlink_to(real)
	backup = tmp_path / ".multiSSH3.config.json.bak"
	if stale_backup:
		# up to 6.31 the backup was the renamed link: a new backup must replace it, not write through it
		backup.symlink_to(real)

	assert _store_with_backup(monkeypatch, link) == (0o600, 0o600)

	# the dotfiles copy is updated through the link, the old config is copied next to the link
	assert link.is_symlink()
	assert json.loads(real.read_text())["DEFAULT_PASSWORD"] == "secret"
	assert not backup.is_symlink()
	assert backup.read_text() == '{"DEFAULT_PASSWORD": "old"}'
	assert [p.name for p in dotfiles.iterdir()] == ["multiSSH3.config.json"]


def _another_group():
	"""A group to stand in for another owner: root may use any, a user one of their own groups."""
	if not hasattr(os, "chown"):
		pytest.skip("no chown")
	if os.geteuid() == 0:
		return 65534
	others = [group for group in os.getgroups() if group != os.getgid()]
	if not others:
		pytest.skip("the user is in no other group")
	return others[0]


def test_the_backed_up_config_is_rewritten_with_the_owner_and_group_it_had(monkeypatch, tmp_path):
	# sudo keeping HOME: the new file made by root must stay the user's
	old = tmp_path / "multiSSH3.config.json"
	old.write_text('{"DEFAULT_PASSWORD": "old"}')
	old.chmod(0o600)
	group = _another_group()
	os.chown(str(old), -1, group)

	_store_with_backup(monkeypatch, old)

	assert json.loads(old.read_text())["DEFAULT_PASSWORD"] == "secret"
	assert old.stat().st_gid == group
	assert Path(str(old) + ".bak").read_text() == '{"DEFAULT_PASSWORD": "old"}'


@pytest.mark.parametrize("config_group", ["own", "other"])
def test_the_backup_of_a_symlinked_config_belongs_to_the_writer(monkeypatch, tmp_path, config_group):
	# as in 6.38: neither an old backup's owner nor the config's group (one we may not be in) can make the store fail
	dotfiles = tmp_path / "dotfiles"
	dotfiles.mkdir()
	real = dotfiles / "multiSSH3.config.json"
	real.write_text('{"DEFAULT_PASSWORD": "old"}')
	real.chmod(0o600)
	if config_group == "other":
		os.chown(str(real), -1, _another_group())
	link = tmp_path / ".multiSSH3.config.json"
	link.symlink_to(real)
	backup = Path(str(link) + ".bak")
	backup.write_text("{}")
	os.chown(str(backup), -1, _another_group())

	_store_with_backup(monkeypatch, link)

	assert backup.read_text() == '{"DEFAULT_PASSWORD": "old"}'
	assert backup.stat().st_gid == os.getgid()


def test_a_stale_backup_of_another_owner_does_not_stop_the_store(monkeypatch, tmp_path):
	# a backup left root's by an earlier sudo run, beside a symlinked config in a group we are not in
	dotfiles = tmp_path / "dotfiles"
	dotfiles.mkdir()
	real = dotfiles / "multiSSH3.config.json"
	real.write_text('{"DEFAULT_PASSWORD": "old"}')
	real.chmod(0o600)
	link = tmp_path / ".multiSSH3.config.json"
	link.symlink_to(real)
	backup = Path(str(link) + ".bak")
	backup.write_text("{}")
	real_lstat = os.lstat

	def not_in_its_group(fd, uid, gid):
		raise PermissionError(1, "Operation not permitted")

	def root_s(path, *args, **kwargs):
		st = real_lstat(path, *args, **kwargs)
		if str(path) == str(backup):
			return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, st.st_gid, st.st_size,
				int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
		return st

	monkeypatch.setattr(os, "fchown", not_in_its_group)
	monkeypatch.setattr(os, "lstat", root_s)
	_store_with_backup(monkeypatch, link)

	assert backup.read_text() == '{"DEFAULT_PASSWORD": "old"}'
	assert '"DEFAULT_PASSWORD": "secret"' in real.read_text()


@pytest.mark.parametrize("mode", [0o666, 0o600], ids=["too_open", "already_private"])
def test_someone_elses_config_is_not_written(monkeypatch, tmp_path, capsys, mode):
	# a file we cannot keep the owner of would be taken over by the rename: not replaced, whatever its mode
	shared = tmp_path / "team.json"
	shared.write_text('{"DEFAULT_TIMEOUT": 5}')
	shared.chmod(mode)
	monkeypatch.setattr(multiSSH3.os, "geteuid", lambda: 12345)  # the file belongs to someone else

	def not_our_file(fd, uid, gid):
		raise PermissionError(1, "Operation not permitted")

	monkeypatch.setattr(multiSSH3.os, "fchown", not_our_file)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(shared), force=True)

	assert shared.read_text() == '{"DEFAULT_TIMEOUT": 5}'
	assert '"DEFAULT_PASSWORD": "secret"' in capsys.readouterr().out
	assert stat.S_IMODE(shared.stat().st_mode) == mode
	assert [p.name for p in tmp_path.iterdir()] == ["team.json"]  # no temporary file left


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to chown a symlink")
def test_store_does_not_write_through_someone_elses_symlink(monkeypatch, tmp_path, capsys):
	victim = tmp_path / "victim"
	victim.write_text("precious")
	planted = tmp_path / "x.json"  # e.g. /tmp/x.json planted by another user
	planted.symlink_to(victim)
	os.lchown(planted, 23456, -1)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])

	multiSSH3.write_default_config(args, str(planted), force=True)

	assert victim.read_text() == "precious"
	assert sorted(p.name for p in tmp_path.iterdir()) == ["victim", "x.json"]  # no temporary file next to the victim


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give a file to another user")
def test_a_link_swapped_in_for_the_temporary_is_not_chowned(monkeypatch, tmp_path):
	# root writing a config in a directory of another user (sudo keeping HOME): that user can put a link
	# at the temporary's name between its creation and the chown, the owner goes to the open file only
	victim = tmp_path / "victim"
	victim.write_text("precious")
	config = tmp_path / "multiSSH3.config.json"
	config.write_text("{}")
	os.chown(str(config), 65534, 65534)
	real_open = os.open

	def swap_in_a_link(path, *args, **kwargs):
		fd = real_open(path, *args, **kwargs)
		if str(path).endswith(".tmp"):
			os.unlink(path)
			os.symlink(str(victim), path)
		return fd

	monkeypatch.setattr(multiSSH3.os, "open", swap_in_a_link)
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	multiSSH3.write_default_config(args, str(config), force=True)

	assert (victim.stat().st_uid, victim.stat().st_gid) == (0, 0)
	assert victim.read_text() == "precious"


# Under sudo: the config of the user who ran sudo is written with their rights. The unprivileged tests
# check whose rights are taken and how they are put back; the root ones (run in the test VM) do it for real.

def test_without_root_or_sudo_mssh_writes_as_itself(monkeypatch, tmp_path):
	monkeypatch.setenv("SUDO_UID", str(os.getuid()))
	if os.geteuid() != 0:
		assert multiSSH3._sudo_user_of(str(tmp_path)) is None
	monkeypatch.setattr(multiSSH3.os, "geteuid", lambda: 0)
	monkeypatch.delenv("SUDO_UID")
	assert multiSSH3._sudo_user_of(str(tmp_path)) is None


@pytest.mark.skipif(not hasattr(os, "seteuid") or os.geteuid() == 0, reason="POSIX, as a user other than root (root's own: the root tests)")
@pytest.mark.parametrize("name", ["config.json", "missing/config.json"], ids=["the_file", "a_missing_one_s_directory"])
def test_under_sudo_the_users_own_path_is_written_as_them(monkeypatch, tmp_path, name):
	monkeypatch.setattr(multiSSH3.os, "geteuid", lambda: 0)
	monkeypatch.setenv("SUDO_UID", str(os.getuid()))
	monkeypatch.setenv("SUDO_GID", str(os.getgid()))
	(tmp_path / "config.json").write_text("{}")

	uid, gid, groups = multiSSH3._sudo_user_of(str(tmp_path / name))

	assert (uid, gid) == (os.getuid(), os.getgid()) and gid in groups
	monkeypatch.setenv("SUDO_UID", str(os.getuid() + 1))  # a path of someone else than the user who ran sudo
	assert multiSSH3._sudo_user_of(str(tmp_path / name)) is None


@pytest.mark.skipif(not hasattr(os, "seteuid"), reason="POSIX only")
@pytest.mark.parametrize("fails", [False, True], ids=["the_block_ends", "the_block_raises"])
def test_root_s_ids_are_put_back_in_order(monkeypatch, fails):
	calls = []
	for name in ("setgroups", "setegid", "seteuid"):
		monkeypatch.setattr(multiSSH3.os, name, lambda value, name=name: calls.append((name, value)))
	monkeypatch.setattr(multiSSH3.os, "getgroups", lambda: [0, 1])
	monkeypatch.setattr(multiSSH3.os, "getegid", lambda: 0)

	try:
		with multiSSH3._as_user((1000, 1001, [1001, 27])):
			calls.append("block")
			if fails:
				raise RuntimeError
	except RuntimeError:
		assert fails

	assert calls == [("setgroups", [1001, 27]), ("setegid", 1001), ("seteuid", 1000), "block",
		("seteuid", 0), ("setegid", 0), ("setgroups", [0, 1])]


needs_root = pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to act as the user who ran sudo")
SUDO_USER_ID = 65534
STRANGER = 23456


@pytest.fixture
def sudo_home(monkeypatch):
	"""root under `sudo -E`: the user who ran sudo is nobody, with a home and a dotfiles directory they can reach."""
	import shutil
	import tempfile

	base = Path(tempfile.mkdtemp(prefix="mssh-sudo-", dir="/tmp"))  # tmp_path is under root's 0700 directory
	base.chmod(0o755)
	home = base / "home"
	dotfiles = home / "dotfiles"
	dotfiles.mkdir(parents=True)
	for directory in (home, dotfiles):
		os.chown(str(directory), SUDO_USER_ID, SUDO_USER_ID)
	monkeypatch.setenv("SUDO_UID", str(SUDO_USER_ID))
	monkeypatch.setenv("SUDO_GID", str(SUDO_USER_ID))
	ids = (os.geteuid(), os.getegid(), sorted(os.getgroups()))
	yield home
	assert (os.geteuid(), os.getegid(), sorted(os.getgroups())) == ids  # root's again
	shutil.rmtree(str(base))


def _users_file(path, text):
	path.write_text(text)
	path.chmod(0o600)
	os.chown(str(path), SUDO_USER_ID, SUDO_USER_ID)
	return path


def _owner(path):
	st = os.lstat(str(path))
	return st.st_uid, st.st_gid


def _store_answering(monkeypatch, path, answer):
	monkeypatch.setattr(multiSSH3, "__configs_from_file", {})
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *args, **kwargs: answer)
	args = multiSSH3.process_args(["127.0.0.1", "true", "-p", "secret"])
	return multiSSH3.write_default_config(args, str(path), force=False)


@needs_root
@pytest.mark.parametrize("answer", ["b", "o"])
def test_under_sudo_the_users_dotfiles_link_is_written_through(monkeypatch, sudo_home, answer):
	real = _users_file(sudo_home / "dotfiles" / "multiSSH3.config.json", '{"DEFAULT_PASSWORD": "old"}')
	link = sudo_home / ".multiSSH3.config.json"
	link.symlink_to(real)
	os.lchown(str(link), SUDO_USER_ID, SUDO_USER_ID)

	assert _store_answering(monkeypatch, link, answer)

	assert link.is_symlink() and json.loads(real.read_text())["DEFAULT_PASSWORD"] == "secret"
	assert _owner(real) == (SUDO_USER_ID, SUDO_USER_ID)
	backup = Path(str(link) + ".bak")
	if answer == "b":
		assert not backup.is_symlink() and backup.read_text() == '{"DEFAULT_PASSWORD": "old"}'
		assert _owner(backup) == (SUDO_USER_ID, SUDO_USER_ID) and stat.S_IMODE(backup.stat().st_mode) == 0o600
	else:
		assert not os.path.lexists(str(backup))
	assert sorted(os.listdir(str(sudo_home / "dotfiles"))) == ["multiSSH3.config.json"]


@needs_root
def test_under_sudo_the_users_config_and_its_backup_stay_theirs(monkeypatch, sudo_home):
	config = _users_file(sudo_home / ".multiSSH3.config.json", '{"DEFAULT_PASSWORD": "old"}')

	assert _store_answering(monkeypatch, config, "b")

	assert json.loads(config.read_text())["DEFAULT_PASSWORD"] == "secret"
	assert _owner(config) == (SUDO_USER_ID, SUDO_USER_ID) and stat.S_IMODE(config.stat().st_mode) == 0o600
	backup = Path(str(config) + ".bak")
	assert backup.read_text() == '{"DEFAULT_PASSWORD": "old"}' and _owner(backup) == (SUDO_USER_ID, SUDO_USER_ID)


@needs_root
def test_under_sudo_a_new_config_is_the_users(monkeypatch, sudo_home):
	config = sudo_home / ".multiSSH3.config.json"

	assert _store_answering(monkeypatch, config, None)

	assert json.loads(config.read_text())["DEFAULT_PASSWORD"] == "secret"
	assert _owner(config) == (SUDO_USER_ID, SUDO_USER_ID) and stat.S_IMODE(config.stat().st_mode) == 0o600


@needs_root
def test_under_sudo_the_users_link_is_followed_only_where_they_may_write(monkeypatch, sudo_home, capsys):
	# written with the user's rights, not root's: the kernel refuses a file the user may not write
	roots = sudo_home.parent / "roots.json"
	roots.write_text("{}")
	roots.chmod(0o644)
	link = sudo_home / ".multiSSH3.config.json"
	link.symlink_to(roots)
	os.lchown(str(link), SUDO_USER_ID, SUDO_USER_ID)

	assert not _store_answering(monkeypatch, link, "o")

	assert roots.read_text() == "{}" and _owner(roots) == (0, 0)
	assert '"DEFAULT_PASSWORD": "secret"' in capsys.readouterr().out
	assert sorted(os.listdir(str(sudo_home.parent))) == ["home", "roots.json"]


@needs_root
@pytest.mark.parametrize("answer", ["b", "o"])
def test_under_sudo_a_strangers_link_is_not_written_through(monkeypatch, sudo_home, answer):
	shared = sudo_home.parent / "shared"  # e.g. /tmp
	shared.mkdir(mode=0o777)
	shared.chmod(0o1777)
	victim = _users_file(sudo_home / "dotfiles" / "victim", "precious")
	planted = shared / "x.json"
	planted.symlink_to(victim)
	os.lchown(str(planted), STRANGER, STRANGER)

	_store_answering(monkeypatch, planted, answer)

	assert victim.read_text() == "precious" and _owner(victim) == (SUDO_USER_ID, SUDO_USER_ID)
	assert sorted(os.listdir(str(sudo_home / "dotfiles"))) == ["victim"]


@needs_root
def test_under_sudo_a_third_users_config_is_written_by_root_keeping_its_owner(monkeypatch, sudo_home):
	# as 6.39: root writing a config of someone else than the user who ran sudo keeps its owner and group
	config = sudo_home.parent / "theirs.json"
	config.write_text('{"DEFAULT_PASSWORD": "old"}')
	config.chmod(0o600)
	os.chown(str(config), STRANGER, STRANGER)

	assert _store_answering(monkeypatch, config, "o")

	assert json.loads(config.read_text())["DEFAULT_PASSWORD"] == "secret" and _owner(config) == (STRANGER, STRANGER)


@needs_root
@pytest.mark.parametrize("sudo", [False, True], ids=["root", "under_sudo"])
def test_a_config_put_in_place_of_a_strangers_link_is_roots(monkeypatch, tmp_path, sudo):
	# b moves a link planted e.g. in /tmp aside and writes root's config (it can hold passwords) in its place:
	# not the file of whoever owns what the link points to
	theirs = tmp_path / "theirs.json"
	theirs.write_text("{}")
	os.chown(str(theirs), STRANGER, STRANGER)
	planted = tmp_path / "x.json"
	planted.symlink_to(theirs)
	os.lchown(str(planted), STRANGER, STRANGER)
	if sudo:
		monkeypatch.setenv("SUDO_UID", str(SUDO_USER_ID))
		monkeypatch.setenv("SUDO_GID", str(SUDO_USER_ID))

	assert _store_answering(monkeypatch, planted, "b")

	assert theirs.read_text() == "{}"
	assert not planted.is_symlink() and _owner(planted) == (0, 0) and stat.S_IMODE(planted.stat().st_mode) == 0o600
	assert os.path.islink(str(planted) + ".bak")
