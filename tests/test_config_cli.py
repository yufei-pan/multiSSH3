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


def test_the_backup_of_a_symlinked_config_belongs_to_the_writer_not_to_the_old_backup(monkeypatch, tmp_path):
	# an old backup of another owner (root's, after a sudo run) must not make the next store fail
	dotfiles = tmp_path / "dotfiles"
	dotfiles.mkdir()
	real = dotfiles / "multiSSH3.config.json"
	real.write_text('{"DEFAULT_PASSWORD": "old"}')
	real.chmod(0o600)
	link = tmp_path / ".multiSSH3.config.json"
	link.symlink_to(real)
	backup = Path(str(link) + ".bak")
	backup.write_text("{}")
	os.chown(str(backup), -1, _another_group())

	_store_with_backup(monkeypatch, link)

	assert backup.read_text() == '{"DEFAULT_PASSWORD": "old"}'
	assert backup.stat().st_gid == os.getgid()


@pytest.mark.parametrize("mode", [0o666, 0o600], ids=["too_open", "already_private"])
def test_someone_elses_config_is_not_written(monkeypatch, tmp_path, capsys, mode):
	# a file we cannot keep the owner of would be taken over by the rename: not replaced, whatever its mode
	shared = tmp_path / "team.json"
	shared.write_text('{"DEFAULT_TIMEOUT": 5}')
	shared.chmod(mode)
	monkeypatch.setattr(multiSSH3.os, "getuid", lambda: 12345)  # the file belongs to someone else

	def not_our_file(path, uid, gid):
		raise PermissionError(1, "Operation not permitted")

	monkeypatch.setattr(multiSSH3.os, "chown", not_our_file)
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
