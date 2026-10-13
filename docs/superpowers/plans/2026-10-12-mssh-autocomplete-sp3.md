# mssh Autocomplete SP3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Warn about mistakes in an mssh line while it is typed (unknown hosts, range surprises, unreachable hosts, conflicting options), never blocking Enter, with background DNS and ping knowledge kept fresh, and move all of mssh's runtime state to one fallback chain of reboot-cleared directories.

**Architecture:** `multiSSH3.py` keeps host semantics: the runtime-directory chain, `host_validity` (mssh's host rule with three DNS answers) and `OPTION_NO_EFFECT`. `mssh_complete.py` gains a host-state cache and probe queue in the runtime directory, a detached lock-guarded prober (`mssh-complete probe`: DNS, `ssh -G`, ping; as parallel as mssh's own `max_connections`; never connects to a host), and `Engine.diagnose`, answered for requests with `diag=1` as `W` records, an `R` reason line and a `pending` directive. The picker, the plain-bash line editor, zsh, ble.sh and fish show the warnings; queries only read the cache and never wait on the network.

**Tech Stack:** Python 3.6+ standard library only (socket, threading, subprocess); bash 4.2+ readline, the bash line editor (bash 4.4+), zsh 5.3+ zle (`region_highlight`, `zle -M`, `zle -F`, `add-zle-hook-widget`), zsh-autosuggestions 0.7.1, fish 4 (warnings) / fish 3.0+ (Ctrl-R), ble.sh nightly 2026-09-08 (highlight layers, info line, idle tasks); iputils `ping`; pytest; Docker for the shell matrix.

**Spec:** `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp3-design.md` (read it; where this plan differs, the "Deviations from the spec" section says why, and Task 14 appends that table to the spec).

## Global Constraints

- Python syntax and library floor is 3.6: no walrus, no dataclasses, no `subprocess.run(capture_output=...)`. Standard library only.
- Single-file modules: SP3 lives in `mssh_complete.py` and `multiSSH3.py`; the keystroke path never imports `multiSSH3` (the prober and the index builder may).
- Never cost keystrokes: warnings never block Enter, never alter typed text, never take a key from the shell (fish 3 keeps its space key).
- When unsure, say nothing: a DNS timeout, a resolver error, a failing `ssh -G`, a missing `ping`, a host that never answered ping: no warning. Only "no such name" makes a host unknown.
- Never reach a host with credentials: the prober only calls `getaddrinfo`, `ssh -G` (reads the ssh config) and `ping`; no TCP connection to any port, no ssh session, no password or key.
- A keystroke never waits on the network: queries read `host-state.tsv`; the prober fills it in the background.
- Runtime state (index, lock files, `unavailable_hosts.csv`, `complete.log`, `host-state.tsv`, `probe-queue`, `probe.lock`) lives in the runtime chain ($XDG_RUNTIME_DIR/multiSSH3, /run/user/<uid>/multiSSH3, /dev/shm/multiSSH3-<uid>, <tempdir>/multiSSH3-<uid>); files with times in them carry the boot id.
- Prober limits adapt: parallelism is mssh's `_normalize_max_connections(DEFAULT_MAX_CONNECTIONS)`, halved while the 1-minute load average is at or above the CPU count (never below 4) and on EMFILE / ENFILE / EAGAIN; a run lasts at most 120 s; nice 10.
- Ping expiry: mssh's unreachable-host expiry (600 s unless the mssh config changes it), `-uhe` on the line, `$MSSH_COMPLETE_PING_TTL` first.
- Only finished words are checked: the word under or just before the cursor is skipped.
- Glue floors: bash 4.2 (ble.sh: as tested), zsh 5.3 for the warnings, fish 4 for the reason line (fish 3: picker only).
- Repository style: tabs, `'''` docstrings, sparse comments, pytest tests as plain `test_*` functions in `tests/`.
- The whole suite passes after every task; the Docker matrix passes for the shells a task touches (Tasks 10 to 13) and in full after Task 14. Shell tests never start a prober (Task 11's harness holds its lock).
- End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e`.

## Review Focus

Failure modes the spec implies that a person using this would hit first; each has a test in the task that owns the code.

1. **A word still being typed** must never be marked (it would flash "unknown host" at every key): `test_the_word_being_typed_is_left_alone` (Task 6), `test_no_warnings_are_asked_for_while_keys_wait` (Task 10).
2. **A host that blocks ICMP but takes ssh, a slow DNS server** must never produce a warning: `test_ping_silence_alone_says_nothing` (Task 7), `test_a_lookup_that_hangs_is_unsure` (Task 2).
3. **A password** must never appear in a warning, also attached (`-ip=secret`) or given twice: `test_an_option_given_twice`, `test_options_that_do_nothing_here` (Task 8).
4. **The background checks never connect to a host** (fail2ban in `aggressive` mode counts any pre-auth connection, and every user of a login node shares its address): `test_the_prober_never_connects_to_a_host` (Task 5).
5. **A session without `$XDG_RUNTIME_DIR`** (su, sudo -u, cron, a broken PAM profile) keeps its runtime state, and mssh and mssh-complete agree where: `test_the_first_usable_place_wins_in_both_modules` (Task 1).

## Deviations from the spec

| Area | The design said | Implemented | Why |
|---|---|---|---|
| Reason line | Each shell composes "first warning (+N more)" from the `W` records | The response also carries the composed line as an `R` record | zsh, ble.sh and fish show the same text without three copies of the logic; the mark is `⚠` or `!` by the engine's locale, which is the shell's |
| zsh queries | `diag=1` in the grey-text query when one is sent | zsh asks with its own `diag=1` query, only when the finished words of the line change | warnings then work the same with zsh's own widgets and with zsh-autosuggestions, and typing inside a word costs nothing |
| fish | Reason printed after space on every fish 3.3+ | fish 4 only; fish 3 keeps its space key and shows warnings in the picker | fish 3 inserts nothing for `self-insert` in a binding that also runs a function, so taking space broke typing |
| ble.sh reason line | `ble/edit/info/set-default` | set as the default and drawn at once, as `ble/edit/info/immediate-show` draws | a deferred default only appears at ble.sh's next panel render |
| Flag defaults | (not specified) | the index records what mssh's flags set and their defaults (config rows `flag_sets`, `flag_defaults`) and the `OPTION_NO_EFFECT` entries (section `no_effect`) | skipping (`-su`) and "on by default" (`--ipmi`) follow the mssh config without importing mssh on the keystroke path |
| Ping expiry | `MSSH_COMPLETE_PING_TTL`, else mssh's default expiry | also `-uhe` on the line | it is mssh's unreachable host expiry for that run |
| IPv4 ranges | (not specified) | parts in mssh's IPv4 range syntax (`127.0.0.1-20`, `10.0.[1-2].x`) get no warning | they hold only IP addresses; replaying real history flagged `127.0.0.1-20` before this |
| Probe queue | Queries append hosts | hosts already waiting are left out | a query for a long range repeats on every keystroke |
| Ranges past the member limit | Checked up to the limit | the first `RANGE_MEMBERS_LIMIT` members are checked, the total is counted without expanding | `expand_ranges` gives up on a range over its limit |
| Shell tests | (not specified) | the harness holds the prober's lock (tests write host states themselves) and gives the terminal a size | no DNS or ping from tests; ble.sh sizes its info panel from the terminal |

## How this plan was verified

Every code block in this plan was run before the plan was written: SP3 was built in a scratch clone, one commit per task. A script then turned each commit into this plan's steps, applied them in order to a clean checkout of the spec commit, and checked for every task that its tests fail before the implementation step and pass after it (for ble.sh and fish, which this machine lacks, the failure shows in the Docker matrix), that the whole suite passes after it, that the matrix passes where the task says, and that the files are then byte-for-byte the verified commit. The "Expected" lines below are that run's output.

## File Structure

| File | Responsibility |
|---|---|
| `multiSSH3.py` | `runtime_dir` (the chain; `_unavailable_hosts_file_path` uses it); `host_validity`; `OPTION_NO_EFFECT`; version 6.30. |
| `mssh_complete.py` | `cache_dir` follows the chain; new sections Host state (cache, queue), Prober (`run_probe`, `spawn_probe`, `mssh-complete probe`) and Diagnostics (`Diagnostic`, helpers) before Engine; `Engine.diagnose` and its checks; `diag=1`, `W`, `R`, `pending` in the protocol; index rows for flag settings and `no_effect`; picker warnings, `reason_line`; the line editor's warnings; zsh, ble.sh and fish glue; `eval --diagnostics`; version 0.3. |
| `tests/test_runtime_dir.py`, `tests/test_host_validity.py`, `tests/test_option_no_effect.py` | The runtime chain; mssh's host rule; option combinations with no effect. |
| `tests/test_complete_hoststate.py`, `tests/test_complete_probe.py` | Host-state cache and queue; the prober. |
| `tests/test_complete_diagnose.py` | The four checks, ordering, the protocol. |
| `tests/test_complete_picker.py`, `tests/test_complete_editor.py`, `tests/test_complete_keys.py` | Warnings in the picker, the line editor, and real bash, zsh, ble.sh and fish. |
| `tests/complete_shell_harness.py`, `tests/vt_grid.py`, `tests/conftest.py` | No prober and a sized terminal in shell tests; waiting in `FakeTerminal`; no real /run/user or /dev/shm in tests. |
| `tests/test_complete_eval.py`, `tests/bench_complete.py` | The warnings replayed over history; warning query timings. |

---
Starting point: branch `mssh-autocomplete-sp3` at the spec commit; `python3 -m pytest -q` gives `835 passed, 32 skipped in 71.39s (0:01:11)`.

### Task 1: Runtime directory chain

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/test_runtime_dir.py`
- Modify: `mssh_complete.py`
- Modify: `multiSSH3.py`

**Interfaces:**
- Consumes: multiSSH3: `_private_dir`, `_owned_and_not_writable_by_others`, `_unavailable_hosts_file_path`; mssh_complete: `cache_dir`, `_private_dir`
- Produces: multiSSH3: `_RUN_USER_ROOT = '/run/user'`, `_SHM_DIR = '/dev/shm'`, `runtime_dir(create=True) -> str | None` ($XDG_RUNTIME_DIR/multiSSH3, /run/user/<uid>/multiSSH3, /dev/shm/multiSSH3-<uid>, <tempdir>/multiSSH3-<uid>); `_unavailable_hosts_file_path(create=True)` is `runtime_dir(create)` + `unavailable_hosts.csv`. mssh_complete: the same two constants, `cache_dir(create=True)` the same chain. tests/conftest.py: an autouse fixture points both modules' `_RUN_USER_ROOT` / `_SHM_DIR` at paths that cannot exist, so no test touches the real ones.

- [ ] **Step 1: Write the failing tests**

In `tests/conftest.py`, replace this text (it occurs exactly once):

````python
		if fn is not None and hasattr(fn, "cache_clear"):
			fn.cache_clear()


````

with:

````python
		if fn is not None and hasattr(fn, "cache_clear"):
			fn.cache_clear()


@pytest.fixture(autouse=True)
def no_system_runtime_dirs():
	"""Keep tests out of the real /run/user/<uid> and /dev/shm: the runtime chain sees neither."""
	import mssh_complete
	# a patcher of its own: a test's monkeypatch must still be undone before restore_module_globals runs
	with pytest.MonkeyPatch.context() as patch:
		for module in (multiSSH3, mssh_complete):
			patch.setattr(module, "_RUN_USER_ROOT", "/dev/null/no-run-user", raising=False)
			patch.setattr(module, "_SHM_DIR", "/dev/null/no-shm", raising=False)
		yield


````

Create `tests/test_runtime_dir.py` with exactly this content:

````python
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
def test_without_any_usable_place_there_is_no_runtime_dir(places, monkeypatch):
	monkeypatch.delenv('XDG_RUNTIME_DIR')
	for name in ('run_user', 'shm', 'temp'):
		os.rmdir(str(places['roots'][name]))
	assert multiSSH3.runtime_dir() is None and mc.cache_dir() is None
	assert multiSSH3._unavailable_hosts_file_path() is None


@posix_only
def test_reading_creates_nothing(places, monkeypatch):
	monkeypatch.delenv('XDG_RUNTIME_DIR')
	assert multiSSH3.runtime_dir(create=False) is None and mc.cache_dir(create=False) is None
	assert not places['run_user'].exists()
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_runtime_dir.py tests/test_unavailable_hosts.py tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'multiSSH3' has no attribute 'runtime_dir'` (`9 failed, 43 passed in 0.33s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

def cache_dir(create=True):
	'''
	mssh's private cache directory, where unavailable_hosts.csv lives, or None.

	$XDG_RUNTIME_DIR/multiSSH3 when the runtime dir is ours, else <tempdir>/multiSSH3-<uid>,
	exactly as multiSSH3._unavailable_hosts_file_path picks it.
	'''
	import tempfile
````

with:

````python
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

# as in multiSSH3 (tests point them elsewhere)
_RUN_USER_ROOT = '/run/user'
_SHM_DIR = '/dev/shm'

def cache_dir(create=True):
	'''
	mssh's private runtime directory, where unavailable_hosts.csv and the index live, or None.

	Exactly as multiSSH3.runtime_dir picks it: $XDG_RUNTIME_DIR/multiSSH3 when that runtime dir
	is ours, /run/user/<uid>/multiSSH3, /dev/shm/multiSSH3-<uid>, then <tempdir>/multiSSH3-<uid>.
	'''
	import tempfile
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	if runtime_dir and _owned_and_not_writable_by_others(runtime_dir):
		candidates.append(os.path.join(runtime_dir, 'multiSSH3'))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
````

with:

````python
	if runtime_dir and _owned_and_not_writable_by_others(runtime_dir):
		candidates.append(os.path.join(runtime_dir, 'multiSSH3'))
	if hasattr(os, 'getuid'):
		run_user = os.path.join(_RUN_USER_ROOT, str(user_id))
		if _owned_and_not_writable_by_others(run_user):
			candidates.append(os.path.join(run_user, 'multiSSH3'))
		if os.path.isdir(_SHM_DIR):
			candidates.append(os.path.join(_SHM_DIR, 'multiSSH3-{}'.format(user_id)))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
````

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

def _unavailable_hosts_file_path(create=True):
	'''
	Where unavailable hosts are cached between runs, or None to run without the cache.

	create: set up the private cache directory (for writing). Without it only an existing one
	is used, so reading the cache changes nothing on disk.

	The per-user runtime dir ($XDG_RUNTIME_DIR) is private and cleared at reboot. Without
	it (cron, su, non systemd), a private directory in the temp dir is used. The home
	directory is avoided so mssh keeps working when it is full or read-only.
	'''
	user_id = os.getuid() if hasattr(os, 'getuid') else getpass.getuser()
	candidates = []
	runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
	# with another user's environment (sudo -E, su) the runtime dir is theirs, they could swap our subdirectory
	if runtime_dir and _owned_and_not_writable_by_others(runtime_dir):
		candidates.append(os.path.join(runtime_dir, 'multiSSH3'))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for cache_dir in candidates:
		if _private_dir(cache_dir, create):
			return os.path.join(cache_dir, 'unavailable_hosts.csv')
	return None


````

with:

````python
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

# where logind makes per-user runtime directories, and the tmpfs every Linux mounts (tests point them elsewhere)
_RUN_USER_ROOT = '/run/user'
_SHM_DIR = '/dev/shm'

def runtime_dir(create=True):
	'''
	mssh's private directory for state that must not outlive a reboot, or None to run without it.

	create: set up the directory (for writing). Without it only an existing one is used, so
	reading changes nothing on disk.

	The first of these that is a directory only we control (_private_dir):
	1. $XDG_RUNTIME_DIR/multiSSH3, when $XDG_RUNTIME_DIR is ours and only we can write to it
	2. /run/user/<uid>/multiSSH3, the same place when su, sudo -u or cron leave $XDG_RUNTIME_DIR unset
	3. /dev/shm/multiSSH3-<uid>: tmpfs, so local and cleared at reboot, and there without a login session
	4. <tempdir>/multiSSH3-<uid>: may survive a reboot, so state with a time in it carries the boot id
	The home directory is avoided so mssh keeps working when it is full or read-only.
	mssh_complete.cache_dir picks the same directory.
	'''
	user_id = os.getuid() if hasattr(os, 'getuid') else getpass.getuser()
	candidates = []
	xdg_runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
	# with another user's environment (sudo -E, su) the runtime dir is theirs, they could swap our subdirectory
	if xdg_runtime_dir and _owned_and_not_writable_by_others(xdg_runtime_dir):
		candidates.append(os.path.join(xdg_runtime_dir, 'multiSSH3'))
	if hasattr(os, 'getuid'):
		run_user = os.path.join(_RUN_USER_ROOT, str(user_id))
		if _owned_and_not_writable_by_others(run_user):
			candidates.append(os.path.join(run_user, 'multiSSH3'))
		if os.path.isdir(_SHM_DIR):
			candidates.append(os.path.join(_SHM_DIR, 'multiSSH3-{}'.format(user_id)))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
		if _private_dir(directory, create):
			return directory
	return None

def _unavailable_hosts_file_path(create=True):
	'''
	Where unavailable hosts are cached between runs (in runtime_dir), or None to run without the cache.

	create: set up the runtime directory (for writing). Without it only an existing one is used,
	so reading the cache changes nothing on disk.
	'''
	directory = runtime_dir(create)
	return os.path.join(directory, 'unavailable_hosts.csv') if directory else None


````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_runtime_dir.py tests/test_unavailable_hosts.py tests/test_complete_index.py -q`

Expected: PASS (`52 passed in 0.33s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `844 passed, 32 skipped in 70.84s (0:01:10)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py multiSSH3.py tests/conftest.py tests/test_runtime_dir.py
git commit -F - <<'EOF'
feat: one runtime-directory chain for mssh and mssh-complete

$XDG_RUNTIME_DIR, /run/user/<uid>, /dev/shm, then the temp dir: mssh keeps
its runtime state when the session's runtime dir is missing.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 2: host_validity: mssh's host rule with three DNS answers

**Files:**
- Create: `tests/test_host_validity.py`
- Modify: `multiSSH3.py`

**Interfaces:**
- Consumes: multiSSH3: `_local_hostname_source`, `_ssh_config_values`, `_ssh_config_target`, `_binPaths`
- Produces: multiSSH3: `host_validity(hostname, timeout=2.0) -> 'valid' | 'invalid' | 'unsure'` (user@ allowed; only EAI_NONAME / EAI_NODATA make a name invalid; a timeout, another error or a failing `ssh -G` give unsure); `_dns_answer(hostname, timeout) -> 'yes' | 'no' | 'unsure'`; `_DNS_NO_SUCH_NAME`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_host_validity.py` with exactly this content:

````python
'''host_validity: mssh's own rule for a host name, with "does not exist" told apart from "no answer".'''
import shutil
import socket
import threading
import time

import pytest

import multiSSH3


@pytest.fixture
def hermetic(monkeypatch, tmp_path):
	'''No hosts file, env or env-file aliases, no ssh: names only go to (fake) DNS.'''
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(tmp_path / 'no-hosts'))
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
	monkeypatch.setattr(multiSSH3, '_no_env', True)
	monkeypatch.setattr(multiSSH3, '_env_files', [str(tmp_path / 'no-env')])
	monkeypatch.delitem(multiSSH3._binPaths, 'ssh', raising=False)
	multiSSH3.readEnvFromFile.cache_clear()
	multiSSH3.getIP.cache_clear()
	yield tmp_path
	multiSSH3.getIP.cache_clear()
	multiSSH3.readEnvFromFile.cache_clear()


def fake_dns(monkeypatch, answers):
	'''getaddrinfo answering from answers: name -> an address, a gaierror code, or 'hang'; others do not exist.'''
	def getaddrinfo(host, *args, **kwargs):
		answer = answers.get(host, socket.EAI_NONAME)
		if answer == 'hang':
			threading.Event().wait(5)
			raise socket.gaierror(socket.EAI_AGAIN, 'timed out')
		if isinstance(answer, int):
			raise socket.gaierror(answer, 'fake')
		return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (answer, 0))]
	monkeypatch.setattr(multiSSH3.socket, 'getaddrinfo', getaddrinfo)


@pytest.mark.parametrize('answer, verdict', [
	('10.0.0.5', 'valid'),
	(socket.EAI_NONAME, 'invalid'),
	# no answer, a broken resolver: nothing is known about the name
	(socket.EAI_AGAIN, 'unsure'),
	(socket.EAI_FAIL, 'unsure'),
])
def test_dns_answers_in_three_ways(hermetic, monkeypatch, answer, verdict):
	fake_dns(monkeypatch, {'gpu17': answer})
	assert multiSSH3.host_validity('gpu17') == verdict


def test_a_lookup_that_hangs_is_unsure(hermetic, monkeypatch):
	fake_dns(monkeypatch, {'slow': 'hang'})
	started = time.monotonic()
	assert multiSSH3.host_validity('slow', timeout=0.2) == 'unsure'
	assert time.monotonic() - started < 2


def test_local_names_need_no_dns(hermetic, monkeypatch):
	hosts = hermetic / 'hosts'
	hosts.write_text('10.0.0.9 node9\n')
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(hosts))
	fake_dns(monkeypatch, {})
	assert [multiSSH3.host_validity(name) for name in ('node9', 'root@node9', '10.1.2.3')] == ['valid'] * 3


def test_an_env_alias_is_valid(hermetic, monkeypatch):
	monkeypatch.setattr(multiSSH3, '_no_env', False)
	monkeypatch.setenv('MSSHTESTGROUP', 'node1,node2')
	fake_dns(monkeypatch, {})
	assert multiSSH3.host_validity('MSSHTESTGROUP') == 'valid'


def test_ssh_config_mapping_is_mssh_s_rule(hermetic, monkeypatch):
	# ssh -G only reads the config: a HostName or a ProxyJump makes a name valid, a catch-all block does not
	real_ssh = shutil.which('ssh')
	if not real_ssh:
		pytest.skip('ssh not installed')
	config = hermetic / 'ssh_config'
	config.write_text('Host gpu-alias\n  HostName 127.0.0.7\nHost jump-*\n  ProxyJump bastion2\nHost *\n  ProxyJump bastion\n')
	wrapper = hermetic / 'ssh'
	wrapper.write_text('#!/bin/sh\nexec {} -F {} "$@"\n'.format(real_ssh, config))
	wrapper.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', str(wrapper))
	fake_dns(monkeypatch, {})
	assert [multiSSH3.host_validity(name) for name in ('gpu-alias', 'jump-a', 'nodee1-typo')] == ['valid', 'valid', 'invalid']


def test_an_ssh_config_that_cannot_be_read_is_unsure(hermetic, monkeypatch):
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', shutil.which('false') or '/bin/false')
	fake_dns(monkeypatch, {})
	assert multiSSH3.host_validity('gpu17') == 'unsure'
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_host_validity.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'multiSSH3' has no attribute 'host_validity'` (`9 failed in 0.02s`)

- [ ] **Step 3: Implement**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
		return 'env_file'
	return None

@cache_decorator
````

with:

````python
		return 'env_file'
	return None

# getaddrinfo errors saying the name does not exist; any other failure says nothing about it
_DNS_NO_SUCH_NAME = frozenset(code for code in (getattr(socket, 'EAI_NONAME', None), getattr(socket, 'EAI_NODATA', None)) if code is not None)

def _dns_answer(hostname, timeout):
	''''yes' when DNS resolves hostname, 'no' when it says the name does not exist, else 'unsure'.'''
	result = []
	def lookup():
		try:
			socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
			result.append('yes')
		except socket.gaierror as e:
			result.append('no' if e.errno in _DNS_NO_SUCH_NAME else 'unsure')
		except Exception:
			result.append('unsure')
	# getaddrinfo takes no timeout: a lookup still running after it is left to finish on its own
	thread = threading.Thread(target=lookup, daemon=True)
	thread.start()
	thread.join(timeout)
	return result[0] if result else 'unsure'

def host_validity(hostname, timeout=2.0):
	'''
	Whether mssh would accept hostname: 'valid', 'invalid' or 'unsure'.

	The rule __validate_expand_hostname applies (an IP address, a hosts file name, an env / env
	file alias, a name DNS resolves, a name the ssh config maps to another HostName or puts
	behind a ProxyJump / ProxyCommand), except that DNS answers in three ways: only "no such name"
	(EAI_NONAME, EAI_NODATA) can make a name invalid. A lookup failing otherwise or taking longer
	than timeout seconds, or an ssh -G that fails, makes it 'unsure'. Nothing connects to the
	host: ssh -G only reads the ssh config.

	Args:
		hostname (str): One host name, user@ allowed
		timeout (float): Seconds the DNS lookup may take
	'''
	if '@' in hostname:
		hostname = hostname.rsplit('@', 1)[1]
	hostname = hostname.strip().strip('$')
	if not hostname:
		return 'invalid'
	if _local_hostname_source(hostname):
		return 'valid'
	answer = _dns_answer(hostname, timeout)
	if answer == 'yes':
		return 'valid'
	if 'ssh' in _binPaths and not hostname.startswith('-'):
		if _ssh_config_values(hostname) is None:
			return 'unsure'
		if _ssh_config_target(hostname):
			return 'valid'
	return 'invalid' if answer == 'no' else 'unsure'

@cache_decorator
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_host_validity.py -q`

Expected: PASS (`9 passed in 0.22s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `853 passed, 32 skipped in 71.02s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add multiSSH3.py tests/test_host_validity.py
git commit -F - <<'EOF'
feat: host_validity, mssh's host rule with three DNS answers

Only "no such name" makes a host invalid; a timeout, another resolver
error or a failing ssh -G leaves it unsure.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 3: OPTION_NO_EFFECT: option combinations main() ignores

**Files:**
- Create: `tests/test_option_no_effect.py`
- Modify: `multiSSH3.py`

**Interfaces:**
- Consumes: multiSSH3: `get_parser`, `process_args`, `Host`, `_build_command`
- Produces: multiSSH3: `OPTION_NO_EFFECT`, a tuple of `(long option, 'with' | 'without', other long options, why)`: `--no_skip_unreachable` with `--script`; the six `--ipmi_*` settings without `--ipmi` / `--store_config_file` / `--generate_config_file`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_option_no_effect.py` with exactly this content:

````python
'''OPTION_NO_EFFECT: every entry is an option combination main() really ignores.'''
import pytest

import multiSSH3

ENTRIES = {entry[0]: entry for entry in multiSSH3.OPTION_NO_EFFECT}
IPMI_SETTINGS = ['-mpre=10.0.', '-iu=admin', '-ip=secret', '-ia=-I lanplus', '-im=redfish', '-irlt=30']


def test_entries_name_real_options():
	parser = multiSSH3.get_parser()
	strings = {string for action in parser._actions for string in action.option_strings}
	for option, kind, others, message in multiSSH3.OPTION_NO_EFFECT:
		assert option in strings and set(others) <= strings and kind in ('with', 'without') and message


@pytest.fixture
def ipmi_definitions(monkeypatch):
	'''process_args rewrites DEFAULT_IPMI_DEFINITIONS: start each call from the same list.'''
	saved = [dict(definition) for definition in multiSSH3.DEFAULT_IPMI_DEFINITIONS]

	def processed(argv):
		monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_DEFINITIONS', [dict(definition) for definition in saved])
		return multiSSH3.process_args(argv)
	return processed


def built(processed, argv):
	'''What mssh would run for the first host of argv.'''
	args = processed(argv)
	host = multiSSH3.Host(args.hosts, ' '.join(args.commands), ipmi=args.ipmi)
	attempt = multiSSH3._build_command(host, None, list(multiSSH3.DEFAULT_IPMI_DEFINITIONS))
	return attempt.action, attempt.argv


def test_no_skip_unreachable_does_nothing_with_script(ipmi_definitions):
	assert ENTRIES['--no_skip_unreachable'][1:3] == ('with', ('--script',))
	assert vars(ipmi_definitions(['node1', 'true', '--script', '-nsu'])) == vars(ipmi_definitions(['node1', 'true', '--script']))
	# without --script it does something
	assert ipmi_definitions(['node1', 'true', '-nsu']).skip_unreachable is False


@pytest.mark.parametrize('setting', IPMI_SETTINGS)
def test_ipmi_settings_do_nothing_without_ipmi(ipmi_definitions, setting):
	option = next(action.option_strings[-1] for action in multiSSH3.get_parser()._actions if setting.split('=')[0] in action.option_strings)
	assert ENTRIES[option][1:3] == ('without', ('--ipmi', '--store_config_file', '--generate_config_file'))
	assert built(ipmi_definitions, ['node1', 'true', setting]) == built(ipmi_definitions, ['node1', 'true'])


def test_ipmi_changes_what_runs(ipmi_definitions):
	# the comparison above can see a difference
	assert built(ipmi_definitions, ['node1', 'true', '-M']) != built(ipmi_definitions, ['node1', 'true'])
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_option_no_effect.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'multiSSH3' has no attribute 'OPTION_NO_EFFECT'` (`1 error in 0.03s`)

- [ ] **Step 3: Implement**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python


def get_parser():
	parser = argparse.ArgumentParser(
````

with:

````python


# Option combinations main() ignores, for the warnings mssh-complete shows while a line is typed
# (it reads them through its index). Each entry is (option, kind, others, why):
#   'with': the option does nothing when one of others is on the line
#   'without': the option does nothing unless one of others is on the line or on by default
# tests/test_option_no_effect.py proves every entry.
_IPMI_OR_STORED = ('--ipmi', '--store_config_file', '--generate_config_file')
OPTION_NO_EFFECT = (
	('--no_skip_unreachable', 'with', ('--script',), '--script skips unreachable hosts anyway'),
	('--ipmi_interface_ip_prefix', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_username', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_password', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_args', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_method', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
	('--ipmi_retry_lockout_time', 'without', _IPMI_OR_STORED, 'only used with --ipmi'),
)

def get_parser():
	parser = argparse.ArgumentParser(
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_option_no_effect.py -q`

Expected: PASS (`9 passed in 0.04s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `862 passed, 32 skipped in 71.48s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add multiSSH3.py tests/test_option_no_effect.py
git commit -F - <<'EOF'
feat: OPTION_NO_EFFECT, option combinations main() ignores

-nsu with --script, and the --ipmi_* settings without --ipmi; each entry
is proved by a test that compares what mssh would run.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 4: Host-state cache and probe queue

**Files:**
- Create: `tests/test_complete_hoststate.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: mssh_complete: `_has_control`
- Produces: mssh_complete: `HOST_STATE_NAME = 'host-state.tsv'`, `PROBE_QUEUE_NAME = 'probe-queue'`, `PROBE_LOCK_NAME = 'probe.lock'`, `VALIDITY_FRESH = 600.0`, `UNSURE_FRESH = 60.0`, `PING_FRESH = 60.0`; `boot_id() -> str | None`; `HostState(validity='', checked_at=0.0, ping='', pinged_at=0.0, answered_at=0.0)` with `fresh_validity(now)` and `fresh_ping(now)` (`''` when stale); `needs_probe(state, now) -> bool`; `read_host_states(directory) -> {host: HostState}`; `write_host_states(directory, states)` (atomic, boot id first, mode 0600); `queue_probes(directory, hosts)` (one write, hosts already waiting left out); `take_probe_queue(directory) -> [host, ...]` (newest first, each once, queue emptied).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_hoststate.py` with exactly this content:

````python
'''What the prober learned about hosts (host-state.tsv) and the hosts queries asked about (probe-queue).'''
import os
import stat

import pytest

import mssh_complete as mc

NOW = 1790000000.0


@pytest.fixture
def directory(tmp_path, monkeypatch):
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	return str(tmp_path)


def test_states_survive_a_write_and_a_read(directory):
	states = {
		'node1': mc.HostState('valid', NOW, 'answer', NOW, NOW),
		'gpu017': mc.HostState('invalid', NOW - 5),
		'node9': mc.HostState('unsure', NOW, 'silent', NOW - 1, NOW - 300),
	}
	mc.write_host_states(directory, states)
	again = mc.read_host_states(directory)
	assert {host: (state.validity, state.checked_at, state.ping, state.pinged_at, state.answered_at) for host, state in again.items()} == {
		'node1': ('valid', NOW, 'answer', NOW, NOW),
		'gpu017': ('invalid', NOW - 5, '', 0.0, 0.0),
		'node9': ('unsure', NOW, 'silent', NOW - 1, NOW - 300),
	}
	path = os.path.join(directory, mc.HOST_STATE_NAME)
	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
	assert os.listdir(directory) == [mc.HOST_STATE_NAME]


def test_states_from_another_boot_are_ignored(directory, monkeypatch):
	mc.write_host_states(directory, {'node1': mc.HostState('valid', NOW)})
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-b')
	assert mc.read_host_states(directory) == {}


@pytest.mark.parametrize('content', [
	'',
	'node1\tvalid\t1790000000\t\t0\t0\n',                      # no boot id line: not ours
	'#boot_id,boot-a\nnode1\tmaybe\t1\t\t0\t0\nnode2\tvalid\tx\t\t0\t0\nnode3\tvalid\t1\n',
])
def test_foreign_or_broken_lines_are_skipped(directory, content):
	with open(os.path.join(directory, mc.HOST_STATE_NAME), 'w') as f:
		f.write(content)
	assert mc.read_host_states(directory) == {}


@pytest.mark.parametrize('state, age, validity, ping', [
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 30, 'valid', 'answer'),
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 90, 'valid', ''),
	(mc.HostState('invalid', NOW), 599, 'invalid', ''),
	(mc.HostState('invalid', NOW), 601, '', ''),
	(mc.HostState('unsure', NOW, 'none', NOW), 59, 'unsure', 'none'),
	(mc.HostState('unsure', NOW, 'none', NOW), 61, '', ''),
])
def test_answers_stay_fresh_for_their_time(state, age, validity, ping):
	assert (state.fresh_validity(NOW + age), state.fresh_ping(NOW + age)) == (validity, ping)


@pytest.mark.parametrize('state, age, needed', [
	(None, 0, True),
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 30, False),
	# the ping is old: ping again
	(mc.HostState('valid', NOW, 'answer', NOW, NOW), 90, True),
	# a host that does not exist is not pinged
	(mc.HostState('invalid', NOW), 90, False),
	# could not ping (no ping command): that is an answer too, until it is old
	(mc.HostState('unsure', NOW, 'none', NOW), 30, False),
])
def test_which_hosts_the_prober_must_look_at(state, age, needed):
	assert mc.needs_probe(state, NOW + age) is needed


def test_the_queue_hands_out_hosts_newest_first_once(directory):
	mc.queue_probes(directory, ['node1', 'node2'])
	mc.queue_probes(directory, ['node3', 'bad\thost', 'esc\x1bhost', ''])
	assert mc.take_probe_queue(directory) == ['node3', 'node2', 'node1']
	assert mc.take_probe_queue(directory) == []


def test_a_host_already_queued_is_not_queued_again(directory):
	# a query for a long range repeats on every keystroke
	mc.queue_probes(directory, ['node1', 'node2'])
	mc.queue_probes(directory, ['node2', 'node3', 'node3'])
	with open(os.path.join(directory, mc.PROBE_QUEUE_NAME)) as f:
		assert f.read().split() == ['node1', 'node2', 'node3']
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_hoststate.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'HostState'. Did you mean: 'HostTable'?` (`1 error in 0.03s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		spawn_rebuild(directory)
	return index, tail

#%% ------------ Engine ----------------
````

with:

````python
		spawn_rebuild(directory)
	return index, tail

#%% ------------ Host state ----------------
HOST_STATE_NAME = 'host-state.tsv'
PROBE_QUEUE_NAME = 'probe-queue'
PROBE_LOCK_NAME = 'probe.lock'
VALIDITY_FRESH = 600.0  # seconds a valid / invalid answer stays fresh
UNSURE_FRESH = 60.0     # seconds an unsure answer stays fresh
PING_FRESH = 60.0       # seconds a ping result stays fresh (a host on the line is pinged again after)

def boot_id():
	'''An identifier of the current boot, or None where the system has none.'''
	try:
		with open('/proc/sys/kernel/random/boot_id') as f:
			return f.read().strip() or None
	except OSError:
		return None

class HostState(object):
	'''
	What the prober learned about one host. Times are wall-clock seconds.

	validity: 'valid', 'invalid' or 'unsure' (multiSSH3.host_validity), '' when never checked;
	ping: 'answer', 'silent', 'none' (could not ping) or '' when never pinged;
	answered_at: when the host last answered ping (0 when never).
	'''
	__slots__ = ('validity', 'checked_at', 'ping', 'pinged_at', 'answered_at')

	def __init__(self, validity='', checked_at=0.0, ping='', pinged_at=0.0, answered_at=0.0):
		self.validity = validity
		self.checked_at = checked_at
		self.ping = ping
		self.pinged_at = pinged_at
		self.answered_at = answered_at

	def fresh_validity(self, now):
		'''The validity while it is fresh, else ''.'''
		limit = UNSURE_FRESH if self.validity == 'unsure' else VALIDITY_FRESH
		return self.validity if self.validity and now - self.checked_at <= limit else ''

	def fresh_ping(self, now):
		'''The ping result while it is fresh, else ''.'''
		return self.ping if self.ping and now - self.pinged_at <= PING_FRESH else ''

def needs_probe(state, now):
	'''Whether the prober must look at a host: its validity is not fresh, or it may be pinged and its ping is not.'''
	if state is None:
		return True
	validity = state.fresh_validity(now)
	return not validity or (validity != 'invalid' and not state.fresh_ping(now))

_VALIDITIES = ('valid', 'invalid', 'unsure')
_PINGS = ('', 'answer', 'silent', 'none')

def read_host_states(directory):
	'''host -> HostState from host-state.tsv; {} for a missing, foreign or other-boot file.'''
	try:
		with open(os.path.join(directory, HOST_STATE_NAME), encoding='utf-8', errors='replace') as f:
			lines = f.read().split('\n')
	except OSError:
		return {}
	head = lines[0].split(',', 1)
	if len(head) != 2 or head[0] != '#boot_id':
		return {}
	current = boot_id()
	if current and head[1] != current:
		return {}
	states = {}
	for line in lines[1:]:
		fields = line.split('\t')
		if len(fields) != 6 or not fields[0] or fields[1] not in _VALIDITIES or fields[3] not in _PINGS:
			continue
		try:
			states[fields[0]] = HostState(fields[1], float(fields[2]), fields[3], float(fields[4]), float(fields[5]))
		except ValueError:
			continue
	return states

def write_host_states(directory, states):
	'''Replace host-state.tsv with states (host -> HostState), atomically.'''
	import tempfile
	lines = ['#boot_id,{}'.format(boot_id() or '')]
	for host in sorted(states):
		state = states[host]
		lines.append('\t'.join([host, state.validity, repr(float(state.checked_at)), state.ping,
			repr(float(state.pinged_at)), repr(float(state.answered_at))]))
	fd, temporary = tempfile.mkstemp(prefix='.host-state.', dir=directory)
	try:
		with os.fdopen(fd, 'w', encoding='utf-8') as f:
			f.write('\n'.join(lines) + '\n')
		os.replace(temporary, os.path.join(directory, HOST_STATE_NAME))
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

def _queueable(host):
	return bool(host) and '\t' not in host and not _has_control(host)

def queue_probes(directory, hosts):
	'''
	Append hosts to the probe queue in one write (queries do this; the prober takes them).

	Hosts already waiting in the queue are left out: a query for a long range repeats on every
	keystroke.
	'''
	path = os.path.join(directory, PROBE_QUEUE_NAME)
	try:
		with open(path, encoding='utf-8', errors='surrogateescape') as f:
			waiting = set(f.read().split('\n'))
	except OSError:
		waiting = set()
	new = []
	for host in hosts:
		if _queueable(host) and host not in waiting:
			waiting.add(host)
			new.append(host)
	if not new:
		return
	data = ''.join(host + '\n' for host in new)
	fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
	try:
		os.write(fd, data.encode('utf-8', 'surrogateescape'))
	finally:
		os.close(fd)

def take_probe_queue(directory):
	'''
	Empty the probe queue and return its hosts, newest first, each once.

	The queue is renamed before it is read: a query appending meanwhile starts a new queue. A host
	lost to that race is queued again by the next query that finds it without a fresh answer.
	'''
	path = os.path.join(directory, PROBE_QUEUE_NAME)
	taken = path + '.taken'
	try:
		os.replace(path, taken)
	except OSError:
		return []
	try:
		with open(taken, encoding='utf-8', errors='surrogateescape') as f:
			lines = f.read().split('\n')
	except OSError:
		lines = []
	try:
		os.unlink(taken)
	except OSError:
		pass
	hosts = []
	for host in reversed(lines):
		if _queueable(host) and host not in hosts:
			hosts.append(host)
	return hosts

#%% ------------ Engine ----------------
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_hoststate.py -q`

Expected: PASS (`18 passed in 0.03s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `880 passed, 32 skipped in 71.15s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_hoststate.py
git commit -F - <<'EOF'
feat: host-state cache and probe queue

host-state.tsv (boot id stamped, written atomically) keeps what the
prober learned with its age; queries append hosts to probe-queue.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 5: mssh-complete probe, the background host checker

**Files:**
- Create: `tests/test_complete_probe.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 2: `multiSSH3.host_validity`; Task 4: everything; mssh_complete: `take_lock`, `_import_mssh`, `_debug`
- Produces: mssh_complete: `PROBE_RUN_LIMIT = 120.0`, `PING_COMMAND`, `DNS_TIMEOUT = 2.0`; `probe_parallelism(mssh) -> int` (mssh's `_normalize_max_connections(DEFAULT_MAX_CONNECTIONS)`, halved under load, at least 4); `ping_host(host) -> 'answer' | 'silent' | 'none'`; `run_probe(directory, lock=None, now=time.time, limit=PROBE_RUN_LIMIT) -> {'checked': int, 'parallel': int}`; `spawn_probe(directory) -> bool`; `_spawn_detached(directory, lock_name, command)` (`spawn_rebuild` now uses it); command `mssh-complete probe --lock LOCK`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_probe.py` with exactly this content:

````python
'''The prober: checks queued hosts in the background, as parallel as the machine allows, never connecting to them.'''
import errno
import os
import socket
import subprocess
import types

import pytest

import multiSSH3
import mssh_complete as mc

NOW = 1790000000.0
REAL_HOST_VALIDITY = multiSSH3.host_validity
# a stand-in for ping: the last argument is the host; hosts in $FAKE_PING_UP answer
FAKE_PING = '''#!/bin/sh
for host; do :; done
echo "$host" >> "$FAKE_PING_LOG"
case " $FAKE_PING_UP " in *" $host "*) exit 0 ;; esac
exit "${FAKE_PING_SILENT:-1}"
'''


@pytest.fixture
def env(tmp_path, monkeypatch):
	bin_dir = tmp_path / 'bin'
	bin_dir.mkdir()
	(bin_dir / 'ping').write_text(FAKE_PING)
	(bin_dir / 'ping').chmod(0o755)
	monkeypatch.setenv('PATH', str(bin_dir) + os.pathsep + os.environ.get('PATH', ''))
	monkeypatch.setenv('FAKE_PING_LOG', str(tmp_path / 'ping.log'))
	monkeypatch.setenv('FAKE_PING_UP', 'node1 node2')
	verdicts = {'node1': 'valid', 'node2': 'valid', 'node3': 'valid', 'gpu017': 'invalid'}
	monkeypatch.setattr(multiSSH3, 'host_validity', lambda host, timeout=2.0: verdicts.get(host, 'valid'))
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	# the prober lowers its own priority: not the test runner's
	monkeypatch.setattr(mc.os, 'nice', lambda increment: 0)
	directory = tmp_path / 'run'
	directory.mkdir(mode=0o700)
	log = tmp_path / 'ping.log'
	return types.SimpleNamespace(directory=str(directory), pinged=lambda: log.read_text().split() if log.exists() else [])


def states(env):
	return {host: (state.validity, state.ping, state.pinged_at, state.answered_at) for host, state in mc.read_host_states(env.directory).items()}


def test_queued_hosts_are_checked_and_pinged(env):
	mc.queue_probes(env.directory, ['node1', 'node3', 'gpu017'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert states(env) == {
		'node1': ('valid', 'answer', NOW, NOW),
		'node3': ('valid', 'silent', NOW, 0.0),
		'gpu017': ('invalid', '', 0.0, 0.0),
	}
	# a host that does not exist is not pinged
	assert sorted(env.pinged()) == ['node1', 'node3']
	assert mc.take_probe_queue(env.directory) == []


def test_fresh_answers_are_not_asked_for_again(env):
	mc.write_host_states(env.directory, {'node1': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	mc.queue_probes(env.directory, ['node1'])
	mc.run_probe(env.directory, now=lambda: NOW + 30)
	assert env.pinged() == []


def test_a_host_going_silent_keeps_when_it_last_answered(env):
	mc.write_host_states(env.directory, {'node3': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	mc.queue_probes(env.directory, ['node3'])
	mc.run_probe(env.directory, now=lambda: NOW + 90)
	assert states(env)['node3'] == ('valid', 'silent', NOW + 90, NOW)


@pytest.mark.parametrize('ping', ['missing', 'failing'])
def test_without_a_working_ping_hosts_get_none(env, monkeypatch, ping):
	if ping == 'missing':
		monkeypatch.setenv('PATH', '/nonexistent')
	else:
		# iputils ping exits 2 on errors (no permission, a name it cannot resolve)
		monkeypatch.setenv('FAKE_PING_SILENT', '2')
	mc.queue_probes(env.directory, ['node3', 'node4'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert {host: state[1] for host, state in states(env).items()} == {'node3': 'none', 'node4': 'none'}


def test_parallelism_follows_mssh_and_backs_off_under_load(monkeypatch):
	monkeypatch.setattr(multiSSH3, '_normalize_max_connections', lambda value: value)
	monkeypatch.setattr(mc.os, 'cpu_count', lambda: 8)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 40)
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (2.0, 2.0, 2.0))
	assert mc.probe_parallelism(multiSSH3) == 40
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (8.0, 8.0, 8.0))
	assert mc.probe_parallelism(multiSSH3) == 20
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 6)
	assert mc.probe_parallelism(multiSSH3) == 4


def test_the_open_file_limit_caps_parallelism(monkeypatch):
	# mssh's own rule clamps to what the descriptor limit supports
	monkeypatch.setattr(multiSSH3, '__max_connections_nofile_limit_supported', 10)
	monkeypatch.setattr(multiSSH3, 'DEFAULT_MAX_CONNECTIONS', 400)
	monkeypatch.setattr(mc.os, 'getloadavg', lambda: (0.0, 0.0, 0.0))
	assert mc.probe_parallelism(multiSSH3) == 10


def test_running_out_of_descriptors_halves_and_retries(env, monkeypatch):
	real_run = subprocess.run
	calls = []

	def flaky_run(argv, **kwargs):
		calls.append(argv)
		if len(calls) == 1:
			raise OSError(errno.EMFILE, 'Too many open files')
		return real_run(argv, **kwargs)
	monkeypatch.setattr(subprocess, 'run', flaky_run)
	monkeypatch.setattr(mc, 'probe_parallelism', lambda mssh: 8)
	mc.queue_probes(env.directory, ['node1', 'node2', 'node3'])
	summary = mc.run_probe(env.directory, now=lambda: NOW)
	assert summary['parallel'] == 4
	assert {host: state[1] for host, state in states(env).items()} == {'node1': 'answer', 'node2': 'answer', 'node3': 'silent'}


def test_a_run_stops_at_its_limit_and_leaves_the_rest_queued(env, monkeypatch):
	monkeypatch.setattr(mc, 'probe_parallelism', lambda mssh: 4)
	hosts = ['node{}'.format(number) for number in range(10, 20)]
	mc.queue_probes(env.directory, hosts)
	clock = [NOW]
	write = mc.write_host_states

	def write_and_tick(directory, host_states):
		write(directory, host_states)
		clock[0] = NOW + 500  # the first batch took the whole run
	monkeypatch.setattr(mc, 'write_host_states', write_and_tick)
	mc.run_probe(env.directory, now=lambda: clock[0], limit=100)
	# the newest four were checked, the rest wait for the next run, newest first
	assert sorted(states(env)) == ['node16', 'node17', 'node18', 'node19']
	assert mc.take_probe_queue(env.directory) == ['node15', 'node14', 'node13', 'node12', 'node11', 'node10']


def test_the_prober_never_connects_to_a_host(env, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'host_validity', REAL_HOST_VALIDITY)

	def no_connection(*args, **kwargs):
		raise AssertionError('the prober opened a connection')
	monkeypatch.setattr(socket.socket, 'connect', no_connection)
	monkeypatch.setattr(socket.socket, 'connect_ex', no_connection)
	monkeypatch.setattr(socket, 'create_connection', no_connection)
	monkeypatch.setattr(multiSSH3.socket, 'getaddrinfo', lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, 'fake')))
	real_run = subprocess.run
	commands = []

	def recording_run(argv, **kwargs):
		commands.append(list(argv))
		if os.path.basename(argv[0]) == 'ssh':
			return subprocess.CompletedProcess(argv, 0, stdout='hostname {}\n'.format(argv[-1]))
		return real_run(argv, **kwargs)
	monkeypatch.setattr(subprocess, 'run', recording_run)
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', '/usr/bin/ssh')
	mc.queue_probes(env.directory, ['node1', 'typo1'])
	mc.run_probe(env.directory, now=lambda: NOW)
	assert commands and all(os.path.basename(argv[0]) == 'ping' or (os.path.basename(argv[0]) == 'ssh' and '-G' in argv) for argv in commands)


def test_one_prober_at_a_time(tmp_path, monkeypatch):
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda argv, **kwargs: started.append(argv))
	assert mc.spawn_probe(str(tmp_path)) is True
	assert mc.spawn_probe(str(tmp_path)) is False
	assert len(started) == 1 and started[0][-3:] == ['probe', '--lock', os.path.join(str(tmp_path), mc.PROBE_LOCK_NAME)]
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_probe.py tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'run_probe'` (`11 failed, 20 passed in 0.33s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return False

def spawn_rebuild(directory):
	'''Start a detached `rebuild` unless one is running. Returns whether one was started.'''
	lock = os.path.join(directory, LOCK_NAME)
	if not take_lock(lock):
		return False
	import subprocess
	try:
		subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), 'rebuild', '--lock', lock],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
			close_fds=True, start_new_session=True, cwd='/')
	except OSError as e:
		_debug('cannot start rebuild: {!r}'.format(e))
		try:
			os.unlink(lock)
````

with:

````python
	return False

def _spawn_detached(directory, lock_name, command):
	'''Start `mssh-complete <command> --lock <lock>` detached unless one is running. Returns whether one was started.'''
	lock = os.path.join(directory, lock_name)
	if not take_lock(lock):
		return False
	import subprocess
	try:
		subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), command, '--lock', lock],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
			close_fds=True, start_new_session=True, cwd='/')
	except OSError as e:
		_debug('cannot start {}: {!r}'.format(command, e))
		try:
			os.unlink(lock)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return False
	return True

def _load_index(path):
````

with:

````python
		return False
	return True

def spawn_rebuild(directory):
	'''Start a detached `rebuild` unless one is running. Returns whether one was started.'''
	return _spawn_detached(directory, LOCK_NAME, 'rebuild')

def _load_index(path):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			hosts.append(host)
	return hosts

#%% ------------ Engine ----------------
````

with:

````python
			hosts.append(host)
	return hosts

#%% ------------ Prober ----------------
PROBE_RUN_LIMIT = 120.0  # seconds one prober run may last; the next query starts another for what is left
PING_COMMAND = ('ping', '-c2', '-i0.2', '-W1', '-q')
DNS_TIMEOUT = 2.0

def _out_of_resources(error):
	'''Whether error says the system is out of descriptors or processes (a smaller batch may work).'''
	import errno
	return isinstance(error, OSError) and error.errno in (errno.EMFILE, errno.ENFILE, errno.EAGAIN)

def probe_parallelism(mssh):
	'''
	How many hosts the prober checks at once: mssh's own rule for parallel ssh sessions (the mssh
	config's DEFAULT_MAX_CONNECTIONS, default 4 x CPUs, clamped by the open-file limit), halved
	while the 1-minute load average is at or above the CPU count; never below 4.
	'''
	try:
		parallel = int(mssh._normalize_max_connections(mssh.DEFAULT_MAX_CONNECTIONS))
	except Exception:
		parallel = 4 * (os.cpu_count() or 1)
	try:
		if os.getloadavg()[0] >= (os.cpu_count() or 1):
			parallel //= 2
	except (AttributeError, OSError):
		pass
	return max(parallel, 4)

def ping_host(host):
	'''
	'answer' or 'silent' after two pings; 'none' when ping fails otherwise (no permission, a name it
	cannot resolve). Raises FileNotFoundError without a ping command, OSError when out of
	descriptors or processes.
	'''
	import subprocess
	argv = list(PING_COMMAND) + (['-6'] if ':' in host else []) + [host]
	try:
		code = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode
	except subprocess.TimeoutExpired:
		return 'silent'
	except FileNotFoundError:
		raise
	except OSError as e:
		if _out_of_resources(e):
			raise
		return 'none'
	return {0: 'answer', 1: 'silent'}.get(code, 'none')

def _probe_batch(mssh, hosts, states, now, ping_available):
	'''
	Check and ping hosts at once, one thread each, updating states (host -> HostState).

	Returns:
		list: the hosts that could not be checked for lack of descriptors or processes, in order
	'''
	import threading
	retry = []
	guard = threading.Lock()

	def check(host):
		state = states.get(host) or HostState()
		try:
			if not state.fresh_validity(now()):
				state.validity, state.checked_at = mssh.host_validity(host, timeout=DNS_TIMEOUT), now()
			if state.validity != 'invalid' and not state.fresh_ping(now()):
				answer = 'none'
				if ping_available[0]:
					try:
						answer = ping_host(host)
					except FileNotFoundError:
						ping_available[0] = False
				state.ping, state.pinged_at = answer, now()
				if answer == 'answer':
					state.answered_at = state.pinged_at
		except Exception as e:
			if _out_of_resources(e):
				with guard:
					retry.append(host)
			else:
				_debug('probing {} failed: {!r}'.format(host, e))
			return
		with guard:
			states[host] = state

	threads = []
	for number, host in enumerate(hosts):
		thread = threading.Thread(target=check, args=(host,), daemon=True)
		try:
			thread.start()
		except RuntimeError:
			# no more threads: the rest waits for a smaller batch
			retry.extend(hosts[number:])
			break
		threads.append(thread)
	for thread in threads:
		thread.join()
	return sorted(retry, key=hosts.index)

def run_probe(directory, lock=None, now=time.time, limit=PROBE_RUN_LIMIT):
	'''
	One prober run, at low CPU priority: check the queued hosts, newest first, recording what is
	learned in host-state.tsv after each batch, until the queue is empty or limit seconds have
	passed. Hosts left over go back into the queue. Never connects to a host: only DNS, ssh -G
	(which reads the ssh config) and ping.

	Returns:
		dict: {'checked': hosts looked at, 'parallel': hosts checked at once at the end}
	'''
	try:
		os.nice(10)
	except (AttributeError, OSError):
		pass
	mssh = _import_mssh()
	parallel = probe_parallelism(mssh)
	started = now()
	checked = 0
	ping_available = [True]
	while now() - started < limit:
		hosts = take_probe_queue(directory)
		if not hosts:
			break
		states = read_host_states(directory)
		moment = now()
		todo = [host for host in hosts if needs_probe(states.get(host), moment)]
		while todo:
			if now() - started >= limit:
				queue_probes(directory, todo[::-1])
				return {'checked': checked, 'parallel': parallel}
			batch, todo = todo[:parallel], todo[parallel:]
			retry = _probe_batch(mssh, batch, states, now, ping_available)
			checked += len(batch) - len(retry)
			write_host_states(directory, states)
			if lock:
				# a lock that keeps changing is not stale
				try:
					os.utime(lock, None)
				except OSError:
					pass
			if retry:
				if parallel == 1:
					queue_probes(directory, (retry + todo)[::-1])
					return {'checked': checked, 'parallel': parallel}
				parallel = max(parallel // 2, 1)
				todo = retry + todo
	return {'checked': checked, 'parallel': parallel}

def spawn_probe(directory):
	'''Start a detached `probe` unless one is running. Returns whether one was started.'''
	return _spawn_detached(directory, PROBE_LOCK_NAME, 'probe')

#%% ------------ Engine ----------------
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
				pass

def _cmd_eval(args):
	import argparse
````

with:

````python
				pass

def _cmd_probe(args):
	lock = args[1] if len(args) == 2 and args[0] == '--lock' else None
	try:
		directory = cache_dir()
		if directory is None:
			return 1
		run_probe(directory, lock)
		return 0
	except Exception as e:
		_debug('probe failed: {!r}'.format(e))
		return 1
	finally:
		if lock:
			try:
				os.unlink(lock)
			except OSError:
				pass

def _cmd_eval(args):
	import argparse
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
````

with:

````python
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command == 'probe':
		return _cmd_probe(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | pick | edit TEXT | rebuild | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

````

with:

````python
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | pick | edit TEXT | rebuild | probe | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_probe.py tests/test_complete_index.py -q`

Expected: PASS (`31 passed in 0.33s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `891 passed, 32 skipped in 71.10s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_probe.py
git commit -F - <<'EOF'
feat: mssh-complete probe, the background host checker

Checks queued hosts with mssh's host rule and ping, as many at once as
mssh's own max connections allow (halved under load and when out of
descriptors), at low priority, for at most two minutes per run; never
connects to a host.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 6: Warnings for unknown hosts and range surprises (diag=1)

**Files:**
- Create: `tests/test_complete_diagnose.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 4: `read_host_states`, `needs_probe`, `queue_probes`; Task 5: `spawn_probe`; mssh_complete: `lex`, `assign_roles`, `_mssh_start`, `HostTable`, `_is_digits`, `_DIGITS`, `_unicode_terminal`, `_clean`
- Produces: `Token(text, raw, quoted=False, open_quote='', start=-1)` (lex sets `start`); `HostTable.sources(name) -> int`; `Diagnostic(start, end, kind, message)`; `DIAGNOSTIC_KINDS = ('unknown', 'range', 'unreachable', 'options')`; `MAX_MESSAGE = 160`; `Engine.directory`; `Engine.host_states()`; `Engine.diagnose(request, probe=True, now=None) -> (list of Diagnostic, pending)`; `Engine.query` with flag `diag=1` (and/or `ghost=1`) returns no candidates, `diagnostics` set and directive `pending`; `format_response` writes `W <start>\t<end>\t<kind>\t<message>`; `engine_for` sets `engine.directory`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_diagnose.py` with exactly this content:

````python
'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000.0
HOSTS_FILE, HISTORY = mc.SRC_HOSTS_FILE, mc.SRC_HISTORY


def index(tmp_path, hosts, aliases=None):
	'''An index holding hosts (name -> sources) and aliases (name -> members).'''
	names = sorted(hosts)
	number = {name: str(position) for position, name in enumerate(names)}
	aliases = aliases or {}
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {}, [
		('host_names', [names]),
		('host_meta', [[str(hosts[name]), ''] for name in names]),
		('alias_names', [sorted(aliases)]),
		('aliases', [['env'] + [number[member] for member in aliases[name]] for name in sorted(aliases)]),
	])
	return mc.NsvIndex.load(path)


@pytest.fixture
def engine(tmp_path, monkeypatch):
	'''An engine with a runtime directory, a host table and host states; the prober is not started.'''
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)
	started = []
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: started.append(directory) or True)
	directory = tmp_path / 'run'
	directory.mkdir(mode=0o700)
	hosts = {'gpu17': HOSTS_FILE, 'gpu18': HOSTS_FILE, 'login1': HISTORY, 'nodex1': HISTORY, 'nodey1': HISTORY, 'db1': HISTORY, 'ghost1': mc.SRC_ALIAS}
	hosts.update({'node{:02d}'.format(number): HOSTS_FILE for number in range(1, 17)})
	engine = mc.Engine(SPEC, [], mc.HostTable(index(tmp_path, hosts, {'all': ['node01', 'ghost1']})))
	engine.directory = str(directory)
	engine.started = started
	return engine


def seed(engine, **validities):
	mc.write_host_states(engine.directory, {host: mc.HostState(validity, NOW) for host, validity in validities.items()})


def warnings(engine, line, cursor=None, probe=True):
	before, after = line[:cursor], line[cursor:] if cursor is not None else ''
	found, pending = engine.diagnose(mc.Request('bash', before, after, ''), probe=probe, now=NOW)
	return [(line[item.start:item.end], item.kind, item.message) for item in found], pending


def test_an_unknown_host_is_marked_with_the_host_it_was_meant_to_be(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 nvidia-smi') == ([('gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')], False)


def test_the_word_being_typed_is_left_alone(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017')[0] == []
	# the cursor back inside it: still being edited
	assert warnings(engine, 'mssh gpu017 nvidia-smi', cursor=8)[0] == []


def test_a_host_without_an_answer_yet_is_queued_for_the_prober(engine):
	assert warnings(engine, 'mssh login1,10.0.0.5,gpu17 uptime') == ([], True)
	# all are pinged; an IP address and a hosts-file name need no DNS (they are valid at once)
	assert mc.take_probe_queue(engine.directory) == ['gpu17', '10.0.0.5', 'login1']
	assert engine.started == [engine.directory]


def test_hosts_with_fresh_answers_are_not_queued(engine):
	mc.write_host_states(engine.directory, {
		'login1': mc.HostState('valid', NOW, 'answer', NOW, NOW), 'gpu17': mc.HostState('valid', NOW, 'answer', NOW, NOW)})
	assert warnings(engine, 'mssh login1,gpu17 uptime') == ([], False)
	assert mc.take_probe_queue(engine.directory) == []


def test_without_probe_nothing_is_queued(engine):
	assert warnings(engine, 'mssh login1 uptime', probe=False) == ([], True)
	assert mc.take_probe_queue(engine.directory) == [] and engine.started == []


@pytest.mark.parametrize('typed, meant', [
	('gpu017', 'gpu17'),       # zero padding
	('gpu99', None),           # nothing close
	('login2', 'login1'),      # one substitution
	('lgoin1', 'login1'),      # two letters swapped
	('gp17', 'gpu17'),         # one letter left out
	('nodez1', None),          # nodex1 and nodey1 are equally close
	('db2', None),             # too short to guess from one edit
])
def test_did_you_mean_needs_one_clear_candidate(engine, typed, meant):
	seed(engine, **{typed: 'invalid'})
	message = warnings(engine, 'mssh {} uptime'.format(typed))[0][0][2]
	assert message == typed + ': unknown host' + (' — did you mean {}?'.format(meant) if meant else '')


def test_a_host_known_not_to_exist_is_never_suggested(engine):
	seed(engine, gpu017='invalid', gpu17='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host'


def test_each_host_of_a_list_is_marked_on_its_own(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh root@node01,root@gpu017 uptime')[0] == [('root@gpu017', 'unknown', 'gpu017: unknown host — did you mean gpu17?')]
	# inside quotes the whole word is marked
	assert warnings(engine, 'mssh "node01,gpu017" uptime')[0][0][0] == '"node01,gpu017"'


def test_a_range_with_unknown_members_suggests_the_padded_range(engine):
	seed(engine, **{'node{}'.format(number): 'invalid' for number in range(1, 10)})
	assert warnings(engine, 'mssh node[1-16] uptime')[0] == [(
		'node[1-16]', 'range', 'node[1-16]: 9 of 16 hosts unknown (node1, node2, node3, …) — did you mean node[01-16]?')]


def test_a_range_still_being_checked_says_how_far_it_got(engine):
	seed(engine, gpu5='invalid', gpu6='valid')
	assert warnings(engine, 'mssh gpu[1-8] uptime') == ([('gpu[1-8]', 'range', 'gpu[1-8]: 2 of 8 checked, 1 unknown so far')], True)


def test_an_alias_with_unknown_members(engine):
	seed(engine, ghost1='invalid')
	assert warnings(engine, 'mssh all uptime')[0] == [('all', 'range', 'all: 1 of 2 hosts unknown (ghost1)')]


def test_an_ascii_terminal_gets_ascii_messages(engine, monkeypatch):
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: False)
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'mssh gpu017 uptime')[0][0][2] == 'gpu017: unknown host - did you mean gpu17?'


def test_a_range_mssh_completion_cannot_expand_says_nothing(engine):
	# letter ranges: nothing is known about their members
	assert warnings(engine, 'mssh node[a-c] uptime') == ([], False)


def test_a_huge_range_is_checked_up_to_the_member_limit(engine, monkeypatch):
	monkeypatch.setattr(mc, 'RANGE_MEMBERS_LIMIT', 4)
	seed(engine, host1='invalid')
	assert warnings(engine, 'mssh host[1-100000] uptime', probe=False) == ([(
		'host[1-100000]', 'range', 'host[1-100000]: 1 of 100000 checked, 1 unknown so far')], True)


def test_lines_that_do_not_run_mssh_get_nothing(engine):
	seed(engine, gpu017='invalid')
	assert warnings(engine, 'ssh gpu017 uptime') == ([], False)


def test_diag_requests_answer_with_w_records(engine, monkeypatch):
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	seed(engine, gpu017='invalid')
	response = engine.query(mc.Request('bash', 'mssh gpu017,login1 uptime', '', '', flags={'diag': '1'}))
	text = mc.format_response(response, nul=False).decode()
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_engine.py tests/test_complete_lex.py -q`

Expected: FAIL, e.g. `E AttributeError: 'Engine' object has no attribute 'diagnose'` (`22 failed, 54 passed in 0.21s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
#%% ------------ Shell lexing ----------------
class Token(object):
	'''One shell word. text is the dequoted value, raw the text as typed.'''
	__slots__ = ('text', 'raw', 'quoted', 'open_quote')

	def __init__(self, text, raw, quoted=False, open_quote=''):
		self.text = text
		self.raw = raw
		self.quoted = quoted
		self.open_quote = open_quote

	def __repr__(self):
````

with:

````python
#%% ------------ Shell lexing ----------------
class Token(object):
	'''One shell word. text is the dequoted value, raw the text as typed, start where raw starts in the line (-1: unknown).'''
	__slots__ = ('text', 'raw', 'quoted', 'open_quote', 'start')

	def __init__(self, text, raw, quoted=False, open_quote='', start=-1):
		self.text = text
		self.raw = raw
		self.quoted = quoted
		self.open_quote = open_quote
		self.start = start

	def __repr__(self):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
				parts.append(char)
				index += 1
		tokens.append(Token(''.join(parts), line[start:min(index, length)], quoted, open_quote))

# marks the cursor while lexing; a private use character that does not appear in command lines
````

with:

````python
				parts.append(char)
				index += 1
		tokens.append(Token(''.join(parts), line[start:min(index, length)], quoted, open_quote, start))

# marks the cursor while lexing; a private use character that does not appear in command lines
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		lo, hi = _prefix_range(self.alias_names, prefix)
		return [(index, self.alias_names[index]) for index in range(lo, hi)]

	def alias_index(self, name):
````

with:

````python
		lo, hi = _prefix_range(self.alias_names, prefix)
		return [(index, self.alias_names[index]) for index in range(lo, hi)]

	def sources(self, name):
		'''The SRC_* bits of a host name in the table, 0 for a name it does not hold.'''
		number = bisect_left(self.names, name)
		if number >= len(self.names) or self.names[number] != name or number >= self.index.count('host_meta'):
			return 0
		try:
			return int(self.index.row('host_meta', number)[0])
		except (IndexError, ValueError):
			return 0

	def alias_index(self, name):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return _spawn_detached(directory, PROBE_LOCK_NAME, 'probe')

#%% ------------ Engine ----------------
PRIOR = 0.001              # score of a candidate that nothing in history supports
````

with:

````python
	return _spawn_detached(directory, PROBE_LOCK_NAME, 'probe')

#%% ------------ Diagnostics ----------------
DIAGNOSTIC_KINDS = ('unknown', 'range', 'unreachable', 'options')  # the order warnings are shown in
MAX_MESSAGE = 160

class Diagnostic(object):
	'''A warning about part of an mssh line: line[start:end] is marked, message says why.'''
	__slots__ = ('start', 'end', 'kind', 'message')

	def __init__(self, start, end, kind, message):
		self.start = start
		self.end = end
		self.kind = kind
		self.message = message

	def __repr__(self):
		return 'Diagnostic({}, {}, {!r}, {!r})'.format(self.start, self.end, self.kind, self.message)

def _punctuation():
	'''The dash and the ellipsis messages use: typographic on a UTF-8 terminal, ASCII elsewhere.'''
	return (' — ', '…') if _unicode_terminal() else (' - ', '...')

# what separates hosts in a hosts argument, as split_hosts (mssh's own separators) and spaces
_HOST_SEPARATORS = frozenset(',\n\r\t;|/& ')

def _host_parts(token):
	'''
	(host name without user@, (start, end) in the line) for each host of a hosts word. A quoted or
	escaped word is marked whole: its parts have no exact place in the line.
	'''
	text = token.text
	exact = token.raw == text and token.start >= 0
	parts = []
	position = 0
	while position < len(text):
		if text[position] in _HOST_SEPARATORS:
			position += 1
			continue
		end = position
		while end < len(text) and text[end] not in _HOST_SEPARATORS:
			end += 1
		name = text[position:end].rsplit('@', 1)[-1].strip('$')
		span = (token.start + position, token.start + end) if exact else (token.start, token.start + len(token.raw))
		parts.append((name, span))
		position = end
	return parts

def _is_ip_address(name):
	'''A dotted IPv4 address, or anything with a colon (IPv6: host names hold none).'''
	parts = name.split('.')
	if len(parts) == 4 and all(_is_digits(part) and int(part) <= 255 for part in parts):
		return True
	return ':' in name

def _range_count(text):
	'''How many names expand_ranges makes of text, without a limit; None when it cannot expand it.'''
	start = text.find('[')
	end = text.find(']', start + 1)
	if start < 0 or end < 0:
		return 1
	count = 0
	for part in text[start + 1:end].split(','):
		low, sep, high = part.strip().partition('-')
		if sep and _is_digits(low) and _is_digits(high):
			count += max(int(high) - int(low) + 1, 0)
		elif not sep and part.strip():
			count += 1
		else:
			return None
	rest = _range_count(text[end + 1:])
	return None if rest is None else count * rest

def _iter_range(text):
	'''The names expand_ranges makes of text, one at a time (text must be one _range_count can count).'''
	start = text.find('[')
	end = text.find(']', start + 1)
	if start < 0 or end < 0:
		yield text
		return
	head, tail = text[:start], text[end + 1:]
	for part in text[start + 1:end].split(','):
		low, sep, high = part.strip().partition('-')
		if sep:
			width = min(len(low), len(high))
			values = ('{:0{}d}'.format(number, width) for number in range(int(low), int(high) + 1))
		else:
			values = [part.strip()]
		for value in values:
			for name in _iter_range(head + value + tail):
				yield name

def _padded_range(name):
	'''node[1-16] -> node[01-16]: the one range of name with its lower bound padded to the upper's width, or None.'''
	start = name.find('[')
	end = name.find(']', start + 1)
	if start < 0 or end < 0 or '[' in name[end:]:
		return None
	low, sep, high = name[start + 1:end].partition('-')
	if not sep or not _is_digits(low) or not _is_digits(high) or low.startswith('0') or len(low) >= len(high):
		return None
	return '{}[{}-{}]{}'.format(name[:start], low.zfill(len(high)), high, name[end + 1:])

def _strip_zeros(name):
	'''name with leading zeros dropped from every run of digits: gpu017 -> gpu17.'''
	out = []
	index = 0
	while index < len(name):
		end = index
		while end < len(name) and name[end] in _DIGITS:
			end += 1
		if end > index:
			out.append(name[index:end].lstrip('0') or '0')
			index = end
		else:
			out.append(name[index])
			index += 1
	return ''.join(out)

def _one_edit(typed, other):
	'''Whether other is one insertion, deletion, substitution or swap of adjacent characters away from typed.'''
	if typed == other:
		return False
	if len(typed) == len(other):
		differ = [index for index in range(len(typed)) if typed[index] != other[index]]
		if len(differ) == 1:
			return True
		return (len(differ) == 2 and differ[1] == differ[0] + 1
			and typed[differ[0]] == other[differ[1]] and typed[differ[1]] == other[differ[0]])
	if abs(len(typed) - len(other)) != 1:
		return False
	short, long_ = (typed, other) if len(typed) < len(other) else (other, typed)
	return any(long_[:index] + long_[index + 1:] == short for index in range(len(long_)))

def _unique(names):
	'''names without repeats, in order.'''
	seen = set()
	return [name for name in names if not (name in seen or seen.add(name))]

#%% ------------ Engine ----------------
PRIOR = 0.001              # score of a candidate that nothing in history supports
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	candidates are replacements for the request's word, best first. delegate is
	(word index, prefix, words) when the shell should add its own completion of a remote
	command. ghost (SP2) and diagnostics (SP3) are not filled in yet.
	'''
	__slots__ = ('context', 'candidates', 'directives', 'delegate', 'ghost', 'diagnostics')
````

with:

````python
	candidates are replacements for the request's word, best first. delegate is
	(word index, prefix, words) when the shell should add its own completion of a remote
	command. ghost is the grey suggestion (SP2), diagnostics the warnings about the line (SP3).
	'''
	__slots__ = ('context', 'candidates', 'directives', 'delegate', 'ghost', 'diagnostics')
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)

	def query(self, request, deadline=None):
		if request.flags.get('ghost') == '1':
			response = Response(parse_context(request.before, request.after, self.spec))
			response.ghost = self.suggest(request, deadline)
			return response
		context = parse_context(request.before, request.after, self.spec)
````

with:

````python
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)
		# the runtime directory: host states, the probe queue; None runs without them
		self.directory = None

	def query(self, request, deadline=None):
		ghost = request.flags.get('ghost') == '1'
		diag = request.flags.get('diag') == '1'
		if ghost or diag:
			# grey text and warnings come without candidates
			response = Response(parse_context(request.before, request.after, self.spec))
			if ghost:
				response.ghost = self.suggest(request, deadline)
			if diag:
				try:
					response.diagnostics, pending = self.diagnose(request)
					if pending:
						response.directives.add('pending')
				except Exception as e:
					_debug('diagnostics failed: {!r}'.format(e))
			return response
		context = parse_context(request.before, request.after, self.spec)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		response.candidates = self._frame(candidates, context, request, response.directives)
		return response

	def suggest(self, request, deadline=None):
````

with:

````python
		response.candidates = self._frame(candidates, context, request, response.directives)
		return response

	def host_states(self):
		'''What the prober learned (host -> HostState), from the runtime directory.'''
		return read_host_states(self.directory) if self.directory else {}

	def diagnose(self, request, probe=True, now=None):
		'''
		Warnings for the words of the request's line (before + after) already typed, most
		important first, and whether the prober still owes answers for hosts on the line.

		Args:
			probe (bool): queue those hosts and start the prober (needs self.directory)

		Returns:
			tuple: (list of Diagnostic, pending)
		'''
		now = time.time() if now is None else now
		line = request.before + request.after
		tokens = lex(line)
		start = _mssh_start(tokens)
		if start is None:
			return [], False
		cursor = len(request.before)
		words = tokens[start + 1:]
		states = self.host_states()
		wanted = []
		found = []
		for token, (role, _) in zip(words, assign_roles(words, self.spec)):
			if token.start <= cursor <= token.start + len(token.raw):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(token, states, now, wanted))
		wanted = _unique(wanted)
		if probe and wanted and self.directory:
			try:
				queue_probes(self.directory, wanted)
				spawn_probe(self.directory)
			except OSError as e:
				_debug('cannot queue hosts: {!r}'.format(e))
		found.sort(key=lambda item: (DIAGNOSTIC_KINDS.index(item.kind), item.start))
		return found, bool(wanted)

	def _host_diagnostics(self, token, states, now, wanted):
		'''Unknown hosts and range surprises in a hosts word.'''
		found = []
		for name, (start, end) in _host_parts(token):
			if not name:
				continue
			members = self._host_members(name)
			if members is None:
				if self._verdict(name, states, now, wanted) == 'invalid':
					found.append(Diagnostic(start, end, 'unknown', self._unknown_message(name, states, now)))
			elif members:
				item = self._range_diagnostic(name, members[0], members[1], (start, end), states, now, wanted)
				if item is not None:
					found.append(item)
		return found

	def _host_members(self, name):
		'''
		(members, how many) for an alias or a range, the members up to RANGE_MEMBERS_LIMIT; None for
		one host; () for a range that cannot be expanded here (letters, hex): nothing is said about it.
		'''
		number = self.hosts.alias_index(name)
		if number is not None:
			members = self.hosts.alias_members(number)
			return members, len(members)
		if '[' not in name:
			return None
		total = _range_count(name)
		if total is None:
			return ()
		members = []
		for member in _iter_range(name):
			if len(members) >= RANGE_MEMBERS_LIMIT:
				break
			members.append(member)
		return (members, total) if members != [name] else None

	def _valid_at_once(self, name):
		'''An IP address or a hosts-file name: valid without DNS.'''
		return bool(self.hosts.sources(name) & SRC_HOSTS_FILE) or _is_ip_address(name)

	def _verdict(self, name, states, now, wanted):
		'''
		What is known about one host: 'valid', 'invalid', 'unsure', or '' (the prober is asked).
		A host whose answer or ping is not fresh goes into wanted.
		'''
		state = states.get(name)
		if self._valid_at_once(name):
			# no DNS needed, only a ping
			if state is None or not state.fresh_ping(now):
				wanted.append(name)
			return 'valid'
		if needs_probe(state, now):
			wanted.append(name)
		return state.fresh_validity(now) if state is not None else ''

	def _unknown_message(self, name, states, now):
		dash, _ = _punctuation()
		meant = self._did_you_mean(name, states, now)
		return '{}: unknown host'.format(name) + (dash + 'did you mean {}?'.format(meant) if meant else '')

	def _did_you_mean(self, name, states, now):
		'''
		The one known host name meant instead of name: the same once leading zeros are dropped
		(gpu017 -> gpu17), else one edit away (names of at least 4 characters); None when there is
		no such name or more than one.
		'''
		def possible(candidate):
			state = states.get(candidate)
			return candidate != name and not (state is not None and state.fresh_validity(now) == 'invalid')
		stripped = _strip_zeros(name)
		same = [candidate for candidate in self.hosts.names if _strip_zeros(candidate) == stripped and possible(candidate)]
		if same:
			return same[0] if len(same) == 1 else None
		if len(name) < 4:
			return None
		close = [candidate for candidate in self.hosts.names
			if abs(len(candidate) - len(name)) <= 1 and possible(candidate) and _one_edit(name, candidate)]
		return close[0] if len(close) == 1 else None

	def _range_diagnostic(self, name, members, total, span, states, now, wanted):
		'''The warning for a range or an alias with members mssh would reject, or None.'''
		unknown = []
		checked = 0
		for member in members:
			verdict = self._verdict(member, states, now, wanted)
			if verdict:
				checked += 1
				if verdict == 'invalid':
					unknown.append(member)
		if not unknown:
			return None
		dash, more = _punctuation()
		if checked < total:
			message = '{}: {} of {} checked, {} unknown so far'.format(name, checked, total, len(unknown))
		else:
			shown = ', '.join(unknown[:3] + ([more] if len(unknown) > 3 else []))
			message = '{}: {} of {} hosts unknown ({})'.format(name, len(unknown), total, shown)
			padded = _padded_range(name)
			if padded is not None:
				# every member is asked about, so the suggestion can appear once the prober answers
				verdicts = [self._verdict(member, states, now, wanted) for member in _iter_range(padded)]
				if all(verdict == 'valid' for verdict in verdicts):
					message += dash + 'did you mean {}?'.format(padded)
		return Diagnostic(span[0], span[1], 'range', message)

	def suggest(self, request, deadline=None):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	if response.ghost is not None and safe_field(response.ghost.text) and '\t' not in response.ghost.text:
		lines.append('G {}\t{}'.format(response.ghost.kind, response.ghost.text))
	if response.delegate is not None:
		index, prefix, words = response.delegate
````

with:

````python
	if response.ghost is not None and safe_field(response.ghost.text) and '\t' not in response.ghost.text:
		lines.append('G {}\t{}'.format(response.ghost.kind, response.ghost.text))
	for item in response.diagnostics:
		lines.append('W {}\t{}\t{}\t{}'.format(item.start, item.end, item.kind, _clean(item.message)[:MAX_MESSAGE]))
	if response.delegate is not None:
		index, prefix, words = response.delegate
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	engine = Engine(spec, knowledges, HostTable(index), users)
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	return engine

````

with:

````python
	engine = Engine(spec, knowledges, HostTable(index), users)
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	engine.directory = directory
	return engine

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_engine.py tests/test_complete_lex.py -q`

Expected: PASS (`76 passed in 0.18s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `913 passed, 32 skipped in 71.21s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_diagnose.py
git commit -F - <<'EOF'
feat: warnings for unknown hosts and range surprises (diag=1)

Engine.diagnose marks hosts mssh would reject, with the host meant when
one is clearly close, and ranges or aliases with such members; hosts
without a fresh answer go to the prober. Answers come as W records with
a pending directive while the prober works.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 7: Warnings for unreachable hosts

**Files:**
- Modify: `tests/test_complete_diagnose.py`
- Modify: `tests/test_complete_index.py` (append)
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 6: `Engine.diagnose`, `_host_diagnostics`, `_verdict`; Task 4: `boot_id`
- Produces: `flag_settings(parser) -> ({long string: value set}, {dest: default})`; index config rows `flag_sets`, `flag_defaults`; `Engine.flag_sets`, `Engine.flag_defaults` (filled by `engine_for`); `read_unavailable(directory) -> frozenset`; `Engine._line_settings(words, roles) -> (skipping, ping expiry)`; `Engine._unreachable(name, state, now, reach)`; `_host_diagnostics(token, states, now, wanted, reach)`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_complete_diagnose.py`, replace this text (it occurs exactly once):

````python
'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import pytest

````

with:

````python
'''Warnings before Enter: what the engine says about the words of an mssh line already typed.'''
import os

import pytest

````

In `tests/test_complete_diagnose.py`, replace this text (it occurs exactly once):

````python
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text
````

with:

````python
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text


def unavailable(engine, *hosts, boot='boot-a', left=300):
	'''mssh's unavailable_hosts.csv, as a run that failed on hosts writes it.'''
	expiry = int(mc.time.monotonic()) + left
	with open(os.path.join(engine.directory, 'unavailable_hosts.csv'), 'w') as f:
		f.write('#boot_id,{}\n'.format(boot) + ''.join('{},{}\n'.format(host, expiry) for host in hosts))


@pytest.fixture
def skipping(engine):
	'''Skipping unreachable hosts on by default, as mssh ships.'''
	engine.flag_sets, engine.flag_defaults = mc.flag_settings(multiSSH3.get_parser())
	engine.flag_defaults['skip_unreachable'] = True
	return engine


@pytest.mark.parametrize('options, message', [
	('', 'node05: will be skipped — unreachable in a recent mssh run'),
	('-nsu ', 'node05: unreachable in a recent mssh run'),
	# --script skips unreachable hosts whatever else is given
	('--script -nsu ', 'node05: will be skipped — unreachable in a recent mssh run'),
])
def test_a_host_that_failed_in_a_recent_run(skipping, options, message):
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh {}node05 uptime'.format(options))[0] == [('node05', 'unreachable', message)]


def test_when_skipping_is_off_by_default_only_su_skips(skipping):
	skipping.flag_defaults['skip_unreachable'] = False
	unavailable(skipping, 'node05')
	assert warnings(skipping, 'mssh node05 uptime')[0][0][2] == 'node05: unreachable in a recent mssh run'
	assert warnings(skipping, 'mssh -su node05 uptime')[0][0][2] == 'node05: will be skipped — unreachable in a recent mssh run'


@pytest.mark.parametrize('boot, left', [('boot-b', 300), ('boot-a', -5)], ids=['another_boot', 'expired'])
def test_old_failures_are_forgotten(skipping, boot, left):
	unavailable(skipping, 'node05', boot=boot, left=left)
	assert warnings(skipping, 'mssh node05 uptime')[0] == []


def pinged(engine, host, ping, pinged_ago, answered_ago=None):
	mc.write_host_states(engine.directory, {host: mc.HostState('valid', NOW, ping, NOW - pinged_ago, 0.0 if answered_ago is None else NOW - answered_ago)})


def test_a_host_that_stopped_answering_ping(skipping):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=240)
	assert warnings(skipping, 'mssh login1 uptime') == ([('login1', 'unreachable', 'login1: no answer to ping (answered 4 min ago)')], False)


@pytest.mark.parametrize('pinged_ago, answered_ago', [
	(10, None),   # never answered: ping may be blocked, ssh may still work
	(10, 700),    # answered longer ago than the ping expiry (600 s)
	(90, 120),    # the silent ping is older than a minute: asked again
])
def test_ping_silence_alone_says_nothing(skipping, pinged_ago, answered_ago):
	pinged(skipping, 'login1', 'silent', pinged_ago, answered_ago)
	assert warnings(skipping, 'mssh login1 uptime')[0] == []


def test_the_ping_expiry_follows_mssh_or_the_environment(skipping, monkeypatch):
	pinged(skipping, 'login1', 'silent', 10, answered_ago=700)
	monkeypatch.setenv('MSSH_COMPLETE_PING_TTL', '900')
	assert warnings(skipping, 'mssh login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'
	monkeypatch.delenv('MSSH_COMPLETE_PING_TTL')
	# -uhe on the line is mssh's expiry for this run
	assert warnings(skipping, 'mssh -uhe 900 login1 uptime')[0][0][2] == 'login1: no answer to ping (answered 11 min ago)'


def test_unreachable_members_of_a_range(skipping):
	unavailable(skipping, 'node03')
	mc.write_host_states(skipping.directory, {'node07': mc.HostState('valid', NOW, 'silent', NOW - 5, NOW - 60)})
	assert warnings(skipping, 'mssh node[01-08] uptime')[0] == [('node[01-08]', 'unreachable', 'node[01-08]: 2 unreachable (node03, node07)')]


def test_an_unknown_host_is_not_also_unreachable(skipping):
	seed(skipping, gpu017='invalid')
	unavailable(skipping, 'gpu017')
	assert [kind for _, kind, _ in warnings(skipping, 'mssh gpu017 uptime')[0]] == ['unknown']
````

Append to the end of `tests/test_complete_index.py` (the text starts with the line breaks that separate it from what is there):

````python


def test_the_index_records_what_flags_do_and_their_defaults(home, monkeypatch):
	monkeypatch.setattr(multiSSH3, 'DEFAULT_SKIP_UNREACHABLE', False)
	index, directory = build()
	engine = mc.engine_for(mc.Request('bash', 'mssh ', '', ''), directory, NOW)
	assert engine.flag_sets['--no_skip_unreachable'] is False and engine.flag_sets['--skip_unreachable'] is True
	assert engine.flag_defaults['skip_unreachable'] is False and engine.flag_defaults['ipmi'] is multiSSH3.DEFAULT_IPMI
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'flag_settings'` (`1 failed, 42 passed, 13 errors in 0.36s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			groups.get(id(action), ''), _one_line(default), _one_line(action.help or '')))
	return ParserSpec(options)

#%% ------------ Context ----------------
````

with:

````python
			groups.get(id(action), ''), _one_line(default), _one_line(action.help or '')))
	return ParserSpec(options)

def flag_settings(parser):
	'''
	What the flags of an argparse parser do (index builder side): ({long string: the value it
	sets}, {dest: its default}). The defaults follow the mssh config the parser was made with.
	'''
	import argparse
	sets = {}
	defaults = {}
	for action in parser._actions:
		if action.option_strings and isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
			sets[OptionSpec(action.dest, action.option_strings).long] = bool(action.const)
			defaults[action.dest] = bool(parser.get_default(action.dest))
	return sets, defaults

def _flag_rows(sets, defaults):
	'''flag_settings as index config rows.'''
	return [['flag_sets'] + ['{}={}'.format(string, int(value)) for string, value in sorted(sets.items())],
		['flag_defaults'] + ['{}={}'.format(dest, int(value)) for dest, value in sorted(defaults.items())]]

def _flag_values(fields):
	'''The 'name=0|1' fields of an index config row as name -> bool.'''
	values = {}
	for field in fields:
		name, sep, value = field.rpartition('=')
		if sep and value in ('0', '1'):
			values[name] = value == '1'
	return values

#%% ------------ Context ----------------
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	now = time.time() if now is None else now
	mssh = mssh or _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	history_path = os.path.expanduser(mssh.DEFAULT_HISTORY_FILE)
	lines, offset, inode = read_history(history_path)
````

with:

````python
	now = time.time() if now is None else now
	mssh = mssh or _import_mssh()
	parser = mssh.get_parser()
	spec = spec_from_parser(parser)
	history_path = os.path.expanduser(mssh.DEFAULT_HISTORY_FILE)
	lines, offset, inode = read_history(history_path)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	sections = [
		('spec', spec.to_rows()),
		('config', [['users'] + sorted(user for user in users if safe_field(user))]),
		('sources', source_rows),
		('features', [features]),
````

with:

````python
	sections = [
		('spec', spec.to_rows()),
		('config', [['users'] + sorted(user for user in users if safe_field(user))] + _flag_rows(*flag_settings(parser))),
		('sources', source_rows),
		('features', [features]),
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			pass
		raise

def _queueable(host):
````

with:

````python
			pass
		raise

def read_unavailable(directory):
	'''
	The hosts mssh's unavailable_hosts.csv lists now: failed in a recent run of this boot, their
	expiry (time.monotonic() seconds) not passed.
	'''
	try:
		with open(os.path.join(directory, 'unavailable_hosts.csv'), encoding='utf-8', errors='replace') as f:
			lines = f.read().split('\n')
	except OSError:
		return frozenset()
	now = time.monotonic()
	written = None
	hosts = set()
	for line in lines:
		fields = line.strip().split(',')
		if len(fields) != 2:
			continue
		if fields[0] == '#boot_id':
			written = fields[1]
		elif fields[0] and _is_digits(fields[1]) and int(fields[1]) > now:
			hosts.add(fields[0])
	current = boot_id()
	if current and written and current != written:
		return frozenset()
	return frozenset(hosts)

def _queueable(host):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		# the runtime directory: host states, the probe queue; None runs without them
		self.directory = None

	def query(self, request, deadline=None):
````

with:

````python
		# the runtime directory: host states, the probe queue; None runs without them
		self.directory = None
		# what mssh's flags set ({long string: value}) and their defaults ({dest: value}): flag_settings
		self.flag_sets = {}
		self.flag_defaults = {}

	def query(self, request, deadline=None):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		cursor = len(request.before)
		words = tokens[start + 1:]
		states = self.host_states()
		wanted = []
		found = []
		for token, (role, _) in zip(words, assign_roles(words, self.spec)):
			if token.start <= cursor <= token.start + len(token.raw):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(token, states, now, wanted))
		wanted = _unique(wanted)
		if probe and wanted and self.directory:
````

with:

````python
		cursor = len(request.before)
		words = tokens[start + 1:]
		roles = assign_roles(words, self.spec)
		states = self.host_states()
		unavailable = read_unavailable(self.directory) if self.directory else frozenset()
		reach = (unavailable,) + self._line_settings(words, roles)
		wanted = []
		found = []
		for token, (role, _) in zip(words, roles):
			if token.start <= cursor <= token.start + len(token.raw):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(token, states, now, wanted, reach))
		wanted = _unique(wanted)
		if probe and wanted and self.directory:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return found, bool(wanted)

	def _host_diagnostics(self, token, states, now, wanted):
		'''Unknown hosts and range surprises in a hosts word.'''
		found = []
		for name, (start, end) in _host_parts(token):
````

with:

````python
		return found, bool(wanted)

	def _host_diagnostics(self, token, states, now, wanted, reach):
		'''
		Unknown hosts, range surprises and unreachable hosts in a hosts word. reach is (the hosts
		in mssh's unavailable list, whether they are skipped, the ping expiry).
		'''
		found = []
		for name, (start, end) in _host_parts(token):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
				if self._verdict(name, states, now, wanted) == 'invalid':
					found.append(Diagnostic(start, end, 'unknown', self._unknown_message(name, states, now)))
			elif members:
				item = self._range_diagnostic(name, members[0], members[1], (start, end), states, now, wanted)
				if item is not None:
					found.append(item)
		return found

````

with:

````python
				if self._verdict(name, states, now, wanted) == 'invalid':
					found.append(Diagnostic(start, end, 'unknown', self._unknown_message(name, states, now)))
				else:
					why = self._unreachable(name, states.get(name), now, reach)
					if why:
						found.append(Diagnostic(start, end, 'unreachable', why))
			elif members:
				members, total = members
				verdicts = [self._verdict(member, states, now, wanted) for member in members]
				item = self._range_diagnostic(name, members, verdicts, total, (start, end), states, now, wanted)
				if item is not None:
					found.append(item)
				down = [member for member, verdict in zip(members, verdicts)
					if verdict != 'invalid' and self._unreachable(member, states.get(member), now, reach)]
				if down:
					_, more = _punctuation()
					shown = ', '.join(down[:3] + ([more] if len(down) > 3 else []))
					found.append(Diagnostic(start, end, 'unreachable', '{}: {} unreachable ({})'.format(name, len(down), shown)))
		return found

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return state.fresh_validity(now) if state is not None else ''

	def _unknown_message(self, name, states, now):
		dash, _ = _punctuation()
````

with:

````python
		return state.fresh_validity(now) if state is not None else ''

	def _line_settings(self, words, roles):
		'''
		(whether unreachable hosts are skipped, the ping expiry in seconds) for the options of a line.

		Skipping: the last of -su / -nsu on the line, else the mssh config's default; --script
		always skips (process_args). Ping expiry: $MSSH_COMPLETE_PING_TTL, else mssh's unreachable
		host expiry (-uhe on the line, else its default).
		'''
		flags = {}
		expiry = None
		for token, (role, option) in zip(words, roles):
			if option is None:
				continue
			if role == ROLE_OPTION and option.nargs == '0' and option.long in self.flag_sets:
				flags[option.dest] = self.flag_sets[option.long]
			elif option.dest == 'unavailable_host_expiry':
				value = token.text if role == ROLE_VALUE else self.spec.lookup(token.text)[1]
				if value is not None and _is_digits(value):
					expiry = int(value)
		def flag(dest):
			return flags.get(dest, self.flag_defaults.get(dest, False))
		skipping = flag('script') or flag('skip_unreachable')
		ttl = os.environ.get('MSSH_COMPLETE_PING_TTL', '')
		if _is_digits(ttl) and int(ttl) > 0:
			expiry = int(ttl)
		if expiry is None:
			default = next((option.default for option in self.spec.options if option.dest == 'unavailable_host_expiry'), '')
			expiry = int(default) if _is_digits(default) else 600
		return skipping, expiry

	def _unreachable(self, name, state, now, reach):
		'''Why a host looks unreachable, or None: it failed in a recent mssh run, or stopped answering ping.'''
		unavailable, skipping, expiry = reach
		if name in unavailable:
			dash, _ = _punctuation()
			return '{}: {}unreachable in a recent mssh run'.format(name, 'will be skipped' + dash if skipping else '')
		if (state is not None and state.fresh_ping(now) == 'silent' and state.answered_at
				and now - state.answered_at <= expiry):
			return '{}: no answer to ping (answered {} min ago)'.format(name, max(1, int((now - state.answered_at) // 60)))
		return None

	def _unknown_message(self, name, states, now):
		dash, _ = _punctuation()
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return close[0] if len(close) == 1 else None

	def _range_diagnostic(self, name, members, total, span, states, now, wanted):
		'''The warning for a range or an alias with members mssh would reject, or None.'''
		unknown = []
		checked = 0
		for member in members:
			verdict = self._verdict(member, states, now, wanted)
			if verdict:
				checked += 1
````

with:

````python
		return close[0] if len(close) == 1 else None

	def _range_diagnostic(self, name, members, verdicts, total, span, states, now, wanted):
		'''The warning for a range or an alias with members mssh would reject (verdicts: theirs, in order), or None.'''
		unknown = []
		checked = 0
		for member, verdict in zip(members, verdicts):
			if verdict:
				checked += 1
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		config = {row[0]: row[1:] for row in (index.row('config', number) for number in range(index.count('config'))) if row}
		users = config.get('users', ())
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		spec = spec_from_parser(_import_mssh().get_parser())
	if tail:
		memory = MemoryKnowledge()
````

with:

````python
		config = {row[0]: row[1:] for row in (index.row('config', number) for number in range(index.count('config'))) if row}
		users = config.get('users', ())
		flags = (_flag_values(config.get('flag_sets', ())), _flag_values(config.get('flag_defaults', ())))
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		parser = _import_mssh().get_parser()
		spec = spec_from_parser(parser)
		flags = flag_settings(parser)
	if tail:
		memory = MemoryKnowledge()
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	engine.directory = directory
	return engine

````

with:

````python
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	engine.directory = directory
	engine.flag_sets, engine.flag_defaults = flags
	return engine

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_index.py -q`

Expected: PASS (`56 passed in 0.34s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `927 passed, 32 skipped in 71.27s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_diagnose.py tests/test_complete_index.py
git commit -F - <<'EOF'
feat: warnings for unreachable hosts

A host that failed in a recent mssh run (mssh's unavailable list, read
at query time), or that answered ping within the ping expiry and now
does not; with skipping in effect the warning says the host will be
skipped. The index records what mssh's flags do and their defaults.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 8: Warnings for conflicting options

**Files:**
- Modify: `tests/test_complete_diagnose.py` (append)
- Modify: `tests/test_complete_index.py` (append)
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 3: `multiSSH3.OPTION_NO_EFFECT`; Task 7: `flag_sets`, `flag_defaults`
- Produces: index section `no_effect` (rows `[option, kind, why, others...]`); `Engine.no_effect` (list of `(option, kind, others tuple, why)`, filled by `engine_for`); `Engine._option_diagnostics(options)`; `Engine._on_by_default(string)`; `_option_name(text, attached)`.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_diagnose.py` (the text starts with the line breaks that separate it from what is there):

````python


def test_options_of_one_exclusive_group(skipping):
	assert warnings(skipping, 'mssh -su -nsu node01 uptime')[0] == [('-nsu', 'options', '-nsu cannot be used with -su (mssh stops with an error)')]
	# the same option twice is allowed
	assert warnings(skipping, 'mssh -su -su node01 uptime')[0] == []


def test_an_option_given_twice(engine):
	assert warnings(engine, 'mssh -u admin -u=root node01 uptime')[0] == [('-u', 'options', '-u given twice: mssh uses root')]
	assert warnings(engine, 'mssh -u root -u root node01 uptime')[0] == []
	# a password never shows
	assert warnings(engine, 'mssh -p one --password=two node01 uptime')[0] == [('-p', 'options', '-p given twice: mssh uses the last one')]
	# the second value is still being typed
	assert warnings(engine, 'mssh -u admin -u ro')[0] == []


@pytest.fixture
def no_effect(skipping):
	skipping.no_effect = [(option, kind, tuple(others), why) for option, kind, others, why in multiSSH3.OPTION_NO_EFFECT]
	skipping.flag_defaults['ipmi'] = False
	return skipping


@pytest.mark.parametrize('line, expected', [
	('mssh --script -nsu node01 true', [('-nsu', 'options', '-nsu does nothing: --script skips unreachable hosts anyway')]),
	('mssh -iu admin node01 true', [('-iu', 'options', '-iu does nothing: only used with --ipmi')]),
	('mssh -M -iu admin node01 true', []),
	('mssh -iu admin --generate_config_file node01 true', []),
	# the message names the option, never the value given with it
	('mssh -ip=secret node01 true', [('-ip=secret', 'options', '-ip does nothing: only used with --ipmi')]),
])
def test_options_that_do_nothing_here(no_effect, line, expected):
	assert warnings(no_effect, line)[0] == expected


def test_settings_used_by_default_are_not_flagged(no_effect):
	# the mssh config turns --ipmi on
	no_effect.flag_defaults['ipmi'] = True
	assert warnings(no_effect, 'mssh -iu admin node01 true')[0] == []
````

Append to the end of `tests/test_complete_index.py` (the text starts with the line breaks that separate it from what is there):

````python


def test_the_index_records_option_combinations_with_no_effect(home):
	_, directory = build()
	engine = mc.engine_for(mc.Request('bash', 'mssh ', '', ''), directory, NOW)
	assert engine.no_effect == [(option, kind, tuple(others), why) for option, kind, others, why in multiSSH3.OPTION_NO_EFFECT]
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AssertionError: assert [] == [('-nsu', 'op...h an error)')]` (`6 failed, 59 passed in 0.37s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		('groups', group_rows),
		('unavailable', [unavailable]),
	]
	path = os.path.join(directory, INDEX_NAME)
````

with:

````python
		('groups', group_rows),
		('unavailable', [unavailable]),
		# option combinations main() ignores: [option, kind, why, others...]
		('no_effect', [[option, kind, why] + list(others) for option, kind, others, why in getattr(mssh, 'OPTION_NO_EFFECT', ())]),
	]
	path = os.path.join(directory, INDEX_NAME)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return any(long_[:index] + long_[index + 1:] == short for index in range(len(long_)))

def _unique(names):
	'''names without repeats, in order.'''
````

with:

````python
	return any(long_[:index] + long_[index + 1:] == short for index in range(len(long_)))

def _option_name(text, attached):
	'''An option word without the value given with it: -ip=secret -> -ip, -uroot -> -u.'''
	if attached is None:
		return text
	return text[:len(text) - len(attached)].rstrip('=')

def _unique(names):
	'''names without repeats, in order.'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self.flag_sets = {}
		self.flag_defaults = {}

	def query(self, request, deadline=None):
````

with:

````python
		self.flag_sets = {}
		self.flag_defaults = {}
		# OPTION_NO_EFFECT entries from mssh: (long option, 'with' | 'without', other long options, why)
		self.no_effect = []

	def query(self, request, deadline=None):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		wanted = []
		found = []
		for token, (role, _) in zip(words, roles):
			if token.start <= cursor <= token.start + len(token.raw):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(token, states, now, wanted, reach))
		wanted = _unique(wanted)
		if probe and wanted and self.directory:
````

with:

````python
		wanted = []
		found = []
		options = []
		def typing(token):
			return token.start <= cursor <= token.start + len(token.raw)
		for number, (token, (role, option)) in enumerate(zip(words, roles)):
			if role == ROLE_OPTION and option is not None:
				_, attached = self.spec.lookup(token.text)
				value, value_done = attached, not typing(token)
				if attached is None and number + 1 < len(words) and roles[number + 1][0] == ROLE_VALUE:
					value, value_done = words[number + 1].text, not typing(words[number + 1])
				options.append((token, option, _option_name(token.text, attached), value, not typing(token), value_done))
			if typing(token):
				# still being typed
				continue
			if role == ROLE_HOSTS:
				found.extend(self._host_diagnostics(token, states, now, wanted, reach))
		found.extend(self._option_diagnostics(options))
		wanted = _unique(wanted)
		if probe and wanted and self.directory:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			wanted.append(name)
		return state.fresh_validity(now) if state is not None else ''

	def _line_settings(self, words, roles):
````

with:

````python
			wanted.append(name)
		return state.fresh_validity(now) if state is not None else ''

	def _option_diagnostics(self, options):
		'''
		Conflicting options: two of one exclusive group (the later one is marked), a value option
		given twice with different values (the earlier one), an option with no effect on this line
		(OPTION_NO_EFFECT). options: (token, OptionSpec, name, value, word typed, value typed) per
		option word, in order.
		'''
		found = []
		on_line = {option.long for _, option, _, _, word_done, _ in options if word_done}
		groups = {}
		values = {}
		for token, option, name, value, word_done, value_done in options:
			if not word_done:
				continue
			span = (token.start, token.start + len(token.raw))
			if option.group:
				first = groups.setdefault(option.group, (option, name))
				if first[0].long != option.long:
					found.append(Diagnostic(span[0], span[1], 'options', '{} cannot be used with {} (mssh stops with an error)'.format(name, first[1])))
			if option.nargs != '0' and not option.repeat and value is not None and value_done:
				earlier = values.get(option.dest)
				if earlier is not None and earlier[1] != value:
					shown = 'the last one' if option.dest in PASSWORD_DESTS else value
					found.append(Diagnostic(earlier[0].start, earlier[0].start + len(earlier[0].raw), 'options',
						'{} given twice: mssh uses {}'.format(earlier[2], shown)))
				values[option.dest] = (token, value, name)
			for entry, kind, others, why in self.no_effect:
				if entry != option.long:
					continue
				if kind == 'with':
					applies = any(other in on_line for other in others)
				else:
					applies = not any(other in on_line or self._on_by_default(other) for other in others)
				if applies:
					found.append(Diagnostic(span[0], span[1], 'options', '{} does nothing: {}'.format(name, why)))
		return found

	def _on_by_default(self, string):
		'''Whether a flag (by its long string) is on without being given: the mssh config turned it on.'''
		option = self.spec.lookup(string)[0]
		return option is not None and option.nargs == '0' and self.flag_sets.get(option.long) is True and self.flag_defaults.get(option.dest, False)

	def _line_settings(self, words, roles):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		users = config.get('users', ())
		flags = (_flag_values(config.get('flag_sets', ())), _flag_values(config.get('flag_defaults', ())))
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		parser = _import_mssh().get_parser()
		spec = spec_from_parser(parser)
		flags = flag_settings(parser)
	if tail:
		memory = MemoryKnowledge()
````

with:

````python
		users = config.get('users', ())
		flags = (_flag_values(config.get('flag_sets', ())), _flag_values(config.get('flag_defaults', ())))
		no_effect = [(row[0], row[1], tuple(row[3:]), row[2]) for row in (index.row('no_effect', number) for number in range(index.count('no_effect'))) if len(row) >= 3]
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		mssh = _import_mssh()
		parser = mssh.get_parser()
		spec = spec_from_parser(parser)
		flags = flag_settings(parser)
		no_effect = [(option, kind, tuple(others), why) for option, kind, others, why in getattr(mssh, 'OPTION_NO_EFFECT', ())]
	if tail:
		memory = MemoryKnowledge()
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	engine.directory = directory
	engine.flag_sets, engine.flag_defaults = flags
	return engine

````

with:

````python
	engine.directory = directory
	engine.flag_sets, engine.flag_defaults = flags
	engine.no_effect = no_effect
	return engine

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_index.py -q`

Expected: PASS (`65 passed in 0.35s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `936 passed, 32 skipped in 71.53s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_diagnose.py tests/test_complete_index.py
git commit -F - <<'EOF'
feat: warnings for conflicting options

Two options of one exclusive group, a value option given twice with
different values (passwords never shown), and options that do nothing
on the line (mssh's OPTION_NO_EFFECT, carried in the index).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 9: The Ctrl-R picker lists the line's warnings

**Files:**
- Modify: `tests/test_complete_picker.py` (append)
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 6: `Engine.diagnose`; SP2: `Picker`, `_cmd_pick`, `_cmd_edit`
- Produces: `Picker(slot_items, history_items, slot_title='', now=None, unicode=None, warnings=())` (up to three under the title); `reason_line(diagnostics, unicode=None) -> str` (`⚠ first (+N more)`, `!` without UTF-8); `picker_warnings(engine, request) -> [message, ...]`.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_picker.py` (the text starts with the line breaks that separate it from what is there):

````python


WARNINGS = ['gpu017: unknown host — did you mean gpu17?', 'node05: unreachable in a recent mssh run', '-nsu cannot be used with -su', 'one more']


def test_render_lists_up_to_three_warnings_under_the_title():
	picker = mc.Picker(items('gpu01', 'gpu02'), [], 'hosts', now=NOW, unicode=True, warnings=WARNINGS)
	lines = picker.render(60, 2)
	assert len(lines) == 1 + 3 + 2 + 1
	assert lines[1].startswith('│ ⚠ gpu017: unknown host') and lines[3].startswith('│ ⚠ -nsu cannot') and 'one more' not in ''.join(lines)
	assert 'gpu01' in lines[4] and all(mc.text_width(text) <= 60 for text in lines)
	assert mc.Picker(items('gpu01'), [], 'hosts', unicode=False, warnings=WARNINGS[:1]).render(60, 1)[1].startswith('| ! gpu017')


def test_run_makes_room_for_the_warnings():
	grid = Grid(24, 80)
	grid.feed('$ mssh gpu017 ')
	seen = []

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(grid.lines())
			return FakeTerminal.read_key(self, timeout)

	picker = mc.Picker(items('nvidia-smi'), [], 'commands', unicode=True, warnings=WARNINGS[:1])
	assert picker.run(Watching(['\x1b'], grid=grid)) == 'cancel'
	assert ' commands ' in seen[0][1] and 'gpu017: unknown host' in seen[0][2] and 'nvidia-smi' in seen[0][3]
	assert grid.lines()[1:] == [''] * 23


@pytest.mark.parametrize('unicode, expected', [(True, '⚠ a (+2 more)'), (False, '! a (+2 more)')])
def test_reason_line_shows_the_first_warning_and_counts_the_rest(unicode, expected):
	found = [mc.Diagnostic(0, 1, 'unknown', 'a'), mc.Diagnostic(2, 3, 'range', 'b'), mc.Diagnostic(4, 5, 'options', 'c')]
	assert mc.reason_line(found, unicode) == expected
	assert mc.reason_line(found[:1], unicode) == expected[:3]
	assert mc.reason_line([], unicode) == ''


def test_picker_warnings_come_from_the_line(tmp_path, monkeypatch):
	monkeypatch.setattr(mc, 'boot_id', lambda: 'boot-a')
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)
	monkeypatch.setattr(mc.time, 'time', lambda: NOW)
	monkeypatch.setattr(mc, 'spawn_probe', lambda directory: True)
	warned = engine()
	warned.directory = str(tmp_path)
	mc.write_host_states(str(tmp_path), {'gpu017': mc.HostState('invalid', NOW)})
	assert mc.picker_warnings(warned, mc.Request('bash', 'mssh gpu017 ', '', '')) == ['gpu017: unknown host']
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_picker.py tests/test_complete_editor.py -q`

Expected: FAIL, e.g. `E TypeError: Picker.__init__() got an unexpected keyword argument 'warnings'` (`5 failed, 65 passed in 0.26s`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	(whole past invocations), a fuzzy filter and a selection. run() draws it below the prompt line.
	'''
	def __init__(self, slot_items, history_items, slot_title='', now=None, unicode=None):
		self.items = {'slot': list(slot_items), 'history': list(history_items)}
		self.titles = {'slot': slot_title or 'candidates', 'history': 'history'}
		self.tab = 'slot' if self.items['slot'] else 'history'
````

with:

````python
	(whole past invocations), a fuzzy filter and a selection. run() draws it below the prompt line.
	'''
	def __init__(self, slot_items, history_items, slot_title='', now=None, unicode=None, warnings=()):
		self.items = {'slot': list(slot_items), 'history': list(history_items)}
		# up to three warnings about the line, shown under the title
		self.warnings = [_printable(text) for text in list(warnings)[:3]]
		self.titles = {'slot': slot_title or 'candidates', 'history': 'history'}
		self.tab = 'slot' if self.items['slot'] else 'history'
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		fill = max(inner - text_width(title) - text_width(counter), 0)
		lines = [fit(top_left + title + horizontal * fill + counter + top_right, width)]
		for number in range(self.offset, self.offset + rows):
			if number >= len(matches):
````

with:

````python
		fill = max(inner - text_width(title) - text_width(counter), 0)
		lines = [fit(top_left + title + horizontal * fill + counter + top_right, width)]
		for warning in self.warnings:
			text = fit(' {} {}'.format('⚠' if self.unicode else '!', warning), inner)
			lines.append(vertical + text + ' ' * (inner - text_width(text)) + vertical)
		for number in range(self.offset, self.offset + rows):
			if number >= len(matches):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		'''
		rows, width = term.size()
		height = min(PICKER_ROWS, rows - 4)
		if height < 1 or width < 20:
			return 'unavailable'
````

with:

````python
		'''
		rows, width = term.size()
		height = min(PICKER_ROWS, rows - 4 - len(self.warnings))
		if height < 1 or width < 20:
			return 'unavailable'
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			cursor = ('\x1b[{}A'.format(end_row - row) if end_row > row else '') + '\r' + ('\x1b[{}C'.format(column) if column else '')
		# make room below the line (the screen may scroll), come back to the same column and save it
		lines = height + 2
		term.write('\n' * lines + '\x1b[{}A\x1b7'.format(lines))
		try:
````

with:

````python
			cursor = ('\x1b[{}A'.format(end_row - row) if end_row > row else '') + '\r' + ('\x1b[{}C'.format(column) if column else '')
		# make room below the line (the screen may scroll), come back to the same column and save it
		lines = height + 2 + len(self.warnings)
		term.write('\n' * lines + '\x1b[{}A\x1b7'.format(lines))
		try:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		finally:
			term.write('\x1b8\r\n\x1b[J\x1b8' + ('\x1b[{}A'.format(up) if up else '') + ('\r' if line is not None else ''))

def _sets_password(words, spec):
````

with:

````python
		finally:
			term.write('\x1b8\r\n\x1b[J\x1b8' + ('\x1b[{}A'.format(up) if up else '') + ('\r' if line is not None else ''))

def reason_line(diagnostics, unicode=None):
	'''The one line shown under the prompt: the first warning, and how many more there are ('' for none).'''
	if not diagnostics:
		return ''
	unicode = _unicode_terminal() if unicode is None else unicode
	more = len(diagnostics) - 1
	return '{} {}{}'.format('⚠' if unicode else '!', diagnostics[0].message, ' (+{} more)'.format(more) if more else '')

def picker_warnings(engine, request):
	'''Up to three warnings about the request's line, for the top of the picker.'''
	try:
		found, _ = engine.diagnose(Request(request.shell, request.before, request.after, ''))
	except Exception as e:
		_debug('diagnostics failed: {!r}'.format(e))
		return []
	return [item.message for item in found[:3]]

def _sets_password(words, spec):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		if not slot and not history:
			return 2
		picker = Picker(slot, history, title, now)
		prompt = _prompt_from_flags(request.flags)
		line = before = None
````

with:

````python
		if not slot and not history:
			return 2
		picker = Picker(slot, history, title, now, warnings=picker_warnings(engine, request))
		prompt = _prompt_from_flags(request.flags)
		line = before = None
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		if not slot and (slot_only or not items):
			return None
		picker = Picker(slot, [] if slot_only else items, title)
		editor.erase(term)
		outcome = picker.run(term, prompt + text, prompt + text[:cursor])
````

with:

````python
		if not slot and (slot_only or not items):
			return None
		picker = Picker(slot, [] if slot_only else items, title, warnings=picker_warnings(engine, request))
		editor.erase(term)
		outcome = picker.run(term, prompt + text, prompt + text[:cursor])
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_picker.py tests/test_complete_editor.py -q`

Expected: PASS (`70 passed in 0.25s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `941 passed, 32 skipped in 71.29s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_picker.py
git commit -F - <<'EOF'
feat: the Ctrl-R picker lists the line's warnings

Up to three under the title, in every shell; reason_line() makes the
one line shown under the prompt.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 10: The mssh line editor marks warned words

**Files:**
- Modify: `tests/test_complete_editor.py` (append)
- Modify: `tests/test_complete_keys.py`
- Modify: `tests/vt_grid.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 9: `reason_line`; Task 6: `Engine.diagnose`
- Produces: `WARNING_ASKS = (0.3, 1.0, 3.0)`; `LineEditor(text, suggest=None, complete=None, pick=None, diagnose=None)` with `diagnose(text, cursor) -> (diagnostics, pending)`, `refresh_warnings(again=False)`, `marks`, `reason`; `mssh-complete edit` passes the engine's `diagnose`. tests/vt_grid.py: a `None` burst in `FakeTerminal` is the operator waiting (`timeouts` records the read timeouts).

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_editor.py` (the text starts with the line breaks that separate it from what is there):

````python


UNKNOWN = [mc.Diagnostic(5, 11, 'unknown', 'gpu017: unknown host')]


@pytest.fixture
def warning_terminal(monkeypatch):
	monkeypatch.delenv('NO_COLOR', raising=False)
	monkeypatch.setattr(mc, '_unicode_terminal', lambda: True)


@pytest.mark.parametrize('no_color, style', [(False, '4;31'), (True, '4')])
def test_a_warning_underlines_its_span_and_explains_below(warning_terminal, monkeypatch, no_color, style):
	if no_color:
		monkeypatch.setenv('NO_COLOR', '1')
	edit = editor('mssh gpu017 ', diagnose=lambda text, cursor: (UNKNOWN, False))
	term = FakeTerminal([])
	edit.refresh_warnings()
	edit.draw(term, '$ ', None)
	assert term.grid.lines()[:2] == ['$ mssh gpu017', '⚠ gpu017: unknown host']
	assert [column for column, cell in enumerate(term.grid.styles(0)) if cell] == list(range(7, 13))
	assert term.grid.styles(0)[7] == style and term.grid.cursor == (0, 14)
	edit.erase(term)
	assert term.grid.lines()[:2] == ['', '']


def test_while_the_prober_works_the_editor_asks_again(warning_terminal):
	answers = [([], True), ([], True), (UNKNOWN, False)]
	asked = []
	seen = []

	def diagnose(text, cursor):
		asked.append(text)
		return answers.pop(0) if answers else (UNKNOWN, False)

	class Watching(FakeTerminal):
		def read_key(self, timeout=None):
			seen.append(self.grid.lines()[1])
			return FakeTerminal.read_key(self, timeout)

	term = Watching([None, None, '\r'])
	assert editor('mssh gpu017 ', diagnose=diagnose).run(term, '$ ') == ('pass', b'\r')
	# at 0.3 s and 1 s after the first answer (the fake terminal lets no time pass); the third answer is
	# not pending, so the editor waits for keys
	assert len(asked) == 3 and term.timeouts == [pytest.approx(0.3, abs=0.1), pytest.approx(1.0, abs=0.1)]
	assert seen[-1] == '⚠ gpu017: unknown host'


def test_no_warnings_are_asked_for_while_keys_wait(warning_terminal):
	asked = []
	edit = editor('mssh ', diagnose=lambda text, cursor: (asked.append((text, cursor)) or ([], False)))
	assert edit.run(FakeTerminal(['abc', '\r']), '$ ') == ('pass', b'\r')
	assert asked == [('mssh ', 5), ('mssh abc', 8)]
````

In `tests/test_complete_keys.py`, replace this text (it occurs exactly once):

````python
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import re
import subprocess
````

with:

````python
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import os
import re
import subprocess
````

In `tests/test_complete_keys.py`, replace this text (it occurs exactly once):

````python
		assert '\x1b[38;5;244mu[01-16] "nvidia-smi"' in session.read_until(b'nvidia-smi', 10)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()
````

with:

````python
		assert '\x1b[38;5;244mu[01-16] "nvidia-smi"' in session.read_until(b'nvidia-smi', 10)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_editor_marks_an_unknown_host_and_says_why(home):
	env, home = home
	# the prober found gpu017 does not exist
	mc.write_host_states(os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3'), {'gpu017': mc.HostState('invalid', time.time())})
	session = editor_session(env, home)
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
	finally:
		session.close()
````

In `tests/vt_grid.py`, replace this text (it occurs exactly once):

````python
	What the picker and the editor need from a Terminal, drawing into a Grid. Keys come in scripted
	bursts (what the operator typed at once), one key per read; queue holds the burst's unread keys.
	'''
	def __init__(self, bursts, rows=24, columns=80, grid=None):
````

with:

````python
	What the picker and the editor need from a Terminal, drawing into a Grid. Keys come in scripted
	bursts (what the operator typed at once), one key per read; queue holds the burst's unread keys.
	A burst of None is the operator waiting: a read with a timeout returns None (timeouts records them).
	'''
	def __init__(self, bursts, rows=24, columns=80, grid=None):
````

In `tests/vt_grid.py`, replace this text (it occurs exactly once):

````python
		self.bursts = list(bursts)
		self.queue = []

	def size(self):
````

with:

````python
		self.bursts = list(bursts)
		self.queue = []
		self.timeouts = []

	def size(self):
````

In `tests/vt_grid.py`, replace this text (it occurs exactly once):

````python
				raise AssertionError('the program read more keys than the test scripted')
			burst = self.bursts.pop(0)
			self.queue = mc.decode_keys(burst.encode('utf-8') if isinstance(burst, str) else burst)
		return self.queue.pop(0)
````

with:

````python
				raise AssertionError('the program read more keys than the test scripted')
			burst = self.bursts.pop(0)
			if burst is None:
				if timeout is None:
					raise AssertionError('the program waits for a key with no timeout while the test waits')
				self.timeouts.append(timeout)
				return None
			self.queue = mc.decode_keys(burst.encode('utf-8') if isinstance(burst, str) else burst)
		return self.queue.pop(0)
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_editor.py tests/test_complete_keys.py -q`

Expected: FAIL, e.g. `E TypeError: LineEditor.__init__() got an unexpected keyword argument 'diagnose'` (`5 failed, 65 passed, 11 skipped in 64.10s (0:01:04)`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k editor' tests/shells/run_matrix.sh modern current legacy centos7`

Expected: FAIL, e.g. `E AssertionError: assert '⚠ gpu017: unknown host' in 'mssh@@READY@@ mssh @@READY@@ mssh gpu017 '`, with:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
1 failed, 11 passed, 1 skipped, 19 deselected in 44.55s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
1 failed, 11 passed, 1 skipped, 19 deselected in 44.77s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
1 failed, 11 passed, 1 skipped, 19 deselected in 44.60s
=== centos7 (requires bash,blesh)
Python 3.6.8
1 passed, 12 skipped, 19 deselected in 0.97s
````

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
DIAGNOSTIC_KINDS = ('unknown', 'range', 'unreachable', 'options')  # the order warnings are shown in
MAX_MESSAGE = 160

class Diagnostic(object):
````

with:

````python
DIAGNOSTIC_KINDS = ('unknown', 'range', 'unreachable', 'options')  # the order warnings are shown in
MAX_MESSAGE = 160
WARNING_ASKS = (0.3, 1.0, 3.0)  # seconds after an answer with the prober still working when a frontend asks again

class Diagnostic(object):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	replace word at the end of before; pick(text, cursor, slot_only) -> (text, cursor) or None.
	'''
	def __init__(self, text, suggest=None, complete=None, pick=None):
		self.text = text
		self.cursor = len(text)
````

with:

````python
	replace word at the end of before; pick(text, cursor, slot_only) -> (text, cursor) or None.
	'''
	def __init__(self, text, suggest=None, complete=None, pick=None, diagnose=None):
		self.text = text
		self.cursor = len(text)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self.complete = complete
		self.pick = pick
		self.ghost = ''
		self._ghost_for = None
		# more typed keys are waiting (set by run): no suggestion is asked for until they are handled
		self.busy = False

	def refresh(self):
````

with:

````python
		self.complete = complete
		self.pick = pick
		self.diagnose = diagnose
		self.ghost = ''
		self._ghost_for = None
		# more typed keys are waiting (set by run): no suggestion is asked for until they are handled
		self.busy = False
		# warnings: spans of the text to underline, the line shown under it, when to ask again (monotonic)
		self.marks = []
		self.reason = ''
		self._warned_for = None
		self._asks = []

	def refresh(self):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			return 'pass', raw
		self.refresh()
		return None

	def _tab(self):
````

with:

````python
			return 'pass', raw
		self.refresh()
		self.refresh_warnings()
		return None

	def refresh_warnings(self, again=False):
		'''
		Ask for warnings about the line, unless more keys wait or the answer is for this line
		already. While the prober still owes answers (pending), ask again WARNING_ASKS seconds
		after the answer to a key; again: this is one of those asks (the schedule goes on).
		'''
		if self.diagnose is None or self.busy:
			return
		if not again and self._warned_for == (self.text, self.cursor):
			return
		try:
			found, pending = self.diagnose(self.text, self.cursor)
		except Exception as e:
			_debug('warnings failed: {!r}'.format(e))
			found, pending = [], False
		self.marks = [(item.start, item.end) for item in found if 0 <= item.start < item.end <= len(self.text)]
		self.reason = reason_line(found)
		self._warned_for = (self.text, self.cursor)
		if not pending:
			self._asks = []
		elif not again:
			now = time.monotonic()
			self._asks = [now + delay for delay in WARNING_ASKS]

	def _wait(self):
		'''Seconds until warnings are asked for again, or None (wait for a key).'''
		return max(self._asks[0] - time.monotonic(), 0.0) if self._asks else None

	def _marked_text(self):
		'''The text with the warned spans underlined (in red unless NO_COLOR is set).'''
		on = '\x1b[4m' if os.environ.get('NO_COLOR') else '\x1b[4;31m'
		out = []
		position = 0
		for start, end in sorted(self.marks):
			start = max(start, position)
			if start >= end:
				continue
			out.append(self.text[position:start] + on + self.text[start:end] + '\x1b[0m')
			position = end
		out.append(self.text[position:])
		return ''.join(out)

	def _tab(self):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python

	def draw(self, term, prompt, style):
		'''Draw the prompt's last line, the text and the grey suggestion; leave the cursor at the text's cursor.'''
		width = term.size()[1]
		rows, cursor_row, cursor_column, end_column = self.layout(prompt, width)
		ghost = (style + self.ghost + '\x1b[0m') if (style and self.ghost) else ''
		out = []
		if getattr(self, '_row', 0):
			out.append('\x1b[{}A'.format(self._row))
		out.append('\r' + prompt + self.text + ghost + '\x1b[J')
		end_row = rows - 1
		if end_column == width:
			# the terminal waits to wrap until the next character: wrap now so moves are exact
			out.append('\r\n')
			end_row += 1
		if end_row > cursor_row:
			out.append('\x1b[{}A'.format(end_row - cursor_row))
````

with:

````python

	def draw(self, term, prompt, style):
		'''
		Draw the prompt's last line, the text (warned spans underlined), the grey suggestion and the
		warning's reason on the row below; leave the cursor at the text's cursor.
		'''
		width = term.size()[1]
		rows, cursor_row, cursor_column, end_column = self.layout(prompt, width)
		ghost = (style + self.ghost + '\x1b[0m') if (style and self.ghost) else ''
		reason = fit(_printable(self.reason), width - 1) if self.reason else ''
		out = []
		if getattr(self, '_row', 0):
			out.append('\x1b[{}A'.format(self._row))
		out.append('\r' + prompt + self._marked_text() + ghost)
		end_row = rows - 1
		if end_column == width:
			# the terminal waits to wrap until the next character: wrap now so moves are exact
			out.append('\r\n' + reason)
			end_row += 1
		elif reason:
			out.append('\x1b[K\r\n' + reason)
			end_row += 1
		out.append('\x1b[J')
		if end_row > cursor_row:
			out.append('\x1b[{}A'.format(end_row - cursor_row))
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self._row = 0
		self.refresh()
		self.draw(term, prompt, style)
		while True:
			name, raw = term.read_key()
			self.busy = term.has_input()
			outcome = self.handle(name, raw)
````

with:

````python
		self._row = 0
		self.refresh()
		self.refresh_warnings()
		self.draw(term, prompt, style)
		while True:
			key = term.read_key(self._wait())
			if key is None:
				# the prober may have answered by now
				self._asks.pop(0)
				self.refresh_warnings(again=True)
				self.draw(term, prompt, style)
				continue
			name, raw = key
			self.busy = term.has_input()
			outcome = self.handle(name, raw)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))

	editor = LineEditor(options.text, suggest, complete, pick)
	try:
		with term:
````

with:

````python
		return apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))

	def diagnose(text, cursor):
		return engine.diagnose(Request('bash', text[:cursor], text[cursor:], ''))

	editor = LineEditor(options.text, suggest, complete, pick, diagnose)
	try:
		with term:
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_editor.py tests/test_complete_keys.py -q`

Expected: PASS (`70 passed, 11 skipped in 54.09s`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k editor' tests/shells/run_matrix.sh modern current legacy centos7`

Expected:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
12 passed, 1 skipped, 19 deselected in 34.57s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
12 passed, 1 skipped, 19 deselected in 34.81s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
12 passed, 1 skipped, 19 deselected in 34.64s
=== centos7 (requires bash,blesh)
Python 3.6.8
1 passed, 12 skipped, 19 deselected in 1.13s
````

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `946 passed, 32 skipped in 71.42s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_editor.py tests/test_complete_keys.py tests/vt_grid.py
git commit -F - <<'EOF'
feat: the mssh line editor marks warned words and says why below the line

Warned spans are underlined (red unless NO_COLOR), the first warning and
how many more show on the row under the text, and while the prober works
the editor asks again at 0.3, 1 and 3 seconds.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 11: zsh marks warned words and shows why

**Files:**
- Modify: `tests/complete_shell_harness.py`
- Modify: `tests/test_complete_diagnose.py`
- Modify: `tests/test_complete_keys.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 9: `reason_line`; Task 6: `diag=1` queries
- Produces: `format_response` writes `R <reason line>` after the `W` records; in `ZSH_GLUE`: `_mssh_complete_warn_clear`, `_mssh_complete_warn_cancel`, `_mssh_complete_warn_ask`, `_mssh_complete_warn_redraw`, `_mssh_complete_warn_ready`, `_mssh_complete_warn_answer`, `_mssh_complete_warn_finish`, `_mssh_complete_warn_setup` (called from `_mssh_complete_setup`). tests/complete_shell_harness.py: `make_home` takes the prober's lock (no prober in shell tests).

- [ ] **Step 1: Write the failing tests**

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python

def make_home(tmp_path, history_lines=()):
	'''A private HOME and XDG_RUNTIME_DIR holding the given mssh history. Returns (env, home).'''
	home = tmp_path / 'home'
	runtime = tmp_path / 'runtime'
	home.mkdir()
	runtime.mkdir(mode=0o700)
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in history_lines))
	env = {
````

with:

````python

def make_home(tmp_path, history_lines=()):
	'''
	A private HOME and XDG_RUNTIME_DIR holding the given mssh history. Returns (env, home).

	The prober's lock is taken, so no prober runs (no DNS, no ping): tests that want answers about
	hosts write host-state.tsv themselves.
	'''
	home = tmp_path / 'home'
	runtime = tmp_path / 'runtime'
	home.mkdir()
	runtime.mkdir(mode=0o700)
	(runtime / 'multiSSH3').mkdir(mode=0o700)
	(runtime / 'multiSSH3' / 'probe.lock').write_text('')
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in history_lines))
	env = {
````

In `tests/test_complete_diagnose.py`, replace this text (it occurs exactly once):

````python
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text


````

with:

````python
	assert 'W 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\n' in text
	assert 'D pending\n' in text
	# the reason line every shell shows under the prompt
	assert 'R ⚠ gpu017: unknown host — did you mean gpu17?\n' in text
	assert '\nR ' not in mc.format_response(mc.Response(None), nul=False).decode()


````

In `tests/test_complete_keys.py`, replace this text (it occurs exactly once):

````python


def test_zsh_alt_f_takes_an_escaped_word_whole(tmp_path):
	env, home = make_home(tmp_path, ["17900000{:02d}\t/x/multiSSH3.py\t-su -f='my file.txt'\tnode1\t/tmp".format(number) for number in range(6)])
````

with:

````python


def runtime(env):
	return os.path.join(env['XDG_RUNTIME_DIR'], 'multiSSH3')


def known(env, **validities):
	"""Host states as the prober would write them (no prober runs in these tests: make_home)."""
	mc.write_host_states(runtime(env), {host: mc.HostState(validity, time.time()) for host, validity in validities.items()})


def rendered(session):
	"""The terminal after everything the session printed."""
	from vt_grid import Grid
	grid = Grid(24, 80)
	grid.feed(session.output.decode('utf-8', 'replace'))
	return grid


def screen(session):
	return rendered(session).lines()


def underlined(session, text):
	"""Whether text is on screen with every character underlined."""
	grid = rendered(session)
	for row, line in enumerate(grid.lines()):
		column = line.find(text)
		if column >= 0:
			styles = grid.styles(row)[column:column + len(text)]
			return all('4' in style.split(';') for style in styles)
	return False


@pytest.mark.parametrize('zas', [False, True], ids=['own', 'zsh-autosuggestions'])
def test_zsh_marks_an_unknown_host_and_says_why(home, zas):
	env, home = home
	known(env, gpu017='invalid')
	session = zsh_with(env, home, zas)
	try:
		session.send('mssh gpu017 ')
		output = session.read_until('unknown host'.encode(), 10)
		assert '⚠ gpu017: unknown host' in plain(output)
		# the host is underlined
		assert underlined(session, 'gpu017')
	finally:
		session.close()


def test_zsh_warning_appears_when_the_prober_answers(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu099 ')
		time.sleep(0.2)
		known(env, gpu099='invalid')
		# no key pressed: the glue asks again while the prober works
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode(), 10)
	finally:
		session.close()


def test_zsh_warning_goes_away_when_the_host_is_fixed(home):
	env, home = home
	known(env, gpu017='invalid', gpu17='valid')
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu017 ')
		assert 'unknown host' in session.read_until('unknown host'.encode(), 10)
		session.send('\x7f' * 7 + 'gpu17 ')
		session.read_until(b'gpu17 ', 10)
		time.sleep(1)
		session.read_until(b'@@never@@', 0.5)
		assert not [row for row in screen(session) if 'unknown host' in row]
	finally:
		session.close()


def test_zsh_alt_f_takes_an_escaped_word_whole(tmp_path):
	env, home = make_home(tmp_path, ["17900000{:02d}\t/x/multiSSH3.py\t-su -f='my file.txt'\tnode1\t/tmp".format(number) for number in range(6)])
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_keys.py -q`

Expected: FAIL, e.g. `E AssertionError: assert 'R ⚠ gpu017: unknown host — did you mean gpu17?\n' in 'MSSHC1\nD pending\nW 5\t11\tunknown\tgpu017: unknown host — did you mean gpu17?\nE\n'` (`1 failed, 63 passed, 15 skipped in 54.34s`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k zsh' tests/shells/run_matrix.sh modern current legacy`

Expected: FAIL, e.g. `E AssertionError: assert '⚠ gpu017: unknown host' in 'm\x08mssh gpu017 '`, with:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
4 failed, 7 passed, 25 deselected in 48.41s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
4 failed, 7 passed, 25 deselected in 48.67s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
4 failed, 7 passed, 25 deselected in 47.98s
````

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup, then
	\\traw when bash escaping changed the text), an X line for delegation, then E, and a NUL unless
	nul is False.
	'''
	lines = [PROTOCOL]
````

with:

````python
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup, then
	\\traw when bash escaping changed the text), a G line (grey text), W lines (warnings:
	start\\tend\\tkind\\tmessage) and an R line (the reason line shown under the prompt), an X line
	for delegation, then E, and a NUL unless nul is False.
	'''
	lines = [PROTOCOL]
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	for item in response.diagnostics:
		lines.append('W {}\t{}\t{}\t{}'.format(item.start, item.end, item.kind, _clean(item.message)[:MAX_MESSAGE]))
	if response.delegate is not None:
		index, prefix, words = response.delegate
````

with:

````python
	for item in response.diagnostics:
		lines.append('W {}\t{}\t{}\t{}'.format(item.start, item.end, item.kind, _clean(item.message)[:MAX_MESSAGE]))
	if response.diagnostics:
		# the line shells show under the prompt, the same everywhere
		lines.append('R ' + _clean(reason_line(response.diagnostics)))
	if response.delegate is not None:
		index, prefix, words = response.delegate
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
}

_mssh_complete_setup() {
	# precmd, once, at the first prompt (plugins loaded after the mssh block are there by then):
	# Ctrl-R, and grey text through zsh-autosuggestions when it is loaded, else with own widgets
	add-zsh-hook -d precmd _mssh_complete_setup
	_mssh_complete_take_ctrl_r
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		_mssh_complete_zas_strategy
````

with:

````python
}

_mssh_complete_warn_clear() {
	# drop our marks (others' highlights stay) and the reason line (inside a widget)
	local mark
	for mark in "${_mssh_complete_warn_marks[@]}"; do
		region_highlight=("${(@)region_highlight:#${(b)mark}}")
	done
	_mssh_complete_warn_marks=()
	if [[ -n $_mssh_complete_warn_reason ]]; then
		_mssh_complete_warn_reason=
		zle -M ''
	fi
}

_mssh_complete_warn_cancel() {
	# forget the pending query for warnings
	[[ -n $_mssh_complete_warn_fd ]] || return 0
	zle -F $_mssh_complete_warn_fd 2>/dev/null
	exec {_mssh_complete_warn_fd}<&- 2>/dev/null
	_mssh_complete_warn_fd=
}

_mssh_complete_warn_ask() {
	# ask for warnings about the line, after $1 hundredths of a second
	_mssh_complete_warn_asked=$BUFFER$'\0'$CURSOR
	exec {_mssh_complete_warn_fd}< <(
		(( $1 > 0 )) && zselect -t $1
		_mssh_complete_request 'diag=1 nul=0' "$LBUFFER" "$RBUFFER" | _mssh_complete_engine query 2>/dev/null)
	zle -F $_mssh_complete_warn_fd _mssh_complete_warn_ready
}

_mssh_complete_warn_redraw() {
	# line-pre-redraw hook: ask for warnings when a finished word changed, keep the reason line shown
	emulate -L zsh
	setopt extended_glob
	# the line without the word at the cursor, which is still being typed
	local key=${LBUFFER%%[^[:space:]]#}$'\0'${RBUFFER##[^[:space:]]#}
	if [[ $key == "$_mssh_complete_warn_key" ]]; then
		[[ -n $_mssh_complete_warn_reason ]] && zle -M -- "$_mssh_complete_warn_reason"
		return 0
	fi
	_mssh_complete_warn_key=$key
	_mssh_complete_warn_cancel
	if ! _mssh_complete_is_mssh "$BUFFER"; then
		_mssh_complete_warn_clear
		return 0
	fi
	# while the prober works, ask again 0.3, 1 and 3 seconds after this answer
	_mssh_complete_warn_delays=(30 70 200)
	_mssh_complete_warn_ask 0
}

_mssh_complete_warn_ready() {
	# zle -F handler: the engine answered the query for warnings
	emulate -L zsh
	local fd=$1 resp= chunk line reason= pending=0
	local -a marks fields
	while sysread -i $fd chunk 2>/dev/null; do
		resp+=$chunk
	done
	zle -F $fd
	exec {fd}<&-
	_mssh_complete_warn_fd=
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		case $line in
			('W '*)
				fields=("${(@ps:\t:)${line#W }}")
				marks+=("${fields[1]} ${fields[2]}") ;;
			('R '*) reason=${line#R } ;;
			('D '*) [[ " ${line#D } " == *' pending '* ]] && pending=1 ;;
		esac
	done
	zle _mssh_complete_warn_answer -- "$pending" "$reason" "${marks[@]}"
	return 0
}

_mssh_complete_warn_answer() {
	# widget: show the warnings if the line is still the one asked about
	emulate -L zsh
	[[ $BUFFER$'\0'$CURSOR == "$_mssh_complete_warn_asked" ]] || return 0
	local pending=$1 reason=$2 mark style=underline,fg=red
	shift 2
	[[ -n ${NO_COLOR-} ]] && style=underline
	_mssh_complete_warn_clear
	for mark in "$@"; do
		_mssh_complete_warn_marks+=("$mark $style")
	done
	region_highlight+=("${_mssh_complete_warn_marks[@]}")
	if [[ -n $reason ]]; then
		_mssh_complete_warn_reason=$reason
		zle -M -- "$reason"
	fi
	if (( pending && $#_mssh_complete_warn_delays )); then
		_mssh_complete_warn_ask $_mssh_complete_warn_delays[1]
		shift _mssh_complete_warn_delays
	fi
	zle -R
}

_mssh_complete_warn_finish() {
	# line-finish hook: no warnings left on a line that was accepted
	emulate -L zsh
	_mssh_complete_warn_cancel
	_mssh_complete_warn_clear
	_mssh_complete_warn_key=
}

_mssh_complete_warn_setup() {
	# warnings under the line (zsh 5.3 and later), with grey text from either source
	emulate -L zsh
	autoload -Uz is-at-least add-zle-hook-widget
	is-at-least 5.3 || return 0
	zmodload zsh/zleparameter zsh/system zsh/zselect 2>/dev/null || return 0
	typeset -g _mssh_complete_warn_fd= _mssh_complete_warn_asked= _mssh_complete_warn_key= _mssh_complete_warn_reason=
	typeset -ga _mssh_complete_warn_marks _mssh_complete_warn_delays
	zle -N _mssh_complete_warn_answer
	zle -N _mssh_complete_warn_redraw
	zle -N _mssh_complete_warn_finish
	add-zle-hook-widget line-pre-redraw _mssh_complete_warn_redraw
	add-zle-hook-widget line-finish _mssh_complete_warn_finish
}

_mssh_complete_setup() {
	# precmd, once, at the first prompt (plugins loaded after the mssh block are there by then):
	# Ctrl-R, warnings, and grey text through zsh-autosuggestions when it is loaded, else with own widgets
	add-zsh-hook -d precmd _mssh_complete_setup
	_mssh_complete_take_ctrl_r
	_mssh_complete_warn_setup
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		_mssh_complete_zas_strategy
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_diagnose.py tests/test_complete_keys.py -q`

Expected: PASS (`64 passed, 15 skipped in 54.33s`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k zsh' tests/shells/run_matrix.sh modern current legacy`

Expected:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
11 passed, 25 deselected in 20.15s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
11 passed, 25 deselected in 20.46s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
11 passed, 25 deselected in 20.04s
````

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `946 passed, 36 skipped in 71.73s (0:01:11)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/complete_shell_harness.py tests/test_complete_diagnose.py tests/test_complete_keys.py
git commit -F - <<'EOF'
feat: zsh marks warned words and shows why under the line

Marks through region_highlight (others' highlights stay), the reason line
through zle -M, asked for when a finished word changes, again at 0.3, 1
and 3 seconds while the prober works; with own widgets and with
zsh-autosuggestions. Responses carry the reason line as an R record.
Shell tests hold the prober's lock: no DNS or ping in tests.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 12: ble.sh marks warned words and shows why

**Files:**
- Modify: `tests/complete_shell_harness.py`
- Modify: `tests/test_complete_keys.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 11: the `R` record; SP2: the ble.sh branch of `BASH_GLUE`
- Produces: in the ble.sh branch of `BASH_GLUE`: `_mssh_complete_ble_warn_watch`, `_mssh_complete_ble_warn_ask`, `_mssh_complete_ble_warn_info`, `_mssh_complete_ble_warn_reset`, `_mssh_complete_ble_warnings` (the `mssh` highlight layer, face `mssh_warning`). tests/complete_shell_harness.py: every session's terminal is 24x80.

- [ ] **Step 1: Write the failing tests**

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
'''Drive real shells for the autocomplete tests: a pseudo-terminal session, or a direct call.'''
import os
import pty
````

with:

````python
'''Drive real shells for the autocomplete tests: a pseudo-terminal session, or a direct call.'''
import fcntl
import os
import pty
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
````

with:

````python
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
		self.pid, self.fd = pty.fork()
		if self.pid == 0:
			if cwd:
				os.chdir(str(cwd))
````

with:

````python
		self.pid, self.fd = pty.fork()
		if self.pid == 0:
			# a real terminal has a size (ble.sh sizes its panels from it)
			fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
			if cwd:
				os.chdir(str(cwd))
````

In `tests/test_complete_keys.py`, replace this text (it occurs exactly once):

````python


def test_blesh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
````

with:

````python


def test_blesh_marks_an_unknown_host_and_says_why(home):
	env, home = home
	known(env, gpu017='invalid')
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 15))
		session.read_until(b'@@never@@', 1)
		assert underlined(session, 'gpu017')
	finally:
		session.close()


def test_blesh_warning_appears_when_the_prober_answers(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu099 ')
		time.sleep(0.2)
		known(env, gpu099='invalid')
		# no key pressed: the glue asks again while the prober works
		assert 'gpu099: unknown host' in session.read_until('unknown host'.encode(), 15)
	finally:
		session.close()


def test_blesh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_keys.py -q`

Expected here: `21 passed, 17 skipped in 54.43s` (this machine has no ble.sh or fish: those tests skip and fail in the matrix below)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k blesh' tests/shells/run_matrix.sh modern current legacy centos7`

Expected: FAIL, e.g. `E AssertionError: assert '⚠ gpu017: unknown host' in '@@READY@@ mssh gpu017 '`, with:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
2 failed, 2 passed, 34 deselected in 44.13s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
2 failed, 2 passed, 34 deselected in 44.34s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
2 failed, 2 passed, 34 deselected in 44.56s
=== centos7 (requires bash,blesh)
Python 3.6.8
2 failed, 2 passed, 34 deselected in 44.79s
````

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	}
	blehook/eval-after-load complete _mssh_complete_ble_source
elif [[ $- == *i* ]]; then
	# readline counts READLINE_POINT in bytes before bash 5
````

with:

````python
	}
	blehook/eval-after-load complete _mssh_complete_ble_source

	_mssh_complete_warn_ranges=()
	_mssh_complete_warn_key=
	_mssh_complete_warn_delays=()

	_mssh_complete_ble_warn_watch() {
		# the finished words of the line ($1) changed: ask for warnings when ble.sh is idle
		local before=${1::_ble_edit_ind} after=${1:_ble_edit_ind} key
		# the line without the word at the cursor, which is still being typed
		key=${before%"${before##*[[:space:]]}"}$'\1'${after#"${after%%[[:space:]]*}"}
		[[ $key == "$_mssh_complete_warn_key" ]] && return 0
		_mssh_complete_warn_key=$key
		# while the prober works, ask again 0.3, 1 and 3 seconds after this answer
		_mssh_complete_warn_delays=(300 700 2000)
		ble/util/idle.cancel _mssh_complete_ble_warn_ask
		ble/util/idle.push _mssh_complete_ble_warn_ask
	}

	_mssh_complete_ble_warn_ask() {
		# idle task: ask the engine about the line, mark the words and show the reason line
		local request=$_ble_base_run/$$.mssh-complete.warn.request answer=$_ble_base_run/$$.mssh-complete.warn.answer
		local line reason= pending=0 status start
		local -a ranges=() starts=()
		if _mssh_complete_is_mssh "$_ble_edit_str"; then
			_mssh_complete_request 'diag=1 nul=0' "${_ble_edit_str::_ble_edit_ind}" "${_ble_edit_str:_ble_edit_ind}" > "$request" 2>/dev/null || return 0
			ble/util/conditional-sync '_mssh_complete_engine query < "$request" > "$answer" 2>/dev/null' '! ble/decode/has-input' 20 "timeout=${MSSH_COMPLETE_GHOST_TIMEOUT:-300}"
			status=$?
			if ((status == 148)); then
				# typing interrupted: ask again at the next redraw
				_mssh_complete_warn_key=
				return 0
			fi
			((status == 0)) || return 0
			while IFS= read -r line; do
				case $line in
					'W '*)
						_mssh_complete_split "${line:2}"
						# one mark per start, in order
						starts[_mssh_complete_fields[0]]=${_mssh_complete_fields[1]} ;;
					'R '*) reason=${line:2} ;;
					'D '*) [[ " ${line:2} " == *' pending '* ]] && pending=1 ;;
				esac
			done < "$answer"
			for start in "${!starts[@]}"; do
				ranges+=("$start" "${starts[start]}")
			done
		fi
		_mssh_complete_warn_ranges=(${ranges[@]+"${ranges[@]}"})
		ble/textarea#invalidate
		_mssh_complete_ble_warn_info "$reason"
		if ((pending && ${#_mssh_complete_warn_delays[@]})); then
			ble/util/idle.push --sleep "${_mssh_complete_warn_delays[0]}" _mssh_complete_ble_warn_ask
			_mssh_complete_warn_delays=("${_mssh_complete_warn_delays[@]:1}")
		fi
	}

	_mssh_complete_ble_warn_info() {
		# the reason line under the prompt, kept as ble.sh's default info and drawn now (as
		# ble/edit/info/immediate-show does), the cursor left where it was
		local ret pos
		ble/edit/info/set-default text "$1"
		[[ $_ble_edit_info_scene == default ]] && ble/edit/info/.rendering-enabled || return 0
		ble/canvas/panel/save-position
		pos=$ret
		ble/edit/info#panel::render "$_ble_edit_info_panel"
		ble/canvas/panel/load-position "$pos"
		ble/util/buffer.flush
	}

	_mssh_complete_ble_warn_reset() {
		# a new prompt: no warnings left from the last line
		_mssh_complete_warn_ranges=()
		_mssh_complete_warn_key=
		ble/util/idle.cancel _mssh_complete_ble_warn_ask
		ble/edit/info/set-default text ''
	}

	_mssh_complete_ble_warnings() {
		# warnings for mssh lines: an mssh highlight layer marks the words, ble.sh's info line says why
		declare -F ble/highlight/layer:{selection}/declare ble/util/idle.push ble/util/idle.cancel \
			ble/edit/info/set-default ble/edit/info/.rendering-enabled ble/edit/info#panel::render \
			ble/canvas/panel/save-position ble/canvas/panel/load-position ble/util/buffer.flush \
			ble/array#insert-before ble/textarea#invalidate >/dev/null 2>&1 || return 0
		if [[ -n ${NO_COLOR-} ]]; then
			ble/color/defface mssh_warning underline
		else
			ble/color/defface mssh_warning underline,fg=red
		fi
		ble/highlight/layer:{selection}/declare mssh
		function ble/highlight/layer:mssh/update {
			_mssh_complete_ble_warn_watch "$1"
			local -a sel=(${_mssh_complete_warn_ranges[@]+"${_mssh_complete_warn_ranges[@]}"}) gflags=()
			local ret i
			ble/color/face2g mssh_warning
			for ((i = 0; i < ${#sel[@]} / 2; i++)); do
				gflags[i]=$ret
			done
			ble/highlight/layer:{selection}/update mssh "$@"
		}
		function ble/highlight/layer:mssh/getg {
			ble/highlight/layer:{selection}/getg mssh "$@"
		}
		[[ " ${_ble_highlight_layer_list[*]} " == *' mssh '* ]] || ble/array#insert-before _ble_highlight_layer_list region mssh
		blehook PRECMD+=_mssh_complete_ble_warn_reset
	}
	_mssh_complete_ble_warnings
elif [[ $- == *i* ]]; then
	# readline counts READLINE_POINT in bytes before bash 5
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_keys.py -q`

Expected: PASS (`21 passed, 17 skipped in 54.55s`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k blesh' tests/shells/run_matrix.sh modern current legacy centos7`

Expected:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
4 passed, 34 deselected in 15.57s
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
4 passed, 34 deselected in 15.78s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
4 passed, 34 deselected in 16.03s
=== centos7 (requires bash,blesh)
Python 3.6.8
4 passed, 34 deselected in 16.22s
````

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `946 passed, 38 skipped in 72.07s (0:01:12)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/complete_shell_harness.py tests/test_complete_keys.py
git commit -F - <<'EOF'
feat: ble.sh marks warned words and shows why in its info line

An mssh highlight layer (ble.sh's selection layer) underlines the words;
the reason line is ble.sh's default info, drawn at once; asked for in an
idle task when a finished word changes, again while the prober works.
Test terminals have a size, as real ones do (ble.sh sizes its panels).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 13: fish prints why after a space (fish 4)

**Files:**
- Modify: `tests/test_complete_keys.py`
- Modify: `mssh_complete.py`

**Interfaces:**
- Consumes: Task 11: the `R` record; SP2: `FISH_KEYS_GLUE`
- Produces: in `FISH_KEYS_GLUE`: `__mssh_complete_echo`, `__mssh_complete_check`, `__mssh_complete_take_space` (fish 4 and later), `__mssh_complete_new_line`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_complete_keys.py`, replace this text (it occurs exactly once):

````python
# ---------------------------------------------------------------- fish

def test_fish_ctrl_r_opens_the_picker_and_keeps_the_previous_binding(home):
	env, home = home
````

with:

````python
# ---------------------------------------------------------------- fish

def fish_major():
	output = subprocess.run([require_shell('fish'), '--version'], stdout=subprocess.PIPE, universal_newlines=True).stdout
	return int(re.search(r'(\d+)\.', output).group(1))


def test_fish_says_why_a_host_is_unknown_once(home):
	if fish_major() < 4:
		pytest.skip('fish 3 keeps its space key (self-insert does nothing next to a function): warnings only in the picker')
	env, home = home
	known(env, gpu017='invalid')
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE))
	try:
		session.send('mssh gpu017 ')
		assert '⚠ gpu017: unknown host' in plain(session.read_until('unknown host'.encode(), 10))
		# the space was typed, and the same warning is not printed again at the next one
		assert printed(session, 'uptime ') == 'mssh gpu017 uptime '
		assert plain(session.output.decode('utf-8', 'replace')).count('gpu017: unknown host') == 1
	finally:
		session.close()


def test_fish_space_still_expands_abbreviations(home):
	env, home = home
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre="abbr -a gg 'git grep'")
	try:
		assert printed(session, 'gg ') == 'git grep '
	finally:
		session.close()


def test_fish_ctrl_r_opens_the_picker_and_keeps_the_previous_binding(home):
	env, home = home
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_keys.py -q`

Expected here: `21 passed, 19 skipped in 54.62s` (this machine has no ble.sh or fish: those tests skip and fail in the matrix below)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k fish' tests/shells/run_matrix.sh modern legacy`

Expected: FAIL, e.g. `E AssertionError: assert '⚠ gpu017: unknown host' in 'mssh gpu017 mssh gpu017 '`, with:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
1 failed, 2 passed, 37 deselected in 12.60s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
2 passed, 1 skipped, 37 deselected in 2.59s
````

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
'''

FISH_KEYS_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish keys: Ctrl-R picker for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it defines functions; Ctrl-R is taken at the first prompt.
switch "$FISH_VERSION"
	case '1.*' '2.*'
````

with:

````python
'''

FISH_KEYS_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish keys: Ctrl-R picker and warnings for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it defines functions; Ctrl-R and space are taken at the first prompt.
switch "$FISH_VERSION"
	case '1.*' '2.*'
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
					bind -M $mode \cr "__mssh_complete_ctrl_r $mode"
				end
			end
		end
````

with:

````python
					bind -M $mode \cr "__mssh_complete_ctrl_r $mode"
				end
			end
			function __mssh_complete_echo
				# print $argv's output under the command line, then redraw the prompt (fish's __fish_echo, which fish 3.3 lacks)
				set -l line (commandline --line)
				string >&2 repeat -N \n --count=(math (commandline | count) - $line + 1)
				$argv >&2
				string >&2 repeat -N \n --count=(math (count (fish_prompt)) - 1)
				string >&2 repeat -N \n --count=(math $line - 1)
				commandline -f repaint
			end
			function __mssh_complete_check
				# after a space: the first warning about an mssh line, printed under it when it changes
				set -l full (string join \n -- (commandline))
				set -l reason
				if __mssh_complete_is_mssh "$full"
					set -l before (string join \n -- (commandline -c))
					set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
					set -l keep 1000
					set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
					set -l timeout_cmd
					if command -sq timeout
						set -l limit 0.3
						set -q MSSH_COMPLETE_TIMEOUT; and set limit $MSSH_COMPLETE_TIMEOUT
						set timeout_cmd timeout $limit
					end
					set -l lines (begin
						command printf '%s\0' MSSHC1 fish $FISH_VERSION "diag=1 nul=0 term=$TERM" "$before" "$after" ''
						history -n $keep 2>/dev/null
					end | $timeout_cmd @ENGINE@ query 2>/dev/null)
					if test (count $lines) -ge 2; and test "$lines[1]" = MSSHC1; and test "$lines[-1]" = E
						for line in $lines
							string match -q 'R *' -- $line; and set reason (string sub -s 3 -- $line)
						end
					end
				end
				test "$reason" = "$__mssh_complete_reason"; and return
				set -g __mssh_complete_reason $reason
				test -n "$reason"; and __mssh_complete_echo printf '%s\n' $reason
			end
			function __mssh_complete_take_space --on-event fish_prompt
				# at the first prompt: space does what it did, then checks the line. Not on fish 3, which
				# inserts nothing for self-insert in a binding that also runs a function
				functions -e __mssh_complete_take_space
				string match -qr '^3\.' -- $FISH_VERSION; and return
				for mode in default insert
					set -l line (bind -M $mode ' ' 2>/dev/null)
					test (count $line) -ge 1; or continue
					string match -q '*__mssh_complete_check*' -- "$line[-1]"; and continue
					eval "set -g __mssh_complete_words -- $line[-1]"
					set -l words $__mssh_complete_words[2..-1]
					set -e __mssh_complete_words
					while set -q words[1]; and string match -q -- '-*' $words[1]
						contains -- $words[1] -M --mode -m --sets-mode; and set -e words[1]
						set -e words[1]
					end
					set -e words[1]
					set -q words[1]; or continue
					bind -M $mode ' ' $words __mssh_complete_check
				end
			end
			function __mssh_complete_new_line --on-event fish_prompt
				# a new prompt: the next warning is printed even if it is the last line's
				set -e __mssh_complete_reason
			end
		end
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_keys.py -q`

Expected: PASS (`21 passed, 19 skipped in 54.72s`)

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k fish' tests/shells/run_matrix.sh modern legacy`

Expected:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
3 passed, 37 deselected in 3.24s
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
2 passed, 1 skipped, 37 deselected in 2.59s
````

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `946 passed, 40 skipped in 72.12s (0:01:12)`

- [ ] **Step 6: Commit**

````bash
git add mssh_complete.py tests/test_complete_keys.py
git commit -F - <<'EOF'
feat: fish prints why under the command line after a space (fish 4)

A function bound to space after fish's own binding prints the first
warning when it changes. fish 3 keeps its space key: self-insert inserts
nothing next to a function there; its warnings show in the picker.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````

### Task 14: Replay over history, docs, multiSSH3 6.30

**Files:**
- Modify: `tests/bench_complete.py`
- Modify: `tests/test_complete_diagnose.py`
- Modify: `tests/test_complete_eval.py` (append)
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp3-design.md` (append)
- Modify: `mssh_complete.py`
- Modify: `multiSSH3.py`

**Interfaces:**
- Consumes: everything above
- Produces: `Engine.diagnose(..., states=None)`; `_ipv4_range(name)`; `diagnostics_replay(lines, spec, validity, hosts=None, now=None)`; `format_diagnostics_report(report)`; `mssh-complete eval --diagnostics`; multiSSH3 6.30, mssh_complete 0.3; the README section; the spec's deviation table; warning timings in `tests/bench_complete.py`.

- [ ] **Step 1: Write the failing tests**

In `tests/bench_complete.py`, replace this text (it occurs exactly once):

````python
			timings.sort()
			print('suggest {!r:30} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		interactive(engine, env)
	finally:
````

with:

````python
			timings.sort()
			print('suggest {!r:30} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		# warnings: the query alone (the prober's lock is held, so no prober competes for the CPU)
		(runtime / 'multiSSH3' / 'probe.lock').write_text('')
		for line in ('mssh node00042 uptime ', 'mssh node[00001-00100] uptime ', 'mssh -u root node00042,nodeX uptime '):
			request = 'MSSHC1\0bash\x005.2\0diag=1 nul=0\0{}\0\0\0'.format(line).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('warnings {!r:34} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		interactive(engine, env)
	finally:
````

In `tests/test_complete_diagnose.py`, replace this text (it occurs exactly once):

````python


def test_lines_that_do_not_run_mssh_get_nothing(engine):
	seed(engine, gpu017='invalid')
````

with:

````python


def test_ipv4_ranges_hold_only_addresses(engine):
	# mssh's IPv4 range syntax: ranges, x, * or ? in an octet (found replaying real history)
	assert warnings(engine, 'mssh 127.0.0.1-20,10.0.[1-2].x,10.1.1.* uptime') == ([], False)


def test_lines_that_do_not_run_mssh_get_nothing(engine):
	seed(engine, gpu017='invalid')
````

Append to the end of `tests/test_complete_eval.py` (the text starts with the line breaks that separate it from what is there):

````python


# the hosts synthetic history names: the rest does not exist
SYNTHETIC_HOSTS = ['gpu{:02d}'.format(number) for number in range(1, 17)] + ['storage1', 'storage2', 'storage3', 'storage4', 'login1', 'login2', 'us_east']


def synthetic_table(tmp_path):
	path = str(tmp_path / 'index.nsv')
	names = sorted(SYNTHETIC_HOSTS)
	mc.write_nsv(path, {}, [('host_names', [names]), ('host_meta', [[str(mc.SRC_HISTORY), ''] for _ in names])])
	return mc.HostTable(mc.NsvIndex.load(path))


def validity(name):
	return 'valid' if name in SYNTHETIC_HOSTS else 'invalid'


def test_clean_synthetic_history_gets_no_warning(tmp_path):
	report = mc.diagnostics_replay(mc.synthetic_history(entries=300), SPEC, validity, synthetic_table(tmp_path))
	assert report['lines'] == 300 and report['warned'] == {kind: 0 for kind in mc.DIAGNOSTIC_KINDS}


# typos and padding mistakes an operator makes, and the host meant
MISTAKES = {
	'gpu[01-16]': 'gpu[1-16]', 'storage[1-4]': 'storgae[1-4]', 'login[1-2]': 'login[1-3]', 'us_east': 'us_eats',
}


def with_mistake(line):
	import shlex
	fields = line.split('\t')
	hosts = shlex.split(fields[3])[0]
	mistaken = MISTAKES.get(hosts) or 'gpu0' + hosts[3:]
	return '\t'.join(fields[:3] + [shlex.quote(mistaken)] + fields[4:])


def test_mistakes_in_synthetic_history_are_caught(tmp_path):
	lines = [with_mistake(line) for line in mc.synthetic_history(entries=300)]
	report = mc.diagnostics_replay(lines, SPEC, validity, synthetic_table(tmp_path))
	# every line holds one mistake, and every one is caught
	assert report['warned']['unknown'] + report['warned']['range'] == 300
	# a single host is meant to be the one it is a typo of
	assert {name: entry['meant'] for name, entry in report['unknown'].items()} == {
		name: ('us_east' if name == 'us_eats' else 'gpu' + name[4:]) for name in report['unknown']}


def test_the_diagnostics_report(tmp_path):
	lines = [with_mistake(line) for line in mc.synthetic_history(entries=100)]
	text = mc.format_diagnostics_report(mc.diagnostics_replay(lines, SPEC, validity, synthetic_table(tmp_path)))
	assert text.startswith('warnings over 100 history lines (DNS, no ping)\n')
	assert '  hosts mssh would reject:\n' in text and 'did you mean' in text
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_eval.py tests/test_complete_diagnose.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'diagnostics_replay'` (`4 failed, 52 passed in 0.92s`)

- [ ] **Step 3: Implement**

In `README.md`, replace this text (it occurs exactly once):

````markdown
Ctrl-R on an mssh line opens a menu below the prompt with the candidates for the word under the cursor (hosts, commands for those hosts, option values), how often and how long ago you used them; Tab switches to whole past invocations. Type to filter, ↑/↓ to move, Enter to insert, Esc to leave the line as it was. On any other line Ctrl-R does what it did before (readline's search, fzf, atuin, ...).

| Environment variable | Effect |
| --- | --- |
````

with:

````markdown
Ctrl-R on an mssh line opens a menu below the prompt with the candidates for the word under the cursor (hosts, commands for those hosts, option values), how often and how long ago you used them; Tab switches to whole past invocations. Type to filter, ↑/↓ to move, Enter to insert, Esc to leave the line as it was. On any other line Ctrl-R does what it did before (readline's search, fzf, atuin, ...).

### Warnings before Enter

While you type an mssh line, words already typed that mssh would trip over are marked, and one line under the prompt says why. Nothing is ever blocked: Enter runs what you typed.

- **Unknown host:** a name mssh would reject (no IP, alias or hosts-file entry, not in DNS, not mapped by your ssh config), with the host you probably meant: `gpu017: unknown host — did you mean gpu17?`
- **Range surprises:** a range or alias with members mssh would reject: `node[1-16]: 9 of 16 hosts unknown (node1, node2, node3, …) — did you mean node[01-16]?`
- **Unreachable host:** one that failed in your recent mssh runs (`will be skipped` with `-su`), or that answered ping recently and stopped.
- **Conflicting options:** two options mssh refuses together, an option given twice, or one that does nothing on this line (`-iu does nothing: only used with --ipmi`).

zsh, bash with ble.sh and the plain-bash line editor mark the words and show the reason; fish 4 prints the reason under the line after a space; fish 3 and plain bash without the editor list the warnings at the top of the Ctrl-R menu.

Hosts are checked in the background by `mssh-complete probe`: DNS, `ssh -G` (which only reads your ssh config) and ping. It never connects or logs in to a host, so it cannot trip fail2ban; it runs at low priority, as many checks at once as mssh's own `max_connections` allows. What it learns lives in mssh's runtime directory (`$XDG_RUNTIME_DIR/multiSSH3`, else `/run/user/<uid>/multiSSH3`, `/dev/shm/multiSSH3-<uid>` or the temp dir) and is gone after a reboot. `mssh-complete eval --diagnostics` replays your history and lists the hosts mssh would reject.

| Environment variable | Effect |
| --- | --- |
````

In `README.md`, replace this text (it occurs exactly once):

````markdown
| `MSSH_COMPLETE_SHELL_HISTORY` | Lines of shell history sent along (default 1000) |
| `MSSH_COMPLETE_EDITOR` | `1` turns on the plain-bash mssh line editor (`install bash editor` sets it) |
| `MSSH_COMPLETE_DEBUG` | `1` logs errors to `complete.log` in the cache directory |

````

with:

````markdown
| `MSSH_COMPLETE_SHELL_HISTORY` | Lines of shell history sent along (default 1000) |
| `MSSH_COMPLETE_EDITOR` | `1` turns on the plain-bash mssh line editor (`install bash editor` sets it) |
| `MSSH_COMPLETE_PING_TTL` | Seconds a host that answered ping is expected to keep answering (default: mssh's unreachable host expiry, 600) |
| `MSSH_COMPLETE_DEBUG` | `1` logs errors to `complete.log` in the cache directory |

````

Append to the end of `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp3-design.md` (the text starts with the line breaks that separate it from what is there):

````markdown

## Deviations found while implementing

Implementing and testing SP3 (unit tests, real bash, zsh, fish and ble.sh in the Docker matrix, a replay of real history) changed these details of the design above.

| Area | The design said | Implemented | Why |
|---|---|---|---|
| Reason line | Each shell composes "first warning (+N more)" from the `W` records | The response also carries the composed line as an `R` record | zsh, ble.sh and fish show the same text without three copies of the logic; the mark is `⚠` or `!` by the engine's locale, which is the shell's |
| zsh queries | `diag=1` in the grey-text query when one is sent | zsh asks with its own `diag=1` query, only when the finished words of the line change | warnings then work the same with zsh's own widgets and with zsh-autosuggestions, and typing inside a word costs nothing |
| fish | Reason printed after space on every fish 3.3+ | fish 4 only; fish 3 keeps its space key and shows warnings in the picker | fish 3 inserts nothing for `self-insert` in a binding that also runs a function, so taking space broke typing |
| ble.sh reason line | `ble/edit/info/set-default` | set as the default and drawn at once, as `ble/edit/info/immediate-show` draws | a deferred default only appears at ble.sh's next panel render |
| Flag defaults | (not specified) | the index records what mssh's flags set and their defaults (config rows `flag_sets`, `flag_defaults`) and the `OPTION_NO_EFFECT` entries (section `no_effect`) | skipping (`-su`) and "on by default" (`--ipmi`) follow the mssh config without importing mssh on the keystroke path |
| Ping expiry | `MSSH_COMPLETE_PING_TTL`, else mssh's default expiry | also `-uhe` on the line | it is mssh's unreachable host expiry for that run |
| IPv4 ranges | (not specified) | parts in mssh's IPv4 range syntax (`127.0.0.1-20`, `10.0.[1-2].x`) get no warning | they hold only IP addresses; replaying real history flagged `127.0.0.1-20` before this |
| Probe queue | Queries append hosts | hosts already waiting are left out | a query for a long range repeats on every keystroke |
| Ranges past the member limit | Checked up to the limit | the first `RANGE_MEMBERS_LIMIT` members are checked, the total is counted without expanding | `expand_ranges` gives up on a range over its limit |
| Shell tests | (not specified) | the harness holds the prober's lock (tests write host states themselves) and gives the terminal a size | no DNS or ping from tests; ble.sh sizes its info panel from the terminal |
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
from bisect import bisect_left

version = '0.2'
__version__ = version
PROTOCOL = 'MSSHC1'
````

with:

````python
from bisect import bisect_left

version = '0.3'
__version__ = version
PROTOCOL = 'MSSHC1'
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return ':' in name

def _range_count(text):
	'''How many names expand_ranges makes of text, without a limit; None when it cannot expand it.'''
````

with:

````python
	return ':' in name

def _ipv4_range(name):
	'''
	Whether name is in mssh's IPv4 range syntax (an a-b range, x, * or ? in an octet, an octet in
	[ ]) without being one address: its members are all IP addresses.
	'''
	parts = name.split('.')
	if len(parts) != 4:
		return False
	plain = True
	for part in parts:
		if part.startswith('[') and part.endswith(']'):
			part = part[1:-1]
			plain = False
		low, sep, high = part.partition('-')
		for end in ((low, high) if sep else (low,)):
			if end in ('x', '*', '?'):
				plain = False
			elif not (_is_digits(end) and int(end) <= 255):
				return False
		plain = plain and not sep
	return not plain

def _range_count(text):
	'''How many names expand_ranges makes of text, without a limit; None when it cannot expand it.'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return read_host_states(self.directory) if self.directory else {}

	def diagnose(self, request, probe=True, now=None):
		'''
		Warnings for the words of the request's line (before + after) already typed, most
````

with:

````python
		return read_host_states(self.directory) if self.directory else {}

	def diagnose(self, request, probe=True, now=None, states=None):
		'''
		Warnings for the words of the request's line (before + after) already typed, most
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		Args:
			probe (bool): queue those hosts and start the prober (needs self.directory)

		Returns:
````

with:

````python
		Args:
			probe (bool): queue those hosts and start the prober (needs self.directory)
			states: what is known about hosts (anything with get(host) -> HostState or None), instead
				of what the prober wrote (the replay passes its own)

		Returns:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		words = tokens[start + 1:]
		roles = assign_roles(words, self.spec)
		states = self.host_states()
		unavailable = read_unavailable(self.directory) if self.directory else frozenset()
		reach = (unavailable,) + self._line_settings(words, roles)
````

with:

````python
		words = tokens[start + 1:]
		roles = assign_roles(words, self.spec)
		states = self.host_states() if states is None else states
		unavailable = read_unavailable(self.directory) if self.directory else frozenset()
		reach = (unavailable,) + self._line_settings(words, roles)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		found = []
		for name, (start, end) in _host_parts(token):
			if not name:
				continue
			members = self._host_members(name)
````

with:

````python
		found = []
		for name, (start, end) in _host_parts(token):
			if not name or _ipv4_range(name):
				# IP addresses only: nothing to say about them
				continue
			members = self._host_members(name)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			return candidate != name and not (state is not None and state.fresh_validity(now) == 'invalid')
		stripped = _strip_zeros(name)
		same = [candidate for candidate in self.hosts.names if _strip_zeros(candidate) == stripped and possible(candidate)]
		if same:
			return same[0] if len(same) == 1 else None
````

with:

````python
			return candidate != name and not (state is not None and state.fresh_validity(now) == 'invalid')
		stripped = _strip_zeros(name)
		same = [candidate for candidate in self.hosts.names if candidate != name and _strip_zeros(candidate) == stripped and possible(candidate)]
		if same:
			return same[0] if len(same) == 1 else None
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			return None
		close = [candidate for candidate in self.hosts.names
			if abs(len(candidate) - len(name)) <= 1 and possible(candidate) and _one_edit(name, candidate)]
		return close[0] if len(close) == 1 else None

````

with:

````python
			return None
		close = [candidate for candidate in self.hosts.names
			if abs(len(candidate) - len(name)) <= 1 and _one_edit(name, candidate) and possible(candidate)]
		return close[0] if len(close) == 1 else None

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return '\n'.join(lines)

def synthetic_history(seed=1, entries=1500, start=1700000000):
	'''
````

with:

````python
	return '\n'.join(lines)

def diagnostics_replay(lines, spec, validity, hosts=None, now=None):
	'''
	Replay history lines through the warnings. validity(name) -> 'valid', 'invalid' or 'unsure'
	stands in for the prober (asked once per host); there is no ping and no unavailable list.

	Returns:
		dict: lines (replayed), warned (kind -> lines with such a warning), unknown (host -> {'lines':
			lines naming it, 'meant': the host suggested or None}), checked (verdict -> hosts)
	'''
	now = time.time() if now is None else now
	engine = Engine(spec, [], hosts)
	verdicts = {}

	class Answers(object):
		'''host -> HostState, as the prober would have found it: validity(name), could not ping.'''
		def get(self, name, default=None):
			if name not in verdicts:
				verdicts[name] = validity(name)
			return HostState(verdicts[name], now, 'none', now)

	answers = Answers()
	report = {'lines': 0, 'warned': {kind: 0 for kind in DIAGNOSTIC_KINDS}, 'unknown': {}, 'checked': {}}
	for line in lines:
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		text = ' '.join(['mssh'] + [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']) + ' '
		found, _ = engine.diagnose(Request('bash', text, '', ''), probe=False, now=now, states=answers)
		report['lines'] += 1
		for kind in set(item.kind for item in found):
			report['warned'][kind] += 1
		for item in found:
			if item.kind == 'unknown':
				name = item.message.split(':', 1)[0]
				entry = report['unknown'].setdefault(name, {'lines': 0, 'meant': engine._did_you_mean(name, answers, now)})
				entry['lines'] += 1
	for verdict in verdicts.values():
		report['checked'][verdict] = report['checked'].get(verdict, 0) + 1
	return report

def format_diagnostics_report(report):
	'''The diagnostics replay as text: what was checked, which lines would warn, the hosts mssh would reject.'''
	checked = report['checked']
	out = ['warnings over {} history lines (DNS, no ping)'.format(report['lines']),
		'  hosts checked: {} (valid {}, unsure {}, invalid {})'.format(sum(checked.values()), checked.get('valid', 0), checked.get('unsure', 0), checked.get('invalid', 0)),
		'  lines warned: ' + ', '.join('{} {}'.format(kind, report['warned'][kind]) for kind in DIAGNOSTIC_KINDS)]
	if report['unknown']:
		out.append('  hosts mssh would reject:')
		for name, entry in sorted(report['unknown'].items(), key=lambda item: (-item[1]['lines'], item[0])):
			meant = '  (did you mean {}?)'.format(entry['meant']) if entry['meant'] else ''
			out.append('    {}  {} line{}{}'.format(name, entry['lines'], '' if entry['lines'] == 1 else 's', meant))
	return '\n'.join(out) + '\n'

def synthetic_history(seed=1, entries=1500, start=1700000000):
	'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	options = parser.parse_args(args)
	mssh = _import_mssh()
````

with:

````python
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	parser.add_argument('--diagnostics', action='store_true', help='replay the warnings instead, looking hosts up in DNS (no ping): lists the hosts mssh would reject')
	options = parser.parse_args(args)
	mssh = _import_mssh()
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	else:
		lines, _, _ = read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

def main(argv=None):
````

with:

````python
	else:
		lines, _, _ = read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	if options.diagnostics:
		lines = [line for line in lines if _entry_time(line) >= options.since][-options.limit:]
		hosts = engine_for(Request('bash', 'mssh ', '', '')).hosts
		print(format_diagnostics_report(diagnostics_replay(lines, spec, mssh.host_validity, hosts)), end='')
		return 0
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

def _entry_time(line):
	'''The unix time an mssh history line starts with, 0 when it has none.'''
	head = line.split('\t', 1)[0]
	return int(head) if _is_digits(head) else 0

def main(argv=None):
````

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python


version = '6.29'
VERSION = version
__version__ = version
````

with:

````python


version = '6.30'
VERSION = version
__version__ = version
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_eval.py tests/test_complete_diagnose.py -q`

Expected: PASS (`56 passed in 0.94s`)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `950 passed, 40 skipped in 72.20s (0:01:12)`

- [ ] **Step 6: Run the whole shell matrix**

Run: `tests/shells/run_matrix.sh`

Expected:

````text
=== modern (requires bash,zsh,fish,blesh,zas)
Python 3.13.5
440 passed, 1 skipped in 115.47s (0:01:55)
=== current (requires bash,zsh,fish,blesh,zas)
Python 3.15.0
440 passed, 1 skipped in 116.70s (0:01:56)
=== legacy (requires bash,zsh,fish,blesh,zas)
Python 3.6.8
438 passed, 3 skipped in 116.17s (0:01:56)
=== centos7 (requires bash,blesh)
Python 3.6.8
400 passed, 41 skipped in 60.36s (0:01:00)
````

- [ ] **Step 7: Commit**

````bash
git add README.md docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp3-design.md mssh_complete.py multiSSH3.py tests/bench_complete.py tests/test_complete_diagnose.py tests/test_complete_eval.py
git commit -F - <<'EOF'
feat: replay the warnings over history; docs; multiSSH3 6.30

mssh-complete eval --diagnostics looks the hosts of the history up in
DNS and lists those mssh would reject; on synthetic history clean lines
warn nothing and injected mistakes are all caught. Replaying real history
found IPv4 ranges flagged: they hold only addresses now. README section,
the spec's deviations, the benchmark's warning queries.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014nn9wafoD4CjdbuahfCV2e
EOF
````
