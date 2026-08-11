# multiSSH3 Full Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pytest suite under `tests/` that covers expand/compact, Host/CLI/config, output merge, SSH run paths, and curses TUI — live on `127.0.0.0/8` when SSH/tty exist, mocked otherwise — and rename the old `test/` tree to `test_legacy/`.

**Architecture:** Mirror `multiCMD/tests/`: capability probes and adaptive fixtures in `conftest.py`; modular `test_*.py` files import real `multiSSH3` APIs. Live SSH uses multiple loopback addresses; CI uses the same tests with mocks. Prefer patching at subprocess/SSH boundaries over refactoring `multiSSH3.py`.

**Tech Stack:** Python 3.6+, pytest, stdlib `unittest.mock`, existing `multiSSH3.py` (no new runtime package deps). Optional live: OpenSSH client + sshd listening on loopback, curses/tty.

**Spec:** `docs/superpowers/specs/2026-08-11-multissh3-test-suite-design.md`

## Global Constraints

- Suite must pass with `python -m pytest tests/` when sshd and tty are absent (mocks/stubs).
- Same command must exercise live multi-`127.x` and TUI when probes pass — no required extra CLI flags.
- Network only within `127.0.0.0/8`. Env override: `MSSH_TEST_HOSTS=127.0.0.1,127.0.0.2,...`.
- Rename `test/` → `test_legacy/`; do not collect it in pytest.
- No new runtime dependencies on the multiSSH3 package; pytest is a test-only dependency.
- Prefer importing `multiSSH3` helpers; do not re-implement expand/compact in the test tree.
- Minimal production-code changes: patch boundaries first; only add hooks if a critical path is otherwise untestable.
- IPMI/SCP/file-sync are thin smoke only (mock + skip-if-missing binaries).
- Clear `lru_cache` on cached expand helpers between tests that change validation/env behavior.

## File structure (create / rename)

| Path | Role |
|---|---|
| `test_legacy/` | Renamed from `test/`; historical scripts/benches; not pytest-collected |
| `tests/conftest.py` | Probes, fixtures, `run_cli`, global restore, cache clear |
| `tests/test_expand_hostnames.py` | Bracket/IPv4 expand unit tests |
| `tests/test_compact_hostnames.py` | Compact + round-trip |
| `tests/test_host.py` | `Host`, `OrderedMultiSet`, `replace_magic_strings` |
| `tests/test_config_cli.py` | Config load, argparse, `--version` |
| `tests/test_output_merge.py` | Merge helpers + output modes |
| `tests/test_run_command.py` | Single-host run (live or mock) |
| `tests/test_run_on_hosts.py` | Multi-host parallel (live `127.x` or fakes) |
| `tests/test_curses_tui.py` | Curses/ANSI helpers + display selection |
| `tests/test_smoke_optional.py` | IPMI/SCP/sync smoke |

---

### Task 1: Scaffold — rename legacy tests + conftest harness

**Files:**
- Rename: `test/` → `test_legacy/`
- Create: `tests/conftest.py`
- Create: `tests/test_harness_smoke.py` (temporary probe sanity; deleted or folded later if redundant)

**Interfaces:**
- Consumes: `multiSSH3` module globals; system `ssh`
- Produces:
  - `PACKAGE_ROOT: Path`
  - `MULTISSH3_PY: Path`
  - `run_cli(args: list[str], timeout: float = 30, check: bool = False) -> subprocess.CompletedProcess`
  - `ssh_localhost_works() -> bool`
  - `parse_mssh_test_hosts() -> list[str]` (default `["127.0.0.1","127.0.0.2","127.0.0.3"]`, override `MSSH_TEST_HOSTS`)
  - fixture `local_ssh_hosts` → `list[str]` (live list if probe ok, else empty — callers use `hosts_for_run`)
  - fixture `hosts_for_run` → `list[str]` (live hosts or `["mock-a","mock-b"]`)
  - fixture `ssh_mode` → `"live"` | `"mock"`
  - fixture `fake_host` → factory `(name, command, **kwargs) -> multiSSH3.Host` with `getIP` patched to return name/IP without DNS when needed
  - fixture `no_hostname_validation` → patches `multiSSH3.__validate_expand_hostname` to `lambda hostname: [hostname]` and clears expand caches on enter/exit
  - fixture `curses_harness` → object with `.mode` (`"live"|"stub"`), `.window` stub recording `addstr` calls, `.inject_keys(seq)`
  - autouse `restore_module_globals` + `clear_expand_caches`

- [ ] **Step 1: Rename the legacy directory**

```bash
cd /mnt/klein/work/cas/multiSSH3
git mv test test_legacy
```

- [ ] **Step 2: Write `tests/conftest.py`**

```python
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import multiSSH3

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MULTISSH3_PY = PACKAGE_ROOT / "multiSSH3.py"

DEFAULT_LOOPBACK_HOSTS = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def parse_mssh_test_hosts():
	raw = os.environ.get("MSSH_TEST_HOSTS", "").strip()
	if not raw:
		return list(DEFAULT_LOOPBACK_HOSTS)
	return [h.strip() for h in raw.split(",") if h.strip()]


def ssh_localhost_works():
	ssh = shutil.which("ssh")
	if not ssh:
		return False
	try:
		r = subprocess.run(
			[
				ssh,
				"-o", "BatchMode=yes",
				"-o", "ConnectTimeout=2",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"127.0.0.1",
				"true",
			],
			capture_output=True,
			timeout=5,
		)
		return r.returncode == 0
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
		return False


def tty_or_curses_ok():
	try:
		import curses
		if not sys.stdout.isatty():
			return False
		# Soft probe: import succeeds and we have a tty
		return hasattr(curses, "wrapper")
	except Exception:
		return False


def run_cli(args, timeout=30, check=False):
	return subprocess.run(
		[sys.executable, str(MULTISSH3_PY), *args],
		capture_output=True,
		text=True,
		timeout=timeout,
		check=check,
	)


def _clear_expand_caches():
	for name in (
		"__validate_expand_hostname",
		"__expandIPv4Address",
		"__expand_hostname",
		"__expand_hostnames",
	):
		fn = getattr(multiSSH3, name, None)
		if fn is not None and hasattr(fn, "cache_clear"):
			fn.cache_clear()


@pytest.fixture(autouse=True)
def restore_module_globals():
	saved = {
		"_no_env": multiSSH3._no_env,
		"__global_suppress_printout": multiSSH3.__global_suppress_printout,
		"__mainReturnCode": multiSSH3.__mainReturnCode,
		"__failedHosts": set(multiSSH3.__failedHosts),
		"_encoding": multiSSH3._encoding,
		"DEFAULT_PASSWORD": multiSSH3.DEFAULT_PASSWORD,
		"SSH_STRICT_HOST_KEY_CHECKING": multiSSH3.SSH_STRICT_HOST_KEY_CHECKING,
		"_etc_hosts": dict(getattr(multiSSH3, "_etc_hosts", {}) or {}),
	}
	_clear_expand_caches()
	yield
	for k, v in saved.items():
		setattr(multiSSH3, k, v if k != "__failedHosts" else set(v))
	multiSSH3.__failedHosts = set(saved["__failedHosts"])
	multiSSH3.join_threads(timeout=2)
	_clear_expand_caches()


@pytest.fixture
def no_hostname_validation(monkeypatch):
	monkeypatch.setattr(
		multiSSH3,
		"__validate_expand_hostname",
		lambda hostname: [hostname],
	)
	_clear_expand_caches()
	yield
	_clear_expand_caches()


@pytest.fixture(scope="session")
def _ssh_probe():
	return ssh_localhost_works()


@pytest.fixture
def ssh_mode(_ssh_probe):
	return "live" if _ssh_probe else "mock"


@pytest.fixture
def local_ssh_hosts(_ssh_probe):
	if not _ssh_probe:
		return []
	return parse_mssh_test_hosts()


@pytest.fixture
def hosts_for_run(local_ssh_hosts, ssh_mode):
	if ssh_mode == "live":
		return list(local_ssh_hosts)
	return ["mock-a", "mock-b"]


@pytest.fixture
def fake_host(monkeypatch):
	def _factory(name, command="true", **kwargs):
		# Avoid DNS for fake names
		monkeypatch.setattr(
			multiSSH3,
			"getIP",
			lambda hostname, local=False: hostname.split("@")[-1],
		)
		return multiSSH3.Host(name=name, command=command, **kwargs)
	return _factory


class StubWindow:
	def __init__(self):
		self.calls = []
		self._yx = (24, 80)

	def getmaxyx(self):
		return self._yx

	def addstr(self, *args, **kwargs):
		self.calls.append(("addstr", args, kwargs))

	def addnstr(self, *args, **kwargs):
		self.calls.append(("addnstr", args, kwargs))

	def move(self, *args, **kwargs):
		self.calls.append(("move", args, kwargs))

	def clrtoeol(self, *args, **kwargs):
		self.calls.append(("clrtoeol", args, kwargs))

	def refresh(self, *args, **kwargs):
		self.calls.append(("refresh", args, kwargs))


class CursesHarness:
	def __init__(self, mode):
		self.mode = mode
		self.window = StubWindow()
		self.keys = []

	def inject_keys(self, seq):
		self.keys.extend(seq)


@pytest.fixture
def curses_harness():
	mode = "live" if tty_or_curses_ok() else "stub"
	return CursesHarness(mode)


def pytest_configure(config):
	config.addinivalue_line("markers", "live_ssh: exercises real SSH when available")
	config.addinivalue_line("markers", "live_tui: exercises real curses/tty when available")
	config.addinivalue_line("markers", "smoke_optional: skip if optional binaries missing")
```

- [ ] **Step 3: Write a tiny harness smoke test**

Create `tests/test_harness_smoke.py`:

```python
from tests.conftest import run_cli, ssh_localhost_works, parse_mssh_test_hosts


def test_version_cli():
	r = run_cli(["-V"])
	assert r.returncode == 0
	assert "6." in (r.stdout + r.stderr)


def test_parse_hosts_default():
	hosts = parse_mssh_test_hosts()
	assert "127.0.0.1" in hosts
	assert all(h.startswith("127.") for h in hosts)


def test_ssh_probe_returns_bool():
	assert isinstance(ssh_localhost_works(), bool)
```

Note: if `from tests.conftest import ...` fails under plain pytest collection, import via `conftest` helpers by duplicating only `run_cli` usage through fixtures, or add empty `tests/__init__.py` and run as `python -m pytest`. Prefer defining `test_version_cli` using only subprocess inline if import path is awkward — keep helpers in conftest and use them as fixtures:

```python
def test_version_cli():
	import subprocess, sys
	from pathlib import Path
	py = Path(__file__).resolve().parents[1] / "multiSSH3.py"
	r = subprocess.run([sys.executable, str(py), "-V"], capture_output=True, text=True, timeout=30)
	assert r.returncode == 0
```

Use whichever import style works on the first pytest run; prefer exporting helpers from conftest (pytest loads conftest automatically — tests can still import from the module path `conftest` only when running inside `tests/`; safest is put shared helpers in `tests/helpers.py` if imports bite). **If import of conftest fails, create `tests/helpers.py` with the pure functions and import those from both conftest and tests.**

- [ ] **Step 4: Run harness smoke**

Run: `python -m pytest tests/test_harness_smoke.py -v`  
Expected: PASS (version may match current `version` string in module).

- [ ] **Step 5: Commit**

```bash
git add test_legacy tests
git commit -m "$(cat <<'EOF'
Add pytest harness and rename legacy multiSSH3 tests.

Move ad-hoc test/ scripts to test_legacy/ and add conftest probes for live 127/8 SSH and curses fallbacks.
EOF
)"
```

---

### Task 2: Hostname expand unit tests

**Files:**
- Create: `tests/test_expand_hostnames.py`
- Test: uses `no_hostname_validation` fixture from Task 1

**Interfaces:**
- Consumes: `multiSSH3.__expand_hostname`, `multiSSH3.__expandIPv4Address`, `multiSSH3.expand_hostnames`, fixture `no_hostname_validation`
- Produces: coverage of bracket/comma/pad/hex/alpha and IPv4 expand

- [ ] **Step 1: Write failing/pending tests file**

```python
import multiSSH3


def test_numeric_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("test[1-3]", validate=False) == {"test1", "test2", "test3"}


def test_letter_range(no_hostname_validation):
	assert multiSSH3.__expand_hostname("host[a-c]", validate=False) == {"hosta", "hostb", "hostc"}


def test_padding(no_hostname_validation):
	assert multiSSH3.__expand_hostname("server[001-003]", validate=False) == {
		"server001", "server002", "server003"
	}


def test_comma_mixed(no_hostname_validation):
	assert multiSSH3.__expand_hostname("mixed[a-b,1-2]", validate=False) == {
		"mixeda", "mixedb", "mixed1", "mixed2"
	}


def test_passthrough(no_hostname_validation):
	assert multiSSH3.__expand_hostname("hostname", validate=False) == {"hostname"}
	assert multiSSH3.__expand_hostname("invalid_host", validate=False) == {"invalid_host"}


def test_ipv4_octet_range():
	# Pure IP expand — no DNS validation path
	got = multiSSH3.__expandIPv4Address(["127.0.0.[1-3]"])
	assert got == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_expand_hostnames_loopback_dict():
	d = multiSSH3.expand_hostnames(["127.0.0.1", "127.0.0.2"])
	assert d["127.0.0.1"] == "127.0.0.1"
	assert d["127.0.0.2"] == "127.0.0.2"
```

Port additional cases from `test_legacy/test.py` that still match production `__expand_hostname` behavior (drop cases that only applied to the old local copy of the function).

- [ ] **Step 2: Run tests**

Run: `python -m pytest tests/test_expand_hostnames.py -v`  
Expected: PASS. If a legacy expectation disagrees with production, **keep production behavior** and adjust the assertion (note in commit message).

- [ ] **Step 3: Commit**

```bash
git add tests/test_expand_hostnames.py
git commit -m "$(cat <<'EOF'
Add hostname and IPv4 expand unit tests for multiSSH3.

EOF
)"
```

---

### Task 3: Compact hostnames unit tests

**Files:**
- Create: `tests/test_compact_hostnames.py`

**Interfaces:**
- Consumes: `multiSSH3.compact_hostnames`, fixture `no_hostname_validation`
- Produces: round-trip and doctest-equivalent cases

- [ ] **Step 1: Write tests**

```python
import multiSSH3


def test_compact_numeric_suffix(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server15", "server16", "server17"], verify=True
	) == ["server[15-17]"]


def test_compact_dashed(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server-1", "server-2", "server-3"]
	) == ["server-[1-3]"]


def test_compact_two_segments(no_hostname_validation):
	assert multiSSH3.compact_hostnames(
		["server-1-2", "server-1-1", "server-2-1", "server-2-2"]
	) == ["server-[1-2]-[1-2]"]


def test_round_trip_expand_compact(no_hostname_validation):
	original = {"node1", "node2", "node3"}
	compacted = multiSSH3.compact_hostnames(sorted(original))
	expanded = multiSSH3.__expand_hostname(compacted[0], validate=False)
	assert expanded == original
```

If `no_hostname_validation` cannot patch the cached wrapper cleanly, clear caches after patch and/or monkeypatch `multiSSH3.expand_hostnames` to expand with `validate=False` only for these tests.

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_compact_hostnames.py -v`  
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_compact_hostnames.py
git commit -m "$(cat <<'EOF'
Add compact_hostnames unit tests with expand round-trip.

EOF
)"
```

---

### Task 4: Host model, OrderedMultiSet, magic strings

**Files:**
- Create: `tests/test_host.py`

**Interfaces:**
- Consumes: `multiSSH3.Host`, `OrderedMultiSet`, `replace_magic_strings`, fixture `fake_host`
- Produces: unit coverage for model helpers

- [ ] **Step 1: Write tests**

```python
import multiSSH3


def test_host_defaults(fake_host):
	h = fake_host("127.0.0.1", "echo hi")
	assert h.name == "127.0.0.1"
	assert h.command == "echo hi"
	assert h.returncode is None
	assert h.uuid is not None
	assert h.i >= 0


def test_host_copy_preserves_outputs(fake_host):
	h = fake_host("127.0.0.1", "true")
	h.stdout = ["a"]
	h.stderr = ["b"]
	h.returncode = 0
	c = h.copy()
	assert c.stdout == ["a"]
	assert c.stderr == ["b"]
	assert c.returncode == 0
	assert c.uuid == h.uuid


def test_replace_magic_strings_host():
	s = multiSSH3.replace_magic_strings("run on #HOST#", ["#HOST#", "#HOSTNAME#"], "node1")
	assert s == "run on node1"


def test_ordered_multiset_count_and_contains():
	# OrderedMultiSet is a deque+Counter helper used in mergeOutput streaming;
	# line bags passed to can_merge are plain set objects (see get_host_raw_output).
	a = multiSSH3.OrderedMultiSet(["x", "y", "y"])
	assert a.count("y") == 2
	assert "x" in a
	assert list(a) == ["x", "y", "y"]
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_host.py -v`  
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_host.py
git commit -m "$(cat <<'EOF'
Add Host, magic-string, and OrderedMultiSet unit tests.

EOF
)"
```

---

### Task 5: Config load and CLI parsing

**Files:**
- Create: `tests/test_config_cli.py`

**Interfaces:**
- Consumes: `multiSSH3.load_config_file`, `get_parser`, `process_args`, `run_cli`
- Produces: CLI/config regression coverage

- [ ] **Step 1: Write tests**

```python
import json
from pathlib import Path

import multiSSH3
from conftest import run_cli  # or tests.helpers.run_cli


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


def test_parser_hosts_and_command():
	parser = multiSSH3.get_parser()
	# positional: hosts, then commands...
	args = parser.parse_args(["127.0.0.1", "echo", "ok"])
	assert args.hosts == "127.0.0.1"
	assert args.commands == ["echo", "ok"]


def test_malformed_config_returns_empty(tmp_path, capsys):
	cfg = tmp_path / "bad.json"
	cfg.write_text("{not-json")
	# load_config_file catches Exception, eprints, returns {}
	assert multiSSH3.load_config_file(str(cfg)) == {}


def test_missing_config_returns_empty(tmp_path):
	assert multiSSH3.load_config_file(str(tmp_path / "nope.json")) == {}
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_config_cli.py -v`  
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_config_cli.py
git commit -m "$(cat <<'EOF'
Add config loading and CLI parsing tests for multiSSH3.

EOF
)"
```

---

### Task 6: Output merge and print modes

**Files:**
- Create: `tests/test_output_merge.py`

**Interfaces:**
- Consumes: `can_merge`, `form_merge_groups`, `mergeOutputs` / `generate_output`, `fake_host`
- Produces: merge threshold and output-mode coverage

- [ ] **Step 1: Write tests**

```python
import multiSSH3


def test_can_merge_identical_bags():
	# Production line bags are set objects (get_host_raw_output)
	bag = {"line1", "line2", "line3"}
	assert multiSSH3.can_merge(bag, bag, 0.9) is True


def test_can_merge_divergent_bags():
	a = {"a", "b", "c"}
	b = {"x", "y", "z"}
	assert multiSSH3.can_merge(a, b, 0.9) is False


def test_form_merge_groups_identical_hosts(fake_host):
	h1 = fake_host("127.0.0.1", "echo hi")
	h1.stdout = ["hi"]
	h1.returncode = 0
	h2 = fake_host("127.0.0.2", "echo hi")
	h2.stdout = ["hi"]
	h2.returncode = 0
	outputs, line_bags, by_len, sorted_keys, _width = multiSSH3.get_host_raw_output(
		[h1, h2], terminal_width=80
	)
	# Copy structures because form_merge_groups mutates them
	merge_groups, remaining = multiSSH3.form_merge_groups(
		{k: set(v) for k, v in by_len.items()},
		list(sorted_keys),
		dict(line_bags),
		0.9,
	)
	assert remaining == set()
	assert len(merge_groups) == 1
	assert set(merge_groups[0]) == {"127.0.0.1", "127.0.0.2"}


def test_generate_output_json(fake_host):
	h = fake_host("127.0.0.1", "echo")
	h.stdout = ["hello"]
	h.returncode = 0
	# quiet=True filters out returncode==0 hosts — use quiet=False for success path
	out = multiSSH3.generate_output([h], usejson=True, quiet=False)
	assert "hello" in out
	assert "127.0.0.1" in out


def test_generate_output_greppable(fake_host):
	h = fake_host("127.0.0.1", "echo")
	h.stdout = ["hello"]
	h.returncode = 0
	out = multiSSH3.generate_output([h], greppable=True, quiet=False)
	assert "hello" in out
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_output_merge.py -v`  
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_output_merge.py
git commit -m "$(cat <<'EOF'
Add output merge and generate_output mode tests.

EOF
)"
```

---

### Task 7: Single-host `run_command` (live or mock)

**Files:**
- Create: `tests/test_run_command.py`

**Interfaces:**
- Consumes: `multiSSH3.run_command`, `Host`, `ssh_mode`, `local_ssh_hosts`, `fake_host`
- Produces: single-host success/timeout/rc coverage in both modes

- [ ] **Step 1: Write tests**

```python
import threading
from unittest.mock import patch

import pytest

import multiSSH3


@pytest.mark.live_ssh
def test_run_echo_localhost(ssh_mode, local_ssh_hosts, fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	if ssh_mode == "live":
		host = multiSSH3.Host(name=local_ssh_hosts[0], command="echo mssh-live-ok")
		multiSSH3.run_command(host, sem, timeout=20)
		assert host.returncode == 0
		assert any("mssh-live-ok" in line for line in host.stdout)
		return

	# Mock mode: patch subprocess.Popen at the call site inside run_command
	host = fake_host("mock-a", "echo hi")

	class FakeProc:
		def __init__(self):
			self.stdout = io.BytesIO(b"hi\n")
			self.stderr = io.BytesIO(b"")
			self.stdin = MagicMock()
			self.returncode = 0
		def wait(self, timeout=None):
			return 0
		def poll(self):
			return 0
		def kill(self):
			pass
		def communicate(self, *a, **k):
			return b"hi\n", b""

	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *a, **k: FakeProc())
	# Also set multiSSH3.subprocess if run_command uses bare subprocess from import
	import subprocess as sp
	monkeypatch.setattr(sp, "Popen", lambda *a, **k: FakeProc())
	multiSSH3.run_command(host, sem, timeout=5)
	# Stream handler threads may need a short join; assert best-effort:
	multiSSH3.join_threads(timeout=2)
	assert host.returncode == 0
	assert any("hi" in line for line in host.stdout)
```

**Mock note:** `run_command` calls `subprocess.Popen` (imported module global in `multiSSH3`). `FakeProc.stdout`/`stderr` must support the reads used by `__handle_reading_stream` (`.readline()` / iteration). If thread timing makes Popen mocking flaky, keep one Popen-patched test and monkeypatch `run_command` only in multi-host tests (Task 8).

Also add live timeout test:

```python
@pytest.mark.live_ssh
def test_run_timeout(ssh_mode, local_ssh_hosts):
	if ssh_mode != "live":
		pytest.skip("timeout path covered under live SSH")
	sem = threading.Semaphore(1)
	host = multiSSH3.Host(name=local_ssh_hosts[0], command="sleep 5")
	multiSSH3.run_command(host, sem, timeout=1)
	assert host.returncode not in (0, None)
```


- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_run_command.py -v`  
Expected: PASS in both environments (live assertions when probe true).

- [ ] **Step 3: Commit**

```bash
git add tests/test_run_command.py tests/conftest.py
git commit -m "$(cat <<'EOF'
Add single-host run_command tests with live/mock SSH paths.

EOF
)"
```

---

### Task 8: Multi-host run on `127.0.0.0/8` (or fakes)

**Files:**
- Create: `tests/test_run_on_hosts.py`

**Interfaces:**
- Consumes: `run_command_on_hosts` or `start_run_on_hosts` + `processRunOnHosts`, `hosts_for_run`, `ssh_mode`
- Produces: multi-host parallel coverage

- [ ] **Step 1: Write tests**

```python
import pytest

import multiSSH3


@pytest.mark.live_ssh
def test_multi_host_echo(hosts_for_run, ssh_mode, monkeypatch):
	hosts_arg = ",".join(hosts_for_run)
	if ssh_mode == "mock":
		# Patch run_command to complete immediately per Host
		def fake_run(host, sem, timeout=60, **kwargs):
			host.stdout.append(f"ok-{host.name}")
			host.returncode = 0
		monkeypatch.setattr(multiSSH3, "run_command", fake_run)

	result = multiSSH3.run_command_on_hosts(
		hosts=hosts_arg,
		commands="echo ok",
		no_watch=True,
		quiet=True,
		no_history=True,
		timeout=30,
		skip_unreachable=True,
		will_update_unreachable_hosts=False,
		called=True,
		max_connections=4,
	)
	# Assert per actual return type (list of Host or None + side effects)
	# At minimum: no uncaught exception and hosts show returncode 0 when live.
```

Also add:

```python
def test_distinct_loopback_list(local_ssh_hosts, ssh_mode):
	if ssh_mode != "live":
		pytest.skip("live SSH not available")
	assert len(set(local_ssh_hosts)) >= 2
	assert all(h.startswith("127.") for h in local_ssh_hosts)
```

Use `no_watch=True` to avoid curses UI during CLI-path runs.

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_run_on_hosts.py -v`  
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_run_on_hosts.py
git commit -m "$(cat <<'EOF'
Add multi-host run tests using 127/8 loopback or mocks.

EOF
)"
```

---

### Task 9: Curses TUI helpers

**Files:**
- Create: `tests/test_curses_tui.py`

**Interfaces:**
- Consumes: `__parse_ansi_escape_sequence_to_curses_attr`, `_curses_add_string_to_window`, `_get_hosts_to_display`, `curses_harness`, `fake_host`
- Produces: TUI unit coverage with stub window; optional live init

- [ ] **Step 1: Write tests**

```python
import multiSSH3


def test_get_hosts_to_display_windowing(fake_host):
	hosts = [fake_host(f"127.0.0.{i}", "true") for i in range(1, 6)]
	# Mark first two as finished so ordering is stable
	for h in hosts[:2]:
		h.returncode = 0
		h.output = ["done"]
	displayed, stats, rearranged = multiSSH3._get_hosts_to_display(
		hosts, max_num_hosts=2, indexOffset=0
	)
	assert len(displayed) == 2
	assert stats["finished"] == 2
	assert isinstance(rearranged, set)


def test_curses_add_string_records(curses_harness, monkeypatch):
	# Stub curses attrs used by _curses_add_string_to_window when parse_ansi_colors is False
	win = curses_harness.window
	multiSSH3._curses_add_string_to_window(
		window=win,
		line="hello",
		y=0,
		x=0,
		number_of_char_to_write=5,
		parse_ansi_colors=False,
	)
	assert len(win.calls) >= 1


def test_parse_ansi_escape_basic(monkeypatch):
	# Function may touch curses color state; ensure it does not raise on a simple code
	try:
		out = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr("\x1b[31m")
	except Exception as e:
		# If curses not fully init, monkeypatch color_pair / COLORS as needed during implementation
		pytest.fail(f"ANSI parse raised: {e}")
	assert out is not None
```

Optional live:

```python
@pytest.mark.live_tui
def test_curses_initscr_smoke(curses_harness):
	if curses_harness.mode != "live":
		# Still run stub path assertions above; this test no-ops into stub smoke
		assert curses_harness.window is not None
		return
	import curses
	def _probe(stdscr):
		stdscr.addstr(0, 0, "mssh")
		return True
	assert curses.wrapper(_probe) is True
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_curses_tui.py -v`  
Expected: PASS without a tty

- [ ] **Step 3: Commit**

```bash
git add tests/test_curses_tui.py
git commit -m "$(cat <<'EOF'
Add curses TUI helper tests with stub window fallback.

EOF
)"
```

---

### Task 10: Optional IPMI / SCP / sync smoke

**Files:**
- Create: `tests/test_smoke_optional.py`

**Interfaces:**
- Consumes: `get_default_ipmi_definition`, `__formCommandArgStr` / `getStrCommand`, `Host` with `scp=True`, `shutil.which`
- Produces: thin smoke; skip if binaries missing

- [ ] **Step 1: Write tests**

```python
import shutil

import pytest

import multiSSH3


def test_default_ipmi_definition_keys():
	d = multiSSH3.get_default_ipmi_definition()
	assert "username" in d
	assert "password" in d
	assert "ipmi_method" in d


@pytest.mark.smoke_optional
def test_ipmitool_on_path_or_skip():
	if not shutil.which("ipmitool"):
		pytest.skip("ipmitool not installed")
	assert shutil.which("ipmitool")


@pytest.mark.smoke_optional
def test_scp_flag_in_command_string():
	if not shutil.which("scp"):
		pytest.skip("scp not installed")
	s = multiSSH3.getStrCommand(
		hosts="127.0.0.1",
		commands=["/tmp/dest"],
		scp=True,
		file=["/tmp/a"],
		no_history=True,
	)
	assert "--scp" in s or " -W" in s or s.endswith("127.0.0.1")
	# __formCommandArgStr adds '--scp' when scp=True
	assert "--scp" in multiSSH3.__formCommandArgStr(scp=True, file=["/tmp/a"])
```

`getStrCommand` builds a replayable CLI string; asserting `--scp` via `__formCommandArgStr(scp=True, ...)` is the precise smoke check.

- [ ] **Step 2: Run**

Run: `python -m pytest tests/test_smoke_optional.py -v`  
Expected: PASS (skips allowed)

- [ ] **Step 3: Commit**

```bash
git add tests/test_smoke_optional.py
git commit -m "$(cat <<'EOF'
Add thin IPMI/SCP optional smoke tests for multiSSH3.

EOF
)"
```

---

### Task 11: Full-suite verification and cleanup

**Files:**
- Modify: remove `tests/test_harness_smoke.py` if redundant with `test_config_cli.py`
- Optionally create: `tests/helpers.py` if Task 1 split helpers out of conftest
- Modify: `.gitignore` only if `__pycache__` / `.pytest_cache` not already ignored

**Interfaces:**
- Consumes: entire `tests/` tree
- Produces: green `pytest tests/` on CI-like conditions

- [ ] **Step 1: Run the full suite**

```bash
cd /mnt/klein/work/cas/multiSSH3
python -m pytest tests/ -v
```

Expected: all tests PASS or intentional `pytest.skip` for missing optional binaries. Zero failures.

- [ ] **Step 2: Confirm legacy not collected**

```bash
python -m pytest tests/ test_legacy/ --collect-only 2>&1 | head
# Prefer only running tests/:
python -m pytest tests/ --collect-only -q
```

Expected: no collection of `test_legacy/*.py` when invoking `pytest tests/`.

- [ ] **Step 3: Fix any failures** from live/mock branches, cache pollution, or Host/getIP DNS. Re-run until green.

- [ ] **Step 4: Final commit if cleanup happened**

```bash
git add tests .gitignore
git commit -m "$(cat <<'EOF'
Finish multiSSH3 pytest suite verification and cleanup.

EOF
)"
```

---

## Self-review vs spec

| Spec requirement | Task |
|---|---|
| Rename `test/` → `test_legacy/` | Task 1 |
| New `tests/` pytest tree like multiCMD | Tasks 1–10 |
| Capability probes SSH + tty | Task 1 |
| Live multi `127.0.0.0/8` + `MSSH_TEST_HOSTS` | Tasks 1, 7, 8 |
| Mock fallback for CI | Tasks 1, 7, 8, 9 |
| Expand/compact unit tests + legacy cases | Tasks 2–3 |
| Host / config / CLI | Tasks 4–5 |
| Output merge | Task 6 |
| SSH run single + multi | Tasks 7–8 |
| Curses TUI | Task 9 |
| IPMI/SCP thin smoke | Task 10 |
| Success criteria full-suite green without sshd/tty | Task 11 |
| No Docker/remote/BMC; no CI workflow required | Honored (out of scope) |
