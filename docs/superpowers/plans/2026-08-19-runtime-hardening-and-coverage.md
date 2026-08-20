# multiSSH3 Runtime Hardening and Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the approved runtime and CLI defects and raise deterministic branch coverage for the complete packaged `multiSSH3.py` module from 52.19% to at least 70%.

**Architecture:** Preserve the single-module public API and harden behavior in place. Add only narrow private helpers for backoff, unavailable-host persistence, positive repeat parsing, and concurrency normalization; extend the pytest harness at process, clock, filesystem, and curses boundaries.

**Tech Stack:** Python 3.6+, pytest 8, Coverage.py 7 with branch tracing, stdlib `threading`, `subprocess`, `argparse`, `tempfile`, and `unittest.mock`; no new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-08-19-runtime-hardening-and-coverage-design.md`

## Global Constraints

- Preserve command names, public function signatures, `Host` fields, and output formats except for the approved error and return-code corrections.
- A timeout initiated by multiSSH3 must return exactly `124`.
- EMFILE retries must release the semaphore before backoff and must terminate after the existing retry budget.
- Keep current `ipmitool` and `redfishtool` command construction unchanged; add only the approved real-hardware verification comment.
- Reject repeat counts below one with argparse exit code 2; sleep only between repeated runs.
- `max_connections=None` uses `4 * os.cpu_count()`, zero uses the positive detected safe limit, negative values remain CPU multipliers, and positive values retain safe-limit clamping.
- Unavailable-host state must be canonical, atomic, and free of malformed or expired entries.
- The deterministic suite must pass without live SSH, a real TTY, or IPMI hardware.
- Acceptance uses Coverage.py JSON `covered_branches / num_branches`, not its combined display percentage, and must be at least 0.70 for all of `multiSSH3.py`.
- Maintain Python 3.6 syntax compatibility; do not use built-in generic annotations such as `list[str]` or `dict[str, int]`.

## File Structure

| Path | Responsibility |
|---|---|
| `multiSSH3.py` | Approved runtime, persistence, and CLI corrections plus narrow private helpers |
| `tests/conftest.py` | Global restoration, deterministic terminal windows/panels, and shared harness state |
| `tests/test_run_command_branches.py` | EMFILE, timeout, shell fallback, retry, and subprocess lifecycle contracts |
| `tests/test_unavailable_hosts.py` | Canonical parsing, atomic persistence, expiry, and orchestration integration |
| `tests/test_main_lifecycle.py` | Repeat validation/order, exit aggregation, history, signals, timed input, and config processing |
| `tests/test_run_on_hosts_modes.py` | Exact concurrency normalization and host/file-transfer orchestration |
| `tests/test_cli_branches.py` | Complete script-mode and missing-config contracts |
| `tests/test_curses_branches.py` | Exact ANSI/color semantics and lower-level window rendering |
| `tests/test_curses_event_loop.py` | Deterministic display geometry, keys, panels, redraw, and `curses_print` reconfiguration |
| `tests/test_runtime_branch_matrix.py` | Remaining high-value output, IPMI retry, orchestration, and configuration branches |

---

### Task 1: Make EMFILE retry bounded and semaphore-safe

**Files:**
- Modify: `multiSSH3.py:2076-2182`
- Modify: `tests/test_run_command_branches.py`

**Interfaces:**
- Consumes: `run_command(host, sem, timeout, passwds, retry_limit, ipmi_definitions_list)`
- Produces: `_emfile_backoff_seconds(attempt)` returning `min(0.1 * 2**attempt, 1.0)` and EMFILE retry that reuses the formatted command outside the held semaphore

- [ ] **Step 1: Add failing EMFILE success-after-retry and exhaustion tests**

Add `import errno` and these tests to `tests/test_run_command_branches.py`:

```python
def test_run_command_emfile_retries_after_releasing_semaphore(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def fake_popen(*args, **kwargs):
		attempts.append(args[0])
		if len(attempts) == 1:
			raise OSError(errno.EMFILE, "too many open files")
		return FakeProc()

	def fake_sleep(seconds):
		acquired = sem.acquire(blocking=False)
		assert acquired, "EMFILE backoff ran while the semaphore was held"
		sem.release()
		delays.append(seconds)

	_patch_popen(monkeypatch, fake_popen)
	monkeypatch.setattr(multiSSH3.time, "sleep", fake_sleep)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=2)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 0


def test_run_command_emfile_exhausts_retry_budget(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "true")
	attempts = []
	delays = []

	def always_emfile(*args, **kwargs):
		attempts.append(args[0])
		raise OSError(errno.EMFILE, "too many open files")

	_patch_popen(monkeypatch, always_emfile)
	monkeypatch.setattr(multiSSH3.time, "sleep", delays.append)

	multiSSH3.run_command(host, sem, timeout=5, retry_limit=1)

	assert len(attempts) == 2
	assert delays == [0.1]
	assert host.returncode == 1
	assert any("Retry limit" in line for line in host.stderr)
```

- [ ] **Step 2: Run the tests and confirm the unsafe behavior**

Run: `python3 -m pytest tests/test_run_command_branches.py::test_run_command_emfile_retries_after_releasing_semaphore tests/test_run_command_branches.py::test_run_command_emfile_exhausts_retry_budget -v`

Expected: FAIL; the first test observes the semaphore still held or hangs under the test timeout, and exhaustion does not produce the required bounded result.

- [ ] **Step 3: Implement a loop around the existing semaphore-held subprocess lifecycle**

Add near `run_command`:

```python
def _emfile_backoff_seconds(attempt):
	return min(0.1 * (2 ** attempt), 1.0)
```

In `run_command`, mechanically indent the current `with sem:` block under `while True`, initialize the retry flag before acquiring the semaphore, and keep the current `Popen`, stream-thread, polling, cleanup, and non-EMFILE exception statements in their current order. The new loop boundary starts with:

```python
	emfile_attempt = 0
	while True:
		retry_after_emfile = False
		with sem:
			try:
				proc = subprocess.Popen(formatedCMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				stdout_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stdout, host.stdout, host, host.stdout_buffer), daemon=True)
				stdout_thread.start()
				stderr_thread = threading.Thread(target=__handle_reading_stream, args=(proc.stderr, host.stderr, host, host.stderr_buffer), daemon=True)
				stderr_thread.start()
				stdin_stop_event = threading.Event()
				stdin_thread = threading.Thread(target=__handle_writing_stream, args=(proc.stdin, stdin_stop_event, host), daemon=True)
				stdin_thread.start()
			except OSError as exc:
				if exc.errno != errno.EMFILE:
					raise
				retry_after_emfile = True
				host.returncode = None

		if not retry_after_emfile:
			break
		if retry_limit <= 0:
			host.output.append("Error: Retry limit reached after too many open files!")
			host.stderr.append("Error: Retry limit reached after too many open files!")
			host.returncode = 1
			return
		host.output.append("Warning: Too many open files. retrying...")
		time.sleep(_emfile_backoff_seconds(emfile_attempt))
		emfile_attempt += 1
		retry_limit -= 1
```

Import `errno` at module scope. Remove the old `time.sleep(0.1)` and recursive `run_command` call from the errno-24 branch. Preserve the post-execution IPMI and rsync fallback logic after the loop.

- [ ] **Step 4: Run focused and neighboring runtime tests**

Run: `python3 -m pytest tests/test_run_command.py tests/test_run_command_branches.py -q`

Expected: all deterministic tests pass; the live timeout test may skip when SSH is unavailable.

- [ ] **Step 5: Commit**

```bash
git add multiSSH3.py tests/test_run_command_branches.py
git commit -m "fix: make EMFILE retries semaphore-safe"
```

---

### Task 2: Standardize timeout results and terminate shell fallback correctly

**Files:**
- Modify: `multiSSH3.py:1984-2018,2094-2160`
- Modify: `tests/test_run_command.py`
- Modify: `tests/test_run_command_branches.py`

**Interfaces:**
- Consumes: existing `Host.returncode`, process polling, and SSH-to-localhost fallback
- Produces: deterministic timeout code `124`; exactly one subprocess invocation for missing-`sh` shell fallback; unchanged IPMI argv

- [ ] **Step 1: Add a deterministic timeout test**

Add this process double and test to `tests/test_run_command.py`:

```python
class TimeoutProc(FakeProc):
	def __init__(self):
		super().__init__()
		self.returncode = None
		self.signals = []
		self.terminated = False

	def send_signal(self, sig):
		self.signals.append(sig)

	def terminate(self):
		self.terminated = True
		self.returncode = -15


def test_run_timeout_is_124_without_live_ssh(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("mock-a", "sleep forever")
	proc = TimeoutProc()
	ticks = iter([0.0, 2.0])
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda *args, **kwargs: proc)
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3, "__handle_writing_stream", lambda *args: 0)

	multiSSH3.run_command(host, sem, timeout=1)

	assert proc.signals == [multiSSH3.signal.SIGINT]
	assert proc.terminated is True
	assert host.returncode == 124
	assert "Timeout!" in host.stderr
```

- [ ] **Step 2: Add a missing-`sh` fallback regression test**

Add to `tests/test_run_command_branches.py`:

```python
def test_shell_fallback_returns_after_single_ssh_attempt(fake_host, monkeypatch):
	sem = threading.Semaphore(1)
	host = fake_host("ignored", "echo fallback", shell=True)
	calls = []
	multiSSH3._binPaths.pop("sh", None)

	def fake_popen(argv, **kwargs):
		calls.append(argv)
		return FakeProc(stdout=b"fallback\n")

	_patch_popen(monkeypatch, fake_popen)
	multiSSH3.run_command(host, sem, timeout=5)

	assert len(calls) == 1
	assert calls[0][-3:] == ["--", "localhost", "echo fallback"]
	assert host.returncode == 0
```

- [ ] **Step 3: Run both tests and verify they fail**

Run: `python3 -m pytest tests/test_run_command.py::test_run_timeout_is_124_without_live_ssh tests/test_run_command_branches.py::test_shell_fallback_returns_after_single_ssh_attempt -v`

Expected: FAIL; timeout retains `-15`, and shell fallback continues after recursion.

- [ ] **Step 4: Implement the selected behavior**

In the subprocess polling block, initialize `timed_out = False` before the loop, set it immediately before sending SIGINT, and make it authoritative after `proc.poll()`:

```python
			timed_out = False
			while proc.poll() is None:
				if timeout > 0 and time.monotonic() - host.lastUpdateTime > timeout:
					timed_out = True
					host.stderr.append("Timeout!")
					host.output.append("Timeout!")
					proc.send_signal(signal.SIGINT)
					time.sleep(0.1)
					proc.terminate()
					break
```

After `host.returncode = proc.poll()`, apply:

```python
			if timed_out:
				host.returncode = 124
			elif host.returncode is None:
				if host.stderr and host.stderr[-1].strip().startswith("Ctrl C detected, Emergency Stop!"):
					host.returncode = 137
				else:
					host.returncode = -1
```

Change the missing-`sh` fallback call to:

```python
				return run_command(host, sem, timeout, passwds, retry_limit=retry_limit - 1, ipmi_definitions_list=ipmi_definitions_list)
```

Immediately above the existing IPMI command construction, add this comment without changing its argv:

```python
			# Compatibility note: the unusual shell/direct IPMI argument forms may work around
			# ipmitool behavior on deployed machines. Verify on real IPMI hardware before changing.
```

- [ ] **Step 5: Strengthen the optional live timeout assertion and run runtime tests**

Change `tests/test_run_command.py::test_run_timeout` to assert `host.returncode == 124` and that `"Timeout!"` appears in `host.stderr`. Run:

`python3 -m pytest tests/test_run_command.py tests/test_run_command_branches.py -q`

Expected: deterministic tests pass; live timeout passes or skips.

- [ ] **Step 6: Commit**

```bash
git add multiSSH3.py tests/test_run_command.py tests/test_run_command_branches.py
git commit -m "fix: standardize timeout and shell fallback results"
```

---

### Task 3: Make unavailable-host persistence canonical and atomic

**Files:**
- Modify: `multiSSH3.py:3390-3474,3718-3745`
- Create: `tests/test_unavailable_hosts.py`

**Interfaces:**
- Produces: `_unavailable_hosts_file_path()`, `_read_unavailable_hosts_file(path, now=None)`, `_write_unavailable_hosts_file(path, unavailable_hosts, available_hosts=(), now=None)`
- Consumes: dictionaries whose values are monotonic expiry timestamps

- [ ] **Step 1: Write parsing and atomic-write tests**

Create `tests/test_unavailable_hosts.py`:

```python
import os

import multiSSH3


def test_read_unavailable_hosts_discards_malformed_and_expired(tmp_path):
	path = tmp_path / "unavailable.csv"
	path.write_text("live-a,150\nexpired,99\nbad\nmissing-number,nope\n")

	assert multiSSH3._read_unavailable_hosts_file(str(path), now=100) == {"live-a": 150}


def test_write_unavailable_hosts_is_canonical_and_removes_available(tmp_path):
	path = tmp_path / "unavailable.csv"
	result = multiSSH3._write_unavailable_hosts_file(
		str(path),
		{"z-host": 180, "a-host": 170, "expired": 90},
		available_hosts={"z-host"},
		now=100,
	)

	assert result == {"a-host": 170}
	assert path.read_text() == "a-host,170\n"
	assert list(tmp_path.iterdir()) == [path]


def test_write_unavailable_hosts_cleans_temp_file_after_replace_error(tmp_path, monkeypatch, capsys):
	path = tmp_path / "unavailable.csv"
	monkeypatch.setattr(multiSSH3.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("replace failed")))

	result = multiSSH3._write_unavailable_hosts_file(str(path), {"a": 200}, now=100)

	assert result == {"a": 200}
	assert list(tmp_path.iterdir()) == []
	assert "replace failed" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests and verify helpers are absent**

Run: `python3 -m pytest tests/test_unavailable_hosts.py -v`

Expected: FAIL with `AttributeError` for `_read_unavailable_hosts_file`.

- [ ] **Step 3: Implement the persistence helpers**

Add near `processRunOnHosts`:

```python
def _unavailable_hosts_file_path():
	return os.path.join(tempfile.gettempdir(), "__{}_multiSSH3_UNAVAILABLE_HOSTS.csv".format(getpass.getuser()))


def _read_unavailable_hosts_file(path, now=None):
	current_time = time.monotonic() if now is None else now
	result = {}
	try:
		with open(path, "r") as handle:
			for raw_line in handle:
				parts = raw_line.strip().split(",")
				if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
					continue
				expiry = int(parts[1])
				if expiry > current_time:
					result[parts[0]] = expiry
	except FileNotFoundError:
		return {}
	except Exception as exc:
		eprint("Warning: Unable to read unavailable hosts from {!r}: {}".format(path, exc))
	return result


def _write_unavailable_hosts_file(path, unavailable_hosts, available_hosts=(), now=None):
	current_time = time.monotonic() if now is None else now
	available = set(available_hosts)
	clean = {
		host: int(expiry)
		for host, expiry in unavailable_hosts.items()
		if host not in available and int(expiry) > current_time
	}
	temporary_path = "{}.{}".format(path, uuid4().hex)
	try:
		with open(temporary_path, "w") as handle:
			for host in sorted(clean):
				handle.write("{},{}\n".format(host, clean[host]))
			handle.flush()
			os.fsync(handle.fileno())
		os.replace(temporary_path, path)
	except Exception as exc:
		eprint("Error writing unavailable hosts to {!r}: {}".format(path, exc))
		try:
			if os.path.exists(temporary_path):
				os.unlink(temporary_path)
		except OSError:
			pass
	return clean
```

Replace both duplicated path expressions with `_unavailable_hosts_file_path()`. In `run_command_on_hosts`, replace the manual file parser with:

```python
	unavailable_path = _unavailable_hosts_file_path()
	if os.path.exists(unavailable_path):
		loaded_unavailable = _read_unavailable_hosts_file(unavailable_path)
		__globalUnavailableHosts.update(loaded_unavailable)
		if loaded_unavailable and not __global_suppress_printout:
			eprint("Read unavailable hosts from the file {}".format(unavailable_path))
	elif "__multiSSH3_UNAVAILABLE_HOSTS" in readEnvFromFile():
		__globalUnavailableHosts.update({
			host: int(time.monotonic() + unavailable_host_expiry)
			for host in readEnvFromFile()["__multiSSH3_UNAVAILABLE_HOSTS"].split(",")
			if host
		})
```

In `processRunOnHosts`, after classifying every host and building `availableHosts`, replace the manual merge/write block with:

```python
			canonical_unavailable = _write_unavailable_hosts_file(
				_unavailable_hosts_file_path(), unavailableHosts, availableHosts
			)
			unavailableHosts.clear()
			unavailableHosts.update(canonical_unavailable)
			__globalUnavailableHosts.clear()
			__globalUnavailableHosts.update(canonical_unavailable)
```

This keeps the caller-provided dictionary and the module-global dictionary synchronized with exactly what was persisted.

- [ ] **Step 4: Add orchestration integration for timeout classification**

Append:

```python
def test_process_run_marks_timeout_unavailable(tmp_path, fake_host, monkeypatch):
	path = tmp_path / "unavailable.csv"
	host = fake_host("mock-a", "true")
	host.returncode = 124
	host.stderr = ["Timeout!"]
	unavailable = {}
	monkeypatch.setattr(multiSSH3, "_unavailable_hosts_file_path", lambda: str(path))
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])

	multiSSH3.processRunOnHosts(
		timeout=1,
		password=None,
		max_connections=1,
		hosts=[host],
		return_unfinished=False,
		no_watch=True,
		json=False,
		no_output=True,
		greppable=False,
		unavailableHosts=unavailable,
		will_update_unreachable_hosts=True,
		pre_merge=False,
	)

	assert "mock-a" in unavailable
	assert multiSSH3._read_unavailable_hosts_file(str(path)) == unavailable
```

- [ ] **Step 5: Run focused and orchestration tests**

Run: `python3 -m pytest tests/test_unavailable_hosts.py tests/test_run_on_hosts.py tests/test_run_on_hosts_modes.py -q`

Expected: all pass without creating state outside pytest temporary directories.

- [ ] **Step 6: Commit**

```bash
git add multiSSH3.py tests/test_unavailable_hosts.py
git commit -m "fix: persist unavailable hosts atomically"
```

---

### Task 4: Correct repeat validation, interval ordering, and missing-config warnings

**Files:**
- Modify: `multiSSH3.py:4066-4135,4138-4153,4321-4356`
- Modify: `tests/test_cli_branches.py`
- Create: `tests/test_main_lifecycle.py`

**Interfaces:**
- Produces: `_positive_int(value)` for argparse; `main` sequence `run, sleep, run`; reliable warning for missing explicit config

- [ ] **Step 1: Add repeat parser and missing-config tests**

Append to `tests/test_cli_branches.py`:

```python
@pytest.mark.parametrize("repeat", ["0", "-1"])
def test_process_args_rejects_nonpositive_repeat(repeat):
	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_args(["127.0.0.1", "true", "--repeat", repeat])
	assert exc_info.value.code == 2


def test_process_args_warns_for_missing_explicit_config(tmp_path, capsys):
	missing = tmp_path / "missing.json"
	args = multiSSH3.process_args(["--config_file", str(missing), "127.0.0.1", "true"])

	assert args.config_file == str(missing)
	assert "Config file {!r} not found".format(str(missing)) in capsys.readouterr().err
```

Add `import pytest` if the file does not already import it.

- [ ] **Step 2: Add a direct main interval-order test**

Create `tests/test_main_lifecycle.py`:

```python
import pytest

import multiSSH3


def test_main_runs_immediately_and_sleeps_only_between_repeats(fake_host, monkeypatch):
	events = []
	host = fake_host("mock-a", "true")
	host.returncode = 0

	def fake_run(**kwargs):
		events.append("run")
		return [host]

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: events.append(("sleep", seconds)))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["mock-a", "true", "--repeat", "3", "--interval", "2", "--no_output", "--no_history"])

	assert exc_info.value.code == 0
	assert events == ["run", ("sleep", 2), "run", ("sleep", 2), "run"]
```

- [ ] **Step 3: Run tests and verify failures**

Run: `python3 -m pytest tests/test_cli_branches.py::test_process_args_rejects_nonpositive_repeat tests/test_cli_branches.py::test_process_args_warns_for_missing_explicit_config tests/test_main_lifecycle.py::test_main_runs_immediately_and_sleeps_only_between_repeats -v`

Expected: repeat zero is accepted, the warning is missing, and interval events are shifted.

- [ ] **Step 4: Implement parser validation and ordering**

Add before `get_parser`:

```python
def _positive_int(value):
	parsed = int(value)
	if parsed < 1:
		raise argparse.ArgumentTypeError("must be at least 1")
	return parsed
```

Change the repeat argument's type from `int` to `_positive_int`. In `process_args`, change the warning to use `cfpa.config_file`:

```python
			else:
				eprint("Warning: Config file {!r} not found, ignoring it.".format(cfpa.config_file))
```

Move interval sleeping inside `main` so it occurs before attempts after the first:

```python
	for i in range(args.repeat):
		if i > 0 and args.interval > 0:
			eprint("Sleeping for {} seconds".format(args.interval))
			time.sleep(args.interval)
		if not __global_suppress_printout and args.repeat > 1:
			eprint("Running the {}/{} time".format(i + 1, args.repeat))
		hosts = run_command_on_hosts(**vars(args), called=False)
```

- [ ] **Step 5: Run CLI and lifecycle tests**

Run: `python3 -m pytest tests/test_cli_processing.py tests/test_cli_branches.py tests/test_config_cli.py tests/test_main_lifecycle.py -q`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add multiSSH3.py tests/test_cli_branches.py tests/test_main_lifecycle.py
git commit -m "fix: validate repeats and order intervals"
```

---

### Task 5: Normalize connection limits explicitly

**Files:**
- Modify: `multiSSH3.py:3746-3758`
- Modify: `tests/test_run_on_hosts_modes.py`

**Interfaces:**
- Produces: `_normalize_max_connections(max_connections)` returning the exact integer passed to `processRunOnHosts`
- Consumes: `os.cpu_count()`, `__max_connections_nofile_limit_supported`, and `__system_nofile_limit`

- [ ] **Step 1: Replace the outcome-only test with exact normalization tests**

Add to `tests/test_run_on_hosts_modes.py`:

```python
@pytest.mark.parametrize(
	"requested,safe_limit,expected",
	[
		(None, 100, 32),
		(0, 100, 100),
		(0, 0, 32),
		(-2, 100, 16),
		(3, 100, 3),
		(200, 100, 100),
	],
)
def test_normalize_max_connections(requested, safe_limit, expected, monkeypatch):
	monkeypatch.setattr(multiSSH3.os, "cpu_count", lambda: 8)
	monkeypatch.setattr(multiSSH3, "__max_connections_nofile_limit_supported", safe_limit)

	assert multiSSH3._normalize_max_connections(requested) == expected


def test_run_on_hosts_zero_forwards_safe_limit(monkeypatch):
	forwarded = []
	monkeypatch.setattr(multiSSH3, "__max_connections_nofile_limit_supported", 17)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	monkeypatch.setattr(
		multiSSH3,
		"processRunOnHosts",
		lambda *args, **kwargs: forwarded.append(kwargs["max_connections"]),
	)

	hosts = multiSSH3.run_command_on_hosts(
		hosts="mock-a",
		commands="true",
		max_connections=0,
		no_watch=True,
		quiet=True,
		no_history=True,
		called=True,
		will_update_unreachable_hosts=False,
	)

	assert len(hosts) == 1
	assert forwarded == [17]
```

Ensure `pytest` is imported. Remove the old `test_run_on_hosts_max_connections_variants` outcome-only loop after these exact tests replace it.

- [ ] **Step 2: Run the new test and verify the helper is missing**

Run: `python3 -m pytest tests/test_run_on_hosts_modes.py::test_normalize_max_connections -v`

Expected: FAIL with `AttributeError`.

- [ ] **Step 3: Implement normalization and use it once**

Add near `run_command_on_hosts`:

```python
def _normalize_max_connections(max_connections):
	cpu_default = 4 * os.cpu_count()
	safe_limit = __max_connections_nofile_limit_supported
	if max_connections is None:
		normalized = cpu_default
	elif max_connections == 0:
		normalized = safe_limit if safe_limit > 0 else cpu_default
	elif max_connections < 0:
		normalized = (-max_connections) * os.cpu_count()
	else:
		normalized = max_connections
	if safe_limit > 0 and normalized > safe_limit:
		eprint(
			"Warning: The number of maximum connections {} is larger than estimated limit {} "
			"from ulimit nofile limit {}, setting the maximum connections to {}.".format(
				normalized, safe_limit, __system_nofile_limit, safe_limit
			)
		)
		normalized = safe_limit
	return normalized
```

Replace the existing falsy/zero/negative/clamp block with:

```python
	max_connections = _normalize_max_connections(max_connections)
```

Do not change the public signature or negative multiplier semantics.

- [ ] **Step 4: Run host orchestration tests**

Run: `python3 -m pytest tests/test_run_on_hosts.py tests/test_run_on_hosts_modes.py -q`

Expected: all pass and the zero case asserts the safe limit rather than merely completing one host.

- [ ] **Step 5: Commit**

```bash
git add multiSSH3.py tests/test_run_on_hosts_modes.py
git commit -m "fix: normalize max connection modes"
```

---

### Task 6: Replace permissive contract assertions

**Files:**
- Modify: `tests/test_run_on_hosts_modes.py`
- Modify: `tests/test_run_command_branches.py`
- Modify: `tests/test_cli_branches.py`
- Modify: `tests/test_curses_branches.py`

**Interfaces:**
- Consumes: existing production behavior after Tasks 1-5
- Produces: exact file-transfer, script-mode, and ANSI transition contracts

- [ ] **Step 1: Strengthen file-sync orchestration assertions**

In `test_run_on_hosts_file_sync_builds_hosts`, replace the truthy disjunction with:

```python
	assert len(hosts) == 1
	assert hosts[0].files == [str(src.resolve())]
	assert hosts[0].command == str(src.resolve().parent) + os.path.sep
	assert hosts[0].scp is True
	assert hosts[0].gatherMode is False
```

Add `import os`. In the existing scp, rsync, and gather tests, replace executable-only assertions with these complete argv expectations:

```python
	assert scp_calls[0] == [
		"scp", "-rp",
		"-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]
	assert rsync_calls[0] == [
		"rsync", "-ahlX", "--partial", "--inplace", "--info=name",
		"--rsh", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		"--", "/tmp/a", "mock-a:/tmp/dest",
	]
	assert gather_calls[0] == [
		"scp", "-rp",
		"-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null",
		"--", "mock-a:/tmp/remote", "/tmp/local",
	]
```

Rename each test's local `calls` list to `scp_calls`, `rsync_calls`, or `gather_calls` to match its assertion; keep them as three independent tests.

- [ ] **Step 2: Strengthen the script-mode contract**

Replace the broad assertions in `test_process_args_script_and_output_flags` with:

```python
	assert args.no_watch is True
	assert args.skip_unreachable is True
	assert args.no_env is True
	assert args.no_history is True
	assert args.greppable is True
	assert args.error_only is True
	assert args.json is True
	assert args.no_output is True
	assert args.use_key is True
	assert args.extraargs == "--x"
```

- [ ] **Step 3: Replace ANSI smoke assertions with semantic cases**

Keep the malformed-input cases as non-raising smoke tests. Replace valid escape cases with this table and exact assertions:

```python
@pytest.mark.parametrize(
	"escape,state_index,expected",
	[
		("\x1b[31m", 0, curses.COLOR_RED),
		("\x1b[41m", 1, curses.COLOR_RED),
		("\x1b[91m", 0, curses.COLOR_RED),
		("\x1b[101m", 1, curses.COLOR_RED),
	],
)
def test_parse_ansi_updates_exact_color_state(curses_color_mocks, escape, state_index, expected):
	state = [-1, -1, 1]
	attr = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr(escape, state)

	assert state[state_index] == expected
	assert state[2] == attr


def test_parse_ansi_reset_clears_styles(curses_color_mocks):
	state = [curses.COLOR_RED, curses.COLOR_BLUE, curses.A_BOLD | curses.A_UNDERLINE]
	attr = multiSSH3.__parse_ansi_escape_sequence_to_curses_attr("\x1b[0m", state)

	assert state == [-1, -1, attr]
	assert attr & curses.A_BOLD == 0
	assert attr & curses.A_UNDERLINE == 0
```

- [ ] **Step 4: Run the strengthened tests**

Run: `python3 -m pytest tests/test_run_on_hosts_modes.py tests/test_run_command_branches.py tests/test_cli_branches.py tests/test_curses_branches.py -q`

Expected: all assertions pass. If an exact argv expectation exposes an unintended production mismatch outside the approved changes, stop and document the mismatch rather than weakening the assertion.

- [ ] **Step 5: Commit**

```bash
git add tests/test_run_on_hosts_modes.py tests/test_run_command_branches.py tests/test_cli_branches.py tests/test_curses_branches.py
git commit -m "test: assert complete runtime contracts"
```

---

### Task 7: Cover main, history, signals, timed input, and config processing

**Files:**
- Modify: `tests/test_main_lifecycle.py`
- Modify: `tests/conftest.py`

**Interfaces:**
- Consumes: `main`, `record_command_history`, `signal_handler`, `input_with_timeout_and_countdown`, and `process_config_file`
- Produces: deterministic direct coverage of formerly zero-covered lifecycle helpers

- [ ] **Step 1: Extend global restoration before exercising lifecycle functions**

Add these values to `restore_module_globals` and restore mutable containers by copy:

```python
		"_emo": multiSSH3._emo,
		"_env_files": list(multiSSH3._env_files),
		"__globalUnavailableHosts": dict(multiSSH3.__globalUnavailableHosts),
		"__keyPressesIn": [list(line) for line in multiSSH3.__keyPressesIn],
		"DEFAULT_IPMI_DEFINITIONS": [dict(item) for item in multiSSH3.DEFAULT_IPMI_DEFINITIONS],
		"ERRORS": list(multiSSH3.ERRORS),
```

Restore each list/dict using a fresh list/dict so later tests cannot retain references.

Add these explicit restorations after `yield` and before `join_threads`:

```python
	multiSSH3._env_files = list(saved["_env_files"])
	multiSSH3.__globalUnavailableHosts = dict(saved["__globalUnavailableHosts"])
	multiSSH3.__keyPressesIn = [list(line) for line in saved["__keyPressesIn"]]
	multiSSH3.DEFAULT_IPMI_DEFINITIONS = [dict(item) for item in saved["DEFAULT_IPMI_DEFINITIONS"]]
	multiSSH3.ERRORS = list(saved["ERRORS"])
```

- [ ] **Step 2: Add main aggregation and history tests**

Append to `tests/test_main_lifecycle.py`:

```python
def test_main_aggregates_failed_and_successful_hosts(fake_host, monkeypatch, capsys):
	failed = fake_host("bad", "false")
	failed.returncode = 7
	succeeded = fake_host("good", "true")
	succeeded.returncode = 0
	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", lambda **kwargs: [failed, succeeded])

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.main(["mock-a", "true", "--success_hosts", "--no_history"])

	assert exc_info.value.code == 1
	assert multiSSH3.__failedHosts == {"bad"}
	assert "failed_hosts: bad" in capsys.readouterr().err


def test_record_command_history_writes_timestamped_command(tmp_path, monkeypatch):
	path = tmp_path / "history"
	monkeypatch.setattr(multiSSH3.time, "time", lambda: 1234)
	multiSSH3.record_command_history({
		"hosts": "mock-a",
		"commands": ["true"],
		"history_file": str(path),
	})

	line = path.read_text()
	assert line.startswith("1234\t")
	assert "mock-a" in line
	assert "true" in line
```

- [ ] **Step 3: Add signal and timed-input tests**

Append:

```python
def test_signal_handler_first_interrupt_sets_emergency_stop(monkeypatch, capsys):
	monkeypatch.setattr(multiSSH3, "_emo", False)
	multiSSH3.signal_handler(None, None)

	assert multiSSH3._emo is True
	assert "Ctrl C caught" in capsys.readouterr().err


def test_signal_handler_second_interrupt_exits(monkeypatch):
	commands = []
	monkeypatch.setattr(multiSSH3, "_emo", True)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	monkeypatch.setattr(multiSSH3.os, "system", lambda command: commands.append(command))

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.signal_handler(None, None)

	assert exc_info.value.code == 1
	assert commands and commands[0].startswith("pkill -ef")


def test_input_with_timeout_returns_inline_input(monkeypatch):
	class InlineThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			self.target()

	monkeypatch.setattr(multiSSH3.threading, "Thread", InlineThread)
	monkeypatch.setattr(multiSSH3.sys.stdin, "readline", lambda: "multiple\n")

	assert multiSSH3.input_with_timeout_and_countdown(3) == "multiple"


def test_input_with_timeout_returns_none(monkeypatch):
	class IdleThread:
		def __init__(self, target, daemon):
			self.target = target
		def start(self):
			return None

	ticks = iter([0.0, 2.0])
	monkeypatch.setattr(multiSSH3.threading, "Thread", IdleThread)
	monkeypatch.setattr(multiSSH3.time, "monotonic", lambda: next(ticks, 2.0))
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	assert multiSSH3.input_with_timeout_and_countdown(1) is None
```

- [ ] **Step 4: Add config generation dispatch coverage**

Append:

```python
def test_process_config_file_generates_and_exits_without_work(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["--generate_config_file"])
	calls = []
	monkeypatch.setattr(
		multiSSH3,
		"write_default_config",
		lambda parsed, CONFIG_FILE=None, force=False: calls.append((CONFIG_FILE, force)),
	)

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.process_config_file(args)

	assert exc_info.value.code == 0
	assert calls == [(None, True)]


def test_process_config_file_generates_and_returns_when_commands_remain(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["mock-a", "true", "--generate_config_file"])
	calls = []
	monkeypatch.setattr(
		multiSSH3,
		"write_default_config",
		lambda parsed, CONFIG_FILE=None, force=False: calls.append((CONFIG_FILE, force)),
	)

	result = multiSSH3.process_config_file(args)

	assert result is args
	assert calls == [(None, True)]
```

- [ ] **Step 5: Run lifecycle tests**

Run: `python3 -m pytest tests/test_main_lifecycle.py tests/test_config_cli.py tests/test_cli_processing.py -q`

Expected: all pass with no persisted history or global emergency state after the module finishes.

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py tests/test_main_lifecycle.py
git commit -m "test: cover CLI lifecycle and interactive helpers"
```

---

### Task 8: Build a deterministic curses event-loop harness

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/test_curses_event_loop.py`

**Interfaces:**
- Produces: fixture `stub_curses_harness` with `.window`, `.windows`, `.panels`, `.inject_keys(seq)`, and patched `curses.newwin`, `curses.panel`, and `curses.doupdate`
- Consumes: existing `StubWindow` call-record format `(method, args, kwargs)`

- [ ] **Step 1: Extend `StubWindow` with event-loop operations**

Change its constructor and add methods:

```python
class StubWindow:
	def __init__(self, yx=(24, 80), keys=None):
		self.calls = []
		self._yx = yx
		self.keys = list(keys or [])

	def getch(self):
		self.calls.append(("getch", (), {}))
		return self.keys.pop(0) if self.keys else -1

	def set_size(self, rows, columns):
		self._yx = (rows, columns)

	def clear(self):
		self.calls.append(("clear", (), {}))

	def nodelay(self, value):
		self.calls.append(("nodelay", (value,), {}))

	def idlok(self, value):
		self.calls.append(("idlok", (value,), {}))

	def scrollok(self, value):
		self.calls.append(("scrollok", (value,), {}))

	def leaveok(self, value):
		self.calls.append(("leaveok", (value,), {}))

	def box(self):
		self.calls.append(("box", (), {}))

	def vline(self, *args):
		self.calls.append(("vline", args, {}))

	def noutrefresh(self):
		self.calls.append(("noutrefresh", (), {}))

	def touchwin(self):
		self.calls.append(("touchwin", (), {}))
```

Keep all existing methods.

- [ ] **Step 2: Add panel and harness implementations**

Add:

```python
class StubPanel:
	def __init__(self, window):
		self.window = window
		self.hidden = False
		self.calls = []
	def hide(self):
		self.hidden = True
		self.calls.append("hide")
	def show(self):
		self.hidden = False
		self.calls.append("show")


class StubPanelModule:
	def __init__(self, harness):
		self.harness = harness
	def new_panel(self, window):
		panel = StubPanel(window)
		self.harness.panels.append(panel)
		return panel
	def update_panels(self):
		self.harness.panel_updates += 1


class StubCursesHarness:
	def __init__(self):
		self.window = StubWindow()
		self.windows = []
		self.panels = []
		self.panel_updates = 0
		self.screen_updates = 0
	def inject_keys(self, seq):
		self.window.keys.extend(seq)
	def newwin(self, rows, columns, y, x):
		window = StubWindow((rows, columns))
		window.calls.append(("origin", (y, x), {}))
		self.windows.append(window)
		return window
```

- [ ] **Step 3: Add the always-stubbed fixture**

```python
@pytest.fixture
def stub_curses_harness(monkeypatch):
	import curses
	harness = StubCursesHarness()
	panel_module = StubPanelModule(harness)
	monkeypatch.setattr(curses, "newwin", harness.newwin)
	monkeypatch.setattr(curses, "panel", panel_module)
	monkeypatch.setattr(curses, "doupdate", lambda: setattr(harness, "screen_updates", harness.screen_updates + 1))
	monkeypatch.setattr(curses, "ACS_VLINE", ord("|"), raising=False)
	monkeypatch.setattr(curses, "KEY_RESIZE", 410, raising=False)
	monkeypatch.setattr(curses, "KEY_REFRESH", 12, raising=False)
	monkeypatch.setattr(curses, "KEY_F5", 269, raising=False)
	monkeypatch.setattr(curses, "KEY_EXIT", 361, raising=False)
	monkeypatch.setattr(curses, "KEY_HELP", 353, raising=False)
	monkeypatch.setattr(curses, "KEY_F1", 265, raising=False)
	monkeypatch.setattr(curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(curses, "can_change_color", lambda: False)
	monkeypatch.setattr(curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(curses, "color_pair", lambda pair: pair << 8)
	monkeypatch.setattr(curses, "A_BOLD", 1 << 16, raising=False)
	monkeypatch.setattr(curses, "A_DIM", 1 << 17, raising=False)
	monkeypatch.setattr(curses, "A_UNDERLINE", 1 << 18, raising=False)
	monkeypatch.setattr(curses, "A_BLINK", 1 << 19, raising=False)
	monkeypatch.setattr(curses, "A_REVERSE", 1 << 20, raising=False)
	monkeypatch.setattr(curses, "A_INVIS", 1 << 21, raising=False)
	monkeypatch.setattr(multiSSH3, "__curses_global_color_pairs", {})
	monkeypatch.setattr(multiSSH3, "__curses_current_color_pair_index", 1)
	return harness
```

- [ ] **Step 4: Add and run a harness sanity test**

Create `tests/test_curses_event_loop.py`:

```python
def test_stub_curses_harness_records_windows_and_keys(stub_curses_harness):
	harness = stub_curses_harness
	harness.inject_keys([410])
	child = harness.newwin(3, 20, 1, 2)

	assert harness.window.getch() == 410
	assert child.getmaxyx() == (3, 20)
	assert child.calls[0] == ("origin", (1, 2), {})
```

Run: `python3 -m pytest tests/test_curses_event_loop.py::test_stub_curses_harness_records_windows_and_keys -v`

Expected: PASS.

- [ ] **Step 5: Run existing curses tests to ensure harness compatibility**

Run: `python3 -m pytest tests/test_curses_tui.py tests/test_curses_branches.py tests/test_curses_event_loop.py -q`

Expected: all pass; live TUI smoke may use its existing adaptive fixture.

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py tests/test_curses_event_loop.py
git commit -m "test: add deterministic curses event-loop harness"
```

---

### Task 9: Exercise curses display and reconfiguration branches semantically

**Files:**
- Modify: `tests/test_curses_event_loop.py`

**Interfaces:**
- Consumes: `stub_curses_harness`, `__generate_display`, `curses_print`, and `fake_host`
- Produces: deterministic geometry, key, help-panel, edit, redraw, and wrapper-loop coverage

- [ ] **Step 1: Add a running-host factory and geometry-return matrix**

Add:

```python
import curses

import pytest

import multiSSH3


def _running_host(fake_host):
	host = fake_host("mock-a", "true")
	host.returncode = None
	host.output = ["working"]
	host.lineNumToPrintSet = {0}
	return host


@pytest.mark.parametrize(
	"key,expected_index,expected_value,reason",
	[
		(410, None, None, "Terminal resize requested"),
		(95, 3, 1, "Decrease line length"),
		(43, 3, 3, "Increase line length"),
		(123, 2, 9, "Decrease character length"),
		(125, 2, 11, "Increase character length"),
		(124, 4, True, "Toggle single window mode"),
	],
)
def test_generate_display_geometry_keys(
	stub_curses_harness, fake_host, key, expected_index, expected_value, reason
):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([key])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		min_char_len=10,
		min_line_len=2,
		single_window=False,
	)

	assert result[6] == reason
	if expected_index is not None:
		assert result[expected_index] == expected_value
```

- [ ] **Step 2: Add terminal-size and no-host boundary tests**

Add:

```python
def test_generate_display_rejects_tiny_terminal(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.window.set_size(1, 1)

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host])

	assert result[6] == "Terminal too small"


def test_generate_display_reports_no_hosts(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	stats = {"running": 0, "failed": 0, "finished": 0, "waiting": 0}
	monkeypatch.setattr(multiSSH3, "_get_hosts_to_display", lambda *args, **kwargs: ([], stats, set()))

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result[6] == "No hosts to display"
```

- [ ] **Step 3: Add help, editing, and redraw tests**

Add:

```python
def test_generate_display_shows_help_then_refreshes(stub_curses_harness, fake_host):
	host = _running_host(fake_host)
	stub_curses_harness.inject_keys([63, 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert result[5] is True
	assert result[6] == "Refresh requested"
	assert "show" in stub_curses_harness.panels[-1].calls
	assert stub_curses_harness.panel_updates >= 2


def test_generate_display_edits_input_and_redraws_host(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([ord("x"), 12])

	result = multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert multiSSH3.__keyPressesIn == [["x"]]
	assert result[1] == 1
	assert result[6] == "Refresh requested"
	assert any(call[0] == "vline" for window in stub_curses_harness.windows for call in window.calls)
	assert stub_curses_harness.screen_updates >= 1
```

Add these navigation and mutation matrices; key `12` terminates each sequence deterministically:

```python
@pytest.mark.parametrize(
	"history,key,start_line,start_cursor,expected_line,expected_cursor",
	[
		([list("old\n"), []], 259, -1, 0, -2, 4),
		([list("old\n"), []], 258, -2, 0, -1, 0),
		([list("ab")], 260, -1, 2, -1, 1),
		([list("ab")], 261, -1, 0, -1, 1),
		([list("one\n"), list("two\n"), []], 339, -1, 0, -3, 0),
		([list("one\n"), list("two\n"), []], 338, -3, 0, -1, 0),
		([list("ab")], 262, -1, 2, -1, 0),
		([list("ab")], 360, -1, 0, -1, 2),
	],
)
def test_generate_display_navigation_keys(
	stub_curses_harness,
	fake_host,
	monkeypatch,
	history,
	key,
	start_line,
	start_cursor,
	expected_line,
	expected_cursor,
):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list(line) for line in history])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window,
		[host],
		lineToDisplay=start_line,
		curserPosition=start_cursor,
		min_char_len=10,
		min_line_len=2,
	)

	assert result[0] == expected_line
	assert result[1] == expected_cursor
	assert result[6] == "Refresh requested"


@pytest.mark.parametrize(
	"key,start_cursor,expected_history,expected_cursor",
	[
		(8, 1, [list("b")], 0),
		(330, 0, [list("b")], 0),
		(10, 2, [list("ab\n"), []], 0),
	],
)
def test_generate_display_mutates_input(
	stub_curses_harness, fake_host, monkeypatch, key, start_cursor, expected_history, expected_cursor
):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [list("ab")])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([key, 12])

	result = multiSSH3.__generate_display(
		stub_curses_harness.window, [host], curserPosition=start_cursor, min_char_len=10, min_line_len=2
	)

	assert multiSSH3.__keyPressesIn == expected_history
	assert result[1] == expected_cursor


def test_generate_display_ctrl_d_queues_exit(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	monkeypatch.setattr(multiSSH3, "__keyPressesIn", [[]])
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([4, 12])

	multiSSH3.__generate_display(stub_curses_harness.window, [host], min_char_len=10, min_line_len=2)

	assert multiSSH3.__keyPressesIn == [list("exit\n"), []]


def test_generate_display_host_offset_updates_stats(stub_curses_harness, fake_host, monkeypatch):
	hosts = [_running_host(fake_host) for _ in range(2)]
	hosts[0].name = "mock-a"
	hosts[1].name = "mock-b"
	monkeypatch.setattr(multiSSH3.time, "perf_counter", lambda: 1.0)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)
	stub_curses_harness.inject_keys([62, 12])

	multiSSH3.__generate_display(stub_curses_harness.window, hosts, min_char_len=10, min_line_len=2)

	text_args = [
		arg
		for window in stub_curses_harness.windows
		for method, args, kwargs in window.calls
		for arg in args
		if method == "addnstr" and isinstance(arg, str)
	]
	assert any("i:1" in text for text in text_args)
```

- [ ] **Step 4: Add `curses_print` initialization and reconfiguration tests**

Use a callable sequence for `__generate_display`:

```python
def test_curses_print_reloads_configuration(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	responses = iter([
		(-1, 0, 20, 4, True, False, "Toggle single window mode"),
		None,
	])
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: next(responses))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(multiSSH3.curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "can_change_color", lambda: False)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.curses_print(stub_curses_harness.window, [host], [object()])

	addstr_text = [call[1][2] for call in stub_curses_harness.window.calls if call[0] == "addstr"]
	assert any("Toggle single window mode" in text for text in addstr_text)
	assert any(call[0] == "refresh" for call in stub_curses_harness.window.calls)
```

Add:

```python
def test_curses_print_returns_before_generation_for_tiny_screen(stub_curses_harness, monkeypatch):
	stub_curses_harness.window.set_size(1, 1)
	calls = []
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: calls.append(args))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)

	multiSSH3.curses_print(stub_curses_harness.window, [], [])

	assert calls == []


def test_curses_print_renders_error_traceback(stub_curses_harness, fake_host, monkeypatch):
	host = _running_host(fake_host)
	responses = iter([
		(-1, 0, 20, 4, False, False, "Error: boom", "line-one\nline-two"),
		None,
	])
	monkeypatch.setattr(multiSSH3, "__generate_display", lambda *args: next(responses))
	monkeypatch.setattr(multiSSH3.curses, "curs_set", lambda value: None)
	monkeypatch.setattr(multiSSH3.curses, "start_color", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "use_default_colors", lambda: None)
	monkeypatch.setattr(multiSSH3.curses, "init_pair", lambda *args: None)
	monkeypatch.setattr(multiSSH3.curses, "COLORS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "COLOR_PAIRS", 256, raising=False)
	monkeypatch.setattr(multiSSH3.curses, "can_change_color", lambda: False)
	monkeypatch.setattr(multiSSH3.time, "sleep", lambda seconds: None)

	multiSSH3.curses_print(stub_curses_harness.window, [host], [object()])

	text = [call[1][2] for call in stub_curses_harness.window.calls if call[0] == "addstr"]
	assert any("Error: boom" in item for item in text)
	assert "line-one" in text
	assert "line-two" in text
```

- [ ] **Step 5: Run event-loop tests and inspect their branch contribution**

Run:

```bash
python3 -m coverage run --data-file=/tmp/multissh3-task9-coverage --branch --source=multiSSH3 -m pytest tests/test_curses_tui.py tests/test_curses_branches.py tests/test_curses_event_loop.py
python3 -m coverage report --data-file=/tmp/multissh3-task9-coverage -m
```

Expected: all tests pass; `__generate_display` and `curses_print` are no longer zero-covered. No per-function percentage is required.

- [ ] **Step 6: Commit**

```bash
git add tests/test_curses_event_loop.py
git commit -m "test: exercise curses event loop behavior"
```

---

### Task 10: Cover remaining high-value branches and enforce the 70% gate

**Files:**
- Create: `tests/test_runtime_branch_matrix.py`
- Modify: `tests/test_config_validate.py`
- Modify: focused test files identified by the exact Coverage.py report

**Interfaces:**
- Consumes: all behavior and harnesses from Tasks 1-9
- Produces: at least 70% exact branch coverage for all of `multiSSH3.py`

- [ ] **Step 1: Add the remaining execution and orchestration matrix**

Create `tests/test_runtime_branch_matrix.py` with focused tests for these exact cases:

```python
import io
import threading

import pytest

import multiSSH3


class ImmediateProc:
	def __init__(self, returncode=0, stdout=b"", stderr=b""):
		self.returncode = returncode
		self.stdout = io.BytesIO(stdout)
		self.stderr = io.BytesIO(stderr)
		self.stdin = io.BytesIO()
	def poll(self):
		return self.returncode
	def communicate(self, timeout=None):
		return b"", b""


def test_run_command_ssh_ipmitool_defaults_and_user(fake_host, monkeypatch):
	host = fake_host("cli-user@mock-a", "", ipmi=True)
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	definition.update({"ipmi_method": "ssh_ipmitool", "username": "bmc-user", "password": "bmc-pass"})
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, passwds="cli-pass", ipmi_definitions_list=[definition])

	assert host.returncode == 0
	assert host.command == "ipmitool power status"
	assert "bmc-user@mock-a" in calls[0]


def test_run_command_rsync_failure_retries_with_scp(fake_host, monkeypatch):
	host = fake_host("mock-a", "/dest", files=["/source"], scp=False)
	calls = []
	procs = iter([ImmediateProc(returncode=1, stderr=b"rsync failed\n"), ImmediateProc(returncode=0)])
	monkeypatch.setitem(multiSSH3._binPaths, "rsync", "rsync")
	monkeypatch.setitem(multiSSH3._binPaths, "scp", "scp")
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or next(procs))

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5)

	assert calls[0][0] == "rsync"
	assert calls[1][0] == "scp"
	assert host.scp is True
	assert host.returncode == 0
```

Append these exact IPMI and orchestration cases:

```python
def test_run_command_ipmi_definition_exhaustion(fake_host):
	host = fake_host("mock-a", "status", ipmi=True)

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, ipmi_definitions_list=[])

	assert host.returncode == 1
	assert host.stderr == ["Error: Exhausted all matching ipmi definitions!"]


def test_run_command_missing_local_ipmitool_falls_back_to_ssh(fake_host, monkeypatch):
	host = fake_host("mock-a", "power status", ipmi=True)
	calls = []
	definition = multiSSH3.get_default_ipmi_definition()
	multiSSH3._binPaths.pop("ipmitool", None)
	monkeypatch.setitem(multiSSH3._binPaths, "ssh", "ssh")
	monkeypatch.setattr(multiSSH3.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or ImmediateProc())

	multiSSH3.run_command(host, threading.Semaphore(1), timeout=5, ipmi_definitions_list=[definition])

	assert calls[0][0] == "ssh"
	assert "ipmitool power status" in calls[0][-1]
	assert host.returncode == 0


def test_process_run_return_unfinished_registers_threads(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = None
	thread = object()
	monkeypatch.setattr(multiSSH3, "__running_threads", set())
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [thread])

	multiSSH3.processRunOnHosts(
		1, None, 1, [host], True, True, False, True, False,
		{}, False, pre_merge=False,
	)

	assert thread in multiSSH3.__running_threads


def test_process_run_premerges_and_prints(fake_host, monkeypatch):
	host = fake_host("mock-a", "true")
	host.returncode = 0
	events = []
	monkeypatch.setattr(multiSSH3, "start_run_on_hosts", lambda *args, **kwargs: [])
	monkeypatch.setattr(multiSSH3, "pre_merge_hosts", lambda hosts: events.append("merge") or hosts)
	monkeypatch.setattr(multiSSH3, "print_output", lambda hosts, usejson=False, quiet=False, greppable=False: events.append("print"))

	multiSSH3.processRunOnHosts(
		1, None, 1, [host], False, True, False, False, False,
		{}, False, pre_merge=True,
	)

	assert events == ["merge", "print"]


def test_generate_output_includes_connection_refused_and_buffer(fake_host):
	host = fake_host("mock-a", "true")
	host.returncode = 255
	host.stderr = ["ssh: connect to host mock-a port 22: Connection refused"]
	host.output_buffer.write(b"partial-output")

	text = multiSSH3.generate_output([host], greppable=True, quiet=False)

	assert "mock-a" in text
	assert "Connection refused" in text or "partial-output" in text
```

- [ ] **Step 2: Add interactive config-write branches**

Append to `tests/test_config_validate.py`:

```python
def test_write_default_config_backup_choice(tmp_path, monkeypatch):
	path = tmp_path / "config.json"
	path.write_text('{"old": true}')
	args = multiSSH3.get_parser().parse_args(["mock-a", "true"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda timeout: "b")

	multiSSH3.write_default_config(args, CONFIG_FILE=str(path), force=False)

	assert (tmp_path / "config.json.bak").read_text() == '{"old": true}'
	assert json.loads(path.read_text())["DEFAULT_HOSTS"] == "mock-a"


def test_write_default_config_abort_choice(tmp_path, monkeypatch):
	path = tmp_path / "config.json"
	path.write_text("{}")
	args = multiSSH3.get_parser().parse_args(["mock-a", "true"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda timeout: "n")

	with pytest.raises(SystemExit) as exc_info:
		multiSSH3.write_default_config(args, CONFIG_FILE=str(path), force=False)

	assert exc_info.value.code == 0
	assert path.read_text() == "{}"
```

Add `import pytest` to `tests/test_config_validate.py`.

- [ ] **Step 3: Run the complete deterministic suite under fresh branch coverage**

Run:

```bash
python3 -m coverage erase --data-file=/tmp/multissh3-final-coverage
python3 -m coverage run --data-file=/tmp/multissh3-final-coverage --branch --source=multiSSH3 -m pytest -ra
python3 -m coverage json --data-file=/tmp/multissh3-final-coverage -o /tmp/multissh3-final-coverage.json
python3 -c 'import json; d=json.load(open("/tmp/multissh3-final-coverage.json")); t=d["totals"]; p=100.0*t["covered_branches"]/t["num_branches"]; print("branch coverage: {:.2f}% ({}/{})".format(p,t["covered_branches"],t["num_branches"])); raise SystemExit(0 if p >= 70.0 else 1)'
```

Expected: pytest exits zero apart from documented optional skips; the final command prints at least `70.00%` and exits zero.

- [ ] **Step 4: Use the exact report to place any necessary final test in its responsibility file**

If Step 3 is below 70%, run:

```bash
python3 -m coverage report --data-file=/tmp/multissh3-final-coverage -m
```

Select the first still-uncovered deterministic case represented by a test in Tasks 7-10, extend that test with the missing input variant and an exact assertion, run that single test, then repeat Step 3. Do not add production branches, exclude lines, or weaken assertions to satisfy the metric. If the report exposes behavior not specified by the approved design, stop and request a design amendment instead of inventing semantics.

- [ ] **Step 5: Run non-coverage regression verification**

Run: `python3 -m pytest -ra`

Expected: all deterministic tests pass; only capability-based live SSH/TUI tests may skip.

- [ ] **Step 6: Verify working-tree scope**

Run:

```bash
git status --short
git diff --check
git diff --stat
```

Expected: only `multiSSH3.py`, test harness/test modules, and approved test documentation/configuration are changed; `git diff --check` is silent.

- [ ] **Step 7: Commit the coverage expansion**

```bash
git add tests/test_runtime_branch_matrix.py tests/test_config_validate.py
git commit -m "test: raise multiSSH3 branch coverage above 70 percent"
```

---

## Final Verification

- [ ] Run `python3 -m pytest -ra` and record exact pass/skip/fail counts.
- [ ] Run the fresh branch-coverage command from Task 10 and record exact statement and branch totals.
- [ ] Confirm branch coverage for all of `multiSSH3.py` is at least 70.00%.
- [ ] Confirm optional live SSH/TUI skips are the only skips in the deterministic environment.
- [ ] Run `git status --short` and confirm no uncommitted implementation artifacts remain.
- [ ] Review `git log --oneline` and verify each task produced a focused commit.
