# Final Integration Review Fix Wave

**Date:** 2026-08-19

**Base:** `cd37b04a4d284351ce2021337dead51f4dee5f9b`

**Status:** PASS

## Finding-by-finding changes and evidence

### 1. Numeric configuration defaults bypassed positive repeat validation

- Added a real CLI regression that loads `{"DEFAULT_REPEAT": 0}` from an explicit JSON config and requires argparse exit code 2.
- Added explicit post-parse normalization through `_positive_int`; invalid parsed/default values are routed through `parser.error(...)`.
- RED: `test_cli_rejects_nonpositive_repeat_from_numeric_config_default` returned 1 with `UnboundLocalError: ... 'hosts' ... not associated with a value` instead of 2.
- GREEN: the config regression and the two existing explicit nonpositive `--repeat` cases passed: `3 passed`.

### 2. Timeout persistence depended on the timeout marker being last

- Changed unreachable classification to require return code 124 and find a `Timeout!` marker anywhere in `host.stderr`.
- Added a regression with `stderr == ["Timeout!", "late child stderr"]`.
- RED: the persisted unavailable-host set was empty.
- GREEN: both the original timeout persistence case and the late-stderr case passed: `2 passed`.

### 3. `skip_unreachable=False` discarded unrelated persisted state

- Built the persistence input from a copy of the canonical global unavailable-host state merged with the current local state, while continuing to remove currently available hosts through `availableHosts`.
- Added an integration regression through `run_command_on_hosts(skip_unreachable=False)` with one currently available record and one unrelated unavailable record.
- RED: the file was rewritten to an empty state and the unrelated record disappeared.
- GREEN: the currently available record was removed while the unrelated record remained on disk and in `__globalUnavailableHosts`; the focused persistence group passed: `3 passed`.

### 4. EMFILE retry covered post-launch lifecycle failures

- Reset `proc` per launch attempt and permit EMFILE retry only when `Popen` did not return a process.
- Added a regression whose launched process raises EMFILE from `poll()` and requires the error to propagate after exactly one `Popen`.
- RED: no OSError propagated because the command was relaunched until the retry budget was exhausted.
- GREEN: the post-launch regression, launch-time semaphore-safe retry, and launch-time exhaustion cases passed: `3 passed`.

### 5. `_binPaths` test mutations were not failure-safe

- Replaced all direct `_binPaths.pop(...)` calls in the affected tests with `monkeypatch.delitem(..., raising=False)`.
- Extended the autouse global-restoration fixture to snapshot and restore `_binPaths` by assigning a fresh dictionary.
- Confirmed no direct `_binPaths.pop`, `.clear`, `.update`, or `del` mutations remain under `tests/`.

### 6. Permissive output assertion covered neither promised behavior exactly

- Replaced the greppable/disjunctive test with a plain-output test that exactly observes `SSH not reachable!` and the normalized stderr value.
- Moved the partial-buffer contract to the curses display lifecycle and asserted that `buffer-tail` is rendered exactly once.
- Kept the compound ANSI case focused on ANSI rendering and escape removal.
- Focused output/isolation group passed: `5 passed`.

### 7. Read-side unavailable-host I/O failure lacked coverage

- Added a read failure case that injects `OSError("read failed")` and asserts both an empty result and the exact warning.
- The existing production behavior satisfied the characterization immediately: `1 passed`.

## Verification

### Neighboring tests

Command:

```text
python3 -m pytest tests/test_config_cli.py tests/test_cli_branches.py tests/test_main_lifecycle.py tests/test_unavailable_hosts.py tests/test_run_on_hosts.py tests/test_run_on_hosts_modes.py tests/test_run_command.py tests/test_run_command_branches.py tests/test_runtime_branch_matrix.py tests/test_curses_event_loop.py -q
```

Result: **143 passed, 2 skipped**.

### Full suite

Command: `python3 -m pytest -ra`

Result: **238 passed, 2 skipped, 0 failed** out of 240 collected tests.

The two capability-based skips were:

- `tests/test_run_command.py:121`: timeout path covered under live SSH.
- `tests/test_run_on_hosts.py:47`: live SSH not available.

### Fresh branch coverage

The prior data file was erased, then the full suite ran with branch tracing and `--source=multiSSH3`. Coverage JSON arithmetic reported:

- Statements: **2240/2846 (78.71%)**.
- Branches: **1019/1424 (71.56%)**.

The acceptance ratio is `1019 / 1424 = 0.715589...`, above the required 0.70.

### Static and scope checks

- `python3 -m py_compile` succeeded for the production module and all changed Python test files.
- `git diff --check` was silent.
- Direct `_binPaths` destructive-mutation search under `tests/` returned no matches.

## Files changed

- `multiSSH3.py`
- `tests/conftest.py`
- `tests/test_config_cli.py`
- `tests/test_curses_event_loop.py`
- `tests/test_run_command_branches.py`
- `tests/test_runtime_branch_matrix.py`
- `tests/test_unavailable_hosts.py`
- `.superpowers/sdd/2026-08-19-runtime-hardening-and-coverage/final-fix-report.md`

## Self-review

- The production diff is limited to explicit repeat validation, timeout marker classification, unavailable-host state merging, and launch-only EMFILE retry eligibility.
- Public function signatures, command names, Host fields, output formats outside the reviewed correction, and IPMI argv construction are unchanged.
- The production edits use Python 3.6-compatible syntax.
- The accepted history fixture ruling was not changed, and the deferred successful-host summary assertion was not added.
- Tests assert externally observable exit codes, persistence state, launch count, formatted output, and warnings; no source-text assertions or disjunctions were introduced.

## Concerns

- A post-launch OSError continues to follow the pre-existing non-EMFILE behavior and propagates. The fix prevents a second command launch, but it does not introduce a new best-effort terminate/join cleanup path for a process that is still alive when such an exceptional lifecycle failure occurs. The regression uses completed in-memory streams, so no test leak occurs; a real still-running child remains a theoretical cleanup concern outside this minimum review fix.
- Live SSH was unavailable in this environment, accounting for the two documented skips. Deterministic timeout and orchestration coverage passed.
