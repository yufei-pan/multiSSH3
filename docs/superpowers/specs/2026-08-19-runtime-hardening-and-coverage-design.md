# multiSSH3 Runtime Hardening and Coverage Design

**Date:** 2026-08-19
**Status:** Approved for implementation planning
**Package:** multiSSH3 (single-module CLI: `multiSSH3.py`)

## Goal

Correct confirmed failure-path and CLI defects without changing multiSSH3's public API, then expand deterministic tests until branch coverage for the complete packaged `multiSSH3.py` module is at least 70%.

The work uses staged hardening with small internal extractions. It does not redesign the execution engine or impose a special coverage quota on curses or any other subsystem.

## Context

The current suite passes 163 tests with two environment-dependent skips. Subprocess-aware coverage reports 1,688 of 2,811 statements covered (60.05%) and 750 of 1,437 branches covered (52.19%). Utility code is comparatively well tested, while execution, orchestration, persistence, `main`, and the curses event loop contain the largest behavioral gaps.

Confirmed defects include a semaphore-held EMFILE retry, inconsistent timeout return codes, malformed unavailable-host persistence, a non-terminating shell fallback, invalid repeat handling, shifted repeat intervals, an unreachable zero-concurrency branch, and a suppressed missing-config warning.

## Decisions

| Topic | Decision |
|---|---|
| Implementation shape | Staged hardening with narrow helpers; preserve public APIs |
| EMFILE | Release the semaphore, back off, and retry within the existing retry budget |
| Timeout result | A timeout initiated by multiSSH3 always returns `124` |
| Unavailable-host state | Canonical one-record-per-line format and atomic replacement; discard malformed and expired records |
| Missing local `sh` | Preserve SSH-to-localhost fallback and return its result immediately |
| IPMI construction | Preserve current behavior; document that real-hardware compatibility must be verified before changing it |
| Repeat count | Reject values below one during argument parsing |
| Repeat interval | Run immediately and sleep only between subsequent runs |
| `max_connections=0` | Use the detected safe file-descriptor limit |
| Missing explicit config | Warn with the requested path and continue |
| Coverage scope | At least 70% branch coverage across all of `multiSSH3.py`; no subsystem-specific quota |
| Environment | The coverage gate must pass without live SSH, a real TTY, or IPMI hardware |

## Architecture and Scope

Production changes remain in `multiSSH3.py`. Existing command names, public function signatures, `Host` fields, and output formats remain unchanged except for the selected error and return-code corrections.

Narrow helpers may be introduced for responsibilities that need an isolated contract:

- normalizing concurrency settings;
- parsing and atomically writing unavailable-host records;
- validating positive repeat counts.

The subprocess lifecycle remains part of `run_command`. Retry control may be reshaped locally so an EMFILE retry happens only after leaving the semaphore, but command construction and the broader execution model will not be extracted into a new subsystem.

The test harness in `tests/conftest.py` will be extended with deterministic process, clock, terminal-window, and panel behavior as needed. New test files may be added by responsibility rather than continuing to enlarge unrelated modules.

## Runtime Behavior

### EMFILE retry

An `OSError` with errno 24 during process launch marks the attempt for retry. The semaphore is released before waiting. Backoff starts at 0.1 seconds, doubles per failed launch, and is capped at one second. Each failed launch consumes the existing retry budget.

The already formatted command is reused for EMFILE attempts. Exhaustion sets a nonzero host result and records a clear terminal error; it must not recurse while holding a concurrency permit or wait indefinitely.

Other `OSError` values retain their existing exception behavior.

### Timeout finalization

`run_command` records when multiSSH3, rather than the child process itself, initiates timeout termination. Signal delivery, process termination, stream draining, and reader/writer thread cleanup still occur. After cleanup, a multiSSH3 timeout overrides the raw signal result with return code `124`.

Unavailable-host classification uses this deterministic result. Ordinary child exits, user emergency stops, and unrelated signals retain their existing result handling.

### Shell fallback

When shell mode is requested and `sh` is unavailable, the existing SSH-to-localhost fallback remains. The outer call returns immediately after the fallback call, so it cannot continue with an empty command or execute twice.

### IPMI compatibility

The existing shell and direct argument construction for `ipmitool` and `redfishtool` will not change in this effort. A focused comment will identify it as a suspected compatibility workaround and require verification on a real IPMI machine before it is refactored. Tests may characterize current construction but must not redefine it.

## Persistent Unavailable-Host State

Unavailable-host state uses one `host,expiry` record per line. Reading ignores malformed records and records whose expiry is not in the future. Current available hosts are removed before writing.

Every update writes the complete canonical state to a uniquely named temporary file in the destination directory, flushes and closes it, then uses `os.replace` for atomic publication. All records end in a newline, including the first file creation.

Read or write failures remain nonfatal and emit a warning. Temporary files are cleaned up when an update fails after creation.

## CLI Semantics

The repeat argument uses a positive-integer parser contract. Zero and negative values fail argument parsing with the standard argparse usage error and exit code 2, preventing `hosts` from being uninitialized.

For repeated commands, attempt zero runs immediately. Before each later attempt, multiSSH3 sleeps for the requested interval. It never sleeps before the first attempt or after the final attempt.

Concurrency normalization distinguishes the following inputs:

- omitted or `None`: `4 * os.cpu_count()`;
- zero: the detected safe file-descriptor-derived limit;
- negative: the absolute value multiplied by `os.cpu_count()`;
- positive: the supplied value, subject to the existing safe-limit clamp.

If zero is requested but no positive safe limit was detected, normalization falls back to `4 * os.cpu_count()`.

When an explicit `--config_file` path does not exist, processing prints a warning containing that path and continues with normal defaults. The warning path must not access the remaining raw argument list as though it were a parsed namespace.

## Test Design

### Execution lifecycle

Scripted fake processes and clocks will cover:

- successful and failed launches;
- EMFILE release, retry ordering, backoff, success after retry, and exhaustion;
- exact timeout code `124`, signal/terminate calls, stream draining, and thread cleanup;
- emergency stop and non-timeout nonzero results;
- subprocess and communication exceptions;
- IPMI retry behavior without changing its command contract;
- rsync-to-scp fallback.

The deterministic timeout test is mandatory. The optional live-SSH timeout test remains and will assert the same externally visible contract when SSH is available.

### Orchestration and persistence

Tests will assert the exact normalized concurrency value passed to execution for omitted, zero, negative, positive, and clamped inputs. They will verify constructed `Host` fields and exact rsync/scp argv for send, gather, sync, and fallback modes.

Persistence tests will use isolated temporary paths and cover first creation, multiple records, malformed input, expired records, available-host removal, atomic replacement, and nonfatal I/O failures.

### CLI lifecycle

Direct `main(args)` tests will replace external execution and exit boundaries. They will assert repeat ordering, sleep placement, host success/failure aggregation, exit codes, success/failed summaries, missing configuration, and history behavior. Subprocess smoke tests remain for genuine argparse exit behavior.

Script mode tests will assert every implied flag and relevant interactions with explicitly supplied options. Repeat validation will cover zero, negative, and valid positive values.

### Curses and remaining branches

The fake curses harness will support recorded windows, panels, terminal dimensions, refreshes, and injected key sequences. Tests may cover resize, navigation, help, scrolling, history, cursor movement, selective redraw, single/multi-window layouts, and error recovery when those branches offer useful behavioral assertions.

Curses has no independent target. Coverage work will select deterministic branches across the entire module based on risk and assertion quality. Smaller stable functions such as timed input, signal handling, config-file processing, and history recording will also receive direct tests.

Tests must assert resulting state, output, calls, or errors. Assertions that merely require a non-null result, any one of several promised flags, or an unrelated truthy field do not count as adequate coverage for this effort.

## Coverage Measurement

The authoritative scope is the complete packaged `multiSSH3.py` module, excluding tests and auxiliary non-packaged scripts. Coverage runs with branch tracing enabled while executing the configured `tests/` suite.

Success is calculated from Coverage.py JSON totals:

```text
covered_branches / num_branches >= 0.70
```

Coverage.py's combined line-and-branch display percentage is not the acceptance metric. Optional live tests may skip; their absence must not lower the deterministic run below the gate. The final report will include exact covered and total statement and branch counts, test pass/skip counts, and any environment-dependent caveats.

## Files Expected to Change

- `multiSSH3.py`
- `tests/conftest.py`
- existing focused test modules under `tests/`
- new focused test modules under `tests/` when that keeps responsibilities clear
- coverage configuration or developer-test documentation only if needed to make the 70% command reproducible

No runtime dependency will be added for testing support.

## Non-Goals

- Redesigning multiSSH3 into multiple production modules.
- Changing public APIs or adding `Host` fields.
- Changing IPMI command construction before real-hardware verification.
- Requiring live SSH, a real terminal, or IPMI hardware for the coverage gate.
- Achieving 100% coverage or writing tests solely to execute defensively unreachable code.
- Adding remote infrastructure, containers, or CI workflow configuration.

## Risks and Mitigations

- **Global state leaks between tests:** expand the autouse restoration fixture and assert cleanup explicitly.
- **Threading flakes:** use scripted processes, events, bounded joins, and fake clocks; never depend on arbitrary wall-clock sleeps.
- **Curses implementation coupling:** assert user-visible state and recorded window operations rather than entire internal call snapshots.
- **Coverage-driven low-value tests:** require semantic assertions and keep the target global rather than assigning quotas to individual functions.
- **Behavior drift in a large module:** implement each correction test-first and run focused tests before the complete suite.

## Success Criteria

1. All nine behavior decisions in this specification are implemented without unintended public-interface changes.
2. The deterministic pytest suite passes when live SSH and TTY tests skip.
3. Exact branch coverage for all of `multiSSH3.py` is at least 70%.
4. Timeout behavior consistently returns `124` and feeds unavailable-host tracking.
5. EMFILE handling releases concurrency permits and terminates after bounded retries.
6. Unavailable-host persistence is canonical, atomic, and excludes malformed or expired records.
7. Repeat, interval, concurrency-zero, shell-fallback, and missing-config behaviors match this specification.
8. IPMI construction remains unchanged and carries the real-hardware verification note.
