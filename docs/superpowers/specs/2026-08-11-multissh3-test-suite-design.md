# multiSSH3 Full Test Suite Design

**Date:** 2026-08-11  
**Status:** Approved for implementation planning  
**Package:** multiSSH3 (single-module CLI: `multiSSH3.py`)

## Goal

Build a pytest-based test suite with broad coverage of multiSSH3, including curses TUI behavior. Prefer live localhost SSH and a real tty when available (developer machine). On CI or non-interactive boxes, the same suite still runs: live paths auto-fall back to mocks/stubs when SSH or TUI is not detected. No extra flags required for CI.

## Context

- `multiSSH3.py` is a ~4.3k-line single module (hostname expand/compact, Host model, SSH/SCP/IPMI execution, output merge, curses TUI, config/CLI).
- Existing `test/` is ad-hoc scripts and benches (not pytest), including duplicated expand/compact experiments and curses prototypes.
- Sibling package `multiCMD` already has a modular pytest layout (`tests/conftest.py`, `test_*.py`, capability probes, CLI subprocess helper) that this suite should mirror.

## Decisions (from brainstorming)

| Topic | Choice |
|---|---|
| Scope depth | Broad, including curses TUI |
| Environment | Developer-first live paths; CI runs mocks when SSH/TUI absent |
| Live SSH target | Auto-detect localhost; if SSH works, use it; else mock |
| Multi-host live | Use multiple addresses in `127.0.0.0/8` (same machine, multi-host capability) |
| Layout | New clean `tests/`; rename current `test/` → `test_legacy/` |
| Peripheral features | Core + TUI + SSH first-class; IPMI/SCP/sync thin smoke (mock + skip-if-missing) |
| Approach | multiCMD-style layered pytest with capability probes |

## Architecture

### Directory layout

```
multiSSH3/
  multiSSH3.py
  tests/                    # pytest suite (collected)
    conftest.py
    test_expand_hostnames.py
    test_compact_hostnames.py
    test_host.py
    test_config_cli.py
    test_output_merge.py
    test_run_command.py
    test_run_on_hosts.py
    test_curses_tui.py
    test_smoke_optional.py
  test_legacy/              # renamed from test/; not collected by pytest
    ...existing scripts/benches...
  docs/superpowers/specs/
    2026-08-11-multissh3-test-suite-design.md
```

Pytest should not collect `test_legacy/` (directory name outside default `test_*.py` / `tests/` discovery, or explicit `norecursedirs` if needed).

### Capability model

Probed once in `conftest.py`:

| Probe | When true | When false |
|---|---|---|
| `ssh_localhost_works` | Live SSH to addresses in `127.0.0.0/8` | Mock `run_command` / SSH subprocess boundary |
| `tty_or_curses_ok` | Prefer real `curses` / tty-backed tests | Stub window + injected keys |

Markers (documentation / optional filtering, not required for CI):

- `@pytest.mark.live_ssh`
- `@pytest.mark.live_tui`
- `@pytest.mark.smoke_optional`

Default command: `python -m pytest tests/` runs the full suite. Live tests self-adapt via fixtures; they do not fail the suite solely because sshd or a tty is missing.

### Coverage tiers

1. **Always (unit):** hostname expand/compact, IPv4 expand, Host model, config load, CLI/argparse, magic strings, output merge/grouping, non-curses color helpers, OrderedMultiSet.
2. **First-class (SSH + TUI):** single- and multi-host run paths; curses color parse, window write, host display selection, help/key handling — live when probes pass, mocked otherwise.
3. **Thin smoke:** IPMI arg/definition wiring; SCP/file-sync command construction — mocked; skip if `ipmitool` / `scp` binaries are missing.

## Fixtures and harness

### `conftest.py` responsibilities

- **`restore_module_globals` (autouse):** Snapshot and restore module-level globals that tests may mutate (pattern from multiCMD).
- **`run_cli(args)`:** Subprocess invocation of `multiSSH3.py` with captured stdout/stderr/returncode.
- **`ssh_localhost_works`:** Probe `ssh` to `127.0.0.1` with BatchMode and a short connect timeout. Failure → SSH fixtures supply mocks so the same tests still run; markers may filter live-only selection but are not required for a green CI run.
- **`local_ssh_hosts`:** When the probe passes, yield a small list of `127.0.0.0/8` addresses for real multi-host runs against one machine.
  - Default: 2–3 addresses (e.g. `127.0.0.1`, `127.0.0.2`, `127.0.0.3`).
  - Override via env: `MSSH_TEST_HOSTS=127.0.0.1,127.0.0.2,...`
  - Rationale: the entire `127.0.0.0/8` block is loopback; distinct addresses exercise multi-host merge/parallel logic without a second physical host.
- **`mock_ssh` / `fake_host`:** Build `Host` objects with canned stdout/stderr/rc; patch at the subprocess/SSH entry points so CI never opens remote sockets.
- **`curses_harness`:** Prefer real curses when a usable tty exists; otherwise a minimal stub window that records `addstr`/attributes and accepts injected key sequences.

### Live vs mock selection

Tests request high-level fixtures (`hosts`, `ssh_runner`, `curses_harness`) and do not branch on “CI vs laptop.” Fixtures choose live or mock from probes. Multi-host assertions use `local_ssh_hosts` when live, or N fake hosts on CI.

### Harness out of scope

- No Docker or extra VMs.
- No real remote cluster.
- No IPMI BMC hardware.

## Test modules

| File | Focus |
|---|---|
| `test_expand_hostnames.py` | Bracket/comma ranges, padding, hex/alpha, IPv4 expand, validation; port useful cases from legacy `test.py` against real `multiSSH3` APIs |
| `test_compact_hostnames.py` | Round-trip expand↔compact, multi-segment patterns, edge cases from legacy notes |
| `test_host.py` | `Host` construction, uuid defaults, repr, command/field wiring |
| `test_config_cli.py` | Config file chain/load, argparse/`process_args`, `--version`, defaults, magic-string substitution |
| `test_output_merge.py` | `can_merge`, `form_merge_groups`, `mergeOutput(s)`, greppable/json/quiet/`--no_output` |
| `test_run_command.py` | Single-host run: live via `127.x` when available, else mock; timeout/rc/stderr paths |
| `test_run_on_hosts.py` | Multi-host parallel (`local_ssh_hosts` or N fakes): merge-relevant ordering, unavailable-host handling, repeat/interval smoke |
| `test_curses_tui.py` | ANSI→curses attrs, `_curses_add_string_to_window`, `_get_hosts_to_display`, help key, display generation — live tty or stub harness |
| `test_smoke_optional.py` | Thin IPMI arg/definition wiring; SCP/sync command formation; skip if tools missing |

Migrate valuable assertions from `test_legacy/test.py` into the expand/compact modules; do not keep dual sources of truth for those cases.

## Error handling under test

- Bad hostname / empty expand input → stable empty or passthrough matching current API behavior.
- SSH auth/connect failure on a probed-good localhost → surface as host unavailable / non-zero rc, not hang.
- Timeout path: short timeout + slow command (`sleep`) asserts incomplete/timeout behavior.
- Config missing or malformed JSON → graceful error; not treated as success.
- Curses stub: missing tty never raises; live tty path still exercises real curses init when available.

**Flake policy**

- Live SSH failures *after* a successful probe → fail the test (real regression).
- Probe failure → mock path; never fail the suite for “no sshd on CI.”
- No network beyond `127.0.0.0/8`.

## Out of scope

- Real remote clusters, Docker/VMs, IPMI BMCs, password-prompt UX, ControlMaster longevity tests.
- Performance SLAs (legacy benches remain in `test_legacy/`).
- Large refactors of `multiSSH3.py` for testability; prefer patching at subprocess/SSH boundaries. Add minimal hooks only if a critical path is otherwise untestable.
- Adding CI workflow config in this repo (suite must be CI-safe; wiring is optional/follow-up).

## Success criteria

1. `python -m pytest tests/` passes on a box with no sshd and no tty (mocks/stubs).
2. Same command on a laptop with sshd + tty exercises live multi-`127.x` and TUI paths without extra flags.
3. Core logic regressions (expand/compact/merge/CLI) are caught without SSH.
4. Optional smoke tests skip cleanly when `ipmitool` / `scp` are absent.
5. Old ad-hoc suite is preserved under `test_legacy/` and is not part of default pytest collection.

## Implementation notes (non-binding)

- Follow multiCMD `tests/conftest.py` patterns for globals restore and `run_cli`.
- Prefer importing public and existing module-level helpers from `multiSSH3`; avoid re-implementing expand/compact in the test tree.
- Keep the suite dependency-light: pytest only for running tests; no new runtime dependencies for the package.
- Document probes and `MSSH_TEST_HOSTS` briefly in a short `tests/README.md` only if needed for contributors; otherwise conftest docstrings suffice.
