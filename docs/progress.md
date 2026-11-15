# multiSSH3: progress

Open work lives here and nowhere else (RULES, "Long work: the progress file"). Edit rows in place, in the commit that changes the work.

## Goal
- 2026-11-05, for every cas tool: "we improve the cas scripts iteratively. feel free to add scope / tasks if when doing some work, you noticed some other thing that can be improved with cas scripts." (the user; no goal for this repo alone is written in the repo)
- Picks that scope the open work (picks, not goal statements): 2026-11-05 "Deferred, design first (Recommended)" and "Add to the design pass (Recommended)" (docs/limitations.md, the Ctrl-C and TMOUT entries); 2026-11-12 "Add 3.11 to CI (Recommended)" (the main session's brief; not written in this repo). The deferral rule is under Standing decisions.

## Open work

### mssh 6.47 (no written plan: scope is the "deferred (6.47)" entries in docs/limitations.md and the "planned next" lines of the v6.46 GitHub release)
- **Paused 2026-11-14 at the user's ask, building:** branch feat/647 (worktree mssh-647), WIP e596798: the `$(` with `bang_hist` entry for a first TAB (a `!` that goes in a double quote is written outside it, `"zz"\!"x"`, everywhere), not yet tested. Left: its tests, the glue's own split of a double-quoted command in place of `compset -q` (one change for the `\"` entry, `$` and backticks in a quoted command, the bang case in a quoted command, and the backticks entry's quoted-command case), the other entries, Python 3.11 in CI, the version, the README, every acceptance run. Calls for review: the spelling everywhere rather than detecting `$(`; a later TAB on a word already holding `!` keeps 6.46's behaviour (a known-limitation candidate, not written).
- **6.47: the seven zsh entries marked "Kind: deferred (6.47)" in docs/limitations.md** (one `### zsh: ...` heading each, each with its own "Revisit when: 6.47: ..." plan). State: not started. Where: no 6.47 branch or worktree; main is 89be29f, the same commit as tag v6.46 on origin, and has no commit after 2026-11-08. Order from the v6.46 release notes: first the `$(` with `bang_hist` case (write the `!` outside the double quote), then the split value's lost quote after `=`. The `\"` entry also names a workaround in `_mssh`'s quoted-command path, and that report was sent by the user on 2026-11-10 ("I have send the zsh email"); the entry says so. After release: README "Upgrading to 6.47", bump the `multissh3==` pin in cas-toolbox/pyproject.toml (now 6.46) in the next Monday roll-up. From: the main session's plan; the user's deferral rule (Standing decisions, 2026-11-05).

### mssh glue: Ctrl-C and timed reads, a design pass (no written plan: no spec, branch or notes in the repo beyond the three entries)
- **The design pass itself.** State: not started, and past its date: the three entries below say "Revisit when: the glue's Ctrl-C and timed-read design pass after 6.43", and 6.43, 6.44 and 6.46 are released. Where: design first (brainstorm, spec), then build; no branch. Idea to test: `stty -isig` during the query and the reads (limitations.md, the Ctrl-C entries). From: "Deferred, design first (Recommended)", 2026-11-05.
- **TMOUT after Ctrl-R and in the line editor (bash before 5.2).** State: not started, waits for the design pass. Where: docs/limitations.md "TMOUT after Ctrl-R or in the line editor"; moving the wait's read into `$( )` fixed nothing (tested). From: "Deferred, design first (Recommended)" and "Add to the design pass (Recommended)", 2026-11-05.
- **Ctrl-C after Ctrl-R loses the first letter (bash 4.3, 4.4, 5.0), with the residual window.** State: not started, waits for the design pass. Where: docs/limitations.md "Ctrl-C after Ctrl-R loses the first letter"; the terminal is left cooked in a window of about 0.4% of tries, far wider under CPU shortage, and `test_bash_ctrl_c_right_after_ctrl_r_leaves_the_terminal_in_readline_s_mode` fails on a loaded host for this cause. From: "Deferred to design pass (Recommended)" and "Add to the design pass (Recommended)", 2026-11-05.
- **Ctrl-C during TAB's query loses the first letter (bash 4.3 to 5.2).** State: not started, waits for the design pass. Where: docs/limitations.md "Ctrl-C during TAB's query loses the first letter"; a line that looks cancelled runs on Enter. From: "Deferred to design pass (Recommended)" and "Keep deferred, release 6.43 (Recommended)", 2026-11-05.

### CI: Python 3.11 in the GitHub matrix (the next release of every cas repo)
- **Add "3.11" to the `pytest` job's matrix.** State: not started. Where: .github/workflows/test.yml has `python-version: ["3.9", "3.12", "3.14"]`; add 3.11 with the next release (main's last run, on 89be29f, is green in all five jobs). From: "Add 3.11 to CI (Recommended)", 2026-11-12 (via the main session).

### Autocomplete roadmap: parts after SP3 (docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md "Roadmap (decided)"; docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp3-design.md "Out of scope")
- **Remote probing: completing remote paths and commands from the remote host.** State: not started; no spec or plan (the SP3 spec calls it "a later sub-project"). Where: bound by SP3's principle 6, "Never reach a host with credentials" (no ssh session, no connection to any port; `ssh -G` only). The completion of a remote command's names from this machine's own completions (6.40 to 6.46) is not this part. From: the SP1 spec's "Roadmap (decided)".
- **The mssh TUI that imports the completion engine in-process.** State: not started; no spec or plan. Where: SP2 built `Terminal`, `Picker` and `LineEditor` in mssh_complete.py "so the future TUI can embed them"; multiSSH3TUI.py is the old prototype, unchanged since 6.01. From: the SP1 spec's "Roadmap (decided)".

### Upstream reports the user picked (not code in this repo)
- **Reports and replies still waiting.** State: paused on the upstream maintainers, and on the user's OK for the ssh-copy-id one. Where: ble.sh #745 (the `timeout=` report; open, our reply of 2026-11-09 is the last comment); zsh-autosuggestions #861 (open, no reply) and #862 (keys arriving together; posted 2026-11-06 at the user's pick "Draft and post it (Recommended)"; open, no reply); the zsh-workers report on the `\"` entry (sent by the user, 2026-11-10: "I have send the zsh email"); the ssh-copy-id HUP report (drafted in PR #1; given to the user to file on OpenSSH's bugzilla, 2026-11-14, "Give me the text to file"; when it is filed, docs/limitations.md "An interrupted `--copy_id -p`..." says so); the bash 4.2 SIGCHLD `conditional-sync` report for ble.sh (not drafted: docs/limitations.md "The centos7 test image patches ble.sh's conditional-sync"; drop the `sed` in tests/shells/Dockerfile.centos7 when the ble.sh pin moves to a fix). From: "KL + draft report (Recommended)" 2026-11-04; "Drop, record, draft upstream (Recommended)" 2026-10-24.

### Standing rows
- **Deferred work** is in `docs/limitations.md` (entries of kind "deferred"); each names when it is revisited. Today: the seven "deferred (6.47)" entries (row above), the three design-pass entries (rows above), and the centos7 image's ble.sh patch (last row above).

## Standing decisions
The user's rulings on how the cas repos are worked, one line each; a line changes only on the user's word. The cas monorepo's CLAUDE.md holds the same list, with how to reach the test machines.
- Deferrals (2026-11-05): "please do not ask me about features you think should defer to next version anymore. instead, note them down and after getting the current version done, start the next version right away. only ask me to approve things that are going into limitations that we do not have plans to fix it any time soon."
- The release gate (2026-11-09): "releasing a new version gate is only if it does not make an existing issue worse. even if the fix does not completely resolve the problem, if it makes the result more tolerable, we shall not gate it for release because there are still issues."
- Review before upload (2026-10-18): "commit and push is fine but when packaging, please follow the rule that need a code review before uvpack / upload to pypi".
- A test that passed only on a rerun (2026-11-06, "Green with a warning (Recommended)"): CI stays green with a warning, and "Before any upload, every such test still needs a written cause either way."
- Release pushes (2026-11-10, "Release OK covers it (Recommended)"): an OK for a release covers its push of main, the version tag and the GitHub release.
- Tests (2026-11-12, "Core per release, full at roll-up (Recommended)"): CI's own command on Python 3.14 and 3.11 in Docker before each release; the full gate (every Python in CI, macOS, EL7 on Python 3.11) before a Monday roll-up pin moves.
- CentOS 7 (2026-11-04): "for centos 7, which is already EOL, we only target all the last packages released for it. this also includes EPEL which is also in archive right now."
- EL8 (2026-11-05): "yes rocky 8 it is. let's also only test on them when you think test on real kernel is needed."
- macOS (2026-11-11): tests run on the user's own always-on Mac, as a standard user made for them, never with sudo.

## Questions waiting for the user
- None now. Decided 2026-11-15, a chief's decision (not the user's words): draft the ble.sh report on bash 4.2's lost SIGCHLD in `conditional-sync`; posting it stays the user's word, so the draft comes here as a question when it exists.

## Closed
- Autocomplete SP1 (engine, knowledge index, TAB for bash, zsh and fish, install, replay): done in 6.28, merge e566014.
- Autocomplete SP2 (grey suggestions, Ctrl-R picker, plain-bash line editor): done in 6.29, merge 2ced272 (review fixes 3f15fc3).
- Autocomplete SP3 (warnings before Enter, host prober, runtime-directory chain): done in 6.30, merge d17b3c4.
- 6.46 plan, a quote after a plain name's `=` stays (`dd if="zz`, `make VAR="`): done in ccdda60, released in 6.46 (tag v6.46, PyPI 6.46, 2026-11-09).
- 6.46 plan, inside backticks the extra quoting level in `_mssh_complete_compadd` and `_mssh`'s text loop: done in d8ab127, released in 6.46.
- 6.46 plan, history names beside local names in a word holding a `/` (split at the last `/`, added with `-p`), for a command typed as words, a quoted argument and after an unquoted `=`: done in 17cad9e and f89c18f, released in 6.46; the quoted-command, double-quoted-expansion and after-a-quote-at-`=` cases are the first 6.47 entry.
- 6.45 (zsh backticks, quote at a remote option's `=`, history name beside a local name): built on feat/645 (0c2741d), never released alone; released inside 6.46 (the v6.46 GitHub release says so).
