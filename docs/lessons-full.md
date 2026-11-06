# Lessons: full entries

Why this project's APIs, formats and agreed behaviours had to change. `lessons.md` has one line per
entry: read that first, and look entries up here by date and name rather than reading this whole. New
entries go last, in the same commit as the change:

```markdown
## YYYY-MM-DD <short name>
- Changed: ...
- Why we had to change: ...
- Original design was wrong because: ...
- Lesson: ...
```

## 2026-10-28 multiSSH3: mssh-complete eval moved to tests/replay.py
- Changed: `mssh-complete eval [HISTORY_FILE]` (with `--synthetic`, `--diagnostics`, `--since`, `--limit`) is no longer a subcommand of the installed tool. It prints `mssh-complete eval moved to the source tree: python3 tests/replay.py` and exits 2. The same replay runs from a checkout as `python3 tests/replay.py [--synthetic|--diagnostics] [--since T] [--limit N] [HISTORY]`; the tests import it from there.
- Why we had to change: the replay (about 360 lines, 3.7% of the module) was compiled by every TAB's engine and shipped to every operator, for a tuning job only the developer does. Its output is aggregate tables, nothing an operator uses at the prompt.
- Original design was wrong because: the spec made the yardstick for ranking changes an installed operator command, so a development tool grew inside the product, and its own fixes (printing host names stdout cannot encode) went into the shipped module.
- Lesson: ship what the operator runs; keep measuring and tuning tools in the source tree next to the tests that use them. When a subcommand goes, make the old name fail with the one-line fix, not the usage text.

## 2026-10-28 multiSSH3: Completion index format 3
- Changed: `INDEX_FORMAT` is 3. An index of format 2 (what 0.11 wrote) is ignored and rebuilt, once, on the first TAB after the upgrade (or by `mssh --completion install`). The reader lost its guards for sections an older index lacked (`host_meta` and `alias_users` counts, `feature_uses`, `_password_free_help`, `OPTION_NO_EFFECT` via getattr).
- Why we had to change: sections were added through 6.32-6.38 without a format bump, so every reader had to guard each one against an index that might not hold it.
- Original design was wrong because: the format version was there to make a reader refuse what it cannot read, and was not bumped when the format changed. The index is a cache rebuilt in about a second, so a bump costs one rebuild; the guards cost code on every query, forever.
- Lesson: a cache's format version is cheap to bump: bump it with every change to what is stored, and never teach the reader to cope with old caches. While an older engine still runs (a shell started before the upgrade), it rebuilds its own format under the same name; the two replace each other until those shells end, which is harmless for a cache.

## 2026-10-28 multiSSH3: ssh timeout options always passed
- Changed: what mssh hands ssh, scp, rsync's ssh and ssh-copy-id. `-o ConnectTimeout=`, `-o ServerAliveInterval=` and `-o ServerAliveCountMax=` (from `DEFAULT_SSH_*`, 0 leaving one out) are always passed, placed after `-ea`'s options so an `-o` there wins. mssh no longer reads the ssh config files (with their `Include`s, `-ea '-F FILE'`, an `ssh -G` per host) to leave out an option the config sets. An `-ea` `ServerAliveInterval` now also gets mssh's `ServerAliveCountMax` (4).
- Why we had to change: honouring the ssh config took a reader of ssh's config grammar, an `-ea` parser and an `ssh -G` per host (which runs `Match exec` lines): about 120 code and 180 test lines, to change how long a dead host takes to fail.
- Original design was wrong because: it tried to merge two sources of the same setting by re-implementing ssh's own precedence outside ssh. ssh already has an order (first value wins, command line before config); mssh only had to choose its place in it.
- Lesson: when a tool has a precedence rule, place your values in it (after the user's, as here) instead of reading the tool's configuration to predict it. A setting of our own (`DEFAULT_SSH_*`, 0 to opt out) is the interface; the other tool's config files are not.

## 2026-10-28 multiSSH3: Rebuild and prober locks are flocks
- Changed: runtime files of mssh-complete. `complete-index.lock` and `probe.lock` are empty files held with `flock(LOCK_EX|LOCK_NB)`: the query that starts a rebuild or prober takes the lock and passes the descriptor to the child, which holds it until it exits. A failed rebuild touches `complete-index.failed`; no rebuild starts while it is younger than 60 s. `mssh-complete rebuild --lock X` and `probe --lock X` are accepted and ignored. Without `fcntl` nothing locks.
- Why we had to change: the lock files held a pid, a start time and a token; a lock older than 60 s was stale and taken over, so a slow resolver or a suspended machine let a second prober start beside the first, and their writes undid each other's. Each fix added a branch (tokens, refreshes, a "failed" mark kept in the lock).
- Original design was wrong because: it built a lease out of file contents and timestamps, where the kernel has a lock that is released however the holder ends.
- Lesson: for "one at a time" between local processes, use the kernel's lock and let the holder's exit release it; never infer liveness from a pid or a timestamp. Keep accepting the old flags so an older engine still running mid-upgrade gets no usage error.

## 2026-10-28 multiSSH3: SIGPIPE before the run
- Changed: CLI exit status. Output before the run (`-h`, `-V`, `--generate_config_file`, a usage error, the prompts) into a closed pipe now ends mssh by SIGPIPE's default action: a shell still reports 141, a Python subprocess caller sees -13 (6.38: exit code 141); Windows exits 120. A message `eprint` cannot write to stderr is dropped, not written to stdout.
- Why we had to change: exiting 141 by hand took `_WatchedStream` and `_exit_if_output_closed` (about 60 lines), and the fallback of writing stderr's messages to stdout corrupted `-j` output and made `mssh ... 2>&1 | true` exit 1 under `PYTHONUNBUFFERED=1`.
- Original design was wrong because: it rebuilt in Python what the OS does for every command-line tool (Python ignores SIGPIPE at start), and the stdout fallback mixed diagnostics into the results stream.
- Lesson: let the OS default apply where the tool behaves like any other filter; restore the old disposition for the part that must survive a closed pipe (the run). Never send diagnostics to stdout when stderr fails.

## 2026-10-28 multiSSH3: runtime_dir(create) ignored
- Changed: public function `multiSSH3.runtime_dir(create=True)` and `_unavailable_hosts_file_path(create=True)` accept `create` and ignore it: reading sets the directory up (0700, created when missing) as writing does. `mssh_complete.cache_dir` lost its `create` parameter.
- Why we had to change: the read path (`create=False`) had to predict where a write would go without creating anything, and got it wrong in 6.36 (three release tests failed).
- Original design was wrong because: two code paths answered one question ("where is our state?"), so they could disagree.
- Lesson: one function, one answer; a read that sets up a private directory is cheaper than a second resolver. The parameter stays for callers written for 6.38 (an mssh_complete 0.11 beside multiSSH3 6.39 still calls `create=False`).

## 2026-10-28 multiSSH3: compact_hostnames / expand_hostnames hosts_only ignored
- Changed: public functions `compact_hostnames(..., hosts_only=False)` and `expand_hostnames(hosts, hosts_only=False)` accept `hosts_only` and ignore it. Output headers, merged group names and `Skipping hosts:` use `compact_hostnames_local`, so names that do not compact into one range are listed in natural order (`db2,db10`), not sorted as text.
- Why we had to change: compacting a name list for display expanded and verified it a second time (DNS included) and needed a check that the shown name was right.
- Original design was wrong because: display compaction reused the verifying compactor meant for host input.
- Lesson: a function that displays names should not resolve them; keep a released keyword accepted when its meaning goes away.

## 2026-10-28 multiSSH3: expand_ranges gives a mixed text back whole
- Changed: `mssh_complete.expand_ranges(text, limit)` returns a text that mixes number and letter groups (`n[1-2]x[a-b]`) whole, instead of half expanded (`n1x[a-b]`, `n2x[a-b]`); the range warning counts names with their repeats past 4,096 names.
- Why we had to change: exact counting took a repeat analysis and a second counter.
- Original design was wrong because: it promised exact counts for ranges far past anything shown to the operator.
- Lesson: match precision to what the operator reads; above the display limit an upper bound is enough.

## 2026-10-28 multiSSH3: mssh-complete edit --expand and install on fish 2
- Changed: `mssh-complete edit --expand` is accepted and ignored (bash 4.2/4.3 get no prompt; `expand=1` from an older glue means "no prompt"). `mssh --completion install fish` on fish 2 succeeds (exit 0) and the glue registers nothing; 6.38 refused with exit 1.
- Why we had to change: the 46-line PS1 expander served bash before 4.4; the fish version probe (about 90 lines with tests) served a fish no supported distribution ships.
- Original design was wrong because: both added our own code for end-of-life platforms the glue already handled (bash 4.4's `${PS1@P}`, the glue's own fish < 3 guard).
- Lesson: support a floor in one place (the glue's guard); keep old flags accepted so an old caller gets the new behaviour, not an argparse error.

## 2026-11-01 multiSSH3: the bash glue under ble.sh sends the word as typed
- Changed: the glue/engine protocol. The word of a `bash` request with `ble=1` is read as typed: the engine lexes it (`_shell_word`), as it does zsh's and fish's. The bash glue under ble.sh builds the request from ble.sh's own record of the line (`comp_line`, `comp_point`, `COMPS`, `progcomp_prefix`), and falls back to `COMP_LINE` and `$2` when they are missing; a 6.39 glue's word (ble.sh's requoted `$2`) reads right the same way. The bash glue no longer reads a `C` record's fourth field (the unescaped text); the engine still sends it for older glues.
- Why we had to change: ble.sh hands a completion function its words evaluated and quoted again and builds `COMP_LINE` from them, so a quoted remote command completed nothing, a typed `~/x` reached the engine as the local home, and an escaped argument made the next word a command name. The fourth field existed only to hand mssh's words to readline's file name mode, which mixed them with local file names (a `/` after a remote word naming a local directory, a bare `~`).
- Original design was wrong because: it took ble.sh's emulation of bash's completion interface for the original, checked only for plain words, and it fixed the file name mode's damage per word (an unescaped copy) instead of keeping mssh's words out of that mode.
- Lesson: when a shell emulates another's completion interface, check what the emulation hands over for quoted and expanded words, and read the line from the emulator's own record of it when it keeps one, with the emulation as the fallback. When one switch applies to a whole reply, keep words that must not get it out of the reply while it is on, rather than shaping them for it.

## 2026-11-01 multiSSH3: --add_control_master_config refuses another owner's ~/.ssh/config link
- Changed: `mssh --add_control_master_config` no longer follows a `~/.ssh/config` symlink of anyone but the writer (or root): it prints one line, `Error adding ControlMaster configuration: '...' is a symlink owned by someone else, not writing through it`, with no traceback, and changes nothing. As root (6.39) it wrote the block wherever such a link pointed.
- Why we had to change: `--store_config_file` already refused such a link, and the approved limitation said this command followed the same rule, but its write path (`_replace_file` with `follow=True`) never checked the owner; a planted link received the block wherever it pointed.
- Original design was wrong because: two commands that write a user's dotfile shared the writer but not the rule about whose link may be followed; the rule sat in one caller.
- Lesson: put a safety rule where every writer passes (or check every caller against it when it is added), and test the documented rule against each command that claims it.

## 2026-11-01 multiSSH3: under sudo, the invoking user's files are written with their rights
- Changed: when mssh runs as root with `SUDO_UID` set and a config (the link itself or the file; for a missing one the nearest directory above it) or `~/.ssh/config` belongs to that user, it is looked at, backed up and written with that user's effective uid, gid (`SUDO_GID`) and groups (`_as_user`), and root's again afterwards. Their link is followed only where they may write; the `.bak` and new files are theirs. `_own_symlink` and `_replace_file` compare owners with the effective uid, not the real one. A path of anyone else, and root without sudo, are as before.
- Why we had to change: under `sudo -E` a user's own dotfiles link counted as someone else's: `b` moved the link to the `.bak` and put a regular file in its place, a new config was root's `0600` file the user could not read, and an NFS home that squashes root could not be written at all.
- Original design was wrong because: it decided "whose file is this" from the real uid alone, so root could not tell the user who ran sudo from a stranger, and it then had root do the user's write with root's rights, where the kernel's own checks for that user were the rule we wanted.
- Lesson: when root acts on a user's behalf, do it with that user's rights and let the kernel decide what they may write, rather than re-implementing their permissions as root. Compare ownership with the effective uid, which is the identity the write runs under.
