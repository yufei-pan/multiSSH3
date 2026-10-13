# mssh Autocomplete — SP3: Warnings Before Enter

**Date:** 2026-10-12
**Status:** Design approved in conversation; written spec awaiting review
**Package:** multiSSH3 (`mssh_complete.py`, shell glue, `multiSSH3.py`)
**Builds on:** `docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md` (SP1: engine, index, TAB) and `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp2-design.md` (SP2: grey text, picker, line editor). Everything they decided still holds unless this spec says otherwise.

## Goal

Catch mistakes in an mssh line while it is typed, before Enter runs it on many hosts:

- **Unknown host:** a name mssh would reject (`gpu017` for `gpu17`), with "did you mean …" when one known host is clearly meant.
- **Range surprises:** a range or alias with members mssh would reject (`node[1-16]` when the nodes are `node01`–`node16`).
- **Unreachable host:** a host that failed in the operator's recent mssh runs, or stopped answering ping.
- **Conflicting options:** options argparse rejects together, a non-repeatable option given twice, and options that do nothing in this combination.

Warnings mark the offending word and show one reason line under the prompt. They never block Enter and never cost a keystroke.

SP3 also moves all of mssh's runtime state to one fallback chain of private, reboot-cleared directories, so mssh keeps working where `/run/user/<uid>` is missing.

The roadmap's third part, remote probing (completing remote paths and commands), becomes its own later sub-project.

## Principles

Inherited from SP1 and SP2:

1. Never cost keystrokes: nothing alters typed text; Enter runs what was typed.
2. Never get in the way: anything slow, missing or failing falls back silently; nothing is printed unless it is a warning this spec defines.
3. Never change what mssh runs.
4. Usefulness before speed.

New in SP3:

5. **When unsure, say nothing.** A false alarm costs more than a missed one. A warning needs a definite answer (DNS says the name does not exist; the host answered ping before and now does not); errors, timeouts and missing tools produce no warning.
6. **Never reach a host with credentials.** Nothing opens an ssh session, connects to any port, or tries a password or key, so background checks cannot trip fail2ban or lock out the login node. `ssh -G` (which only reads the ssh config) is allowed. This rule also binds the later remote-probing sub-project.

## Decisions

| Topic | Decision |
|---|---|
| Scope | Warnings and the host knowledge behind them; remote probing is a later sub-project |
| Checks | Unknown host, range surprises, unreachable host, conflicting options (details below) |
| Display | Mark the word (red underline) and one reason line under the prompt; never blocks Enter. zsh, ble.sh and the bash line editor mark and explain; fish shows the reason only; plain bash without the editor shows warnings in the Ctrl-R picker only |
| What counts as unknown | mssh's own rule: not an IP, alias or hosts-file entry, DNS says the name does not exist, and `ssh -G` shows no ssh config that singles it out (HostName rewrite, ProxyJump, ProxyCommand; catch-all `Host *` blocks excluded, as mssh does) |
| Reachability | mssh's `unavailable_hosts.csv` (hosts that failed in the operator's runs) and ICMP ping; ping silence counts only for a host that answered ping within the ping expiry. No port-22 or other TCP checks (fail2ban in `ddos` / `aggressive` mode counts a bare connect as a failure, and every user on a login node shares its address) |
| Architecture | Detached prober plus a cache (approach A): queries never wait on the network; a short-lived `mssh-complete probe`, started like the index rebuild and guarded by a lock, fills the cache |
| Prober limits | Adaptive, no fixed counts: parallelism follows mssh's own `max_connections` rule (the mssh config's `DEFAULT_MAX_CONNECTIONS`, default 4 × CPUs, clamped by the open-file limit), halved while the load average is at or above the CPU count and on running out of descriptors or processes; every host on the line is checked, up to the range-member limit; a run lasts while there is work (at most 2 minutes) at low CPU priority |
| Ping expiry | Same as mssh's unreachable-host expiry (`DEFAULT_UNAVAILABLE_HOST_EXPIRY`, 600 s unless the mssh config changes it); `MSSH_COMPLETE_PING_TTL` (seconds) overrides |
| Runtime storage | One chain for all runtime state of mssh and mssh-complete: `$XDG_RUNTIME_DIR/multiSSH3` → `/run/user/<uid>/multiSSH3` → `/dev/shm/multiSSH3-<uid>` → `<tempdir>/multiSSH3-<uid>`; nothing SP3 writes survives a reboot |
| Words checked | Only finished words: the word under or just before the cursor is checked once the cursor leaves it |
| Several warnings | Order: unknown host, range, unreachable, options; leftmost first within a kind. The reason line shows the first and `(+N more)`; the picker lists up to three |
| Host semantics | Stay in `multiSSH3.py`: `host_validity`, the runtime-directory chain and the table of options with no effect live there |

## Context

What SP1 and SP2 already give:

- `Response.diagnostics` (always empty so far) and the protocol's `W` record were reserved for SP3. Request flags are parsed as `key=value` pairs and unknown ones are ignored, so an old engine ignores `diag=1`.
- `multiSSH3.expand_hostnames_local(hosts)` expands ranges and env / env-file aliases without DNS and lists the names only DNS or the ssh config could confirm.
- The index holds the host table (hosts file, explicit ssh config `Host` names, known_hosts, ARP, history, aliases and their members) and mssh's unavailable hosts at build time; `HostTable.unavailable` lowers their rank.
- The parser spec records argparse's mutually exclusive groups (`OptionSpec.group`) and whether an option may repeat.
- `mssh_complete.cache_dir()` mirrors `multiSSH3._unavailable_hosts_file_path()`; `test_cache_dir_matches_multissh3` checks they agree.

How mssh decides a host is invalid today (`__validate_expand_hostname`): an IP, an env / env-file alias, a hosts-file entry or a name DNS resolves (`getIP`) is valid; otherwise `_ssh_config_target(name)` asks `ssh -G` (no connection) and accepts names the config maps to another HostName or puts behind ProxyJump / ProxyCommand, comparing with a made-up name so a catch-all `Host *` block does not validate typos. `_resolve_dns` folds "no such name" and "no answer" into one `None`.

mssh's `unavailable_hosts.csv` holds `host,expiry` lines (expiry in `time.monotonic()` seconds) under a `#boot_id,<id>` header; an entry lasts `--unavailable_host_expiry` seconds (default 600); a file from another boot is discarded. A host that succeeds is removed.

fail2ban's sshd filter (checked against its current `filter.d/sshd.conf`): in the default `normal` mode a connection closed before authentication is marked no-failure; in `ddos` and `aggressive` modes `Connection closed by <ip> … [preauth]`, `Did not receive identification string` and `kex_exchange_identification: Connection closed` all count as failures. Only a completed login avoids them.

Shells: zsh draws a message under the line with `zle -M` and marks text with `region_highlight`. ble.sh has `ble/edit/info/set-default` (a standing info line that ble's own menus may take over) and highlight layers listed in `_ble_highlight_layer_list` (internals, like SP2's suggestion source). fish 4.0 has `__fish_echo` (print below the command line, then redraw); fish 3.3 does not.

## Architecture

### Components

| Piece | Job |
|---|---|
| `Engine.diagnose(request, probe=True)` | Returns `Diagnostic(start, end, kind, message)` items for the request's line, from the parsed line, the index, `unavailable_hosts.csv` and the host-state cache; with `probe`, queues hosts the cache does not cover and starts the prober (replay evaluation and unit tests pass `probe=False`) |
| Protocol | Request flag `diag=1`; response `W <start>\t<end>\t<kind>\t<message>` records and a `pending` directive while the prober owes answers for hosts on this line |
| Host-state cache | `host-state.tsv` in the runtime directory: per host, mssh validity and ping results with their times |
| `mssh-complete probe` | Detached, lock-guarded: drains the probe queue, checks validity through `multiSSH3.host_validity` and pings, writes the cache, exits |
| `multiSSH3.py` additions | `host_validity(name)`; `runtime_dir()` (the chain); `OPTION_NO_EFFECT` (verified option combinations with no effect) |
| Glue | Marks and reason lines in zsh, ble.sh and the bash line editor; reason lines in fish; warning lines in the picker |

Frontends ask for diagnostics whenever an mssh line changes, in the same query as grey text when they send one for that change (`ghost=1 diag=1`), else in a query of its own: zsh's grey-text query is only sent with the cursor at the end of the line, and in zsh-autosuggestions mode the strategy runs in a subshell, so those cases send `diag=1` alone. The bash line editor calls `diagnose` in-process; fish runs one query per space.

### Request and response additions

- `diag=1`: compute diagnostics for the line `before + after`.
- `W <start>\t<end>\t<kind>\t<message>`: `start` and `end` are character offsets into `before + after`; `kind` is `unknown`, `range`, `unreachable` or `options`; `message` is one line, at most 160 characters, already passed through the control-character filter. Records come in display order (see Several warnings).
- `pending` (in the `D` directives line): hosts on this line are queued or being probed; while it stays set the frontend asks again 0.3 s, 1 s and 3 s after the answer (a silent host takes about 1.2 s to ping); any change to the line cancels the schedule.

## The checks

### Which words

- Only finished words are checked: a word is skipped while the cursor is inside it or right after its last character.
- Host words are the hosts argument (comma-separated parts, each with an optional `user@`). Option values that name hosts (`-X`, `--skip_hosts`) are not checked: skipping an unknown host does no harm.
- Option words are every option on the line.
- **Valid at once** (no cache, no prober): IP addresses and hosts-file names.

### Unknown host

A plain name (no range syntax, not an alias) is **unknown** when the cache says `host_validity` returned `invalid` for it.

- Names valid at once are never unknown. Anything else without a fresh cache entry is queued and reported as `pending`; no warning until the prober answers.
- `host_validity(name)` in `multiSSH3.py` returns `valid`, `invalid` or `unsure` with mssh's rule above, except that DNS answers in three ways: `getaddrinfo` failing with `EAI_NONAME` (or `EAI_NODATA`) is "does not exist"; `EAI_AGAIN`, other errors or a timeout are `unsure`. `invalid` needs "does not exist" for the name and no ssh config mapping.
- Message: `gpu017: unknown host — did you mean gpu17?` or `gpu017: unknown host`.

**Did you mean:** among the index's host names (all sources) that the cache does not hold as `invalid`, the one candidate that

1. equals the typed name once leading zeros are removed from every digit run (`gpu017` → `gpu17`), or else
2. is one insertion, deletion, substitution or swap of adjacent characters away, for names of at least 4 characters.

Two or more equally good candidates: no suggestion.

### Range surprises

A hosts part with range syntax (`node[1-16]`, IPv4 ranges) or naming an alias is expanded (index members for aliases; `expand_ranges` for ranges, up to `RANGE_MEMBERS_LIMIT`). Members valid at once are cleared; the others are looked up in the cache, and those without a fresh entry are queued.

- Warn when at least one member is `invalid`: `node[1-16]: 9 of 16 hosts unknown (node1, node2, node3, …)`.
- While members are still being checked, the counts say so: `node[1-1000]: 312 of 1000 checked, 12 unknown so far`.
- **Did you mean** for numeric ranges with unpadded bounds: the zero-padded variant (width of the upper bound, `node[01-16]`) when all its members are valid at once or cached `valid`.

### Unreachable host

For a plain name, or each member of a range or alias:

1. **Your recent runs:** the host is in `unavailable_hosts.csv`, read at query time with mssh's rules (expiry, boot id). When skipping is in effect (`-su`, `--script`, or `DEFAULT_SKIP_UNREACHABLE` from the mssh config, which the index records, unless `-nsu` is on the line): `node17: will be skipped — unreachable in a recent mssh run`; otherwise `node17: unreachable in a recent mssh run`.
2. **Ping:** the cache's latest ping got no answer, that ping is at most one minute old, and the host answered ping within the ping expiry: `node17: no answer to ping (answered 4 min ago)`.

Hosts that never answered ping are never reported on ping alone. For ranges and aliases: `gpu[01-16]: 2 unreachable (gpu03, gpu07)`.

### Conflicting options

1. **Mutually exclusive:** two options of one argparse group on the line: `-nsu cannot be used with -su (mssh stops with an error)`. The later one is marked.
2. **Given twice:** a non-repeatable option with a value given twice with different values: `-u given twice: mssh uses root`. The earlier one is marked.
3. **No effect:** an entry of `OPTION_NO_EFFECT` matches: the option is marked with the entry's message. Each entry is a combination verified against `main()`'s argument processing and covered by a test that runs that processing and shows the option changes nothing. Candidates to verify: `-nsu` / `--no_skip_unreachable` with `--script` (which forces skipping); `--ipmi_*` settings without `--ipmi`. An entry that turns out to have an effect is dropped.

### Several warnings

Order: unknown host, range, unreachable, options; within a kind, leftmost first. The reason line shows the first message and `(+N more)` when there are more.

## Host knowledge

### Files

All in the runtime directory (see Runtime storage), each starting with a `#boot_id,<id>` line; a file from another boot, a corrupt or foreign file is ignored and rewritten:

- `host-state.tsv`: `host\tvalidity\tchecked_at\tping\tpinged_at\tanswered_at` (times in wall-clock seconds; `validity` is `valid`, `invalid` or `unsure`; `ping` is `answer`, `silent` or empty).
- `probe-queue`: hosts queries asked about, one per line, newest last.
- `probe.lock`: the prober's lock (as `complete-index.lock`).

Writes are atomic (temporary file and `os.replace`) and made under `probe.lock`; queries only append to the queue (one `write` of whole lines) and read the state.

### Freshness

| Result | Fresh for |
|---|---|
| `valid` / `invalid` | 10 minutes (hosts-file and ssh-config edits reach the index through its usual stale-source rebuild, which clears those names at once) |
| `unsure` | 1 minute |
| A ping result | 1 minute; a host on the line is pinged again once its result is older |
| "Answered ping" | The ping expiry (600 s by default, see Decisions) |

### The prober

`mssh-complete probe` (spawned like `spawn_rebuild`: detached, new session, `cwd='/'`, no inherited descriptors):

1. Takes the lock or exits.
2. Lowers its CPU priority (`nice 10`).
3. Repeats until the queue is empty or 2 minutes have passed: takes the queued hosts, newest first, skipping hosts whose entries are fresh; checks validity (`host_validity`, 2 s each, a timeout is `unsure`) and pings hosts that are not `invalid` (`ping -c2 -i0.2 -W1 -q`, `-6` for IPv6 addresses); merges results into `host-state.tsv` as batches finish, so queries see them early.
4. Releases the lock and exits; the next query starts a new run if hosts are still queued.

How many checks run at once follows mssh's own rule for parallel ssh sessions: `multiSSH3._normalize_max_connections(DEFAULT_MAX_CONNECTIONS)`, the mssh config's value (default 4 × CPUs) clamped by the open-file limit. It is halved (never below 4) while the 1-minute load average is at or above the CPU count, and halved again whenever starting a check fails for lack of descriptors or processes (`EMFILE`, `ENFILE`, `EAGAIN`); those hosts go back into the queue.

If `ping` is missing or reports no permission, ping is skipped for that run. The prober imports `multiSSH3` (it is not on the keystroke path). It never connects to a host: only `getaddrinfo`, `ssh -G` and `ping`.

### Runtime storage

`multiSSH3.runtime_dir(create)` and `mssh_complete.cache_dir()` implement the same chain (a test checks every step agrees):

1. `$XDG_RUNTIME_DIR/multiSSH3`, when `$XDG_RUNTIME_DIR` is set, owned by us and not writable by others.
2. `/run/user/<uid>/multiSSH3`, when that directory exists, owned by us and not writable by others (`su`, `sudo -u`, cron).
3. `/dev/shm/multiSSH3-<uid>`, when `/dev/shm` is a directory.
4. `<tempdir>/multiSSH3-<uid>` (`tempfile.gettempdir()`, so `$TMPDIR` first).

Each candidate must pass today's `_private_dir` check (ours, mode 0700, not a symlink); the first that does wins; with none, mssh runs without runtime state as today. Steps 1–3 are tmpfs on systemd Linux and cleared at reboot (and at the last logout, which is fine for runtime state); step 4 may survive a reboot, so state with time semantics carries the boot id.

Runtime state using the chain: `unavailable_hosts.csv`, the completion index and its lock, `complete.log`, and SP3's files. What survives a reboot stays where it is: `~/.mssh_history`, config files mssh writes on request, the ControlMaster block in `~/.ssh/config`, and the installed shell glue. A state file left at an old location is simply not found; the index rebuilds and the unavailable list refills on the next run.

## Display

| Shell | Mark | Reason line | When the prober finishes |
|---|---|---|---|
| zsh (own widgets) | `region_highlight` entries `<start> <end> underline,fg=red`; the glue keeps the exact entries it added and removes only those | `zle -M`, set again from the line-pre-redraw hook | Delayed queries (a `sleep` before the engine) read through `zle -F` |
| zsh with zsh-autosuggestions | Same, from the glue's own `diag=1` query | Same | Same |
| bash with ble.sh | An `mssh` highlight layer appended to `_ble_highlight_layer_list` | `ble/edit/info/set-default` | ble.sh's idle timer |
| bash line editor | The editor underlines the span when drawing the line | One row under the text, hidden while the picker is open | The editor's key read times out at the schedule's times and it asks again |
| fish | None | Printed under the command line when the first warning changes, from a function bound to space after fish's own space binding; the glue carries its own copy of `__fish_echo` | At the next space |
| plain bash, no editor | None | None | — |

- `NO_COLOR` set: underline only.
- The reason line starts with `⚠ `, or `! ` when the locale is not UTF-8.
- Marks and the reason line disappear as soon as a query returns no warning for them.
- The Ctrl-R picker shows up to three warning lines above its rows in every shell.

To verify first while planning: `zle -M` set from a line-pre-redraw hook stays visible and clears; ble.sh's layer interface works on the ble.sh build the matrix tests. If either fails, that shell shows the reason line only.

## Failure behaviour

- Any exception in `diagnose`: no `W` records, a `complete.log` entry when `MSSH_COMPLETE_DEBUG=1`; TAB, grey text and the picker are unaffected.
- The prober cannot start, the lock is held, DNS fails or is slow, `ping` is missing: those hosts stay without a definite answer and produce no warning. Nothing becomes `invalid` because of an error.
- Corrupt, foreign or other-boot state files: ignored and rewritten.
- A range larger than `RANGE_MEMBERS_LIMIT` is checked up to the limit; the message gives the counts.
- The prober cannot start a check (out of descriptors or processes): it halves its parallelism and requeues the hosts; a run that hits its 2-minute cap leaves the rest queued for the next.
- Old glue never sends `diag=1`; an old engine ignores it.

## Performance

`diagnose` adds at most 10 ms (p50) to a query at 10k hosts and 20k invocations, measured with `tests/bench_complete.py`; reported alongside SP2's numbers.

## Testing

- **Unit (`tests/test_complete_diagnose.py`):** each check with in-memory history and a seeded `host-state.tsv`; finished-word rule; did-you-mean (padding, one edit, ambiguous stays silent); range counts and the padded suggestion; the `-su` wording; options (exclusive group, given twice, each `OPTION_NO_EFFECT` entry); ordering and `(+N more)`; the `W` / `pending` protocol.
- **mssh side:** `host_validity` with a fake resolver telling "does not exist" from "no answer", reusing the `ssh -G` catch-all fixtures; every step of the runtime chain; `test_cache_dir_matches_multissh3` extended to every step; each `OPTION_NO_EFFECT` entry against `main()`'s processing.
- **Prober:** queue, lock, parallelism (mssh's rule, halved under load and on `EMFILE` / `EAGAIN` with the hosts requeued), the 2-minute cap, missing `ping`, boot id, freshness, the ping expiry and `MSSH_COMPLETE_PING_TTL`; a test that fails if the prober opens any socket connection or runs `ssh` with anything but `-G`.
- **Real shells (Docker matrix):** marks and reason lines in zsh (both modes), ble.sh, the bash line editor and fish; the picker's warning lines; the delayed update. `ping` is a fake script on `PATH` and host state is seeded, so the matrix never touches a network.
- **Measurement:** `mssh-complete eval --diagnostics` replays history with real DNS (no ping) and lists every host it would call unknown, so false alarms on real history can be checked by eye (hosts in history were typed for real, but failed typos are in it too); on synthetic history with a fake resolver, clean lines give no warning and injected typos and padding mistakes are caught (a test bounds both).

## Out of scope for SP3

- Remote probing (completing remote paths and commands): a later sub-project, under principle 6.
- TCP or ssh reachability checks, as an option or otherwise.
- Moving the ControlMaster `ControlPath` off `/run/user/%i`: a separate small change using the runtime chain.
- Warnings in plain bash without the line editor while typing (readline cannot draw them).

## Release

multiSSH3 6.30 (`mssh_complete` 0.3); `mssh --completion install` again picks up the new glue (glue from 6.29 keeps working without warnings). cas-toolbox's pin is bumped in a Monday roll-up.

## Deviations found while implementing

Implementing and testing SP3 (unit tests, real bash, zsh, fish and ble.sh in the Docker matrix, a replay of real history) changed these details of the design above.

| Area | The design said | Implemented | Why |
|---|---|---|---|
| Reason line | Each shell composes "first warning (+N more)" from the `W` records | The response also carries the composed line as an `R` record | zsh, ble.sh and fish show the same text without three copies of the logic; the mark is `⚠` or `!` by the engine's locale, which is the shell's |
| zsh queries | `diag=1` in the grey-text query when one is sent | zsh asks with its own `diag=1` query when the finished words of the line change, and again when an answer comes back after keys that changed only the word being typed | warnings then work the same with zsh's own widgets and with zsh-autosuggestions; an answer is never lost to the next key |
| zsh reason line | `zle -M`, set again from the line-pre-redraw hook | set once per answer, with one `zle -M` in the answering widget | zsh keeps the message by itself; setting it on every redraw covered zsh's completion listings, and a second `zle -M` in one widget made zsh draw the line a row too high |
| fish | Reason printed after space on every fish 3.3+ | fish 4 only; fish 3 keeps its space key and shows warnings in the picker | fish 3 inserts nothing for `self-insert` in a binding that also runs a function, so taking space broke typing |
| ble.sh reason line | `ble/edit/info/set-default` | set as the default and drawn at once, as `ble/edit/info/immediate-show` draws | a deferred default only appears at ble.sh's next panel render |
| Flag defaults | (not specified) | the index records what mssh's flags set and their defaults (config rows `flag_sets`, `flag_defaults`) and the `OPTION_NO_EFFECT` entries (section `no_effect`) | skipping (`-su`) and "on by default" (`--ipmi`) follow the mssh config without importing mssh on the keystroke path |
| Ping expiry | `MSSH_COMPLETE_PING_TTL`, else mssh's default expiry | also `-uhe` on the line | it is mssh's unreachable host expiry for that run |
| IPv4 ranges | (not specified) | parts in mssh's IPv4 range syntax (`127.0.0.1-20`, `10.0.[1-2].x`) get no warning | they hold only IP addresses; replaying real history flagged `127.0.0.1-20` before this |
| Probe queue | Queries append hosts | hosts already waiting are left out | a query for a long range repeats on every keystroke |
| Ranges past the member limit | Checked up to the limit | the first `RANGE_MEMBERS_LIMIT` members are checked, the total is counted without expanding | `expand_ranges` gives up on a range over its limit |
| Shell tests | (not specified) | the harness holds the prober's lock (tests write host states themselves) and gives the terminal a size | no DNS or ping from tests; ble.sh sizes its info panel from the terminal |
