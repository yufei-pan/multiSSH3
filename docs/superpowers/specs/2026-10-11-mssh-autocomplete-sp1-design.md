# mssh Autocomplete — SP1: Engine, Knowledge Index, TAB Frontends

**Date:** 2026-10-11
**Status:** Design approved in conversation; written spec awaiting review
**Package:** multiSSH3 (adds a second single-file module, `mssh_complete.py`)

## Goal

Make operators finish mssh invocations with as few keystrokes as possible, without ever getting in their way.

SP1 builds the shared completion engine and its knowledge index, and ships TAB completion for bash (primary), zsh and fish. The engine's interface is designed from the start for the later sub-projects (ghost suggestions, hotkey picker, async diagnostics) and for a future mssh TUI, which will import the engine directly.

Priority order: **useful recommendations first, then speed.** Performance is measured, not gated, until the recommendation quality is proven.

## Core principles

1. **Never cost keystrokes.** Completing must never require more keystrokes than typing the command out. Completion never deletes or rewrites text the operator typed.
2. **Never get in the way.** Nothing happens unless the operator asks (TAB). Any failure, timeout or missing component falls back silently to the shell's normal behavior. Nothing is printed to the terminal.
3. **Never change what mssh runs.** Completion is advisory; mssh's own parsing and behavior are untouched.
4. **One semantics.** Completion understands hosts and options exactly as mssh does, by reusing mssh's own parser and host expansion at index-build time.
5. **Usefulness before speed.** Ranking quality is measured by replaying real history; speed is optimized afterwards.

## Roadmap (decided)

| Sub-project | Scope | Plugs into |
|---|---|---|
| **SP1 (this spec)** | Engine, knowledge index, context-conditioned ranking, TAB frontends (bash, zsh, fish), install, replay evaluation | — |
| SP2 | Ghost suggestions (zsh `POSTDISPLAY` + async `zle -F`, fish native, ble.sh in bash, capability auto-detection) and a hotkey picker (bash `bind -x`, zsh widget) | `Response.ghost`, request capability flags, shared ranking |
| SP3 | Async host knowledge (background DNS / reachability probing), advisory diagnostics (unresolvable / unreachable hosts, incompatible options), remote probing for remote commands and paths | `Response.diagnostics`, `expand_hostnames_local()` unresolved list, `remote_probe` provider slot, parser-spec mutually-exclusive groups |
| Later | mssh TUI | Imports `Engine` in-process |

Each later sub-project gets its own spec → plan → implementation cycle.

## Decisions

| Topic | Decision |
|---|---|
| Architecture | Lean Python one-shot completer + precomputed on-disk index (approach A) |
| Code location | New single-file module `mssh_complete.py` in the multiSSH3 repo, shipped as a second `py_module`; copy-transportable alongside `multiSSH3.py` |
| Hot path imports | Never imports `multiSSH3`; only the index builder does (and degraded mode, see Failure behavior) |
| Index format | Lazy-decoded NSV snapshot (`\0` fields, `\n` rows); data-only, Python-version-independent, language-neutral |
| Append log | `~/.mssh_history` itself; the snapshot records the byte offset it covers |
| Index location | mssh's existing private cache dir (`$XDG_RUNTIME_DIR/multiSSH3` or `/tmp/multiSSH3-<uid>`) |
| Interaction layers in SP1 | TAB completion only; SP2/SP3 fields exist in the response but are empty |
| Shell history | In-memory tail sent by the shell per request (`fc -ln -1000` / fish `history`); ranked below mssh history; not indexed |
| Ranking | Context-conditioned, bidirectional: similar past invocations vote, IDF-weighted, frecency-decayed, with backoff to global frecency |
| bash candidate rule | Every candidate extends readline's word (`$2`); fuzzy matching is reserved for the picker (SP2) |
| Passwords | `-p`/`--password`/`-ip`/`--ipmi_password` values are never indexed or offered |
| Install | `mssh --completion SHELL` prints glue; `mssh --completion install [SHELL]` / `uninstall [SHELL]` writes/removes lazy-load files |
| Performance | Observed, not gated. ~100 ms per TAB acceptable for now. Safety deadlines exist only to protect the prompt |
| Quality | Replay evaluation of keystroke savings and candidate rank is the primary metric; a TAB that alters or deletes operator-typed text must never occur |
| Python floor | Same as multiSSH3/cas-toolbox (`>=3.6` syntax: no walrus, no dataclasses) |
| History hosts field | `~/.mssh_history` records the hosts exactly as typed. Before this change it recorded them expanded, sorted and validated (aliases replaced by members, unresolvable names dropped, with an error printed while recording); lines written before the change keep that form |
| Shell test matrix | Docker images: modern (Debian trixie), legacy (Rocky Linux 8 + EPEL) and CentOS 7 (bash only). Tested floors: bash 4.2, bash-completion 2.1, zsh 5.5, fish 3.3, Python 3.6. Inside the matrix, a missing required shell is a failure, not a skip |
| CentOS 7 | bash compatibility only (bash 4.2.46, bash-completion 2.1, Python 3.6.8); its zsh 5.0.2 and fish 2.3.1 are not supported |
| fish < 3.0 | Unsupported: the glue registers nothing and the installer refuses with a message |
| rc-file safety | Installed rc blocks source the glue only if it is readable and discard its stderr, so a broken or missing glue file can never print in a new shell |

## Context (existing code this builds on)

- CLI shape: `mssh [opts] HOSTS COMMAND...`, parsed with `parse_intermixed_args` (options may appear anywhere), falling back to `parse_known_args` with unknown tokens appended to commands. About 60 options, many with several aliases.
- Host syntax: comma-separated tokens; ranges (`node[1-10]`, `10.0.0.1-3`, `[a-c]`); `user@host`; env-variable and env-file aliases (recursive); `/etc/hosts`; ssh config; DNS.
- `_local_hostname_source()` classifies a host without DNS (`ip`, `env`, `env_file`, or needs DNS). `__expand_hostname(text, validate=False)` expands ranges without resolving. `compact_hostnames(verify=True)` produces round-trip-verified range strings.
- `~/.mssh_history` lines: `<ts>\t<prog>\t<shortened args>\t<hosts>\t<commands>`, mode 0600, append-only. Until this change the hosts field went through `formHostStr()` → `compact_hostnames()`, which expands aliases and ranges, validates names (DNS included), drops unresolvable ones and re-sorts: typing `us_east` recorded its members, and `zzz-bad,localhost` recorded `localhost`. Completion must learn what operators type, so `record_command_history()` now records the hosts argument as typed; the `> command` echo printed at start keeps its current form.
- `_unavailable_hosts_file_path()` defines the private cache dir; `unavailable_hosts.csv` lives there.
- `multiSSH3TUI.py` holds an earlier k-gram `CommandSearcher` prototype; SP1 does not reuse it, but SP2's picker may borrow its fuzzy word search.

Measured on the development machine (Python 3.13): bare `python3 -I -S` startup ≈ 4 ms; `import multiSSH3` ≈ 25 ms; lazy NSV load + one contextual query on a 10k-host / 20k-invocation index ≈ 3.7 ms in-process, ≈ 7 ms whole process (pickle: 16–18 ms / 28 ms; JSON: 16 ms load alone). `fc -ln -1000` ≈ 0.4 ms. A `read -t` deadline on a process substitution adds ≈ 0.13 ms and aborts reliably.

## Architecture

### Files

| File | Change |
|---|---|
| `mssh_complete.py` | New. Engine, index reader/builder, providers, ranking, glue renderers, `mssh-complete` CLI |
| `multiSSH3.py` | Adds `--completion` option (lazy-imports `mssh_complete`), public `expand_hostnames_local()` and `compact_hostnames_local()`, and records history hosts as typed |
| `setup.py` | `py_modules=['multiSSH3', 'mssh_complete']`; console script `mssh-complete=mssh_complete:main` |
| `tests/` | New test modules for the engine, index, invariants, evaluation and real-shell integration |
| `tests/shells/` | Dockerfiles for the modern and legacy shell images, and `run_matrix.sh` |
| `README.md` | New "Autocomplete" section |
| `cas-toolbox/pyproject.toml` (separate repo, release step) | Add `mssh-complete = "mssh_complete:main"` to `[project.scripts]` and bump the `multissh3` pin |

If `mssh_complete.py` is absent (only `multiSSH3.py` was copied), `mssh --completion …` prints a one-line hint and exits nonzero; nothing else in mssh changes.

### Units inside `mssh_complete.py`

Each unit has one job and can be used and tested on its own. The TUI may import any of them.

| Unit | Job | Depends on |
|---|---|---|
| `Request` / `Response` | Plain classes holding a query and its answer | — |
| `parse_context(before, after, word, spec)` | Lex the whole line (tolerating an unterminated quote), assign every token to a slot the way argparse would, and report the slot under the cursor plus the features of all other filled slots | Parser spec from the index |
| `Index` | Locate the cache dir, open the NSV snapshot lazily, check source signatures, merge the unparsed history tail, trigger a detached rebuild | Cache dir, history file |
| `build_index()` | Read every source, build all sections, write the snapshot atomically | `multiSSH3` (the only importer) |
| Providers | `options`, `option_values`, `hosts`, `mssh_history`, `shell_history`, `delegate`, `magic_strings`, `remote_probe` (empty slot until SP3) | `Index`, context |
| `rank(candidates, context, index)` | Merge provider output and score it (see Ranking) | `Index` |
| `Engine.query(request)` | Orchestrate the above, apply prefix filtering and the safety deadline, return a `Response` | All of the above |
| Glue renderers | Produce the bash / zsh / fish glue text | — |
| `main()` | `mssh-complete query` (protocol on stdin/stdout), `rebuild`, `eval` | All of the above |

`Response` fields: `context` (slot kind and details), `candidates` (list of `text, description, group, score`), `directives`, `delegate` (or `None`), `ghost` (always `None` in SP1), `diagnostics` (always empty in SP1).

### Glue ↔ engine protocol (version 1)

The protocol is language-neutral, so a native hot path could replace the Python engine later without changing any shell glue.

**Request** (stdin, UTF-8 with `surrogateescape` on decode):

```
MSSHC1\0<shell>\0<shell_version>\0<flags>\0<before_cursor>\0<after_cursor>\0<word>\0
<shell history tail, one entry per line>
```

- `<before_cursor>` / `<after_cursor>`: the command line split at the cursor (bash: `${COMP_LINE:0:COMP_POINT}` and the rest). Sending text instead of an index keeps the unit question inside the glue. In a UTF-8 locale, bash 4.2 counts `COMP_POINT` in **bytes** while its substring expansion counts characters; bash 4.3 and later count both in characters (verified on 4.2.46, 4.3.48, 4.4.20/23, 5.0, 5.1, 5.2). The bash glue therefore slices inside a function with `local LC_ALL=C` on bash 4.2, which makes the slice byte-based and restores the locale on return.
- `<word>`: the shell's own notion of the word being replaced (bash `$2`, zsh `$PREFIX`, fish `commandline -ct`). Candidates are returned relative to exactly this word. This word is not uniform across shells and versions, so the engine takes it as given: fish passes the raw token including an opening quote (`"a | gré`) and the engine dequotes it; bash 4.2 passes `@no` for `root@no` where bash 5.2 passes `no`, so the engine never assumes `@` splits words.
- `<flags>`: space-separated `key=value` capability flags: `nosort=0|1`, `icase=0|1` (readline `completion-ignore-case`), `ble=0|1`, `zas=0|1` (zsh-autosuggestions), `term=<TERM>`. SP1 uses `nosort` and `icase`; the rest are recorded for SP2.

**Response** (stdout), one record per line, terminated by a single `\0`:

```
MSSHC1
D <directive> <directive> ...
C <text>\t<description>\t<group>
X <cword>\t<prefix>\t<word0>\t<word1>\t...
G <ghost text>
W <severity>\t<message>
\0
```

- `D`: directives — `nospace`, `filenames`, `nosort`, `files` (let the shell do native path completion for this word), `dirs`.
- `C`: one candidate per line, in rank order. `<text>` is the full replacement for `<word>`.
- `X`: delegate local completion for a remote command: the words of that command, the index of the current word, and the `<prefix>` to prepend to each delegated result (needed when the readline word is a whole quoted string, e.g. `a | gre` must come back as `a | grep`).
- `G`, `W`: reserved for SP2 / SP3; SP1 never emits them.
- Unknown record types are ignored (forward compatibility). Text containing a tab or newline is dropped; a delegate whose words contain a tab or newline is not emitted.
- A response whose first line is not `MSSHC1` is treated as no answer.

## Context detection

The parser spec (from the index) records every option string with its `dest`, `nargs` (none, required, optional `?`), whether it repeats (`append`), help text, and mutually exclusive groups.

Rules, in order:

1. Lex the whole line (before and after the cursor) with shell rules. An unterminated quote at the cursor is allowed; the remainder of the line is the quoted word.
2. `-x=value` / `--opt=value` attach the value to the option.
3. An option with required `nargs` takes the next token as its value.
4. An option with optional `nargs='?'` (`-k`, `-s/-fs`, `--config_file`, `--store_config_file`) takes the next token only if argparse would: the token does not start with `-`. So `mssh -fs <TAB>` completes a local path.
5. The first non-option token is HOSTS; following non-option tokens are COMMANDS. After `--`, every token is COMMANDS.
6. A token starting with `-` inside COMMANDS:
   - if every COMMANDS token so far was a quoted string (the command is "closed"), it is an mssh option;
   - otherwise (unquoted command words, e.g. `mssh grp ls -l<TAB>`), it belongs to the remote command and is delegated.
7. Unknown options are treated as COMMANDS, matching mssh's `parse_known_args` fallback.

The slot under the cursor is excluded from the line's features; every other filled slot, before and after the cursor, contributes features (see Ranking). This is what makes backtracking work.

## Candidates per context

| Context | Candidates | Notes |
|---|---|---|
| Option name, bash, word `-` or `--…` | One long form per option | `-x…` (single dash plus letters) matches short aliases, e.g. `-n` → `-nw -nh -nsu -no` |
| Option name, zsh / fish | Grouped aliases with help text as description | |
| (all option names) | Non-repeatable options already present are hidden; the other member of a mutually exclusive pair already present is hidden | `append` options stay available |
| HOSTS | Env aliases, past host strings, host groups, individual hosts from `/etc/hosts`, ssh config, `known_hosts`, ARP, history | Completes the segment after the last `,`; keeps a `user@` prefix and earlier segments (bash's `$2` includes them, since `,` does not break words) |
| `-X/--skip_hosts` | Members of the current HOSTS expansion first, then the HOSTS candidates | |
| `-u`, `-iu` | Usernames from history, `$USER`, ssh config `User` | |
| `-p`, `-ip` | Nothing | Values are never indexed |
| `-k` | Directories and private-key-looking files under `~/.ssh`, then native path completion | |
| `-f`, `-s`, `-ef`, `-efs`, `--host_file`, `-hf`, `--config_file`, `--store_config_file` | Native path completion (`D files`), plus previously used values | |
| `-t -r -i -m -uhe -ww -wh -irlt -dt -e -ea -ia -im -pre -mpre` | Previously used values (context-ranked), then option defaults | |
| COMMANDS, quoted word (`"lscp`, `'systemctl rest`) | Whole commands from mssh history whose text extends the inner word; delegated completion of the last pipeline segment (after the last `\|`, `;`, `&&`, `\|\|`, `$(`); shell-history commands | Readline closes the quote on a unique match |
| COMMANDS, unquoted words (`mssh grp systemctl rest`) | The next word of history commands whose leading words match the typed words; delegated local completion for the command; shell-history words | |
| COMMANDS ending in an unclosed `#…` | `#HOST#`, `#HOSTNAME#`, `#USER#`, `#USERNAME#`, `#ID#`, `#I#`, `#UUID#`, `#RESOLVEDNAME#`, `#IP#` | |
| COMMANDS with `-fs` or `-G` | Native local path completion | Sync sources / gather destination are local |
| COMMANDS with `-f` (push) | Previously used destinations | Remote path probing arrives in SP3 |

### Host groups at scale (target: up to ~10k hosts)

- At build time, hosts are grouped by stem plus numeric run and stored as range strings produced by `compact_hostnames(verify=True)`, with their members (e.g. `node[001-512]`).
- A short prefix yields groups and aliases; individual names appear once the prefix narrows the matching set to at most 50 hosts (initial value, tuned by the replay evaluation).
- Narrowing a group at query time (e.g. `node0` within `node[001-512]`) uses a small stem-plus-zero-padded-number compactor in `mssh_complete.py`. Its output must expand, under mssh's own expansion, to exactly the matching members; this is a tested invariant.
- Hosts present in `unavailable_hosts.csv` stay listed and are only ranked lower.

## Ranking

### Records and features

Each distinct mssh-history invocation becomes a record with: occurrence count, last-used time, a decayed weight, and a feature set:

- the full host string; each host token; the alias group a token came from;
- each option with its value (`-u=root`, `-t=30`; password values excluded);
- the full command; the program word (`systemctl`); the program plus first argument (`systemctl restart`);
- the mode: plain, `-f` push, `-fs` sync, `-G` gather, `-M` IPMI.

An inverted index maps each feature to the ids of the records containing it.

### Score

For the slot under the cursor with candidates already filtered by the word:

- `weight(r)` = Σ over occurrences of `0.5 ^ (age / half_life)` (initial `half_life` = 7 days).
- `idf(f)` = `log(1 + R / df(f))`, where `R` is the number of records and `df(f)` the number of records with feature `f`. Near-universal features (e.g. `-su`) contribute almost nothing; specific hosts and commands contribute a lot.
- `sim(r, line)` = Σ over features shared by record `r` and the current line of `idf(f) × kind_weight(f)`.
- `score(c)` = Σ over records `r` whose slot value is `c` of `weight(r) × (β + sim(r, line))`, where `β` is the backoff constant: with no context, ranking is plain frecency.
- Candidates from non-history sources (host table, ssh config, ARP, defaults, delegation, shell history) receive a source prior: mssh history > delegated local completion > shell history > static sources.
- Host-group candidates take the summed score of their members.

Only records reachable through the line's features are decoded, which keeps the query cheap. Initial constants: `half_life` = 7 days, `β` = 0.1, `kind_weight` = 1.0 for every feature kind, source priors in the order above. All of them (and the group threshold) are tuned with the replay evaluation.

### Matching

- bash: case-sensitive prefix match on `<word>`, or case-insensitive when `icase=1`. Every candidate extends the word.
- zsh and fish: the same prefix filtering in SP1; candidates are passed with the user's own matcher configuration left untouched.
- Rank order is visible in zsh and fish, and in bash 4.4+ via `nosort`.

### Examples of intended behavior

- `mssh gpu[01-16] <TAB>` → commands run on those GPU hosts rank above the globally most common command; `-u root` on the line additionally favors commands run as root.
- Cursor in HOSTS of `mssh ▮ 'systemctl restart slurmd'` → hosts where slurmd was restarted rank first.
- `mssh storage* -<TAB>` → the options habitually used with those hosts rank first.

## Knowledge index

### Sources

| Section | Source |
|---|---|
| Parser spec | `multiSSH3.get_parser()` |
| Config | Effective config-chain defaults: history file, host file, env files, `DEFAULT_HOSTS` |
| Hosts | Configured host file (`/etc/hosts`); ssh config `Host` entries from `~/.ssh/config` and `/etc/ssh/ssh_config` including `Include` (wildcard patterns skipped); unhashed `~/.ssh/known_hosts` entries (`[host]:port` stripped, `\|1\|` hashed entries skipped); ARP (`/proc/net/arp` on Linux, `arp -an` on macOS); every host token in mssh history |
| Host groups | `compact_hostnames(verify=True)` over the host set |
| Aliases | Env-file aliases via mssh's trust-checked `readEnvFromFile()`, expanded with `expand_hostnames_local()`; environment variables only if their name has been used as a host token in mssh history |
| Reachability | `unavailable_hosts.csv` (rank penalty only) |
| History | Records, inverted index, per-option value tables |

### New helper in `multiSSH3.py`

`expand_hostnames_local(hosts)` expands ranges and env / env-file aliases using `__expand_hostname(validate=False)`, `_local_hostname_source()` and `readEnvFromFile()`, with no DNS and no ssh lookups. It returns the expanded names and, separately, the names that would still need DNS. It does not touch mssh's failure counters or print errors. SP3 will use the second list as its background-probe queue.

### Storage: lazy NSV snapshot

- File: `<cache dir>/complete-index.v1.nsv`, mode 0600, inside the 0700 private dir. Written to a temporary file in the same directory and published with `os.replace`.
- Fields are separated by `\0`, rows by `\n`. Strings containing `\0` or `\n` are dropped by the builder (argv cannot contain `\0`; history entries are single-line).
- Row 0 (header): magic `MSSHCIDX`, format version, section row offsets and counts, source signatures, history byte offset covered, build time, mssh version.
- Sections: string table; per-slot sorted candidate rows (prefix bisect); postings (one row per feature id); records; host groups; option value tables; parser spec; config.
- Reading splits the file into rows once and decodes only the rows a query touches (the string table, the relevant sorted rows, the postings of the line's features and the records they reference).
- The lean module computes the cache dir itself (it does not import `multiSSH3`). A test asserts it matches `multiSSH3._unavailable_hosts_file_path()`'s directory.

### Freshness

- Source signatures: `(inode, size, mtime_ns)` for the history file, host file, ssh config files (including resolved `Include`s at build time), `known_hosts`, env files, `unavailable_hosts.csv`, the config-file chain, and `multiSSH3.py` itself (parser changes on upgrade). ARP uses a 5-minute TTL.
- Each request stats the sources. Then:
  - If only the history file grew and the unparsed tail is at most ~64 KB / 500 entries, the tail is parsed in-request and merged in memory. A command run seconds ago is already rankable.
  - If anything else changed, or the tail exceeds the threshold, the current snapshot is served and a detached rebuild starts (`setsid`, standard streams to `/dev/null`). A lock file holding pid and start time prevents stampedes; a lock older than 60 s is stale.
  - If the history file shrank or its inode changed, a full rebuild is scheduled.
- No snapshot (first use, or after reboot since the runtime dir is cleared): build synchronously within a generous budget (initially 2 s); if the budget runs out, answer with what is ready (options, delegation, shell history) and finish the build in the background.
- Index size and rebuild time limits are generous (a background rebuild of a few seconds and an index up to ~10 MB are fine). Caps on records, values and hosts are set by measured quality, not by byte budgets.

### Shell history

Not indexed. Each request carries the shell's in-memory tail (default 1000 entries, configurable with `MSSH_COMPLETE_SHELL_HISTORY`). Lines invoking mssh (any of its five names) are parsed like mssh-history records; other lines contribute local commands and command words. Shell history is weighted below mssh history. A per-shell cache is added only if measurement shows a need.

### Privacy and safety

- Values of `-p`, `--password`, `-ip`, `--ipmi_password` (in any `-x value` / `-x=value` form) are dropped at parse time and never reach the index.
- Otherwise the index holds nothing the user's own history files do not, in a private directory, as data only: a tampered file can produce bad suggestions but never execute code.
- Completion never executes anything taken from history. Delegation only calls completion functions the shell already has registered for that command.
- Env files are read through mssh's existing trust checks.

## Shell frontends

### bash

- Registration: `complete -o default -o bashdefault -F _mssh_complete mssh mssh3 multissh multissh3 multiSSH3`. With `-o default`, an empty answer falls back to bash's filename completion.
- Per TAB:
  1. Build the request: before/after cursor text, `$2`, bash version, flags (`nosort` when bash ≥ 4.4; `icase` from `bind -v`, read once when the glue loads), and `fc -ln -1000`.
  2. `IFS= read -r -d '' -t "$deadline" resp < <(engine query 2>/dev/null)`. On timeout, nonzero status, or a bad first line: return with empty `COMPREPLY`.
  3. Apply directives with `compopt`; fill `COMPREPLY` from `C` records.
  4. For an `X` record: load the command's completion with the first bash-completion loader that exists — `_comp_load` (2.12+), `__load_completion` (2.2–2.11), `_completion_loader` (2.0–2.1) — run its function with local synthetic `COMP_WORDS`, `COMP_CWORD`, `COMP_LINE`, `COMP_POINT`, prepend `<prefix>` to each result, and merge with the engine's candidates (deduplicated, engine order first). Without bash-completion: `compgen -c` for the command word, `compgen -f` for its arguments.
- Verified readline behavior this design relies on (pty probes on bash 4.2.46 and 5.2.37): inside an open quote, `$2` is the dequoted inner text (`"lscp` → `lscp`; `"a | gre` → `a | gre`); `=` breaks words (`-f=/et` → `/et`); `,` does not break words; `@` differs by version (see Protocol).
- The glue is written for bash 4.2: no namerefs (`local -n`, 4.3), no `${var@Q}` (4.4), no `mapfile -d` (4.4), no negative array subscripts (4.3). `compopt -o nosort` is used only on bash ≥ 4.4; older bash shows candidates alphabetically. Verified on 4.2: fractional `read -t` on a process substitution aborts on time; `compopt`, `mapfile`, associative arrays and `fc -ln` work.
- SP1 adds no key bindings, readline variables, `PROMPT_COMMAND` or traps.

### zsh

- The glue file defines `_mssh` and calls `compdef _mssh mssh mssh3 multissh multissh3 multiSSH3` only if `compdef` exists. It never runs `compinit`.
- Request from `$LBUFFER` / `$RBUFFER`, `$PREFIX`, `fc -ln -1000`.
- Deadline: the engine is opened on a file descriptor (`exec {fd}< <(engine query)`) and read with a timeout (`zselect -t` + `sysread`, or `read -t -u $fd`), then the descriptor is closed. `read -t` on a redirected process substitution (`read -t 0.2 x < <(…)`) ignores the timeout in zsh — verified on 5.0.2 and 5.9, where it waited for the producer — so it must not be used.
- Candidates are added with `compadd -V <group> -d <descriptions>` in rank order, grouped as aliases, host groups, hosts, history, options, values.
- Delegation: quoted commands use `compset -q`; then words are shifted to the remote command and `_normal` runs.

### fish

- `complete -c <name> -f -a '(__mssh_complete)'` for each of the five names.
- Request from `commandline -cp`, `commandline -p` with `commandline -C` (characters), `commandline -ct` (raw token), and `history -n 1000`. Candidates are printed as `text\tdescription`; the glue splits engine records with `string split`.
- Requires fish ≥ 3.0. fish 2.3.1 (CentOS 7 EPEL) lacks what the glue needs (`string split` produced nothing, no `string unescape`, `history` options rejected and plain `history` empty inside a completion function), so on fish < 3.0 the glue file returns before registering anything. Verified working on 3.3.1 and 4.0.2.
- Delegation: `complete -C "<remote command line>"`.
- fish's built-in autosuggestions consume these completions automatically.

### Engine invocation from glue

The glue calls `mssh-complete query` if `mssh-complete` is on `PATH` when the glue is generated; otherwise it embeds the absolute interpreter and module path captured at generation (`<sys.executable> -I <path>/mssh_complete.py query`), which covers copy-transported installs.

## Installation

- `mssh --completion bash|zsh|fish` prints the glue to stdout.
- `mssh --completion install [SHELL]` detects the shell from the parent process (`/proc/<ppid>/comm`, falling back to `$SHELL`) unless given, writes the files below, and prints every path it wrote or changed. It is idempotent and refuses to overwrite a file it did not write (files carry a marker line with the glue version). It refuses, with a message naming the minimum version, when the detected shell is below the supported floor (fish < 3.0).
- `mssh --completion uninstall [SHELL]` removes exactly what install wrote, including marked rc-file blocks, leaving the rc file byte-for-byte as it was before install.
- Marked rc-file blocks are fail-safe: bash `[ -r F ] && . F 2>/dev/null`, zsh `[[ -r F ]] && source F 2>/dev/null`. A missing, unreadable or broken glue file therefore produces no output and no error in a new shell. The glue file itself only defines functions and registers completion when sourced; it runs no Python and no external commands at shell start.
- Locations:
  - bash: `${XDG_DATA_HOME:-$HOME/.local/share}/multiSSH3/completion.bash`, plus a marked `source` block appended to `~/.bashrc` (sourcing a small file, no Python at shell start). The bash-completion per-user directory is not used: see "Changes made while planning".
  - zsh: `${XDG_DATA_HOME:-$HOME/.local/share}/multiSSH3/completion.zsh`, plus a marked `source` block appended to `~/.zshrc`; the file registers via `compdef` when available.
  - fish: `${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/<name>.fish` for each of the five names (autoloaded).
- Not recommended (documented only): `eval "$(mssh --completion bash)"` in an rc file, which runs Python on every shell start.

## Failure behavior

- Any engine error (missing engine, exception, timeout, malformed or version-mismatched response) yields no answer, and the shell falls back to its default completion.
- Nothing is printed to the terminal. The glue discards the engine's stderr. With `MSSH_COMPLETE_DEBUG=1`, errors and timings are appended to `<cache dir>/complete.log`, capped at 256 KB (truncated to the newest half when exceeded).
- Safety deadlines (protect the prompt; not performance targets): engine soft deadline ≈ 200 ms (stop scoring, return the best so far); glue hard deadline ≈ 300 ms (`MSSH_COMPLETE_TIMEOUT`, in seconds). A hung stat on an NFS home cannot freeze the prompt; the orphaned engine exits when its I/O completes.
- Snapshot with a bad magic, unknown version, or inconsistent row counts: ignored, rebuild scheduled, request answered in degraded mode.
- Builder failures never leave a partial snapshot (atomic replace) and never propagate to the request.
- No usable private cache dir: degraded mode — options (from `multiSSH3.get_parser()`, imported on demand), delegation and shell history only; no mssh-history ranking.
- Concurrent shells share one read-only snapshot; the rebuild lock prevents duplicate rebuilds.
- Glue/engine version skew after an upgrade: the engine answers with its own protocol version; a glue that does not recognize it returns no answer. `mssh --completion install` refreshes the glue.

## Quality evaluation (primary metric)

`mssh-complete eval [HISTORY_FILE]` replays mssh history chronologically. For each invocation it builds the knowledge available *before* that invocation, then simulates the operator typing it:

- per slot: hosts, option names, option values, commands;
- in both directions: forward (left to right) and backtracking (each slot re-entered with every other slot filled).

Two TAB policies are simulated:

- **bash:** TAB inserts the longest common prefix of the candidates; on a unique candidate it also appends the trailing space or closing quote unless `nospace` applies.
- **ranked:** TAB accepts the top candidate (zsh menu completion; later SP2 ghost suggestions).

For each intended token, a TAB is simulated at every prefix length. A TAB is *useful* when what it inserts (including any appended space or quote) matches the intended continuation, and *divergent* when it inserts anything else. The report gives:

- **keystrokes saved** relative to typing every character, for an operator who presses TAB at the first prefix where it is useful (typed characters + TAB presses; an unwanted appended space or quote counts as the keystrokes needed to fix it);
- top-1 and top-3 hit rate and mean reciprocal rank of the intended token, per slot and per source;
- the **divergent-TAB rate** per slot and position, i.e. how often pressing TAB would insert something the operator did not want;
- the **appended-suffix cost** per slot (e.g. a trailing space after a host when the operator's next character is `,`), which decides each slot's `nospace` policy;
- **TABs that alter or delete operator-typed text: required to be zero.**

History lines written before hosts were recorded as typed hold expanded host strings, so host-slot scores on them measure the wrong target. The history file does not say which mssh version wrote a line, so `eval` accepts `--since TIMESTAMP` to replay only entries written after the upgrade (default: all entries).

Output is aggregate numbers only. Every ranking change (constants, sources, thresholds) is justified with this report, including SP2's ghost suggestions later.

A synthetic history generator with known structure (host groups with distinct command habits, aliases, users, timestamps) produces deterministic datasets so the same metrics run in tests without real history.

## Performance observation

A benchmark script (not a unit test), `tests/bench_complete.py`, generates a 10k-host / 20k-invocation dataset and reports: TAB end-to-end latency in bash (p50, p95), engine in-process load + query, inline history-tail parse, full rebuild time, index size, and shell-startup overhead added by installed glue. None of these is a pass/fail gate in SP1; around 100 ms per TAB is acceptable. Optimization (including a possible native hot path behind the same protocol) happens after quality is established.

## Testing

pytest, plain `test_*` functions, in `tests/`. On a developer machine, real-shell tests for a shell that is not installed are skipped so the local loop stays fast; the Docker shell matrix (below) is where every shell must run.

- **Context parser:** table-driven cases covering `nargs='?'`, `-x=value`, `--`, quoted and unterminated commands, intermixed options, unknown options, the "dash inside COMMANDS" rule, and cursor positions in every slot. Oracle test: for complete generated lines, slot assignment matches what `multiSSH3.get_parser().parse_intermixed_args()` produces.
- **Ranking:** synthetic fixtures for forward affinity, backtracking affinity, IDF down-weighting of universal features, backoff with no context, and host-group score aggregation.
- **Invariants** (fuzzed over generated lines and histories):
  - every bash candidate extends `<word>`;
  - no password value appears anywhere in the snapshot bytes;
  - every host-group candidate (build-time and query-time narrowed) expands under mssh's expansion to exactly its members;
  - the replay evaluation reports zero TABs that alter or delete operator-typed text on the synthetic datasets.
- **Index:** NSV round-trip; lazy decoding touches only needed rows; staleness detected for each source kind; inline tail merge; scrub threshold triggers a rebuild; corrupt and truncated snapshots handled; atomic replacement; rebuild lock and stale-lock recovery; cache-dir agreement with `multiSSH3`.
- **`multiSSH3.py` additions:** `expand_hostnames_local()` (ranges, env and env-file aliases, unresolved list, no DNS calls, no side effects on failure counters); `--completion` printing, install, uninstall (into a temporary `HOME`), and the missing-module hint.
- **Real shells in a pty** (same harness as the design probe): bash with and without bash-completion; the probe's quoting and word-break cases; multibyte text before a mid-line cursor (the bash 4.2 byte-cursor case); the `root@no` word difference between bash versions; a slow engine hitting the zsh deadline; quote closed on a unique match; delegation using a deterministic fake command with its own registered completion function; timeout fallback (engine replaced by a sleeper) still yields filename completion within the deadline; no stray output on screen; installed glue adds no measurable shell-startup cost. zsh and fish equivalents of each case.
- **Shell start safety** (every shell, every matrix image): after `mssh --completion install`, a fresh interactive shell prints zero bytes beyond its prompt and exits 0. The same holds with the glue file deleted, made unreadable, or replaced with a syntax error, and with the engine missing or crashing. After `uninstall`, rc files are byte-for-byte identical to before install.
- **Regression:** the existing suite (269 tests) keeps passing.

### Docker shell matrix

Real-shell behavior differs across shell and bash-completion versions, and the development machine has only bash. The matrix runs the shell-integration tests, the shell-start safety tests and the engine unit tests inside containers:

| Image | bash | bash-completion | zsh | fish | Python |
|---|---|---|---|---|---|
| modern: `debian:trixie-slim` | 5.2.37 | 2.16 (`_comp_load`, `_comp_command_offset`) | 5.9 | 4.0.2 | 3.13.5 |
| legacy: `rockylinux:8` + EPEL | 4.4.20 | 2.7 (`__load_completion`, `_command_offset`) | 5.5.1 | 3.3.1 | 3.6.8 (`python36`) |
| centos7: `centos:7` (bash only) | 4.2.46 | 2.1 (`_completion_loader`, `_command_offset`) | — | — | 3.6.8 (`python3`) |

(Versions as available on 2026-10-11.)

- `tests/shells/Dockerfile.modern`, `Dockerfile.legacy` and `Dockerfile.centos7` install the shells, bash-completion, Python and a pytest that supports the image's Python (pytest 7.0.x for 3.6).
- CentOS 7 is end-of-life: its Dockerfile points the CentOS repositories at `vault.centos.org` and EPEL at `archives.fedoraproject.org/pub/archive/epel/7`, and installs `which` (present on real hosts, missing from the image).
- CentOS 7 has no `C.UTF-8` locale, and bash silently falls back to byte semantics everywhere, which hides the byte-cursor case. Tests in that image run with `LANG=en_US.UTF-8`.
- In the centos7 image `MSSH_REQUIRE_SHELLS=bash`; in the other two `MSSH_REQUIRE_SHELLS=bash,zsh,fish`.
- `tests/shells/run_matrix.sh` builds the images (cached by Docker), then runs the tests in each with the repository bind-mounted read-only and `HOME` set to a fresh temporary directory, so nothing touches the host's shell configuration.
- Inside the matrix, `MSSH_REQUIRE_SHELLS` turns any "required shell not installed" skip into a failure, so zsh and fish support cannot pass without being run.
- "bash without bash-completion" runs in every image by not loading bash-completion.
- The matrix must pass before any change to glue, install or the protocol is merged; for engine-only changes the local suite is enough.
- Versions below the tested floors (bash < 4.2, zsh < 5.5, fish 3.0–3.2) are best effort and not tested; fish < 3.0 is unsupported.
- Every image also has ble.sh (the 2026-09-08 nightly, `d81fd54`, pinned by checksum) at `$MSSH_TEST_BLESH`; `tests/test_complete_blesh.py` checks that TAB completion works inside it, that its grey suggestions come from the engine (→ accepts them), that a slow engine does not hold up typing, and that the glue adds no output at shell start. `MSSH_REQUIRE_SHELLS` includes `blesh` in all three images.

## Out of scope for SP1

- Ghost suggestions, hotkey picker, capability-driven UI (SP2).
- DNS / reachability probing, diagnostics, incompatible-option warnings, remote command or path probing (SP3).
- Following per-line overrides of sources: `-hf`, `-ef`, `-efs` and `--config_file` typed on the line do not switch the index's sources.
- Fuzzy (non-prefix) matching in TAB completion.
- Windows shells.

## Release

1. Bump `version` in `multiSSH3.py`; `mssh_complete.py` declares its own `version` and the protocol version `MSSHC1`.
2. `uvpack` multiSSH3.
3. In `cas-toolbox`: add `mssh-complete = "mssh_complete:main"` to `[project.scripts]` and bump the `multissh3` pin in the next Monday roll-up.

## Changes made while planning

Drafting and testing the implementation against real shells and the replay evaluation changed these details; the code follows this section where it differs from the text above.

| Area | Change | Why |
|---|---|---|
| Host groups | Built with `compact_hostnames_local()` (DNS-free, checked by range expansion) instead of `compact_hostnames(verify=True)` | `compact_hostnames` validates every name through DNS and prints errors |
| Use weight | Each use counts `USE_FLOOR` (0.1) plus the decayed part | With pure decay, history older than a few months scored about 1e-15 and lost to static hosts |
| Context term | `log(1 + weight(r)) * sim(r, line)`; features in more than half of the records are left out of `sim` | A host used nine times outranked the only host a command was ever run on, through a near-universal feature |
| Option features | `o:` keys on the option's long string, not its dest | `-x` and `-a` share a dest, so `--no_skip_unreachable` inherited the score of the `-su` every history line records |
| Path modes | With `-f`, `-fs` or `-G` the command words are `f:` path features | File sync paths showed up as programs |
| Protocol | The response ends with an `E` line before the NUL; fish sends `nul=0` and gets no NUL; the engine reverses fish history (newest first) | fish command substitution cannot carry NUL; the `E` line marks a complete response |
| rc blocks | End with `\|\| :` | A missing or broken glue file left `$?` at 1 or 2 in every new shell |
| Env file aliases | Only values made of host-list characters count, and only when used as a host, list-like (`,`, `[`) or made of known hosts | `~/.bashrc` holds `PATH`, `PS1`, `EDITOR`, ... |
| Test baseline | The existing suite has 520 tests | 269 was an older count |
| Python 3.6 | The argparse cross-check is skipped there | `parse_intermixed_args` arrived in Python 3.7; mssh itself falls back to `parse_known_args` on 3.6 |
| Providers | Providers are `Engine` methods (`_options`, `_values`, `_hosts`, `_commands`); there is no empty `remote_probe` provider | SP3 adds remote probing where it plugs in; an empty stub would only be dead code |
| Case | The `icase` flag is sent but SP1 matches case-sensitively | Case-insensitive matching has to reach every prefix lookup in the index; left for a follow-up |
| zsh groups | zsh shows one list (`compadd -V mssh`) in rank order, with descriptions | Separate groups per kind would break the cross-kind rank order |
| Benchmark | `tests/bench_complete.py` does not time shell start | The installed glue runs no commands at shell start, and `test_new_shells_stay_silent` checks it prints nothing and keeps `$?` |
| bash install | bash always loads the glue from `~/.bashrc` (data-dir `completion.bash` plus the marked block); the bash-completion per-user directory is not used | bash-completion being installed does not mean it runs: stock Debian root shells do not load it, so install would report success while TAB did nothing new |

Measured at the target scale (10k hosts, 20k invocations): a TAB costs 30-45 ms (p50), a rebuild about 0.5 s, the index is 3 MB.

## Changes from the final review

| Area | Change | Why |
|---|---|---|
| Passwords | `-pVALUE` is read as `-p VALUE` (argparse's attached short option), and shell-history lines that run mssh behind a wrapper (`sudo mssh`, `python3 multiSSH3.py`, `cd x && mssh`) are parsed from the mssh word on | A password typed as `-pSECRET`, or behind a wrapper, was offered as a completion |
| bash delegation | Delegated results drop the text in front of bash's own word | bash's word stops at `:` and `=`, so `a:b` completed to `a:a:bfile` |
| bash escaping | No escaping when bash quotes file names itself (`files`, `dirs`); a `C` record may carry a fourth field, the unescaped text, which the glue uses when a delegated completion turned on file name quoting | Paths and words with spaces or `;` were escaped twice |
| Typed host strings | Host strings longer than 256 characters are not offered whole | Recording hosts as typed can store a 2000-host list as one 18 KB string |
| Aliases | `expand_hostnames_local` expands each alias once per user | Aliases with fan-out (`AA='BB,BB'`, `BB='AA,AA'`) made the index builder spin forever |
| Range members | Members of ranges typed before are hosts; they are not listed beside the range itself unless typed on their own or named by the hosts argument (`-X`) | `mssh gpu[01-16] -X <TAB>` offered no member |
| Shell options | The bash glue is safe under `set -e` and `set -u`; every process substitution ends with `\|\| :` | TAB killed `set -e` shells (bash 4.4 exits after a failed process substitution) and printed errors under `set -u` on bash 4.2/4.3 |
| History | Lines with timestamps outside 0 .. 10^11 are ignored | A pathological timestamp stopped every index build |
| Failed rebuilds | A rebuild that fails keeps its lock, marked `failed`, until it goes stale (60 s), and a query without an index stops waiting for a build once it failed | When the index could not be written (a full runtime directory, a file size limit) or built (`mssh_complete.py` copied without `multiSSH3.py`), every query started another full rebuild, and without an index each one waited the whole 2 s budget |
