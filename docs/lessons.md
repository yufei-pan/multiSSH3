# Lessons

What this project's past changes taught us. Read all of this before changing an API, a format or an
agreed behaviour here. For the full story of a line, find the entry with the same date and name in
`lessons-full.md`.

When one has to change, add the full entry to `lessons-full.md` and one line here, newest last, in the
same commit as the change. Keep this file under 20 KB: at the cap, merge lines before adding.

- **2026-10-28 multiSSH3: mssh-complete eval moved to tests/replay.py**: ship what the operator runs; keep measuring and tuning tools in the source tree next to the tests that use them. When a subcommand goes, make the old name fail with the one-line fix, not the usage text.
- **2026-10-28 multiSSH3: Completion index format 3**: a cache's format version is cheap to bump: bump it with every change to what is stored, and never teach the reader to cope with old caches. While an older engine still runs (a shell started before the upgrade), it rebuilds its own format under the same name; the two replace each other until those shells end, which is harmless for a cache.
- **2026-10-28 multiSSH3: ssh timeout options always passed**: when a tool has a precedence rule, place your values in it (after the user's, as here) instead of reading the tool's configuration to predict it. A setting of our own (`DEFAULT_SSH_*`, 0 to opt out) is the interface; the other tool's config files are not.
- **2026-10-28 multiSSH3: Rebuild and prober locks are flocks**: for "one at a time" between local processes, use the kernel's lock and let the holder's exit release it; never infer liveness from a pid or a timestamp. Keep accepting the old flags so an older engine still running mid-upgrade gets no usage error.
- **2026-10-28 multiSSH3: SIGPIPE before the run**: let the OS default apply where the tool behaves like any other filter; restore the old disposition for the part that must survive a closed pipe (the run). Never send diagnostics to stdout when stderr fails.
- **2026-10-28 multiSSH3: runtime_dir(create) ignored**: one function, one answer; a read that sets up a private directory is cheaper than a second resolver. The parameter stays for callers written for 6.38 (an mssh_complete 0.11 beside multiSSH3 6.39 still calls `create=False`).
- **2026-10-28 multiSSH3: compact_hostnames / expand_hostnames hosts_only ignored**: a function that displays names should not resolve them; keep a released keyword accepted when its meaning goes away.
- **2026-10-28 multiSSH3: expand_ranges gives a mixed text back whole**: match precision to what the operator reads; above the display limit an upper bound is enough.
- **2026-10-28 multiSSH3: mssh-complete edit --expand and install on fish 2**: support a floor in one place (the glue's guard); keep old flags accepted so an old caller gets the new behaviour, not an argparse error.
- **2026-11-01 multiSSH3: the bash glue under ble.sh sends the word as typed**: when a shell emulates another's completion interface, check what the emulation hands over for quoted and expanded words, and read the line from the emulator's own record of it when it keeps one, with the emulation as the fallback. When one switch applies to a whole reply, keep words that must not get it out of the reply while it is on, rather than shaping them for it.
- **2026-11-01 multiSSH3: --add_control_master_config refuses another owner's ~/.ssh/config link**: put a safety rule where every writer passes (or check every caller against it when it is added), and test the documented rule against each command that claims it.
- **2026-11-01 multiSSH3: under sudo, the invoking user's files are written with their rights**: when root acts on a user's behalf, do it with that user's rights and let the kernel decide what they may write, rather than re-implementing their permissions as root. Compare ownership with the effective uid, which is the identity the write runs under.
- **2026-11-06 multiSSH3: no answer offers file names only where they are right**: a fallback that runs when the source of truth is silent must be right without it: list the few cases it can tell for itself, and give nothing for the rest, rather than a default that fits most cases and puts in a wrong word for the others.
