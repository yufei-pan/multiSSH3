# Limitations

Approved known limitations and deferrals. Reviewers: read this first, and don't raise these again.

## mssh

### mssh's ssh timeouts override the same options in the ssh config
- Kind: known limitation
- What the operator sees: `ConnectTimeout`, `ServerAliveInterval` and `ServerAliveCountMax` set in
  `~/.ssh/config`, `/etc/ssh/ssh_config` or a file given with `-ea '-F FILE'` do not apply to the ssh, scp,
  rsync and ssh-copy-id mssh runs: `DEFAULT_SSH_CONNECT_TIMEOUT` (30), `DEFAULT_SSH_SERVER_ALIVE_INTERVAL` (15)
  and `DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX` (4) do, as a command-line `-o` beats the ssh config. An `-o` given
  with `-ea` still wins, as mssh puts its own after it. An `-ea '-o ServerAliveInterval=60'` now also gets
  mssh's `ServerAliveCountMax=4`: a silent host fails after 240 s, not after ssh's own count of 3 (180 s).
  Setting one of the three settings to 0 leaves that option to the ssh config.
- Why: honouring the ssh config took a reader of ssh's config files with their `Include`s, an `-ea` parser
  and an `ssh -G` per host (which runs `Match exec` lines), about 120 code and 180 test lines, to change only
  how long a dead host takes to fail.
- Revisit when: someone needs per-host timeouts from the ssh config.
- Approved: 2026-10-24, the user chose "Always pass, after -ea (Recommended)".

### A remote command's own ssh turned away before login is run again
- Kind: known limitation
- What the operator sees: a remote command that prints nothing, then runs ssh to another host that sshd's
  `MaxStartups` turns away before login, is run again, up to 3 times, as if mssh's own connection had been
  dropped. Only a command that printed nothing on stdout and whose stderr holds only those lines; it harms
  only if what ran before that ssh cannot run twice.
- Why: telling the two apart took 55 lines matching the address in ssh's line against the host's addresses
  and `ssh -G`, and it left OpenSSH 8.0's drops (RHEL 8), which name no address, without a retry. They are
  retried now.
- Revisit when: someone hits it.
- Approved: 2026-10-24, the user chose "Drop the check (Recommended)".

### A gather retried with scp puts a directory named without a slash one level up
- Kind: known limitation
- What the operator sees: `-G` from a host without rsync, retried with scp, of a remote directory named
  without a trailing slash into a local destination that does not exist, puts the directory's files in the
  destination itself, where rsync puts the directory inside it: `mssh -G -f /var/log/nginx h1,h2
  './logs/#HOST#'` gives `./logs/h2/access.log` for a host without rsync and `./logs/h1/nginx/access.log`
  for the others.
- Why: the host's files cannot be seen from here, and refusing the retry would also refuse a file gathered to
  a new name.
- Revisit when: someone hits it.
- Approved: 2026-10-24, the user chose "Keep it, record the gap" (the scp retry keeps copying a `dir/` as
  rsync would).

### An interrupted `--copy_id -p` can leave an empty `~/.ssh/ssh-copy-id.XXXXXXXXXX`
- Kind: known limitation
- What the operator sees: Ctrl-C, or a `-t` shorter than ssh's 30 s connect timeout, during `--copy_id -p`
  while ssh is still connecting, leaves an empty `~/.ssh/ssh-copy-id.XXXXXXXXXX` per host stopped;
  `rmdir ~/.ssh/ssh-copy-id.*` removes them. It needs `-p` (sshpass) and several hosts; the CLI's `-t` is 0 by
  default, 50 with `--use_script_timeout`.
- Why: avoiding it took 58 lines that found the session sshpass makes and signalled its process group first.
  The cause is ssh-copy-id's trap, which does not cover SIGHUP: sshpass hangs up its pty when a signal reaches
  it while ssh is still connecting.
- Revisit when: ssh-copy-id traps HUP (then nothing is left; a report is drafted, not posted), or someone
  needs it.
- Approved: 2026-10-24, the user chose "Drop, record, draft upstream (Recommended)".

### Output before a run into a closed pipe ends mssh by SIGPIPE
- Kind: known limitation
- What the operator sees: `mssh -h | true`, `mssh -V | true`, `--generate_config_file | true`, a usage error
  into a closed stderr and the prompts before the run end mssh by SIGPIPE. A shell reports 141, as before; a
  program that starts mssh with Python's subprocess sees -13 (6.38: 141). On Windows, which has no SIGPIPE,
  such output exits 120 with Python's "Exception ignored ... BrokenPipeError" line. A program that imports
  multiSSH3 and calls `main()` itself (with `-V`, `-h`, ...) while its own stdout is a closed pipe is ended
  the same way; 6.38's `main()` raised SystemExit(141) and pointed the program's stdout and stderr at
  /dev/null. While such a `main()` runs on the main thread, from its start until the run starts (arguments,
  prompts, config), SIGPIPE is the default for the whole process: another thread of that program writing to a
  closed pipe or socket then ends it too (6.38: that thread got BrokenPipeError). `run_command_on_hosts()`
  does not touch SIGPIPE. A run still ends quietly with its own status. During a run, a message that cannot
  reach stderr is dropped; 6.38 wrote it to stdout.
- Why: exiting 141 by hand took `_WatchedStream` and `_exit_if_output_closed` (about 60 lines) to rebuild what
  SIGPIPE's default action does.
- Revisit when: a program depends on the 141, or Windows users report the message.
- Approved: 2026-10-24, the user chose "Both (Recommended)". The case of a program calling `main()` itself
  added after the second review, and the other threads of such a program after the third: 2026-10-29, the user
  chose "Add it to the entry (Recommended)" both times.

### Another user's config shared through an ACL is not written
- Kind: known limitation
- What the operator sees: `--store_config_file` on a config file owned by another user, which the operator may
  write only through an ACL (or group or world write), answered `o` (overwrite) or reached through a symlink,
  prints `Error: Unable to write to the config file: ...` and the new config on stdout. 6.38 wrote such a file
  in place when it was 0600 or tighter. With the default answer `b`, a config that is not a symlink is moved
  to the `.bak` and the new one is the operator's. Configs of the operator's own, root writing a user's config
  (now atomic, owner and group kept) and the operator's own symlinked configs are written as before (an own
  config now keeps its group with `b` too). Since 6.40, under sudo, the config of the user who ran sudo (their
  file, their symlink, or a new one in a directory of theirs: whose it is goes by the link itself, not what it
  points to) is that user's own: mssh, as root, looks at it, backs it up and writes it with that user's uid,
  gid and groups, so their own symlink is written through wherever they may write. `--add_control_master_config`
  follows the same rule for `~/.ssh/config` (since 6.40; before, as root it followed a link of any owner).
- Why: writing in place needed a third write path, with its own fchmod / fstat check. Every file is now
  written as `~/.ssh/config` was: a temporary file with the old owner, renamed over it.
- Revisit when: someone shares configs through ACLs.
- Approved: 2026-10-24, the user chose "One writer (Recommended)".

### Under sudo -E, mssh ignores the user's own config
- Kind: known limitation
- What the operator sees: under `sudo -E` (or any sudo that keeps HOME), mssh runs as root and does not load
  the user's `~/.multiSSH3.config.json`: a file of another uid, skipped with the usual "owned by uid ..., not by
  you or root" warning. So `sudo -E mssh --store_config_file` writes the settings of the system configs plus the
  command line, and the user's earlier settings stay only in the `.bak` (the default answer `b`; `o` keeps no
  copy). The file is written as the user since 6.40. Where a system config was loaded, that system config is
  the one written without a path, as for anyone with no config of their own.
- Why: as root, mssh loads only configs of root's own: a config can set program paths (`_sshPath`, ...), so a
  user's file would choose what root runs.
- Revisit when: someone needs their own settings under `sudo -E`.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### Under sudo, a program calling main() runs its threads as the user while a config is written
- Kind: known limitation
- What the operator sees: under sudo, mssh writes the invoking user's config (`--store_config_file`,
  `--add_control_master_config`) with their rights by switching the process's effective user (seteuid) for the
  write. The `mssh` command has no other thread then. A program that imports multiSSH3 and calls `main()` with
  one of these options under sudo has its own threads run as that user while the file is written (milliseconds).
- Why: seteuid applies to the whole process. Writing in a forked child would avoid it, at the cost of a process
  and its error handling, for a case no known program has.
- Revisit when: a program calls `main()` with these options under sudo while its other threads work.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### Reading mssh's runtime state may create its directory
- Kind: known limitation
- What the operator sees: a library call that does not update the unreachable-hosts cache
  (`will_update_unreachable_hosts=False`, `no_start`) and mssh-complete's index build create mssh's private
  runtime directory (mode 0700) when it is missing, and tighten one of the operator's own that others can
  read. 6.38 did that only when writing. `runtime_dir(create=False)` is still accepted and does the same.
- Why: a separate read path had to predict where a write would go, and got it wrong in 6.36. One path cannot
  disagree with itself.
- Revisit when: a caller needs mssh to leave the runtime directory alone.
- Approved: 2026-10-28, the user chose "One path (Recommended)".

### Esc does nothing while the terminal is under 3 rows
- Kind: known limitation
- What the operator sees: with the curses display up and the terminal shrunk below 3 rows (or 2 columns),
  mssh shows "Terminal too small", redrawn every 10 ms (about 0.5% of a core). Esc takes effect once the
  terminal has 3 rows again; Ctrl-C works; keys typed meanwhile reach the display when it is back. 6.33 -
  6.38 waited for a resize and took Esc at once.
- Why: the wait took about 40 code and 66 test lines for a terminal nobody keeps at 2 rows.
- Revisit when: someone hits it.
- Approved: 2026-10-28, the user chose "10 ms redraw (Recommended)".

## Autocomplete

### Older glue files draw the Ctrl-R menu and warnings in ASCII
- Kind: known limitation
- What the operator sees: a glue file installed by mssh 6.36 or earlier for bash, or 6.37 or earlier for zsh
  and fish, does not tell the completer the shell's locale. The Ctrl-R menu, the warnings and the line under
  the prompt are then drawn in ASCII (`+--+`, `!`, ` - `) until `mssh --completion install` runs again.
  Matching is not affected. With fish, the locale is read from the name in its first set `LC_ALL`, `LC_CTYPE`
  or `LANG`, so a UTF-8 locale that is named but not installed (a bare container) draws Unicode.
- Why: guessing the terminal's encoding from inside Python, which rewrites the variables it would read (PEP
  538, UTF-8 mode), and asking the C library about fish's locale names took about 120 code and 250 test
  lines; the current glues say their locale.
- Revisit when: someone keeps an old glue for good reasons, or fish's locale names mislead on a real system.
- Approved: 2026-10-28, the user chose "ASCII for old glues (Recommended)".

### The Ctrl-R history tab holds mssh's history only
- Kind: known limitation
- What the operator sees: runs mssh did not record (`-I`, `--script`, `-hf`, or every run with
  `DEFAULT_NO_HISTORY` on) are not rows of the Ctrl-R history tab, and its "used Nx" counts mssh's runs only.
  The shell's own reverse search finds them. TAB and the grey text still learn from the shell's history.
- Why: adding the shell's lines meant matching each one to mssh's record of the same run, so that one run was
  not two rows or two uses: 130 code lines, 130 test lines and up to 300 ms per Ctrl-R.
- Revisit when: someone misses a `-I` run in the menu.
- Approved: 2026-10-28, the user chose "mssh's history only (Recommended)".

### No prompt beside the Ctrl-R menu on bash 4.2 and 4.3
- Kind: known limitation
- What the operator sees: on bash 4.2 and 4.3, while the Ctrl-R menu is open, the line is drawn without its
  prompt; the prompt comes back when the menu closes.
- Why: bash before 4.4 cannot expand its prompt for a program (`${PS1@P}`); drawing it meant a 46-line PS1
  expander of our own, for systems past their end of life.
- Revisit when: an operator on bash 4.2 / 4.3 asks for it.
- Approved: 2026-10-28, the user chose "No prompt on 4.2/4.3 (Recommended)".

### Large ranges whose names repeat are counted with their repeats
- Kind: known limitation
- What the operator sees: the warning about a range of more than 4,096 names whose groups make some name
  twice (`n[1-100][1-100]`: `n1` `11` and `n11` `1` are both `n111`) counts the repeats in "N of M checked":
  10,000 where mssh runs 9,271. Up to 4,096 distinct names the count is exact. `expand_ranges` gives a text
  that mixes number and letter groups (`n[1-2]x[a-b]`) back whole instead of half expanded.
- Why: exact counting took a repeat analysis and a second counter.
- Revisit when: someone reads a wrong count off a real range.
- Approved: 2026-10-28, the user chose "Simplify (Recommended)".

### A hosts word holding a shell expansion is not checked
- Kind: known limitation
- What the operator sees: no unknown-host, range or unreachable warning for any host of a hosts word that
  holds `$`, a backtick, `(`, `!` or a leading `~`, or braces with a quote or backslash in the word:
  `$NODES,gpu017`, `$USER@gpu017`, `'$NODES'` (single-quoted too), `!$` (fish too, which has no history
  expansion). The same holds for unquoted braces the shell expands: `mssh login1,n{1,2}` gets the brace
  warning only (6.38 also said `login1: unknown host`). The brace warning covers unquoted lists and number
  sequences (`node{1,2}`, `gpu{01..16}`); letter sequences, steps, zsh's character ranges, nested braces
  and a stray `}` get none.
- Why: checking the pieces beside an expansion took a second shell lexer and each shell's expansion rules
  (about 190 lines) that had to agree with the first lexer character for character.
- Revisit when: someone mixes variables and hosts in one word and misses the warning.
- Approved: 2026-10-28, the user chose "Skip such words (Recommended)".

### A remote command's -X, -P and -S apply only to the words compgen makes
- Kind: known limitation
- What the operator sees: in `mssh HOSTS CMD ...<TAB>` in bash, where CMD's compspec combines a completion
  function (`-F`) or command (`-C`) with `-X`, `-P` or `-S`, mssh offers the function's or command's words
  unfiltered and without the prefix or suffix (bash filters and wraps them too); `-P` / `-S` words that do
  not start with the typed word are left out (bash would replace the typed word); a `-C` command's blank
  lines are left out, so a blank first line, which bash reads as an empty answer, can bring file names
  instead; and a result continued over a newline after a backslash is read as two. Of bash-completion 2.11's 1,000 specs, the 12 with `-X` (11
  LibreOffice launchers, explodepkg) and the 4 with `-P` / `-S` (jobs, fg, bg, disown: the local shell's
  jobs) are not commands one runs remotely.
- Why: emulating bash's whole compspec pipeline took about 80 glue lines, 150 test lines and 2.5 minutes of
  pty tests per run; mssh now completes a remote command as bash-completion completes `sudo CMD`.
- Revisit when: an operator hits a remote command whose compspec needs it.
- Approved: 2026-10-28, the user chose "Complete as sudo does (Recommended)".

### Under menu-complete or ble.sh's menu, mssh's words beside a nospace command's mixed words get no space
- Kind: known limitation
- What the operator sees: with bash's TAB bound to `menu-complete`, when a remote command's compspec asks for
  nospace (git, scp, rsync, cd) and offers words with and without a trailing space (`--oneline ` beside
  `--format=`), cycling inserts mssh's own history words without a space. With TAB bound to `complete` (the
  default) nothing changes. A word both mssh and the command offer is listed once. With ble.sh (since 6.40),
  picking one of mssh's own words from ble.sh's menu beside such mixed words (git's `--format=` beside
  `--oneline `) inserts it with no space; the command's `--oneline` gets its space. ble.sh's menu is its
  default, so ble.sh users meet this more often than readline's menu-complete users.
- Why: spacing them one by one took an open-quote scanner (its time grew with quotes times line length:
  11.5 s on a 32,000-character line) and about 50 lines, for a case only menu-complete reaches. Under ble.sh,
  handing mssh's words over with their space would make ble.sh insert them without the open quote of a quoted
  remote command.
- Revisit when: an operator using menu-complete or ble.sh asks for it.
- Approved: 2026-10-28, the user chose "Drop it (Recommended)". Extended to ble.sh's menu: 2026-11-01, the user
  chose "Extend the limitation (Recommended)".

### bash: a remote command with no completion file completes local file names where python-argcomplete's global completer is set
- Kind: known limitation
- What the operator sees: in bash, where python-argcomplete's global completer is set (`complete -D`, as
  `activate-global-python-argcomplete` sets it), `mssh h CMD <TAB>` for a remote command with no completion file
  of its own completes local file names, as with bash-completion alone. bash would run the `-D` completer for
  `CMD` itself. The glue never runs a local program named like the remote command.
- Why: the `-D` completer runs the local program of that name (argcomplete starts it with `_ARGCOMPLETE=1`),
  which need not be the remote one, nor anything to run here; the glue loads a command's completion with
  bash-completion's loaders and does not call `-D`.
- Revisit when: an operator wants a remote command (`ansible-playbook`) completed from its local copy.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### ble.sh: a remote word of mssh's that names a local directory gets a / and no space
- Kind: known limitation
- What the operator sees: with ble.sh, one of mssh's own remote words (from its history) that names a
  directory existing on this machine goes in with `/` and no space: with `othercmd srcx` in mssh's history and a
  local directory `srcx`, `mssh h othercmd sr<TAB>` gives `srcx/`. Plain bash gives `srcx ` since 6.38. On a
  remote that has the directory too, the word still names it.
- Why: ble.sh marks every word a completion function returns that names a directory here; its switch for that
  (`ble/no-mark-directories`) applies to the whole reply, and would cost the remote command's local directory
  names their `/` and missing space.
- Revisit when: an operator hits it with a word that is not a directory on the remote.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### ble.sh: a remote ~/ path from mssh's history goes in with a bare ~
- Kind: known limitation
- What the operator sees: with ble.sh, a remote path `~/...` that mssh offers from its history
  (`mssh h cat <TAB>` with `cat ~/zznotes.txt` in its history) goes on the line as `~/zznotes.txt`, which this
  shell expands to the local home before mssh runs; plain bash inserts `\~/zznotes.txt`, which the remote
  shell expands. The path is right whenever the remote home is the same path as the local one (a shared home,
  the same user). A `~` the operator typed stays as typed in every shell, as with `ssh h cat ~/x`, and so does a
  typed `$HOME/` (since 6.41).
- Why: ble.sh leaves the leading `~` of a completion function's word unescaped, and the glue cannot make it
  escape one word: `noquote` and `ble/syntax-raw` apply to the whole reply. A ble.sh completion source of
  mssh's own would, as a bigger change.
- Revisit when: an operator whose remote home differs from the local one hits it.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### ble.sh: a word split at an = or : after a quote, backslash or expansion is read as in 6.39
- Kind: known limitation
- What the operator sees: with ble.sh, when the part of a word before the `=` or `:` at which ble.sh splits it
  holds a quote, a backslash or an expansion (`"a"=b`, `'a'=b`, `a\ b=c`, `$V:x`), the glue reads that word as
  6.39 did, from ble.sh's evaluated values. It completes as in 6.39, except that a `~` after the split comes back
  as this machine's home with the word quoted again: `mssh h cmd 'a'=~/zzx<TAB>` gives `'a=/home/me/zzxfile'`,
  and `$V:~/zzx` (with `V=a`) gives `'a:/home/me/zzxfile'`; 6.39 offered nothing there. A backslash before the `=` or `:`
  itself (`a\=b`) is no such split: ble.sh does not split there, and the word completes as typed
  (`a\=zzxfile`).
- Why: ble.sh hands the glue the part before the split (`progcomp_prefix`) evaluated; when the typed text is not
  the same as its value, the glue cannot tell where the word starts on the line as typed. After the split, the
  glue completes ble.sh's evaluated `$2`, in which the `~` is already expanded.
- Revisit when: an operator hits it.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### bash 4.3 and 4.4: a remote command's -o noquote is not seen
- Kind: known limitation
- What the operator sees: on bash 4.3 and 4.4, the local file names the bash glue completes for a remote command
  whose compspec sets `-o noquote` are quoted anyway.
- Why: the glue reads a compspec's options from `complete -p`, which leaves `noquote` out on bash 4.4 (checked:
  `complete -o noquote -F f x; complete -p x` prints `complete -F f x`; bash 5.1 prints the option), and bash
  4.4's `compopt` does not list it either. `noquote` is
  rare, and bash 4.3/4.4 are old.
- Revisit when: an operator on bash 4.3 or 4.4 completes for a command whose compspec sets `noquote`.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### With nocasematch on in bash, a Ctrl-C during a TAB can leave it off
- Kind: known limitation
- What the operator sees: with `shopt -s nocasematch` on in the interactive bash, a Ctrl-C while TAB, Ctrl-R
  or the line editor is working can leave nocasematch off until it is turned on again. A command's
  completion function, bash-completion's loaders, a Ctrl-R binding mssh took over and PS1's command
  substitutions run with nocasematch off and bash's default IFS, not the shell's; a compspec's `-X` pattern
  does not follow the shell's nocasematch.
- Why: giving the setting back after a cut took a PROMPT_COMMAND hook (and a ble.sh one), notes of the
  setting around every change and a restore of the shell's IFS (about 60 lines, 160 test lines), for a
  setting bash-completion itself does not work under.
- Revisit when: an operator who keeps nocasematch on hits it.
- Approved: 2026-10-28, the user chose "Simple guard (Recommended)".

### Install on fish 2 succeeds and does nothing
- Kind: known limitation
- What the operator sees: `mssh --completion install fish` with fish 2.x prints what it wrote and exits 0;
  the installed glue registers nothing on fish before 3.0, so TAB keeps fish's own completion. 6.38 refused
  with a message.
- Why: the version probe and its tests (about 90 lines) served a fish no supported distribution ships
  (CentOS 7's EPEL, end of life 2024).
- Revisit when: fish 2 comes back; then the glue's own guard can print the reason.
- Approved: 2026-10-28, the user chose "Drop the refusal (Recommended)".

### A program calling mssh_complete's main() gets BrokenPipeError on its own prints once its stdout reader has gone
- Kind: known limitation
- What the operator sees: a program that imports mssh_complete and calls `main()` itself for an output larger
  than stdout's buffer (a glue: `main(['glue', 'bash'])`) after the reader of its own stdout has gone, and then
  keeps printing, gets Python's usual `BrokenPipeError` on its own later prints (exit 120, "Exception ignored
  ..."). 6.38 pointed the program's fd 1 at /dev/null, so those prints vanished silently; after a short output
  (`main(['-V'])`), still in the buffer when the write fails, 6.39 does that too. Operators are not affected:
  `mssh --completion` ends by SIGPIPE first, and the `mssh-complete` command exits 141.
- Why: no real caller does this, and bringing 6.38's silence back takes a poll-based check of the reader
  (about 7 lines, POSIX only).
- Revisit when: a program that embeds `mssh_complete.main()` hits it.
- Approved: 2026-10-29, the user chose "Known limitation (Recommended)".

## Deferred to the change after 6.40

Found while confirming and reviewing 6.40's items (the user's words are in each entry).

### Inside a quoted argument the engine completes a quoted command
- Kind: known limitation
- What the operator sees: in every shell, TAB inside a quoted argument of a remote command
  (`mssh h cat 'my f<TAB>`) reads the quoted text as a whole quoted command: it completes `f` as an argument of
  a command `my`, so nothing useful is offered there. Typing the whole command in quotes
  (`mssh h 'cat my<TAB>`) completes.
- Why: mssh runs each argument holding whitespace as a command of its own, so `mssh h cat 'my file'` cannot run
  as meant whatever completion inserts, and a quoted argument without whitespace (`'a&b'`) reaches the remote
  shell unquoted anyway. Completing there would need quoting for the remote shell inside this shell's quotes: a
  lot of glue in four shells for a form mssh cannot run.
- Revisit when: mssh passes a quoted argument to the remote shell as one quoted word.
- Approved: 2026-11-02, the user chose "Known limitation (Recommended)".

### zsh before 5.8: a Ctrl-C during a completion query can reach the query
- Kind: deferred
- What the operator sees: with zsh older than 5.8 (zsh 5.5 is EL8's), now and then, for the length of a
  completion query (a TAB, the grey text, the warnings; longer when typing starts more), the query's process
  holds the terminal. A Ctrl-C then reaches the query rather than the shell; zsh usually drops the line anyway,
  but now and then the line stays. The shell stays alive and the keys typed still reach it. 6.39 does the same:
  the zsh glue did not change in 6.40.
- Why: on zsh before 5.8 the glue's hand-back of the terminal sometimes leaves it with the query's process
  group; why needs its own investigation. Until then the test of it
  (`tests/test_complete_keys.py::test_zsh_keeps_the_terminal_while_mssh_asks`) can fail on the legacy image.
- Revisit when: the change right after 6.40.
- Approved: 2026-11-01, the user chose "Defer to after 6.40 (Recommended)".

## Found in 6.41's review

The local file names a remote command's completion gives, as 6.41 writes them for the remote shell (the user's words are in
each entry).

### ble.sh before bash 4.3: names inside a directory that changes are left out
- Kind: known limitation
- What the operator sees: with ble.sh on bash 4.2 (EL7), no name is offered inside a directory whose name the remote
  shell needs quoted (`mssh h cat a\\\&dir/<TAB>`, or `mssh h "cat a&b/zz<TAB>`); elsewhere such names complete. Names
  under a typed `~/` or `$HOME/` whose own directories need no quoting complete.
- Why: ble.sh on bash before 4.3 keeps the typed directory inside the single quotes it puts the rest in, so the remote
  shell got the typed text quoted once more (`'zzq\\\&x/in\&1'` named `zzq\&x/in&1`). Leaving such names out puts
  nothing wrong on the line.
- Revisit when: an operator on EL7 with ble.sh needs names inside such a directory, or ble.sh's insertion on bash 4.2 is
  fixed.
- Approved: 2026-11-03, the user chose "Leave those names out (Recommended)".

### zsh: a directory the remote shell would read otherwise gets no names
- Kind: known limitation
- What the operator sees: in zsh, nothing is offered inside a directory typed so that the remote shell would read it
  otherwise: one typed with this shell's quoting alone (`mssh h cat a\&b/<TAB>`, which mssh would pass on as `a&b/`, so
  the remote shell would read `a` and `b/...`), and one typed bare in a quoted command (`mssh h "cat a&b/zz<TAB>`). bash
  replaces such a directory with the remote shell's word. Typed as the remote shell's word (`a\\\&b/`, `"cat a\\&b/`),
  or completed by TAB, the names inside it complete.
- Why: zsh keeps the directories typed before the word as typed (`compadd -p`); writing them again would need the glue
  to replace zsh's own prefix handling. Offering nothing puts nothing wrong on the line.
- Revisit when: an operator types such directories in zsh and misses the names.
- Approved: 2026-11-03, the user chose "Accept (Recommended)"; the quoted command added the same day, "Extend the Accept
  (Recommended)".

### ble.sh: a name holding a brace is not offered for a remote command typed as words
- Kind: known limitation
- What the operator sees: with ble.sh, a local file name holding `{` is not offered for a remote command typed as words
  (`mssh h rm zzb<TAB>` with a file `zzb{a,b}` offers nothing); in a quoted command it is, and readline and zsh offer it
  quoted.
- Why: ble.sh quotes no brace in what it inserts, natively too: `zzb\{a,b\}`, the remote shell's word, went in as
  `zzb\\{a,b\\}`, which this shell brace-expanded into two words.
- Revisit when: ble.sh gains a way to insert a quoted brace.
- Approved: 2026-11-03, the user chose "Known limitation (Recommended)".

### readline and ble.sh: no names inside a directory whose name holds a quote or a backslash
- Kind: known limitation
- What the operator sees: in bash, under readline and ble.sh, nothing is offered inside a local directory whose name holds
  `"`, `'` or `\` (`mssh h cat zzq<TAB>` gives `zzq\\\"x/`, and the next TAB nothing).
- Why: bash dequotes the word for compgen, and readline's file name completion (ble.sh's too) dequotes its directory
  part once more before reading it: a `"` or `'` there opens a quote and a `\` goes, so another directory is read. Names
  inside it would need the glue to list the directory itself.
- Revisit when: an operator has such directories and misses their names.
- Approved: 2026-11-03, the user chose "Known limitation (Recommended)".

### ble.sh: an expansion partway through a quoted command's word gets no file names
- Kind: known limitation
- What the operator sees: with ble.sh, in a quoted command, a word with a `$` expansion partway through its last part
  (`mssh h "cat Outer$Inn<TAB>` for a file `Outer$Inner.class`) gets no file names; readline completes it.
- Why: ble.sh keeps the typed text only where a name starts with its value of the typed word (`COMPV`), and there that
  value has `$Inn` expanded (this shell expands it inside double quotes): a name written otherwise would replace the
  command typed.
- Revisit when: ble.sh offers a way to keep typed text that differs from its value.
- Approved: 2026-11-03, the user chose "Known limitation (Recommended)".

### readline: TAB on a glob offers nothing
- Kind: known limitation
- What the operator sees: under readline, a remote command's word holding `*`, `?` or `[` (`mssh h cat zz*b<TAB>`) gets
  nothing; 6.40 put in the names it matched.
- Why: readline's `bashdefault` inserts the names a glob matches quoted for this shell alone (`zz?b` gave `zz\;b`, and
  the remote shell ran `b`); the glue turns it off for such a word.
- Revisit when: an operator misses glob completion for remote commands.
- Approved: 2026-11-03, the user chose "Accept (Recommended)".

### readline: names holding an exclamation mark are not offered in a double-quoted command
- Kind: known limitation
- What the operator sees: under readline, in a remote command typed in double quotes (`mssh h "cat zz<TAB>`), a local
  file name holding `!` is not offered.
- Why: with history expansion on, bash reads a `!` inside double quotes, and a backslash before it stays in the word, so
  no writing of the name reaches the remote shell as named. In single quotes (`mssh h 'cat zz<TAB>`) the name is offered;
  with `set +H` it can be typed.
- Revisit when: an operator needs such names in double-quoted commands.
- Approved: 2026-11-03, the user chose "Known limitation (Recommended)".

### readline: a quote opened inside a quoted command gets no names
- Kind: known limitation
- What the operator sees: under readline, a word with its own open quote inside a quoted command (`mssh h "cat 'zz<TAB>`)
  gets nothing. ble.sh, and readline after a `\"`, put the remote shell's word for the name in place of the word, that
  quote dropped (`mssh h "cat zzamp\\&b"`), which the remote shell reads as named.
- Why: inside readline's open double quote compgen keeps the `'` as part of the name, so it matches none; completing there
  would need the glue to read the remote word's own quotes.
- Revisit when: an operator types such quotes and misses the names.
- Approved: 2026-11-03, the user chose "Both known limitations (Recommended)".

### readline: a default-value expansion in a remote word is written broken
- Kind: known limitation
- What the operator sees: under readline, `mssh h cat ${VAR:-x}/zzf<TAB>` puts in a broken word (`${VAR:-x\\\}/zzf...`),
  which mssh and the remote shell read wrong; 6.40 did the same.
- Why: readline's word starts after the `:` (`COMP_WORDBREAKS`), so the glue sees `-x}/zzf` and writes that part as a
  name.
- Revisit when: an operator types such expansions in a remote command.
- Approved: 2026-11-03, the user chose "Both known limitations (Recommended)".

### A directory completed in a quoted command closes the quote
- Kind: deferred
- What the operator sees: in bash, a directory completed in a quoted command closes the quote: `mssh h "ls zzd<TAB>` gives
  `"ls zzdir" `, and `mssh h "cat ~bi<TAB>` gives `"cat ~bin/"`; the quote has to be taken out to go on into the directory.
  6.40 did the same for `"ls zzd<TAB>`.
- Why: readline closes the quote of a single match unless its file name mode finds the match is a directory; in a quoted
  command the match is the whole command typed (`ls zzdir`), which names none. ble.sh closes it too.
- Revisit when: 6.41 has shipped.
- Approved: 2026-11-03, the user chose "Defer both (Recommended)".

### zsh: a variable in a double-quoted command is expanded and nothing completes
- Kind: deferred
- What the operator sees: in zsh, `mssh h "ls $PWD/zzd<TAB>` rewrites the line to `mssh h ls\ /the/directory/zzd` and
  completes nothing; 6.40 did the same.
- Why: zsh's completion expands the parameter in the quoted word before the glue sees it; not looked into further.
- Revisit when: 6.41 has shipped.
- Approved: 2026-11-03, the user chose "Defer both (Recommended)".
