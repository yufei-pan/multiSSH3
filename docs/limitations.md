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

### Inside a quoted argument, names holding whitespace are not offered
- Kind: known limitation
- What the operator sees: in every shell, TAB inside a quoted argument of a remote command typed as words
  (`mssh h cat 'zz<TAB>`) offers the command's own completion and the local file names for the open quote, quoted for
  the remote shell (`'zz\&b'`), but no word holding whitespace, and nothing from history but the words that followed the
  command's other words. Once the quoted text holds whitespace (`mssh h cat 'my f<TAB>`), TAB reads it as a whole quoted
  command: it completes `f` as an argument of a command `my`, and history's whole commands come. Typing the whole command
  in quotes (`mssh h 'cat my<TAB>`) completes names holding whitespace.
- Why: mssh runs each argument holding whitespace as a command of its own, so `mssh h cat 'my file'` cannot run as
  meant whatever completion inserts; a quoted argument without whitespace mssh joins with the command's other words,
  and the remote shell reads them again.
- Revisit when: mssh passes a quoted argument to the remote shell as one quoted word.
- Approved: 2026-11-02, the user chose "Known limitation (Recommended)"; updated 2026-11-03, "Update the entry
  (Recommended)".

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

### zsh and ble.sh: a directory the remote shell would read otherwise gets no names
- Kind: known limitation
- What the operator sees: in zsh, nothing is offered inside a directory typed so that the remote shell would read it
  otherwise: one typed with this shell's quoting alone (`mssh h cat a\&b/<TAB>`, which mssh would pass on as `a&b/`, so
  the remote shell would read `a` and `b/...`), and, in a quoted command, one typed bare (`mssh h "cat a&b/zz<TAB>`) or
  holding an expansion the remote shell makes (`mssh h "cat zzd\$x/zz<TAB>`, where the remote shell reads the variable `x`;
  also a backtick, a brace, a parenthesis, a redirect or, unless `glob_complete` is set, a pattern character). bash (readline) writes a
  directory holding a `$` or a backtick that is there by that name as the remote shell's word.
  Typed as the remote shell's word (`a\\\&b/`, `"cat a\\&b/`, `"cat zzd\\\$x/`), the names inside it complete, outside backticks. A directory
  completed by TAB goes on completing, except one whose name holds a `\` ([the backslash entry](#zsh-no-names-inside-a-directory-whose-name-holds-a-backslash)).
  With ble.sh the same for a directory whose name holds a `$`, typed bare: with a directory `zzd$x` here, `mssh h cat zzd$x/zz<TAB>`
  offers nothing (6.47 wrote `zzd/zzin`, which the remote shell reads as another path); typed `zzd\$x/zz` it completes.
- Why: zsh keeps the directories typed before the word as typed (`compadd -p`); writing them again would need the glue
  to replace zsh's own prefix handling. Offering nothing puts nothing wrong on the line. (In a double-quoted command, `"ls zzd<TAB>`
  and then `in<TAB>` gave nothing in 6.46 for a directory whose name holds `$`, a backtick, `"`, `\` or `!`; from 6.47 only for one
  whose name holds a `\`.)
- Revisit when: an operator types such directories in zsh and misses the names.
- Approved: 2026-11-03, the user chose "Accept (Recommended)"; the quoted command added the same day, "Extend the Accept
  (Recommended)". The further characters (an expansion such as `$`, a backtick, a brace, a parenthesis, a redirect, a pattern character
  unless `glob_complete` is set): 2026-11-17, chief's decision C86 (the user's desk session; not the user's words). ble.sh's bare `$`:
  2026-11-25, chief's decision C248 (not the user's words).

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
- What the operator sees: under readline, in a remote command typed in double quotes (`mssh h "cat zz<TAB>`), or a
  double-quoted argument (`mssh h cat "zz<TAB>`), a local file name holding `!` is not offered.
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

### bash: a default-value expansion in a remote word is written broken
- Kind: known limitation
- What the operator sees: under readline and ble.sh, `mssh h cat ${VAR:-x}/zzf<TAB>` puts in a broken word
  (`${VAR:-x\\\}/zzf...`, ble.sh `'${VAR:-x\}/zzf\&1'`), which mssh and the remote shell read wrong; 6.40 did the same.
- Why: the word bash completes starts after the `:` (`COMP_WORDBREAKS`; ble.sh splits it there too), so the glue sees
  `-x}/zzf` and writes that part as a name.
- Revisit when: an operator types such expansions in a remote command.
- Approved: 2026-11-03, the user chose "Both known limitations (Recommended)".

### A name holding `;`, `|` or `(` in a quoted command cannot be continued
- Kind: known limitation
- What the operator sees: in a quoted command, a word holding the remote shell's `;`, `|` or `(` quoted for it
  (`mssh h "ls zz\\;<TAB>`, as TAB itself writes the common start of `zz;1` and `zz;2`) gets nothing more. A single
  name still completes from before the `;` (`mssh h "ls zz<TAB>`), and in a command typed as words such names complete.
  Nothing wrong goes in.
- Why: the engine finds the last part of a quoted command (after a `;`, `|`, `&&`, `(` ...) without reading the remote
  shell's quoting, so it takes the quoted `;` for the end of a command; reading it would take a lexer of the remote
  shell's syntax.
- Revisit when: an operator works with such names in quoted commands.
- Approved: 2026-11-03, the user chose "Both known limitations (Recommended)".

### With an engine older than the glue, quoted arguments behave as in 6.40
- Kind: known limitation
- What the operator sees: when PATH finds an older mssh-complete than the glue (a system install beside a newer venv,
  `sudo -i`, a downgrade), a quoted argument (`mssh h cat "my<TAB>`) is completed as a quoted command, so a name holding
  whitespace goes in and mssh splits it, as 6.40 does; and a `$'./zzs<TAB>` first word is written so mssh gets the wrong
  name. Quoted commands complete right. Installing the same version, so that PATH finds it, fixes it.
- Why: the older engine does not say which kind of quote it is (6.41's `D quoted` and `D whole`); guessing it from the
  line would add code used only then.
- Revisit when: mixed installs turn out common.
- Approved: 2026-11-03, the user chose "Known limitation (Recommended)".

### Whitespace in names is read as UTF-8
- Kind: known limitation
- What the operator sees: the glues leave out a name holding whitespace as mssh splits its words, and they read the
  no-break spaces and the other non-ASCII whitespace by their UTF-8 bytes. In a Latin-1 locale, where mssh reads a lone
  `\xa0` or `\x85` byte as whitespace, such a name may be offered, and mssh then runs its parts as commands of their own;
  in GBK, where `\xc2\xa0` is a character of its own, a name holding it is left out. Neither locale is tested.
- Why: the glues match bytes so that the rule holds whatever the C library calls whitespace; reading the shell's own
  encoding would need its decoder in each glue, for locales seldom met.
- Revisit when: an operator in such a locale hits it.
- Approved: 2026-11-03, the user chose "Both known limitations (Recommended)".

## Found in 6.42's review

Found while confirming and reviewing 6.42's fixes (the user's words are in each entry).

### ble.sh: in a quoted word, the second try finds nothing after a directory or an expansion
- Kind: known limitation
- What the operator sees: with ble.sh, in a quoted word, ble.sh's second try (its retry matching the typed letters in
  any order, `zzmp` finding `zzamp&b`) finds nothing in a word after a directory (`mssh h cat "sub/zzmp<TAB>`), or in a
  word holding a `$` expansion or a backtick, a leading `~`, or a quote of its own. Typing the start of the name still
  completes (`mssh h cat "sub/zza<TAB>`). Elsewhere in a quoted word the second try works since 6.42.
- Why: the cut ble.sh makes of the word for that try would drop that part, and ble.sh matches names against its own
  value of the typed word (an unset `$ZZNONE` becomes empty), so a name could go in wrong.
- Revisit when: an operator asks for it.
- Approved: 2026-11-04, the user chose "Known limitation (Recommended)".

### zsh before 5.8 with zsh-autosuggestions' async mode: a Ctrl-C now and then keeps the line
- Kind: known limitation
- What the operator sees: with zsh older than 5.8 (zsh 5.5 is EL8's) and zsh-autosuggestions in its asynchronous mode
  (its default from zsh 5.0.8), now and then a Ctrl-C while typing an mssh line keeps the line instead of dropping it: 3
  of 60 test loops on zsh 5.5 after 6.42's fix, 4 of 60 before. The plugin's own processes briefly hold the terminal:
  its background child, up to about 0.3 s on mssh lines (as long as mssh's suggestion strategy runs in it), and the
  `command true` it runs after starting that child, for about a millisecond. It cannot end the shell; press Ctrl-C
  again. zsh-autosuggestions' synchronous mode (`unset ZSH_AUTOSUGGEST_USE_ASYNC` after loading it) avoids it, with
  mssh's grey text then given 50 ms.
- Why: the cause is in the plugin's async fetch on zsh before 5.8, its child and its `command true` (zsh change 44214
  fixed the terminal handover in 5.8); mssh's own queries no longer take the terminal.
- Revisit when: zsh-autosuggestions changes its async child (reported: https://github.com/zsh-users/zsh-autosuggestions/issues/861), or an operator hits it often.
- Approved: 2026-11-04, the user chose "KL + draft report (Recommended)".

## Found in the glue's Ctrl-C and timed-read design (6.49)

What is left of the bash entries the design pass closed in 6.49 (TMOUT after Ctrl-R or in the line editor, and a Ctrl-C after
Ctrl-R or during TAB's query losing the line's first letter).

### bash: a Ctrl-C in the first moment after TAB, Ctrl-R or the line editor's space
- Kind: known limitation
- What the operator sees: in plain bash, a Ctrl-C within about one process start of the key (1 to 2 ms on an idle machine, longer on a
  loaded one) after TAB on an mssh line (bash 4.3 to 5.2), Ctrl-R on an mssh line, or the space that opens the line editor is still a
  signal: now and then it is lost, or the line is dropped and Ctrl-C only rings at the new prompt until the next Enter (bash 5.1
  and 5.2), or a line is left that Enter runs without its first letter. After that moment a Ctrl-C is a key until the menu or the
  editor closes or mssh's query is answered.
- Why: bash has nothing that turns the signal off before a first command has run, and the glue's first command is the `stty -isig`
  that does; an INT trap in its place was what made every later Ctrl-C on the line lose the first letter (bash 4.3 to 5.0).
- Revisit when: an operator hits it.
- Approved: 2026-11-25, chief's decision C245 (not the user's words).

### bash 4.3 to 5.2: a Ctrl-C while a remote command's own completion works
- Kind: known limitation
- What the operator sees: `mssh h git chec<TAB>`, and a Ctrl-C after mssh's query is answered, while git's own completion works (or in
  the glue's own last steps, a moment): `^C`, no new prompt, and Enter runs the line without its first letter (`ssh h git chec`). A second Ctrl-C gives a clean prompt. Any
  command's completion does the same in these bash versions, with or without mssh.
- Why: it is bash's own bug with any completion function, fixed in 5.3. Turning the signal off around another program's completion
  would leave a hung one with no way out.
- Revisit when: bash before 5.3 is no longer supported, or an operator hits it.
- Approved: 2026-11-25, chief's decision C246 (not the user's words).

## Found in 6.43's review

### zsh: a double-quoted expansion is still expanded where the completer is `_expand`
- Kind: known limitation
- What the operator sees: the double-quoted expansion fix does not reach a `zstyle ':completion:*' completer _expand ...`
  setup, where `mssh h "ls $PWD/zzp<TAB>` rewrites the line to `mssh h ls\ /the/directory/zzp`. As in 6.42. On zsh 5.0.2
  the quote is lost but the value is not expanded: `mssh h ls\ $PWD/zzp`.
- Why: those paths do not go through the wrapped `expand-or-complete` widget's handling of a double-quoted word.
- Revisit when: someone using `_expand` reports it.
- Approved: 2026-11-05, the user chose "Known limitation (Recommended)".

### ble.sh: a variable name typed inside a double-quoted command is completed with a space and the quote left open
- Kind: known limitation
- What the operator sees: with ble.sh, `mssh h "cat $HOM<TAB>` gives `"cat $HOME `: the variable's name and a space, the quote
  still open. As in 6.42.
- Why: low impact, seen at once, and the quote stays open.
- Revisit when: someone reports it.
- Approved: 2026-11-05, the user chose "Known limitation (Recommended)".

## Found in 6.43's second review

### zsh: a variable name typed inside a double-quoted command is completed with a space and the quote left open
- Kind: known limitation
- What the operator sees: in zsh, `mssh h "cat $HOM<TAB>` gives `"cat $HOME ` (the name, a space, the quote still open) and
  `"cat ${HOM` gives `"cat ${HOME} `. The same in `mssh h cat "$HOM`, `mssh -f "$HOM` and `mssh h "echo a; cat $HOM`.
  A single-quoted command calls mssh's completion and stays right. Seen in zsh 5.0.2, 5.5.1, 5.8 and 5.9. 6.42 gave
  `mssh h cat\ ` there, with the quote lost.
- Why: zsh hands a parameter name to its own completer before `_mssh` is called.
- Revisit when: the zsh glue wraps the parameter completer.
- Approved: 2026-11-05, the user chose "Known limitation (Recommended)".

### bash-completion: a `~name` word closes the quote
- Kind: known limitation
- What the operator sees: with bash-completion loaded, `mssh h "cat ~bi<TAB>` gives `"cat ~bin" `, quote closed, for every
  command that bash-completion has a completion for (`"cd ~bi`, `'cat ~bi`, `cat "~bi` too). A command with none
  (`zzcmd`) stays open, `~bin/`, except on bash 4.2, where it closes too. As in 6.42 with bash-completion; without it,
  fixed in 6.43.
- Why: bash-completion's own completion of the command (`_tilde`) gives `~bin` beside the glue's word, and readline closes
  the quote for it.
- Revisit when: bash-completion changes `_tilde`.
- Approved: 2026-11-05, the user chose "Known limitation (Recommended)"; the bash 4.2 case 2026-11-06, the same option.

### bash: the glue sourced while the shell is already in posix mode gives bash's default completion
- Kind: known limitation
- What the operator sees: on bash before 5.1 (4.2, 4.3, 4.4 and 5.0 checked), `set -o posix` (or `bash --posix`) before the glue
  is sourced: TAB on an mssh line completes as bash does with no glue, silently (`mssh h "nvid<TAB>` stays as typed). On
  bash 5.1 and later it works. Turning posix mode on after the glue is loaded works on every version.
- Why: the glue's functions use syntax posix mode does not read; nobody is known to run an interactive posix-mode shell.
- Revisit when: someone runs an interactive posix-mode shell with the glue.
- Approved: 2026-11-05, the user chose "Known limitation (Recommended)".

### bash 4.2: a resize can draw the prompt beside the Ctrl-R menu
- Kind: known limitation
- What the operator sees: on bash 4.2, after a window resize with the Ctrl-R menu open, the prompt can appear beside the
  line, the way bash 4.4 and later always look: bash redraws its own line on a resize, and when that comes after the menu's
  redraw the prompt stays. The box, filtering, Esc and the printed line stay right. It came up in 3 to 98 of 300 runs,
  more under load. In a window so narrow that prompt and line wrap (forced at 22 columns, on a test terminal that does not
  reflow), the wrapped text can overwrite the menu's top row until the next key, or old prompt rows can stay above the
  line after Esc. The line stays right.
- Why: `trap '' WINCH` around the menu stopped it, but bash then missed the new width, which is worse. A delayed second
  redraw cannot guarantee the order, and drawing the prompt ourselves is the expander declined in "No prompt beside the
  Ctrl-R menu on bash 4.2 and 4.3".
- Revisit when: an operator on bash 4.2 asks for it.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### bash before 5.1: a Ctrl-C during TAB leaves posix mode off
- Kind: known limitation
- What the operator sees: in an interactive bash before 5.1 with posix mode on, a Ctrl-C that cuts a TAB short leaves
  posix mode off, with `POSIXLY_CORRECT` gone from every child's environment, until the next TAB on an mssh line or
  Ctrl-R, however many prompts pass. On 4.2 a `set +o posix` typed in that window is undone by the next TAB, and an
  exported new value is replaced by the old one, staying exported.
- Why: bash gives no way to tell the call was cut short, and a prompt hook adds a part for shells nobody is known to run.
- Revisit when: someone reports using interactive posix mode.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### zsh: no names inside a directory whose name holds a backslash
- Kind: known limitation
- What the operator sees: zsh offers nothing for a word inside a directory whose name holds a backslash. Stock zsh with no
  glue does the same, on 5.0.2 and 5.9.
- Why: it comes from zsh itself, and it takes a rare directory name.
- Revisit when: zsh changes.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### zsh before 5.3 with zsh-autosuggestions: keys arriving together can run the older line's grey text
- Kind: known limitation
- What the operator sees: on zsh before 5.3 (5.0.2 to 5.2) with zsh-autosuggestions (in its synchronous mode too), keys that
  arrive together (a paste, typing ahead) can take the grey text of the line as it was before them: at `mssh gp` with grey
  `u[01-16] nvidia-smi`, `x`, Right, Enter runs `mssh gpxu[01-16] nvidia-smi`, and Ctrl-E in place of Right the same. As in 6.43.
  From zsh 5.3 on, 6.44 drops the grey text while keys are waiting.
- Why: the plugin's `_zsh_autosuggest_modify` gives the old grey text back while keys are waiting (`$PENDING > 0 || $KEYS_QUEUED_COUNT > 0`),
  before it checks the text against what was typed. The glue drops the text in a `line-pre-redraw` hook, which zsh has from 5.3 only.
- Revisit when: the plugin changes (it does the same alone with its own text); reported upstream as zsh-autosuggestions #862 (2026-11-06).
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### Tab past its limit: a remote option that mssh has too gets a name quoted for this shell
- Kind: known limitation
- What the operator sees: when TAB's query misses MSSH_COMPLETE_TIMEOUT (a slow engine, a loaded machine) and a name here needs
  quoting, `mssh h tail -f zza<TAB>` inserts it quoted for this shell, `zzamp\&b `, which the remote shell reads as
  `tail -f zzamp&b`. The same after `grep -f`, `du -s`, `sort -k` and `rsync --file=`, on bash and zsh. Every other word that may be a
  remote command's or a password gets nothing past the limit (6.44; before, all of them did).
- Why: without the engine's answer the glue cannot tell a remote command's `-f` from mssh's own, and it takes a slow engine and a
  name that needs quoting together.
- Revisit when: someone hits it.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### pip 9 cannot upgrade from or uninstall 6.43 and earlier
- Kind: known limitation
- What the operator sees: With pip 9, the pip of EL7 and EL8 (`pip3 --version`), upgrading from 6.43 or earlier and `pip3 uninstall multiSSH3` of those releases stop with `configparser.DuplicateOptionError: ... option 'multissh3' in section 'console_scripts' already exists`, and nothing changes: the installed release keeps working. Run `pip3 install -U pip` once, then upgrade or uninstall. With `--user` the same happens, except that `pip3 install --user -U multiSSH3` with no version does not stop: it installs the new release, which works, and leaves the old release's metadata behind. `pip3 list` then shows the old release after `pip3 uninstall multiSSH3`, and the next uninstall stops with that error. To avoid this, run `pip3 install --user -U pip` once first. If it has already happened, run that, run `pip3 uninstall multiSSH3` until it says multiSSH3 is not installed, and install again.
- Why: pip 9 parses the installed release's `entry_points.txt` with a parser that folds case, and `multiSSH3` and `multissh3` collide there;
  nothing in a new release can change the old release's metadata (6.44 ships `multiSSH3` as a script file).
- Revisit when: EL's stock pip stops being 9, or never.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### The `multiSSH3` spelling in a venv with a space in its path
- Kind: known limitation
- What the operator sees: With pip 10 or later, in a venv whose path has a space or is too long for the kernel's `#!` line, the `multiSSH3` spelling does not start (the error varies: "bad interpreter", `import: command not found`), because pip gives a script file a plain `#!` line: use `multissh3`. With pip 9 no spelling starts in such a venv, as in 6.43. uv and system or `--user` installs are not affected.
- Why: pip writes a plain `#!<python>` line into a script file and a `/bin/sh` wrapper only for an entry point. A launcher that delegates to the lowercase twin overwrites it on a case-insensitive disk under uv. One that execs `mcmd` or `mssh` works, but prints that name for `-V`, breaks `python3 $(which multiCMD)`, and TSVZ has no such sibling.
- Revisit when: someone hits it.
- Approved: 2026-11-06, the user chose "Known limitation (Recommended)".

### zsh: in a quoted word holding a `/`, no history name beside a command's names that are no file names
- Kind: deferred (6.49)
- What the operator sees: in zsh, in a quoted command with a `/` in the word or in a word before it, and in a double-quoted word holding an
  expansion or after a quote at an `=` with a `/` in the word, when the command's completion offers names that are no file names, mssh's
  history names are not offered beside them: `mssh h "ls /etc --col<TAB>` gives `ls`'s `--color=`, not `--colzz` from history.
  Beside file names, and beside a directory a command gives with an option's text,
  see [the entry below](#zsh-no-history-name-beside-a-directory-a-command-gives-with-an-options-text-nor-from-a-command-typed-as-words).
- Why: 6.47 puts them in the call that adds the command's file names, with its IPREFIX, PREFIX and `-p`. Put in the first call of any
  kind whose PREFIX they start with, they made zsh drop the quote (`mssh h ls /etc --col`), so 6.47 keeps them to file names. 6.48 tried a
  call of their own with the command's matcher: right for `ls`, but `ps` and `rsync` lost the quote and `df` lost the typed words (their
  completions add names with other matchers and prefixes), so 6.48 took it out again.
- Revisit when: 6.49, design first: whether history names can go in beside such names at all. 6.48's call of their own after the
  command's names, with the command's matcher, took the quote off the line for `ps` and `rsync` and cut `df`'s line back.
- Noted: 2026-11-16, the user's standing rule that deferrals are noted, not asked; moved to 6.49 on 2026-11-25 (6.48 fix round 1).

### zsh: no history name beside a directory a command gives with an option's text, nor from a command typed as words
- Kind: deferred (6.49)
- What the operator sees: in zsh, beside a directory that the command's completion gives with an option's text, a history entry typed as
  words is not offered: `mssh h make CFLAGS="-Isub/zz<TAB>`, `make CFLAGS=-Isub/zz<TAB>` and `"make CFLAGS=-Isub/zz<TAB>` with a directory
  `sub/zzlocal` and `make CFLAGS=-Isub/zzhist` in history give `-Isub/zzlocal/` alone (as in 6.46). A history entry that is
  a quoted argument (`"make CFLAGS=-Isub/zzhist"`) is offered in the last two, not after the quote at the `=`. Beside local file names in a
  word holding a `/`, a history entry typed as words (`mssh h cat sub/zzremote`, `dd if=sub/zzremote`)
  is not offered, on the line, in a quoted command, inside `$( )` and backticks (as in 6.46 and 6.47); one whose command was a quoted argument
  (`mssh h "cat sub/zzremote"`) is.
- Why: not traced; the engine returns no history name for a command typed as words there, and the glue adds none beside a call with `-P`.
- Revisit when: 6.49: find why the engine leaves out a command typed as words beside local names, and add history names beside a call with
  `-P` in a call of their own, with its `-P` and `-p`.
- Noted: 2026-11-16, the user's standing rule that deferrals are noted, not asked; narrowed and moved to 6.49 on 2026-11-23 (6.48 builder).

### zsh: in a directory typed with backslashes, no history names beside the local ones
- Kind: deferred (6.49)
- What the operator sees: in zsh, in a word whose typed directory holds backslashes the way TAB writes them, mssh's history names are
  not offered beside the local ones, which go in alone: inside backticks (`` `mssh h cat zzd\\\\\&x/zz<TAB> ``, the five backslashes TAB
  writes there for `zzd&x`) for any history entry, and in a quoted command (`mssh h "cat zzd\\&x/zz<TAB>`). On the line and in `$( )`
  (`mssh h cat zzd\\\&x/zz<TAB>`) they are offered for a history entry whose command is a quoted argument (`mssh h "cat zzd\\&x/zzremote"`),
  not for one typed as words ([the entry above](#zsh-no-history-name-beside-a-directory-a-command-gives-with-an-options-text-nor-from-a-command-typed-as-words)).
  As in 6.47.
- Why: the engine gets the word as typed, before the extra reading backticks get, and finds no history name starting with it; in a
  quoted command the head typed and the names' head read differ in the backslashes.
- Revisit when: 6.49: inside backticks, send the engine the line read once more (`_mssh_complete_tick_read`), and read the head the same
  way in `_mssh_complete_add_texts`; in a quoted command read it as the double quote does.
- Noted: 2026-11-16, the user's standing rule that deferrals are noted, not asked; moved to 6.49 on 2026-11-23 (6.48 builder).

### zsh: TAB inside a command substitution expands a bare `!b` from history
- Kind: known limitation
- What the operator sees: in zsh with `bang_hist` on (the default), a TAB inside an open `$( )` expands the history references typed
  inside it, with any command, with or without mssh: `$(mssh h "echo a!b zz<TAB>` becomes `$(mssh h "echo azz` when no history line
  begins with `b`, and `$(mssh h "echo abfoo bar zz` when `bfoo bar` is one, and on zsh 5.9 completes nothing after it (zsh 5.5.1 and
  5.0.2 complete a name after an expansion that matched). Outside `$( )` the `!b` stays
  until Enter. `setopt no_bang_hist` keeps it.
- Why: zsh itself does it before any completion function runs (stock zsh 5.0.2, 5.5.1 and 5.9 do the same without `compinit`); the
  glue cannot get back what is gone.
- Revisit when: zsh fixes it (a report to the zsh maintainers is drafted, not posted), or an operator needs `!` inside `$( )`.
- Approved: 2026-11-16, chief's decision C61 (the user's desk session; not the user's words): "(a) approve it as a known limitation,
  with an upstream zsh report drafted for you to send".

### zsh: a history name beside a directory stops TAB before its `/`
- Kind: deferred (6.49)
- What the operator sees: in zsh, with a directory `zzdir` here and `mssh h "cat zzdir/zzremote"` in history, `mssh h cat zzd<TAB>` gives `zzdir`,
  without the `/` the directory alone gets (`zzdir/`), and `zz<TAB>` after it finds nothing: type the `/` first. In a quoted command, inside
  backticks and inside `$( )` the same. A history entry typed as words (`cat zzdir/zzremote`) does not stop it. As in 6.46 and 6.47.
- Why: zsh writes a directory's `/` only when it is the one name left, and the history name is a second one, so the two share `zzdir`. 6.48
  held the history name back where the command's own names include the directory. That needed a copy in the glue of the names the command
  adds and of which of two equal names zsh keeps, and each review found a completion where the copy and zsh differ; there TAB wrote the
  command's name alone and the history name was no longer offered. So 6.48 took it out again.
- Revisit when: 6.49, design first: a route with no copy of the command's names. One tried: where a history name goes in beside it, the
  command's directory goes in with the `/` in its name, so zsh finds `zzdir/` shared and keeps the history name in the list. Open there: a
  `/` typed after TAB doubles, a space typed after TAB keeps the `/`, and TAB then walks into
  [the entry below](#zsh-tab-in-a-directory-can-write-a-start-that-a-history-name-further-down-lacks) for a history name two levels down.
- Noted: 2026-11-16, the user's standing rule that deferrals are noted, not asked; moved to 6.49 on 2026-11-25 (6.48 design check).

### zsh: TAB in a directory can write a start that a history name further down lacks
- Kind: deferred (6.49)
- What the operator sees: in zsh, with a file `zzdir/zzlocal` here and `mssh h "cat zzdir/sub/zzremote"` in history,
  `mssh h cat zzdir/<TAB>` gives `zzdir/zz`, which the history name does not start with, and the next TAB gives `zzdir/zzlocal `:
  the history name is offered again only when the `zz` is deleted (`zzdir/s<TAB>` gives it). In a quoted command the same. As in 6.47.
- Why: not traced. The history name goes in as `sub/zzremote` behind the typed `zzdir/`, with a matcher that lets a typed part end
  at a `/`; zsh seems to take `sub/` as matched and write the `zz` that both names have after it.
- Revisit when: 6.49, with the entry above, whose fix makes TAB walk into this one.
- Noted: 2026-11-25, the user's standing rule that deferrals are noted, not asked (found by 6.48's last fix round).

### zsh 5.0.2: one TAB takes seconds when the command passes tens of thousands of names
- Kind: deferred (6.49)
- What the operator sees: in zsh 5.0.2 (EL7), when a remote command's completion passes every name of a large directory or list
  (`compadd -f -- *`, `compadd -a`), one TAB takes about 17 s at 40,000 names, where zsh without mssh takes about 1 s; zsh 5.5.1
  to 5.9 take about 3 s. `_files`, which passes only the matching names, takes about 1.5 s. As in 6.47.
- Why: not traced: the glue's `compadd` wrapper reads each name the command passes in shell code, which zsh 5.0.2 runs far slower.
- Revisit when: 6.49: find where 5.0.2 spends the time in `_mssh_complete_compadd`'s loop over the names.
- Noted: 2026-11-25, the user's standing rule that deferrals are noted, not asked (found by 6.48's last fix round).

### zsh: a quote opened partway through a word of a double-quoted command holding an expansion
- Kind: deferred (6.49)
- What the operator sees: in zsh, in a double-quoted command holding an expansion, a quote the command opens partway through the word at
  the cursor offers nothing (`mssh h "echo $USER zz'a b<TAB>`), and so does a `\"` quote holding a `$`, a backtick or a backslash, which the
  remote shell would read in it (`mssh h "echo $USER \"zz\\\$x`). So does the TAB after TAB wrote a name's start with its `!` outside the
  double quote and a letter was typed behind it (bang_hist on): `\"zz"\!"x` or `'zz"\!"x` for files `zz!x` and `zz!y`, `\"zzd"\!"x/zz` for a
  directory `zzd!x`. A quote opened at the word's start completes (6.48: `"echo $USER 'zz<TAB>`).
- Why: the glue reads a quote at the word's start into IPREFIX; one partway through needs the place in the typed text where the quote's
  reading starts.
- Revisit when: 6.49: map the quote's place in the text read back to the text typed, and read the part before it as the double quote does.
- Noted: 2026-11-16, the user's standing rule that deferrals are noted, not asked; narrowed and moved to 6.49 on 2026-11-23 (6.48 builder).

### zsh: compset -q writes outside its memory for a double-quoted word holding a backslash inside a quote of its own
- Kind: known limitation
- What the operator sees: in zsh 5.0.2 to 5.9, zsh's own `compset -q` writes outside its memory for a double-quoted word that holds a
  backslash inside a quote of its own, with or without mssh, and zsh 5.9 can end (`malloc(): invalid size`). 6.46 ran it on every quoted
  command, so it met the fault for every such command (`mssh h "grep 'a\\.b' zz<TAB>`). Since 6.47 the glue splits the command itself, and
  offers nothing where `compset -q` would still meet it: the cursor inside such a quote (`mssh h "grep 'a\\.b<TAB>`), and a word that the
  command's own completion splits after the remote shell's `\'` or `\"` and a backslash (`mssh h "make CFLAGS=-DFMT=\\\"%s\\\\n\\\"<TAB>`).
  A backslash outside such a quote does not stop it (6.48: `"cat 'a' b\\c 'zz` completes).
- Why: zsh's own fault: stock zsh does it with no mssh (`_zzq() { compset -q; _files }; compdef _zzq zzq`, then `zzq "cat 'a\\b' zz<TAB>`),
  which under glibc's malloc checker (`MALLOC_CHECK_=3`, with `LD_PRELOAD=libc_malloc_debug.so.0` from glibc 2.34 on) prints
  `free(): invalid pointer` and ends. Whether the shell ends without the checker depends on what lies next to the block, so any change to
  the glue could turn it on or off. The report to the zsh maintainers is drafted (docs/progress/zsh-compset-q-report.md), not posted.
- Revisit when: zsh fixes it: the glue's test (`_mssh_complete_qfault`) goes for the zsh versions with the fix.
- Noted: 2026-11-17, as a deferral; the report is the user's to send.
- Approved: 2026-11-25, chief's decision C247 (not the user's words).

### zsh: no names for two words whose quoting the glue cannot read back the same at every level
- Kind: known limitation
- What the operator sees: in zsh, no names for an escaped blank beside a `\!` or a `\\\$` in a word the command splits itself
  (`mssh h "make CFLAGS=-O2\\ -Izzd\\\$x/zz<TAB>`), and inside backticks for a single-quoted command's value the command splits
  (`` `mssh h 'make CFLAGS=-Izzd\\\&x/zz<TAB> ``). 6.46 and 6.47 wrote a wrong word there.
- Why: 6.47's step back settled that such words get nothing, or the second-pass design that 6.48 built, never one more rule; these
  are the ones the second pass cannot take.
- Revisit when: an operator needs names there.
- Approved: 2026-11-25, chief's decision C247 (not the user's words).

### zsh: the start two names share, written for a double quote, can end inside an escape
- Kind: deferred (6.49)
- What the operator sees: in zsh, in a double-quoted command holding an expansion, two names whose written words share a start that ends
  inside an escape go in to that start: with files `zz$x` and `zz&y`, `mssh h "echo $USER zz<TAB>` gives `zz\\`, the remote shell's `zz\`.
  The `&` typed next and a TAB complete `zz\\&y`, but a `$x` typed next is read by this shell as its variable. As in 6.46.
- Why: zsh takes the start the words share as they are written (`-Q`), `zz\\\$x` and `zz\\&y`, not as the names they stand for.
- Revisit when: 6.49: insert the written form of the start the names share (`zz`), as zsh does for the words it writes itself.
- Noted: 2026-11-23, the user's standing rule that deferrals are noted, not asked (found by the 6.48 builder).

### zsh: in a quoted command, TAB on a word of df can take the words before it off the line
- Kind: deferred (6.49)
- What the operator sees: in zsh 5.5.1 to 5.9, with or without history, `mssh h "df /etc -<TAB>` and `mssh h "df -h -<TAB>` leave
  `mssh h "df `, and `mssh h "df /etc /<TAB>` leaves `mssh h "/` (as in 6.47; `'df` the same); with no history a lone `-` goes in
  any shape there (`mssh h df -<TAB>` gives `mssh h df `), as zsh's own df completion does without mssh. zsh 5.0.2 keeps the line.
- Why: not traced (found by the 6.48 fix round).
- Revisit when: 6.49: find which of df's calls takes the words before the cursor off the line in a quoted command.
- Noted: 2026-11-25, the user's standing rule that deferrals are noted, not asked.

### zsh: a name holding `!` in a double quote that the remote command opens in a quoted command reaches it with a backslash
- Kind: deferred (6.49)
- What the operator sees: in zsh with bang_hist on, `mssh h "cat \"zz<TAB>` with a file `zz!x` gives `\"zz\\\!x\"`, and
  `mssh h 'cat "zz<TAB>` gives `"zz\!x"`: the remote shell gets `zz\!x`. As in 6.47. `setopt no_bang_hist` avoids it.
- Why: there zsh writes the word itself (`compset -q`), for its own double quote, where the `\!` is history's escape. The remote shell's
  double quote keeps the backslash.
- Revisit when: 6.49: put the `!` outside both quotes, as 6.48 does for a double-quoted command holding an expansion, or offer nothing
  there with bang_hist on.
- Noted: 2026-11-25, the user's standing rule that deferrals are noted, not asked (found by the 6.48 fix round's review).

### The centos7 test image patches ble.sh's conditional-sync
- Kind: deferred
- What the operator sees: nothing from mssh; the test matrix's centos7 image (bash 4.2) runs a ble.sh whose `conditional-sync` sends its own
  shell a SIGCHLD before each `kill -0` (`tests/shells/Dockerfile.centos7`, a `sed` whose `grep` fails the build if the line moves).
  The hang is in ble.sh's own `conditional-sync`, so an EL7 user of ble.sh can hit it without mssh too: a TAB now and then waits
  for the next key, which cancels it.
- Why: on bash 4.2 a timed read can lose a job's SIGCHLD, so the job stays a zombie, `kill -0` keeps finding it, and ble.sh waited for
  the next key, which cancelled TAB: 1 in 100 to 1000 of the no-answer tests' TABs failed. Not reported to ble.sh yet (its other `conditional-sync` report, a `timeout=` that expires early, is akinomyoga/ble.sh#745).
- Revisit when: the ble.sh pin moves to a release with the fix: drop the `sed` and its `grep`.
- Noted: 2026-11-07, the user's standing rule that deferrals are noted, not asked.
