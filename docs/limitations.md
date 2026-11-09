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

### zsh: a directory the remote shell would read otherwise gets no names
- Kind: known limitation
- What the operator sees: in zsh, nothing is offered inside a directory typed so that the remote shell would read it
  otherwise: one typed with this shell's quoting alone (`mssh h cat a\&b/<TAB>`, which mssh would pass on as `a&b/`, so
  the remote shell would read `a` and `b/...`), and one typed bare in a quoted command (`mssh h "cat a&b/zz<TAB>`). bash
  replaces such a directory with the remote shell's word. Typed as the remote shell's word (`a\\\&b/`, `"cat a\\&b/`),
  the names inside it complete. A directory completed by TAB goes on completing, except in a double-quoted command
  (`"ls zzd<TAB>`, then `in<TAB>`) for a directory whose name holds `$`, a backtick, `"`, `\` or `!`, where it gives
  nothing.
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

### bash: the picker or the editor can come up with nothing reading its answer
- Kind: known limitation
- What the operator sees: in bash, Ctrl-R's picker or the line editor now and then comes up after the glue has
  stopped waiting for it, or after a Ctrl-C pressed just as it started: it draws on the terminal, but the choice made
  in it is not applied, and the line stays as it was. Press Enter or Esc to close it and try again. In tests timed
  at that moment on purpose: 1 in 250 to 300 tries; the window is tens of microseconds.
- Why: the glue waits for the picker's "ready" at most MSSH_COMPLETE_START_TIMEOUT seconds (2) and checks once more
  after the wait; between that check and its end of the pipe, the picker can still start. Closing it fully needs a
  claim step (the picker taking the terminal only once the glue confirms it still waits), as the zsh and fish glue
  have.
- Revisit when: an operator hits it.
- Approved: 2026-11-04, the user chose "Known limitation (Recommended)".

### TMOUT after Ctrl-R or in the line editor (bash before 5.2)
- Kind: deferred
- What the operator sees: on a host setting `TMOUT`, Ctrl-R on an mssh line and walking away leaves the shell logged in
  until the next Enter. The same with the line editor (`MSSH_COMPLETE_EDITOR=1`) on bash 4.4, 5.0 and 5.1: `mssh h ` and
  walking away stays logged in, also after Esc or a TAB in the editor; bash 5.2 logs out. Off mssh lines 6.43 logs out
  (6.42 stayed logged in everywhere).
- Why: moving the wait's read into `$( )` fixed nothing on any version (tested); it needs a design pass. The editor has
  the same cause.
- Revisit when: the glue's Ctrl-C and timed-read design pass after 6.43.
- Approved: 2026-11-05, the user chose "Deferred, design first (Recommended)", kept for Ctrl-R when they then picked "Fix TAB in 6.43 (Recommended)"; the line editor added the same day, "Add to the design pass (Recommended)".

### Ctrl-C after Ctrl-R loses the first letter (bash 4.3, 4.4, 5.0)
- Kind: deferred
- What the operator sees: `mssh h rm x`, Ctrl-R, Esc, Ctrl-C shows nothing and the line stays on screen; Enter then runs
  `ssh h rm x`.
- Why: a bare binding doing `trap x INT; trap - INT` does it too (seen on 4.4 and 5.0), and having no INT trap on those
  versions was not enough.
- Also: since 6.43 puts the terminal's mode back after a Ctrl-C right after Ctrl-R, the terminal is still left cooked (the
  line editor and Ctrl-U misbehave until the next Enter) in a small window around each 0.1 s read boundary: 2 of 480
  tries (about 0.4%), measured in 6.43's second review. Short of CPU the window is far wider: on bash 5.0 in a container capped
  at 0.4 of a processor, 8 of 40 tries on 6.43's glue and 12 of 40 on 6.44's, the same code, and a loaded host makes
  test_bash_ctrl_c_right_after_ctrl_r_leaves_the_terminal_in_readline_s_mode fail for this cause. The idea to test in the design pass: `stty -isig`.
- Revisit when: the glue's Ctrl-C and timed-read design pass after 6.43.
- Approved: 2026-11-05, the user chose "Deferred to design pass (Recommended)"; the residual window added the same day, "Add to the design pass (Recommended)".

### Ctrl-C during TAB's query loses the first letter (bash 4.3 to 5.2)
- Kind: deferred
- What the operator sees: `^C` with no new prompt; Enter then runs `ssh h rm x` for `mssh h rm x`, so a line that looks
  cancelled runs. A second Ctrl-C gives a clean prompt (checked on 4.4, 5.0, 5.1, 5.2; 24 of 24 in 6.43's second review).
  6.42 sometimes gave a clean prompt at once (6 of 24 tries on 4.4.23, 4 of 24 on 5.1.16, 2 of 24 on 5.0 and 5.2, 4 of 24
  on EL9); 6.43's `$( )` for the query makes it 0 of 24 on 4.3, 4.4.20, 4.4.23, 5.0, 5.1.8, 5.1.16 and 5.2: the line always
  stays. The window lasts only as long as the query.
- Why: bash's bug, fixed in 5.3: a completion with no mssh glue does it. `$( )` does not cure it, and ignoring INT
  during the query makes it worse: `trap - INT` then breaks every later Ctrl-C on that line before 5.3 (tested). Next
  idea, untested: `stty -isig` during the query.
- Revisit when: the glue's Ctrl-C and timed-read design pass after 6.43.
- Approved: 2026-11-05, the user chose "Deferred to design pass (Recommended)"; the new evidence added the same day, "Keep deferred, release 6.43 (Recommended)".

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
- Revisit when: the plugin changes (it does the same alone with its own text).
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

### zsh: beside the command's own names, a history name in a quoted command's word holding a `/` is left out
- Kind: deferred (6.47)
- What the operator sees: in zsh, in a quoted command (`mssh h "cat ~/.zz<TAB>`, `mssh h 'ls /etc --col<TAB>`), a double-quoted word
  holding an expansion (`mssh h "ls $PWD/zz<TAB>`) or after a quote at an `=` (`mssh h sort --output="sub/zz<TAB>`), when the word holds
  a `/` and the command's completion offers names, mssh's history names are not offered beside them; when it offers nothing they are,
  as in 6.45. Typed as words, in a quoted argument and after an unquoted `=` (`mssh h cat ~/.zz`, `cat "sub/zz`, `sort --output=sub/zz`)
  6.46 offers them beside the command's names.
  Inside backticks, in a typed directory holding backslashes (`` `mssh h cat zzd\\\\\&x/zz ``), history names are never offered: with a
  local name beside them it goes in alone, with none nothing is offered.
- Why: 6.46 puts history names in behind the directory typed (`-p`), as `_files` does; where the command's completion reads another
  word than mssh's (`compset -q` of a quoted command, `--output=` moved off the word) zsh then cut the line back (`mssh h "/.zzr`), so
  those cases keep 6.45's rule. Inside backticks the typed head is compared with the history names before the extra reading
  backticks get, so one holding a backslash matches none.
- Revisit when: 6.47: add history names from inside `_mssh_complete_compadd`, in the call that adds the command's file names, with
  that call's IPREFIX, PREFIX and `-p`, each history name less the part of mssh's word those stand for.
  Inside backticks: read the head in `_mssh_complete_add_texts` through `_mssh_complete_tick_read`, as `_mssh_complete_in_word` reads
  PREFIX, before `(Q)`.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: inside backticks, TAB does not go on into a changed directory in a quoted command or after a quote at an `=`
- Kind: deferred (6.47)
- What the operator sees: in zsh, inside backticks, with a directory `zzd&x` holding `zzin`, `` `mssh h "cat zzd<TAB> `` gives
  `` `mssh h "cat zzd\\\\&x/ `` (right), and a second `zz<TAB>` offers nothing. The same in a double-quoted word holding an expansion
  (`` `mssh h "ls $PWD/zzd ``) and after a quote at an `=` (`` `mssh h dd if="zzd ``, `` `mssh --file="zzd `` for `zzd$x`). Typed as
  words, in a single-quoted command, in a quoted argument and for mssh's own file options typed bare (`` `mssh -f zzd ``) TAB goes on
  into it. A directory that needs no quoting is not affected.
- Why: the text in backticks is read once more before the quoted command is split into words; `compset -q` splits it unread, at
  the `&` of `zzd\\\\&x`. Reading it once more before `compset -q` would rewrite the words typed before the one at the cursor.
- Revisit when: 6.47: read the quoted command once more for `compset -q` and put the words typed before the cursor's back in IPREFIX
  as typed.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: inside `$( )`, with bang_hist on, a name holding `!` in a double quote reaches mssh as `\!`
- Kind: deferred (6.47)
- What the operator sees: in zsh with `bang_hist` on (the default), inside `$(`, `$(mssh -f "zz<TAB>` for a file `zz!x` gives
  `$(mssh -f "zz\!x"`, and mssh gets `-f zz\!x`, a file that is not there; `$(mssh h "cat zz<TAB>` gives a remote `cat zz\!x`. On the
  line itself and inside backticks the name reaches mssh as `zz!x`. Found in 6.46's tests through Enter; 6.45 does the same for these.
  A history value after a quote at an `=` (`$(mssh h dd if="zz<TAB>` with `dd if=zz!x` in history) is new in 6.46: it now keeps the
  quote, `if="zz\!x"`, and mssh gets `if=zz\!x` (the remote shell `if=zz!x`); 6.45 dropped the quote, `if=zz\!x`, and mssh got
  `if=zz!x`.
- Why: zsh writes the `!` of a double-quoted word `\!` for its history, and inside `$(` the history does not take that backslash off.
- Revisit when: 6.47: detect the open `$(` and write the `!` outside the double quote (`"zz"\!"x"`) or in single quotes: inside
  `$(` with bang_hist on, `"zz!x"` is an event not found and `"zz\!x"` keeps the backslash; only `zz\!x` unquoted, `"zz"\!"x"` and
  `'zz!x'` give `zz!x` (Enter, 5.9 and 5.0.2). Check then how a later TAB reads that spelling.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: a value the command splits after a quote at an `=` loses the quote
- Kind: deferred (6.47)
- What the operator sees: in zsh, `mssh h make CFLAGS="-ggd<TAB>` gives `mssh h make CFLAGS=-ggdb`: the typed `"` is gone, so a `"`
  typed later to close it opens a new quote. The same after `--` (`mssh h -- make CFLAGS="-O`). 6.45 and stock zsh's `make` do the
  same. With a history name for the value (`make CFLAGS=-O2` in history) 6.46 keeps the quote: `CFLAGS="-O2" `, after `--` too. Not
  for a value holding a `/` with a local name beside it (`CFLAGS="-Isub/zz` with a directory `sub/zzlocal`): there the history name
  is not offered and the line becomes `CFLAGS=-Isub/zzlocal/`, as in 6.45 (the history-names entry above).
- Why: the command's completion (`_gcc` for make's `CFLAGS`) takes the quote off with `compset -q` and puts its names in without it.
- Revisit when: 6.47: in `_mssh_complete_compadd`, put such names in with the lead and the quote typed (`-p`), as mssh's own words are,
  so the line keeps them.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: in a double-quoted command holding `\"`, TAB puts the name after the typed word
- Kind: deferred (6.47)
- What the operator sees: in zsh, `mssh h "grep \"a b\" zz<TAB>` with a file `zzfile` gives `mssh h "grep \"a b\" zzfilezz`: the
  name goes in after what was typed instead of completing it (`sub/zz` gives `sub/zzfilezz`). A single-quoted command is fine. 6.45
  does the same, on 5.9 and 5.0.2.
- Why: zsh's own `compset -q` does it: `_zzq() { compset -q; _files }` gives `zzq "cat \"\" zzfilezz` in stock zsh 5.9 and 5.0.2.
- Revisit when: 6.47: one workaround in `_mssh`'s quoted-command path (split the command's words itself when it holds `\"`), and
  the upstream report to zsh-workers (drafted; the user sends it from their own address).
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: no names inside a directory holding `$` or a backtick in a quoted command
- Kind: deferred (6.47)
- What the operator sees: in zsh, with a directory `zzd$x` (or ``zzd`x``) holding `zzin`, `mssh h "cat zzd<TAB>` gives `"cat zzd\\\$x/`
  (right), and a second `zz<TAB>` offers nothing, on the line and in `$(`. As in 6.45. Typed as words or in a quoted argument TAB goes on.
- Why: after `compset -q` the completion reads the directory as `zzd\$x`, written for the remote shell, which names no directory here.
- Revisit when: 6.47: in a quoted command, read each directory of the word the way `_mssh_complete_typed_dirs` matches them (written for
  this shell or for the remote shell) before the completion looks in it, and put the typed text back in front, as inside backticks.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

### zsh: `dd`'s completion turns a typed `~` after `if=` into this machine's home
- Kind: deferred (6.47)
- What the operator sees: in zsh, `mssh h dd if="~/zz<TAB>` puts this machine's home path where the `~` was typed. Inside the quote the
  typed `~` is a literal `~`, which the remote shell gets as it is (a file named `~` there), so TAB deletes it and can change the remote
  word. The same unquoted (`mssh h dd if=~/zz`), where this shell does not expand the `~` either. Stock zsh does it for
  `dd` itself (`dd if="~/zz<TAB>`, 5.9 and 5.0.2), and 6.45 did it too, dropping the quote; `sort --output="~/zz<TAB>` keeps the `~`.
- Why: zsh's completion of `dd` (`_dd`) writes back the directory it expanded.
- Revisit when: 6.47: keep the typed directories of a value after an `=` in front (`_mssh_complete_dq_parts`), as for a double-quoted
  word, so `_dd` reads the expanded directory and the line keeps the `~`.
- Noted: 2026-11-08, the user's standing rule that deferrals are noted, not asked.

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
