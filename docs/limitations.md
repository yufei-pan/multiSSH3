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
  such output exits 120 with Python's "Exception ignored ... BrokenPipeError" line. A run still ends quietly
  with its own status. A message that cannot reach stderr is dropped; 6.38 wrote it to stdout.
- Why: exiting 141 by hand took `_WatchedStream` and `_exit_if_output_closed` (about 60 lines) to rebuild
  what SIGPIPE's default action does.
- Revisit when: a program depends on the 141, or Windows users report the message.
- Approved: 2026-10-24, the user chose "Both (Recommended)".

### Another user's config shared through an ACL is not written
- Kind: known limitation
- What the operator sees: `--store_config_file` on a config file owned by another user, which the operator
  may write only through an ACL (or group or world write), prints `Error: Unable to write to the config
  file: ...` and the new config on stdout. 6.38 wrote such a file in place when it was 0600 or tighter.
  Configs of the operator's own, root writing a user's config (now atomic, owner and group kept) and
  symlinked configs are written as before. `--add_control_master_config` follows the same rule for
  `~/.ssh/config`, as it already did.
- Why: writing in place needed a third write path (about 40 lines with its own fchmod / fstat check). Every
  file is now written as `~/.ssh/config` was: a temporary file with the old owner, renamed over it.
- Revisit when: someone shares configs through ACLs.
- Approved: 2026-10-24, the user chose "One writer (Recommended)".

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

### Under menu-complete, mssh's words beside a nospace command's mixed words get no space
- Kind: known limitation
- What the operator sees: with bash's TAB bound to `menu-complete`, when a remote command's compspec asks for
  nospace (git, scp, rsync, cd) and offers words with and without a trailing space (`--oneline ` beside
  `--format=`), cycling inserts mssh's own history words without a space. With TAB bound to `complete` (the
  default) nothing changes. A word both mssh and the command offer is listed once.
- Why: spacing them one by one took an open-quote scanner (its time grew with quotes times line length:
  11.5 s on a 32,000-character line) and about 50 lines, for a case only menu-complete reaches.
- Revisit when: an operator using menu-complete asks for it.
- Approved: 2026-10-28, the user chose "Drop it (Recommended)".

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

## Deferred to 6.40

The items below were open for 6.39. On 2026-10-28 the user chose "Record as Deferred, 6.40 (Recommended)"
for all of them.

### ble.sh: spaces and duplicates beside a nospace command's words
- Kind: deferred
- What the operator sees: with ble.sh, a TAB in the middle of a line on a remote command whose compspec asks
  for nospace (git) leaves two spaces after the word; beside such a command's words, mssh's own words get no
  space; and a word the command gives escaped (`a\ b`) and mssh unescaped (`a b`) is not seen as the same
  word, so both can be listed.
- Why: mssh's words reach ble.sh unescaped and the command's escaped, and ble.sh treats the two kinds
  differently. An untested idea: unescape the command's words under ble.sh and use the readline rule.
- Revisit when: 6.40.
- Approved: 2026-10-28, the user chose "Record as Deferred, 6.40 (Recommended)".

### bash: a result equal to the text before bash's word reaches readline as an empty word
- Kind: deferred
- What the operator sees: when bash's word starts after a `:` or `=` and is empty (`mssh h CMD --opt=<TAB>`),
  a result of CMD's completion that is exactly the text before it (`--opt=`) becomes an empty candidate and
  goes to readline: alone, TAB adds a space after the `=`; beside other words, TAB inserts nothing of what
  they share.
- Why: found in the 6.38 review; the fix (skip an empty word after the cut) was left for a later round.
- Revisit when: 6.40.
- Approved: 2026-10-28, the user chose "Record as Deferred, 6.40 (Recommended)".

### ble.sh completes nothing in a quoted remote command
- Kind: deferred
- What the operator sees: with ble.sh, TAB inside a quoted remote command (`mssh h "systemctl rest<TAB>`)
  offers nothing, as in 6.37. Unquoted remote commands and plain bash complete.
- Why: needs a look at how ble.sh hands over a word that holds an open quote.
- Revisit when: 6.40.
- Approved: 2026-10-28, the user chose "Record as Deferred, 6.40 (Recommended)".

### bash: file names from a remote command's completion are not quoted
- Kind: deferred
- What the operator sees: in bash, file names the glue completes on this machine for a remote command (from
  `compgen -f`, `-d`, `-G` or `-c` in its compspec, and for a command with no compspec) go in unquoted and
  unmarked: `my dir` is not escaped and a directory gets a space, not a `/`. Also, for every command whose
  completion runs bash-completion's `_filedir` (cat, ls, cp, mv, rm, tail, grep, `_longopt`, ...), a history
  path `~/x` goes on the line bare, for the local shell to expand to the local home: with bash-completion
  loaded and history `cat ~/zznotes.txt`, `mssh h cat ~/zzn<TAB>` gives `cat ~/zznotes.txt `. Those functions
  turn readline's `-o filenames` on themselves, and under it readline takes mssh's words unescaped and never
  quotes a leading `~`. 6.37 and 6.38 behave the same; the test of the remote home path runs without
  bash-completion.
- Why: turning readline's `-o filenames` on for the delegate's results broke mssh's own history candidates
  and was taken back out in 6.38. The planned design: the glue quotes delegated file names itself, marks
  directories and never leaves readline's file name mode on while mssh's words are in the reply. It must also
  undo a completion function's own `compopt -o filenames` (turn on `noquote`, quote the function's words,
  mark directories), not only the glue's compgen calls. Seen too: where python-argcomplete is installed,
  `complete -D` is its global completer; the glue calls bash-completion's loaders directly, so a command with
  no completion file gets the glue's `compgen -f` where bash would run the `-D` completer.
- Revisit when: 6.40.
- Approved: deferred to 6.39 by the user in the 6.38 round; on 2026-10-28 the user chose "Record as Deferred,
  6.40 (Recommended)".

### bash: -W, -G and the actions match the whole remote word
- Kind: deferred
- What the operator sees: for a remote command whose compspec uses `-W`, `-G` or an action (`-f`, `-d`,
  `-u`, `-A ...`), and for the `&` of its `-X`, compgen gets the whole remote word, not readline's shorter
  word after a `:` or `=`. With `complete -u CMD`, `mssh h CMD --user=roo<TAB>` puts in a local file name
  (`--user=rootnotes`), where bash alone completes `--user=root`; with `complete -d CMD`, `mssh h CMD x=zz<TAB>`
  lists a file beside the directory (`zzfile` beside `zzsub/`), where bash alone completes `x=zzsub/`. (`complete -f CMD` gets the right file names from mssh's own file-name
  fallback, unless mssh offers words of its own.) Completion functions and `-C` commands are not affected.
- Why: compgen is given the word as the remote command sees it; cutting it as readline does needs care with
  the prefix mssh puts back.
- Revisit when: 6.40.
- Approved: 2026-10-28, the user chose "Record as Deferred, 6.40 (Recommended)".
