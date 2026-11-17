# Draft: zsh report, `compset -q` frees an invalid pointer for a double-quoted word with a backslash inside a quote of its own

A draft for the user to send to zsh-workers@zsh.org (posting it is the user's own word). Found in the second design check of
multiSSH3 6.47 (2026-11-17), listed in docs/limitations.md on feat/647 as "zsh: compset -q writes outside its memory for a
double-quoted word holding a backslash inside a quote of its own". Checked 2026-11-17 in Docker with the repo's test images
(Debian trixie zsh 5.9, Rocky 9 zsh 5.8, Rocky 8 zsh 5.5.1, CentOS 7 zsh 5.0.2), as a non-root user, in `zsh -f -i` with
`compinit`, under glibc's malloc checker: `MALLOC_CHECK_=3`, with `LD_PRELOAD=libc_malloc_debug.so.0` from glibc 2.34 on.

---

Subject: compset -q calls free() on an invalid pointer for a double-quoted word with a backslash inside a quote of its own

Hello,

`compset -q` on a double-quoted word that holds a backslash inside a quote of its own (`'...'`, or `\"...\"`) calls
free() on an invalid pointer. glibc's malloc checker ends the shell at the call. Without it nothing shows in the small setup
below; in a larger setup (a completion function of mine that runs `compset -q` on such a word) zsh 5.9 ended some time
later with `malloc(): invalid size (unsorted)`, so whether the shell ends depends on what lies next to the block.

To reproduce, in an empty directory holding one file `zzfile`, with no rc files:

    % zsh -f
    % autoload -Uz compinit; compinit -u
    % _zzq() { compset -q; _files }
    % compdef _zzq zzq
    % zzq "cat 'a\\b' zz<TAB>

With `MALLOC_CHECK_=3` (and `LD_PRELOAD=libc_malloc_debug.so.0` where glibc is 2.34 or later), zsh prints
`free(): invalid pointer` and ends (CentOS 7 also prints a backtrace).

Which words do it (typed after `zzq `, then TAB; every line here is a double-quoted word that `compset -q` splits):

    "cat 'a\b' zz        ends   (one backslash)
    "cat 'a\\b' zz       ends
    "cat 'a\\\\b' zz     ends
    "cat 'a\\' zz        ends   (the backslash last in the quote)
    "cat 'a\\b           ends   (the quote not closed)
    "cat \"a\\b\" zz     ends   (an escaped double quote as the inner quote)
    "cat a\\b zz         fine   (the backslash outside any inner quote)
    "cat 'a' b\\c zz     fine
    "cat 'a\$b' zz       fine   (the backslash of \$, \` or \" only)
    "cat 'a\"b' zz       fine
    "cat 'a b' zz        fine   (no backslash)
    "cat 'zz             fine

Seen with zsh 5.9, 5.8, 5.5.1 and 5.0.2, all alike (the unclosed-quote line on 5.5.1 in every one of six tries).

What I expected: `compset -q` leaves its memory alone, whatever the word holds. I have not looked for the cause in the source;
a build with AddressSanitizer would show which free it is.

Thank you.
