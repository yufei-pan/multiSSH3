# Draft: zsh report, history expansion at TAB inside an open `$( )`

A draft for the user to send to zsh-workers@zsh.org (posting it is the user's own word). Chief's decision C61 (2026-11-16)
asked for it with the known limitation "zsh: TAB inside a command substitution expands a bare `!b` from history"
(docs/limitations.md on feat/647). Checked 2026-11-16 in Docker with the repo's test images (Debian trixie zsh 5.9,
Rocky 8 zsh 5.5.1, CentOS 7 zsh 5.0.2), as a non-root user, with a widget that prints `$BUFFER` after the TAB.

---

Subject: TAB inside an unclosed $( ) performs history expansion on the buffer

Hello,

With BANG_HIST set (the default), pressing TAB while the cursor is inside an unclosed command substitution runs history
expansion on the text typed inside the substitution and writes the result back into the edit buffer. Nothing is completed.
Outside $( ) the same text stays as typed until accept-line.

To reproduce, in an empty directory holding one file `zzplain`, with no compinit and default options:

    % echo $(echo "a!b zz<TAB>

The buffer becomes `echo $(echo "azz`: the `!b ` is gone, with no message, and `zz` is not completed. After
`print -s 'bfoo bar'`, the same TAB gives `echo $(echo "abfoo bar zz`. Other shapes:

    $(echo a!b zz<TAB>       ->  $(echo azz         (unquoted)
    $(echo "zz!b<TAB>        ->  $(echo "zz         (the reference at the end of the word)
    echo "a!b zz<TAB>        ->  unchanged           (no command substitution)
    setopt no_bang_hist; $(echo "a!b zz<TAB>  ->  unchanged

Seen with zsh 5.0.2, 5.5.1 and 5.9, the same with and without compinit.

What I expected: TAB leaves the `!b` in the buffer, as it does outside $( ), so that accept-line expands it or reports
"event not found". As it is, a reference with no matching event disappears silently, and one with a match is replaced by
history text the user did not ask to see yet.

Thank you.
