# mssh Autocomplete — SP2: Grey Suggestions and the Picker

**Date:** 2026-10-12
**Status:** Design approved in conversation; written spec awaiting review
**Package:** multiSSH3 (`mssh_complete.py`, shell glue, `multiSSH3.py --completion`)
**Builds on:** `docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md` (SP1: engine, index, TAB completion). Everything SP1 decided still holds unless this spec says otherwise.

## Goal

Cut more keystrokes from mssh lines without getting in the way:

- **Grey suggestions** ("ghost text"): while typing an mssh line, show the most likely rest of the line in grey after the cursor; one key accepts it. In zsh, in bash with ble.sh, and in plain bash through an opt-in mssh line editor. fish keeps its built-in suggestions, which already use SP1's completions.
- **The picker:** Ctrl-R on an mssh line opens a menu below the prompt with the ranked candidates for what the cursor is on, plus a tab of whole past invocations, filtered by fuzzy typing.

Both are built so the future mssh TUI can reuse them.

## Principles (inherited from SP1)

1. Never cost keystrokes: a suggestion is only taken by an explicit key; Enter runs what was typed, never the grey text; nothing alters or deletes typed text.
2. Never get in the way: anything slow, missing or failing falls back silently to the shell's normal behaviour; nothing is printed; every key the operator relies on keeps working.
3. Never change what mssh runs.
4. Usefulness before speed: suggestion quality is measured by replaying history and tuned before release.

## Decisions

| Topic | Decision |
|---|---|
| Where grey text appears | zsh (own widget, or as a zsh-autosuggestions strategy when that plugin is loaded); bash with ble.sh (an `mssh` source in ble.sh's suggestion list); plain bash through the mssh line editor; fish unchanged |
| Plain bash entry | Opt-in (`mssh --completion install bash --editor`): pressing space when the line is exactly an mssh name (cursor at its end) enters the editor |
| Plain bash exit | Any edit that breaks the `mssh ` prefix, and any key the editor does not handle, hands the line back to readline (unhandled keys are replayed through the operator's own binding) |
| What the grey text predicts | Adaptive: the whole rest of the line when one past invocation clearly dominates, only the rest of the current word when only that is clear, nothing when unsure |
| Picker | Slot menu (candidates for the current slot) with a history tab (whole past invocations); fuzzy filter; inserts, never runs |
| Picker key | Ctrl-R on mssh lines; on other lines Ctrl-R does exactly what it did before the glue loaded |
| Architecture | One process per request (approach A): async one-shot queries in zsh, interruptible one-shot queries in ble.sh, one `mssh-complete pick` per Ctrl-R, one `mssh-complete edit` per edited mssh line (engine loaded once inside it); no daemons |
| Code location | Stays in `mssh_complete.py` (new sections for suggestions, terminal drawing, editor, picker); `multiSSH3.py` only gains `--completion install ... --editor` |
| Index | Format 2: adds per-feature use counts and last-used times (for the picker); a format-1 index is rejected and rebuilt in the background |
| Quality gate | Replay evaluation gains a `ghost` policy; thresholds tuned on synthetic and real history; a test bounds the wrong-suggestion rate on synthetic history (initially 10%) |

## Context

What SP1 already gives:

- `Response.ghost` and the protocol's `G` record were reserved for this; requests already carry `ble=`, `zas=` and `term=` flags.
- fish autosuggestions already draw from SP1's completions.
- With ble.sh loaded, bash already shows grey text built from SP1's TAB candidates (verified in the Docker matrix on bash 4.2, 4.4 and 5.2); → accepts it. ble.sh decides which candidate becomes the grey text.
- The replay evaluation shows that always taking the top candidate is wrong 24–34% of the time on synthetic history, so grey text needs a confidence threshold.

Spike results (plain bash, 10k hosts, 20k history entries, measured in the Docker images):

| bash | Space after `mssh` → editor ready | Per key, query + redraw (p50 / max) |
|---|---|---|
| 5.2 | 31 ms | 1.5 / 3.7 ms |
| 4.4 | 41 ms | 2.6 / 6.6 ms |
| 4.2 | 51 ms | 3.4 / 9.0 ms |

Facts the spike established:

- A space bound to a macro `"\C-x\C-t\C-x\C-y"`, where `\C-x\C-t` runs a `bind -x` function and that function rebinds `\C-x\C-y` on the fly (to `accept-line`, or to a no-op, or to anything else), lets a `bind -x` function decide what readline does next. Enter-runs-the-line and plain spaces both work this way on bash 4.2, 4.4 and 5.2.
- Every bash version clears the current line (`\r\e[K`) before running a `bind -x` command, so a program that draws on that line must redraw the prompt itself.
- A whole-line suggestion inside an open quote must include the closing quote; otherwise bash reads a continuation line.

ble.sh (nightly 2026-09-08, `d81fd54`): grey text comes from the sources named in the array `_ble_complete_auto_source` (default `(history syntax)`), each a function `ble/complete/auto-complete/source:<name>` that returns 0 after calling `ble/complete/auto-complete/enter <type> <comp1> <suggestion> <cand> <word> [<insert> <suffix>]`, 1 to let the next source try, or 148 when interrupted by input. `ble/util/conditional-sync <command> [<continue>] [<weight>] [<opts>]` runs a command in the background and returns 148 as soon as the user types, 142 on `timeout=<ms>`. These are ble.sh internals, not a published API.

## Architecture

### Components

| Piece | Job |
|---|---|
| `Engine.suggest(request)` | Fills `Response.ghost` with a `Ghost(kind, text, confidence)`: `kind` is `line`, `word` or absent; `text` is what goes after the cursor |
| Protocol | Request flag `ghost=1` asks for a suggestion; the response carries `G <kind>\t<text>` (SP1 reserved the record; old glue ignores it) |
| Terminal layer | Raw-mode `/dev/tty` handling, key decoding, display width (wide characters), wrapping, drawing with restore on exit and on termination signals, colour capability |
| `mssh-complete pick` | The picker: reads an `MSSHC1` request on stdin, draws on `/dev/tty`, prints the new line and cursor; exit 0 chosen, 1 cancelled, 2 unavailable (the shell then falls back) |
| `mssh-complete edit` | The plain-bash line editor: owns the line after `mssh `; prints the line, cursor and what readline should do next |
| Glue | zsh suggestion widget or zsh-autosuggestions strategy; ble.sh source; plain-bash editor entry; Ctrl-R in all four shells |

The terminal layer, the picker and the editor are classes (`Terminal`, `Picker`, `LineEditor`) that take a terminal and a candidate source, so the future TUI can embed them.

### Request and response additions

- Request flags: `ghost=1` (compute a suggestion), `pick=1` (sent by `pick`, which reads the same request format), `redraw=1` (the picker or editor must redraw the prompt line; the expanded prompt follows the word field in a `prompt=` flag value, base64-encoded so it may hold any bytes).
- `G` record: `G line\t<text>` or `G word\t<text>`; at most one; only when the cursor is at the end of the line.
- `pick` and `edit` print `MSSHC1`, then `L <cursor>\t<line>`, then for `edit` a `K <action>\t<key>` record, then `E` and a NUL. `<action>` is `run` (readline accepts the line), `edit` (readline continues editing), `pass` (readline handles `<key>`, the raw bytes of the key that ended the editor, written with C-style escapes) or `abandon` (the line is dropped and a fresh prompt shown, like Ctrl-C).

## The suggestion model

### When

Only on mssh lines (the first word is an mssh name), only with the cursor at the end of the line, never while the picker or a menu is open.

### What

Slot by slot, because history holds mssh's canonical form (shortened, reordered options; `-su` on every line) and a textual match against past lines rarely lines up with what was typed:

1. Parse the line with SP1's `parse_context`. Rank the values of the current slot that extend the typed word (SP1's scoring, context from both sides of the cursor).
2. Take the top value `v` and its share of the summed scores: `p_word`.
3. Rank the continuation: each positional slot after the current one that is not typed yet — the hosts (when the cursor is before them) and the first command — is scored with SP1's scoring, using the line's features plus `v`'s own feature (as if `v` were typed, e.g. `h:gpu[01-16]`). The continuation `c` is each such slot's top value; `p_rest` is the smallest of those values' shares.
4. Build the suggestion text:
   - the rest of `v` after the typed word;
   - when `p_rest` passes, then `c`: a space and the hosts, and/or a space and each command quoted with the quote style already used on the line (default `"`), choosing a quote that needs no escapes (SP1's `_quote_command` rule);
   - when the cursor is inside an open quote, the closing quote after the current command's rest.
   Options are never added in SP2.
5. Show it: `line` when `p_word ≥ T_word` and `p_rest ≥ T_line` and a continuation exists; `word` when only `p_word ≥ T_word`; nothing otherwise. Initial `T_word = 0.5`, `T_line = 0.6`, both tuned by the replay evaluation.

The suggestion must extend the typed text: the shown line is always `typed + text`.

### Keys

- Accept all: → at the end of the line, End, Ctrl-F.
- Accept the next word: Alt-→, Ctrl-→, Alt-F.
- Typing a character equal to the next character of the suggestion shrinks it without a new query; any other edit asks for a new suggestion.
- Enter runs only what was typed. TAB keeps its SP1 behaviour.

### Measuring it

The replay evaluation adds a `ghost` policy: at each position the simulated operator presses → (or the word-accept key) when the suggestion matches the intended continuation, else types a character. It reports keys saved, how often a suggestion shows, how often a shown suggestion is wrong (divergent), and accepts that alter typed text (required zero). Thresholds are set from this report on synthetic history and on real history recorded with typed hosts (`--since`) before release.

## The plain-bash line editor

### Turning it on

`mssh --completion install bash --editor` writes `export MSSH_COMPLETE_EDITOR=1` into the marked rc block before the glue is sourced. The glue binds the editor entry only when that variable is `1`, ble.sh is not loaded, and readline is in emacs mode (`set -o emacs`); vi-mode users keep TAB and the picker.

### Entering

Space is bound in the emacs keymap to the macro `"\C-x\C-t\C-x\C-y"`. The `bind -x` function behind `\C-x\C-t`:

- If the line is exactly one of `mssh mssh3 multissh multissh3 multiSSH3` and the cursor is at its end, it runs `mssh-complete edit` with the line, the expanded prompt (below) and the shell history tail, then applies the result.
- Otherwise it inserts a space at the cursor and binds `\C-x\C-y` to a no-op.

If the editor cannot start (missing engine, Python error before it reads a key), the function inserts the space as usual. Keys typed while the editor starts stay in the terminal's buffer (readline is not reading) and reach the editor in order.

### What the editor handles

| Key | In the editor |
|---|---|
| Printable characters | Insert at the cursor |
| Backspace / Delete | Delete inside the editor's part of the line; Backspace at the start of that part breaks the prefix (see Leaving) |
| ← / → | Move; → at the end accepts the suggestion |
| Ctrl-A / Home, Ctrl-E / End | Move to the start of the editor's part / the end (End accepts the suggestion) |
| Alt-→, Ctrl-→, Alt-F / Alt-←, Ctrl-←, Alt-B | Accept the next suggested word, else move a word / move back a word |
| TAB | Insert the candidates' common prefix like bash; when nothing would be inserted, open the slot menu (the picker's slot tab) |
| Ctrl-R | The picker, in-process |
| Enter | Hand back with `run` |
| Ctrl-C | Hand back with `abandon` |

### Leaving

The editor always hands back the line and the cursor; readline carries on.

- **The prefix breaks** (Backspace into `mssh `, Ctrl-U, Ctrl-W reaching the prefix): action `edit` with the edited text.
- **A key the editor does not handle** (↑/↓, Ctrl-K, Ctrl-L, Alt-shortcuts, function keys, anything else): action `pass` with the key's bytes. The glue binds `\C-x\C-y` to a macro of those bytes, so readline applies the operator's own binding for that key.
- **Enter**: `run` → `\C-x\C-y` bound to `accept-line`.
- **Ctrl-C**: `abandon` → the line is emptied and `\C-x\C-y` bound to `accept-line`, which shows a fresh prompt without running anything.
- **Any failure** after starting: action `edit` with the text as it was when the editor started, or as typed so far if the editor still knows it.

### Drawing

- The prompt: bash has cleared the line, so the editor redraws the last line of the prompt and the text. The glue passes `${PS1@P}` on bash 4.4+; on bash 4.2/4.3 the editor expands `PS1` itself for `\u \h \H \w \W \$ \[ \] \e \033 \n \t \d \@ \A \T \j \s \v \V \!` and leaves `$(...)` and variables unexpanded. Non-printing sequences (between `\[ \]` or ANSI escapes) take no width.
- The line wraps at the terminal width (re-read on `SIGWINCH`); display width counts wide characters as two columns.
- The grey text is drawn with `\e[2m` (dim), or `\e[38;5;244m` when `TERM` names a 256-colour terminal. With `TERM=dumb`, an unknown terminal or no colour support, the editor shows no grey text but otherwise works.
- On exit the editor erases everything it drew and leaves the cursor where bash expects it, so bash's redraw is exact.

## zsh

- **With zsh-autosuggestions** (its `_zsh_autosuggest_start` function exists): the glue defines `_zsh_autosuggest_strategy_mssh` and prepends `mssh` to `ZSH_AUTOSUGGEST_STRATEGY`. The strategy answers only on mssh lines (it sets nothing otherwise, so the next strategy runs), reuses the previous suggestion while the buffer still extends it, and otherwise queries the engine through a file descriptor read with `zselect` and a 50 ms limit (the SP1 zsh glue's mechanism), giving up silently when it passes. zsh-autosuggestions draws and accepts.
- **Without it**: an own widget set, needing zsh 5.3+ (`add-zle-hook-widget line-pre-redraw`):
  - on each redraw where the buffer changed, is an mssh line and the cursor is at the end, close any pending request and start a new one on a file descriptor (`exec {fd}< <(...)`), with `zle -F $fd` as the handler;
  - the handler reads the response, and if the buffer is unchanged sets `POSTDISPLAY` to the suggestion and adds a `region_highlight` entry (`fg=8`, or `fg=244` with 256 colours) covering it;
  - the accept keys are widgets wrapping `forward-char`, `end-of-line`, `forward-word` (and the Ctrl-→ / Alt-→ sequences): with a suggestion showing at the end of the line they accept it (all or one word); otherwise they do their normal job;
  - `POSTDISPLAY` is cleared when the line is accepted or the buffer stops being an mssh line.
- The tested floor stays zsh 5.5.

## bash with ble.sh

- When `BLE_VERSION` is set and both `_ble_complete_auto_source` and `ble/complete/auto-complete/enter` exist, the glue defines `ble/complete/auto-complete/source:mssh` and prepends `mssh` to `_ble_complete_auto_source`. Otherwise it adds nothing (TAB still works as in SP1).
- The source returns 1 (next source) unless the line is an mssh line with the cursor at the end. It writes the request to a temporary file, runs `mssh-complete query` through `ble/util/conditional-sync` with `timeout=300`, returns 148 if the user typed meanwhile, and otherwise calls `ble/complete/auto-complete/enter h 0 "<text>" '' "<line + text>"` (a whole-line suggestion, like ble.sh's history source) for both `line` and `word` suggestions.
- ble.sh draws the grey text and handles its accept keys.

## fish

Suggestions stay fish's own. Ctrl-R on mssh lines opens the picker (below).

## Ctrl-R in every shell

On an mssh line Ctrl-R opens the picker; the chosen text replaces the line and the cursor is placed after it. On any other line Ctrl-R does exactly what it did before the glue loaded.

- **Plain bash:** when the glue loads, it records the current `\C-r` binding from `bind -p` (a readline function), `bind -s` (a macro) or `bind -X` (a shell command, e.g. fzf's). `\C-r` becomes the macro `"\C-x\C-r\C-x\C-y"`; the `bind -x` function behind `\C-x\C-r` runs the picker on mssh lines and otherwise binds `\C-x\C-y` to the recorded binding (function name, macro, or the same shell command through `bind -x`).
- **bash with ble.sh:** a ble.sh widget bound to `C-r` in the emacs and vi-insert keymaps; it calls the picker on mssh lines and otherwise the widget previously bound to `C-r` (recorded with `ble-bind -P`), falling back to `ble/widget/history-isearch-backward`.
- **zsh:** the widget previously bound to `^R` (recorded with `bindkey '^R'`) is kept and called on non-mssh lines.
- **fish:** the previous `\cr` binding (from `bind \cr`, in the default and insert modes) is kept and called on non-mssh lines; on mssh lines the result replaces the line with `commandline -r`.
- The rc block is appended at the end of the rc file, so it records fzf's or atuin's Ctrl-R when those are set up earlier.

## The picker

### Running it

`mssh-complete pick` reads an `MSSHC1` request (flag `pick=1`) on stdin, draws on `/dev/tty` in raw mode, and prints the result as described under "Request and response additions". In the plain-bash editor the same `Picker` runs in-process.

### Layout

- Up to 10 rows below the prompt line (fewer when the terminal is short), like `fzf --height`: the picker prints the needed newlines, moves back up, and draws.
- bash clears the line before a `bind -x` command runs, so the bash glue sends `redraw=1` with the expanded prompt and the picker redraws the prompt's last line and the text first (same prompt handling as the editor). zsh and fish leave the line on screen and do not send it.
- A title row (`commands for gpu[01-16]`, `hosts`, `history`), the candidate rows (text, description, uses and age, the selected row in reverse video), and a status row: `type to filter · Tab: history · Esc`.
- On exit the picker erases its rows and returns the cursor to the prompt line.

### Tabs

- **Slot** (opens first): the candidates for the current slot, up to 200, from the same engine and ranking as TAB. Choosing one replaces the current word exactly as completing it would (SP1's framing rules, closing quote and space included).
- **History** (Tab switches): whole past invocations, the last 5000 distinct lines of the history file plus the mssh lines of the shell history in the request, ranked by similarity to what is typed (SP1's features) and then by recency. Choosing one replaces the whole line with the mssh name the operator typed (or `mssh`) followed by the recorded options, hosts and commands.

### Filtering

Typing filters by fuzzy match: the query's characters in order, scored with bonuses for consecutive characters and word starts; space-separated terms must all match. The match score is combined with the context rank so likely choices stay on top. Backspace edits the filter.

### Keys

↑/↓ or Ctrl-P/Ctrl-N move; PgUp/PgDn page; Ctrl-R moves down (as repeated reverse search does); Enter chooses; Esc or Ctrl-G cancels and leaves the line unchanged; Tab switches tabs.

### Uses and age

Rows show "used 12x · 2h ago". The index (format 2) adds two rows aligned with the feature table: `fcounts` (uses per feature) and `flast` (last-used time per feature); `MemoryKnowledge` tracks both for the history tail and the shell history.

### Unavailable

With `TERM=dumb`, an unknown terminal, or fewer than 5 rows, `pick` exits with status 2 and Ctrl-R keeps its previous behaviour.

## Installation

- `mssh --completion install bash|zsh|fish` installs the SP1 completion plus SP2's suggestions and Ctrl-R. `--editor` (bash only) also turns on the plain-bash editor.
- `uninstall` still removes exactly what install wrote.
- The glue file is generated at install time. After upgrading mssh, run `install` again to get new glue; old glue keeps working without the new features because every new record and flag is optional. The README says so.

## Failure behaviour

- Nothing is printed and nothing blocks: zsh suggestions are asynchronous (the zsh-autosuggestions strategy has a 50 ms deadline), ble.sh queries are interrupted by typing and time out at 300 ms, the picker and editor always restore the terminal mode (in `finally` blocks and on `SIGTERM`/`SIGHUP`), and a crash leaves the line as it was.
- With no index yet, the picker opens with "building index…" in its status row and fills in when the background build finishes; grey text appears once the index exists.
- A key the editor does not handle is replayed through readline, never dropped.
- When the terminal cannot do what is needed (`TERM=dumb`, too few rows), suggestions and the picker are off and everything else works as in SP1.

## Performance observation

The benchmark (`tests/bench_complete.py`) adds: suggestion query time (one-shot), editor start and per-key time, and picker open time, at 10k hosts and 20k invocations. As in SP1 these are observations, not gates.

## Testing

pytest, plain `test_*` functions, in `tests/`; real-shell tests run in the Docker matrix, where missing required shells or tools fail.

- **Suggestion engine:** `line`/`word`/none levels and thresholds; slot-by-slot construction (current word, hosts, commands); quote choice and the closing quote inside an open quote; the shown line always extends the typed text; no suggestion when the cursor is not at the end or the line is not an mssh line.
- **Replay evaluation:** the `ghost` policy's metrics; on synthetic history the wrong-suggestion rate stays at or below 10% and the policy saves more keys than SP1's bash TAB policy; zero accepts that alter typed text.
- **Terminal layer:** key decoding (CSI, SS3, Alt as Esc-prefix, UTF-8); display width with wide characters; wrapping; drawing into an in-memory terminal grid (a small VT100 subset written for the tests, no third-party libraries).
- **Picker:** fuzzy scoring; history-tab line reconstruction; how a choice replaces the word or the line; rendering of title, rows and status in the grid; cancel leaves the line unchanged.
- **Editor as a state machine:** keys → text, cursor and action (`run`, `edit`, `pass`, `abandon`); prefix breaks; the bash 4.2/4.3 prompt expander.
- **Real shells (matrix):**
  - plain-bash editor: entering on space, a fast type-ahead burst, accepting a suggestion with →, Enter running the line (a fake `mssh` shell function records its arguments), breaking the prefix, ↑ replayed to readline (recalls history), Ctrl-C, Ctrl-R inside the editor, `TERM=dumb`;
  - Ctrl-R picker on mssh lines and the previous binding (readline's, and a fake fzf-style shell command) on other lines, in plain bash, ble.sh, zsh and fish;
  - zsh suggestions with and without zsh-autosuggestions;
  - ble.sh suggestions coming from the `mssh` source (a suggestion that only the engine can know);
  - new shells stay silent with the SP2 glue (including `--editor`), and keep `$?`.
- **Matrix images** add zsh-autosuggestions, pinned by checksum like ble.sh, in the images that have zsh.
- **Regression:** the existing suite and SP1's shell tests keep passing.

## Out of scope for SP2

- Diagnostics and async host probing (SP3).
- Adding options to suggestions.
- The editor in vi mode.
- A per-shell warm worker or a daemon (approach B/C), unless zsh's per-keystroke cost proves to matter on busy login nodes.
- The mssh TUI itself.

## Release

1. Bump `version` in `multiSSH3.py` and in `mssh_complete.py`.
2. `uvpack` multiSSH3.
3. cas-toolbox: bump the `multissh3` pin (and add `mssh-complete` to `[project.scripts]` if SP1's release did not) in the next Monday roll-up.


## Deviations found while implementing

Implementing and testing SP2 (unit tests, the synthetic replay, real bash 4.2 / 4.4 / 5.2, zsh 5.5 / 5.9, fish 3.3 / 4.0 and ble.sh in Docker) changed these details of the design above.

| Area | The design said | Implemented | Why |
|---|---|---|---|
| Turning the editor on | `mssh --completion install bash --editor` | `mssh --completion install bash editor` (`mssh-complete install bash --editor` also works) | mssh's own argument parser rejects `--editor` as an unknown option |
| Prompt for `pick` / `edit` | base64 `prompt=` flag | `$MSSH_COMPLETE_PROMPT` (with `expand=1` / `--expand` when it is PS1 itself, bash 4.2 / 4.3) | no encoding needed, any bytes pass |
| `pick` / `edit` output | ends with `E` and a NUL | ends with `E` | the shells read it with command substitution |
| Editor actions | `run`, `edit`, `pass`, `abandon` | `pass` (keys for readline, possibly none) and `abandon` | Enter is passed on as `\C-m`, so the operator's own Enter binding runs; a broken prefix passes nothing |
| Hook keys | `\C-x\C-r` for Ctrl-R | `\C-x\C-o` (emacs), `\C-x\C-q` (vi-insert), `\C-x\C-t` (space), trampoline `\C-x\C-y` | `\C-x\C-r` is readline's `re-read-init-file`; before bash 5.1 one table holds the `bind -x` commands of all keymaps |
| When bash takes its keys | when the glue loads | at the first prompt (PROMPT_COMMAND entry that removes itself) | the rc line sends stderr to /dev/null, where readline starting early loses its terminal setup; bindings made later in the rc file (fzf) are recorded too |
| Ctrl-R on other lines, bash | `\C-x\C-y` bound to the recorded binding | a readline function or macro is put back on Ctrl-R while it runs and Ctrl-R is taken back at the next prompt; a shell command (fzf, atuin) is called directly; when the binding cannot be listed (`bind -x` before bash 4.3) Ctrl-R is left alone | readline's incremental search repeats on Ctrl-R only when Ctrl-R is bound to it |
| Ctrl-R on other lines, zsh | the previous widget is called | also `bindkey -M isearch '^R'` to that widget | zsh's search repeats on Ctrl-R only when Ctrl-R is bound to it |
| zsh setup | when the glue loads | at the first prompt (precmd, once) | zsh-autosuggestions loaded after the mssh block is found |
| zsh-autosuggestions limit | 50 ms | 50 ms in its synchronous mode; the normal timeout in its asynchronous mode (the default from zsh 5.0.8) | async fetches do not block typing |
| ble.sh | source and Ctrl-R defined at load | through `blehook/eval-after-load` (`complete`, `keymap_emacs`, `keymap_vi`); Ctrl-R is taken when its binding is a widget, `-x` or `-c` | ble.sh loads those modules lazily |
| fish Ctrl-R | (not placed) | `~/.config/fish/conf.d/mssh-complete.fish`, taking Ctrl-R at the first prompt | fish loads completion files lazily; key bindings exist only from the first prompt |
| Picker placement | the picker prints newlines and moves back up | the same, keeping the column with raw line feeds and save / restore cursor; no cursor position report | a late report over a slow link would leak into the shell's input |
| Picker without an index | "building index…" status, filled in later | the first query builds the index within SP1's first-build budget | one code path |
| Editor entry | space bound to the macro | only when space is `self-insert` or `magic-space` | other space bindings are the operator's |
| Thresholds | `T_word = 0.5`, `T_line = 0.6` | `T_WORD = 0.7`, `T_LINE = 0.6`, confidence = share × uses / (uses + 1) | tuned on synthetic and real history: 7% of shown suggestions wrong, more keys saved than TAB alone |
| Raw mode | (not specified) | `TCSANOW` | the default `TCSAFLUSH` drops keys typed while the program starts |
| Suggestions | on mssh lines | the engine also refuses lines whose first word is not an mssh name | |
| Index file | (format 2) | still `complete-index.v1.nsv`, format 2 inside | an old engine finds a format it cannot read and rebuilds, as the design says |
| ble.sh query limit | 300 ms | `MSSH_COMPLETE_GHOST_TIMEOUT` (ms, default 300) | |
| Reading keys (final review) | (not specified) | the picker and the editor read one key at a time; the editor asks for no suggestion while more keys wait (an accept key still asks) | keys typed after the key that ends them stay in the terminal for the shell, in order: a burst after Ctrl-R, pasted mssh lines, keys typed after a choice |
| Editor bash floor (final review) | bash 4.2+ | bash 4.4+; the Ctrl-R picker still works from 4.2 | bash 4.2 redraws a wrapped line wrongly after every `bind -x` command, and the editor runs one on every space |
| bash hook keys (final review) | (not specified) | the hook commands end with `"$_"` | bash sets `$_` to a command's last argument: `cd $_` keeps working |
| History tab (final review) | whole past invocations | lines that give a password option (`-p`, `--password`, `-ip`, `--ipmi_password`) are left out | passwords are never offered |
| Picker on a wrapped line (final review) | (not specified) | with the line redrawn (bash), the menu opens below all of its rows and the cursor ends at the line's start | where bash redraws the line after a `bind -x` command |
| Shared start (user testing) | the most likely value's rest, when its share reaches T_WORD | when no value does: the start all known values of the slot share (what TAB inserts), once they were used at least 3 times between them; it never closes a quote | on a short real history, values like `cloud` and `cloud,la,localhost,rtr` split the share and hid any suggestion; replaying that history, grey text shows for 22% of host positions (was 12%) and 41% of option values (was 20%), and fewer of the shown ones are wrong |
| Shell matrix (user testing) | modern, legacy and centos7 images | a fourth image, current: CPython 3.15.0 installed by uv 0.13.0 (as `uv tool install` does), with the modern image's shells; each image prints its Python version | uv installs the newest Python while the images ran 3.13 and 3.6: Python 3.14+ rejects a too-small ioctl buffer, which broke the editor and the Ctrl-R picker in every shell while the matrix passed |
| Uses in the picker (after 0.4) | "used 12x" from the uses of mssh's history and the shell's; the history tab adds the shell's mssh lines | a use is one run of mssh. A run is in both histories, written differently (mssh's: short options, `-su` on every line, its quoting); the picker matches a shell line to mssh's history by its hosts, commands and the options that change something (a flag by the value it leaves, a value unless it is the default), however spelled and whatever the program's name: first to a record of the same options, else to one mssh may have written in another form (6.31 left the script timeout, 0 and empty values and the display, IPMI, host file and config options out; -T, -uk, -k DIR, -s PATH and, later, --config_file are recorded as other values). A matched line adds nothing; lines beyond the runs mssh's history holds (`-I`, a trimmed history) and unmatched lines add uses and rows, one row per run; once mssh's history has more distinct runs than the tab holds (5000), a line matching no row counts only with -I, --script or -hf (the index counts the others). Local commands are not uses. The grey suggestions still weigh every shell line, as before | one run showed "used 2x" on the slot tab and two rows of "used 1x" on the history tab; a shell line typed 3 times showed "used 1x" |
| Esc and CSI u keys (user testing) | Esc cancels the picker; keys decoded from CSI, SS3 and Alt as an Esc prefix | Esc however the terminal sends it: alone, twice at once (a double press that arrived together over ssh or mosh, or Alt+Esc: `\e\e[C` stays Alt+→), or as the kitty keyboard protocol's `CSI 27 u` / xterm modifyOtherKeys' `CSI 27;1;27 ~`. Any key sent in those two forms (`CSI 13 u` Enter, `CSI 99;5 u` Ctrl-C, `CSI 102;3 u` Alt-F, ...) is read as the key it stands for, and the editor hands it to readline as the bytes a legacy terminal sends; keys with no such bytes (Ctrl+Enter, Super+A, key releases) stay unknown | found while looking into Esc not closing the picker (that was zellij's web client dropping a lone Esc): Esc Esc was Alt+Esc, which the picker ignored; tmux 3.5a passes an outer terminal's `CSI 27 u` to the pane as it came; readline does not understand these forms (a `CSI 13 u` Enter handed to it did not run the line). fish 4.0 turns the kitty protocol off while a binding runs, so its picker gets legacy keys |
