# mssh Autocomplete SP2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Grey suggestions while typing mssh lines (zsh, bash with ble.sh, plain bash through an opt-in mssh line editor) and a Ctrl-R picker on mssh lines in bash, ble.sh, zsh and fish, built on SP1's engine.

**Architecture:** Everything stays in `mssh_complete.py`. The engine gains `Engine.suggest` (line, word or nothing, by confidence), answered for requests with `ghost=1` as a `G` record; index format 2 adds per-feature use counts and last use. New sections draw on the terminal: a terminal layer, the `Picker` and the `LineEditor`, run by the new commands `mssh-complete pick` and `mssh-complete edit` (one process per Ctrl-R or per edited line, no daemons). The shell glue asks for grey text asynchronously (zsh, ble.sh), binds Ctrl-R on mssh lines while calling the previous binding elsewhere, and in plain bash enters the editor on the space after an mssh name.

**Tech Stack:** Python 3.6+ standard library only (termios, tty, select); bash 4.2+ readline (`bind -x`, macros), zsh 5.3+ zle (`add-zle-hook-widget`, `zle -F`, `POSTDISPLAY`), zsh-autosuggestions 0.7.1, fish 3.0+, ble.sh nightly 2026-09-08; pytest; Docker for the shell matrix.

**Spec:** `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp2-design.md` (read it; where this plan differs, the "Deviations from the spec" section says why, and Task 11 appends it to the spec).

## Global Constraints

- Python syntax and library floor is 3.6: no walrus, no dataclasses, no `subprocess.run(capture_output=...)`. Standard library only.
- Single-file module: all of SP2 is in `mssh_complete.py`; `multiSSH3.py` only changes its version, date and `--completion` help.
- Never cost keystrokes: a suggestion is only taken by an explicit key; Enter runs what was typed; nothing alters or deletes typed text. The replay evaluation's `altered` count stays 0.
- Never get in the way: anything slow, missing or failing falls back silently to the shell's own behaviour; nothing is printed; Ctrl-R on lines that are not mssh lines does exactly what it did before; keys typed while the picker or editor starts are never lost.
- Never change what mssh runs; passwords (`-p`, `--password`, `-ip`, `--ipmi_password`) are never suggested.
- Grey text only on mssh lines (first word an mssh name), only with the cursor at the end of the line.
- No daemons: one engine process per request, per Ctrl-R, per edited line.
- Glue syntax floors: bash 4.2, zsh 5.3 for the own widgets (tested floor 5.5), fish 3.0.
- Repository style: tabs, `'''` docstrings, sparse comments, pytest tests as plain `test_*` functions in `tests/`.
- The existing suite keeps passing after every task; the Docker matrix (`tests/shells/run_matrix.sh`) passes after Tasks 8, 9, 10 and 11.
- End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

Failure modes the spec implies that a person using this would hit first; each has a test in the task that owns the code.

1. **Keys typed while the picker or editor starts** (a fast typist, a paste) must reach it in order: `test_terminal_keeps_keys_typed_before_it_started` (Task 4), `test_editor_keeps_a_burst_of_type_ahead` (Task 8).
2. **Ctrl-R on a line that is not an mssh line** must behave exactly as before, including a second Ctrl-R inside readline's, zsh's and ble.sh's own search and an fzf-style `bind -x` binding made before or after the glue: `test_bash_ctrl_r_on_other_lines_*`, `test_bash_vi_mode_ctrl_r` (Task 8), `test_zsh_ctrl_r_*` (Task 9), `test_blesh_ctrl_r_*` (Task 8), `test_fish_ctrl_r_*` (Task 10).
3. **Multibyte text on bash 4.x**, where readline counts the cursor in bytes: `test_space_elsewhere_is_a_space` (Task 8; the matrix runs it on bash 4.2 and 4.4).
4. **A new shell with the SP2 glue** (editor on, engine missing, glue file broken) prints nothing and keeps `$?`: `test_new_shells_stay_silent`, `test_new_bash_with_the_editor_stays_silent` (Task 10).
5. **A terminal without colours or a terminal at all** (`TERM=dumb`, no controlling terminal): the editor edits without grey text, `pick` steps aside so Ctrl-R does what it did before: `test_editor_without_colours_still_edits` (Task 8), `test_pick_and_edit_without_a_terminal_step_aside` (Task 7).

## Deviations from the spec

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

## How this plan was verified

Every code block in this plan was run before the plan was written. A script then applied the tasks in order to a clean checkout of the spec commit and checked, for each task, that its tests fail before the implementation step and pass after it, that the whole suite passes where a task says so, that the Docker shell matrix passes in Tasks 8 to 11, and that the final files are byte-for-byte the verified versions. The "Expected" lines below are that run's output. The local machine has bash but not zsh, fish or ble.sh: those tests skip locally and run in the matrix.

## File Structure

| File | Responsibility |
|---|---|
| `mssh_complete.py` | Adds: index format 2 (Knowledge, Building the index); `Engine.suggest` and the `G` record (Engine, Protocol); sections Terminal, Picker, Line editor (before Shell glue); `pick` / `edit` (Command line); SP2 glue in `BASH_GLUE`, `ZSH_GLUE`, new `FISH_KEYS_GLUE`; install of the fish conf.d file and the bash editor switch; the `ghost` replay policy. |
| `multiSSH3.py` | Version 6.29, date, `--completion` help. |
| `tests/test_complete_suggest.py`, `test_complete_terminal.py`, `test_complete_picker.py`, `test_complete_editor.py` | Suggestion engine; terminal layer; picker (and the `pick` / `edit` commands without a terminal); line editor. |
| `tests/vt_grid.py` | A small in-memory VT100 terminal (`Grid`) and a scripted `FakeTerminal` for the drawing tests. |
| `tests/test_complete_keys.py` | SP2 in real shells: Ctrl-R, the editor, grey text in ble.sh and zsh. |
| `tests/complete_shell_harness.py`, `tests/test_complete_shells.py` | Harness: rc text before / after the glue, interactive fish; install and shell-start safety. |
| `tests/test_complete_index.py`, `tests/test_complete_eval.py` | Index format 2; the `ghost` replay policy. |
| `tests/shells/Dockerfile.{modern,legacy}`, `tests/shells/run_matrix.sh` | zsh-autosuggestions in the images; test selection with `MSSH_MATRIX_TESTS`. |
| `tests/bench_complete.py` | Suggestion, editor and picker timings (observations, not gates). |

---
Starting point: branch `mssh-autocomplete-sp2` at the spec commit; `python3 -m pytest -q` gives `683 passed, 21 skipped`.

### Task 1: Index format 2: uses and last use per feature

**Files:**
- Modify: `mssh_complete.py` (Index storage: `INDEX_FORMAT`; Knowledge: `MemoryKnowledge.add`, `feature_uses` on both knowledge classes; Building the index: `serialize_knowledge`, `build_index`)
- Modify: `tests/test_complete_index.py` (append)

**Interfaces:**
- Consumes: SP1's `MemoryKnowledge`, `SnapshotKnowledge`, `NsvIndex`, `serialize_knowledge`, `build_index`
- Produces: `INDEX_FORMAT = '2'`; index sections `fcounts` and `flast` (one row each, aligned with `features`); `MemoryKnowledge.add(features, weight, ts=0)`; `feature_uses(key) -> (times used: int, last used unix time: int)` on `MemoryKnowledge` (key = feature text) and `SnapshotKnowledge` (key = feature index); `serialize_knowledge(memory) -> (features, record rows, posting rows, fweights row, fcounts row, flast row)`. A format-1 index raises `IndexCorrupt` and is rebuilt like any unreadable index.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_index.py` (the text starts with the blank lines that separate it from what is there):

````python


def test_index_counts_uses_and_last_use_of_each_feature(home):
	index, _ = build()
	snapshot = mc.SnapshotKnowledge(index, NOW)
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, mc.spec_from_parser(multiSSH3.get_parser()), NOW)
	for feature, uses in (('h:gpu[01-16]', (2, 1789990100)), ('v:username=admin', (1, 1789990200)), ('c:uptime', (1, 1789990300))):
		assert snapshot.feature_uses(snapshot.feature_key(feature)) == uses
		assert memory.feature_uses(feature) == uses


def test_an_index_of_the_previous_format_is_not_read(home):
	_, directory = build()
	path = os.path.join(directory, mc.INDEX_NAME)
	with open(path, encoding='utf-8') as f:
		data = f.read()
	assert data.startswith(mc.INDEX_MAGIC + '\0' + mc.INDEX_FORMAT + '\0')
	with open(path, 'w', encoding='utf-8') as f:
		f.write(mc.INDEX_MAGIC + '\0' + '1' + data[len(mc.INDEX_MAGIC) + 1 + len(mc.INDEX_FORMAT):])
	with pytest.raises(mc.IndexCorrupt):
		mc.NsvIndex.load(path)
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AttributeError: 'SnapshotKnowledge' object has no attribute 'feature_uses'. Did you mean: 'feature_key'?` (`2 failed, 18 passed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python

#%% ------------ Index storage (NSV) ----------------
INDEX_MAGIC = 'MSSHCIDX'
INDEX_FORMAT = '1'
INDEX_NAME = 'complete-index.v1.nsv'

class IndexCorrupt(Exception):
````

with:

````python

#%% ------------ Index storage (NSV) ----------------
INDEX_MAGIC = 'MSSHCIDX'
INDEX_FORMAT = '2'
INDEX_NAME = 'complete-index.v1.nsv'

class IndexCorrupt(Exception):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self._by_features = {}
		self._postings = {}
		self._weights = {}
		self._sorted = None

	def add(self, features, weight):
		key = tuple(features)
		rid = self._by_features.get(key)
		if rid is None:
````

with:

````python
		self._by_features = {}
		self._postings = {}
		self._weights = {}
		self._uses = {}
		self._sorted = None

	def add(self, features, weight, ts=0):
		'''Add one use of an invocation with these features, at unix time ts (0 if unknown).'''
		key = tuple(features)
		rid = self._by_features.get(key)
		if rid is None:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		self.records[rid][0] += weight
		for feature in features:
			self._weights[feature] = self._weights.get(feature, 0.0) + weight

	def add_history(self, lines, spec, now):
		'''Add ~/.mssh_history lines, each weighted by its age.'''
		for line in lines:
			entry = parse_history_line(line, spec)
			if entry is not None:
				self.add(entry.features(), use_weight(now - entry.ts))

	def record_count(self):
		return len(self.records)
````

with:

````python
		self.records[rid][0] += weight
		for feature in features:
			self._weights[feature] = self._weights.get(feature, 0.0) + weight
			count, last = self._uses.get(feature, (0, 0))
			self._uses[feature] = (count + 1, max(last, ts))

	def add_history(self, lines, spec, now):
		'''Add ~/.mssh_history lines, each weighted by its age.'''
		for line in lines:
			entry = parse_history_line(line, spec)
			if entry is not None:
				self.add(entry.features(), use_weight(now - entry.ts), entry.ts)

	def record_count(self):
		return len(self.records)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python

	def feature_weight(self, key):
		return self._weights.get(key, 0.0)

class SnapshotKnowledge(object):
	'''The records stored in the index, read lazily, with weights decayed to now.'''
````

with:

````python

	def feature_weight(self, key):
		return self._weights.get(key, 0.0)

	def feature_uses(self, key):
		'''(times used, last used unix time) of a feature.'''
		return self._uses.get(key, (0, 0))

class SnapshotKnowledge(object):
	'''The records stored in the index, read lazily, with weights decayed to now.'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		if self._weights is None:
			self._weights = self.index.single('fweights')
		return float(self._weights[key]) * self.scale

#%% ------------ Ranking ----------------
BETA = 0.1                  # weight of plain frecency next to similarity with the line
````

with:

````python
		if self._weights is None:
			self._weights = self.index.single('fweights')
		return float(self._weights[key]) * self.scale

	def feature_uses(self, key):
		'''(times used, last used unix time) of a feature.'''
		counts = self.index.single('fcounts')
		lasts = self.index.single('flast')
		try:
			return int(counts[key]), int(lasts[key])
		except (IndexError, ValueError):
			return 0, 0

#%% ------------ Ranking ----------------
BETA = 0.1                  # weight of plain frecency next to similarity with the line
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	The features, records, postings and feature weight rows of the heaviest MAX_RECORDS records.

	Returns:
		tuple: (features, record rows, posting rows, fweights row)
	'''
	records = sorted(memory.records, key=lambda record: -record[0])[:MAX_RECORDS]
	features = sorted({feature for _, record_features in records for feature in record_features if safe_field(feature)})
````

with:

````python
	The features, records, postings and feature weight rows of the heaviest MAX_RECORDS records.

	Returns:
		tuple: (features, record rows, posting rows, fweights row, fcounts row, flast row)
	'''
	records = sorted(memory.records, key=lambda record: -record[0])[:MAX_RECORDS]
	features = sorted({feature for _, record_features in records for feature in record_features if safe_field(feature)})
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		for number in ids:
			postings[number].append(str(rid))
			weights[number] += weight
	return features, record_rows, postings, ['%.6g' % weight for weight in weights]

def build_index(directory, now=None, mssh=None):
	'''
````

with:

````python
		for number in ids:
			postings[number].append(str(rid))
			weights[number] += weight
	uses = [memory.feature_uses(feature) for feature in features]
	return (features, record_rows, postings, ['%.6g' % weight for weight in weights],
		[str(count) for count, _ in uses], [str(last) for _, last in uses])

def build_index(directory, now=None, mssh=None):
	'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	lines, offset, inode = read_history(history_path)
	memory = MemoryKnowledge()
	memory.add_history(lines, spec, now)
	features, record_rows, postings, fweights = serialize_knowledge(memory)
	history_tokens = {feature[2:] for feature in features if feature.startswith('t:')}
	hosts = {}
	def add(name, source, address=''):
````

with:

````python
	lines, offset, inode = read_history(history_path)
	memory = MemoryKnowledge()
	memory.add_history(lines, spec, now)
	features, record_rows, postings, fweights, fcounts, flast = serialize_knowledge(memory)
	history_tokens = {feature[2:] for feature in features if feature.startswith('t:')}
	hosts = {}
	def add(name, source, address=''):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		('sources', source_rows),
		('features', [features]),
		('fweights', [fweights]),
		('postings', postings),
		('records', record_rows),
		('host_names', [names]),
````

with:

````python
		('sources', source_rows),
		('features', [features]),
		('fweights', [fweights]),
		('fcounts', [fcounts]),
		('flast', [flast]),
		('postings', postings),
		('records', record_rows),
		('host_names', [names]),
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_index.py -q`

Expected: `20 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `685 passed, 21 skipped`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_index.py mssh_complete.py
git commit -m "feat: index format 2 with use counts and last use per feature

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 2: The suggestion engine

**Files:**
- Modify: `mssh_complete.py` (Engine: thresholds, `Ghost`, shell escaping, `Engine.suggest` and its helpers, `ghost=1` requests, literal framing for `insert=1`; Protocol: `G` record, `engine_for`)
- Create: `tests/test_complete_suggest.py`

**Interfaces:**
- Consumes: Task 1: `feature_uses`. SP1: `parse_context`, `score_features`, `make_features`, `Response`, `format_response`, `answer`
- Produces: `T_WORD = 0.7`, `T_LINE = 0.6`, `SUPPORT = 1.0`; `Ghost(kind, text, confidence)` with kind `line` or `word`; `_shell_escape(shell, text)`; `Engine.suggest(request, deadline=None) -> Ghost|None` (None unless the first word is an mssh name and nothing follows the cursor); `Engine.usage(context, value) -> (uses, last)`; `Engine.history_path`; `Engine.query` with flag `ghost=1` returns a `Response` whose `ghost` is set and no candidates; with flag `insert=1` candidates are framed for literal insertion in any shell; `format_response` writes `G <kind>\t<text>`; `engine_for(request, directory=Ellipsis, now=None) -> Engine` (what `answer` queries).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_suggest.py` with exactly this content:

````python
'''Grey suggestions: how much of the line the engine dares to predict, and that it only ever extends what was typed.'''
import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su', 'gpu[01-16]', '"nvidia-smi"') for number in range(6)]
HISTORY += [line(NOW - 50 * number, '-su -u=root', 'storage1', '"df -h /data"') for number in range(3)]
HISTORY += [line(NOW - 70 * number, '-su', 'login1', '"uptime"') for number in range(2)]
HISTORY += [line(NOW - 90 * number, '-su', 'login1', '"w"') for number in range(2)]


def suggest(before, after='', shell='bash', history=HISTORY):
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	return mc.Engine(SPEC, [memory]).suggest(mc.Request(shell, before, after, ''))


def test_whole_line_when_one_invocation_dominates():
	ghost = suggest('mssh gp')
	assert (ghost.kind, ghost.text) == ('line', 'u[01-16] "nvidia-smi"')


def test_only_the_word_when_what_follows_is_unclear():
	# login1 ran uptime and w equally often: the host is clear, the command is not
	ghost = suggest('mssh log')
	assert (ghost.kind, ghost.text) == ('word', 'in1')


def test_nothing_when_the_word_itself_is_unclear():
	# gpu[01-16] is the most used host, but not by enough
	assert suggest('mssh ') is None
	assert suggest('mssh x') is None


def test_option_values_continue_with_hosts_and_command():
	ghost = suggest('mssh -u ro')
	assert (ghost.kind, ghost.text) == ('line', 'ot storage1 "df -h /data"')


def test_inside_an_open_quote_the_suggestion_closes_it():
	ghost = suggest('mssh gpu[01-16] "nv')
	assert ghost.text == 'idia-smi"'


def test_unquoted_command_words_are_escaped():
	ghost = suggest('mssh storage1 cat /da', history=[line(NOW - number, '-su', 'storage1', '"cat /data|wc"') for number in range(5)])
	assert ghost.text == 'ta\\|wc'


def test_zsh_escapes_glob_characters():
	assert suggest('mssh gp', shell='zsh').text == 'u\\[01-16\\] "nvidia-smi"'


@pytest.mark.parametrize('before, after', [('mssh gp', 'x'), ('ls gp', ''), ('mssh -p ', ''), ('mssh -p se', '')])
def test_no_suggestion(before, after):
	assert suggest(before, after) is None


def test_a_value_seen_once_is_not_suggested():
	assert suggest('mssh on', history=[line(NOW, '-su', 'onlyonce1', '"uptime"')]) is None


def test_every_suggestion_extends_what_was_typed():
	for entry in HISTORY:
		full = 'mssh ' + ' '.join(entry.split('\t')[2:])
		for cut in range(5, len(full)):
			ghost = suggest(full[:cut])
			if ghost is not None:
				assert ghost.text and (ghost.kind in ('line', 'word'))
				words = [token.text for token in mc.lex(full[:cut] + ghost.text)]
				assert words[0] == 'mssh'


def test_ghost_requests_answer_with_one_g_record():
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, SPEC, NOW)
	engine = mc.Engine(SPEC, [memory])
	response = engine.query(mc.Request('bash', 'mssh gp', '', 'gp', flags={'ghost': '1'}))
	assert mc.format_response(response, nul=False) == 'MSSHC1\nG line\tu[01-16] "nvidia-smi"\nE\n'.encode()
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_suggest.py -q`

Expected: FAIL, e.g. `E AttributeError: 'Engine' object has no attribute 'suggest'` (`14 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			return index
	return None

def shell_history_knowledge(lines, spec):
	'''
	The shell's history as weak records: lines running mssh like mssh history (passwords dropped),
````

with:

````python
			return index
	return None

# tuned with `mssh-complete eval` (ghost policy): wrong suggestions under 10% of those shown on
# synthetic and real history, the most keys saved on top of TAB
T_WORD = 0.7   # confidence the top value of the current word needs before its rest is suggested
T_LINE = 0.6   # share each following slot's top value needs before the rest of the line is suggested
SUPPORT = 1.0  # confidence = share * uses / (uses + SUPPORT): a value seen once is not yet sure

class Ghost(object):
	'''
	A grey suggestion: text goes after the cursor.

	kind is 'line' when the text goes past the current word into following slots, 'word' otherwise;
	confidence is the smallest share that let it through.
	'''
	__slots__ = ('kind', 'text', 'confidence')

	def __init__(self, kind, text, confidence):
		self.kind = kind
		self.text = text
		self.confidence = confidence

	def __repr__(self):
		return 'Ghost({!r}, {!r}, {:.3f})'.format(self.kind, self.text, self.confidence)

def _top_share(scores):
	'''(top value, its share of the positive scores) of a value -> score dict, or (None, 0).'''
	best = None
	total = 0.0
	for value, score in scores.items():
		total += max(score, 0.0)
		if best is None or (score, value) > (scores[best], best):
			best = value
	if best is None or total <= 0:
		return None, 0.0
	return best, max(scores[best], 0.0) / total

def shell_history_knowledge(lines, spec):
	'''
	The shell's history as weak records: lines running mssh like mssh history (passwords dropped),
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
def _bash_escape(text):
	return ''.join('\\' + char if char in _BASH_SPECIAL else char for char in text)

class Engine(object):
	'''Answers completion requests from parsed options, history knowledge and the host table.'''
	def __init__(self, spec, knowledges=(), hosts=None, users=()):
		self.spec = spec
		self.knowledges = [knowledge for knowledge in knowledges if knowledge is not None]
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)

	def query(self, request, deadline=None):
		context = parse_context(request.before, request.after, self.spec)
		response = Response(context)
		if context is None:
````

with:

````python
def _bash_escape(text):
	return ''.join('\\' + char if char in _BASH_SPECIAL else char for char in text)

# characters zsh reads specially in an unquoted word, globs included (zsh fails on a glob that matches nothing)
_ZSH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()!*?[]#~^{}')

def _zsh_escape(text):
	return ''.join('\\' + char if char in _ZSH_SPECIAL else char for char in text)

# characters fish reads specially in an unquoted word
_FISH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()*?[]#~{}')

def _shell_escape(shell, text):
	'''text escaped for an unquoted word of shell.'''
	special = {'bash': _BASH_SPECIAL, 'zsh': _ZSH_SPECIAL, 'fish': _FISH_SPECIAL}.get(shell)
	if special is None:
		return text
	return ''.join('\\' + char if char in special else char for char in text)

class Engine(object):
	'''Answers completion requests from parsed options, history knowledge and the host table.'''
	def __init__(self, spec, knowledges=(), hosts=None, users=()):
		self.history_path = None
		self.spec = spec
		self.knowledges = [knowledge for knowledge in knowledges if knowledge is not None]
		self.hosts = hosts if hosts is not None else HostTable()
		self.users = list(users)

	def query(self, request, deadline=None):
		if request.flags.get('ghost') == '1':
			response = Response(parse_context(request.before, request.after, self.spec))
			response.ghost = self.suggest(request, deadline)
			return response
		context = parse_context(request.before, request.after, self.spec)
		response = Response(context)
		if context is None:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		response.candidates = self._frame(candidates, context, request, response.directives)
		return response

	def _frame(self, candidates, context, request, directives=()):
		'''
		Turn slot values into replacements for the shell's word, best first, without duplicates.

		For bash, text left unquoted is escaped, except when bash quotes file names itself (files, dirs).
		'''
		word = _shell_word(request)
		prefix = context.prefix
		if word is None:
````

with:

````python
		response.candidates = self._frame(candidates, context, request, response.directives)
		return response

	def suggest(self, request, deadline=None):
		'''
		The grey suggestion for a line with the cursor at its end, or None.

		The current word's most likely value (when its share of the scores reaches T_WORD), then,
		when each following positional slot's top value reaches T_LINE, those slots: the hosts and
		the first command. Options are never added. The suggestion always extends the typed text.
		'''
		if request.after.strip():
			return None
		tokens = lex(request.before)
		if not tokens or os.path.basename(tokens[0].text) not in MSSH_NAMES:
			return None
		context = parse_context(request.before, request.after, self.spec)
		if context is None or (context.slot == SLOT_VALUE and context.option.dest in PASSWORD_DESTS):
			return None
		if context.slot == SLOT_COMMAND and not context.quoted and context.mode == 'plain' and context.command_words:
			return self._suggest_command_words(context, request.shell, deadline)
		typed = context.value
		values = {}
		for candidate in self._slot_candidates(context, deadline):
			if candidate.text.startswith(typed):
				values[candidate.text] = max(values.get(candidate.text, 0.0), candidate.score)
		top, share = _top_share(values)
		if top is None:
			return None
		share *= self._support(context, top)
		if share < T_WORD:
			return None
		rest = top[len(typed):]
		if context.open_quote:
			closing = '"' if context.open_quote == '"' else "'"
			unsafe = '"\\$`' if closing == '"' else "'"
			if any(char in unsafe for char in rest):
				return None
			if context.slot == SLOT_COMMAND:
				rest += closing
		elif rest:
			rest = _shell_escape(request.shell, rest)
		continuation, rest_share = self._continuation(context, top, request.shell, deadline)
		if continuation and rest_share >= T_LINE:
			return Ghost('line', rest + continuation, min(share, rest_share))
		if not rest:
			return None
		return Ghost('word', rest, share)

	def _suggest_command_words(self, context, shell, deadline):
		'''
		Suggestion for a command typed as unquoted words: the rest of the most likely past command
		whose words start with the typed ones, each word escaped so the remote command is the same.
		'''
		typed = context.command_words
		commands = {}
		for feature, score in score_features(self.knowledges, 'c:' + ' '.join(typed), context.features, deadline).items():
			words = [token.text for token in lex(feature[2:])]
			if len(words) >= len(typed) and words[:len(typed) - 1] == typed[:-1] and words[len(typed) - 1].startswith(typed[-1]):
				key = tuple(words)
				commands[key] = commands.get(key, 0.0) + score
		top, share = _top_share(commands)
		if top is None:
			return None
		uses = self._uses('c:' + ' '.join(top))
		share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		next_words = {}
		for words, score in commands.items():
			next_words[words[len(typed) - 1]] = next_words.get(words[len(typed) - 1], 0.0) + score
		word, word_share = _top_share(next_words)
		word_share *= float(uses) / (uses + SUPPORT) if SUPPORT > 0 else 1.0
		rest = _shell_escape(shell, top[len(typed) - 1][len(typed[-1]):])
		more = ''.join(' ' + _shell_escape(shell, extra) for extra in top[len(typed):])
		if more and share >= T_LINE:
			return Ghost('line', rest + more, share)
		if rest and word_share >= T_WORD:
			return Ghost('word', _shell_escape(shell, word[len(typed[-1]):]), word_share)
		return None

	def _uses(self, feature):
		'''How many times a feature was used, over all knowledge.'''
		count = 0
		for knowledge in self.knowledges:
			key = knowledge.feature_key(feature)
			if key is not None and hasattr(knowledge, 'feature_uses'):
				count += knowledge.feature_uses(key)[0]
		return count

	def usage(self, context, value):
		'''(times used, last used unix time) of a value of the current slot, over all knowledge.'''
		if context.slot == SLOT_HOSTS:
			segment = value.rpartition(',')[2].rpartition('@')[2]
			features = ['h:' + value, 't:' + segment]
		elif context.slot == SLOT_VALUE:
			features = ['v:{}={}'.format(context.option.dest, value)]
		elif context.slot == SLOT_OPTION:
			option = self.spec.lookup(value)[0]
			features = ['o:' + option.long] if option else []
		else:
			features = [('f:' if context.mode in PATH_MODES else 'c:') + value]
		best = (0, 0)
		for feature in features:
			count = 0
			last = 0
			for knowledge in self.knowledges:
				key = knowledge.feature_key(feature)
				if key is not None and hasattr(knowledge, 'feature_uses'):
					uses, when = knowledge.feature_uses(key)
					count += uses
					last = max(last, when)
			best = max(best, (count, last))
		return best

	def _support(self, context, value):
		'''uses / (uses + SUPPORT) for a value of the current slot: evidence behind a suggestion.'''
		if SUPPORT <= 0:
			return 1.0
		uses = self.usage(context, value)[0]
		return float(uses) / (uses + SUPPORT)

	def _slot_candidates(self, context, deadline):
		'''The slot values the providers rank for the current slot, unframed.'''
		scratch = Response(context)
		if context.slot == SLOT_OPTION:
			return self._options(context, 'zsh')
		if context.slot == SLOT_VALUE:
			return self._values(context, scratch, deadline)
		if context.slot == SLOT_HOSTS:
			return self._hosts(context.value, context, deadline)
		return self._commands(context, scratch, deadline)

	def _continuation(self, context, value, shell, deadline):
		'''
		The following positional slots nobody typed yet, as text, and the smallest share among them.

		After a hosts value: the first command. After an option value: the hosts (when not typed)
		and the first command (when not typed). Only in plain mode, never after commands.
		'''
		if context.mode != 'plain' or context.open_quote or context.slot in (SLOT_OPTION, SLOT_COMMAND):
			return '', 0.0
		features = set(context.features)
		if any(feature.startswith('c:') for feature in features):
			return '', 0.0
		text = ''
		shares = []
		if context.slot == SLOT_HOSTS:
			features.update(make_features([], value, []))
		else:
			features.add('v:{}={}'.format(context.option.dest, value))
			if not context.hosts:
				hosts, share = _top_share(self._feature_values('h:', features, deadline))
				if hosts is None:
					return '', 0.0
				text += ' ' + _shell_escape(shell, hosts)
				shares.append(share)
				features.update(make_features([], hosts, []))
		command, share = _top_share(self._feature_values('c:', features, deadline))
		quote = _quote_command(command) if command is not None else None
		if quote is None:
			return '', 0.0
		text += ' ' + quote + command + quote
		shares.append(share)
		return text, min(shares)

	def _feature_values(self, kind, features, deadline):
		'''value -> score of every feature of a kind ('h:', 'c:'), scored against features.'''
		return {feature[len(kind):]: score for feature, score in score_features(self.knowledges, kind, sorted(features), deadline).items()}

	def _frame(self, candidates, context, request, directives=()):
		'''
		Turn slot values into replacements for the shell's word, best first, without duplicates.

		For bash, and for any shell that inserts the text as it is (request flag insert=1: the picker),
		text left unquoted is escaped for that shell, except when bash quotes file names itself.
		'''
		literal = request.shell == 'bash' or request.flags.get('insert') == '1'
		word = _shell_word(request)
		prefix = context.prefix
		if word is None:
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			if not full.startswith(prefix) or full in seen:
				continue
			rest = full[len(prefix):]
			if request.shell == 'bash':
				if context.open_quote == '"' and any(char in rest for char in '"\\$`'):
					continue
				if context.open_quote in ("'", "$'") and "'" in rest:
					continue
				if not context.open_quote and not {'files', 'dirs'} & set(directives):
					rest = _bash_escape(rest)
			if '\t' in rest or '\n' in rest:
				continue
			seen.add(full)
````

with:

````python
			if not full.startswith(prefix) or full in seen:
				continue
			rest = full[len(prefix):]
			if literal:
				if context.open_quote == '"' and any(char in rest for char in '"\\$`'):
					continue
				if context.open_quote in ("'", "$'") and "'" in rest:
					continue
				if not context.open_quote and not (request.shell == 'bash' and {'files', 'dirs'} & set(directives)):
					rest = _shell_escape(request.shell, rest)
			if '\t' in rest or '\n' in rest:
				continue
			seen.add(full)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		if safe_field(candidate.text) and '\t' not in candidate.text:
			raw = '\t' + candidate.raw if candidate.raw and safe_field(candidate.raw) and '\t' not in candidate.raw else ''
			lines.append('C {}\t{}\t{}{}'.format(candidate.text, _clean(candidate.description), candidate.group, raw))
	if response.delegate is not None:
		index, prefix, words = response.delegate
		fields = [str(index), prefix] + list(words)
````

with:

````python
		if safe_field(candidate.text) and '\t' not in candidate.text:
			raw = '\t' + candidate.raw if candidate.raw and safe_field(candidate.raw) and '\t' not in candidate.raw else ''
			lines.append('C {}\t{}\t{}{}'.format(candidate.text, _clean(candidate.description), candidate.group, raw))
	if response.ghost is not None and safe_field(response.ghost.text) and '\t' not in response.ghost.text:
		lines.append('G {}\t{}'.format(response.ghost.kind, response.ghost.text))
	if response.delegate is not None:
		index, prefix, words = response.delegate
		fields = [str(index), prefix] + list(words)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	Answer a request from the index in directory: mssh's cache dir by default, None for no index
	(degraded: options from mssh's parser, shell history, no ranking from mssh history).
	'''
	now = time.time() if now is None else now
	if directory is Ellipsis:
		directory = cache_dir()
````

with:

````python
	Answer a request from the index in directory: mssh's cache dir by default, None for no index
	(degraded: options from mssh's parser, shell history, no ranking from mssh history).
	'''
	return engine_for(request, directory, now).query(request, deadline)

def engine_for(request, directory=Ellipsis, now=None):
	'''The engine for a request: the index in directory (as for answer), its history tail, the shell's history.'''
	now = time.time() if now is None else now
	if directory is Ellipsis:
		directory = cache_dir()
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		# fish lists its history newest first, the others oldest first
		history = request.history[::-1] if request.shell == 'fish' else request.history
		knowledges.append(shell_history_knowledge(history, spec))
	return Engine(spec, knowledges, HostTable(index), users).query(request, deadline)

#%% ------------ Shell glue ----------------
GLUE_MARK = 'MSSH_COMPLETE_GLUE'
````

with:

````python
		# fish lists its history newest first, the others oldest first
		history = request.history[::-1] if request.shell == 'fish' else request.history
		knowledges.append(shell_history_knowledge(history, spec))
	engine = Engine(spec, knowledges, HostTable(index), users)
	engine.history_path = index.header.get('history') if index is not None else os.path.expanduser('~/.mssh_history')
	return engine

#%% ------------ Shell glue ----------------
GLUE_MARK = 'MSSH_COMPLETE_GLUE'
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_suggest.py -q`

Expected: `14 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `699 passed, 21 skipped`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_suggest.py mssh_complete.py
git commit -m "feat: grey suggestions from the engine (line, word or nothing)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 3: Replay evaluation of grey suggestions

**Files:**
- Modify: `mssh_complete.py` (Replay evaluation: `simulate_ghost`, `slot_cases`, `evaluate`, `format_report`)
- Modify: `tests/test_complete_eval.py` (append)

**Interfaces:**
- Consumes: Task 2: `Engine.suggest`, `_shell_escape`
- Produces: `simulate_ghost(engine, before, intended, quoted=False, ahead='', shell='bash', tab=True) -> dict` (keys, chars, visited, shown, divergent, altered); `slot_cases(entry)` yields `(slot, before, after, intended, quoted, ahead)`; `evaluate(lines, spec, since=0, limit=300, policies=('bash', 'ranked', 'ghost'))` adds `('ghost', slot)` totals; `format_report` prints a second table (cases, saved, shown, wrong) for them.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_eval.py` (the text starts with the blank lines that separate it from what is there):

````python


def test_ghost_suggestions_are_rarely_wrong_and_save_more_than_tab():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash', 'ghost'))
	ghost = {slot: total for (policy, slot), total in totals.items() if policy == 'ghost'}
	shown = sum(total['shown'] for total in ghost.values())
	assert shown and float(sum(total['divergent'] for total in ghost.values())) / shown <= 0.10
	assert sum(total['altered'] for total in ghost.values()) == 0

	def saved(policy):
		chosen = [totals[(policy, slot)] for slot in ghost]
		return 1 - float(sum(total['keys'] for total in chosen)) / sum(total['chars'] for total in chosen)
	assert saved('ghost') > saved('bash')


def test_report_has_a_ghost_table():
	report = mc.format_report(mc.evaluate(mc.synthetic_history(entries=300), SPEC, limit=50))
	assert 'shown' in report and '\nghost ' in report
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_eval.py -q`

Expected: FAIL, e.g. `E KeyError: 'shown'` (`2 failed, 7 passed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return "'"
	return None

def slot_cases(entry):
	'''(slot, before, after, intended, quoted) cases to replay for one history entry.'''
	import shlex
	options = [(option, value, name) for (option, value), name in zip(entry.options, entry.option_texts) if option.dest not in PASSWORD_DESTS]
	option_texts = [name if value is None else '{}={}'.format(name, shlex.quote(value)) for option, value, name in options]
````

with:

````python
		return "'"
	return None

def simulate_ghost(engine, before, intended, quoted=False, ahead='', shell='bash', tab=True):
	'''
	Simulate an operator typing intended after before (nothing behind the cursor) with grey suggestions.

	At each position the operator takes the suggestion when it is what they mean: all of it when the
	rest of their line starts with it (ahead is what they would type after the slot), else its first
	word when that matches; otherwise, with tab, they press TAB when bash's TAB would insert what they
	mean (as simulate_slot's bash policy), else they type a character.

	Returns:
		dict: keys, chars, visited, shown (positions with a suggestion), divergent (shown but not
			what the operator means), altered (TAB candidates not extending what was typed: must stay 0)
	'''
	result = {'keys': 0, 'chars': len(intended), 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0}
	target = intended + ('"' if quoted else '') + ahead
	position = 0
	while position < len(intended):
		ghost = engine.suggest(Request(shell, before + intended[:position], '', ''))
		result['visited'] += 1
		if ghost is not None:
			result['shown'] += 1
			remaining = target[position:]
			word = ghost.text.split(' ', 1)[0] if not ghost.text.startswith(' ') else ''
			if remaining.startswith(ghost.text):
				result['keys'] += 1
				position += len(ghost.text)
				continue
			if word and remaining.startswith(word):
				result['keys'] += 1
				position += len(word)
				continue
			result['divergent'] += 1
		if tab:
			typed = intended[:position]
			response = engine.query(Request('zsh', before + typed, '', typed))
			result['altered'] += sum(1 for candidate in response.candidates if not candidate.text.startswith(typed))
			inserted, suffix = _tab(response.candidates, typed, 'bash', quoted, 'nospace' in response.directives)
			if inserted and intended[position:].startswith(inserted):
				result['keys'] += 1
				position += len(inserted)
				if suffix and position < len(intended):
					result['keys'] += 1
				continue
		result['keys'] += 1
		position += 1
	return result

def slot_cases(entry):
	'''
	(slot, before, after, intended, quoted, ahead) cases to replay for one history entry.

	ahead is how the positional slots after this one read when nothing follows the cursor yet
	(the grey suggestions' continuation), '' when they are not suggested.
	'''
	import shlex
	options = [(option, value, name) for (option, value), name in zip(entry.options, entry.option_texts) if option.dest not in PASSWORD_DESTS]
	option_texts = [name if value is None else '{}={}'.format(name, shlex.quote(value)) for option, value, name in options]
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		quoted_commands.append(quote + command + quote)
	head = ' '.join(['mssh'] + option_texts) + ' '
	tail = (' ' + ' '.join(quoted_commands)) if quoted_commands else ''
	cases = []
	if entry.hosts and not any(char in entry.hosts for char in ' \'"\\$`'):
		cases.append(('hosts', head, '', entry.hosts, False))
		if tail:
			cases.append(('hosts-back', head, tail, entry.hosts, False))
		if commands and _quote_command(commands[0]) == '"':
			cases.append(('command', head + entry.hosts + ' "', '', commands[0], True))
	for number, (_, value, name) in enumerate(options):
		others = ' '.join(['mssh'] + option_texts[:number] + option_texts[number + 1:]) + ' '
		rest = (' ' + entry.hosts + tail) if entry.hosts else ''
		cases.append(('option', others + '-', rest, name[1:], False))
		if value and not any(char in value for char in ' \'"\\$`\t'):
			cases.append(('value', others + name + ' ', rest, value, False))
	return cases

def evaluate(lines, spec, since=0, limit=300, policies=('bash', 'ranked')):
	'''
	Replay history lines in time order: each entry is typed with only the entries before it known.

````

with:

````python
		quoted_commands.append(quote + command + quote)
	head = ' '.join(['mssh'] + option_texts) + ' '
	tail = (' ' + ' '.join(quoted_commands)) if quoted_commands else ''
	first_command = (' ' + quoted_commands[0]) if quoted_commands else ''
	plain = not any(option.dest in ('file', 'file_sync', 'gather_mode', 'ipmi') for option, _, _ in options)
	cases = []
	if entry.hosts and not any(char in entry.hosts for char in ' \'"\\$`'):
		cases.append(('hosts', head, '', entry.hosts, False, first_command if plain else ''))
		if tail:
			cases.append(('hosts-back', head, tail, entry.hosts, False, ''))
		if commands and _quote_command(commands[0]) == '"':
			cases.append(('command', head + entry.hosts + ' "', '', commands[0], True, ''))
	for number, (_, value, name) in enumerate(options):
		others = ' '.join(['mssh'] + option_texts[:number] + option_texts[number + 1:]) + ' '
		rest = (' ' + entry.hosts + tail) if entry.hosts else ''
		cases.append(('option', others + '-', rest, name[1:], False, ''))
		if value and not any(char in value for char in ' \'"\\$`\t'):
			ahead = ((' ' + entry.hosts) if entry.hosts else '') + first_command if plain else ''
			cases.append(('value', others + name + ' ', rest, value, False, ahead))
	return cases

def evaluate(lines, spec, since=0, limit=300, policies=('bash', 'ranked', 'ghost')):
	'''
	Replay history lines in time order: each entry is typed with only the entries before it known.

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		limit (int): Replay at most this many of the newest entries

	Returns:
		dict: (policy, slot) -> totals of simulate_slot results plus 'cases'
	'''
	entries = sorted((entry for entry in (parse_history_line(line, spec) for line in lines) if entry is not None), key=lambda entry: entry.ts)
	replay = [number for number, entry in enumerate(entries) if entry.ts >= since][-limit:] if limit else []
````

with:

````python
		limit (int): Replay at most this many of the newest entries

	Returns:
		dict: (policy, slot) -> totals of simulate_slot (or, for the ghost policy, simulate_ghost)
			results plus 'cases'
	'''
	entries = sorted((entry for entry in (parse_history_line(line, spec) for line in lines) if entry is not None), key=lambda entry: entry.ts)
	replay = [number for number, entry in enumerate(entries) if entry.ts >= since][-limit:] if limit else []
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	for number in replay:
		entry = entries[number]
		engine = Engine(spec, [memory])
		for slot, before, after, intended, quoted in slot_cases(entry):
			if not intended:
				continue
			for policy in policies:
				result = simulate_slot(engine, before, after, intended, quoted, policy)
				total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'top1': 0, 'top3': 0,
					'mrr': 0.0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0})
````

with:

````python
	for number in replay:
		entry = entries[number]
		engine = Engine(spec, [memory])
		for slot, before, after, intended, quoted, ahead in slot_cases(entry):
			if not intended:
				continue
			for policy in policies:
				if policy == 'ghost':
					# suggestions need the cursor at the end of the line: replay the slot typed last
					if slot in ('hosts-back', 'option'):
						continue
					result = simulate_ghost(engine, before, intended, quoted, ahead)
					total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0})
					total['cases'] += 1
					for key in ('keys', 'chars', 'visited', 'shown', 'divergent', 'altered'):
						total[key] += result[key]
					continue
				result = simulate_slot(engine, before, after, intended, quoted, policy)
				total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'top1': 0, 'top3': 0,
					'mrr': 0.0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0})
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	return totals

def format_report(totals):
	'''The evaluation as a text table.'''
	lines = ['{:7} {:10} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9} {:>8} {:>7}'.format(
		'policy', 'slot', 'cases', 'saved', 'top1', 'top3', 'mrr', 'divergent', 'altered', 'suffix')]
	for (policy, slot), total in sorted(totals.items()):
````

with:

````python
	return totals

def format_report(totals):
	'''The evaluation as text tables: TAB policies, then grey suggestions.'''
	ghost = {key: total for key, total in totals.items() if key[0] == 'ghost'}
	totals = {key: total for key, total in totals.items() if key[0] != 'ghost'}
	lines = ['{:7} {:10} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9} {:>8} {:>7}'.format(
		'policy', 'slot', 'cases', 'saved', 'top1', 'top3', 'mrr', 'divergent', 'altered', 'suffix')]
	for (policy, slot), total in sorted(totals.items()):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
			policy, slot, total['cases'], 1 - float(total['keys']) / (total['chars'] or 1),
			float(total['top1']) / cases, float(total['top3']) / cases, total['mrr'] / cases,
			float(total['divergent']) / (total['visited'] or 1), total['altered'], total['suffix_cost']))
	return '\n'.join(lines)

def synthetic_history(seed=1, entries=1500, start=1700000000):
````

with:

````python
			policy, slot, total['cases'], 1 - float(total['keys']) / (total['chars'] or 1),
			float(total['top1']) / cases, float(total['top3']) / cases, total['mrr'] / cases,
			float(total['divergent']) / (total['visited'] or 1), total['altered'], total['suffix_cost']))
	if ghost:
		lines.append('')
		lines.append('{:7} {:10} {:>6} {:>7} {:>7} {:>7}'.format('policy', 'slot', 'cases', 'saved', 'shown', 'wrong'))
		for (policy, slot), total in sorted(ghost.items()):
			lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%}'.format(policy, slot, total['cases'],
				1 - float(total['keys']) / (total['chars'] or 1), float(total['shown']) / (total['visited'] or 1),
				float(total['divergent']) / (total['shown'] or 1)))
	return '\n'.join(lines)

def synthetic_history(seed=1, entries=1500, start=1700000000):
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_eval.py -q`

Expected: `9 passed`

- [ ] **Step 5: Record the replay report**

Run: `python3 mssh_complete.py eval --synthetic --limit 300`

Expected (deterministic):

````
policy  slot        cases   saved   top1   top3    mrr divergent  altered  suffix
bash    command       300  80.2%  56.7%  99.0%  0.762     0.0%        0       0
bash    hosts         300  71.4%  75.0%  94.0%  0.819     0.0%        0       0
bash    hosts-back    300  71.4%  94.0%  94.0%  0.945     0.0%        0       0
bash    option        667   0.0%   0.0% 100.0%  0.500     0.0%        0       0
bash    value         367  40.2% 100.0% 100.0%  1.000     0.0%        0       0
ranked  command       300  88.0%  56.7%  99.0%  0.762    25.3%        0      19
ranked  hosts         300  85.5%  75.0%  94.0%  0.819    33.8%        0       0
ranked  hosts-back    300  87.4%  94.0%  94.0%  0.945    23.7%        0       0
ranked  option        667   0.0%   0.0% 100.0%  0.500    69.0%        0       0
ranked  value         367  70.1% 100.0% 100.0%  1.000     0.0%        0       0

policy  slot        cases   saved   shown   wrong
ghost   command       300  83.5%  36.4%   2.4%
ghost   hosts         300  78.5%  50.0%  11.3%
ghost   value         367  50.3%  66.2%   9.2%
````

The ghost policy must show at most 10% wrong in total and 0 altered. Also run `python3 mssh_complete.py eval` on real history if there is any (it reads `~/.mssh_history`).

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_eval.py mssh_complete.py
git commit -m "feat: replay grey suggestions in mssh-complete eval

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 4: Terminal layer and an in-memory terminal for tests

**Files:**
- Modify: `mssh_complete.py` (new section Terminal, before Shell glue)
- Create: `tests/vt_grid.py`
- Create: `tests/test_complete_terminal.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `decode_keys(data: bytes) -> [(name, raw bytes)]` (names: characters, `up down left right home end insert delete pgup pgdn enter tab backspace esc unknown`, `ctrl-<letter>`, `alt-<char>`, `ctrl-right ctrl-left alt-right alt-left`); `char_width(char)`, `strip_escapes(text)`, `text_width(text)`, `fit(text, width)`; `ghost_style(term) -> escape sequence | None`; `_incomplete_utf8(data) -> int`; `Terminal(path='/dev/tty')`: context manager (raw mode with `TCSANOW`, restores on exit and on SIGTERM/SIGHUP) with `size() -> (rows, columns)`, `write(text)`, `read_keys(timeout=None) -> [(name, raw)]`. Tests: `vt_grid.Grid(rows, columns)` (`feed`, `line`, `lines`, `styles`, `cursor`) and `vt_grid.FakeTerminal(batches, rows=24, columns=80, grid=None)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/vt_grid.py` with exactly this content:

````python
'''
A small in-memory terminal for the drawing tests: the VT100 subset the picker and the editor use.

Printable text (wide characters take two cells, the last column wraps on the next character),
CR, LF (raw mode: no carriage return), BS, CSI A B C D G H J K P m, ESC 7 / ESC 8. Other
sequences are read and ignored. Each cell remembers the SGR parameters it was written with.
'''
import re
import unicodedata

CSI = re.compile(r'\x1b\[([0-9;?<=>]*)([ -/]*)([@-~])')
OTHER = re.compile(r'\x1b(\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[@-Z\\-_=>])')


def width(char):
	if unicodedata.combining(char) or ord(char) < 32:
		return 0
	return 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1


class Grid(object):
	def __init__(self, rows=24, columns=80):
		self.rows = rows
		self.columns = columns
		self.cells = [[(' ', '') for _ in range(columns)] for _ in range(rows)]
		self.row = 0
		self.column = 0
		self.saved = (0, 0)
		self.style = ''
		self.scrolled = 0

	def _line_feed(self):
		if self.row == self.rows - 1:
			self.cells.pop(0)
			self.cells.append([(' ', '') for _ in range(self.columns)])
			self.scrolled += 1
		else:
			self.row += 1

	def _put(self, char):
		size = width(char)
		if size == 0:
			return
		if self.column + size > self.columns:
			self.column = 0
			self._line_feed()
		self.cells[self.row][self.column] = (char, self.style)
		if size == 2:
			self.cells[self.row][self.column + 1] = ('', self.style)
		self.column += size

	def _csi(self, params, final):
		private = params.startswith(('?', '<', '=', '>'))
		numbers = [int(part) if part.isdigit() else 0 for part in params.lstrip('?<=>').split(';')] if params else []
		first = numbers[0] if numbers and numbers[0] else 1
		if private:
			return
		if final == 'A':
			self.row = max(0, self.row - first)
		elif final == 'B':
			self.row = min(self.rows - 1, self.row + first)
		elif final == 'C':
			self.column = min(self.columns - 1, self.column + first)
		elif final == 'D':
			self.column = max(0, min(self.column, self.columns - 1) - first)
		elif final == 'G':
			self.column = min(self.columns - 1, first - 1)
		elif final in 'Hf':
			self.row = min(self.rows - 1, first - 1)
			self.column = min(self.columns - 1, (numbers[1] if len(numbers) > 1 and numbers[1] else 1) - 1)
		elif final == 'K':
			mode = numbers[0] if numbers else 0
			start, end = {0: (self.column, self.columns), 1: (0, self.column + 1), 2: (0, self.columns)}[mode]
			for column in range(start, min(end, self.columns)):
				self.cells[self.row][column] = (' ', '')
		elif final == 'J':
			mode = numbers[0] if numbers else 0
			if mode == 0:
				self._csi('', 'K')
				for row in range(self.row + 1, self.rows):
					self.cells[row] = [(' ', '') for _ in range(self.columns)]
			elif mode == 2:
				self.cells = [[(' ', '') for _ in range(self.columns)] for _ in range(self.rows)]
		elif final == 'P':
			line = self.cells[self.row]
			column = min(self.column, self.columns - 1)
			del line[column:column + first]
			line.extend([(' ', '')] * (self.columns - len(line)))
		elif final == 'm':
			self.style = '' if params in ('', '0') else (self.style + ';' + params).lstrip(';')
			if params in ('27', '22', '39'):
				self.style = ''

	def feed(self, text):
		index = 0
		while index < len(text):
			char = text[index]
			if char == '\x1b':
				match = CSI.match(text, index)
				if match:
					self._csi(match.group(1), match.group(3))
					index = match.end()
					continue
				if text.startswith('\x1b7', index):
					self.saved = (self.row, min(self.column, self.columns - 1))
					index += 2
					continue
				if text.startswith('\x1b8', index):
					self.row, self.column = self.saved
					index += 2
					continue
				match = OTHER.match(text, index)
				index = match.end() if match else index + 1
				continue
			if char == '\r':
				self.column = 0
			elif char == '\n':
				self._line_feed()
			elif char == '\b':
				self.column = max(0, min(self.column, self.columns - 1) - 1)
			elif char >= ' ':
				self._put(char)
			index += 1

	def line(self, row):
		return ''.join(char for char, _ in self.cells[row]).rstrip()

	def lines(self):
		return [self.line(row) for row in range(self.rows)]

	def styles(self, row):
		'''The SGR parameters of each cell of row, wide characters' second cells left out.'''
		return [style for char, style in self.cells[row] if char != '']

	@property
	def cursor(self):
		return self.row, min(self.column, self.columns - 1)


class FakeTerminal(object):
	'''What the picker and the editor need from a Terminal, drawing into a Grid; keys are scripted batches.'''
	def __init__(self, batches, rows=24, columns=80, grid=None):
		self.grid = grid or Grid(rows, columns)
		self.batches = list(batches)

	def size(self):
		return self.grid.rows, self.grid.columns

	def write(self, text):
		self.grid.feed(text)

	def read_keys(self, timeout=None):
		import mssh_complete as mc
		if not self.batches:
			raise AssertionError('the program read more keys than the test scripted')
		batch = self.batches.pop(0)
		return mc.decode_keys(batch.encode('utf-8') if isinstance(batch, str) else batch)
````

Create `tests/test_complete_terminal.py` with exactly this content:

````python
'''The terminal layer the picker and the editor draw with: keys, display width, raw mode.'''
import os
import pty
import termios

import pytest

import mssh_complete as mc
from vt_grid import Grid


@pytest.mark.parametrize('data, expected', [
	(b'ab', [('a', b'a'), ('b', b'b')]),
	(b'\x1b[A\x1bOB\x1b[C\x1b[D', [('up', b'\x1b[A'), ('down', b'\x1bOB'), ('right', b'\x1b[C'), ('left', b'\x1b[D')]),
	(b'\x1b[1;5C\x1b[1;3D', [('ctrl-right', b'\x1b[1;5C'), ('alt-left', b'\x1b[1;3D')]),
	(b'\x1b[H\x1b[4~\x1b[3~\x1b[5~', [('home', b'\x1b[H'), ('end', b'\x1b[4~'), ('delete', b'\x1b[3~'), ('pgup', b'\x1b[5~')]),
	(b'\x1bf\x1bb', [('alt-f', b'\x1bf'), ('alt-b', b'\x1bb')]),
	(b'\x1b', [('esc', b'\x1b')]),
	(b'\x1b[15~', [('unknown', b'\x1b[15~')]),
	(b'\r\t\x7f\x08\x12\x03', [('enter', b'\r'), ('tab', b'\t'), ('backspace', b'\x7f'), ('backspace', b'\x08'), ('ctrl-r', b'\x12'), ('ctrl-c', b'\x03')]),
	('é漢'.encode('utf-8'), [('é', 'é'.encode('utf-8')), ('漢', '漢'.encode('utf-8'))]),
])
def test_decode_keys(data, expected):
	assert mc.decode_keys(data) == expected


def test_display_width_counts_wide_and_combining_characters():
	assert [mc.char_width(char) for char in 'a漢́\x07'] == [1, 2, 0, 0]
	assert mc.text_width('\x1b[1mab\x1b[0m漢') == 4
	assert mc.text_width('\x01\x1b[32m\x02$ ') == 2


def test_fit_cuts_at_columns_and_keeps_escapes():
	assert mc.fit('漢字ab', 3) == '漢'
	assert mc.fit('\x1b[7mabc', 2) == '\x1b[7mab'
	assert mc.fit('abc', 5) == 'abc'


@pytest.mark.parametrize('term, style', [
	('', None), ('dumb', None), ('xterm', '\x1b[2m'), ('screen', '\x1b[2m'),
	('xterm-256color', '\x1b[38;5;244m'), ('tmux-256color', '\x1b[38;5;244m'),
])
def test_ghost_style(term, style):
	assert mc.ghost_style(term) == style


@pytest.mark.parametrize('data, cut', [(b'ab', 0), (b'a\xc3', 1), (b'\xe6\xbc', 2), ('é'.encode('utf-8'), 0), (b'\xf0\x9f\x98', 3), (b'', 0)])
def test_incomplete_utf8(data, cut):
	assert mc._incomplete_utf8(data) == cut


@pytest.fixture
def tty_pair():
	master, slave = pty.openpty()
	path = os.ttyname(slave)
	yield master, slave, path
	os.close(master)
	os.close(slave)


def test_terminal_keeps_keys_typed_before_it_started(tty_pair):
	master, slave, path = tty_pair
	os.write(master, b'xy')
	with mc.Terminal(path) as term:
		assert [name for name, _ in term.read_keys(timeout=1)] == ['x', 'y']


def test_terminal_restores_the_mode(tty_pair):
	master, slave, path = tty_pair
	before = termios.tcgetattr(slave)
	with mc.Terminal(path) as term:
		assert not termios.tcgetattr(slave)[3] & termios.ICANON
		term.write('drawn')
	assert termios.tcgetattr(slave) == before
	assert os.read(master, 100).endswith(b'drawn')


def test_terminal_joins_a_character_cut_between_reads(tty_pair):
	master, slave, path = tty_pair
	with mc.Terminal(path) as term:
		os.write(master, b'a\xc3')
		assert term.read_keys(timeout=1) == [('a', b'a')]
		os.write(master, b'\xa9')
		assert term.read_keys(timeout=1) == [('é', 'é'.encode('utf-8'))]
		assert term.read_keys(timeout=0.05) == []


def test_grid_wraps_wide_characters_and_restores_the_cursor():
	grid = Grid(3, 5)
	grid.feed('abcd漢\x1b7xy\r\n\x1b[2Cz\x1b8!')
	assert grid.lines() == ['abcd', '漢!y', '  z']
	assert grid.cursor == (1, 3)
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_terminal.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'decode_keys'` (`26 failed, 1 passed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Shell glue ----------------` (the line itself stays):

````python
#%% ------------ Terminal ----------------
# the keys terminals send as escape sequences (xterm, VT220, rxvt, linux console)
_KEY_SEQUENCES = {
	'\x1b[A': 'up', '\x1b[B': 'down', '\x1b[C': 'right', '\x1b[D': 'left',
	'\x1bOA': 'up', '\x1bOB': 'down', '\x1bOC': 'right', '\x1bOD': 'left',
	'\x1b[H': 'home', '\x1b[F': 'end', '\x1bOH': 'home', '\x1bOF': 'end',
	'\x1b[1~': 'home', '\x1b[4~': 'end', '\x1b[7~': 'home', '\x1b[8~': 'end',
	'\x1b[2~': 'insert', '\x1b[3~': 'delete', '\x1b[5~': 'pgup', '\x1b[6~': 'pgdn',
	'\x1b[1;5C': 'ctrl-right', '\x1b[1;5D': 'ctrl-left', '\x1b[5C': 'ctrl-right', '\x1b[5D': 'ctrl-left',
	'\x1bOc': 'ctrl-right', '\x1bOd': 'ctrl-left',
	'\x1b[1;3C': 'alt-right', '\x1b[1;3D': 'alt-left', '\x1b\x1b[C': 'alt-right', '\x1b\x1b[D': 'alt-left',
}
_KEY_NAMES = {'\r': 'enter', '\n': 'enter', '\t': 'tab', '\x7f': 'backspace', '\x08': 'backspace', '\x00': 'ctrl-space'}

def decode_keys(data):
	'''
	Split bytes read from a terminal into keys.

	Returns:
		list: (name, raw bytes) pairs. name is a key name ('up', 'enter', 'ctrl-r', 'alt-f', 'esc', 'unknown')
			or, for text, the character itself.
	'''
	text = data.decode('utf-8', 'replace')
	keys = []
	index = 0
	while index < len(text):
		char = text[index]
		if char == '\x1b':
			for length in range(min(len(text) - index, 7), 1, -1):
				sequence = text[index:index + length]
				if sequence in _KEY_SEQUENCES:
					keys.append((_KEY_SEQUENCES[sequence], sequence.encode()))
					index += length
					break
			else:
				if index + 1 < len(text) and text[index + 1] in '[O':
					# an escape sequence nobody named: up to its final byte
					end = index + 2
					while end < len(text) and not '@' <= text[end] <= '~':
						end += 1
					keys.append(('unknown', text[index:end + 1].encode()))
					index = end + 1
				elif index + 1 < len(text):
					# Alt + key arrives as Esc then the key
					keys.append(('alt-' + text[index + 1], text[index:index + 2].encode('utf-8')))
					index += 2
				else:
					keys.append(('esc', b'\x1b'))
					index += 1
			continue
		if char in _KEY_NAMES:
			keys.append((_KEY_NAMES[char], char.encode()))
		elif ord(char) < 32:
			keys.append(('ctrl-' + chr(ord(char) + 96), char.encode()))
		else:
			keys.append((char, char.encode('utf-8')))
		index += 1
	return keys

def char_width(char):
	'''Columns a character takes on a terminal: 0 (combining, control), 1, or 2 (wide).'''
	import unicodedata
	if ord(char) < 32 or ord(char) == 127 or unicodedata.combining(char) or unicodedata.category(char) in ('Mn', 'Me', 'Cf'):
		return 0
	return 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1

_ESCAPES = None

def strip_escapes(text):
	'''text without terminal escape sequences and readline's \\001 / \\002 markers.'''
	global _ESCAPES
	if _ESCAPES is None:
		import re
		_ESCAPES = re.compile('\x1b\\[[0-9;?<=>]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|\x1b[()][0-9A-Za-z]|\x1b[@-Z\\\\-_]|[\x01\x02]')
	return _ESCAPES.sub('', text)

def text_width(text):
	'''Columns text takes on a terminal, escape sequences left out.'''
	return sum(char_width(char) for char in strip_escapes(text))

def fit(text, width):
	'''text cut to at most width columns (escape sequences are not counted and stay).'''
	out = []
	used = 0
	index = 0
	plain = strip_escapes(text)
	if text_width(plain) <= width:
		return text
	while index < len(text) and used < width:
		match = None
		if text[index] in '\x1b\x01\x02':
			match = _ESCAPES.match(text, index) if _ESCAPES is not None else None
		if match:
			out.append(match.group())
			index = match.end()
			continue
		size = char_width(text[index])
		if used + size > width:
			break
		out.append(text[index])
		used += size
		index += 1
	return ''.join(out)

def ghost_style(term):
	'''The escape sequence that draws grey text on terminal type term, or None where grey text is not drawn.'''
	if not term or term in ('dumb', 'unknown') or term.startswith(('vt52', 'cons25')):
		return None
	if '256color' in term or 'truecolor' in term or 'direct' in term:
		return '\x1b[38;5;244m'
	return '\x1b[2m'

class Terminal(object):
	'''The controlling terminal in raw mode, for the picker and the editor. Restores the mode on exit and on SIGTERM / SIGHUP.'''
	def __init__(self, path='/dev/tty'):
		self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
		self._saved = None
		self._handlers = {}
		self._pending = b''

	def __enter__(self):
		import signal
		import termios
		import tty
		self._saved = termios.tcgetattr(self.fd)
		for number in (signal.SIGTERM, signal.SIGHUP):
			self._handlers[number] = signal.signal(number, self._interrupted)
		# TCSANOW: TCSAFLUSH (the default) would drop keys typed while the program started
		tty.setraw(self.fd, termios.TCSANOW)
		return self

	def _interrupted(self, number, frame):
		self.restore()
		raise SystemExit(128 + number)

	def restore(self):
		import termios
		if self._saved is not None:
			try:
				termios.tcsetattr(self.fd, termios.TCSADRAIN, self._saved)
			except termios.error:
				pass

	def __exit__(self, *exc):
		import signal
		self.restore()
		for number, handler in self._handlers.items():
			signal.signal(number, handler)
		os.close(self.fd)

	def size(self):
		'''(rows, columns), 24x80 when the terminal does not say.'''
		import fcntl
		import struct
		import termios
		try:
			rows, columns = struct.unpack('hh', fcntl.ioctl(self.fd, termios.TIOCGWINSZ, b'\0' * 4))
			if rows > 0 and columns > 0:
				return rows, columns
		except OSError:
			pass
		return 24, 80

	def write(self, text):
		data = text.encode('utf-8', 'replace')
		while data:
			written = os.write(self.fd, data)
			data = data[written:]

	def read_keys(self, timeout=None):
		'''The keys typed so far (waiting up to timeout seconds for the first, None: forever); [] on timeout.'''
		import select
		ready, _, _ = select.select([self.fd], [], [], timeout)
		if not ready:
			return []
		data = self._pending + os.read(self.fd, 4096)
		self._pending = b''
		# a lone Esc may be the start of a sequence, and a character may be cut: wait for the rest
		while data == b'\x1b' or _incomplete_utf8(data):
			ready, _, _ = select.select([self.fd], [], [], 0.03)
			if not ready:
				break
			data += os.read(self.fd, 4096)
		cut = _incomplete_utf8(data)
		if cut:
			data, self._pending = data[:-cut], data[-cut:]
		return decode_keys(data)

def _incomplete_utf8(data):
	'''How many bytes at the end of data start a UTF-8 character that is not complete yet (0 if none).'''
	for back in range(1, min(len(data), 3) + 1):
		byte = data[-back]
		if byte & 0xC0 != 0x80:
			needed = 2 if byte & 0xE0 == 0xC0 else 3 if byte & 0xF0 == 0xE0 else 4 if byte & 0xF8 == 0xF0 else 1
			return back if needed > back else 0
	return 0

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_terminal.py -q`

Expected: `27 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/vt_grid.py tests/test_complete_terminal.py mssh_complete.py
git commit -m "feat: terminal layer for the picker and the editor

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 5: The picker

**Files:**
- Modify: `mssh_complete.py` (new section Picker, before Shell glue)
- Create: `tests/test_complete_picker.py`

**Interfaces:**
- Consumes: Task 2: `Engine.query` with `insert=1`, `Engine.usage`; Task 4: `text_width`, `fit`, `FakeTerminal`, `Grid`. SP1: `read_history`, `parse_history_line`, `line_features`, `lex`, `safe_field`
- Produces: `PICKER_ROWS = 10`, `HISTORY_LIMIT = 5000`; `PickItem(text, description='', uses=0, last=0)`; `fuzzy_score(query, text) -> float|None`; `Picker(slot_items, history_items, slot_title='', now=None, unicode=None)` with `tab`, `query`, `selected`, `matches()`, `handle(name) -> 'choose'|'cancel'|None`, `chosen()`, `render(width, rows) -> [lines]`, `run(term, prompt=None, column=1) -> 'choose'|'cancel'|'unavailable'`; `picker_items(request, engine, history_lines, now=None) -> (slot items, title, history items, word)`; `apply_pick(request, picker, word, context) -> (line, cursor)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_picker.py` with exactly this content:

````python
'''The Ctrl-R picker: fuzzy filter, keys, drawing below the prompt, and what a choice does to the line.'''
import multiSSH3
import mssh_complete as mc
from vt_grid import FakeTerminal, Grid

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su', 'gpu[01-16]', '"nvidia-smi"') for number in range(5)]
HISTORY += [line(NOW - 3600, '-su -u=root', 'storage1', '"df -h /data"')]


def engine(history=HISTORY):
	memory = mc.MemoryKnowledge()
	memory.add_history(history, SPEC, NOW)
	return mc.Engine(SPEC, [memory])


def items(*texts):
	return [mc.PickItem(text) for text in texts]


def test_fuzzy_score_prefers_consecutive_characters_and_word_starts():
	assert mc.fuzzy_score('gpu', 'gpu[01-16]') > mc.fuzzy_score('gpu', 'xgxpxu')
	assert mc.fuzzy_score('df', 'df -h /data') > mc.fuzzy_score('df', 'xdxf')
	assert mc.fuzzy_score('zz', 'gpu') is None
	assert mc.fuzzy_score('df data', 'df -h /data') is not None
	assert mc.fuzzy_score('df zz', 'df -h /data') is None
	assert mc.fuzzy_score('', 'anything') == 0


def test_filter_keeps_matches_and_the_context_rank_breaks_ties():
	picker = mc.Picker(items('login1', 'gpu01', 'gpu02'), [])
	for char in 'gpu':
		picker.handle(char)
	assert [item.text for item in picker.matches()] == ['gpu01', 'gpu02']
	picker.handle('backspace')
	assert picker.query == 'gp'


def test_keys_move_choose_and_cancel():
	picker = mc.Picker(items('a', 'b', 'c'), items('mssh x y'))
	assert picker.handle('down') is None and picker.chosen().text == 'b'
	assert picker.handle('ctrl-r') is None and picker.chosen().text == 'c'
	assert picker.handle('down') is None and picker.chosen().text == 'c'
	assert picker.handle('ctrl-p') is None and picker.chosen().text == 'b'
	assert picker.handle('tab') is None and picker.tab == 'history' and picker.chosen().text == 'mssh x y'
	assert picker.handle('enter') == 'choose'
	assert picker.handle('esc') == 'cancel'
	assert picker.handle('ctrl-g') == 'cancel'


def test_enter_with_nothing_matching_cancels():
	picker = mc.Picker(items('a'), [])
	picker.handle('z')
	assert picker.handle('enter') == 'cancel'


def test_tab_stays_when_the_other_tab_is_empty():
	picker = mc.Picker(items('a'), [])
	picker.handle('tab')
	assert picker.tab == 'slot'


def test_render_shows_title_rows_uses_and_status():
	picker = mc.Picker([mc.PickItem('gpu[01-16]', 'host', uses=12, last=NOW - 7200), mc.PickItem('login1')], items('mssh a b'), 'hosts', now=NOW, unicode=True)
	lines = picker.render(60, 3)
	assert len(lines) == 5
	assert lines[0].startswith('┌ hosts ') and lines[0].endswith(' 1/2 ┐')
	assert 'gpu[01-16]' in lines[1] and 'host  used 12x · 2h ago' in lines[1] and '\x1b[7m' in lines[1]
	assert 'login1' in lines[2] and '\x1b[7m' not in lines[2]
	assert lines[3] == '│' + ' ' * 57 + '│'
	assert 'type to filter · Tab: history · Esc' in lines[4]
	assert all(mc.text_width(text) <= 60 for text in lines)


def test_render_without_unicode_uses_ascii():
	picker = mc.Picker(items('a'), [], 'hosts', unicode=False)
	assert all(ord(char) < 128 for text in picker.render(40, 2) for char in text)


def test_run_draws_below_the_line_and_erases_after():
	grid = Grid(24, 80)
	grid.feed('$ mssh gp')
	term = FakeTerminal(['\x1b[B', '\r'], grid=grid)
	picker = mc.Picker(items('gpu01', 'gpu02'), [], 'hosts')
	assert picker.run(term) == 'choose'
	assert picker.chosen().text == 'gpu02'
	assert grid.lines()[0] == '$ mssh gp' and grid.lines()[1:] == [''] * 23
	assert grid.cursor == (0, 9)


def test_run_shows_the_rows_while_open():
	grid = Grid(24, 80)
	grid.feed('$ mssh gp')
	seen = []

	class Watching(FakeTerminal):
		def read_keys(self, timeout=None):
			seen.append(grid.lines())
			return FakeTerminal.read_keys(self, timeout)

	assert mc.Picker(items('gpu01', 'gpu02'), [], 'hosts').run(Watching(['\x1b'], grid=grid)) == 'cancel'
	assert ' hosts ' in seen[0][1] and 'gpu01' in seen[0][2] and 'gpu02' in seen[0][3]


def test_run_at_the_bottom_scrolls_and_keeps_the_column():
	grid = Grid(24, 80)
	grid.feed('\n' * 23 + '$ mssh gp')
	assert mc.Picker(items('gpu01'), [], 'hosts').run(FakeTerminal(['\x1b'], grid=grid)) == 'cancel'
	assert grid.cursor[1] == 9
	assert grid.line(grid.cursor[0]) == '$ mssh gp'


def test_run_redraws_the_prompt_bash_cleared():
	grid = Grid(24, 80)
	assert mc.Picker(items('gpu01'), [], 'hosts').run(FakeTerminal(['\x1b'], grid=grid), '$ mssh gp x', 10) == 'cancel'
	assert grid.line(0) == '$ mssh gp x'
	assert grid.cursor == (0, 9)


def test_run_is_unavailable_on_a_tiny_terminal():
	assert mc.Picker(items('a'), []).run(FakeTerminal([], rows=4)) == 'unavailable'


def request(before, after='', history=()):
	return mc.Request('bash', before, after, '', history=list(history))


def test_slot_tab_offers_the_slot_and_a_choice_replaces_the_word():
	req = request('mssh gpu[01-16] nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	assert title == 'commands for gpu[01-16]' and word == 'nv'
	assert slot[0].text == 'nvidia-smi' and slot[0].uses == 5
	picker = mc.Picker(slot, history, title)
	assert mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC)) == ('mssh gpu[01-16] nvidia-smi ', 27)


def test_a_choice_inside_an_open_quote_closes_it():
	req = request('mssh gpu[01-16] "nv')
	slot, title, history, word = mc.picker_items(req, engine(), HISTORY, NOW)
	picker = mc.Picker(slot, history, title)
	line, cursor = mc.apply_pick(req, picker, word, mc.parse_context(req.before, req.after, SPEC))
	assert line == 'mssh gpu[01-16] "nvidia-smi" ' and cursor == len(line)


def test_history_tab_rebuilds_whole_lines_with_the_typed_name():
	# what is typed (-u root) ranks the lines that share it first, then recency
	req = request('multissh -u root ', history=['ls', 'multissh -u admin login1 uptime'])
	_, _, history, _ = mc.picker_items(req, engine(), HISTORY, NOW)
	texts = [item.text for item in history]
	assert texts[0] == 'multissh -su -u=root storage1 "df -h /data"'
	assert 'multissh -su gpu[01-16] "nvidia-smi"' in texts
	assert 'multissh -u admin login1 uptime' in texts and 'ls' not in texts
	assert len(texts) == len(set(texts))
	picker = mc.Picker([], history)
	assert mc.apply_pick(req, picker, None, None) == (texts[0], len(texts[0]))
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_picker.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'fuzzy_score'` (`15 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Shell glue ----------------` (the line itself stays):

````python
#%% ------------ Picker ----------------
PICKER_ROWS = 10       # candidate rows the picker shows at most
HISTORY_LIMIT = 5000   # distinct past invocations the history tab offers

class PickItem(object):
	'''A picker row: text replaces the word (slot tab) or the whole line (history tab).'''
	__slots__ = ('text', 'description', 'uses', 'last')

	def __init__(self, text, description='', uses=0, last=0):
		self.text = text
		self.description = description
		self.uses = uses
		self.last = last

	def __repr__(self):
		return 'PickItem({!r})'.format(self.text)

def fuzzy_score(query, text):
	'''
	How well query matches text: its characters in order (case-insensitive), with more for
	consecutive characters and word starts. Space-separated terms must all match.

	Returns:
		float, or None when it does not match
	'''
	lower = text.lower()
	score = 0.0
	for term in query.lower().split():
		position = 0
		last = -2
		for char in term:
			found = lower.find(char, position)
			if found < 0:
				return None
			score += 1.0
			if found == last + 1:
				score += 2.0
			if found == 0 or not lower[found - 1].isalnum():
				score += 1.5
			last = found
			position = found + 1
	return score

def _age(seconds):
	'''A short age: now, 5m, 2h, 3d, 4w, 1y.'''
	for size, unit in ((365 * 86400, 'y'), (7 * 86400, 'w'), (86400, 'd'), (3600, 'h'), (60, 'm')):
		if seconds >= size:
			return '{}{}'.format(int(seconds // size), unit)
	return 'now'

def _unicode_terminal():
	import locale
	return (locale.getpreferredencoding(False) or '').lower().replace('-', '') == 'utf8'

class Picker(object):
	'''
	The Ctrl-R menu as state: a slot tab (candidates for the word at the cursor) and a history tab
	(whole past invocations), a fuzzy filter and a selection. run() draws it below the prompt line.
	'''
	def __init__(self, slot_items, history_items, slot_title='', now=None, unicode=None):
		self.items = {'slot': list(slot_items), 'history': list(history_items)}
		self.titles = {'slot': slot_title or 'candidates', 'history': 'history'}
		self.tab = 'slot' if self.items['slot'] else 'history'
		self.query = ''
		self.selected = 0
		self.offset = 0
		self.now = time.time() if now is None else now
		self.unicode = _unicode_terminal() if unicode is None else unicode

	def matches(self):
		'''The rows of the current tab that match the filter, best first.'''
		items = self.items[self.tab]
		if not self.query:
			return items
		scored = []
		for rank, item in enumerate(items):
			score = fuzzy_score(self.query, item.text)
			if score is not None:
				# the filter decides, the context rank breaks near ties
				scored.append((score - 3.0 * rank / len(items), rank, item))
		scored.sort(key=lambda entry: (-entry[0], entry[1]))
		return [item for _, _, item in scored]

	def handle(self, name):
		'''Apply one key. Returns 'choose', 'cancel' or None.'''
		count = len(self.matches())
		if name == 'enter':
			return 'choose' if count else 'cancel'
		if name in ('esc', 'ctrl-g', 'ctrl-c'):
			return 'cancel'
		if name in ('up', 'ctrl-p'):
			self.selected = max(0, self.selected - 1)
		elif name in ('down', 'ctrl-n', 'ctrl-r'):
			self.selected = min(max(count - 1, 0), self.selected + 1)
		elif name == 'pgup':
			self.selected = max(0, self.selected - PICKER_ROWS)
		elif name == 'pgdn':
			self.selected = min(max(count - 1, 0), self.selected + PICKER_ROWS)
		elif name == 'tab':
			other = 'history' if self.tab == 'slot' else 'slot'
			if self.items[other]:
				self.tab = other
				self.selected = self.offset = 0
		elif name == 'backspace':
			self.query = self.query[:-1]
			self.selected = self.offset = 0
		elif len(name) == 1 and name >= ' ':
			self.query += name
			self.selected = self.offset = 0
		return None

	def chosen(self):
		matches = self.matches()
		return matches[self.selected] if 0 <= self.selected < len(matches) else None

	def render(self, width, rows):
		'''
		The menu's lines: a title, rows candidate rows (blank when fewer match), a status line;
		each at most width columns. The selected row is in reverse video.
		'''
		matches = self.matches()
		if self.selected < self.offset:
			self.offset = self.selected
		if self.selected >= self.offset + rows:
			self.offset = self.selected - rows + 1
		horizontal, vertical, top_left, top_right, bottom_left, bottom_right = (
			('─', '│', '┌', '┐', '└', '┘') if self.unicode else ('-', '|', '+', '+', '+', '+'))
		inner = max(width - 3, 10)
		title = ' {} '.format(self.titles[self.tab] + (' · ' + self.query if self.query and self.unicode else (' : ' + self.query if self.query else '')))
		counter = ' {}/{} '.format(self.selected + 1 if matches else 0, len(matches))
		fill = max(inner - text_width(title) - text_width(counter), 0)
		lines = [fit(top_left + title + horizontal * fill + counter + top_right, width)]
		for number in range(self.offset, self.offset + rows):
			if number >= len(matches):
				lines.append(vertical + ' ' * (inner) + vertical)
				continue
			item = matches[number]
			used = []
			if item.uses:
				used.append('used {}x'.format(item.uses))
			if item.last:
				age = _age(max(self.now - item.last, 0))
				used.append(age if age == 'now' else age + ' ago')
			right = '  '.join(([item.description] if item.description else []) + ([(' · ' if self.unicode else ', ').join(used)] if used else []))
			marker = '> ' if number == self.selected else '  '
			left = fit(marker + item.text, max(inner - text_width(right) - 1, 8))
			middle = left + ' ' * max(inner - text_width(left) - text_width(right), 1) + right
			middle = fit(middle, inner)
			middle += ' ' * (inner - text_width(middle))
			if number == self.selected:
				middle = '\x1b[7m' + middle + '\x1b[27m'
			lines.append(vertical + middle + vertical)
		other = 'history' if self.tab == 'slot' else self.titles['slot']
		status = ' type to filter · Tab: {} · Esc '.format(other) if self.unicode else ' type to filter - Tab: {} - Esc '.format(other)
		if not self.items['history' if self.tab == 'slot' else 'slot']:
			status = status.replace(' · Tab: {}'.format(other), '').replace(' - Tab: {}'.format(other), '')
		lines.append(fit(bottom_left + status + horizontal * max(inner - text_width(status), 0) + bottom_right, width))
		return lines

	def run(self, term, prompt=None, column=1):
		'''
		Show the menu below the cursor's line and read keys until a choice or a cancel.

		Args:
			term (Terminal): In raw mode (line feeds keep the column)
			prompt (str): The prompt line to draw first when the shell cleared it (bash), else None
			column (int): With prompt: the 1-based column of the cursor on that line

		Returns:
			str: 'choose', 'cancel', or 'unavailable' when the terminal is too small
		'''
		rows, width = term.size()
		height = min(PICKER_ROWS, rows - 4)
		if height < 1 or width < 20:
			return 'unavailable'
		if prompt is not None:
			term.write('\r' + prompt + '\x1b[K\r' + ('\x1b[{}C'.format(column - 1) if column > 1 else ''))
		# make room below the line (the screen may scroll), come back to the same column and save it
		lines = height + 2
		term.write('\n' * lines + '\x1b[{}A\x1b7'.format(lines))
		try:
			while True:
				menu = self.render(width - 1, height)
				term.write(''.join('\r\n' + line + '\x1b[K' for line in menu) + '\x1b8')
				for name, _ in term.read_keys():
					outcome = self.handle(name)
					if outcome:
						return outcome
		finally:
			term.write('\x1b8\r\n\x1b[J\x1b8')

def picker_items(request, engine, history_lines, now=None):
	'''
	What the picker offers for a request.

	Returns:
		tuple: (slot items, slot title, history items, word): word is the text before the cursor the
			slot items replace (None when nothing can be framed: the slot tab is empty)
	'''
	now = time.time() if now is None else now
	context = parse_context(request.before, request.after, engine.spec)
	slot = []
	title = ''
	word = None
	if context is not None and request.before.endswith(context.prefix):
		word = context.prefix
		response = engine.query(Request(request.shell, request.before, request.after, word, request.shell_version, dict(request.flags, insert='1')))
		for candidate in response.candidates:
			value = (candidate.raw or candidate.text)[context.value_start:]
			uses, last = engine.usage(context, value)
			slot.append(PickItem(candidate.text, candidate.description, uses, last))
		title = {SLOT_HOSTS: 'hosts', SLOT_OPTION: 'options'}.get(context.slot, '')
		if context.slot == SLOT_VALUE:
			title = context.option.long
		elif context.slot == SLOT_COMMAND:
			title = 'commands for ' + context.hosts if context.hosts else 'commands'
	name = 'mssh'
	tokens = lex(request.before)
	if tokens and os.path.basename(tokens[0].text) in MSSH_NAMES:
		name = tokens[0].raw
	features = set(context.features) if context is not None else set()
	seen = {}
	entries = []
	for line in reversed(history_lines):
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		parts = [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']
		text = ' '.join([name] + parts)
		if not safe_field(text) or '\t' in text:
			continue
		if text in seen:
			seen[text][1] += 1
			continue
		if len(entries) >= HISTORY_LIMIT:
			continue
		entry = parse_history_line(line, engine.spec)
		overlap = len(features & set(entry.features())) if entry is not None else 0
		ts = entry.ts if entry is not None else 0
		seen[text] = [len(entries), 1]
		entries.append([overlap, ts, text])
	shell_lines = request.history[::-1] if request.shell != 'fish' else request.history
	for line in shell_lines:
		line = line.strip()
		tokens = lex(line)
		if tokens and os.path.basename(tokens[0].text) in MSSH_NAMES and line not in seen and len(entries) < HISTORY_LIMIT:
			seen[line] = [len(entries), 1]
			entries.append([len(features & set(line_features(tokens[1:], engine.spec))), 0, line])
	order = sorted(range(len(entries)), key=lambda number: (-entries[number][0], -entries[number][1], number))
	history = [PickItem(entries[number][2], '', seen[entries[number][2]][1], entries[number][1]) for number in order]
	return slot, title, history, word

def apply_pick(request, picker, word, context):
	'''The new line and cursor after a choice: (line, cursor).'''
	item = picker.chosen()
	if picker.tab == 'history':
		return item.text, len(item.text)
	suffix = ' '
	if context is not None and context.open_quote:
		suffix = ('"' if context.open_quote == '"' else "'") + ' '
	elif item.text.endswith('/'):
		suffix = ''
	before = request.before[:len(request.before) - len(word)] + item.text + suffix
	return before + request.after, len(before)

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_picker.py -q`

Expected: `15 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_picker.py mssh_complete.py
git commit -m "feat: the Ctrl-R picker (slot and history tabs, fuzzy filter)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 6: The plain-bash line editor

**Files:**
- Modify: `mssh_complete.py` (new section Line editor, before Shell glue)
- Create: `tests/test_complete_editor.py`

**Interfaces:**
- Consumes: Task 2: `Ghost`; Task 4: `strip_escapes`, `char_width`, `FakeTerminal`, `Grid`
- Produces: `expand_prompt(ps1, environ=None, now=None) -> str`; `readline_keyseq(raw: bytes) -> str`; `LineEditor(text, suggest=None, complete=None, pick=None)` with `text`, `cursor`, `prefix`, `ghost`, `refresh()`, `handle(name, raw) -> None | ('pass', bytes) | ('abandon', b'')`, `layout(prompt, width)`, `draw(term, prompt, style)`, `erase(term)`, `run(term, prompt, style=None) -> (action, replay bytes)`. `suggest(before) -> Ghost|None`; `complete(before) -> (texts, word)`; `pick(text, cursor, slot_only) -> (text, cursor)|None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_editor.py` with exactly this content:

````python
'''The plain-bash mssh line editor as a state machine, its drawing, and the bash 4.2/4.3 prompt expander.'''
import pytest

import mssh_complete as mc
from vt_grid import FakeTerminal, Grid

GHOST = 'u[01-16] "nvidia-smi"'


def suggester(calls=None):
	'''A suggestion source that knows one line: mssh gpu[01-16] "nvidia-smi".'''
	full = 'mssh gpu[01-16] "nvidia-smi"'

	def suggest(before):
		if calls is not None:
			calls.append(before)
		if full.startswith(before) and len(before) > len('mssh ') and before != full:
			return mc.Ghost('line', full[len(before):], 0.9)
		return None
	return suggest


def editor(text='mssh ', **kwargs):
	kwargs.setdefault('suggest', suggester())
	return mc.LineEditor(text, **kwargs)


def keys(edit, *names):
	'''Apply keys by name ('left', 'tab') or character; the outcome of the last one.'''
	outcome = None
	for name in names:
		outcome = edit.handle(name, name.encode('utf-8') if len(name) == 1 else b'')
	return outcome


def test_typing_inserts_and_asks_for_a_suggestion():
	edit = editor()
	assert keys(edit, 'g', 'p') is None
	assert (edit.text, edit.cursor, edit.ghost) == ('mssh gp', 7, GHOST)


def test_typing_along_the_suggestion_does_not_ask_again():
	calls = []
	edit = editor(suggest=suggester(calls))
	keys(edit, 'g', 'p')
	asked = len(calls)
	keys(edit, 'u', '[')
	assert len(calls) == asked and edit.ghost == '01-16] "nvidia-smi"'


@pytest.mark.parametrize('key', ['right', 'end', 'ctrl-f', 'ctrl-e'])
def test_accept_all(key):
	edit = editor()
	keys(edit, 'g', 'p')
	assert edit.handle(key, b'') is None
	assert (edit.text, edit.cursor) == ('mssh gpu[01-16] "nvidia-smi"', 28)


@pytest.mark.parametrize('key', ['alt-right', 'ctrl-right', 'alt-f'])
def test_accept_a_word(key):
	edit = editor()
	keys(edit, 'g', 'p')
	edit.handle(key, b'')
	assert edit.text == 'mssh gpu[01-16]' and edit.ghost == ' "nvidia-smi"'
	edit.handle(key, b'')
	assert edit.text == 'mssh gpu[01-16] "nvidia-smi"'


def test_moving_off_the_end_hides_the_suggestion_and_right_moves():
	edit = editor()
	keys(edit, 'g', 'p', 'left')
	assert edit.ghost == '' and edit.cursor == 6
	edit.handle('right', b'')
	assert edit.cursor == 7 and edit.ghost == GHOST


def test_enter_hands_the_typed_line_back():
	edit = editor()
	keys(edit, 'g', 'p')
	assert edit.handle('enter', b'\r') == ('pass', b'\r')
	assert edit.text == 'mssh gp'


def test_ctrl_c_abandons():
	assert editor().handle('ctrl-c', b'\x03') == ('abandon', b'')


@pytest.mark.parametrize('name, raw', [('up', b'\x1b[A'), ('ctrl-k', b'\x0b'), ('ctrl-l', b'\x0c'), ('alt-.', b'\x1b.'), ('unknown', b'\x1b[15~')])
def test_keys_it_does_not_handle_are_passed_on(name, raw):
	edit = editor('mssh x')
	assert edit.handle(name, raw) == ('pass', raw)
	assert edit.text == 'mssh x'


def test_backspace_into_the_prefix_hands_the_line_back():
	edit = editor()
	keys(edit, 'x')
	assert edit.handle('backspace', b'\x7f') is None and edit.text == 'mssh '
	assert edit.handle('backspace', b'\x7f') == ('pass', b'')
	assert (edit.text, edit.cursor) == ('mssh', 4)


def test_moving_left_of_the_prefix_hands_the_line_back():
	edit = editor()
	assert edit.handle('left', b'\x1b[D') == ('pass', b'\x1b[D')


def test_ctrl_u_and_ctrl_w_at_the_prefix_hand_the_line_back():
	edit = editor('mssh ')
	keys(edit, 'a', 'b')
	assert edit.handle('ctrl-u', b'\x15') == ('pass', b'')
	assert (edit.text, edit.cursor) == ('', 0)
	edit = editor('mssh ')
	keys(edit, 'a', 'b')
	assert edit.handle('ctrl-w', b'\x17') is None and edit.text == 'mssh '
	assert edit.handle('ctrl-w', b'\x17') == ('pass', b'\x17')


def test_home_goes_to_the_start_of_the_editors_part():
	edit = editor()
	keys(edit, 'a', 'b', 'home')
	assert edit.cursor == 5


def test_tab_inserts_the_common_part_then_a_space():
	edit = editor(complete=lambda before: (['gpu01', 'gpu02'], 'g'))
	keys(edit, 'g', 'tab')
	assert edit.text == 'mssh gpu0'
	edit = editor(complete=lambda before: (['gpu01'], 'g'))
	keys(edit, 'g', 'tab')
	assert edit.text == 'mssh gpu01 '


def test_tab_with_nothing_to_insert_opens_the_slot_menu():
	opened = []

	def pick(text, cursor, slot_only):
		opened.append(slot_only)
		return 'mssh gpu02 ', 11
	edit = editor(complete=lambda before: (['gpu01', 'gpu02'], 'gpu0'), pick=pick)
	keys(edit, 'g', 'p', 'u', '0', 'tab')
	assert opened == [True] and (edit.text, edit.cursor) == ('mssh gpu02 ', 11)
	keys(edit, 'ctrl-r')
	assert opened == [True, False]


def test_run_replays_the_ending_key_and_everything_typed_after_it():
	term = FakeTerminal(['g', 'x\x1b[Ayz'])
	edit = editor()
	assert edit.run(term, '$ ', '\x1b[2m') == ('pass', b'\x1b[Ayz')
	assert edit.text == 'mssh gx'


def test_draw_shows_grey_text_and_puts_the_cursor_after_the_typed_text():
	grid = Grid(5, 80)
	edit = editor()
	keys(edit, 'g', 'p')
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[38;5;244m')
	assert grid.line(0) == '$ mssh gpu[01-16] "nvidia-smi"'
	styles = grid.styles(0)
	assert styles[8] == '' and styles[9] == '38;5;244' and styles[29] == '38;5;244'
	assert grid.cursor == (0, 9)
	edit.erase(FakeTerminal([], grid=grid))
	assert grid.line(0) == '' and grid.cursor == (0, 0)


def test_draw_without_a_style_shows_no_grey_text():
	grid = Grid(5, 80)
	edit = editor()
	keys(edit, 'g', 'p')
	edit.draw(FakeTerminal([], grid=grid), '$ ', None)
	assert grid.line(0) == '$ mssh gp'


def test_draw_wraps_and_comes_back_to_the_cursor():
	grid = Grid(5, 10)
	edit = editor('mssh 漢字 ')
	edit.ghost = 'abcdef'
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[2m')
	assert grid.lines()[:2] == ['$ mssh 漢', '字 abcdef']
	assert grid.cursor == (1, 3)
	edit.draw(FakeTerminal([], grid=grid), '$ ', '\x1b[2m')
	assert grid.lines()[:3] == ['$ mssh 漢', '字 abcdef', '']
	edit.erase(FakeTerminal([], grid=grid))
	assert grid.lines()[:2] == ['', ''] and grid.cursor == (0, 0)


def test_layout_counts_the_line_the_terminal_has_not_wrapped_yet():
	edit = editor('mssh ab')
	assert edit.layout('$ ', 9) == (1, 0, 9, 9)


def test_expand_prompt_does_what_bash_does_for_common_escapes():
	environ = {'USER': 'ops', 'HOME': '/home/ops', 'PWD': '/home/ops/src', 'BASH_VERSION': '4.2.46(2)-release'}
	text = mc.expand_prompt('\\[\\e[1m\\]\\u:\\w \\W \\v\\033[0m\\$ $(date)', environ)
	assert text == '\x01\x1b[1m\x02ops:~/src src 4.2\x1b[0m{} $(date)'.format('#' if mc.os.geteuid() == 0 else '$')


@pytest.mark.parametrize('raw, keyseq', [
	(b'\x1b[A', '\\e[A'), (b'"\\', '\\"\\\\'), (b'\r', '\\C-m'), (b'\x7f', '\\C-?'),
	('é'.encode('utf-8'), '\\303\\251'), (b'', ''),
])
def test_readline_keyseq(raw, keyseq):
	assert mc.readline_keyseq(raw) == keyseq
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_editor.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'LineEditor'` (`35 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Shell glue ----------------` (the line itself stays):

````python
#%% ------------ Line editor ----------------
_PROMPT_ESCAPES = None

def expand_prompt(ps1, environ=None, now=None):
	'''
	PS1 expanded the way bash does for its common escapes (\\u \\h \\H \\w \\W \\$ \\[ \\] \\e \\033 \\n
	\\t \\d \\@ \\A \\T \\j \\s \\v \\V \\!), for bash 4.2 / 4.3 where ${PS1@P} does not exist.
	$(...) and variables stay as they are.
	'''
	import socket
	environ = os.environ if environ is None else environ
	now = time.localtime(time.time() if now is None else now)
	home = environ.get('HOME', '')
	cwd = environ.get('PWD') or os.getcwd()
	short = '~' + cwd[len(home):] if home and (cwd == home or cwd.startswith(home + '/')) else cwd
	host = socket.gethostname()
	user = environ.get('USER') or environ.get('LOGNAME') or ''
	if not user:
		import getpass
		try:
			user = getpass.getuser()
		except Exception:
			user = ''
	version = environ.get('BASH_VERSION', '')
	values = {
		'u': user, 'h': host.split('.')[0], 'H': host, 'w': short, 'W': os.path.basename(short) if short not in ('/', '~') else short,
		'$': '#' if hasattr(os, 'geteuid') and os.geteuid() == 0 else '$', '[': '\x01', ']': '\x02', 'e': '\x1b', 'n': '\n',
		't': time.strftime('%H:%M:%S', now), 'T': time.strftime('%I:%M:%S', now), '@': time.strftime('%I:%M %p', now),
		'A': time.strftime('%H:%M', now), 'd': time.strftime('%a %b %d', now), 'j': '0', 's': 'bash',
		'v': '.'.join(version.split('.')[:2]), 'V': version.split('(')[0], '!': '!', '\\': '\\', 'a': '\a',
	}
	out = []
	index = 0
	while index < len(ps1):
		char = ps1[index]
		if char == '\\' and index + 1 < len(ps1):
			name = ps1[index + 1]
			if ps1[index + 1:index + 4].isdigit() and len(ps1[index + 1:index + 4]) == 3:
				out.append(chr(int(ps1[index + 1:index + 4], 8)))
				index += 4
				continue
			if name in values:
				out.append(values[name])
				index += 2
				continue
		out.append(char)
		index += 1
	return ''.join(out)

def readline_keyseq(raw):
	'''raw key bytes written in readline's key sequence notation (for a bind macro).'''
	out = []
	for byte in bytearray(raw):
		if byte == 0x1b:
			out.append('\\e')
		elif byte == 0x5c:
			out.append('\\\\')
		elif byte == 0x22:
			out.append('\\"')
		elif byte == 0x7f:
			out.append('\\C-?')
		elif byte < 32:
			out.append('\\C-' + chr(byte + 96))
		elif byte < 127:
			out.append(chr(byte))
		else:
			out.append('\\{:03o}'.format(byte))
	return ''.join(out)

class LineEditor(object):
	'''
	The plain-bash editor for an mssh line, as state: text, cursor and the grey suggestion.

	The editor owns the text after its prefix (the line it started with, "mssh "). handle() returns
	None to keep editing or the bytes readline must replay when the editor hands the line back
	(the key that ended it and any keys typed after it), or the action 'abandon'.

	suggest(before) -> Ghost or None; complete(before) -> (candidate texts, word) where the texts
	replace word at the end of before; pick(text, cursor, slot_only) -> (text, cursor) or None.
	'''
	def __init__(self, text, suggest=None, complete=None, pick=None):
		self.text = text
		self.cursor = len(text)
		self.prefix = len(text)
		self.suggest = suggest
		self.complete = complete
		self.pick = pick
		self.ghost = ''
		self._ghost_for = None

	def refresh(self):
		'''Keep the suggestion in step with the text: ask again unless typing followed it.'''
		if self.cursor != len(self.text) or self.suggest is None:
			self.ghost = ''
			self._ghost_for = None
			return
		if self._ghost_for == self.text:
			return
		ghost = None
		try:
			ghost = self.suggest(self.text)
		except Exception as e:
			_debug('suggestion failed: {!r}'.format(e))
		self.ghost = ghost.text if ghost is not None else ''
		self._ghost_for = self.text

	def _insert(self, text):
		at_end = self.cursor == len(self.text)
		self.text = self.text[:self.cursor] + text + self.text[self.cursor:]
		self.cursor += len(text)
		if at_end and self.ghost.startswith(text):
			# typing along the suggestion keeps the rest of it
			self.ghost = self.ghost[len(text):]
			self._ghost_for = self.text

	def _accept(self, whole):
		if not self.ghost:
			return False
		if whole:
			taken = self.ghost
		else:
			# leading spaces, then the next word
			stripped = len(self.ghost) - len(self.ghost.lstrip(' '))
			end = self.ghost.find(' ', stripped)
			taken = self.ghost if end < 0 else self.ghost[:end]
		self._insert(taken)
		return True

	def _word_left(self):
		position = self.cursor
		while position > self.prefix and self.text[position - 1] == ' ':
			position -= 1
		while position > self.prefix and self.text[position - 1] != ' ':
			position -= 1
		return position

	def _word_right(self):
		position = self.cursor
		while position < len(self.text) and self.text[position] == ' ':
			position += 1
		while position < len(self.text) and self.text[position] != ' ':
			position += 1
		return position

	def handle(self, name, raw):
		'''
		Apply one key.

		Returns:
			None to keep editing; ('pass', bytes) to hand the line back with bytes for readline to
			replay; ('abandon', b'') to drop the line
		'''
		at_end = self.cursor == len(self.text)
		if name == 'enter':
			return 'pass', raw
		if name == 'ctrl-c':
			return 'abandon', b''
		if len(name) == 1 and name >= ' ':
			self._insert(name)
		elif name == 'backspace':
			if self.cursor <= self.prefix:
				# deleting into the prefix: the line is readline's again
				if self.cursor > 0:
					self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
					self.cursor -= 1
				return 'pass', b''
			self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
			self.cursor -= 1
		elif name in ('delete', 'ctrl-d'):
			if self.cursor < len(self.text):
				self.text = self.text[:self.cursor] + self.text[self.cursor + 1:]
		elif name in ('left', 'ctrl-b'):
			if self.cursor <= self.prefix:
				return 'pass', raw
			self.cursor -= 1
		elif name in ('right', 'ctrl-f'):
			if not (at_end and self._accept(True)):
				self.cursor = min(len(self.text), self.cursor + 1)
		elif name in ('end', 'ctrl-e'):
			if not (at_end and self._accept(True)):
				self.cursor = len(self.text)
		elif name in ('home', 'ctrl-a'):
			self.cursor = self.prefix
		elif name in ('alt-right', 'ctrl-right', 'alt-f'):
			if not (at_end and self._accept(False)):
				self.cursor = self._word_right()
		elif name in ('alt-left', 'ctrl-left', 'alt-b'):
			self.cursor = self._word_left()
		elif name == 'ctrl-u':
			self.text = self.text[self.cursor:]
			self.cursor = 0
			return 'pass', b''
		elif name == 'ctrl-w':
			start = self._word_left()
			if start <= self.prefix and self.cursor == self.prefix:
				return 'pass', raw
			self.text = self.text[:start] + self.text[self.cursor:]
			self.cursor = start
		elif name == 'tab':
			self._tab()
		elif name == 'ctrl-r':
			self._pick(False)
		else:
			return 'pass', raw
		self.refresh()
		return None

	def _tab(self):
		if self.complete is None:
			return
		texts, word = self.complete(self.text[:self.cursor])
		if not texts:
			return
		common = os.path.commonprefix(texts)
		if len(common) > len(word) and common.startswith(word):
			self._insert(common[len(word):])
			if len(set(texts)) == 1 and self.cursor == len(self.text):
				self._insert(' ')
		else:
			self._pick(True)

	def _pick(self, slot_only):
		if self.pick is None:
			return
		result = self.pick(self.text, self.cursor, slot_only)
		if result is not None:
			self.text, self.cursor = result
			self._ghost_for = None

	def layout(self, prompt, width):
		'''
		Where things go on screen: (rows used, cursor row, cursor column, column after the last
		character), rows counted from the prompt's row, wrapped at width.
		'''
		def advance(row, column, chunk):
			for char in strip_escapes(chunk):
				size = char_width(char)
				if column + size > width:
					row, column = row + 1, 0
				column += size
			return row, column
		row, column = advance(0, 0, prompt)
		cursor_row, cursor_column = advance(row, column, self.text[:self.cursor])
		end_row, end_column = advance(row, column, self.text + self.ghost)
		return end_row + 1, cursor_row, cursor_column, end_column

	def draw(self, term, prompt, style):
		'''Draw the prompt's last line, the text and the grey suggestion; leave the cursor at the text's cursor.'''
		width = term.size()[1]
		rows, cursor_row, cursor_column, end_column = self.layout(prompt, width)
		ghost = (style + self.ghost + '\x1b[0m') if (style and self.ghost) else ''
		out = []
		if getattr(self, '_row', 0):
			out.append('\x1b[{}A'.format(self._row))
		out.append('\r' + prompt + self.text + ghost + '\x1b[J')
		end_row = rows - 1
		if end_column == width:
			# the terminal waits to wrap until the next character: wrap now so moves are exact
			out.append('\r\n')
			end_row += 1
		if end_row > cursor_row:
			out.append('\x1b[{}A'.format(end_row - cursor_row))
		out.append('\r')
		if cursor_column:
			out.append('\x1b[{}C'.format(cursor_column))
		term.write(''.join(out))
		self._row = cursor_row

	def erase(self, term):
		'''Erase what the editor drew; the cursor ends at the start of the prompt's row.'''
		term.write(('\x1b[{}A'.format(self._row) if getattr(self, '_row', 0) else '') + '\r\x1b[J')
		self._row = 0

	def run(self, term, prompt, style=None):
		'''
		Edit until the line is handed back.

		Returns:
			tuple: ('pass', bytes readline replays) or ('abandon', b'')
		'''
		self._row = 0
		self.refresh()
		self.draw(term, prompt, style)
		while True:
			keys = term.read_keys()
			for number, (name, raw) in enumerate(keys):
				outcome = self.handle(name, raw)
				if outcome is not None:
					action, replay = outcome
					# keys typed after the one that ended the editor belong to readline
					replay += b''.join(rest for _, rest in keys[number + 1:])
					self.erase(term)
					return action, replay
			self.draw(term, prompt, style)

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_editor.py -q`

Expected: `35 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_editor.py mssh_complete.py
git commit -m "feat: the mssh line editor for plain bash

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 7: mssh-complete pick and edit

**Files:**
- Modify: `mssh_complete.py` (Command line: `_prompt_from_flags`, `_cmd_pick`, `_cmd_edit`, `main`)
- Modify: `tests/test_complete_picker.py` (append)

**Interfaces:**
- Consumes: Task 2: `engine_for`, `Engine.suggest`; Task 4: `Terminal`, `ghost_style`, `text_width`; Task 5: `Picker`, `picker_items`, `apply_pick`; Task 6: `LineEditor`, `expand_prompt`, `readline_keyseq`
- Produces: `mssh-complete pick`: request on stdin (flags `pick=1`, `redraw=1` and `expand=1` for bash), prompt in `$MSSH_COMPLETE_PROMPT`; prints `MSSHC1`, `L <cursor>\t<line>`, `E`; exit 0 chosen, 1 cancelled, 2 unavailable. `mssh-complete edit [--expand] TEXT`: history on stdin, prompt in `$MSSH_COMPLETE_PROMPT`; prints `MSSHC1`, `L <cursor>\t<line>`, `K <pass|abandon>\t<readline key sequence>`, `E`; exit 3 when it cannot start.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_complete_picker.py` (the text starts with the blank lines that separate it from what is there):

````python


def run_engine(args, data, env):
	'''Run the engine with no controlling terminal.'''
	import subprocess
	from complete_shell_harness import ENGINE
	return subprocess.run(ENGINE + args, input=data, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, timeout=60)


def test_pick_and_edit_without_a_terminal_step_aside(tmp_path):
	from complete_shell_harness import make_home
	env, _ = make_home(tmp_path, HISTORY)
	pick = b'\0'.join([b'MSSHC1', b'bash', b'5.2', b'pick=1', b'mssh gp', b'', b'', b''])
	for data, term in ((pick, 'xterm'), (pick, 'dumb'), (b'not a request', 'xterm')):
		result = run_engine(['pick'], data, dict(env, TERM=term))
		assert (result.returncode, result.stdout, result.stderr) == (2, b'', b'')
	edit = run_engine(['edit', 'mssh '], b'', env)
	assert (edit.returncode, edit.stdout) == (3, b'')
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_picker.py -q`

Expected: FAIL, e.g. `E AssertionError: assert (2, b'', b'us...ll [SHELL]\n') == (2, b'', b'')` (`1 failed, 15 passed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		_debug('query failed: {!r}'.format(e))
		return 1
	sys.stdout.buffer.write(format_response(response, nul=request.flags.get('nul', '1') != '0'))
	sys.stdout.buffer.flush()
	return 0

````

with:

````python
		_debug('query failed: {!r}'.format(e))
		return 1
	sys.stdout.buffer.write(format_response(response, nul=request.flags.get('nul', '1') != '0'))
	sys.stdout.buffer.flush()
	return 0

def _prompt_from_flags(flags):
	'''
	The prompt line to redraw when a request says redraw=1 (bash clears the line before running
	pick or edit), or None. The prompt is in $MSSH_COMPLETE_PROMPT: expanded, or PS1 itself with expand=1.
	'''
	if flags.get('redraw') != '1':
		return None
	prompt = os.environ.get('MSSH_COMPLETE_PROMPT', '')
	if flags.get('expand') == '1':
		prompt = expand_prompt(prompt)
	return prompt.rsplit('\n', 1)[-1].replace('\x01', '').replace('\x02', '')

def _cmd_pick():
	'''
	mssh-complete pick: the Ctrl-R picker. Reads a request on stdin, draws on /dev/tty, prints the new
	line (MSSHC1, L <cursor>\\t<line>, E; no NUL: shells read it with command substitution). Exit 0
	chosen, 1 cancelled, 2 unavailable (the shell then does what Ctrl-R did before).
	'''
	data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
	try:
		request = parse_request(data)
	except ValueError:
		return 2
	if ghost_style(os.environ.get('TERM', '')) is None:
		return 2
	now = time.time()
	try:
		engine = engine_for(request, now=now)
		history_lines = read_history(engine.history_path)[0] if engine.history_path else []
		slot, title, history, word = picker_items(request, engine, history_lines, now)
		if not slot and not history:
			return 2
		picker = Picker(slot, history, title, now)
		prompt = _prompt_from_flags(request.flags)
		column = 1
		if prompt is not None:
			column = text_width(prompt + request.before) + 1
			prompt += request.before + request.after
		with Terminal() as term:
			outcome = picker.run(term, prompt, column)
	except Exception as e:
		_debug('pick failed: {!r}'.format(e))
		return 2
	if outcome == 'unavailable':
		return 2
	if outcome != 'choose':
		return 1
	line, cursor = apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))
	sys.stdout.buffer.write('MSSHC1\nL {}\t{}\nE\n'.format(cursor, line).encode('utf-8', 'surrogateescape'))
	sys.stdout.buffer.flush()
	return 0

def _cmd_edit(args):
	'''
	mssh-complete edit [--expand] TEXT: the plain-bash editor for an mssh line.

	The prompt to redraw is in $MSSH_COMPLETE_PROMPT (PS1 itself with --expand); stdin holds the
	shell's history tail. Prints MSSHC1, L <cursor>\\t<line>, K <action>\\t<keys> (pass: readline
	replays keys, written as a readline key sequence; abandon: drop the line), E. Exit 3 when the
	editor cannot start; the shell then goes on as if it had not been asked.
	'''
	import argparse
	import glob
	parser = argparse.ArgumentParser(prog='mssh-complete edit')
	parser.add_argument('--expand', action='store_true')
	parser.add_argument('text')
	options = parser.parse_args(args)
	prompt = _prompt_from_flags({'redraw': '1', 'expand': '1' if options.expand else '0'}) or ''
	history = [line for line in sys.stdin.read().split('\n') if line.strip()] if not sys.stdin.isatty() else []
	try:
		engine = engine_for(Request('bash', options.text, '', '', history=history))
		term = Terminal()
	except Exception as e:
		_debug('editor cannot start: {!r}'.format(e))
		return 3
	cache = {}

	def suggest(before):
		return engine.suggest(Request('bash', before, '', ''))

	def complete(before):
		context = parse_context(before, '', engine.spec)
		if context is None or not before.endswith(context.prefix):
			return [], ''
		response = engine.query(Request('bash', before, '', context.prefix))
		texts = [candidate.text for candidate in response.candidates]
		if 'files' in response.directives or 'dirs' in response.directives:
			for path in sorted(glob.glob(context.value + '*')):
				if 'files' in response.directives or os.path.isdir(path):
					texts.append(context.prefix[:context.value_start] + path + ('/' if os.path.isdir(path) else ''))
		return texts, context.prefix

	def pick(text, cursor, slot_only):
		if 'history' not in cache:
			cache['history'] = read_history(engine.history_path)[0] if engine.history_path else []
		request = Request('bash', text[:cursor], text[cursor:], None, history=history)
		slot, title, items, word = picker_items(request, engine, cache['history'])
		if not slot and (slot_only or not items):
			return None
		picker = Picker(slot, [] if slot_only else items, title)
		editor.erase(term)
		outcome = picker.run(term, prompt + text, text_width(prompt + text[:cursor]) + 1)
		if outcome != 'choose':
			return None
		return apply_pick(request, picker, word, parse_context(request.before, request.after, engine.spec))

	editor = LineEditor(options.text, suggest, complete, pick)
	try:
		with term:
			action, replay = editor.run(term, prompt, ghost_style(os.environ.get('TERM', '')))
	except Exception as e:
		_debug('editor failed: {!r}'.format(e))
		action, replay = 'pass', b''
	out = 'MSSHC1\nL {}\t{}\nK {}\t{}\nE\n'.format(editor.cursor, editor.text, action, readline_keyseq(replay))
	sys.stdout.buffer.write(out.encode('utf-8', 'surrogateescape'))
	sys.stdout.buffer.flush()
	return 0

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return _cmd_rebuild(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
	if command in ('glue', 'install', 'uninstall'):
		return completion_command(argv[1:] if command == 'glue' else argv)
	if command in ('-V', '--version'):
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | rebuild | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

if __name__ == '__main__':
````

with:

````python
		return _cmd_rebuild(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
	if command == 'pick':
		return _cmd_pick()
	if command == 'edit':
		return _cmd_edit(argv[1:])
	if command in ('glue', 'install', 'uninstall'):
		return completion_command(argv[1:] if command == 'glue' else argv)
	if command in ('-V', '--version'):
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete query | pick | edit TEXT | rebuild | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

if __name__ == '__main__':
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_picker.py -q`

Expected: `16 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `779 passed, 21 skipped`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_picker.py mssh_complete.py
git commit -m "feat: mssh-complete pick and edit

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 8: bash glue: Ctrl-R, the line editor, ble.sh

**Files:**
- Modify: `mssh_complete.py` (`BASH_GLUE`)
- Modify: `tests/complete_shell_harness.py`
- Modify: `tests/test_complete_shells.py` (`_interactive_output`)
- Create: `tests/test_complete_keys.py`

**Interfaces:**
- Consumes: Task 7: `pick`, `edit`; Task 2: `ghost=1` queries
- Produces: In `BASH_GLUE`: `_mssh_complete_engine`, `_mssh_complete_is_mssh`, `_mssh_complete_request`, `_mssh_complete_prompt`, `_mssh_complete_cut`, `_mssh_complete_set`, `_mssh_complete_apply`, `_mssh_complete_pick`, `_mssh_complete_ctrl_r`, `_mssh_complete_rearm`, `_mssh_complete_arm`, `_mssh_complete_previous`, `_mssh_complete_space`, `_mssh_complete_keys` (plain bash, run once from PROMPT_COMMAND at the first prompt); for ble.sh `ble/widget/mssh-complete/ctrl-r` and `ble/complete/auto-complete/source:mssh`. Hook keys: `\C-x\C-o` (emacs Ctrl-R), `\C-x\C-q` (vi-insert Ctrl-R), `\C-x\C-t` (space), trampoline `\C-x\C-y`. Harness: `bash_session(..., pre='')`, `zsh_session(..., pre='', extra='')`, `fish_session(home, env, keys_glue, pre='')`.

- [ ] **Step 1: Write the failing tests**

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
PS1='@@READY@@ '
bind -x '"\C-x\C-p": printf "@@LINE[%s]@@\n" "$READLINE_LINE"'
{bash_completion}
# a command with its own completion, for delegation tests
_fakecmd() {{ COMPREPLY=($(compgen -W "alpha beta" -- "$2")); }}
complete -F _fakecmd fakecmd
````

with:

````python
PS1='@@READY@@ '
bind -x '"\C-x\C-p": printf "@@LINE[%s]@@\n" "$READLINE_LINE"'
{bash_completion}
{pre}
# a command with its own completion, for delegation tests
_fakecmd() {{ COMPREPLY=($(compgen -W "alpha beta" -- "$2")); }}
complete -F _fakecmd fakecmd
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
ZSH_TEST_RC = r'''
PS1='@@READY@@ '
autoload -Uz compinit && compinit -u -D
_mssh_test_print() {{ print -r -- "@@LINE[$BUFFER]@@" }}
zle -N _mssh_test_print
bindkey '^X^P' _mssh_test_print
````

with:

````python
ZSH_TEST_RC = r'''
PS1='@@READY@@ '
autoload -Uz compinit && compinit -u -D
{pre}
_mssh_test_print() {{ print -r -- "@@LINE[$BUFFER]@@" }}
zle -N _mssh_test_print
bindkey '^X^P' _mssh_test_print
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
_fakecmd() {{ compadd alpha beta }}
compdef _fakecmd fakecmd
[[ -r {glue} ]] && source {glue} 2>/dev/null
'''

def require_blesh():
````

with:

````python
_fakecmd() {{ compadd alpha beta }}
compdef _fakecmd fakecmd
[[ -r {glue} ]] && source {glue} 2>/dev/null
{extra}
'''

def require_blesh():
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python
	session.read_until(b'@@READY@@', timeout=60)
	return session

def bash_session(home, env, glue, bash_completion=True, extra=''):
	rc = home / 'test.bashrc'
	loader = '. /usr/share/bash-completion/bash_completion 2>/dev/null' if bash_completion else ''
	rc.write_text(BASH_TEST_RC.format(bash_completion=loader, glue=glue, extra=extra))
	session = Session([require_shell('bash'), '--noprofile', '--rcfile', str(rc), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@')
	return session

def zsh_session(home, env, glue):
	(home / '.zshrc').write_text(ZSH_TEST_RC.format(glue=glue))
	session = Session([require_shell('zsh'), '-i'], dict(env, ZDOTDIR=str(home)), cwd=home)
	session.read_until(b'@@READY@@')
	return session
````

with:

````python
	session.read_until(b'@@READY@@', timeout=60)
	return session

def bash_session(home, env, glue, bash_completion=True, extra='', pre=''):
	'''An interactive bash with the glue; pre runs before the glue loads, extra after.'''
	rc = home / 'test.bashrc'
	loader = '. /usr/share/bash-completion/bash_completion 2>/dev/null' if bash_completion else ''
	rc.write_text(BASH_TEST_RC.format(bash_completion=loader, glue=glue, extra=extra, pre=pre))
	session = Session([require_shell('bash'), '--noprofile', '--rcfile', str(rc), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@')
	return session

def zsh_session(home, env, glue, pre='', extra=''):
	'''An interactive zsh with the glue; pre runs before the glue loads, extra after.'''
	(home / '.zshrc').write_text(ZSH_TEST_RC.format(glue=glue, pre=pre, extra=extra))
	session = Session([require_shell('zsh'), '-i'], dict(env, ZDOTDIR=str(home)), cwd=home)
	session.read_until(b'@@READY@@')
	return session
````

In `tests/complete_shell_harness.py`, replace this text (it occurs exactly once):

````python

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"
````

with:

````python

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"

FISH_TEST_CONFIG = r'''
set -g fish_greeting
function fish_prompt; printf '@@READY@@ '; end
bind \cx\cp 'printf "@@LINE[%s]@@\\n" (commandline)'
{pre}
'''

def fish_session(home, env, keys_glue, pre=''):
	'''An interactive fish with the Ctrl-R glue in conf.d; pre runs in config.fish (after conf.d).'''
	config = home / '.config' / 'fish'
	(config / 'conf.d').mkdir(parents=True, exist_ok=True)
	(config / 'conf.d' / 'mssh-complete.fish').write_text(keys_glue)
	(config / 'config.fish').write_text(FISH_TEST_CONFIG.format(pre=pre))
	session = Session([require_shell('fish'), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@', timeout=20)
	return session
````

In `tests/test_complete_shells.py`, replace this text (it occurs exactly once):

````python
import os
import subprocess
import time

````

with:

````python
import os
import re
import subprocess
import time

````

In `tests/test_complete_shells.py`, replace this text (it occurs exactly once):

````python
	'''Everything a fresh interactive shell prints before its first prompt, without the prompt.'''
	argv = {'bash': [shell, '-i'], 'zsh': [shell, '-i'], 'fish': [shell, '-i']}[os.path.basename(shell)]
	result = subprocess.run(argv, input=b'exit\n', env=dict(env, PS1='', PROMPT=''), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	return result.returncode, result.stdout.decode('utf-8', 'replace')


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
````

with:

````python
	'''Everything a fresh interactive shell prints before its first prompt, without the prompt.'''
	argv = {'bash': [shell, '-i'], 'zsh': [shell, '-i'], 'fish': [shell, '-i']}[os.path.basename(shell)]
	result = subprocess.run(argv, input=b'exit\n', env=dict(env, PS1='', PROMPT=''), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	# bash 4.2's readline turns on xterm's meta key mode again when keys were bound at the first
	# prompt: the same invisible mode, sent twice
	return result.returncode, re.sub('(\x1b\\[\\?1034h)+', '\x1b[?1034h', result.stdout.decode('utf-8', 'replace'))


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
````

Create `tests/test_complete_keys.py` with exactly this content:

````python
'''
SP2 in real shells: grey suggestions, the Ctrl-R picker and the plain-bash mssh line editor.

Every shell gets a private HOME holding an mssh history where one invocation clearly dominates,
so the engine's suggestion for "mssh gp" is the whole line u[01-16] "nvidia-smi".
'''
import re
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, bash_session, blesh_session, build_index, fish_session, make_home,
	require_shell, zsh_session)

HISTORY = ['17900000{:02d}\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"'.format(number) for number in range(6)] + [
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]
SHELL_HISTORY = 'echo aa1\necho aa2\necho bb\n'
FAKE_MSSH = 'mssh() { printf "@@RAN[%s]@@\\n" "$*"; }'
RIGHT = '\x1b[C'
UP = '\x1b[A'


@pytest.fixture
def home(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	(home / '.bash_history').write_text(SHELL_HISTORY)
	return env, home


def glue_file(home, shell, name=None):
	path = home / (name or 'glue.' + shell)
	path.write_text(mc.render_glue(shell, ENGINE))
	return path


def printed(session, keys, wait=0.6):
	'''Send keys, then the print key; the command line the shell printed (None if it did not).'''
	session.send(keys)
	time.sleep(wait)
	session.send(session.print_key)
	text = session.read_until(b']@@', 10)
	start = text.rfind('@@LINE[')
	end = text.find(']@@', start)
	return text[start + 7:end] if start >= 0 and end > start else None


def plain(text):
	'''Terminal output without escape sequences and carriage returns.'''
	return re.sub(r'\x1b(\[[0-9;?<=>]*[ -/]*[@-~]|[()][A-Z0-9]|[=>78])', '', text).replace('\r', '')


def words(line):
	'''The words a line means, whatever quoting was chosen.'''
	return None if line is None else [token.text for token in mc.lex(line)]


PICKED = ['mssh', 'gpu[01-16]', 'nvidia-smi']


def bash_version(env):
	output = subprocess.run([require_shell('bash'), '-c', 'echo ${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}'], env=env, stdout=subprocess.PIPE)
	return int(output.stdout.decode().strip())


# ---------------------------------------------------------------- plain bash: Ctrl-R

def test_bash_ctrl_r_opens_the_picker_on_mssh_lines(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
	finally:
		session.close()


def test_bash_ctrl_r_cancel_keeps_the_line(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] nv')
		time.sleep(0.3)
		session.send('\x12')
		session.read_until(b'commands for', 10)
		assert printed(session, '\x1b') == 'mssh gpu[01-16] nv'
	finally:
		session.close()


def test_bash_ctrl_r_on_other_lines_is_still_reverse_search(home):
	env, home = home
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		# the second Ctrl-R finds the older match, as readline's own search does
		session.send('\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
		# and the next prompt opens the picker again on mssh lines
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for' in session.read_until(b'commands for', 10)
	finally:
		session.close()


@pytest.mark.parametrize('where', ['before', 'after'])
def test_bash_ctrl_r_on_other_lines_calls_a_previous_shell_command(home, where):
	env, home = home
	fzf = '_fakefzf() { READLINE_LINE=FZF; READLINE_POINT=3; }\nbind -x \'"\\C-r": _fakefzf\''
	# bound before the glue loads, or after it in the same rc file: both are there at the first prompt
	session = bash_session(home, env, glue_file(home, 'bash'), **{'pre' if where == 'before' else 'extra': fzf})
	try:
		assert printed(session, 'ls\x12') == 'FZF'
		session.send('\x15mssh gpu[01-16] \x12')
		if bash_version(env) < 43:
			# bash 4.2 cannot list bind -x bindings: Ctrl-R stays the shell command everywhere
			assert printed(session, '') == 'FZF'
		else:
			assert 'commands for' in session.read_until(b'commands for', 10)
	finally:
		session.close()


def test_bash_vi_mode_ctrl_r(home):
	env, home = home
	pre = 'set -o vi\nbind -m vi-insert -x \'"\\C-x\\C-p": printf "@@LINE[%s]@@\\n" "$READLINE_LINE"\''
	session = bash_session(home, env, glue_file(home, 'bash'), pre=pre)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.3)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
	finally:
		session.close()


# ---------------------------------------------------------------- plain bash: the mssh line editor

def editor_session(env, home, **kwargs):
	return bash_session(home, dict(env, MSSH_COMPLETE_EDITOR='1', **kwargs), glue_file(home, 'bash'), extra=FAKE_MSSH)


def test_editor_shows_and_accepts_the_suggestion(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		assert '\x1b[38;5;244mu[01-16] "nvidia-smi"' in session.read_until(b'nvidia-smi', 10)
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_editor_enter_runs_what_was_typed(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		session.send('\r')
		assert '@@RAN[gp]@@' in session.read_until(b'@@RAN[', 10) + session.read_until(b']@@', 10)
	finally:
		session.close()


def test_editor_keeps_a_burst_of_type_ahead(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] "nvidia-smi"\r')
		assert '@@RAN[gpu[01-16] nvidia-smi]@@' in session.read_until(b'@@RAN', 10) + session.read_until(b'@@READY@@', 10)
	finally:
		session.close()


def test_editor_hands_back_a_broken_prefix(home):
	env, home = home
	session = editor_session(env, home)
	try:
		assert printed(session, 'mssh \x7f') == 'mssh'
		session.send('\x15')
		assert printed(session, 'mssh x\x7f\x7f\x7fy') == 'mssy'
	finally:
		session.close()


def test_editor_replays_keys_it_does_not_handle(home):
	env, home = home
	session = editor_session(env, home)
	try:
		# up: readline's previous-history
		assert printed(session, 'mssh x' + UP) == 'echo bb'
	finally:
		session.close()


def test_editor_ctrl_c_drops_the_line(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh x')
		time.sleep(0.5)
		session.send('\x03')
		time.sleep(0.3)
		assert printed(session, '') == ''
	finally:
		session.close()


def test_editor_ctrl_r_opens_the_picker(home):
	env, home = home
	session = editor_session(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		session.send('\r')
		time.sleep(0.3)
		assert words(printed(session, '')) == PICKED
	finally:
		session.close()


def test_editor_without_colours_still_edits(home):
	env, home = home
	session = editor_session(env, home, TERM='dumb')
	try:
		session.send('mssh gp')
		time.sleep(0.5)
		session.send('u\r')
		output = session.read_until(b'@@RAN[', 10) + session.read_until(b']@@', 10)
		assert '@@RAN[gpu]@@' in output
		assert '\x1b[38;5;244m' not in output and '\x1b[2m' not in output
	finally:
		session.close()


def test_space_elsewhere_is_a_space(home):
	env, home = home
	session = editor_session(env, home)
	try:
		assert printed(session, 'echo a b\x02\x02 ') == 'echo a  b'
		session.send('\x05\x15')
		assert printed(session, 'é è\x02 ') == 'é  è'
	finally:
		session.close()


# ---------------------------------------------------------------- ble.sh

def test_blesh_suggests_from_the_engine(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		# only the engine knows the command: the shell history is about echo
		assert printed(session, RIGHT) == 'mssh gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_blesh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
	session = blesh_session(home, env, glue_file(home, 'bash'))
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		# the second Ctrl-R of ble.sh's own search finds the older match
		session.send('\x15\x12aa')
		time.sleep(0.5)
		session.send('\x12')
		assert 'echo aa1' in plain(session.read_until(b'aa1', 10))
		session.send('\x07')
	finally:
		session.close()
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_keys.py tests/test_complete_shells.py -q`

Expected: FAIL, e.g. `E assert 'commands for gpu[01-16]' in "mssh gpu[01-16] \r(reverse-i-search)`': mssh gpu[01-16] "` (`7 failed, 29 passed, 15 skipped`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		{
			printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$flags" "$_mssh_complete_before" "$_mssh_complete_after" "$cur"
			fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
		} | @ENGINE@ query 2>/dev/null || :
	) || return 0
	[[ $resp == MSSHC1$'\n'* ]] || return 0
	while IFS= read -r line; do
````

with:

````python
		{
			printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$flags" "$_mssh_complete_before" "$_mssh_complete_after" "$cur"
			fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
		} | _mssh_complete_engine query 2>/dev/null || :
	) || return 0
	[[ $resp == MSSHC1$'\n'* ]] || return 0
	while IFS= read -r line; do
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
}

complete -o default -o bashdefault -F _mssh_complete mssh mssh3 multissh multissh3 multiSSH3 2>/dev/null
'''

ZSH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ zsh: autocomplete for mssh (multiSSH3), protocol MSSHC1
````

with:

````python
}

complete -o default -o bashdefault -F _mssh_complete mssh mssh3 multissh multissh3 multiSSH3 2>/dev/null

# ---- grey suggestions, the Ctrl-R picker and the mssh line editor (SP2) ----

_mssh_complete_engine() {
	@ENGINE@ "$@"
}

_mssh_complete_is_mssh() {
	# whether $1 is an mssh command line: an mssh name, then a space
	[[ $1 =~ ^[[:space:]]*([^[:space:]]*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)[[:space:]] ]]
}

_mssh_complete_request() {
	# print a request with flags $1 for the line $2 (before the cursor) $3 (after it), then the history tail
	printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$1 term=${TERM-}" "$2" "$3" ''
	fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
}

_mssh_complete_prompt() {
	# the prompt the picker and the editor redraw (bash clears the line before a bind -x command):
	# expanded on bash 4.4 and later, else PS1 itself for the engine to expand
	if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
		_mssh_complete_ps1=${PS1@P}
		_mssh_complete_expand=0
	else
		_mssh_complete_ps1=$PS1
		_mssh_complete_expand=1
	fi
}

_mssh_complete_cut() {
	# READLINE_LINE before and after READLINE_POINT, which readline counts in bytes before bash 5
	(( _mssh_complete_bytes )) && local LC_ALL=C
	_mssh_complete_before=${READLINE_LINE:0:READLINE_POINT}
	_mssh_complete_after=${READLINE_LINE:READLINE_POINT}
}

_mssh_complete_set() {
	# READLINE_LINE=$1 with the cursor after its first $2 characters
	local head=${1:0:$2}
	READLINE_LINE=$1
	(( _mssh_complete_bytes )) && local LC_ALL=C
	READLINE_POINT=${#head}
}

_mssh_complete_apply() {
	# apply a pick or edit response ($1): the line, the cursor, and _mssh_complete_action / _keys
	local line text= cursor=
	_mssh_complete_action=
	_mssh_complete_keys=
	[[ $1 == MSSHC1$'\n'* && $1 == *$'\n'E ]] || return 1
	while IFS= read -r line; do
		case ${line:0:2} in
			'L ') cursor=${line:2}; cursor=${cursor%%$'\t'*}; text=${line#*$'\t'} ;;
			'K ') _mssh_complete_action=${line:2}; _mssh_complete_action=${_mssh_complete_action%%$'\t'*}; _mssh_complete_keys=${line#*$'\t'} ;;
		esac
	done <<< "$1"
	[[ $cursor =~ ^[0-9]+$ ]] || return 1
	_mssh_complete_set "$text" "$cursor"
}

_mssh_complete_pick() {
	# the picker for the mssh line in READLINE_LINE; fails when it is unavailable
	local _mssh_complete_before _mssh_complete_after _mssh_complete_ps1 _mssh_complete_expand resp status
	local _mssh_complete_action _mssh_complete_keys
	_mssh_complete_cut
	_mssh_complete_prompt
	resp=$(_mssh_complete_request "pick=1 redraw=1 expand=$_mssh_complete_expand" "$_mssh_complete_before" "$_mssh_complete_after" |
		MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine pick 2>/dev/null)
	status=$?
	(( status == 0 )) && _mssh_complete_apply "$resp"
	(( status <= 1 ))
}

_mssh_complete_ctrl_r() {
	# Ctrl-R (a macro: the hook key of keymap $1, then "\C-x\C-y"): the picker on mssh lines, else
	# what Ctrl-R did before
	local keymap=$1 previous
	bind -m "$keymap" '"\C-x\C-y": ""'
	_mssh_complete_is_mssh "$READLINE_LINE" && _mssh_complete_pick && return 0
	previous=_mssh_complete_previous_${keymap//-/_}
	previous=${!previous-}
	case $previous in
		x:*) eval "${previous#x:}" ;;
		?*)
			# put the previous binding back while it runs (a reverse search repeats with Ctrl-R
			# only when Ctrl-R is bound to it); the next prompt takes Ctrl-R back
			bind -m "$keymap" "$previous"
			bind -m "$keymap" '"\C-x\C-y": "\C-r"'
			_mssh_complete_unarmed="${_mssh_complete_unarmed-} $keymap"
			[[ ${PROMPT_COMMAND-} == *_mssh_complete_rearm\;* ]] || PROMPT_COMMAND="_mssh_complete_rearm;${PROMPT_COMMAND-}"
			;;
	esac
	return 0
}

_mssh_complete_rearm() {
	# PROMPT_COMMAND, once after a Ctrl-R fallback: Ctrl-R opens the picker again
	local status=$? keymap
	for keymap in ${_mssh_complete_unarmed-}; do
		_mssh_complete_arm "$keymap"
	done
	_mssh_complete_unarmed=
	PROMPT_COMMAND=${PROMPT_COMMAND//_mssh_complete_rearm;/}
	return $status
}

_mssh_complete_arm() {
	# bind Ctrl-R in readline keymap $1 to its hook key, then "\C-x\C-y"; each keymap has its own
	# hook key: before bash 5.1 one table holds the bind -x commands of all keymaps
	if [[ $1 == emacs ]]; then
		bind -m emacs '"\C-r": "\C-x\C-o\C-x\C-y"' 2>/dev/null
	else
		bind -m vi-insert '"\C-r": "\C-x\C-q\C-x\C-y"' 2>/dev/null
	fi
}

_mssh_complete_previous() {
	# the Ctrl-R binding of readline keymap $1, as a bind argument or x:<shell command> (bind -x),
	# into _mssh_complete_found; fails when it is unbound or cannot be told (bind -x before bash 4.3)
	local line
	_mssh_complete_found=
	while IFS= read -r line; do
		[[ $line == '"\C-r": "'*'"' ]] || continue
		line=${line#'"\C-r": "'}
		line=${line%'"'}
		line=${line//'\"'/'"'}
		_mssh_complete_found=x:${line//'\\'/'\'}
		return 0
	done < <(bind -m "$1" -X 2>/dev/null || :)
	while IFS= read -r line; do
		if [[ $line == '"\C-r": '* ]]; then
			_mssh_complete_found=$line
			return 0
		fi
	done < <(bind -m "$1" -s 2>/dev/null; bind -m "$1" -p 2>/dev/null || :)
	return 1
}

_mssh_complete_space() {
	# space ("\C-x\C-t\C-x\C-y"): after an mssh name alone, the mssh line editor; else a space
	local resp _mssh_complete_ps1 _mssh_complete_expand _mssh_complete_action _mssh_complete_keys
	local _mssh_complete_before _mssh_complete_after
	local -a expand=()
	bind -m emacs '"\C-x\C-y": ""'
	case $READLINE_LINE in
		mssh|mssh3|multissh|multissh3|multiSSH3)
			if (( READLINE_POINT == ${#READLINE_LINE} )); then
				_mssh_complete_prompt
				(( _mssh_complete_expand )) && expand=(--expand)
				resp=$(fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null |
					MSSH_COMPLETE_PROMPT=$_mssh_complete_ps1 _mssh_complete_engine edit ${expand[@]+"${expand[@]}"} -- "$READLINE_LINE " 2>/dev/null)
				if _mssh_complete_apply "$resp"; then
					case $_mssh_complete_action in
						abandon) READLINE_LINE= READLINE_POINT=0; bind -m emacs '"\C-x\C-y": accept-line' ;;
						pass) bind -m emacs "\"\\C-x\\C-y\": \"$_mssh_complete_keys\"" ;;
					esac
					return 0
				fi
			fi
			;;
	esac
	if [[ $_mssh_complete_space_previous == magic-space ]]; then
		bind -m emacs '"\C-x\C-y": magic-space'
		return 0
	fi
	_mssh_complete_cut
	READLINE_LINE="$_mssh_complete_before $_mssh_complete_after"
	(( READLINE_POINT += 1 ))
}

if [[ -n ${BLE_VERSION-} ]]; then
	_mssh_complete_bytes=0

	_mssh_complete_ble_call() {
		# run a binding the way ble-bind -P printed it: -m KEYMAP -f|-x|-c KEY COMMAND
		case $3 in
			-f) builtin eval -- "ble/widget/$5" ;;
			-x) ble/widget/.EDIT_COMMAND "$5" ;;
			-c) ble/widget/.SHELL_COMMAND "$5" ;;
		esac
	}

	function ble/widget/mssh-complete/ctrl-r {
		# Ctrl-R: the picker on mssh lines, else the widget Ctrl-R had
		if _mssh_complete_is_mssh "$_ble_edit_str" && ble/widget/.EDIT_COMMAND _mssh_complete_pick; then
			return 0
		fi
		local previous=_mssh_complete_previous_$_ble_decode_keymap
		[[ -n ${!previous-} ]] && builtin eval -- "_mssh_complete_ble_call ${!previous}"
		return 0
	}

	_mssh_complete_ble_bind() {
		# take Ctrl-R in ble.sh keymap $1 when its binding is a widget or a command
		local line
		while IFS= read -r line; do
			case $line in
				*' -f C-r '*|*' -x C-r '*|*' -c C-r '*)
					[[ $line == *mssh-complete/ctrl-r* ]] && return 0
					printf -v "_mssh_complete_previous_$1" '%s' "${line#ble-bind }"
					ble-bind -m "$1" -f C-r mssh-complete/ctrl-r
					return 0
					;;
			esac
		done < <(ble-bind -m "$1" -P 2>/dev/null || :)
	}
	blehook/eval-after-load keymap_emacs '_mssh_complete_ble_bind emacs'
	blehook/eval-after-load keymap_vi '_mssh_complete_ble_bind vi_imap'

	_mssh_complete_ble_source() {
		# define ble.sh's mssh suggestion source and put it first
		declare -F ble/complete/auto-complete/enter >/dev/null 2>&1 || return 0
		function ble/complete/auto-complete/source:mssh {
			# grey text for mssh lines: 1 lets the next source try, 148 when typing interrupted the query
			((_ble_edit_ind == ${#_ble_edit_str})) || return 1
			_mssh_complete_is_mssh "$_ble_edit_str" || return 1
			local request=$_ble_base_run/$$.mssh-complete.request answer=$_ble_base_run/$$.mssh-complete.answer line text= status
			_mssh_complete_request 'ghost=1 ble=1 nul=0' "$_ble_edit_str" '' > "$request" 2>/dev/null || return 1
			ble/util/conditional-sync '_mssh_complete_engine query < "$request" > "$answer" 2>/dev/null' '! ble/decode/has-input' 20 "timeout=${MSSH_COMPLETE_GHOST_TIMEOUT:-300}"
			status=$?
			((status == 148)) && return 148
			((status == 0)) || return 1
			while IFS= read -r line; do
				[[ $line == 'G '* ]] && text=${line#*$'\t'}
			done < "$answer"
			[[ -n $text ]] || return 1
			ble/complete/auto-complete/enter h 0 "$text" '' "$_ble_edit_str$text"
		}
		[[ " ${_ble_complete_auto_source[*]-} " == *' mssh '* ]] || _ble_complete_auto_source=(mssh ${_ble_complete_auto_source[@]+"${_ble_complete_auto_source[@]}"})
	}
	blehook/eval-after-load complete _mssh_complete_ble_source
elif [[ $- == *i* ]]; then
	# readline counts READLINE_POINT in bytes before bash 5
	_mssh_complete_bytes=0
	(( BASH_VERSINFO[0] < 5 )) && _mssh_complete_bytes=1

	_mssh_complete_keys() {
		# PROMPT_COMMAND, once, at the first prompt: take the keys. Not while the rc file loads: there
		# stderr is often /dev/null, and readline starting then would lose its terminal setup
		local status=$? keymap previous
		PROMPT_COMMAND=${PROMPT_COMMAND//_mssh_complete_keys;/}
		[[ -o emacs || -o vi ]] || return $status
		for keymap in emacs vi-insert; do
			# take Ctrl-R only when its binding can be called back (and is not already ours)
			if _mssh_complete_previous "$keymap" && [[ $_mssh_complete_found != *'\C-x\C-y"' ]]; then
				printf -v "_mssh_complete_previous_${keymap//-/_}" '%s' "$_mssh_complete_found"
				if [[ $keymap == emacs ]]; then
					bind -m emacs -x '"\C-x\C-o": _mssh_complete_ctrl_r emacs'
				else
					bind -m vi-insert -x '"\C-x\C-q": _mssh_complete_ctrl_r vi-insert'
				fi
				_mssh_complete_arm "$keymap"
			fi
		done
		if [[ ${MSSH_COMPLETE_EDITOR-} == 1 ]]; then
			# the mssh line editor, entered with a space after an mssh name; only over a plain space key
			previous=$(bind -m emacs -p 2>/dev/null | grep -F '" ": ' || :)
			_mssh_complete_space_previous=${previous#'" ": '}
			case $_mssh_complete_space_previous in
				self-insert|magic-space)
					bind -m emacs -x '"\C-x\C-t": _mssh_complete_space'
					bind -m emacs '" ": "\C-x\C-t\C-x\C-y"'
					;;
			esac
		fi
		return $status
	}
	[[ ${PROMPT_COMMAND-} == *_mssh_complete_keys\;* ]] || PROMPT_COMMAND="_mssh_complete_keys;${PROMPT_COMMAND-}"
fi
'''

ZSH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ zsh: autocomplete for mssh (multiSSH3), protocol MSSHC1
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_keys.py tests/test_complete_shells.py -q`

Expected: `36 passed, 15 skipped` (the skipped tests need zsh, fish or ble.sh, which are not installed here; the Docker matrix runs them)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `794 passed, 23 skipped`

- [ ] **Step 6: Run the matrix**

Run: `tests/shells/run_matrix.sh`

Expected (one line per image; CentOS 7 has no zsh or fish, legacy skips one Python 3.7+ check):

````
modern (requires bash,zsh,fish,blesh)
297 passed
legacy (requires bash,zsh,fish,blesh)
296 passed, 1 skipped
centos7 (requires bash,blesh)
283 passed, 14 skipped
````

- [ ] **Step 7: Commit**

````bash
git add tests/complete_shell_harness.py tests/test_complete_shells.py tests/test_complete_keys.py mssh_complete.py
git commit -m "feat: Ctrl-R picker, mssh line editor and ble.sh suggestions in bash

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 9: zsh glue: grey suggestions and Ctrl-R

**Files:**
- Modify: `mssh_complete.py` (`ZSH_GLUE`)
- Modify: `tests/shells/Dockerfile.modern`, `tests/shells/Dockerfile.legacy` (append zsh-autosuggestions)
- Modify: `tests/shells/run_matrix.sh`
- Modify: `tests/test_complete_keys.py` (append)

**Interfaces:**
- Consumes: Task 7: `pick`; Task 2: `ghost=1` queries; Task 8: `zsh_session(..., pre, extra)`
- Produces: In `ZSH_GLUE`: `_mssh_complete_engine`, `_mssh_complete_is_mssh`, `_mssh_complete_request`, `_mssh_complete_ctrl_r` widget, `_mssh_complete_take_ctrl_r`, `_zsh_autosuggest_strategy_mssh`, the own grey-text widgets (`_mssh_complete_ghost_*`, `_mssh_complete_accept`), `_mssh_complete_setup` (precmd, once). `run_matrix.sh` honours `MSSH_MATRIX_TESTS` and requires `zas` in the modern and legacy images.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/shells/Dockerfile.modern` (the text starts with the blank lines that separate it from what is there):

````dockerfile
# zsh-autosuggestions, pinned: the grey-text tests also run with it
ADD --checksum=sha256:0df7affff21cd87ed298e6a3970ed08a1dd66a6efa676454ee5b091ad503badf \
    https://github.com/zsh-users/zsh-autosuggestions/archive/refs/tags/v0.7.1.tar.gz /tmp/zas.tar.gz
RUN mkdir -p /opt/zsh-autosuggestions && tar -xzf /tmp/zas.tar.gz -C /opt/zsh-autosuggestions --strip-components=1 && rm /tmp/zas.tar.gz
````

Append to the end of `tests/shells/Dockerfile.legacy` (the text starts with the blank lines that separate it from what is there):

````dockerfile
# zsh-autosuggestions, pinned: the grey-text tests also run with it
ADD --checksum=sha256:0df7affff21cd87ed298e6a3970ed08a1dd66a6efa676454ee5b091ad503badf \
    https://github.com/zsh-users/zsh-autosuggestions/archive/refs/tags/v0.7.1.tar.gz /tmp/zas.tar.gz
RUN mkdir -p /opt/zsh-autosuggestions && tar -xzf /tmp/zas.tar.gz -C /opt/zsh-autosuggestions --strip-components=1 && rm /tmp/zas.tar.gz
````

In `tests/shells/run_matrix.sh`, replace this text (it occurs exactly once):

````bash
#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, legacy and centos7 images.
# Usage: tests/shells/run_matrix.sh [modern] [legacy] [centos7]   (default: all three)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
````

with:

````bash
#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, legacy and centos7 images.
# Usage: tests/shells/run_matrix.sh [modern] [legacy] [centos7]   (default: all three)
# MSSH_MATRIX_TESTS picks the pytest arguments (default: tests/test_complete_*.py)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
````

In `tests/shells/run_matrix.sh`, replace this text (it occurs exactly once):

````bash
for name in "${images[@]}"; do
	case $name in
		centos7) required=bash,blesh ;;
		modern|legacy) required=bash,zsh,fish,blesh ;;
		*) echo "unknown image: $name" >&2; exit 2 ;;
	esac
	echo "=== $name (requires $required)"
	docker build -q -t "mssh-shell-test-$name" -f "$here/Dockerfile.$name" "$here" >/dev/null
	# the repository is read-only inside: no bytecode, no pytest cache; HOME is a fresh directory
	docker run --rm -v "$repo":/repo:ro -w /repo -e MSSH_REQUIRE_SHELLS="$required" -e PYTHONDONTWRITEBYTECODE=1 \
		"mssh-shell-test-$name" sh -c 'export HOME=$(mktemp -d); python3 -m pytest -q -p no:cacheprovider tests/test_complete_*.py' \
		|| status=1
done
exit $status
````

with:

````bash
for name in "${images[@]}"; do
	case $name in
		centos7) required=bash,blesh ;;
		modern|legacy) required=bash,zsh,fish,blesh,zas ;;
		*) echo "unknown image: $name" >&2; exit 2 ;;
	esac
	echo "=== $name (requires $required)"
	docker build -q -t "mssh-shell-test-$name" -f "$here/Dockerfile.$name" "$here" >/dev/null
	# the repository is read-only inside: no bytecode, no pytest cache; HOME is a fresh directory
	docker run --rm -v "$repo":/repo:ro -w /repo -e MSSH_REQUIRE_SHELLS="$required" -e PYTHONDONTWRITEBYTECODE=1 \
		-e MSSH_MATRIX_TESTS="${MSSH_MATRIX_TESTS:-tests/test_complete_*.py}" \
		"mssh-shell-test-$name" sh -c 'export HOME=$(mktemp -d); python3 -m pytest -q -p no:cacheprovider $MSSH_MATRIX_TESTS' \
		|| status=1
done
exit $status
````

Append to the end of `tests/test_complete_keys.py` (the text starts with the blank lines that separate it from what is there):

````python


# ---------------------------------------------------------------- zsh

ZAS = '/opt/zsh-autosuggestions/zsh-autosuggestions.zsh'


def zsh_with(env, home, zas=False, after=False):
	pre = ''
	if zas:
		import os
		if not os.path.isfile(ZAS):
			if 'zas' in env.get('MSSH_REQUIRE_SHELLS', '') or 'zas' in os.environ.get('MSSH_REQUIRE_SHELLS', ''):
				pytest.fail('zsh-autosuggestions is required here but not at ' + ZAS)
			pytest.skip('zsh-autosuggestions is not installed at ' + ZAS)
		pre = 'source ' + ZAS
	(home / '.zsh_history').write_text(SHELL_HISTORY)
	history = 'HISTFILE=~/.zsh_history; SAVEHIST=100; HISTSIZE=100; fc -R'
	return zsh_session(home, dict(env, HISTFILE=str(home / '.zsh_history')), glue_file(home, 'zsh'),
		pre=history if after else pre + '\n' + history, extra=pre if after else '')


@pytest.mark.parametrize('zas, after', [(False, False), (True, False), (True, True)], ids=['own', 'zsh-autosuggestions', 'zsh-autosuggestions-loaded-after'])
def test_zsh_suggests_and_right_arrow_accepts(home, zas, after):
	env, home = home
	session = zsh_with(env, home, zas, after)
	try:
		session.send('mssh gp')
		session.read_until(b'nvidia-smi', 10)
		# zsh escapes the glob characters
		assert words(printed(session, RIGHT)) == ['mssh', 'gpu[01-16]', 'nvidia-smi']
	finally:
		session.close()


def test_zsh_ctrl_r_opens_the_picker_and_keeps_isearch_elsewhere(home):
	env, home = home
	session = zsh_with(env, home)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15\x12aa\x12\r')
		assert re.search(r'[\r\n]aa1\r\n', session.read_until(b'aa1\r\n', 10))
	finally:
		session.close()
````

- [ ] **Step 2: Run them to verify they fail**

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k zsh' tests/shells/run_matrix.sh modern legacy`

Expected: FAIL, e.g. `E AssertionError: assert ['mssh', 'gp'] == ['mssh', 'gpu... 'nvidia-smi']` (`4 failed, 17 deselected`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		{
			print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$flags"$'\0'"$before"$'\0'"$after"$'\0'"$PREFIX"$'\0'
			fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
		} | @ENGINE@ query 2>/dev/null
	)
	(( end = EPOCHREALTIME + ${MSSH_COMPLETE_TIMEOUT:-0.3} ))
	resp=
````

with:

````python
		{
			print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$flags"$'\0'"$before"$'\0'"$after"$'\0'"$PREFIX"$'\0'
			fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
		} | _mssh_complete_engine query 2>/dev/null
	)
	(( end = EPOCHREALTIME + ${MSSH_COMPLETE_TIMEOUT:-0.3} ))
	resp=
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
}

(( $+functions[compdef] )) && compdef _mssh mssh mssh3 multissh multissh3 multiSSH3
'''

FISH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish: autocomplete for mssh (multiSSH3), protocol MSSHC1
````

with:

````python
}

(( $+functions[compdef] )) && compdef _mssh mssh mssh3 multissh multissh3 multiSSH3

# ---- grey suggestions and the Ctrl-R picker (SP2) ----

_mssh_complete_engine() {
	@ENGINE@ "$@"
}

_mssh_complete_is_mssh() {
	# whether $1 is an mssh command line: an mssh name, then a space
	emulate -L zsh
	local MATCH MBEGIN MEND
	local -a match mbegin mend
	[[ $1 =~ '^[[:space:]]*([^[:space:]]*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)[[:space:]]' ]]
}

_mssh_complete_request() {
	# print a request with flags $1 for the line $2 (before the cursor) $3 (after it), then the history tail
	print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$1 term=$TERM"$'\0'"$2"$'\0'"$3"$'\0'$'\0'
	fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
}

_mssh_complete_ctrl_r() {
	# Ctrl-R: the picker on mssh lines, else the widget Ctrl-R had
	emulate -L zsh
	local resp line text= cursor= st
	if _mssh_complete_is_mssh "$BUFFER"; then
		resp=$(_mssh_complete_request 'pick=1 nul=0' "$LBUFFER" "$RBUFFER" | _mssh_complete_engine pick 2>/dev/null)
		st=$?
		if (( st == 0 )) && [[ $resp == MSSHC1$'\n'*$'\n'E ]]; then
			for line in "${(@f)resp}"; do
				if [[ $line == 'L '* ]]; then
					cursor=${${line#L }%%$'\t'*}
					text=${line#*$'\t'}
				fi
			done
			if [[ $cursor == <-> ]]; then
				BUFFER=$text
				CURSOR=$cursor
			fi
		fi
		zle reset-prompt
		(( st <= 1 )) && return 0
	fi
	[[ -n $_mssh_complete_previous ]] && zle $_mssh_complete_previous
	return 0
}

_mssh_complete_take_ctrl_r() {
	# bind Ctrl-R to the picker, keeping the widget it had for other lines
	emulate -L zsh
	local -a binding
	binding=(${(z)"$(bindkey '^R')"})
	[[ $binding[2] == _mssh_complete_ctrl_r ]] && return 0
	[[ -n $binding[2] && $binding[2] != undefined-key ]] || return 0
	typeset -g _mssh_complete_previous=$binding[2]
	zle -N _mssh_complete_ctrl_r
	bindkey '^R' _mssh_complete_ctrl_r
	# an incremental search repeats on Ctrl-R only when Ctrl-R is bound to it
	if [[ $_mssh_complete_previous == history-incremental-*search-backward ]] && [[ $(bindkey -M isearch '^R' 2>/dev/null) != *search* ]]; then
		bindkey -M isearch '^R' $_mssh_complete_previous 2>/dev/null
	fi
}

_zsh_autosuggest_strategy_mssh() {
	# zsh-autosuggestions strategy: the engine's grey text for mssh lines, nothing for others
	emulate -L zsh
	zmodload zsh/zselect zsh/system zsh/datetime 2>/dev/null || return 0
	_mssh_complete_is_mssh "$1" || return 0
	local fd resp= chunk line limit=${MSSH_COMPLETE_TIMEOUT:-0.3}
	local -F end
	local -i remaining
	# synchronous zsh-autosuggestions waits for the strategy while the operator types
	(( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || limit=0.05
	exec {fd}< <(_mssh_complete_request 'ghost=1 zas=1 nul=0' "$1" '' | _mssh_complete_engine query 2>/dev/null)
	(( end = EPOCHREALTIME + limit ))
	while true; do
		(( remaining = (end - EPOCHREALTIME) * 100 ))
		(( remaining > 0 )) || break
		zselect -t $remaining -r $fd || break
		sysread -i $fd chunk || break
		resp+=$chunk
	done
	exec {fd}<&-
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		[[ $line == 'G '* ]] && typeset -g suggestion="$1${line#*$'\t'}"
	done
	return 0
}

_mssh_complete_ghost_clear() {
	# drop the grey text (inside a widget)
	[[ -n $_mssh_complete_shown ]] || return 0
	POSTDISPLAY=
	region_highlight=("${(@)region_highlight:#$_mssh_complete_highlight}")
	_mssh_complete_shown=
	_mssh_complete_highlight=
}

_mssh_complete_ghost_show() {
	# show $1 as grey text after the buffer (inside a widget)
	_mssh_complete_ghost_clear
	[[ -n $1 ]] || return 0
	POSTDISPLAY=$1
	_mssh_complete_shown=$1
	_mssh_complete_highlight="$#BUFFER $(( $#BUFFER + $#POSTDISPLAY )) $_mssh_complete_style"
	region_highlight+=("$_mssh_complete_highlight")
}

_mssh_complete_ghost_cancel() {
	# forget the pending query
	[[ -n $_mssh_complete_fd ]] || return 0
	zle -F $_mssh_complete_fd 2>/dev/null
	exec {_mssh_complete_fd}<&- 2>/dev/null
	_mssh_complete_fd=
}

_mssh_complete_ghost_ready() {
	# zle -F handler: the engine answered the query for the buffer in _mssh_complete_asked
	emulate -L zsh
	local fd=$1 resp= chunk line text=
	while sysread -i $fd chunk 2>/dev/null; do
		resp+=$chunk
	done
	zle -F $fd
	exec {fd}<&-
	_mssh_complete_fd=
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n' ]] || return 0
	for line in "${(@f)resp}"; do
		[[ $line == 'G '* ]] && text=${line#*$'\t'}
	done
	[[ -n $text ]] && zle _mssh_complete_ghost_answer -- "$text"
	return 0
}

_mssh_complete_ghost_answer() {
	# widget: show the answer if the buffer is still the one asked about
	emulate -L zsh
	[[ $BUFFER == "$_mssh_complete_asked" ]] && (( CURSOR == $#BUFFER )) || return 0
	_mssh_complete_ghost_show "$1"
	zle -R
}

_mssh_complete_ghost_redraw() {
	# line-pre-redraw hook: keep the grey text in step with the buffer
	emulate -L zsh
	local last=$_mssh_complete_last full
	if [[ $BUFFER == "$last" ]]; then
		(( CURSOR == $#BUFFER )) || _mssh_complete_ghost_clear
		return 0
	fi
	_mssh_complete_last=$BUFFER
	if [[ -n $_mssh_complete_shown ]] && (( CURSOR == $#BUFFER )); then
		full=$last$_mssh_complete_shown
		if [[ $BUFFER == "$last"?* && $full == "$BUFFER"?* ]]; then
			# typed (or took) the next characters of the grey text: show the rest without a new query
			_mssh_complete_ghost_show "${full#"$BUFFER"}"
			return 0
		fi
	fi
	_mssh_complete_ghost_clear
	_mssh_complete_ghost_cancel
	(( CURSOR == $#BUFFER )) && _mssh_complete_is_mssh "$BUFFER" || return 0
	_mssh_complete_asked=$BUFFER
	exec {_mssh_complete_fd}< <(_mssh_complete_request 'ghost=1 nul=0' "$BUFFER" '' | _mssh_complete_engine query 2>/dev/null)
	zle -F $_mssh_complete_fd _mssh_complete_ghost_ready
}

_mssh_complete_ghost_finish() {
	# line-finish hook: no grey text on a line that was accepted
	emulate -L zsh
	_mssh_complete_ghost_cancel
	_mssh_complete_ghost_clear
	_mssh_complete_last=
}

_mssh_complete_accept() {
	# forward-char, end-of-line, forward-word and their vi forms: with grey text showing at the
	# end of the line, take all of it (one word for the word widgets); else do the usual
	emulate -L zsh
	setopt extended_glob
	local take
	if [[ -n $_mssh_complete_shown ]] && (( CURSOR == $#BUFFER )); then
		take=$_mssh_complete_shown
		[[ $WIDGET == *forward-word ]] && take=${(M)take##[[:space:]]#[^[:space:]]##}
		BUFFER+=${take:-$_mssh_complete_shown}
		CURSOR=$#BUFFER
		return 0
	fi
	zle _mssh_complete_orig_$WIDGET -- "$@"
}

_mssh_complete_ghost_setup() {
	# grey text with own widgets (zsh 5.3 and later, a terminal with colours)
	emulate -L zsh
	autoload -Uz is-at-least add-zle-hook-widget
	is-at-least 5.3 || return 0
	[[ -n $TERM && $TERM != dumb ]] || return 0
	zmodload zsh/zleparameter zsh/system 2>/dev/null || return 0
	local widget key
	typeset -g _mssh_complete_fd= _mssh_complete_asked= _mssh_complete_last= _mssh_complete_shown= _mssh_complete_highlight=
	typeset -g _mssh_complete_style=fg=8
	[[ $TERM == *256col* ]] && _mssh_complete_style=fg=244
	zle -N _mssh_complete_ghost_answer
	zle -N _mssh_complete_ghost_redraw
	zle -N _mssh_complete_ghost_finish
	add-zle-hook-widget line-pre-redraw _mssh_complete_ghost_redraw
	add-zle-hook-widget line-finish _mssh_complete_ghost_finish
	for widget in forward-char vi-forward-char end-of-line vi-end-of-line forward-word emacs-forward-word vi-forward-word; do
		[[ -n ${widgets[$widget]} && ${widgets[$widget]} != user:_mssh_complete_accept ]] || continue
		zle -A $widget _mssh_complete_orig_$widget
		zle -N $widget _mssh_complete_accept
	done
	# Ctrl-Right and Alt-Right take a word, unless they are bound already
	for key in '^[[1;5C' '^[[1;3C'; do
		[[ $(bindkey "$key" 2>/dev/null) == *undefined-key* ]] && bindkey "$key" forward-word
	done
}

_mssh_complete_setup() {
	# precmd, once, at the first prompt (plugins loaded after the mssh block are there by then):
	# Ctrl-R, and grey text through zsh-autosuggestions when it is loaded, else with own widgets
	add-zsh-hook -d precmd _mssh_complete_setup
	_mssh_complete_take_ctrl_r
	if (( ${+functions[_zsh_autosuggest_start]} )); then
		(( ${${=ZSH_AUTOSUGGEST_STRATEGY}[(Ie)mssh]} )) || ZSH_AUTOSUGGEST_STRATEGY=(mssh ${=ZSH_AUTOSUGGEST_STRATEGY:-history})
	else
		_mssh_complete_ghost_setup
	fi
}

if [[ -o interactive ]]; then
	autoload -Uz add-zsh-hook
	add-zsh-hook precmd _mssh_complete_setup
fi
'''

FISH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish: autocomplete for mssh (multiSSH3), protocol MSSHC1
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `MSSH_MATRIX_TESTS='tests/test_complete_keys.py -k zsh' tests/shells/run_matrix.sh modern legacy`

Expected:

````
=== modern (requires bash,zsh,fish,blesh,zas)
4 passed, 17 deselected in 3.68s
=== legacy (requires bash,zsh,fish,blesh,zas)
4 passed, 17 deselected in 3.50s
````

- [ ] **Step 5: Run the matrix**

Run: `tests/shells/run_matrix.sh`

Expected (one line per image; CentOS 7 has no zsh or fish, legacy skips one Python 3.7+ check):

````
modern (requires bash,zsh,fish,blesh,zas)
301 passed
legacy (requires bash,zsh,fish,blesh,zas)
300 passed, 1 skipped
centos7 (requires bash,blesh)
283 passed, 18 skipped
````

- [ ] **Step 6: Commit**

````bash
git add tests/shells/Dockerfile.modern tests/shells/Dockerfile.legacy tests/shells/run_matrix.sh tests/test_complete_keys.py mssh_complete.py
git commit -m "feat: grey suggestions and Ctrl-R picker in zsh

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 10: fish Ctrl-R and installation

**Files:**
- Modify: `mssh_complete.py` (`FISH_KEYS_GLUE`, `render_glue`, `_add_rc_block`, `_paths`, `install`, `uninstall`, `completion_command`)
- Modify: `tests/test_complete_shells.py`
- Modify: `tests/test_complete_keys.py` (append)

**Interfaces:**
- Consumes: Task 7: `pick`; Task 8: `fish_session`
- Produces: `FISH_KEYS_GLUE` (rendered with `render_glue('fish-keys')`; takes Ctrl-R at the first prompt); `install(shell, home=None, environ=None, command=None, editor=False)` writes `~/.config/fish/conf.d/mssh-complete.fish` for fish and `export MSSH_COMPLETE_EDITOR=1` into the bash rc block when `editor`, replacing a block that differs; `uninstall` removes the conf.d file; `mssh --completion install bash editor`; `mssh --completion fish` prints both fish scripts.

- [ ] **Step 1: Write the failing tests**

In `tests/test_complete_shells.py`, replace this text (it occurs exactly once):

````python
	command = ['/nonexistent/engine'] if damage == 'no engine' else ENGINE
	code, messages = mc.install(shell, home=str(home), environ=env, command=command)
	assert code == 0, messages
	glues = [line.split(' ', 1)[1] for line in messages if line.startswith('wrote ')]
	for glue in glues:
		if damage == 'deleted':
			os.unlink(glue)
````

with:

````python
	command = ['/nonexistent/engine'] if damage == 'no engine' else ENGINE
	code, messages = mc.install(shell, home=str(home), environ=env, command=command)
	assert code == 0, messages
	# fish sources its conf.d file itself, as bash and zsh source the rc block: mssh writes both whole
	glues = [line.split(' ', 1)[1] for line in messages if line.startswith('wrote ') and '/conf.d/' not in line]
	for glue in glues:
		if damage == 'deleted':
			os.unlink(glue)
````

In `tests/test_complete_shells.py`, replace this text (it occurs exactly once):

````python
			with open(glue, 'a') as f:
				f.write('\n((( broken syntax\n')
	assert _interactive_output(path, env, home) == baseline


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
````

with:

````python
			with open(glue, 'a') as f:
				f.write('\n((( broken syntax\n')
	assert _interactive_output(path, env, home) == baseline


def test_new_bash_with_the_editor_stays_silent(tmp_path):
	path = require_shell('bash')
	env, home = make_home(tmp_path)
	baseline = _interactive_output(path, env, home)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)[0] == 0
	assert _interactive_output(path, env, home) == baseline


def test_install_turns_the_editor_on_and_off(tmp_path):
	env, home = make_home(tmp_path)
	(home / '.bashrc').write_text('alias ll="ls -l"\n')
	mc.install('bash', home=str(home), environ=env, editor=True)
	assert 'export MSSH_COMPLETE_EDITOR=1\n' in (home / '.bashrc').read_text()
	code, messages = mc.install('bash', home=str(home), environ=env)
	text = (home / '.bashrc').read_text()
	assert 'MSSH_COMPLETE_EDITOR' not in text and text.count('# >>> mssh completion >>>') == 1
	assert messages[-1] == 'updated the mssh block in ' + str(home / '.bashrc')
	assert mc.install('bash', home=str(home), environ=env)[1][-1] == '{} already loads it'.format(home / '.bashrc')


def test_completion_command_takes_the_editor_word(monkeypatch):
	calls = []
	monkeypatch.setattr(mc, 'install', lambda shell, editor=False: (calls.append((shell, editor)), (0, []))[1])
	assert mc.completion_command(['install', 'bash', 'editor']) == 0
	assert mc.completion_command(['install', 'bash', '--editor']) == 0
	assert mc.completion_command(['install', 'zsh', 'editor']) == 2
	assert calls == [('bash', True), ('bash', True)]


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
````

Append to the end of `tests/test_complete_keys.py` (the text starts with the blank lines that separate it from what is there):

````python


# ---------------------------------------------------------------- fish

def test_fish_ctrl_r_opens_the_picker_and_keeps_the_previous_binding(home):
	env, home = home
	pre = "bind \\cr 'commandline -r FISHPREV'"
	session = fish_session(home, env, mc.render_glue('fish-keys', ENGINE), pre=pre)
	try:
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		assert words(printed(session, '\r')) == PICKED
		session.send('\x15')
		assert printed(session, 'ls\x12') == 'FISHPREV'
	finally:
		session.close()
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_shells.py tests/test_complete_keys.py -q`

Expected: FAIL, e.g. `E TypeError: install() got an unexpected keyword argument 'editor'` (`4 failed, 36 passed, 19 skipped`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
end
'''

_GLUES = {'bash': BASH_GLUE, 'zsh': ZSH_GLUE, 'fish': FISH_GLUE}

def engine_command():
	'''How the glue runs the engine: mssh-complete if it is on PATH, else this file with this python.'''
````

with:

````python
end
'''

FISH_KEYS_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish keys: Ctrl-R picker for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it defines functions; Ctrl-R is taken at the first prompt.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: take nothing
	case '*'
		if not set -q __mssh_complete_keys
			set -g __mssh_complete_keys 1
			function __mssh_complete_is_mssh
				string match -qr '^\s*(\S*/)?(mssh|mssh3|multissh|multissh3|multiSSH3)\s' -- "$argv[1]"
			end
			function __mssh_complete_ctrl_r --argument-names mode
				# Ctrl-R: the picker on mssh lines, else what Ctrl-R did before in this bind mode
				set -l full (string join \n -- (commandline))
				if __mssh_complete_is_mssh "$full"
					set -l before (string join \n -- (commandline -c))
					set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
					set -l keep 1000
					set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
					set -l lines (begin
						command printf '%s\0' MSSHC1 fish $FISH_VERSION "pick=1 nul=0 term=$TERM" "$before" "$after" ''
						history -n $keep 2>/dev/null
					end | @ENGINE@ pick 2>/dev/null)
					set -l st $status
					if test $st -eq 0; and test (count $lines) -ge 3; and test "$lines[1]" = MSSHC1; and test "$lines[-1]" = E
						for line in $lines[2..-2]
							if string match -qr '^L \d+\t' -- $line
								commandline -r -- (string replace -r '^L \d+\t' '' -- $line)
								commandline -C -- (string replace -r '^L (\d+)\t.*' '$1' -- $line)
							end
						end
					end
					commandline -f repaint
					test $st -le 1; and return
				end
				set -l previous __mssh_complete_previous_$mode
				for command in $$previous
					if contains -- $command (bind --function-names)
						commandline -f $command
					else
						eval $command
					end
				end
			end
			function __mssh_complete_take_ctrl_r --on-event fish_prompt
				# at the first prompt, when the key bindings are set up: record Ctrl-R and take it
				functions -e __mssh_complete_take_ctrl_r
				for mode in default insert
					set -l line (bind -M $mode \cr 2>/dev/null)
					test (count $line) -ge 1; or continue
					string match -q '*__mssh_complete_ctrl_r*' -- "$line[-1]"; and continue
					eval "set -g __mssh_complete_words -- $line[-1]"
					set -l words $__mssh_complete_words[2..-1]
					set -e __mssh_complete_words
					while set -q words[1]; and string match -q -- '-*' $words[1]
						contains -- $words[1] -M --mode -m --sets-mode; and set -e words[1]
						set -e words[1]
					end
					set -e words[1]
					set -q words[1]; or continue
					set -g __mssh_complete_previous_$mode $words
					bind -M $mode \cr "__mssh_complete_ctrl_r $mode"
				end
			end
		end
end
'''

_GLUES = {'bash': BASH_GLUE, 'zsh': ZSH_GLUE, 'fish': FISH_GLUE, 'fish-keys': FISH_KEYS_GLUE}

def engine_command():
	'''How the glue runs the engine: mssh-complete if it is on PATH, else this file with this python.'''
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	if shell not in _GLUES:
		raise ValueError('unsupported shell {!r}, use one of {}'.format(shell, ', '.join(SHELLS)))
	command = engine_command() if command is None else command
	quote = _fish_quote if shell == 'fish' else shlex.quote
	return _GLUES[shell].replace('@VERSION@', version).replace('@ENGINE@', ' '.join(quote(word) for word in command))

#%% ------------ Install ----------------
````

with:

````python
	if shell not in _GLUES:
		raise ValueError('unsupported shell {!r}, use one of {}'.format(shell, ', '.join(SHELLS)))
	command = engine_command() if command is None else command
	quote = _fish_quote if shell.startswith('fish') else shlex.quote
	return _GLUES[shell].replace('@VERSION@', version).replace('@ENGINE@', ' '.join(quote(word) for word in command))

#%% ------------ Install ----------------
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	messages.append('wrote ' + path)
	return True

def _add_rc_block(rc, line, messages):
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape') as f:
			text = f.read()
	except FileNotFoundError:
		text = None
	if text is not None and RC_END in text and (RC_BEGIN in text or RC_BEGIN_CREATED in text):
		messages.append('{} already loads it'.format(rc))
		return
	block = '\n{}\n{}\n{}\n'.format(RC_BEGIN if text is not None else RC_BEGIN_CREATED, line, RC_END)
	with open(rc, 'a', encoding='utf-8', errors='surrogateescape') as f:
		f.write(block)
	messages.append('added a block loading it to ' + rc)
````

with:

````python
	messages.append('wrote ' + path)
	return True

def _add_rc_block(rc, body, messages):
	'''Append a marked block holding body to rc; a block with other lines (editor on or off) is replaced.'''
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			text = f.read()
	except FileNotFoundError:
		text = None
	if text is not None:
		for begin in (RC_BEGIN, RC_BEGIN_CREATED):
			start = text.find('\n' + begin + '\n')
			end = text.find('\n' + RC_END + '\n', start + 1)
			if start < 0 or end < 0:
				continue
			if text[start + len(begin) + 2:end + 1] == body + '\n':
				messages.append('{} already loads it'.format(rc))
				return
			text = text[:start + len(begin) + 2] + body + text[end:]
			with open(rc, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
				f.write(text)
			messages.append('updated the mssh block in ' + rc)
			return
	block = '\n{}\n{}\n{}\n'.format(RC_BEGIN if text is not None else RC_BEGIN_CREATED, body, RC_END)
	with open(rc, 'a', encoding='utf-8', errors='surrogateescape') as f:
		f.write(block)
	messages.append('added a block loading it to ' + rc)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	data = environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share')
	config = environ.get('XDG_CONFIG_HOME') or os.path.join(home, '.config')
	if shell == 'fish':
		return {'files': [os.path.join(config, 'fish', 'completions', name + '.fish') for name in MSSH_NAMES]}
	if shell == 'zsh':
		return {'files': [os.path.join(data, 'multiSSH3', 'completion.zsh')], 'rc': os.path.join(home, '.zshrc')}
	# always from ~/.bashrc: bash-completion's per-user directory only loads where bash-completion
	# runs, which an installed package does not guarantee (stock Debian root shells do not load it)
	return {'files': [os.path.join(data, 'multiSSH3', 'completion.bash')], 'rc': os.path.join(home, '.bashrc')}

def install(shell, home=None, environ=None, command=None):
	'''
	Install the glue for shell for the current user. Never overwrites a file mssh did not write.

	Returns:
		tuple: (exit code, list of messages saying what was done)
````

with:

````python
	data = environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share')
	config = environ.get('XDG_CONFIG_HOME') or os.path.join(home, '.config')
	if shell == 'fish':
		# completions load lazily; the Ctrl-R glue must load at startup: conf.d (written whole, like the rc blocks)
		return {'files': [os.path.join(config, 'fish', 'completions', name + '.fish') for name in MSSH_NAMES],
			'keys': os.path.join(config, 'fish', 'conf.d', 'mssh-complete.fish')}
	if shell == 'zsh':
		return {'files': [os.path.join(data, 'multiSSH3', 'completion.zsh')], 'rc': os.path.join(home, '.zshrc')}
	# always from ~/.bashrc: bash-completion's per-user directory only loads where bash-completion
	# runs, which an installed package does not guarantee (stock Debian root shells do not load it)
	return {'files': [os.path.join(data, 'multiSSH3', 'completion.bash')], 'rc': os.path.join(home, '.bashrc')}

def install(shell, home=None, environ=None, command=None, editor=False):
	'''
	Install the glue for shell for the current user. Never overwrites a file mssh did not write.

	Args:
		editor (bool): bash only: also turn on the mssh line editor (MSSH_COMPLETE_EDITOR=1 in the rc block)

	Returns:
		tuple: (exit code, list of messages saying what was done)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	text = render_glue(shell, command)
	paths = _paths(shell, home, environ)
	written = [path for path in paths['files'] if _write_glue(path, text, messages)]
	if paths.get('rc') and written:
		quoted = shlex.quote(written[0])
		# always ends with status 0: a missing or broken file must not even change $? in a new shell
		line = '[[ -r {0} ]] && source {0} 2>/dev/null || :' if shell == 'zsh' else '[ -r {0} ] && . {0} 2>/dev/null || :'
		_add_rc_block(paths['rc'], line.format(quoted), messages)
	return (0 if written else 1), messages

def uninstall(shell, home=None, environ=None):
````

with:

````python
	text = render_glue(shell, command)
	paths = _paths(shell, home, environ)
	written = [path for path in paths['files'] if _write_glue(path, text, messages)]
	if paths.get('keys') and written:
		_write_glue(paths['keys'], render_glue('fish-keys', command), messages)
	if paths.get('rc') and written:
		quoted = shlex.quote(written[0])
		# always ends with status 0: a missing or broken file must not even change $? in a new shell
		line = '[[ -r {0} ]] && source {0} 2>/dev/null || :' if shell == 'zsh' else '[ -r {0} ] && . {0} 2>/dev/null || :'
		body = line.format(quoted)
		if editor and shell == 'bash':
			body = 'export MSSH_COMPLETE_EDITOR=1\n' + body
		_add_rc_block(paths['rc'], body, messages)
	return (0 if written else 1), messages

def uninstall(shell, home=None, environ=None):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	home = home or os.path.expanduser('~')
	messages = []
	paths = _paths(shell, home, environ)
	for path in paths['files']:
		if _ours(path):
			os.unlink(path)
			messages.append('removed ' + path)
````

with:

````python
	home = home or os.path.expanduser('~')
	messages = []
	paths = _paths(shell, home, environ)
	for path in paths['files'] + ([paths['keys']] if paths.get('keys') else []):
		if _ours(path):
			os.unlink(path)
			messages.append('removed ' + path)
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	'''`mssh --completion ...`: print the glue for a shell, or install / uninstall it.'''
	action = values[0] if values else ''
	if action in SHELLS and len(values) == 1:
		sys.stdout.write(render_glue(action))
		return 0
	if action in ('install', 'uninstall') and len(values) <= 2:
		shell = values[1] if len(values) == 2 else detect_shell()
		if shell not in SHELLS:
			print('mssh: cannot tell which shell to set up, name it: mssh --completion {} bash|zsh|fish'.format(action), file=sys.stderr)
			return 2
		code, messages = install(shell) if action == 'install' else uninstall(shell)
		for message in messages:
			print(message)
		return code
	print('usage: mssh --completion bash|zsh|fish | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
	return 2

#%% ------------ Replay evaluation ----------------
````

with:

````python
	'''`mssh --completion ...`: print the glue for a shell, or install / uninstall it.'''
	action = values[0] if values else ''
	if action in SHELLS and len(values) == 1:
		sys.stdout.write(render_glue(action) + (render_glue('fish-keys') if action == 'fish' else ''))
		return 0
	editor = action == 'install' and values[-1:] in (['editor'], ['--editor'])
	if editor:
		values = values[:-1]
	if action in ('install', 'uninstall') and len(values) <= 2:
		shell = values[1] if len(values) == 2 else detect_shell()
		if shell not in SHELLS:
			print('mssh: cannot tell which shell to set up, name it: mssh --completion {} bash|zsh|fish'.format(action), file=sys.stderr)
			return 2
		if editor and shell != 'bash':
			print('mssh: the mssh line editor is for bash only', file=sys.stderr)
			return 2
		code, messages = install(shell, editor=editor) if action == 'install' else uninstall(shell)
		for message in messages:
			print(message)
		return code
	print('usage: mssh --completion bash|zsh|fish | install [SHELL] [editor] | uninstall [SHELL]', file=sys.stderr)
	return 2

#%% ------------ Replay evaluation ----------------
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_shells.py tests/test_complete_keys.py -q`

Expected: `39 passed, 20 skipped` (the skipped tests need zsh, fish or ble.sh, which are not installed here; the Docker matrix runs them)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `797 passed, 28 skipped`

- [ ] **Step 6: Run the matrix**

Run: `tests/shells/run_matrix.sh`

Expected (one line per image; CentOS 7 has no zsh or fish, legacy skips one Python 3.7+ check):

````
modern (requires bash,zsh,fish,blesh,zas)
305 passed
legacy (requires bash,zsh,fish,blesh,zas)
304 passed, 1 skipped
centos7 (requires bash,blesh)
286 passed, 19 skipped
````

- [ ] **Step 7: Commit**

````bash
git add tests/test_complete_shells.py tests/test_complete_keys.py mssh_complete.py
git commit -m "feat: Ctrl-R picker in fish; install the mssh line editor for bash

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 11: Benchmark, README, versions

**Files:**
- Modify: `tests/bench_complete.py`
- Modify: `README.md`
- Modify: `mssh_complete.py` (`version`)
- Modify: `multiSSH3.py` (`version`, `COMMIT_DATE`, `--completion` help)
- Modify: `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp2-design.md` (append the deviations)

**Interfaces:**
- Consumes: everything above
- Produces: multiSSH3 6.29, mssh_complete 0.2

- [ ] **Step 1: Extend the benchmark**

In `tests/bench_complete.py`, replace this text (it occurs exactly once):

````python
	(home / '.ssh' / 'config').write_text(''.join('Host node{:05d}\n'.format(number) for number in range(hosts)))


def main():
	tmp = Path(tempfile.mkdtemp())
	try:
````

with:

````python
	(home / '.ssh' / 'config').write_text(''.join('Host node{:05d}\n'.format(number) for number in range(hosts)))


def on_terminal(command, data, env):
	'''
	Start command with data on stdin and a pseudo-terminal as its controlling terminal.
	Returns (process, master fd, slave fd); the slave stays open here so the master never reads EIO.
	'''
	import fcntl
	import pty
	import termios
	master, slave = pty.openpty()

	def attach():
		os.setsid()
		fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, preexec_fn=attach)
	process.stdin.write(data)
	process.stdin.close()
	return process, master, slave


def wait_output(master, timeout=10.0):
	'''Read what the program draws next; the time it took in ms.'''
	import select
	started = time.monotonic()
	ready, _, _ = select.select([master], [], [], timeout)
	if ready:
		os.read(master, 65536)
		# the rest of the same frame
		while select.select([master], [], [], 0.005)[0]:
			os.read(master, 65536)
	return (time.monotonic() - started) * 1000


def interactive(engine, env):
	'''Editor start and per-key time, picker open time.'''
	env = dict(env, MSSH_COMPLETE_PROMPT='$ ', TERM='xterm-256color')
	starts, keys, opens = [], [], []
	for _ in range(5):
		started = time.monotonic()
		process, master, slave = on_terminal(engine + ['edit', 'mssh '], b'', env)
		wait_output(master)
		starts.append((time.monotonic() - started) * 1000)
		for key in 'node00042':
			os.write(master, key.encode())
			keys.append(wait_output(master))
		os.write(master, b'\x03')
		process.stdout.read()
		process.wait(timeout=10)
		os.close(master)
		os.close(slave)
		request = 'MSSHC1\0bash\x005.2\0pick=1\0mssh node0\0\0\0'.encode()
		started = time.monotonic()
		process, master, slave = on_terminal(engine + ['pick'], request, env)
		wait_output(master)
		opens.append((time.monotonic() - started) * 1000)
		os.write(master, b'\x1b')
		process.stdout.read()
		process.wait(timeout=10)
		os.close(master)
		os.close(slave)
	keys.sort()
	print('editor start: p50 {:6.1f} ms'.format(statistics.median(starts)))
	print('editor key:   p50 {:6.1f} ms  max {:6.1f} ms'.format(statistics.median(keys), keys[-1]))
	print('picker open:  p50 {:6.1f} ms'.format(statistics.median(opens)))


def main():
	tmp = Path(tempfile.mkdtemp())
	try:
````

- [ ] **Step 2: Extend the benchmark**

In `tests/bench_complete.py`, replace this text (it occurs exactly once):

````python
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('query {!r:32} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)

````

with:

````python
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('query {!r:32} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		for line in ('mssh node0004', 'mssh -u r', 'mssh node00042 "nvid'):
			request = 'MSSHC1\0bash\x005.2\0ghost=1 nul=0\0{}\0\0\0'.format(line).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('suggest {!r:30} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
		interactive(engine, env)
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)

````

- [ ] **Step 3: Document SP2 in the README**

In `README.md`, replace this text (it occurs exactly once):

````markdown

It learns from an index of your history and hosts, kept in mssh's private cache directory (`$XDG_RUNTIME_DIR/multiSSH3` or `/tmp/multiSSH3-<uid>`) and rebuilt in the background when its sources change. `mssh-complete rebuild` rebuilds it now; `mssh-complete eval` replays your history and shows how much typing completion saves.

| Environment variable | Effect |
| --- | --- |
| `MSSH_COMPLETE_TIMEOUT` | Seconds the shell waits for an answer (default 0.3) |
| `MSSH_COMPLETE_SHELL_HISTORY` | Lines of shell history sent along (default 1000) |
| `MSSH_COMPLETE_DEBUG` | `1` logs errors to `complete.log` in the cache directory |

> Tested with bash 4.2 to 5.2, zsh 5.5 to 5.9 (with `compinit` loaded) and fish 3.3 to 4.0. Since 6.28 mssh records hosts in its history as typed; older history lines hold them expanded.

> With [ble.sh](https://github.com/akinomyoga/ble.sh) loaded, bash also shows grey suggestions while you type, taken from mssh's completion; → accepts one. Tested with the 2026-09-08 ble.sh nightly on bash 4.2 to 5.2.

## Options

````

with:

````markdown

It learns from an index of your history and hosts, kept in mssh's private cache directory (`$XDG_RUNTIME_DIR/multiSSH3` or `/tmp/multiSSH3-<uid>`) and rebuilt in the background when its sources change. `mssh-complete rebuild` rebuilds it now; `mssh-complete eval` replays your history and shows how much typing completion saves.

### Grey suggestions

While you type an mssh line, the most likely rest of it shows in grey after the cursor: the rest of the line when one past invocation clearly fits, only the rest of the current word when only that is clear, nothing when mssh is not sure. → (or End, Ctrl-F) takes all of it, Alt-→ / Ctrl-→ / Alt-F one word. Enter runs only what you typed.

- **zsh:** built in; with [zsh-autosuggestions](https://github.com/zsh-users/zsh-autosuggestions) loaded, mssh becomes its first strategy on mssh lines.
- **bash with [ble.sh](https://github.com/akinomyoga/ble.sh):** built in, as ble.sh's first suggestion source.
- **plain bash:** turn on the mssh line editor, which takes over after you type an mssh name and a space, and hands the line back to readline on any key it does not handle (↑, Ctrl-K, ...) or when you delete into `mssh `:

  ```bash
  mssh --completion install bash editor
  ```

- **fish:** fish's own suggestions already use mssh's completion.

### Ctrl-R

Ctrl-R on an mssh line opens a menu below the prompt with the candidates for the word under the cursor (hosts, commands for those hosts, option values), how often and how long ago you used them; Tab switches to whole past invocations. Type to filter, ↑/↓ to move, Enter to insert, Esc to leave the line as it was. On any other line Ctrl-R does what it did before (readline's search, fzf, atuin, ...).

| Environment variable | Effect |
| --- | --- |
| `MSSH_COMPLETE_TIMEOUT` | Seconds the shell waits for an answer (default 0.3) |
| `MSSH_COMPLETE_GHOST_TIMEOUT` | ble.sh only: milliseconds a grey suggestion may take (default 300) |
| `MSSH_COMPLETE_SHELL_HISTORY` | Lines of shell history sent along (default 1000) |
| `MSSH_COMPLETE_EDITOR` | `1` turns on the plain-bash mssh line editor (`install bash editor` sets it) |
| `MSSH_COMPLETE_DEBUG` | `1` logs errors to `complete.log` in the cache directory |

> Tested with bash 4.2 to 5.2, zsh 5.5 to 5.9 (with `compinit` loaded; zsh-autosuggestions 0.7.1), fish 3.3 to 4.0 and the 2026-09-08 ble.sh nightly. Since 6.28 mssh records hosts in its history as typed; older history lines hold them expanded.

> After upgrading mssh, run `mssh --completion install` again to get the new shell glue. Glue from an older mssh keeps working, without the newer features.

> The plain-bash editor binds the space key, so every space typed in bash runs a tiny shell function; Ctrl-R becomes a key macro (the binding it replaced is called for other lines). Uninstall restores both in new shells.

## Options

````

- [ ] **Step 4: Bump mssh_complete to 0.2**

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
import time
from bisect import bisect_left

version = '0.1'
__version__ = version
PROTOCOL = 'MSSHC1'
MSSH_NAMES = ('mssh', 'mssh3', 'multissh', 'multissh3', 'multiSSH3')
````

with:

````python
import time
from bisect import bisect_left

version = '0.2'
__version__ = version
PROTOCOL = 'MSSHC1'
MSSH_NAMES = ('mssh', 'mssh3', 'multissh', 'multissh3', 'multiSSH3')
````

- [ ] **Step 5: Bump multiSSH3 to 6.29 and update the help**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
from pprint import pformat


version = '6.28'
VERSION = version
__version__ = version
COMMIT_DATE = '2026-10-11'
# TODO: Add terminal TUI

# no current-directory entry: a cloned repo or unpacked archive could set any global (e.g. _sshPath),
````

with:

````python
from pprint import pformat


version = '6.29'
VERSION = version
__version__ = version
COMMIT_DATE = '2026-10-12'
# TODO: Add terminal TUI

# no current-directory entry: a cloned repo or unpacked archive could set any global (e.g. _sshPath),
````

Use the date of the release commit (YYYY-MM-DD); the replay used 2026-10-12.

- [ ] **Step 6: Bump multiSSH3 to 6.29 and update the help**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
	parser.add_argument('--force_truecolor', action='store_true', help=f'Force truecolor output even when not in a truecolor terminal. (default: {FORCE_TRUECOLOR})', default=FORCE_TRUECOLOR)
	parser.add_argument('--add_control_master_config', action='store_true', help='Add ControlMaster configuration to ~/.ssh/config to speed up multiple connections to the same host.')
	parser.add_argument('--host_file', type=str,help=f'File containing list of hosts to run the command on, one host per line. Default:{DEFAULT_HOST_FILE}', default=DEFAULT_HOST_FILE)
	parser.add_argument('--completion', nargs='+', metavar='ARG', help='Shell autocomplete: print the glue for bash, zsh or fish, or "install [SHELL]" / "uninstall [SHELL]" it for the current user')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} @ {COMMIT_DATE} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	return parser

````

with:

````python
	parser.add_argument('--force_truecolor', action='store_true', help=f'Force truecolor output even when not in a truecolor terminal. (default: {FORCE_TRUECOLOR})', default=FORCE_TRUECOLOR)
	parser.add_argument('--add_control_master_config', action='store_true', help='Add ControlMaster configuration to ~/.ssh/config to speed up multiple connections to the same host.')
	parser.add_argument('--host_file', type=str,help=f'File containing list of hosts to run the command on, one host per line. Default:{DEFAULT_HOST_FILE}', default=DEFAULT_HOST_FILE)
	parser.add_argument('--completion', nargs='+', metavar='ARG', help='Shell autocomplete: print the glue for bash, zsh or fish, or "install [SHELL] [editor]" / "uninstall [SHELL]" it for the current user ("editor": the plain-bash mssh line editor)')
	parser.add_argument("-V","--version", action='version', version=f'%(prog)s {version} @ {COMMIT_DATE} with [ {", ".join(_binPaths.keys())} ] by {AUTHOR} ({AUTHOR_EMAIL})')
	return parser

````

Use the date of the release commit (YYYY-MM-DD); the replay used 2026-10-12.

- [ ] **Step 7: Append the deviations to the spec**

Append to the end of `docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp2-design.md` (the text starts with the blank lines that separate it from what is there):

````markdown


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
````

- [ ] **Step 8: Run the benchmark**

Run: `python3 tests/bench_complete.py`

Expected (numbers vary by machine; observations, not gates):

````
rebuild: 379 ms, index 3.4 MB
query 'mssh '                          p50   37.7 ms  p95   39.1 ms
query 'mssh node0'                     p50   47.0 ms  p95   47.8 ms
query 'mssh node00042 "'               p50   32.3 ms  p95   34.6 ms
query 'mssh -u '                       p50   29.4 ms  p95   30.6 ms
query 'mssh '                          p50   37.2 ms  p95   38.7 ms
query "mssh -u root node1 'nvid"       p50   30.7 ms  p95   31.9 ms
suggest 'mssh node0004'                p50   30.8 ms  p95   32.2 ms
suggest 'mssh -u r'                    p50   38.9 ms  p95   41.0 ms
suggest 'mssh node00042 "nvid'         p50   29.6 ms  p95   30.0 ms
editor start: p50   43.8 ms
editor key:   p50   12.4 ms  max   21.3 ms
picker open:  p50   96.8 ms
````

- [ ] **Step 9: Run the whole suite and the matrix**

Run: `python3 -m pytest -q && tests/shells/run_matrix.sh`

Expected: `797 passed, 28 skipped`, then

````
modern (requires bash,zsh,fish,blesh,zas)
305 passed
legacy (requires bash,zsh,fish,blesh,zas)
304 passed, 1 skipped
centos7 (requires bash,blesh)
286 passed, 19 skipped
````

- [ ] **Step 10: Commit**

````bash
git add tests/bench_complete.py README.md mssh_complete.py multiSSH3.py docs/superpowers/specs/2026-10-12-mssh-autocomplete-sp2-design.md
git commit -m "docs: grey suggestions, Ctrl-R and the mssh line editor; multiSSH3 6.29

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

---

## After the plan

- Release: `uvpack` multiSSH3 6.29; bump the `multissh3` pin in `cas-toolbox/pyproject.toml` in the next Monday roll-up. After upgrading, `mssh --completion install` (again) installs the new glue; `mssh --completion install bash editor` turns on the plain-bash editor.
- Tune `T_WORD` / `T_LINE` with `mssh-complete eval --since <date>` on the cluster's real history once it holds typed hosts.
- SP3 (async probing, diagnostics) gets its own brainstorm, spec and plan.
