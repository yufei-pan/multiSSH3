# mssh Autocomplete SP1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TAB completion for mssh in bash, zsh and fish (hosts, options, option values, remote commands), ranked by how well past invocations match the rest of the line on both sides of the cursor, built on an engine that SP2 (ghost text, picker), SP3 (async diagnostics) and the future TUI reuse.

**Architecture:** A second single-file module, `mssh_complete.py`, answers `mssh-complete query` requests (protocol `MSSHC1` on stdin) from a lazily decoded NSV index in mssh's private cache directory; only the background index builder imports `multiSSH3`. Shell glue printed by `mssh --completion` asks the engine under a hard deadline and falls back silently to normal completion. `multiSSH3.py` gains DNS-free host helpers, `--completion`, and records history hosts as typed.

**Tech Stack:** Python 3.6+ standard library only; bash 4.2+, zsh 5.5+, fish 3.0+; pytest; Docker for the shell matrix.

**Spec:** `docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md` (read it; where this plan differs, the plan's "Deviations from the spec" section explains why and Task 13 records the change in the spec).

## Global Constraints

- Python syntax and library floor is 3.6 (`python_requires='>=3.6'`): no walrus, no dataclasses, no `str.isascii`, no `subprocess.run(capture_output=...)`, no f-string `=`; f-strings are fine.
- Single-file modules: `mssh_complete.py` is one file next to `multiSSH3.py`; both stay copy-transportable. No third-party runtime dependencies.
- The query path never imports `multiSSH3`; only `build_index`, `_cmd_rebuild`, `_cmd_eval` and degraded mode (`answer(..., directory=None)`) do.
- Protocol name `MSSHC1`; index file `complete-index.v1.nsv`, mode 0600, in mssh's private cache dir (`$XDG_RUNTIME_DIR/multiSSH3` or `<tempdir>/multiSSH3-<uid>`).
- Values of `-p`, `--password`, `-ip`, `--ipmi_password` are never indexed and never offered.
- Every bash candidate extends the shell's word (`$2`); completion never deletes or rewrites typed text.
- Glue prints nothing, never runs Python at shell start, and falls back to the shell's own completion on any failure. bash glue syntax floor is bash 4.2; zsh glue never runs `compinit`; fish glue registers nothing on fish < 3.0.
- Safety deadlines: engine soft deadline `MSSH_COMPLETE_SOFT_DEADLINE` (default 0.2 s), glue hard deadline `MSSH_COMPLETE_TIMEOUT` (default 0.3 s). Performance is observed, not gated.
- Repository style: tabs for indentation, `'''` docstrings, sparse comments, pytest tests as plain `test_*` functions in `tests/`.
- The existing suite (520 tests at the start of this plan) keeps passing after every task.
- End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

These failure modes are implied by the spec but easy to miss; each has a test in the task that owns the code.

1. **Garbage, non-UTF-8 or old-format lines in `~/.mssh_history`** must not stop the index from building (`test_history_with_garbage_lines_still_builds`, Task 7).
2. **No usable private cache directory** (someone else owns `$XDG_RUNTIME_DIR`, `/tmp/multiSSH3-<uid>` is not ours) must still give option and shell-history completion (`test_degraded_mode_without_an_index`, Task 8).
3. **Two shells pressing TAB before the first index exists** must not start a second rebuild and must not wait longer than the first-build budget (`test_concurrent_first_query_waits_for_the_running_build`, Task 7).
4. **Option values typed inside quotes** (`mssh -u "ro`) must complete inside the quote (`test_quoted_option_values`, Task 8).
5. **A shell word the engine cannot line up with what it parsed** (backslash escapes) must produce no candidates rather than wrong ones (`test_word_that_does_not_end_the_parsed_text_gets_nothing`, Task 8).

## Deviations from the spec

Drafting and running this implementation (against the real history on the development machine, the synthetic replay and real shells in Docker) changed these details. Task 13 appends this table to the spec.

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

Measured at the target scale (10k hosts, 20k invocations): a TAB costs 30-45 ms (p50), a rebuild about 0.5 s, the index is 3 MB.

## How this plan was verified

Every code block in this plan was run before the plan was written. A script then applied the tasks in order to a clean checkout of the spec commit and checked, for each task, that its tests fail before the implementation step and pass after it, that the whole suite passes where a task says so, that the Docker shell matrix passes in Tasks 11 and 13, and that the final `mssh_complete.py` and `multiSSH3.py` are byte-for-byte the verified versions. The "Expected" lines below are that run's output.

## File Structure

| File | Responsibility |
|---|---|
| `mssh_complete.py` | The whole autocomplete: lexer, option spec and context, history parsing, NSV index, knowledge and scoring, host table, index builder and freshness, engine, protocol, shell glue, install, replay evaluation, CLI. Sections are marked `#%% ------------ <name> ----------------` and appear in that order; the CLI section stays last. |
| `multiSSH3.py` | `getStrCommand(typed_hosts=...)` and history recording; `expand_hostnames_local`, `compact_hostnames_local`; `--completion` and `_completion_command`. |
| `setup.py` | Ships `mssh_complete` and the `mssh-complete` console script. |
| `tests/test_complete_mssh_helpers.py` | The `multiSSH3.py` changes. |
| `tests/test_complete_lex.py`, `test_complete_context.py`, `test_complete_store.py`, `test_complete_hosts.py`, `test_complete_index.py`, `test_complete_engine.py`, `test_complete_eval.py` | One file per engine area, matching Tasks 3-8 and 12. |
| `tests/complete_shell_harness.py`, `tests/test_complete_shells.py` | Real shells on a pseudo-terminal (bash, zsh) or `complete -C` (fish); install and shell-start safety. |
| `tests/shells/Dockerfile.{modern,legacy,centos7}`, `tests/shells/run_matrix.sh` | The shell matrix. |
| `tests/bench_complete.py` | Timing and size observations at the target scale (not a test). |

---
Starting point: branch `mssh-autocomplete-sp1` at the spec commit; `python3 -m pytest -q` gives `520 passed`.

### Task 1: Record history hosts as typed
**Files:**
- Modify: `multiSSH3.py` (`getStrCommand`, `record_command_history`)
- Create: `tests/test_complete_mssh_helpers.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `getStrCommand(..., typed_hosts=False, ...)` keyword: when true the hosts field is the hosts argument as given (`_typed_host_str(hosts)`: strings unchanged, lists joined with "," in order, sets sorted). `record_command_history()` always passes `typed_hosts=True`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_mssh_helpers.py` with exactly this content:

````python
import multiSSH3


def test_history_records_hosts_as_typed(tmp_path, monkeypatch):
	monkeypatch.setenv('us_east', '127.0.0.5,127.0.0.6')
	path = tmp_path / 'history'
	multiSSH3.record_command_history({'hosts': 'us_east,zz-no-such-host.invalid,127.0.0.[1-3]', 'commands': ['uptime'], 'history_file': str(path)})
	fields = path.read_text().rstrip('\n').split('\t')
	assert fields[3] == "'us_east,zz-no-such-host.invalid,127.0.0.[1-3]'"


def test_history_keeps_list_order_of_typed_hosts(tmp_path):
	path = tmp_path / 'history'
	multiSSH3.record_command_history({'hosts': ['b', 'a'], 'commands': ['true'], 'history_file': str(path)})
	assert path.read_text().split('\t')[3] == 'b,a'


def test_command_echo_still_formats_hosts():
	line = multiSSH3.getStrCommand(hosts='127.0.0.[1-2]', commands=['true'])
	assert '127.0.0.[1-2]' in line
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_mssh_helpers.py -q`

Expected: FAIL, e.g. `E assert "'127.0.0.[1-...27.0.0.[5-6]'" == "'us_east,zz-...27.0.0.[1-3]'"` (`2 failed, 1 passed`)

- [ ] **Step 3: Implement**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
def getStrCommand(hosts = DEFAULT_HOSTS,commands = None,shortend = False,tabSeperated = False,**kwargs) -> str:
	# Allow explicit kwargs to override base parameters when forwarding dicts.
	hosts = kwargs.get('hosts', hosts)
	commands = kwargs.get('commands', commands)
	shortend = kwargs.get('shortend', shortend)
	tabSeperated = kwargs.get('tabSeperated', tabSeperated)
	hosts = hosts if isinstance(hosts,str) else frozenset(hosts)
	hostStr = formHostStr(hosts)
	commandArgKwargs = dict(kwargs)
	commandArgKwargs.pop('hosts', None)
	commandArgKwargs.pop('commands', None)
	commandArgKwargs.pop('shortend', None)
	commandArgKwargs.pop('tabSeperated', None)
````

with:

````python
def _typed_host_str(hosts):
	'''The hosts argument as given, without expanding, validating or sorting it (sets are sorted).'''
	if isinstance(hosts, str):
		return hosts
	if isinstance(hosts, (set, frozenset)):
		hosts = sorted(hosts)
	return ','.join(str(host) for host in hosts)

def getStrCommand(hosts = DEFAULT_HOSTS,commands = None,shortend = False,tabSeperated = False,typed_hosts = False,**kwargs) -> str:
	# Allow explicit kwargs to override base parameters when forwarding dicts.
	hosts = kwargs.get('hosts', hosts)
	commands = kwargs.get('commands', commands)
	shortend = kwargs.get('shortend', shortend)
	tabSeperated = kwargs.get('tabSeperated', tabSeperated)
	typed_hosts = kwargs.get('typed_hosts', typed_hosts)
	if typed_hosts:
		# the history keeps what was typed: aliases and ranges unexpanded, unresolvable names kept
		hostStr = _typed_host_str(hosts) or 'EMPTY_HOSTS'
	else:
		hosts = hosts if isinstance(hosts,str) else frozenset(hosts)
		hostStr = formHostStr(hosts)
	commandArgKwargs = dict(kwargs)
	commandArgKwargs.pop('hosts', None)
	commandArgKwargs.pop('commands', None)
	commandArgKwargs.pop('shortend', None)
	commandArgKwargs.pop('tabSeperated', None)
	commandArgKwargs.pop('typed_hosts', None)
````

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
		historyKwargs['shortend'] = True
		historyKwargs['tabSeperated'] = True
		history_file
````

with:

````python
		historyKwargs['shortend'] = True
		historyKwargs['tabSeperated'] = True
		historyKwargs['typed_hosts'] = True
		history_file
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_mssh_helpers.py -q`

Expected: `3 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `523 passed`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_mssh_helpers.py multiSSH3.py
git commit -m "feat: record history hosts as typed

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 2: DNS-free host expansion and compaction in multiSSH3
**Files:**
- Modify: `multiSSH3.py` (after `expand_hostnames`)
- Modify: `tests/test_complete_mssh_helpers.py`

**Interfaces:**
- Consumes: `__expand_hostname(text, validate=False)`, `__expandIPv4Address`, `_IPV4_RANGE_RE`, `_local_hostname_source`, `readEnvFromFile`, `_split_host_str`, `_natural_sort_key`, `__compact_hostnames` (all existing in `multiSSH3.py`)
- Produces: `expand_hostnames_local(hosts) -> (expanded: list, unresolved: list)` and `compact_hostnames_local(names) -> list`, both public in `multiSSH3`, never resolving names, never printing, never counting failures.

- [ ] **Step 1: Write the failing tests**

In `tests/test_complete_mssh_helpers.py`, replace this text (it occurs exactly once):

````python
import multiSSH3
````

with:

````python
import socket

import pytest

import multiSSH3
````

Append to the end of `tests/test_complete_mssh_helpers.py` (the text starts with blank lines that separate it from what is there):

````python


@pytest.fixture
def no_dns(monkeypatch):
	def fail(*args, **kwargs):
		raise AssertionError('DNS lookup during a local expansion')
	monkeypatch.setattr(socket, 'getaddrinfo', fail)
	monkeypatch.setattr(multiSSH3, '_resolve_dns', fail)


def test_expand_hostnames_local_expands_ranges_and_aliases_without_dns(no_dns, monkeypatch):
	monkeypatch.setenv('rack_a', '127.0.0.5,rack[1-2]')
	monkeypatch.setenv('everything', '$rack_a,10.1.1.1-3')
	expanded, unresolved = multiSSH3.expand_hostnames_local('everything,root@node[01-02],zz-bad')
	assert expanded == ['10.1.1.1', '10.1.1.2', '10.1.1.3', '127.0.0.5', 'rack1', 'rack2', 'root@node01', 'root@node02', 'zz-bad']
	assert unresolved == ['rack1', 'rack2', 'root@node01', 'root@node02', 'zz-bad']


def test_expand_hostnames_local_reads_env_files(no_dns, tmp_path, monkeypatch):
	env_file = tmp_path / 'hosts.env'
	env_file.write_text("gpus='gpu[1-3]'\n")
	monkeypatch.setattr(multiSSH3, '_env_files', [str(env_file)])
	monkeypatch.setattr(multiSSH3, '_explicit_env_files', {str(env_file)})
	assert multiSSH3.expand_hostnames_local(['gpus'])[0] == ['gpu1', 'gpu2', 'gpu3']


def test_expand_hostnames_local_stops_alias_loops(no_dns, monkeypatch):
	monkeypatch.setenv('loop_a', 'loop_b')
	monkeypatch.setenv('loop_b', 'loop_a')
	assert multiSSH3.expand_hostnames_local('loop_a') == ([], [])


def test_expand_hostnames_local_counts_no_failures(no_dns):
	multiSSH3.expand_hostnames_local('zz-bad-host')
	assert multiSSH3.__failedHosts == set()
	assert multiSSH3.__mainReturnCode == 0


def test_compact_hostnames_local_round_trips_without_dns(no_dns):
	names = ['node01', 'node02', 'node03', 'gpu1', '10.0.0.1', '10.0.0.2']
	assert multiSSH3.compact_hostnames_local(names) == ['10.0.0.[1-2]', 'gpu1', 'node[01-03]']
	assert multiSSH3.compact_hostnames_local([]) == []
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_mssh_helpers.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'multiSSH3' has no attribute 'expand_hostnames_local'. Did you mean: 'expand_hostnames'?` (`5 failed, 3 passed`)

- [ ] **Step 3: Implement**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
	return __expand_hostnames(hosts)

# environment variables host expansion looked up since the last refresh, with the value seen (None: unset)
````

with:

````python
	return __expand_hostnames(hosts)

def expand_hostnames_local(hosts):
	'''
	Expand host strings without DNS or ssh config lookups.

	Ranges, IPv4 ranges and env / env file aliases (recursively) are expanded like
	expand_hostnames does. A name that is not an IP address, in the hosts file or an alias
	is kept as it is and also listed as unresolved: only DNS or the ssh config could confirm it.
	Nothing is printed and no failure is counted.

	Args:
		hosts (str or iterable): Host strings, each may hold several hosts separated by ","

	Returns:
		tuple: (expanded, unresolved), two lists in natural sort order. user@ prefixes are kept.
	'''
	if isinstance(hosts, str):
		hosts = [hosts]
	expanded = set()
	unresolved = set()
	def walk(text, user, depth):
		for token in _split_host_str(text):
			token_user = user
			if '@' in token:
				token_user, token = token.split('@', 1)
				token_user = token_user.strip() or user
			token = token.strip()
			if not token:
				continue
			if _IPV4_RANGE_RE.match(token):
				names = __expandIPv4Address(frozenset([token]))
			else:
				names = __expand_hostname(token, validate=False)
			for name in names:
				name = name.strip().strip('$')
				if not name:
					continue
				source = _local_hostname_source(name)
				if source in ('env', 'env_file'):
					# an alias loop expands to nothing
					if depth < 32:
						value = os.environ.get(name) if source == 'env' else readEnvFromFile().get(name)
						walk(value or '', token_user, depth + 1)
					continue
				full = '{}@{}'.format(token_user, name) if token_user else name
				expanded.add(full)
				if source is None:
					unresolved.add(full)
	for host in hosts:
		walk(str(host), None, 0)
	return sorted(expanded, key=_natural_sort_key), sorted(unresolved, key=_natural_sort_key)

def compact_hostnames_local(names):
	'''
	Compact host names into range strings without DNS.

	Like compact_hostnames, but the result is checked by expanding the ranges only, so names
	are never resolved and nothing is printed. If the compacted form does not expand back to
	exactly the names, the names are returned unchanged.

	Args:
		names (iterable): Host names, no aliases or ranges

	Returns:
		list: Range strings (or names) in natural sort order
	'''
	host_set = frozenset(name.strip() for name in names if name and name.strip())
	if not host_set:
		return []
	compacted = __compact_hostnames(host_set)
	back = set()
	for text in compacted:
		back.update(__expand_hostname(text, validate=False))
	if back != host_set:
		return sorted(host_set, key=_natural_sort_key)
	return sorted(compacted, key=_natural_sort_key)

# environment variables host expansion looked up since the last refresh, with the value seen (None: unset)
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_mssh_helpers.py -q`

Expected: `8 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `528 passed`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_mssh_helpers.py multiSSH3.py
git commit -m "feat: expand and compact host names without DNS

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 3: mssh_complete module and shell lexer
**Files:**
- Create: `mssh_complete.py`
- Modify: `setup.py` (`py_modules`)
- Create: `tests/test_complete_lex.py`

**Interfaces:**
- Consumes: nothing
- Produces: `Token(text, raw, quoted=False, open_quote="")`; `lex(line) -> list[Token]`; `CURSOR`; `Cursor(before, current, prefix, open_quote, after)`; `split_at_cursor(before, after) -> Cursor`; module constants `version`, `PROTOCOL = "MSSHC1"`, `MSSH_NAMES`, `SHELLS`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_lex.py` with exactly this content:

````python
import pytest

import mssh_complete as mc


@pytest.mark.parametrize('line, expected', [
	('mssh -u root', [('mssh', False, ''), ('-u', False, ''), ('root', False, '')]),
	('a "b c" d\\ e', [('a', False, ''), ('b c', True, ''), ('d e', False, '')]),
	("x 'it''s'", [('x', False, ''), ('its', True, '')]),
	('"a\\"b" "\\$x"', [('a"b', True, ''), ('$x', True, '')]),
	("$'a\\nb\\x41\\101'", [('a\nbAA', True, '')]),
	('mssh grp "lscp', [('mssh', False, ''), ('grp', False, ''), ('lscp', True, '"')]),
	("mssh 'abc", [('mssh', False, ''), ('abc', True, "'")]),
	("$'ab", [('ab', True, "$'")]),
	('a"b c"d', [('ab cd', True, '')]),
	('tail\\', [('tail', False, '')]),
	('  ', []),
])
def test_lex(line, expected):
	assert [(token.text, token.quoted, token.open_quote) for token in mc.lex(line)] == expected


def test_lex_keeps_raw_text():
	assert [token.raw for token in mc.lex('a "b c" d\\ e')] == ['a', '"b c"', 'd\\ e']


@pytest.mark.parametrize('before, after, words, current, prefix, open_quote, rest', [
	('mssh ', '', ['mssh'], '', '', '', []),
	('mssh gp', '', ['mssh'], 'gp', 'gp', '', []),
	('mssh ho', 'st cmd', ['mssh'], 'host', 'ho', '', ['cmd']),
	('mssh grp "a | gre', '', ['mssh', 'grp'], 'a | gre', 'a | gre', '"', []),
	('mssh h "sys', 'tem ctl"', ['mssh', 'h'], 'system ctl', 'sys', '"', []),
	('mssh h ', ' "uptime"', ['mssh', 'h'], '', '', '', ['uptime']),
	('mssh -f=/et', '', ['mssh'], '-f=/et', '-f=/et', '', []),
	('mssh foo\\', '', ['mssh'], 'foo', 'foo', '', []),
])
def test_split_at_cursor(before, after, words, current, prefix, open_quote, rest):
	cursor = mc.split_at_cursor(before, after)
	assert [token.text for token in cursor.before] == words
	assert cursor.current.text == current
	assert cursor.prefix == prefix
	assert cursor.open_quote == open_quote
	assert [token.text for token in cursor.after] == rest
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_lex.py -q`

Expected: FAIL, e.g. `E ModuleNotFoundError: No module named 'mssh_complete'` (`1 error`)

- [ ] **Step 3: Implement**

Create `mssh_complete.py` with exactly this content:

````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mssh_complete: autocomplete for multiSSH3 (mssh)
# Copyright (C) 2026 Yufei Pan <pan@zopyr.us>
# SPDX-License-Identifier: GPL-3.0-or-later
'''
Autocomplete for mssh (multiSSH3).

Shells send the command line to `mssh-complete query` (protocol MSSHC1 on stdin) and get
ranked candidates back. Answering reads a precomputed index that is decoded lazily; only
building the index (`mssh-complete rebuild`) imports multiSSH3.
'''
import math
import os
import sys
import time
from bisect import bisect_left

version = '0.1'
__version__ = version
PROTOCOL = 'MSSHC1'
MSSH_NAMES = ('mssh', 'mssh3', 'multissh', 'multissh3', 'multiSSH3')
SHELLS = ('bash', 'zsh', 'fish')

#%% ------------ Shell lexing ----------------
class Token(object):
	'''One shell word. text is the dequoted value, raw the text as typed.'''
	__slots__ = ('text', 'raw', 'quoted', 'open_quote')

	def __init__(self, text, raw, quoted=False, open_quote=''):
		self.text = text
		self.raw = raw
		self.quoted = quoted
		self.open_quote = open_quote

	def __repr__(self):
		return 'Token({!r}, raw={!r}, quoted={!r}, open_quote={!r})'.format(self.text, self.raw, self.quoted, self.open_quote)

_ANSI_C_SIMPLE = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b',
	'f': '\f', 'v': '\v', '\\': '\\', "'": "'", '"': '"', '?': '?'}

def _ansi_c_escape(line, index):
	'''Decode the escape after a backslash at line[index] inside $'...'. Returns (text, next index).'''
	char = line[index]
	if char in _ANSI_C_SIMPLE:
		return _ANSI_C_SIMPLE[char], index + 1
	if char == 'x':
		end = index + 1
		while end < len(line) and end < index + 3 and line[end] in '0123456789abcdefABCDEF':
			end += 1
		if end > index + 1:
			return chr(int(line[index + 1:end], 16)), end
		return '\\x', index + 1
	if char in '01234567':
		end = index
		while end < len(line) and end < index + 3 and line[end] in '01234567':
			end += 1
		return chr(int(line[index:end], 8)), end
	return '\\' + char, index + 1

def lex(line):
	'''
	Split a command line into words like a POSIX shell, tolerating an unterminated quote.

	Handles '...', "...", $'...' and backslash escapes. An unterminated quote takes the rest of
	the line, and the word records it in open_quote. Shell operators are not split off.

	Returns:
		list: Token objects
	'''
	tokens = []
	length = len(line)
	index = 0
	while True:
		while index < length and line[index] in ' \t\n':
			index += 1
		if index >= length:
			return tokens
		start = index
		parts = []
		quoted = False
		open_quote = ''
		while index < length and line[index] not in ' \t\n':
			char = line[index]
			if char == '\\':
				if index + 1 < length and line[index + 1] != '\n':
					parts.append(line[index + 1])
				index += 2
			elif char == "'":
				quoted = True
				end = line.find("'", index + 1)
				if end < 0:
					parts.append(line[index + 1:])
					open_quote = "'"
					index = length
				else:
					parts.append(line[index + 1:end])
					index = end + 1
			elif char == '"':
				quoted = True
				index += 1
				while index < length and line[index] != '"':
					if line[index] == '\\' and index + 1 < length and line[index + 1] in '"\\$`\n':
						if line[index + 1] != '\n':
							parts.append(line[index + 1])
						index += 2
					else:
						parts.append(line[index])
						index += 1
				if index >= length:
					open_quote = '"'
				else:
					index += 1
			elif char == '$' and index + 1 < length and line[index + 1] == "'":
				quoted = True
				index += 2
				while index < length and line[index] != "'":
					if line[index] == '\\' and index + 1 < length:
						text, index = _ansi_c_escape(line, index + 1)
						parts.append(text)
					else:
						parts.append(line[index])
						index += 1
				if index >= length:
					open_quote = "$'"
				else:
					index += 1
			else:
				parts.append(char)
				index += 1
		tokens.append(Token(''.join(parts), line[start:min(index, length)], quoted, open_quote))

# marks the cursor while lexing; a private use character that does not appear in command lines
CURSOR = '\ue000'

class Cursor(object):
	'''A command line split at the cursor: the words before it, the word it is in, the words after it.'''
	__slots__ = ('before', 'current', 'prefix', 'open_quote', 'after')

	def __init__(self, before, current, prefix, open_quote, after):
		self.before = before
		self.current = current
		self.prefix = prefix
		self.open_quote = open_quote
		self.after = after

def split_at_cursor(before, after):
	'''
	Lex a command line around the cursor.

	Returns:
		Cursor: prefix is the dequoted part of the current word before the cursor, open_quote the
			quote left open at the cursor ('' if none)
	'''
	tokens = lex(before + CURSOR + after)
	head = lex(before + CURSOR)
	open_quote = head[-1].open_quote if head and CURSOR in head[-1].text else ''
	for index, token in enumerate(tokens):
		if CURSOR in token.text:
			prefix = token.text.split(CURSOR, 1)[0]
			current = Token(token.text.replace(CURSOR, '', 1), token.raw.replace(CURSOR, '', 1), token.quoted, token.open_quote)
			return Cursor(tokens[:index], current, prefix, open_quote, tokens[index + 1:])
	# the cursor char was swallowed (e.g. by a trailing backslash): a new empty word
	return Cursor(tokens, Token('', ''), '', '', [])

````

In `setup.py`, replace this text (it occurs exactly once):

````python
    py_modules=['multiSSH3'],
````

with:

````python
    py_modules=['multiSSH3', 'mssh_complete'],
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_lex.py -q`

Expected: `20 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_lex.py mssh_complete.py setup.py
git commit -m "feat: add mssh_complete with a shell lexer

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 4: Option spec, context detection and history parsing
**Files:**
- Modify: `mssh_complete.py` (append sections Option spec, Context, History)
- Create: `tests/test_complete_context.py`

**Interfaces:**
- Consumes: `lex`, `split_at_cursor`, `Token` (Task 3)
- Produces: `OptionSpec(dest, strings, nargs, repeat, group, default, help)` with `.long`, `.to_row()`, `.from_row(row)`; `ParserSpec(options)` with `.lookup(text) -> (OptionSpec|None, value|None)`, `.by_string`, `.to_rows()`, `.from_rows(rows)`; `spec_from_parser(parser)`; `PASSWORD_DESTS`, `PATH_DESTS`, `USER_DESTS`, `PATH_MODES`; `assign_roles(words, spec, current=None) -> [(role, OptionSpec|None)]`; `split_hosts(text)`; `command_features(command)`; `make_features(options, hosts, commands) -> sorted list`; `line_features(words, spec)`; `SLOT_OPTION/SLOT_VALUE/SLOT_HOSTS/SLOT_COMMAND`; `Context` (slots: slot, option, prefix, value_start, open_quote, quoted, hosts, options, command_words, command_word_index, command_prefix, mode, features; property `value`); `parse_context(before, after, spec) -> Context|None`; `HistoryEntry(ts, options, hosts, commands, option_texts=None)` with `.features()`; `parse_history_line(line, spec) -> HistoryEntry|None`. Features are strings `kind:text` with kinds `o` (option long string), `v` (dest=value), `h` (hosts argument), `t` (host word), `c` (command), `p` (program), `s` (program + first argument), `f` (path in -f/-fs/-G modes), `m` (mode).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_context.py` with exactly this content:

````python
import random
import shlex

import pytest

import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())


def test_spec_describes_every_option():
	strings = {string for option in SPEC.options for string in option.strings}
	assert {'-u', '--username', '-S', '-q', '-nw', '--no_watch'} <= strings
	assert SPEC.by_string['-u'].nargs == '1'
	assert SPEC.by_string['-fs'].nargs == '?'
	assert SPEC.by_string['-q'].nargs == '0'
	assert SPEC.by_string['-f'].repeat
	assert SPEC.by_string['-x'].group and SPEC.by_string['-x'].group == SPEC.by_string['-a'].group
	assert SPEC.by_string['-t'].default == str(multiSSH3.DEFAULT_CLI_TIMEOUT)


def test_spec_rows_round_trip():
	again = mc.ParserSpec.from_rows(SPEC.to_rows())
	assert [option.to_row() for option in again.options] == SPEC.to_rows()


@pytest.mark.parametrize('text, dest, value', [
	('-u', 'username', None),
	('--username', 'username', None),
	('-u=root', 'username', 'root'),
	('--no_w', 'no_watch', None),
	('--usern=x', 'username', 'x'),
	('--no', None, None),
	('-zz', None, None),
])
def test_lookup(text, dest, value):
	option, attached = SPEC.lookup(text)
	assert (option.dest if option else None, attached) == (dest, value)


@pytest.mark.parametrize('before, after, slot, dest, value', [
	('mssh ', '', 'hosts', None, ''),
	('mssh -', '', 'option', None, '-'),
	('mssh --no_', '', 'option', None, '--no_'),
	('mssh -u ', '', 'value', 'username', ''),
	('mssh -u r', '', 'value', 'username', 'r'),
	('mssh -f=/et', '', 'value', 'file', '/et'),
	('mssh -fs ', '', 'value', 'file_sync', ''),
	('mssh -q ', '', 'hosts', None, ''),
	('mssh grp ', '', 'command', None, ''),
	('mssh grp "a | gre', '', 'command', None, 'a | gre'),
	('mssh grp ls -', '', 'command', None, '-'),
	("mssh grp 'uptime' -", '', 'option', None, '-'),
	('mssh -- -x', '', 'command', None, '-x'),
])
def test_slot(before, after, slot, dest, value):
	context = mc.parse_context(before, after, SPEC)
	assert context.slot == slot
	assert (context.option.dest if context.option else None) == dest
	assert context.value == value


def test_program_name_has_no_context():
	assert mc.parse_context('mss', '', SPEC) is None


def test_features_come_from_both_sides_of_the_cursor():
	context = mc.parse_context('mssh ', " 'systemctl restart slurmd' -u root", SPEC)
	assert context.slot == 'hosts'
	assert context.features == ['c:systemctl restart slurmd', 'm:plain', 'o:--username', 'p:systemctl', 's:systemctl restart', 'v:username=root']


def test_passwords_never_become_features():
	context = mc.parse_context('mssh -p=secret -ip hunter2 -u ', ' h c', SPEC)
	assert not any('secret' in feature or 'hunter2' in feature or 'password' in feature for feature in context.features)


def test_quoted_command_delegates_its_last_segment():
	context = mc.parse_context('mssh grp "cat x | gre', '', SPEC)
	assert (context.command_words, context.command_word_index, context.command_prefix) == (['gre'], 0, 'cat x | ')


def test_unquoted_command_words_are_one_command():
	context = mc.parse_context('mssh grp systemctl rest', ' x', SPEC)
	assert (context.command_words, context.command_word_index, context.command_prefix) == (['systemctl', 'rest'], 1, '')
	assert not any(feature.startswith('c:') for feature in context.features)


def test_path_modes_make_path_features():
	assert mc.parse_context('mssh -fs ', ' h /etc/hosts', SPEC).mode == 'sync'
	assert 'f:/data/x' in mc.parse_context('mssh -u ', ' -G h /data/x', SPEC).features


def test_history_line():
	entry = mc.parse_history_line('1762909714\t/x/multiSSH3.py\t-su -f="/etc/a b" -p=pw -u=root\t\'node[1-3],root@gpu1\'\t"lscpu | grep X" uptime', SPEC)
	assert entry.ts == 1762909714
	assert [(option.dest, value) for option, value in entry.options] == [('skip_unreachable', None), ('file', '/etc/a b'), ('password', 'pw'), ('username', 'root')]
	assert entry.option_texts == ['-su', '-f', '-p', '-u']
	assert entry.hosts == 'node[1-3],root@gpu1'
	assert entry.commands == ['lscpu | grep X', 'uptime']
	assert 'h:node[1-3],root@gpu1' in entry.features() and 't:gpu1' in entry.features()
	assert not any('pw' in feature for feature in entry.features())


@pytest.mark.parametrize('line', ['garbage', '1\t2\t3', 'x\ta\tb\tc\td'])
def test_history_line_in_another_format(line):
	assert mc.parse_history_line(line, SPEC) is None


def _generated_lines(count=300, seed=7):
	rng = random.Random(seed)
	options = [['-q'], ['-u', 'root'], ['-u=admin'], ['-t', '30'], ['-su'], ['-fs'], ['-k'], ['--no_watch'], ['-j'], ['-f', '/tmp/a']]
	hosts = ['gpu[01-16]', 'node1,node2', 'us_east']
	commands = [['uptime'], ['df -h'], ['echo', 'hi'], []]
	for _ in range(count):
		words = []
		for _ in range(rng.randint(0, 3)):
			words += rng.choice(options)
		words.append(rng.choice(hosts))
		words += rng.choice(commands)
		yield words


def test_roles_agree_with_argparse():
	parser = multiSSH3.get_parser()
	if not hasattr(parser, 'parse_intermixed_args'):
		pytest.skip('Python 3.6 has no parse_intermixed_args; mssh falls back to parse_known_args there')
	for words in _generated_lines():
		try:
			parsed = parser.parse_intermixed_args(words)
		except SystemExit:
			continue
		tokens = mc.lex(' '.join(shlex.quote(word) for word in words))
		roles = mc.assign_roles(tokens, SPEC)
		hosts = [token.text for token, (role, _) in zip(tokens, roles) if role == 'hosts']
		commands = [token.text for token, (role, _) in zip(tokens, roles) if role == 'command']
		assert hosts == ([parsed.hosts] if parsed.hosts != multiSSH3.DEFAULT_HOSTS or 'all' in words else []), words
		assert commands == parsed.commands, words
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_context.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'spec_from_parser'` (`1 error`)

- [ ] **Step 3: Implement**

Append to the end of `mssh_complete.py` (the text starts with blank lines that separate it from what is there):

````python
#%% ------------ Option spec ----------------
PASSWORD_DESTS = frozenset(('password', 'ipmi_password'))
PATH_DESTS = frozenset(('file', 'file_sync', 'env_file', 'env_files', 'config_file', 'store_config_file', 'host_file', 'history_file'))
USER_DESTS = frozenset(('username', 'ipmi_username'))

def _one_line(text):
	'''text on one line, with NUL, tabs and newlines turned into single spaces.'''
	return ' '.join(str(text).replace('\0', ' ').split())

class OptionSpec(object):
	'''One mssh option: its dest, every string naming it and how many values it takes.'''
	__slots__ = ('dest', 'strings', 'nargs', 'repeat', 'group', 'default', 'help')

	def __init__(self, dest, strings, nargs='0', repeat=False, group='', default='', help=''):
		self.dest = dest
		self.strings = tuple(strings)
		self.nargs = nargs
		self.repeat = repeat
		self.group = group
		self.default = default
		self.help = help

	@property
	def long(self):
		'''The first --long string, or the longest string if there is none.'''
		for string in self.strings:
			if string.startswith('--'):
				return string
		return max(self.strings, key=len)

	def to_row(self):
		return [self.dest, self.nargs, '1' if self.repeat else '0', self.group, self.default, self.help] + list(self.strings)

	@classmethod
	def from_row(cls, row):
		return cls(row[0], row[6:], row[1], row[2] == '1', row[3], row[4], row[5])

class ParserSpec(object):
	'''The options of the mssh parser, looked up the way argparse matches them.'''
	def __init__(self, options):
		self.options = list(options)
		self.by_string = {}
		for option in self.options:
			for string in option.strings:
				self.by_string[string] = option
		self._long = sorted(string for string in self.by_string if string.startswith('--'))

	def lookup(self, text):
		'''
		The option a word names, and the value attached to it with "=".

		Unique abbreviations of --long options are accepted, like argparse does.

		Returns:
			tuple: (OptionSpec or None, attached value or None)
		'''
		option = self.by_string.get(text)
		if option is not None:
			return option, None
		name, sep, value = text.partition('=')
		if sep:
			option = self.by_string.get(name) or self._abbreviation(name)
			return (option, value) if option is not None else (None, None)
		return self._abbreviation(text), None

	def _abbreviation(self, name):
		if not name.startswith('--') or len(name) < 3:
			return None
		found = {}
		for string in self._long[bisect_left(self._long, name):]:
			if not string.startswith(name):
				break
			option = self.by_string[string]
			found[id(option)] = option
		return next(iter(found.values())) if len(found) == 1 else None

	def to_rows(self):
		return [option.to_row() for option in self.options]

	@classmethod
	def from_rows(cls, rows):
		return cls(OptionSpec.from_row(row) for row in rows)

def spec_from_parser(parser):
	'''Describe the options of an argparse parser (index builder side).'''
	import argparse
	groups = {}
	for number, group in enumerate(getattr(parser, '_mutually_exclusive_groups', ())):
		for action in group._group_actions:
			groups[id(action)] = str(number)
	options = []
	for action in parser._actions:
		if not action.option_strings:
			continue
		nargs = '1' if action.nargs is None else str(action.nargs)
		repeat = isinstance(action, (argparse._AppendAction, argparse._AppendConstAction, argparse._CountAction))
		default = action.default
		if isinstance(default, bool) or not isinstance(default, (int, float, str)):
			default = ''
		options.append(OptionSpec(action.dest, action.option_strings, nargs, repeat,
			groups.get(id(action), ''), _one_line(default), _one_line(action.help or '')))
	return ParserSpec(options)

#%% ------------ Context ----------------
ROLE_OPTION = 'option'
ROLE_VALUE = 'value'
ROLE_HOSTS = 'hosts'
ROLE_COMMAND = 'command'
ROLE_SEPARATOR = 'separator'

def _looks_like_option(text):
	return len(text) > 1 and text[0] == '-'

def assign_roles(words, spec, current=None):
	'''
	The role argparse gives each word of an mssh command line (program name excluded).

	words[current] is the word being completed: a dash starting it means an option name,
	except after unquoted command words, where it belongs to the remote command.

	Returns:
		list: (role, OptionSpec or None) per word
	'''
	roles = []
	pending = None
	have_hosts = False
	after_separator = False
	command_seen = False
	commands_quoted = True
	for index, token in enumerate(words):
		text = token.text
		is_current = index == current
		dashed = _looks_like_option(text) or (is_current and text.startswith('-'))
		if pending is not None:
			option = pending
			pending = None
			if not dashed:
				roles.append((ROLE_VALUE, option))
				continue
		if after_separator:
			roles.append((ROLE_COMMAND, None))
			continue
		if text == '--' and not is_current:
			roles.append((ROLE_SEPARATOR, None))
			after_separator = True
			continue
		if dashed:
			if is_current and command_seen and not commands_quoted:
				roles.append((ROLE_COMMAND, None))
				continue
			option, attached = spec.lookup(text)
			if option is None and not is_current:
				# argparse gives unknown options to the commands
				roles.append((ROLE_COMMAND, None))
				if have_hosts:
					command_seen = True
					commands_quoted = False
				continue
			roles.append((ROLE_OPTION, option))
			if option is not None and attached is None and option.nargs != '0':
				pending = option
			continue
		if not have_hosts:
			have_hosts = True
			roles.append((ROLE_HOSTS, None))
		else:
			command_seen = True
			commands_quoted = commands_quoted and token.quoted
			roles.append((ROLE_COMMAND, None))
	return roles

def split_hosts(text):
	'''Split a hosts argument into host words, on the separators mssh accepts.'''
	for separator in ',\n\r\t;|/&':
		text = text.replace(separator, ' ')
	return text.split()

def command_features(command):
	'''Features of one remote command: the command, its program and program plus first argument.'''
	command = command.strip()
	if not command:
		return []
	words = [token.text for token in lex(command)]
	features = ['c:' + command]
	if words:
		features.append('p:' + words[0])
		if len(words) > 1 and words[1] not in ('|', '||', '&&', ';'):
			features.append('s:' + words[0] + ' ' + words[1])
	return features

def _mode(dests):
	dests = set(dests)
	if 'ipmi' in dests:
		return 'ipmi'
	if 'gather_mode' in dests:
		return 'gather'
	if 'file_sync' in dests:
		return 'sync'
	if 'file' in dests:
		return 'push'
	return 'plain'

PATH_MODES = ('push', 'sync', 'gather')

def make_features(options, hosts, commands):
	'''
	The features of an invocation, used to find similar ones in history.

	Args:
		options (list): (OptionSpec, value or None) pairs; password values are never included
		hosts (str): The hosts argument as typed
		commands (list): Command strings

	Returns:
		list: Sorted feature strings, "<kind>:<text>"
	'''
	features = set()
	mode = _mode(option.dest for option, _ in options)
	for option, value in options:
		if option.dest in PASSWORD_DESTS:
			continue
		features.add('o:' + option.long)
		if value:
			features.add('v:{}={}'.format(option.dest, value))
	if hosts:
		features.add('h:' + hosts)
		for word in split_hosts(hosts):
			user, _, host = word.rpartition('@')
			if host:
				features.add('t:' + host)
			if user:
				features.add('v:username=' + user)
	for command in commands:
		if mode in PATH_MODES:
			# with -f / -fs / -G the commands are paths
			if command.strip():
				features.add('f:' + command.strip())
		else:
			features.update(command_features(command))
	features.add('m:' + mode)
	return sorted(feature for feature in features if '\0' not in feature and '\n' not in feature)

def _join_commands(commands):
	'''Commands from command words: quoted words are commands, runs of unquoted words are one command.'''
	joined = []
	run = []
	for text, quoted in commands:
		if quoted:
			if run:
				joined.append(' '.join(run))
				run = []
			joined.append(text)
		else:
			run.append(text)
	if run:
		joined.append(' '.join(run))
	return joined

def _collect(words, roles, skip=()):
	'''The options (with values), hosts and command words of a line, leaving out the words in skip.'''
	options = []
	hosts = ''
	commands = []
	for index, (token, (role, option)) in enumerate(zip(words, roles)):
		if index in skip:
			continue
		if role == ROLE_OPTION and option is not None:
			attached = None
			if '=' in token.text and token.text not in option.strings:
				attached = token.text.partition('=')[2]
			options.append([option, attached])
		elif role == ROLE_VALUE:
			if options and options[-1][0] is option and options[-1][1] is None:
				options[-1][1] = token.text
			else:
				options.append([option, token.text])
		elif role == ROLE_HOSTS:
			hosts = token.text
		elif role == ROLE_COMMAND:
			commands.append((token.text, token.quoted))
	return [(option, value) for option, value in options], hosts, commands

def line_features(words, spec):
	'''Features of a complete mssh command line (program name excluded).'''
	options, hosts, commands = _collect(words, assign_roles(words, spec))
	return make_features(options, hosts, _join_commands(commands))

SLOT_OPTION = 'option'
SLOT_VALUE = 'value'
SLOT_HOSTS = 'hosts'
SLOT_COMMAND = 'command'

class Context(object):
	'''
	What the cursor is completing.

	slot: SLOT_OPTION, SLOT_VALUE, SLOT_HOSTS or SLOT_COMMAND
	option: the OptionSpec whose value is completed (SLOT_VALUE)
	prefix: the dequoted current word up to the cursor; value_start: where the slot's value
		starts in it (after "-x=")
	open_quote / quoted: the quote open at the cursor / whether the current word has quoting
	hosts: the hosts argument (another word); options: (OptionSpec, value) of the other words
	command_words / command_word_index / command_prefix: the remote command words up to the
		cursor, the index of the current one, and the text in front of them inside a quoted word
	mode: plain, push, sync, gather or ipmi; features: features of every other slot
	'''
	__slots__ = ('slot', 'option', 'prefix', 'value_start', 'open_quote', 'quoted', 'hosts', 'options',
		'command_words', 'command_word_index', 'command_prefix', 'mode', 'features')

	def __init__(self, **values):
		for name in self.__slots__:
			setattr(self, name, values.get(name))

	@property
	def value(self):
		return self.prefix[self.value_start:]

_PIPELINE_MARKS = ('||', '&&', '|', ';', '$(', '`', '(')

def _segment_start(text):
	'''Where the last pipeline segment of a command string starts.'''
	start = 0
	for mark in _PIPELINE_MARKS:
		at = text.rfind(mark)
		if at >= 0 and at + len(mark) > start:
			start = at + len(mark)
	return start

def parse_context(before, after, spec):
	'''
	What the cursor completes in an mssh command line, with the rest of the line as features.

	Args:
		before (str): The line up to the cursor, starting with the program name
		after (str): The line after the cursor
		spec (ParserSpec): The mssh options

	Returns:
		Context, or None when the cursor is on the program name
	'''
	cursor = split_at_cursor(before, after)
	if not cursor.before:
		return None
	words = cursor.before[1:] + [cursor.current] + cursor.after
	current = len(cursor.before) - 1
	roles = assign_roles(words, spec, current)
	role, option = roles[current]
	prefix = cursor.prefix
	value_start = 0
	if role == ROLE_OPTION:
		name, sep, _ = prefix.partition('=')
		found = spec.lookup(name)[0] if sep else None
		if found is not None and found.nargs != '0':
			slot, option, value_start = SLOT_VALUE, found, len(name) + 1
		else:
			slot, option = SLOT_OPTION, None
	elif role == ROLE_VALUE:
		slot = SLOT_VALUE
	elif role == ROLE_HOSTS:
		slot = SLOT_HOSTS
	else:
		slot = SLOT_COMMAND
	skip = {current}
	command_words = command_word_index = command_prefix = None
	if slot == SLOT_COMMAND:
		if cursor.current.quoted:
			start = _segment_start(prefix)
			segment = split_at_cursor(prefix[start:], '')
			command_words = [token.text for token in segment.before] + [segment.prefix]
			command_word_index = len(segment.before)
			if prefix.endswith(segment.prefix):
				command_prefix = prefix[:len(prefix) - len(segment.prefix)]
			else:
				command_words = None
		else:
			# the unquoted command words the current word continues
			first = current
			while first > 0 and roles[first - 1][0] == ROLE_COMMAND and not words[first - 1].quoted:
				first -= 1
			last = current
			while last + 1 < len(words) and roles[last + 1][0] == ROLE_COMMAND and not words[last + 1].quoted:
				last += 1
			skip = set(range(first, last + 1))
			command_words = [token.text for token in words[first:current]] + [prefix]
			command_word_index = current - first
			command_prefix = ''
	options, hosts, commands = _collect(words, roles, skip)
	return Context(slot=slot, option=option, prefix=prefix, value_start=value_start,
		open_quote=cursor.open_quote, quoted=cursor.current.quoted, hosts=hosts, options=options,
		command_words=command_words, command_word_index=command_word_index, command_prefix=command_prefix,
		mode=_mode(option.dest for option, _ in options),
		features=make_features(options, hosts, _join_commands(commands)))

#%% ------------ History ----------------
class HistoryEntry(object):
	'''One ~/.mssh_history line: when it ran, its options, its hosts as recorded and its commands.'''
	__slots__ = ('ts', 'options', 'option_texts', 'hosts', 'commands')

	def __init__(self, ts, options, hosts, commands, option_texts=None):
		self.ts = ts
		self.options = options
		self.option_texts = option_texts if option_texts is not None else [option.strings[0] for option, _ in options]
		self.hosts = hosts
		self.commands = commands

	def features(self):
		return make_features(self.options, self.hosts, [command for command in self.commands if command.strip()])

def parse_history_line(line, spec):
	'''
	Parse a ~/.mssh_history line: <ts>\\t<program>\\t<options>\\t<hosts>\\t<commands>.

	Returns:
		HistoryEntry, or None for a line in another format
	'''
	fields = line.rstrip('\r\n').split('\t')
	if len(fields) != 5:
		return None
	try:
		ts = int(fields[0])
	except ValueError:
		return None
	options = []
	texts = []
	tokens = lex(fields[2])
	index = 0
	while index < len(tokens):
		text = tokens[index].text
		option, attached = spec.lookup(text)
		index += 1
		if option is None:
			continue
		if attached is None and option.nargs in ('1', '+') and index < len(tokens):
			attached = tokens[index].text
			index += 1
		options.append((option, attached))
		texts.append(text.partition('=')[0] if attached is not None and '=' in text else text)
	host_tokens = lex(fields[3])
	hosts = host_tokens[0].text if host_tokens else ''
	if hosts == 'EMPTY_HOSTS':
		hosts = ''
	return HistoryEntry(ts, options, hosts, [token.text for token in lex(fields[4])], texts)

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_context.py -q`

Expected: `33 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_context.py mssh_complete.py
git commit -m "feat: detect the completion slot like argparse and parse mssh history

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 5: NSV index storage, knowledge and context-conditioned scoring
**Files:**
- Modify: `mssh_complete.py` (append sections Index storage (NSV), Knowledge, Ranking)
- Create: `tests/test_complete_store.py`

**Interfaces:**
- Consumes: `parse_history_line` (Task 4)
- Produces: `INDEX_MAGIC`, `INDEX_FORMAT = "1"`, `INDEX_NAME = "complete-index.v1.nsv"`; `IndexCorrupt`; `safe_field(text)`; `write_nsv(path, header: dict, sections: [(name, rows)])`; `NsvIndex(data)` / `NsvIndex.load(path)` with `.header`, `.sections`, `.count(name)`, `.row(name, i) -> list`, `.single(name) -> list`; `HALF_LIFE`, `USE_FLOOR`, `decay(age)`, `use_weight(age)`; `MemoryKnowledge()` with `.add(features, weight)`, `.add_history(lines, spec, now)`, `.records`; `SnapshotKnowledge(index, now)`; both expose `record_count()`, `feature_range(prefix) -> [(key, text)]`, `feature_key(text)`, `postings(key)`, `record(rid) -> (weight, features)`, `feature_weight(key)`; `BETA`, `KIND_WEIGHTS`, `COMMON_SHARE`, `MAX_CONTEXT_RECORDS`; `score_features(knowledges, prefix, line_features, deadline=None) -> {feature: score}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_store.py` with exactly this content:

````python
import os
import stat

import pytest

import mssh_complete as mc


def test_nsv_round_trip(tmp_path):
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {'built': '1'}, [('one', [['a', 'b']]), ('many', [['1'], [], ['x', '', 'y']])])
	index = mc.NsvIndex.load(path)
	assert index.header == {'built': '1'}
	assert index.single('one') == ['a', 'b']
	assert [index.row('many', number) for number in range(3)] == [['1'], [], ['x', '', 'y']]
	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_nsv_rejects_unsafe_fields(tmp_path):
	with pytest.raises(ValueError):
		mc.write_nsv(str(tmp_path / 'index.nsv'), {}, [('bad', [['a\nb']])])
	assert os.listdir(str(tmp_path)) == []


@pytest.mark.parametrize('damage', [
	lambda data: data + 'junk',
	lambda data: data[:-5],
	lambda data: data.replace(mc.INDEX_MAGIC, 'NOTMAGIC', 1),
	lambda data: data.replace('\0' + mc.INDEX_FORMAT + '\0', '\x0099\0', 1),
	lambda data: '',
])
def test_damaged_index_is_rejected(tmp_path, damage):
	path = str(tmp_path / 'index.nsv')
	mc.write_nsv(path, {}, [('one', [['a']])])
	with open(path) as f:
		data = f.read()
	with open(path, 'w') as f:
		f.write(damage(data))
	with pytest.raises(mc.IndexCorrupt):
		mc.NsvIndex.load(path)


def memory(records):
	knowledge = mc.MemoryKnowledge()
	for features, weight in records:
		knowledge.add(features, weight)
	return knowledge


def test_identical_invocations_share_a_record():
	knowledge = memory([(['c:uptime', 'h:a'], 1.0), (['c:uptime', 'h:a'], 0.5), (['c:df', 'h:a'], 1.0)])
	assert knowledge.record_count() == 2
	assert knowledge.feature_weight('h:a') == 2.5
	assert knowledge.feature_range('c:') == [('c:df', 'c:df'), ('c:uptime', 'c:uptime')]


def test_use_weight_keeps_a_floor():
	assert mc.use_weight(0) == pytest.approx(1 + mc.USE_FLOOR)
	assert mc.use_weight(mc.HALF_LIFE) == pytest.approx(0.5 + mc.USE_FLOOR)
	assert mc.use_weight(1000 * mc.HALF_LIFE) == pytest.approx(mc.USE_FLOOR)


def test_scores_without_context_are_frecency():
	knowledge = memory([(['c:uptime'], 3.0), (['c:df'], 1.0)])
	scores = mc.score_features([knowledge], 'c:', [])
	assert scores == {'c:uptime': pytest.approx(0.3), 'c:df': pytest.approx(0.1)}


def test_matching_the_line_beats_being_used_often():
	knowledge = memory([
		(['c:uptime', 'h:login1', 'm:plain'], 9.0),
		(['c:df -h /data', 'h:storage1', 'm:plain'], 1.0),
		(['c:free', 'h:other', 'm:plain'], 1.0),
	])
	scores = mc.score_features([knowledge], 'h:', ['c:df -h /data', 'm:plain'])
	assert max(scores, key=scores.get) == 'h:storage1'


def test_features_in_most_records_carry_no_context():
	knowledge = memory([(['c:a', 'm:plain'], 1.0), (['c:b', 'm:plain'], 1.0), (['c:c', 'm:sync'], 1.0)])
	with_common = mc.score_features([knowledge], 'c:', ['m:plain'])
	assert with_common == mc.score_features([knowledge], 'c:', [])
	assert max(mc.score_features([knowledge], 'c:', ['m:sync']).items(), key=lambda item: item[1])[0] == 'c:c'


def test_scores_add_up_across_knowledge():
	first = memory([(['c:a', 'h:x'], 1.0)])
	second = memory([(['c:a', 'h:x'], 1.0), (['c:b', 'h:y'], 1.0)])
	assert mc.score_features([first, second], 'c:', [])['c:a'] == pytest.approx(0.2)
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_store.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'write_nsv'` (`13 failed`)

- [ ] **Step 3: Implement**

Append to the end of `mssh_complete.py` (the text starts with blank lines that separate it from what is there):

````python
#%% ------------ Index storage (NSV) ----------------
INDEX_MAGIC = 'MSSHCIDX'
INDEX_FORMAT = '1'
INDEX_NAME = 'complete-index.v1.nsv'

class IndexCorrupt(Exception):
	'''The index file is not a complete index this version can read.'''

def safe_field(text):
	'''Whether text can be stored in an NSV field (no NUL, no newline).'''
	return '\0' not in text and '\n' not in text

def write_nsv(path, header, sections):
	'''
	Write an index file atomically (a temporary file in the same directory, then os.replace).

	Row 0 holds the magic, the format, "key=value" header fields and "@section=start,count"
	entries; every other row is a section row with its fields joined by NUL.

	Args:
		path (str): Where to write, mode 0600
		header (dict): str -> str
		sections (list): (name, rows) pairs, rows a list of lists of str

	Raises:
		ValueError: a field holds NUL or a newline
	'''
	import tempfile
	body = []
	table = []
	row_number = 1
	for name, rows in sections:
		table.append('@{}={},{}'.format(name, row_number, len(rows)))
		row_number += len(rows)
		for row in rows:
			for field in row:
				if not safe_field(field):
					raise ValueError('field {!r} of section {} holds NUL or a newline'.format(field[:40], name))
			body.append('\0'.join(row))
	head = [INDEX_MAGIC, INDEX_FORMAT] + ['{}={}'.format(key, value) for key, value in sorted(header.items())] + table
	for field in head:
		if not safe_field(field):
			raise ValueError('header field {!r} holds NUL or a newline'.format(field[:40]))
	data = '\0'.join(head) + '\n' + ''.join(row + '\n' for row in body)
	fd, temporary = tempfile.mkstemp(prefix='.complete-index.', dir=os.path.dirname(path) or '.')
	try:
		with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
			f.write(data)
			f.flush()
			os.fsync(f.fileno())
		os.replace(temporary, path)
	except BaseException:
		try:
			os.unlink(temporary)
		except OSError:
			pass
		raise

class NsvIndex(object):
	'''An index file split into rows; a row is only split into fields when it is read.'''
	def __init__(self, data):
		self.rows = data.split('\n')
		head = self.rows[0].split('\0')
		if len(head) < 2 or head[0] != INDEX_MAGIC:
			raise IndexCorrupt('not an mssh completion index')
		if head[1] != INDEX_FORMAT:
			raise IndexCorrupt('index format {!r}, this version reads {!r}'.format(head[1], INDEX_FORMAT))
		self.header = {}
		self.sections = {}
		total = 1
		for field in head[2:]:
			key, sep, value = field.partition('=')
			if not sep:
				raise IndexCorrupt('bad header field {!r}'.format(field[:40]))
			if key.startswith('@'):
				start, _, count = value.partition(',')
				try:
					start, count = int(start), int(count)
				except ValueError:
					raise IndexCorrupt('bad section entry {!r}'.format(field[:40])) from None
				self.sections[key[1:]] = (start, count)
				total += count
			else:
				self.header[key] = value
		# a complete file ends with a newline, leaving one empty string after the last row
		if len(self.rows) != total + 1 or self.rows[-1] != '':
			raise IndexCorrupt('truncated index')
		for start, count in self.sections.values():
			if start < 1 or start + count > total:
				raise IndexCorrupt('section outside the index')
		self._single = {}

	@classmethod
	def load(cls, path):
		with open(path, 'r', encoding='utf-8', errors='surrogateescape', newline='') as f:
			return cls(f.read())

	def count(self, name):
		return self.sections.get(name, (0, 0))[1]

	def row(self, name, index):
		start, count = self.sections[name]
		if not 0 <= index < count:
			raise IndexError('row {} of section {} ({} rows)'.format(index, name, count))
		line = self.rows[start + index]
		return line.split('\0') if line else []

	def single(self, name):
		'''A section stored as one row, split once and kept.'''
		cached = self._single.get(name)
		if cached is None:
			cached = self.row(name, 0) if self.count(name) else []
			self._single[name] = cached
		return cached

#%% ------------ Knowledge ----------------
HALF_LIFE = 7 * 24 * 3600.0
USE_FLOOR = 0.1   # what any use keeps counting however old: frequency outlives recency

def decay(age):
	'''Factor for weights age seconds old: halves every HALF_LIFE.'''
	if age <= 0:
		return 1.0
	return 0.5 ** (age / HALF_LIFE)

def use_weight(age):
	'''Weight of one use age seconds ago: USE_FLOOR plus a recency part that halves every HALF_LIFE.'''
	return USE_FLOOR + decay(age)

def _prefix_range(sorted_items, prefix):
	'''(lo, hi): sorted_items[lo:hi] are the items starting with prefix.'''
	lo = bisect_left(sorted_items, prefix)
	hi = lo
	while hi < len(sorted_items) and sorted_items[hi].startswith(prefix):
		hi += 1
	return lo, hi

class MemoryKnowledge(object):
	'''
	Records held in memory: identical invocations share one record whose weight sums their uses.

	Used for the history tail not yet in the index, the shell's history, the replay evaluation,
	and by the builder to aggregate records before writing them.
	'''
	def __init__(self):
		self.records = []
		self._by_features = {}
		self._postings = {}
		self._weights = {}
		self._sorted = None

	def add(self, features, weight):
		key = tuple(features)
		rid = self._by_features.get(key)
		if rid is None:
			rid = len(self.records)
			self._by_features[key] = rid
			self.records.append([0.0, list(features)])
			for feature in features:
				self._postings.setdefault(feature, []).append(rid)
			self._sorted = None
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

	def feature_range(self, prefix):
		if self._sorted is None:
			self._sorted = sorted(self._postings)
		lo, hi = _prefix_range(self._sorted, prefix)
		return [(text, text) for text in self._sorted[lo:hi]]

	def feature_key(self, text):
		return text if text in self._postings else None

	def postings(self, key):
		return self._postings[key]

	def record(self, rid):
		weight, features = self.records[rid]
		return weight, features

	def feature_weight(self, key):
		return self._weights.get(key, 0.0)

class SnapshotKnowledge(object):
	'''The records stored in the index, read lazily, with weights decayed to now.'''
	def __init__(self, index, now):
		self.index = index
		self.features = index.single('features')
		built = float(index.header.get('built', now) or now)
		self.scale = decay(now - built)
		self._weights = None

	def record_count(self):
		return self.index.count('records')

	def feature_range(self, prefix):
		lo, hi = _prefix_range(self.features, prefix)
		return [(key, self.features[key]) for key in range(lo, hi)]

	def feature_key(self, text):
		key = bisect_left(self.features, text)
		return key if key < len(self.features) and self.features[key] == text else None

	def postings(self, key):
		return [int(rid) for rid in self.index.row('postings', key)]

	def record(self, rid):
		row = self.index.row('records', rid)
		return float(row[0]) * self.scale, [self.features[int(key)] for key in row[1:]]

	def feature_weight(self, key):
		if self._weights is None:
			self._weights = self.index.single('fweights')
		return float(self._weights[key]) * self.scale

#%% ------------ Ranking ----------------
BETA = 0.1                  # weight of plain frecency next to similarity with the line
KIND_WEIGHTS = {}           # feature kind ('h', 't', 'v', 'c', ...) -> weight, 1.0 when absent
COMMON_SHARE = 0.5          # a feature in more than this share of the records carries no context
MAX_CONTEXT_RECORDS = 20000 # records read per query for context

def score_features(knowledges, prefix, line_features, deadline=None):
	'''
	Score every feature starting with prefix (e.g. "c:sys") in the given knowledge.

	score(c) = BETA * frecency(c) + sum over records r holding c of log(1 + weight(r)) * sim(r, line),
	where sim sums idf(f) * KIND_WEIGHTS[kind of f] over the features f shared by r and the line.
	Features in more than COMMON_SHARE of the records are left out of sim; frequency counts
	logarithmically there, so matching the line beats being used often.

	Returns:
		dict: feature text -> score
	'''
	scores = {}
	for knowledge in knowledges:
		for key, text in knowledge.feature_range(prefix):
			scores[text] = scores.get(text, 0.0) + BETA * knowledge.feature_weight(key)
	if not scores or not line_features:
		return scores
	total = sum(knowledge.record_count() for knowledge in knowledges)
	similarity = [dict() for _ in knowledges]
	for feature in line_features:
		lists = []
		for knowledge in knowledges:
			key = knowledge.feature_key(feature)
			lists.append(knowledge.postings(key) if key is not None else [])
		df = sum(len(rids) for rids in lists)
		if not df or df > COMMON_SHARE * total:
			continue
		weight = math.log(1.0 + float(total) / df) * KIND_WEIGHTS.get(feature[0], 1.0)
		for sim, rids in zip(similarity, lists):
			for rid in rids:
				sim[rid] = sim.get(rid, 0.0) + weight
	touched = 0
	for knowledge, sim in zip(knowledges, similarity):
		for rid, value in sim.items():
			touched += 1
			if touched > MAX_CONTEXT_RECORDS or (deadline is not None and touched % 256 == 0 and time.monotonic() > deadline):
				return scores
			weight, features = knowledge.record(rid)
			for text in features:
				if text.startswith(prefix):
					scores[text] = scores.get(text, 0.0) + math.log1p(weight) * value
	return scores

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_store.py -q`

Expected: `13 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_store.py mssh_complete.py
git commit -m "feat: lazily decoded NSV index and context-conditioned scoring

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 6: Host table and range compaction
**Files:**
- Modify: `mssh_complete.py` (append section Hosts)
- Create: `tests/test_complete_hosts.py`

**Interfaces:**
- Consumes: `_prefix_range` (Task 5)
- Produces: `SRC_HOSTS_FILE, SRC_SSH_CONFIG, SRC_KNOWN_HOSTS, SRC_ARP, SRC_HISTORY, SRC_ALIAS` (1, 2, 4, 8, 16, 32); `HostTable(index=None)` with `.names`, `.alias_names`, `.unavailable`, `.names_with_prefix(prefix)`, `.aliases_with_prefix(prefix) -> [(i, name)]`, `.alias_index(name)`, `.alias_members(i)`, `.alias_size(i)`, `.groups() -> [(text, member names)]`; `compact_names(names) -> sorted list`; `expand_ranges(text, limit=100000) -> list`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_hosts.py` with exactly this content:

````python
import multiSSH3
import mssh_complete as mc


def test_compact_names_round_trip_through_mssh_expansion():
	expand = getattr(multiSSH3, '__expand_hostname')
	names = ['node{:05d}'.format(number) for number in range(9000)] + ['n1', 'n2', 'n10', 'n11', 'x-1-a', 'x-2-a', 'plain']
	for prefix in ('', 'n', 'node0', 'node08', 'node0899', 'n1', 'x'):
		subset = [name for name in names if name.startswith(prefix)]
		groups = mc.compact_names(subset)
		assert all(group.startswith(prefix) for group in groups)
		back = set()
		for group in groups:
			back.update(expand(group, validate=False))
		assert back == set(subset), prefix


def test_expand_ranges():
	assert mc.expand_ranges('n[1-3]-[a,b]') == ['n1-a', 'n1-b', 'n2-a', 'n2-b', 'n3-a', 'n3-b']
	assert mc.expand_ranges('n[01-02]') == ['n01', 'n02']
	assert mc.expand_ranges('x[a-c]') == ['x[a-c]']
	assert mc.expand_ranges('n[1-9]', limit=3) == ['n[1-9]']

````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_hosts.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'compact_names'` (`2 failed`)

- [ ] **Step 3: Implement**

Append to the end of `mssh_complete.py` (the text starts with blank lines that separate it from what is there):

````python
#%% ------------ Hosts ----------------
SRC_HOSTS_FILE, SRC_SSH_CONFIG, SRC_KNOWN_HOSTS, SRC_ARP, SRC_HISTORY, SRC_ALIAS = 1, 2, 4, 8, 16, 32

class HostTable(object):
	'''Hosts, aliases and host groups from the index; empty without one.'''
	def __init__(self, index=None):
		self.index = index
		self.names = index.single('host_names') if index is not None else []
		self.alias_names = index.single('alias_names') if index is not None else []
		self.unavailable = frozenset(index.single('unavailable')) if index is not None else frozenset()
		self._groups = None

	def names_with_prefix(self, prefix):
		lo, hi = _prefix_range(self.names, prefix)
		return self.names[lo:hi]

	def aliases_with_prefix(self, prefix):
		lo, hi = _prefix_range(self.alias_names, prefix)
		return [(index, self.alias_names[index]) for index in range(lo, hi)]

	def alias_index(self, name):
		index = bisect_left(self.alias_names, name)
		return index if index < len(self.alias_names) and self.alias_names[index] == name else None

	def alias_members(self, index):
		'''Member host names of the alias at index.'''
		return [self.names[int(member)] for member in self.index.row('aliases', index)[1:]]

	def alias_size(self, index):
		return len(self.index.row('aliases', index)) - 1

	def groups(self):
		'''(range text, member names) of the host groups found when the index was built.'''
		if self._groups is None:
			self._groups = []
			if self.index is not None:
				for number in range(self.index.count('groups')):
					row = self.index.row('groups', number)
					self._groups.append((row[0], [self.names[int(member)] for member in row[1:]]))
		return self._groups

_DIGITS = '0123456789'

def _is_digits(text):
	return bool(text) and all(char in _DIGITS for char in text)

def compact_names(names):
	'''
	Compact host names into range strings: node001..node512 -> node[001-512].

	Names that differ only in their last run of digits (with the same number of digits) are
	grouped, and each run of consecutive numbers becomes one range. Digits all members of a run
	share stay in front of the range, so the range text starts with every prefix they share.

	Returns:
		list: Range strings and names that did not group, sorted
	'''
	buckets = {}
	singles = []
	for name in names:
		end = len(name)
		while end > 0 and name[end - 1] not in _DIGITS:
			end -= 1
		start = end
		while start > 0 and name[start - 1] in _DIGITS:
			start -= 1
		if start == end:
			singles.append(name)
			continue
		key = (name[:start], end - start, name[end:])
		buckets.setdefault(key, []).append(int(name[start:end]))
	out = list(singles)
	for (stem, width, tail), numbers in buckets.items():
		numbers.sort()
		low = previous = numbers[0]
		for number in numbers[1:] + [None]:
			if number is not None and number == previous + 1:
				previous = number
				continue
			out.append(_range_text(stem, width, tail, low, previous))
			if number is not None:
				low = previous = number
	return sorted(out)

def _range_text(stem, width, tail, low, high):
	low_text = '{:0{}d}'.format(low, width)
	high_text = '{:0{}d}'.format(high, width)
	if low == high:
		return stem + low_text + tail
	common = 0
	while common < width - 1 and low_text[common] == high_text[common]:
		common += 1
	return '{}{}[{}-{}]{}'.format(stem, low_text[:common], low_text[common:], high_text[common:], tail)

def expand_ranges(text, limit=100000):
	'''
	Expand [a-b] and [a,b] number ranges in a host name, the common part of mssh's range syntax.

	Text with letter or hex ranges, or that would expand to more than limit names, is returned
	as it is (in a one-item list).
	'''
	start = text.find('[')
	end = text.find(']', start + 1)
	if start < 0 or end < 0:
		return [text]
	head, body, tail = text[:start], text[start + 1:end], text[end + 1:]
	values = []
	for part in body.split(','):
		low, sep, high = part.strip().partition('-')
		if sep and _is_digits(low) and _is_digits(high):
			width = min(len(low), len(high))
			values.extend('{:0{}d}'.format(number, width) for number in range(int(low), int(high) + 1))
		elif not sep and part.strip():
			values.append(part.strip())
		else:
			return [text]
		if len(values) > limit:
			return [text]
	out = []
	for value in values:
		out.extend(expand_ranges(head + value + tail, limit))
		if len(out) > limit:
			return [text]
	return out

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_hosts.py -q`

Expected: `2 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_hosts.py mssh_complete.py
git commit -m "feat: host table and prefix-safe range compaction

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 7: Cache directory, index builder, freshness and detached rebuild
**Files:**
- Modify: `mssh_complete.py` (append sections Cache directory, Index sources, Building the index, Freshness, Command line)
- Modify: `setup.py` (console script)
- Create: `tests/test_complete_index.py`

**Interfaces:**
- Consumes: `spec_from_parser`, `ParserSpec` (Task 4); `write_nsv`, `NsvIndex`, `MemoryKnowledge`, `safe_field` (Task 5); `SRC_*` (Task 6); `multiSSH3.expand_hostnames_local`, `compact_hostnames_local` (Task 2), `multiSSH3._unavailable_hosts_file_path`, `_read_unavailable_hosts_file`, `readEnvFromFile`, `get_parser`, `DEFAULT_HISTORY_FILE`, `DEFAULT_HOST_FILE`, `DEFAULT_ENV_FILES`, `_env_files`, `CONFIG_FILE_CHAIN`
- Produces: `cache_dir(create=True) -> str|None`; `_debug(message)`; `read_hosts_file`, `read_ssh_config(path, base_dir, names, users, read)`, `read_known_hosts`, `read_arp`, `read_history(path, start=0) -> (lines, offset, inode)`; `collect_aliases(mssh, history_tokens, known)`; `file_signature(path)`; `_import_mssh()`; `MAX_RECORDS`; `serialize_knowledge(memory)`; `build_index(directory, now=None, mssh=None) -> path` writing sections spec, config, sources, features, fweights, postings, records, host_names, host_meta, alias_names, aliases, groups, unavailable and header keys built, arp_at, engine, mssh_version, history, history_offset, history_ino; `TAIL_LIMIT_BYTES`, `TAIL_LIMIT_ENTRIES`, `ARP_TTL`, `LOCK_NAME`, `LOCK_STALE`, `FIRST_BUILD_BUDGET`; `check_freshness(index, now) -> (state, tail_lines)`; `take_lock(path, now=None)`; `spawn_rebuild(directory)`; `load_for_query(directory, now) -> (NsvIndex|None, tail_lines)`; CLI `main(argv=None)` with `rebuild [--lock PATH]` and `--version`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_index.py` with exactly this content:

````python
import os
import subprocess
import time

import pytest

import multiSSH3
import mssh_complete as mc

NOW = 1790000000.0
HISTORY = [
	'1789990000\t/x/multiSSH3.py\t-su -u=root -p=topsecret\tgpu[01-16]\t"nvidia-smi"',
	'1789990100\t/x/multiSSH3.py\t-su -u=root\tgpu[01-16]\t"systemctl restart slurmd"',
	'1789990200\t/x/multiSSH3.py\t-su -u=admin\tstorage1,storage2\t"df -h /data"',
	'1789990300\t/x/multiSSH3.py\t-su\tracks\t"uptime"',
]


@pytest.fixture
def home(tmp_path, monkeypatch):
	'''A HOME with mssh history, ssh config, known_hosts and an env file; a private runtime dir.'''
	home = tmp_path / 'home'
	(home / '.ssh').mkdir(parents=True)
	runtime = tmp_path / 'runtime'
	runtime.mkdir(mode=0o700)
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in HISTORY))
	(home / '.ssh' / 'config').write_text('Host jump1 jump2 *.corp\n  User ops\nInclude extra.conf\n')
	(home / '.ssh' / 'extra.conf').write_text('Host bastion\n')
	(home / '.ssh' / 'known_hosts').write_text('kh1,10.9.9.9 ssh-ed25519 AAAA\n|1|hashed= ssh-rsa AAAA\n[kh2]:2222 ssh-rsa AAAA\n')
	env_file = home / 'hosts.env'
	env_file.write_text("racks='rack[1-3]'\nPATH=/usr/bin:/bin\nEDITOR=vim\n")
	monkeypatch.setenv('HOME', str(home))
	monkeypatch.setenv('XDG_RUNTIME_DIR', str(runtime))
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HISTORY_FILE', '~/.mssh_history')
	monkeypatch.setattr(multiSSH3, '_env_files', [str(env_file)])
	monkeypatch.setattr(multiSSH3, '_explicit_env_files', {str(env_file)})
	return home


def build(now=NOW):
	directory = mc.cache_dir()
	return mc.NsvIndex.load(mc.build_index(directory, now=now, mssh=multiSSH3)), directory


def test_cache_dir_matches_multissh3(home):
	assert mc.cache_dir() == os.path.dirname(multiSSH3._unavailable_hosts_file_path())


def test_build_index_collects_every_source(home):
	index, _ = build()
	hosts = mc.HostTable(index)
	names = set(hosts.names)
	assert {'jump1', 'jump2', 'bastion', 'kh1', '10.9.9.9', 'kh2', 'rack1', 'rack2', 'rack3', 'storage1', 'storage2'} <= names
	assert '*.corp' not in names and 'gpu[01-16]' not in names
	assert hosts.alias_names == ['racks']
	assert hosts.alias_members(0) == ['rack1', 'rack2', 'rack3']
	assert ('rack[1-3]', ['rack1', 'rack2', 'rack3']) in hosts.groups()
	assert index.row('config', 0) == ['users', 'ops']
	assert index.header['history_offset'] == str(os.path.getsize(str(home / '.mssh_history')))


def test_index_never_holds_passwords(home):
	index, directory = build()
	with open(os.path.join(directory, mc.INDEX_NAME), 'rb') as f:
		assert b'topsecret' not in f.read()


def test_snapshot_and_memory_knowledge_agree(home):
	index, _ = build()
	snapshot = mc.SnapshotKnowledge(index, NOW)
	memory = mc.MemoryKnowledge()
	memory.add_history(HISTORY, mc.spec_from_parser(multiSSH3.get_parser()), NOW)
	for prefix in ('c:', 't:', 'v:username='):
		assert [text for _, text in snapshot.feature_range(prefix)] == [text for _, text in memory.feature_range(prefix)]
	key = snapshot.feature_key('c:nvidia-smi')
	assert snapshot.feature_weight(key) == pytest.approx(memory.feature_weight('c:nvidia-smi'), rel=1e-5)


def test_snapshot_weights_decay_with_age(home):
	index, _ = build()
	key = mc.SnapshotKnowledge(index, NOW).feature_key('c:uptime')
	fresh = mc.SnapshotKnowledge(index, NOW).feature_weight(key)
	week_later = mc.SnapshotKnowledge(index, NOW + mc.HALF_LIFE).feature_weight(key)
	assert week_later == pytest.approx(fresh / 2)


def test_fresh_index(home):
	index, _ = build(now=time.time())
	assert mc.check_freshness(index, time.time()) == ('fresh', [])


def test_appended_history_is_a_tail(home):
	index, _ = build(now=time.time())
	line = '1790000500\t/x/multiSSH3.py\t-su\tgpu07\t"nvidia-smi -q"'
	with open(str(home / '.mssh_history'), 'a') as f:
		f.write(line + '\n')
	assert mc.check_freshness(index, time.time()) == ('tail', [line])


def test_long_tail_needs_a_rebuild(home):
	index, _ = build(now=time.time())
	with open(str(home / '.mssh_history'), 'a') as f:
		for number in range(mc.TAIL_LIMIT_ENTRIES + 1):
			f.write('1790000500\t/x/multiSSH3.py\t-su\th{}\t"uptime"\n'.format(number))
	assert mc.check_freshness(index, time.time()) == ('rebuild', [])


@pytest.mark.parametrize('change', ['shrink', 'source', 'arp'])
def test_rebuild_needed(home, change):
	index, _ = build(now=time.time())
	now = time.time()
	if change == 'shrink':
		(home / '.mssh_history').write_text(HISTORY[0] + '\n')
	elif change == 'source':
		(home / '.ssh' / 'config').write_text('Host other\n')
	else:
		now += mc.ARP_TTL + 1
	assert mc.check_freshness(index, now)[0] == 'rebuild'


def test_lock_blocks_a_second_rebuild_until_stale(tmp_path):
	lock = str(tmp_path / mc.LOCK_NAME)
	assert mc.take_lock(lock, now=time.time())
	assert not mc.take_lock(lock, now=time.time())
	assert mc.take_lock(lock, now=time.time() + mc.LOCK_STALE + 1)


def test_first_query_builds_the_index(home):
	directory = mc.cache_dir()
	index, tail = mc.load_for_query(directory, time.time())
	assert index is not None and tail == []
	assert not os.path.exists(os.path.join(directory, mc.LOCK_NAME))



def test_history_with_garbage_lines_still_builds(home):
	with open(str(home / '.mssh_history'), 'ab') as f:
		f.write(b'\xff\xfe not utf-8 \x00 at all\n')
		f.write(b'1790000900\t/x/multiSSH3.py\t-su\t\xe9t\xe9\t"echo \xff"\n')
		f.write(b'old style line without tabs\n')
		f.write(b'1790000901\t/x/multiSSH3.py\t-su\tEMPTY_HOSTS\t"uptime"\n')
	index, _ = build()
	features = mc.SnapshotKnowledge(index, NOW).features
	assert 'c:uptime' in features and 'c:nvidia-smi' in features
	assert not any(feature == 'h:EMPTY_HOSTS' for feature in features)


def test_concurrent_first_query_waits_for_the_running_build(home, monkeypatch):
	directory = mc.cache_dir()
	assert mc.take_lock(os.path.join(directory, mc.LOCK_NAME))
	started = []
	monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: started.append(args))
	monkeypatch.setattr(mc, 'FIRST_BUILD_BUDGET', 0.2)
	assert mc.load_for_query(directory, time.time()) == (None, [])
	assert started == []
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_index.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'cache_dir'` (`15 failed`)

- [ ] **Step 3: Implement**

Append to the end of `mssh_complete.py` (the text starts with blank lines that separate it from what is there):

````python
#%% ------------ Cache directory ----------------
def _private_dir(path, create=True):
	'''
	Whether path is a directory only we control, creating it (mode 0700) if create.

	Same rules as multiSSH3._private_dir: not a symlink, owned by us, not accessible to others.
	'''
	import stat
	if create:
		try:
			os.mkdir(path, 0o700)
		except FileExistsError:
			pass
		except OSError:
			return False
	try:
		st = os.lstat(path)
	except OSError:
		return False
	if not stat.S_ISDIR(st.st_mode):
		return False
	if not hasattr(os, 'getuid'):
		return True
	if st.st_uid != os.getuid() or st.st_mode & 0o022:
		return False
	if st.st_mode & 0o077:
		if not create:
			return False
		try:
			os.chmod(path, 0o700)
			st = os.lstat(path)
		except OSError:
			return False
	return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077

def _owned_and_not_writable_by_others(path):
	if not hasattr(os, 'getuid'):
		return True
	try:
		st = os.stat(path)
	except OSError:
		return False
	return st.st_uid == os.getuid() and not st.st_mode & 0o022

def cache_dir(create=True):
	'''
	mssh's private cache directory, where unavailable_hosts.csv lives, or None.

	$XDG_RUNTIME_DIR/multiSSH3 when the runtime dir is ours, else <tempdir>/multiSSH3-<uid>,
	exactly as multiSSH3._unavailable_hosts_file_path picks it.
	'''
	import tempfile
	if hasattr(os, 'getuid'):
		user_id = os.getuid()
	else:
		import getpass
		user_id = getpass.getuser()
	candidates = []
	runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
	if runtime_dir and _owned_and_not_writable_by_others(runtime_dir):
		candidates.append(os.path.join(runtime_dir, 'multiSSH3'))
	candidates.append(os.path.join(tempfile.gettempdir(), 'multiSSH3-{}'.format(user_id)))
	for directory in candidates:
		if _private_dir(directory, create):
			return directory
	return None

def _debug(message):
	'''Append a line to <cache dir>/complete.log when MSSH_COMPLETE_DEBUG=1 (kept under 256 KB).'''
	if os.environ.get('MSSH_COMPLETE_DEBUG') != '1':
		return
	directory = cache_dir()
	if directory is None:
		return
	path = os.path.join(directory, 'complete.log')
	try:
		if os.path.getsize(path) > 256 * 1024:
			with open(path, 'rb') as f:
				f.seek(-128 * 1024, os.SEEK_END)
				kept = f.read()
			with open(path, 'wb') as f:
				f.write(kept)
	except OSError:
		pass
	try:
		with os.fdopen(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), 'a') as f:
			f.write('{:.3f} {} {}\n'.format(time.time(), os.getpid(), message))
	except OSError:
		pass

#%% ------------ Index sources ----------------
def read_hosts_file(path):
	'''name -> address from a hosts file.'''
	hosts = {}
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			for line in f:
				fields = line.split('#', 1)[0].split()
				for name in fields[1:]:
					hosts.setdefault(name, fields[0])
	except OSError:
		pass
	return hosts

def read_ssh_config(path, base_dir, names, users, read):
	'''
	Add the Host names (no patterns) and User values of an ssh config file and the files it Includes.

	Args:
		path (str): The config file
		base_dir (str): Where relative Include paths start (~/.ssh or /etc/ssh)
		names (set), users (set): Filled in
		read (list): Paths read so far, appended to (also stops Include loops)
	'''
	import glob
	path = os.path.expanduser(path)
	if path in read or len(read) > 64:
		return
	try:
		f = open(path, encoding='utf-8', errors='replace')
	except OSError:
		return
	read.append(path)
	with f:
		for line in f:
			line = line.strip()
			if not line or line.startswith('#'):
				continue
			key, _, value = line.replace('=', ' ', 1).partition(' ')
			key = key.lower()
			value = value.strip()
			if key == 'host':
				for pattern in value.split():
					pattern = pattern.strip('"')
					if pattern and not any(char in pattern for char in '*?!'):
						names.add(pattern)
			elif key == 'user' and value:
				users.add(value.strip('"'))
			elif key == 'include':
				for pattern in value.split():
					pattern = os.path.expanduser(pattern.strip('"'))
					if not os.path.isabs(pattern):
						pattern = os.path.join(base_dir, pattern)
					for included in sorted(glob.glob(pattern)):
						read_ssh_config(included, base_dir, names, users, read)

def read_known_hosts(path):
	'''Host names in a known_hosts file; hashed entries and patterns are skipped.'''
	names = set()
	try:
		with open(os.path.expanduser(path), encoding='utf-8', errors='replace') as f:
			for line in f:
				fields = line.split()
				if fields and fields[0].startswith('@'):
					fields = fields[1:]
				if not fields or fields[0].startswith('#'):
					continue
				for entry in fields[0].split(','):
					if entry.startswith('|'):
						continue
					if entry.startswith('['):
						entry = entry[1:].split(']', 1)[0]
					if entry and not any(char in entry for char in '*?!'):
						names.add(entry)
	except OSError:
		pass
	return names

def read_arp():
	'''IPv4 addresses in the neighbour (ARP) table.'''
	addresses = set()
	try:
		with open('/proc/net/arp') as f:
			next(f, None)
			for line in f:
				fields = line.split()
				# IP address, HW type, Flags, HW address, ...: flags 0x0 is an incomplete entry
				if len(fields) >= 4 and fields[2] != '0x0':
					addresses.add(fields[0])
		return addresses
	except OSError:
		pass
	if sys.platform == 'darwin':
		import subprocess
		try:
			output = subprocess.run(['arp', '-an'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2).stdout
		except (OSError, subprocess.SubprocessError):
			return addresses
		for line in output.decode('utf-8', 'replace').splitlines():
			if '(' in line and ')' in line and 'incomplete' not in line:
				addresses.add(line.split('(', 1)[1].split(')', 1)[0])
	return addresses

def read_history(path, start=0):
	'''
	The complete lines of a history file from byte offset start.

	Returns:
		tuple: (lines, offset after the last complete line, inode or None)
	'''
	try:
		with open(path, 'rb') as f:
			inode = os.fstat(f.fileno()).st_ino
			f.seek(start)
			data = f.read()
	except OSError:
		return [], start, None
	cut = data.rfind(b'\n') + 1
	text = data[:cut].decode('utf-8', 'surrogateescape')
	return [line for line in text.split('\n') if line], start + cut, inode

def _is_ip(text):
	import ipaddress
	try:
		ipaddress.ip_address(text)
		return True
	except ValueError:
		return False

_ALIAS_VALUE_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-,[]@*?:$')

def collect_aliases(mssh, history_tokens, known):
	'''
	Host aliases: env file variables that look like host lists, and environment variables used as hosts.

	An env file variable counts when it was used as a host, when its value holds a "," or a
	range, or when everything it expands to is an IP address or a known host. Values with other
	characters (paths, prompts, ...) never count.

	Returns:
		dict: name -> (source, member host names)
	'''
	aliases = {}
	try:
		variables = mssh.readEnvFromFile()
	except Exception:
		variables = {}
	for name, value in variables.items():
		if not name.isidentifier() or not value or not set(value) <= _ALIAS_VALUE_CHARS:
			continue
		members = [member.split('@', 1)[-1] for member in mssh.expand_hostnames_local([name])[0]]
		if not members or members == [name]:
			continue
		if name in history_tokens or ',' in value or '[' in value or all(_is_ip(member) or member in known for member in members):
			aliases[name] = ('env_file', members)
	for name in history_tokens:
		if name in aliases or not name.isidentifier() or name not in os.environ:
			continue
		members = [member.split('@', 1)[-1] for member in mssh.expand_hostnames_local([name])[0]]
		if members and members != [name]:
			aliases[name] = ('env', members)
	return aliases

def file_signature(path):
	'''[path, inode, size, mtime_ns] of a file, or [path] if it cannot be read.'''
	try:
		st = os.stat(path)
	except OSError:
		return [path]
	return [path, str(st.st_ino), str(st.st_size), str(st.st_mtime_ns)]

def _import_mssh():
	'''Import multiSSH3, also when both files were copied somewhere by hand.'''
	here = os.path.dirname(os.path.abspath(__file__))
	if here not in sys.path:
		sys.path.insert(0, here)
	import multiSSH3
	return multiSSH3

#%% ------------ Building the index ----------------
MAX_RECORDS = 50000

def serialize_knowledge(memory):
	'''
	The features, records, postings and feature weight rows of the heaviest MAX_RECORDS records.

	Returns:
		tuple: (features, record rows, posting rows, fweights row)
	'''
	records = sorted(memory.records, key=lambda record: -record[0])[:MAX_RECORDS]
	features = sorted({feature for _, record_features in records for feature in record_features if safe_field(feature)})
	feature_id = {feature: number for number, feature in enumerate(features)}
	record_rows = []
	postings = [[] for _ in features]
	weights = [0.0] * len(features)
	for rid, (weight, record_features) in enumerate(records):
		ids = sorted(feature_id[feature] for feature in record_features if feature in feature_id)
		record_rows.append(['%.6g' % weight] + [str(number) for number in ids])
		for number in ids:
			postings[number].append(str(rid))
			weights[number] += weight
	return features, record_rows, postings, ['%.6g' % weight for weight in weights]

def build_index(directory, now=None, mssh=None):
	'''
	Read every source and write the index into directory.

	Returns:
		str: The index path
	'''
	now = time.time() if now is None else now
	mssh = mssh or _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	history_path = os.path.expanduser(mssh.DEFAULT_HISTORY_FILE)
	lines, offset, inode = read_history(history_path)
	memory = MemoryKnowledge()
	memory.add_history(lines, spec, now)
	features, record_rows, postings, fweights = serialize_knowledge(memory)
	history_tokens = {feature[2:] for feature in features if feature.startswith('t:')}
	hosts = {}
	def add(name, source, address=''):
		if not name or not safe_field(name) or any(char in name for char in ' \t,'):
			return
		entry = hosts.setdefault(name, [0, ''])
		entry[0] |= source
		if address and not entry[1]:
			entry[1] = address
	for name, address in read_hosts_file(mssh.DEFAULT_HOST_FILE).items():
		add(name, SRC_HOSTS_FILE, address)
	ssh_names, users, ssh_paths = set(), set(), []
	read_ssh_config('~/.ssh/config', os.path.expanduser('~/.ssh'), ssh_names, users, ssh_paths)
	read_ssh_config('/etc/ssh/ssh_config', '/etc/ssh', ssh_names, users, ssh_paths)
	for name in ssh_names:
		add(name, SRC_SSH_CONFIG)
	for name in read_known_hosts('~/.ssh/known_hosts'):
		add(name, SRC_KNOWN_HOSTS)
	for address in read_arp():
		add(address, SRC_ARP, address)
	aliases = collect_aliases(mssh, history_tokens, set(hosts) | history_tokens)
	for name in history_tokens:
		if name not in aliases and '[' not in name:
			add(name, SRC_HISTORY)
	for _, members in aliases.values():
		for member in members:
			add(member, SRC_ALIAS)
	names = sorted(hosts)
	host_number = {name: number for number, name in enumerate(names)}
	alias_names = sorted(aliases)
	alias_rows = [[aliases[name][0]] + [str(host_number[member]) for member in aliases[name][1] if member in host_number] for name in alias_names]
	group_rows = []
	for text in mssh.compact_hostnames_local(names):
		if '[' in text and safe_field(text):
			members = [host_number[member] for member in getattr(mssh, '__expand_hostname')(text, validate=False) if member in host_number]
			if len(members) > 1:
				group_rows.append([text] + [str(number) for number in sorted(members)])
	unavailable = []
	unavailable_path = mssh._unavailable_hosts_file_path(create=False)
	if unavailable_path:
		unavailable = sorted(name for name in mssh._read_unavailable_hosts_file(unavailable_path) if safe_field(name))
	env_files = [os.path.expanduser(os.path.expandvars(path)) for path in (mssh._env_files or mssh.DEFAULT_ENV_FILES)]
	sources = [history_path, mssh.DEFAULT_HOST_FILE, os.path.expanduser('~/.ssh/config'), '/etc/ssh/ssh_config',
		os.path.expanduser('~/.ssh/known_hosts')] + ssh_paths + env_files + [os.path.expanduser(path) for path in mssh.CONFIG_FILE_CHAIN]
	if unavailable_path:
		sources.append(unavailable_path)
	sources += [os.path.abspath(mssh.__file__), os.path.abspath(__file__)]
	seen = set()
	source_rows = []
	for path in sources:
		if path not in seen and safe_field(path):
			seen.add(path)
			source_rows.append(file_signature(path))
	header = {
		'built': repr(now),
		'arp_at': repr(now),
		'engine': version,
		'mssh_version': str(getattr(mssh, 'version', '')),
		'history': history_path,
		'history_offset': str(offset),
		'history_ino': str(inode or ''),
	}
	sections = [
		('spec', spec.to_rows()),
		('config', [['users'] + sorted(user for user in users if safe_field(user))]),
		('sources', source_rows),
		('features', [features]),
		('fweights', [fweights]),
		('postings', postings),
		('records', record_rows),
		('host_names', [names]),
		('host_meta', [[str(hosts[name][0]), hosts[name][1]] for name in names]),
		('alias_names', [alias_names]),
		('aliases', alias_rows),
		('groups', group_rows),
		('unavailable', [unavailable]),
	]
	path = os.path.join(directory, INDEX_NAME)
	write_nsv(path, header, sections)
	return path

#%% ------------ Freshness ----------------
TAIL_LIMIT_BYTES = 64 * 1024
TAIL_LIMIT_ENTRIES = 500
ARP_TTL = 300.0
LOCK_NAME = 'complete-index.lock'
LOCK_STALE = 60.0
FIRST_BUILD_BUDGET = 2.0

def check_freshness(index, now):
	'''
	Whether the index still matches its sources.

	Returns:
		tuple: ('fresh' | 'tail' | 'rebuild', history lines appended since the index was built).
			With 'tail' the appended lines are few enough to merge in memory.
	'''
	history = index.header.get('history', '')
	for number in range(index.count('sources')):
		row = index.row('sources', number)
		if row and row[0] != history and file_signature(row[0]) != row:
			return 'rebuild', []
	try:
		if now - float(index.header.get('arp_at', '0')) > ARP_TTL:
			return 'rebuild', []
	except ValueError:
		return 'rebuild', []
	try:
		offset = int(index.header.get('history_offset', '0'))
	except ValueError:
		return 'rebuild', []
	try:
		st = os.stat(history)
	except OSError:
		return ('rebuild', []) if offset else ('fresh', [])
	if str(st.st_ino) != index.header.get('history_ino', '') and offset:
		return 'rebuild', []
	if st.st_size < offset:
		return 'rebuild', []
	if st.st_size == offset:
		return 'fresh', []
	if st.st_size - offset > TAIL_LIMIT_BYTES:
		return 'rebuild', []
	lines, _, _ = read_history(history, offset)
	if len(lines) > TAIL_LIMIT_ENTRIES:
		return 'rebuild', []
	return 'tail', lines

def take_lock(path, now=None):
	'''Create the rebuild lock file, or return False if another rebuild holds it (and it is not stale).'''
	now = time.time() if now is None else now
	for _ in range(2):
		try:
			fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
		except FileExistsError:
			try:
				age = now - os.stat(path).st_mtime
			except OSError:
				continue
			if age < LOCK_STALE:
				return False
			try:
				os.unlink(path)
			except OSError:
				pass
			continue
		except OSError:
			return False
		with os.fdopen(fd, 'w') as f:
			f.write('{} {}\n'.format(os.getpid(), int(now)))
		return True
	return False

def spawn_rebuild(directory):
	'''Start a detached `rebuild` unless one is running. Returns whether one was started.'''
	lock = os.path.join(directory, LOCK_NAME)
	if not take_lock(lock):
		return False
	import subprocess
	try:
		subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), 'rebuild', '--lock', lock],
			stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
			close_fds=True, start_new_session=True, cwd='/')
	except OSError as e:
		_debug('cannot start rebuild: {!r}'.format(e))
		try:
			os.unlink(lock)
		except OSError:
			pass
		return False
	return True

def _load_index(path):
	try:
		return NsvIndex.load(path)
	except (OSError, IndexCorrupt, ValueError) as e:
		_debug('index not usable: {!r}'.format(e))
		return None

def load_for_query(directory, now):
	'''
	The index to answer from and the history lines it is missing.

	Starts a rebuild when the index is stale, and waits up to FIRST_BUILD_BUDGET for the first one.

	Returns:
		tuple: (NsvIndex or None, history tail lines)
	'''
	path = os.path.join(directory, INDEX_NAME)
	index = _load_index(path)
	if index is None:
		spawn_rebuild(directory)
		until = time.monotonic() + FIRST_BUILD_BUDGET
		while index is None and time.monotonic() < until:
			time.sleep(0.05)
			if os.path.exists(path):
				index = _load_index(path)
		if index is None:
			return None, []
	state, tail = check_freshness(index, now)
	if state == 'rebuild':
		spawn_rebuild(directory)
	return index, tail

#%% ------------ Command line ----------------
def _cmd_rebuild(args):
	lock = args[1] if len(args) == 2 and args[0] == '--lock' else None
	try:
		directory = cache_dir()
		if directory is None:
			print('mssh-complete: no private cache directory', file=sys.stderr)
			return 1
		print(build_index(directory))
		return 0
	except Exception as e:
		_debug('rebuild failed: {!r}'.format(e))
		print('mssh-complete: rebuild failed: {!r}'.format(e), file=sys.stderr)
		return 1
	finally:
		if lock:
			try:
				os.unlink(lock)
			except OSError:
				pass

def main(argv=None):
	argv = sys.argv[1:] if argv is None else argv
	command = argv[0] if argv else ''
	if command == 'rebuild':
		return _cmd_rebuild(argv[1:])
	if command in ('-V', '--version'):
		print('mssh-complete {} (protocol {})'.format(version, PROTOCOL))
		return 0
	print('usage: mssh-complete rebuild', file=sys.stderr)
	return 2

if __name__ == '__main__':
	sys.exit(main())
````

In `setup.py`, replace this text (it occurs exactly once):

````python
            'multiSSH3=multiSSH3:main',
````

with:

````python
            'multiSSH3=multiSSH3:main',
            'mssh-complete=mssh_complete:main',
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_index.py -q`

Expected: `15 passed`

- [ ] **Step 5: Commit**

````bash
git add tests/test_complete_index.py mssh_complete.py setup.py
git commit -m "feat: build the completion index in the background from every host source

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 8: Engine, protocol and the query command
**Files:**
- Modify: `mssh_complete.py` (insert sections Engine, Protocol before Command line; extend the CLI)
- Create: `tests/test_complete_engine.py`

**Interfaces:**
- Consumes: everything from Tasks 3-7
- Produces: `PRIOR`, `GROUP_THRESHOLD`, `UNAVAILABLE_PENALTY`, `SHELL_WEIGHT`, `MAX_CANDIDATES`, `MAGIC_STRINGS`; `Request(shell, before, after="", word=None, shell_version="", flags=None, history=())`; `Candidate(text, description="", group="", score=0.0)`; `Response(context=None)` with `candidates`, `directives` (set), `delegate` ((index, prefix, words) or None), `ghost` (None), `diagnostics` ([]); `shell_history_knowledge(lines, spec)`; `Engine(spec, knowledges=(), hosts=None, users=())` with `.query(request, deadline=None) -> Response`; `parse_request(data: bytes) -> Request` (raises ValueError); `format_response(response, nul=True) -> bytes`; `answer(request, deadline=None, directory=Ellipsis, now=None) -> Response` (directory None: degraded); CLI `query`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_engine.py` with exactly this content:

````python
import os
import subprocess
import sys
from pathlib import Path

import pytest

import multiSSH3
import mssh_complete as mc

ENGINE = [sys.executable, '-I', str(Path(__file__).resolve().parents[1] / 'mssh_complete.py')]

SPEC = mc.spec_from_parser(multiSSH3.get_parser())
NOW = 1790000000


def memory(lines):
	knowledge = mc.MemoryKnowledge()
	knowledge.add_history(lines, SPEC, NOW)
	return knowledge


def line(ts, options, hosts, command):
	return '{}\t/x/multiSSH3.py\t{}\t{}\t{}'.format(ts, options, hosts, command)


HISTORY = [line(NOW - 100 * number, '-su -u=root', 'gpu[01-16]', '"nvidia-smi"') for number in range(5)]
HISTORY += [line(NOW - 50 * number, '-su', 'login1', '"uptime"') for number in range(9)]
HISTORY += [line(NOW - 30, '-su -u=admin', 'storage1', '"df -h /data"')]


def texts(response):
	return [candidate.text for candidate in response.candidates]


def query(before, after='', word=None, shell='bash', knowledges=None, hosts=None, flags=None):
	if word is None:
		word = '' if before.endswith(' ') else before.split(' ')[-1]
	engine = mc.Engine(SPEC, [memory(HISTORY)] if knowledges is None else knowledges, hosts)
	return engine.query(mc.Request(shell, before, after, word, flags=flags))


def test_context_beats_global_frequency():
	# uptime was run more often overall, but on gpu hosts it is nvidia-smi
	assert texts(query('mssh gpu[01-16] "', word=''))[0] == 'nvidia-smi'
	assert texts(query('mssh login1 "', word=''))[0] == 'uptime'


def test_backtracking_uses_the_command_after_the_cursor():
	assert texts(query('mssh ', " 'nvidia-smi'"))[0] == 'gpu[01-16]'
	assert texts(query('mssh ', " 'df -h /data'"))[0] == 'storage1'


def test_values_ranked_by_context():
	assert texts(query('mssh -u ', ' storage1 "df -h /data"'))[0] == 'admin'
	assert texts(query('mssh -u ', ' gpu[01-16]'))[0] == 'root'


def test_every_bash_candidate_extends_the_word():
	for before in ('mssh ', 'mssh g', 'mssh -', 'mssh --n', 'mssh -u r', 'mssh login1 "u', 'mssh login1 up', 'mssh -f=/et'):
		response = query(before)
		word = '' if before.endswith(' ') else before.split(' ')[-1]
		if '"' in word:
			word = word.split('"', 1)[1]
		if '=' in word:
			word = word.split('=', 1)[1]
		assert all(text.startswith(word) for text in texts(response)), before


def test_bash_options_show_long_forms():
	assert set(texts(query('mssh --no_'))) == {'--no_env', '--no_history', '--no_output', '--no_watch', '--no_skip_unreachable'}
	assert set(texts(query('mssh -n'))) == {'-nw', '-nh', '-nsu', '-no'}
	assert '-nw' in texts(query('mssh -n', shell='zsh'))


def test_used_options_are_hidden():
	assert '--no_watch' not in texts(query('mssh -q --no_'))
	assert '--no_skip_unreachable' not in texts(query('mssh -x --no_'))


def test_passwords_are_never_completed():
	response = query('mssh -p ')
	assert texts(response) == [] and 'nodefault' in response.directives


def test_path_options_ask_for_files():
	assert 'files' in query('mssh -f ').directives
	assert 'files' in query('mssh -fs ').directives


def test_hosts_complete_the_last_segment():
	assert texts(query('mssh storage1,root@lo'))[0] == 'storage1,root@login1'


def test_magic_strings():
	assert texts(query('mssh h "echo #HO', word='echo #HO')) == ['echo #HOST#', 'echo #HOSTNAME#']


def test_unquoted_command_words():
	assert texts(query('mssh login1 up')) == ['uptime']
	response = query('mssh login1 systemctl rest')
	assert response.delegate == (1, '', ['systemctl', 'rest'])


def test_quoted_command_delegates_with_prefix():
	assert query('mssh h "cat x | gre', word='cat x | gre').delegate == (0, 'cat x | ', ['gre'])


def test_bash_escapes_unquoted_specials():
	knowledge = memory([line(NOW, '-su', 'h', '"date;"')])
	assert texts(query('mssh h da', knowledges=[knowledge])) == [r'date\;']


def test_bash_drops_candidates_that_would_break_the_quote():
	knowledge = memory([line(NOW, '-su', 'h', "'echo \"x\"'"), line(NOW, '-su', 'h', '"echo y"')])
	assert texts(query('mssh h "ech', word='ech', knowledges=[knowledge])) == ['echo y']


def test_word_that_does_not_end_the_parsed_text_gets_nothing():
	assert texts(query('mssh login1 up', word='zz')) == []


def test_zsh_and_fish_words_are_dequoted():
	assert texts(query('mssh gpu[01-16] "nv', word='"nv', shell='fish')) == ['nvidia-smi']


def _host_table(tmp_path, names, aliases=(), groups=(), unavailable=()):
	path = str(tmp_path / 'hosts.nsv')
	number = {name: index for index, name in enumerate(sorted(names))}
	mc.write_nsv(path, {}, [
		('host_names', [sorted(names)]),
		('alias_names', [sorted(name for name, _ in aliases)]),
		('aliases', [['env_file'] + [str(number[member]) for member in members] for _, members in sorted(aliases)]),
		('groups', [[text] + [str(number[member]) for member in members] for text, members in groups]),
		('unavailable', [list(unavailable)]),
	])
	return mc.HostTable(mc.NsvIndex.load(path))


def test_many_hosts_are_grouped(tmp_path):
	names = ['node{:04d}'.format(number) for number in range(1, 2001)]
	table = _host_table(tmp_path, names)
	assert texts(query('mssh no', knowledges=[], hosts=table)) == ['node[0001-2000]']
	narrowed = texts(query('mssh node00', knowledges=[], hosts=table))
	assert narrowed == ['node00[01-99]']
	assert len(texts(query('mssh node000', knowledges=[], hosts=table))) == 9


def test_build_time_groups_are_used_when_they_fit(tmp_path):
	names = ['rack{}-n{}'.format(rack, node) for rack in (1, 2) for node in range(1, 31)]
	groups = [('rack[1-2]-n[1-30]', names)]
	table = _host_table(tmp_path, names, groups=groups)
	assert texts(query('mssh ra', knowledges=[], hosts=table)) == ['rack[1-2]-n[1-30]']


def test_aliases_and_unavailable_hosts(tmp_path):
	table = _host_table(tmp_path, ['a1', 'a2', 'ab'], aliases=[('abc', ['a1', 'a2'])], unavailable=['ab'])
	candidates = query('mssh a', knowledges=[], hosts=table).candidates
	assert [candidate.text for candidate in candidates][0] == 'abc'
	assert candidates[-1].text == 'ab' and candidates[-1].description == 'unreachable recently'


def test_skip_hosts_prefers_members_of_the_hosts_argument(tmp_path):
	table = _host_table(tmp_path, ['n1', 'n2', 'n3', 'm1'])
	assert texts(query('mssh n[2-3] -X ', knowledges=[], hosts=table))[:2] == ['n2', 'n3']


def test_protocol_round_trip():
	request = mc.parse_request(b'MSSHC1\0bash\x005.2\0nosort=1 icase=0\0mssh gp\0 x\0gp\0hist one\nhist two\n')
	assert (request.shell, request.flags, request.before, request.after, request.word, request.history) == ('bash', {'nosort': '1', 'icase': '0'}, 'mssh gp', ' x', 'gp', ['hist one', 'hist two'])
	response = mc.Response()
	response.candidates = [mc.Candidate('gpu1', 'a\tb', 'hosts')]
	response.directives = {'nosort'}
	response.delegate = (0, '', [''])
	assert mc.format_response(response) == b'MSSHC1\nD nosort\nC gpu1\ta b\thosts\nX 0\t\t\nE\n\0'
	assert mc.format_response(response, nul=False).endswith(b'E\n')


@pytest.mark.parametrize('data', [b'', b'MSSHC2\0bash\0\0\0a\0\0\0', b'MSSHC1\0bash'])
def test_bad_requests_are_rejected(data):
	with pytest.raises(ValueError):
		mc.parse_request(data)


def test_query_command_end_to_end(tmp_path):
	runtime = tmp_path / 'runtime'
	runtime.mkdir(mode=0o700)
	(tmp_path / '.mssh_history').write_text(''.join(entry + '\n' for entry in HISTORY))
	env = dict(os.environ, HOME=str(tmp_path), XDG_RUNTIME_DIR=str(runtime))
	request = b'MSSHC1\0bash\x005.2\0nosort=1\0mssh gpu[01-16] "\0\0\0'
	result = subprocess.run(ENGINE + ['query'], input=request, env=env, stdout=subprocess.PIPE, timeout=60)
	assert result.returncode == 0
	assert result.stdout.startswith(b'MSSHC1\nD nosort\nC nvidia-smi\t')
	assert result.stdout.endswith(b'\nE\n\0')


def test_query_command_rejects_garbage(tmp_path):
	result = subprocess.run(ENGINE + ['query'], input=b'hello', stdout=subprocess.PIPE, timeout=60)
	assert result.returncode == 1 and result.stdout == b''


def test_shell_history_ranks_below_mssh_history():
	shell = mc.shell_history_knowledge(['mssh gpu[01-16] "nvidia-smi -q"', 'ls -la', 'nvim notes'], SPEC)
	ranked = texts(query('mssh gpu[01-16] "nvidia', word='nvidia', knowledges=[memory(HISTORY), shell]))
	assert ranked == ['nvidia-smi', 'nvidia-smi -q']
	assert texts(query('mssh h "nv', word='nv', knowledges=[shell])) == ['nvidia-smi -q', 'nvim notes']


def test_quoted_option_values():
	assert texts(query('mssh -u "ro', word='ro')) == ['root']


def test_degraded_mode_without_an_index():
	response = mc.answer(mc.Request('bash', 'mssh --no_w', '', '--no_w', history=['mssh login9 "uptime"']), directory=None)
	assert texts(response) == ['--no_watch']
	assert texts(mc.answer(mc.Request('bash', 'mssh log', '', 'log', history=['mssh login9 "uptime"']), directory=None)) == ['login9']
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_engine.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'Engine'` (`29 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Command line ----------------` (the line itself stays):

````python
#%% ------------ Engine ----------------
PRIOR = 0.001              # score of a candidate that nothing in history supports
GROUP_THRESHOLD = 50       # list single hosts once a prefix matches at most this many
UNAVAILABLE_PENALTY = 0.5  # score factor for hosts mssh found unreachable
SHELL_WEIGHT = 0.25        # weight of a shell history line next to an mssh history use
MAX_CANDIDATES = 200
MAGIC_STRINGS = ('#HOST#', '#HOSTNAME#', '#USER#', '#USERNAME#', '#ID#', '#I#', '#UUID#', '#RESOLVEDNAME#', '#IP#')
COMPLETION_ACTIONS = ('bash', 'zsh', 'fish', 'install', 'uninstall')
ENCODINGS = ('utf-8', 'latin-1', 'ascii', 'utf-16', 'cp1252')
# characters bash would read specially in an unquoted word (globs are left alone: mssh takes ranges)
_BASH_SPECIAL = frozenset(' \t"\'\\$`|&;<>()!')

class Request(object):
	'''A completion request: the shell, its capability flags, the line split at the cursor, the word to replace.'''
	__slots__ = ('shell', 'shell_version', 'flags', 'before', 'after', 'word', 'history')

	def __init__(self, shell, before, after='', word=None, shell_version='', flags=None, history=()):
		self.shell = shell
		self.shell_version = shell_version
		self.flags = dict(flags or {})
		self.before = before
		self.after = after
		self.word = word
		self.history = list(history)

class Candidate(object):
	__slots__ = ('text', 'description', 'group', 'score')

	def __init__(self, text, description='', group='', score=0.0):
		self.text = text
		self.description = description
		self.group = group
		self.score = score

	def __repr__(self):
		return 'Candidate({!r}, {!r}, {!r}, {:.4g})'.format(self.text, self.description, self.group, self.score)

class Response(object):
	'''
	The answer to a request.

	candidates are replacements for the request's word, best first. delegate is
	(word index, prefix, words) when the shell should add its own completion of a remote
	command. ghost (SP2) and diagnostics (SP3) are not filled in yet.
	'''
	__slots__ = ('context', 'candidates', 'directives', 'delegate', 'ghost', 'diagnostics')

	def __init__(self, context=None):
		self.context = context
		self.candidates = []
		self.directives = set()
		self.delegate = None
		self.ghost = None
		self.diagnostics = []

def shell_history_knowledge(lines, spec):
	'''The shell's history as weak records: mssh lines like mssh history, other lines as local commands.'''
	memory = MemoryKnowledge()
	count = len(lines)
	for position, line in enumerate(lines):
		line = line.strip()
		tokens = lex(line) if line else []
		if not tokens:
			continue
		if os.path.basename(tokens[0].text) in MSSH_NAMES:
			features = line_features(tokens[1:], spec)
		else:
			features = command_features(line)
		if features:
			memory.add(features, SHELL_WEIGHT * 0.998 ** (count - 1 - position))
	return memory

def _shell_word(request):
	'''The request's word as the engine compares it: zsh and fish send it quoted as typed.'''
	if request.word is None:
		return None
	if request.shell in ('zsh', 'fish'):
		tokens = lex(request.word)
		return tokens[0].text if len(tokens) == 1 else ('' if not tokens else request.word)
	return request.word

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
			return response
		if context.slot == SLOT_OPTION:
			candidates = self._options(context, request.shell)
		elif context.slot == SLOT_VALUE:
			candidates = self._values(context, response, deadline)
		elif context.slot == SLOT_HOSTS:
			candidates = self._hosts(context.value, context, deadline)
		else:
			candidates = self._commands(context, response, deadline)
		if request.flags.get('nosort') == '1':
			response.directives.add('nosort')
		response.candidates = self._frame(candidates, context, request)
		return response

	def _frame(self, candidates, context, request):
		'''Turn slot values into replacements for the shell's word, best first, without duplicates.'''
		word = _shell_word(request)
		prefix = context.prefix
		if word is None:
			word = prefix
		if not prefix.endswith(word):
			# the shell's word is not the end of what was parsed (e.g. backslash escapes): offer nothing
			return []
		base = prefix[:len(prefix) - len(word)]
		lead = prefix[:context.value_start]
		out = []
		seen = set()
		for candidate in sorted(candidates, key=lambda candidate: (-candidate.score, candidate.text)):
			full = lead + candidate.text
			if not full.startswith(prefix) or full in seen:
				continue
			rest = full[len(prefix):]
			if request.shell == 'bash':
				if context.open_quote == '"' and any(char in rest for char in '"\\$`'):
					continue
				if context.open_quote in ("'", "$'") and "'" in rest:
					continue
				if not context.open_quote:
					rest = _bash_escape(rest)
			if '\t' in rest or '\n' in rest:
				continue
			seen.add(full)
			out.append(Candidate(full[len(base):len(prefix)] + rest, candidate.description, candidate.group, candidate.score))
			if len(out) >= MAX_CANDIDATES:
				break
		return out

	def _options(self, context, shell):
		word = context.prefix
		used = {option.dest for option, _ in context.options if not option.repeat}
		groups = {option.group for option, _ in context.options if option.group}
		scores = score_features(self.knowledges, 'o:', context.features)
		out = []
		for option in self.spec.options:
			if option.dest in used or (option.group and option.group in groups):
				continue
			score = scores.get('o:' + option.long, 0.0) + PRIOR
			if shell == 'bash' and (word in ('', '-') or word.startswith('--')):
				strings = [option.long]
			elif shell == 'bash':
				strings = [string for string in option.strings if not string.startswith('--')]
			else:
				strings = option.strings
			for string in strings:
				if string.startswith(word):
					out.append(Candidate(string, option.help, 'options', score))
		return out

	def _values(self, context, response, deadline):
		option = context.option
		dest = option.dest
		word = context.value
		if dest in PASSWORD_DESTS:
			response.directives.add('nodefault')
			return []
		lead = 'v:{}='.format(dest)
		out = [Candidate(feature[len(lead):], 'used before', 'history', score)
			for feature, score in score_features(self.knowledges, lead + word, context.features, deadline).items()]
		if dest in PATH_DESTS:
			response.directives.add('files')
		elif dest == 'identity_file':
			response.directives.add('files')
			out.extend(self._key_files(word))
		elif dest in USER_DESTS:
			users = set(self.users)
			if os.environ.get('USER'):
				users.add(os.environ['USER'])
			out.extend(Candidate(user, 'user', 'users', PRIOR) for user in users if user.startswith(word))
		elif dest == 'skip_hosts':
			out.extend(self._hosts(word, context, deadline, boost=self._members(context.hosts)))
		elif dest == 'completion':
			out.extend(Candidate(action, '', 'values', PRIOR) for action in COMPLETION_ACTIONS if action.startswith(word))
		elif dest == 'encoding':
			out.extend(Candidate(name, '', 'values', PRIOR) for name in ENCODINGS if name.startswith(word))
		if option.default and option.default.startswith(word):
			out.append(Candidate(option.default, 'default', 'defaults', PRIOR / 2))
		return out

	def _key_files(self, word):
		directory = os.path.expanduser('~/.ssh')
		try:
			entries = os.listdir(directory)
		except OSError:
			return []
		out = []
		for name in sorted(entries):
			if name.endswith('.pub') or not (name.startswith('id_') or name + '.pub' in entries):
				continue
			text = '~/.ssh/' + name
			if text.startswith(word):
				out.append(Candidate(text, 'key', 'keys', PRIOR))
		return out

	def _members(self, hosts_text):
		'''The host names a hosts argument names, as far as the index knows them (aliases, number ranges).'''
		members = set()
		for word in split_hosts(hosts_text or ''):
			word = word.rpartition('@')[2]
			alias = self.hosts.alias_index(word)
			if alias is not None:
				members.update(self.hosts.alias_members(alias))
			else:
				members.update(expand_ranges(word))
		return members

	def _hosts(self, text, context, deadline, boost=frozenset()):
		'''Candidates for a hosts argument whose text so far is text: complete its last host.'''
		head, comma, segment = text.rpartition(',')
		user, at, host_prefix = segment.rpartition('@')
		lead = head + comma + user + at
		scores = {}
		for feature, score in score_features(self.knowledges, 't:' + host_prefix, context.features, deadline).items():
			scores[feature[2:]] = score
		out = []
		if not comma and not at:
			for feature, score in score_features(self.knowledges, 'h:' + segment, context.features, deadline).items():
				if feature[2:] not in scores:
					out.append(Candidate(feature[2:], 'used before', 'history', score))
		aliases = set()
		for number, name in self.hosts.aliases_with_prefix(host_prefix):
			aliases.add(name)
			out.append(Candidate(lead + name, 'alias, {} hosts'.format(self.hosts.alias_size(number)), 'aliases', scores.get(name, 0.0) + 2 * PRIOR))
		names = set(self.hosts.names_with_prefix(host_prefix))
		names.update(name for name in scores if name.startswith(host_prefix) and '[' not in name)
		names -= aliases
		unavailable = self.hosts.unavailable
		def host_score(name):
			score = scores.get(name, 0.0) + PRIOR
			if name in boost:
				score += 1.0
			if name in unavailable:
				score *= UNAVAILABLE_PENALTY
			return score
		def single(name):
			return Candidate(lead + name, 'unreachable recently' if name in unavailable else '', 'hosts', host_score(name))
		# host groups typed before, e.g. node[1-3]
		for name, score in scores.items():
			if '[' in name and name not in aliases:
				out.append(Candidate(lead + name, 'used before', 'groups', score))
		if len(names) <= GROUP_THRESHOLD:
			out.extend(single(name) for name in names)
			return out
		covered = set()
		for group_text, members in self.hosts.groups():
			if group_text.startswith(host_prefix) and len(members) > 1 and names.issuperset(members):
				covered.update(members)
				out.append(Candidate(lead + group_text, '{} hosts'.format(len(members)), 'groups', sum(host_score(member) for member in members)))
		rest = names - covered
		if len(rest) <= GROUP_THRESHOLD:
			out.extend(single(name) for name in rest)
		else:
			for group_text in compact_names(rest):
				members = expand_ranges(group_text)
				description = '{} hosts'.format(len(members)) if len(members) > 1 else ''
				out.append(Candidate(lead + group_text, description, 'groups' if len(members) > 1 else 'hosts', sum(host_score(member) for member in members)))
			used = sorted((name for name in names if scores.get(name)), key=lambda name: -scores[name])[:20]
			out.extend(single(name) for name in used)
		return out

	def _commands(self, context, response, deadline):
		word = context.prefix
		out = []
		if context.mode in ('sync', 'gather'):
			response.directives.add('files')
		if word.count('#') % 2 == 1:
			at = word.rfind('#')
			for magic in MAGIC_STRINGS:
				if magic.startswith(word[at:]):
					out.append(Candidate(word[:at] + magic, 'replaced per host', 'magic', 1e6))
		if context.mode in PATH_MODES:
			for feature, score in score_features(self.knowledges, 'f:' + word, context.features, deadline).items():
				out.append(Candidate(feature[2:], 'used before', 'history', score))
		elif context.quoted:
			for feature, score in score_features(self.knowledges, 'c:' + word, context.features, deadline).items():
				out.append(Candidate(feature[2:], '', 'history', score))
		elif context.command_words:
			typed = context.command_words[:-1]
			partial = context.command_words[-1]
			if not typed:
				for feature, score in score_features(self.knowledges, 'p:' + partial, context.features, deadline).items():
					out.append(Candidate(feature[2:], '', 'history', score))
			else:
				following = {}
				for feature, score in score_features(self.knowledges, 'c:' + ' '.join(typed) + ' ' + partial, context.features, deadline).items():
					words = [token.text for token in lex(feature[2:])]
					if len(words) > len(typed) and words[:len(typed)] == typed and words[len(typed)].startswith(partial):
						following[words[len(typed)]] = following.get(words[len(typed)], 0.0) + score
				out.extend(Candidate(text, '', 'history', score) for text, score in following.items())
		if context.mode == 'plain' and context.command_words is not None:
			response.delegate = (context.command_word_index, context.command_prefix, list(context.command_words))
		return out

#%% ------------ Protocol ----------------
def parse_request(data):
	'''
	Parse a request: MSSHC1\\0shell\\0version\\0flags\\0before\\0after\\0word\\0 then history lines.

	Raises:
		ValueError: not a request of this protocol
	'''
	text = data.decode('utf-8', 'surrogateescape')
	parts = text.split('\0', 7)
	if len(parts) < 8 or parts[0] != PROTOCOL:
		raise ValueError('not an {} request'.format(PROTOCOL))
	flags = {}
	for flag in parts[3].split():
		key, _, value = flag.partition('=')
		flags[key] = value
	history = [line for line in parts[7].split('\n') if line.strip()]
	return Request(parts[1], parts[4], parts[5], parts[6], parts[2], flags, history)

def _clean(text):
	return ' '.join(str(text).split())

def format_response(response, nul=True):
	'''
	The response text: MSSHC1, a D line of directives, C lines (text\\tdescription\\tgroup), an X
	line for delegation, then E, and a NUL unless nul is False.
	'''
	lines = [PROTOCOL]
	if response.directives:
		lines.append('D ' + ' '.join(sorted(response.directives)))
	for candidate in response.candidates:
		if safe_field(candidate.text) and '\t' not in candidate.text:
			lines.append('C {}\t{}\t{}'.format(candidate.text, _clean(candidate.description), candidate.group))
	if response.delegate is not None:
		index, prefix, words = response.delegate
		fields = [str(index), prefix] + list(words)
		if all(safe_field(field) and '\t' not in field for field in fields):
			lines.append('X ' + '\t'.join(fields))
	lines.append('E')
	return ('\n'.join(lines) + '\n' + ('\0' if nul else '')).encode('utf-8', 'surrogateescape')

def answer(request, deadline=None, directory=Ellipsis, now=None):
	'''
	Answer a request from the index in directory: mssh's cache dir by default, None for no index
	(degraded: options from mssh's parser, shell history, no ranking from mssh history).
	'''
	now = time.time() if now is None else now
	if directory is Ellipsis:
		directory = cache_dir()
	index, tail = (None, []) if directory is None else load_for_query(directory, now)
	knowledges = []
	users = ()
	if index is not None:
		spec = ParserSpec.from_rows([index.row('spec', number) for number in range(index.count('spec'))])
		knowledges.append(SnapshotKnowledge(index, now))
		config = {row[0]: row[1:] for row in (index.row('config', number) for number in range(index.count('config'))) if row}
		users = config.get('users', ())
	else:
		# degraded: no index, so options come from mssh's parser and history is not ranked
		spec = spec_from_parser(_import_mssh().get_parser())
	if tail:
		memory = MemoryKnowledge()
		memory.add_history(tail, spec, now)
		knowledges.append(memory)
	if request.history:
		# fish lists its history newest first, the others oldest first
		history = request.history[::-1] if request.shell == 'fish' else request.history
		knowledges.append(shell_history_knowledge(history, spec))
	return Engine(spec, knowledges, HostTable(index), users).query(request, deadline)

````

In `mssh_complete.py`, insert this text immediately before the line that starts with `def _cmd_rebuild(args):` (the line itself stays):

````python
def _cmd_query():
	deadline = time.monotonic() + float(os.environ.get('MSSH_COMPLETE_SOFT_DEADLINE', '0.2'))
	data = sys.stdin.buffer.read() if hasattr(sys.stdin, 'buffer') else sys.stdin.read().encode('utf-8', 'surrogateescape')
	try:
		request = parse_request(data)
	except ValueError as e:
		_debug('bad request: {}'.format(e))
		return 1
	try:
		response = answer(request, deadline)
	except Exception as e:
		_debug('query failed: {!r}'.format(e))
		return 1
	sys.stdout.buffer.write(format_response(response, nul=request.flags.get('nul', '1') != '0'))
	sys.stdout.buffer.flush()
	return 0

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	command = argv[0] if argv else ''
	if command == 'rebuild':
````

with:

````python
	command = argv[0] if argv else ''
	if command == 'query':
		return _cmd_query()
	if command == 'rebuild':
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	print('usage: mssh-complete rebuild', file=sys.stderr)
````

with:

````python
	print('usage: mssh-complete query | rebuild', file=sys.stderr)
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_engine.py -q`

Expected: `29 passed`

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `640 passed`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_engine.py mssh_complete.py
git commit -m "feat: completion engine and the MSSHC1 query command

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 9: Shell glue for bash, zsh and fish
**Files:**
- Modify: `mssh_complete.py` (insert section Shell glue before Command line)
- Create: `tests/complete_shell_harness.py`
- Create: `tests/test_complete_shells.py`

**Interfaces:**
- Consumes: `SHELLS`, `version` (Task 3); the `query` command (Task 8)
- Produces: `GLUE_MARK = "MSSH_COMPLETE_GLUE"`; `BASH_GLUE`, `ZSH_GLUE`, `FISH_GLUE` templates with `@VERSION@` and `@ENGINE@`; `engine_command() -> list`; `render_glue(shell, command=None) -> str` (raises ValueError for other shells). Bash functions `_mssh_complete`, `_mssh_complete_delegate`, `_mssh_complete_split`, `_mssh_complete_slice`; zsh function `_mssh`; fish function `__mssh_complete`. Test harness: `REPO`, `ENGINE`, `require_shell(name)`, `make_home(tmp_path, history_lines=()) -> (env, home)`, `build_index(env)`, `Session` (`read_until`, `send`, `line_after(typed, keys="\t")`, `close`), `bash_session(home, env, glue, bash_completion=True)`, `zsh_session(home, env, glue)`, `fish_complete(env, glue, line) -> [(text, description)]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/complete_shell_harness.py` with exactly this content:

````python
'''Drive real shells for the autocomplete tests: a pseudo-terminal session, or a direct call.'''
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ENGINE = [sys.executable, '-I', str(REPO / 'mssh_complete.py')]

def require_shell(name):
	'''The path of shell name; skip the test if it is missing, unless MSSH_REQUIRE_SHELLS lists it.'''
	path = shutil.which(name)
	if path is None:
		required = [shell for shell in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(',') if shell]
		if name in required:
			pytest.fail('{} is required here (MSSH_REQUIRE_SHELLS) but not installed'.format(name))
		pytest.skip('{} is not installed'.format(name))
	return path

def make_home(tmp_path, history_lines=()):
	'''A private HOME and XDG_RUNTIME_DIR holding the given mssh history. Returns (env, home).'''
	home = tmp_path / 'home'
	runtime = tmp_path / 'runtime'
	home.mkdir()
	runtime.mkdir(mode=0o700)
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in history_lines))
	env = {
		'HOME': str(home), 'XDG_RUNTIME_DIR': str(runtime), 'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
		'TERM': 'xterm-256color', 'LANG': os.environ.get('LANG', 'C.UTF-8'), 'MSSH_COMPLETE_TIMEOUT': '5',
	}
	return env, home

def build_index(env):
	'''Build the index the engine will use for env, so a test does not wait for the first build.'''
	subprocess.run(ENGINE + ['rebuild'], env=env, stdout=subprocess.DEVNULL, check=True, timeout=60)

class Session(object):
	'''An interactive shell on a pseudo-terminal.'''
	def __init__(self, argv, env, cwd=None):
		self.pid, self.fd = pty.fork()
		if self.pid == 0:
			if cwd:
				os.chdir(str(cwd))
			os.execvpe(argv[0], argv, env)
		self.output = b''

	def read_until(self, marker, timeout=10.0):
		'''Read until marker (bytes) shows up after what was read so far; return the new output.'''
		start = len(self.output)
		end = time.monotonic() + timeout
		while marker not in self.output[start:] and time.monotonic() < end:
			ready, _, _ = select.select([self.fd], [], [], 0.05)
			if ready:
				try:
					chunk = os.read(self.fd, 65536)
				except OSError:
					break
				if not chunk:
					break
				self.output += chunk
		return self.output[start:].decode('utf-8', 'replace')

	def send(self, data):
		os.write(self.fd, data.encode('utf-8') if isinstance(data, str) else data)

	def line_after(self, typed, keys='\t', timeout=10.0):
		'''Type typed, press keys, then return the command line as the test binding (Ctrl-X Ctrl-P) prints it.'''
		self.send(typed + keys)
		time.sleep(0.3)
		self.send('\x18\x10')
		text = self.read_until(b']@@', timeout)
		start = text.rfind('@@LINE[')
		end = text.find(']@@', start)
		self.send('\x15')   # clear the line for the next case
		return text[start + 7:end] if start >= 0 and end > start else None

	def close(self):
		try:
			os.kill(self.pid, signal.SIGKILL)
			os.waitpid(self.pid, 0)
		except OSError:
			pass
		os.close(self.fd)

BASH_TEST_RC = r'''
PS1='@@READY@@ '
bind -x '"\C-x\C-p": printf "@@LINE[%s]@@\n" "$READLINE_LINE"'
{bash_completion}
# a command with its own completion, for delegation tests
_fakecmd() {{ COMPREPLY=($(compgen -W "alpha beta" -- "$2")); }}
complete -F _fakecmd fakecmd
[ -r {glue} ] && . {glue} 2>/dev/null
'''

ZSH_TEST_RC = r'''
PS1='@@READY@@ '
autoload -Uz compinit && compinit -u -D
_mssh_test_print() {{ print -r -- "@@LINE[$BUFFER]@@" }}
zle -N _mssh_test_print
bindkey '^X^P' _mssh_test_print
# a command with its own completion, for delegation tests
_fakecmd() {{ compadd alpha beta }}
compdef _fakecmd fakecmd
[[ -r {glue} ]] && source {glue} 2>/dev/null
'''

def bash_session(home, env, glue, bash_completion=True):
	rc = home / 'test.bashrc'
	loader = '. /usr/share/bash-completion/bash_completion 2>/dev/null' if bash_completion else ''
	rc.write_text(BASH_TEST_RC.format(bash_completion=loader, glue=glue))
	session = Session([require_shell('bash'), '--noprofile', '--rcfile', str(rc), '-i'], env, cwd=home)
	session.read_until(b'@@READY@@')
	return session

def zsh_session(home, env, glue):
	(home / '.zshrc').write_text(ZSH_TEST_RC.format(glue=glue))
	session = Session([require_shell('zsh'), '-i'], dict(env, ZDOTDIR=str(home)), cwd=home)
	session.read_until(b'@@READY@@')
	return session

def fish_complete(env, glue, line):
	'''Completions fish offers for line (complete -C), as (text, description) pairs.'''
	fish = require_shell('fish')
	# fakecmd: a command with its own completion, for delegation tests
	script = 'complete -c fakecmd -f -a "alpha beta"; source {}; complete -C{}'.format(glue, _fish_quote(line))
	output = subprocess.run([fish, '--no-config', '-c', script], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	pairs = []
	for row in output.stdout.decode('utf-8', 'replace').splitlines():
		text, _, description = row.partition('\t')
		pairs.append((text, description))
	return pairs

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"
````

Create `tests/test_complete_shells.py` with exactly this content:

````python
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, bash_session, build_index, fish_complete, make_home, zsh_session

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]


@pytest.fixture
def setup(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	return env, home


def glue_file(home, shell, command=ENGINE):
	path = home / ('glue.' + shell)
	path.write_text(mc.render_glue(shell, command))
	return path


@pytest.mark.parametrize('bash_completion', [True, False])
def test_bash_completes_in_a_real_shell(setup, bash_completion):
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion)
	try:
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h "echo #HO') == 'mssh h "echo #HOST'
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
		assert session.line_after('mssh h "date; fakecmd al') == 'mssh h "date; fakecmd alpha" '
	finally:
		session.close()


def test_bash_cursor_in_the_middle_of_a_line_with_multibyte_text(setup):
	# bash 4.2 counts COMP_POINT in bytes: the glue must cut the line in bytes there
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		left = '\x1b[D' * len(' "nvidia-smi"')
		assert session.line_after('mssh -ea=é gp "nvidia-smi"', keys=left + '\t') == 'mssh -ea=é gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_bash_falls_back_to_file_names_when_the_engine_is_slow(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	(home / 'zzfile_unique').write_text('')
	session = bash_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'bash', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		assert time.monotonic() - started < 3
	finally:
		session.close()


def test_zsh_completes_in_a_real_shell(setup):
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'))
	try:
		assert session.line_after('mssh gp') == 'mssh gpu\\[01-16\\] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
	finally:
		session.close()


def test_zsh_gives_up_on_a_slow_engine(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	session = zsh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'zsh', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh gp') == 'mssh gp'
		assert time.monotonic() - started < 3
	finally:
		session.close()


def test_fish_completes(setup):
	env, home = setup
	glue = glue_file(home, 'fish')
	assert fish_complete(env, glue, 'mssh gp') == [('gpu[01-16]', 'used before')]
	assert fish_complete(env, glue, 'mssh gpu[01-16] "nvid')[0] == ('nvidia-smi', '')
	assert fish_complete(env, glue, 'mssh -u r') == [('root', 'used before')]
	assert fish_complete(env, glue, 'mssh h fakecmd al') == [('alpha', '')]
	assert fish_complete(env, glue, 'mssh h "date; fakecmd al') == [('date; fakecmd alpha', '')]
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_shells.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'render_glue'` (`7 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Command line ----------------` (the line itself stays):

````python
#%% ------------ Shell glue ----------------
GLUE_MARK = 'MSSH_COMPLETE_GLUE'

BASH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ bash: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion bash`. Sourcing it only defines functions and registers them.

_mssh_complete_slice() {
	# bash 4.2 counts COMP_POINT in bytes: cut the line in the C locale (restored on return)
	local LC_ALL=C
	_mssh_complete_before=${COMP_LINE:0:COMP_POINT}
	_mssh_complete_after=${COMP_LINE:COMP_POINT}
}

_mssh_complete_split() {
	# split $1 on tabs into _mssh_complete_fields, keeping empty fields
	local text=$1
	_mssh_complete_fields=()
	while [[ $text == *$'\t'* ]]; do
		_mssh_complete_fields+=("${text%%$'\t'*}")
		text=${text#*$'\t'}
	done
	_mssh_complete_fields+=("$text")
}

_mssh_complete_delegate() {
	# $1: index of the current word, $2: text put in front of every result, then the remote command words
	local cword=$1 prefix=$2 cmd spec func item
	shift 2
	local -a words=("$@")
	local cur=${words[cword]}
	cmd=${words[0]}
	_mssh_complete_delegated=()
	if [[ $cword -eq 0 ]]; then
		while IFS= read -r item; do
			_mssh_complete_delegated+=("$prefix$item")
		done < <(compgen -c -- "$cur" 2>/dev/null)
		return 0
	fi
	if ! complete -p -- "$cmd" >/dev/null 2>&1; then
		if declare -F _comp_load >/dev/null 2>&1; then
			_comp_load "$cmd" >/dev/null 2>&1
		elif declare -F __load_completion >/dev/null 2>&1; then
			__load_completion "$cmd" >/dev/null 2>&1
		elif declare -F _completion_loader >/dev/null 2>&1; then
			_completion_loader "$cmd" >/dev/null 2>&1
		fi
	fi
	spec=$(complete -p -- "$cmd" 2>/dev/null)
	if [[ $spec =~ \ -F\ ([^ ]+) ]]; then
		func=${BASH_REMATCH[1]}
		local -a COMP_WORDS=("${words[@]}")
		local COMP_CWORD=$cword COMP_LINE="${words[*]}" COMP_POINT
		COMP_POINT=${#COMP_LINE}
		local -a COMPREPLY=()
		"$func" "$cmd" "$cur" "${words[cword-1]}" >/dev/null 2>&1
		for item in "${COMPREPLY[@]}"; do
			_mssh_complete_delegated+=("$prefix$item")
		done
	else
		while IFS= read -r item; do
			_mssh_complete_delegated+=("$prefix$item")
		done < <(compgen -f -- "$cur" 2>/dev/null)
	fi
}

_mssh_complete() {
	local cur=$2 resp line item flags ble=0 files=0 dirs=0 ended=0 delegate=0
	local _mssh_complete_before _mssh_complete_after
	local -a reply=() delegate_fields=() _mssh_complete_fields=() _mssh_complete_delegated=()
	local -A seen=()
	if (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3 )); then
		_mssh_complete_slice
	else
		_mssh_complete_before=${COMP_LINE:0:COMP_POINT}
		_mssh_complete_after=${COMP_LINE:COMP_POINT}
	fi
	if [[ -z ${_mssh_complete_icase-} ]]; then
		_mssh_complete_icase=0
		[[ $(bind -v 2>/dev/null) == *'completion-ignore-case on'* ]] && _mssh_complete_icase=1
	fi
	[[ -n ${BLE_VERSION-} ]] && ble=1
	flags="nosort=0 icase=$_mssh_complete_icase ble=$ble term=${TERM-}"
	if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
		flags="nosort=1 ${flags#nosort=0 }"
	fi
	IFS= read -r -d '' -t "${MSSH_COMPLETE_TIMEOUT:-0.3}" resp < <(
		{
			printf '%s\0' MSSHC1 bash "$BASH_VERSION" "$flags" "$_mssh_complete_before" "$_mssh_complete_after" "$cur"
			fc -ln -"${MSSH_COMPLETE_SHELL_HISTORY:-1000}" 2>/dev/null
		} | @ENGINE@ query 2>/dev/null
	) || return 0
	[[ $resp == MSSHC1$'\n'* ]] || return 0
	while IFS= read -r line; do
		case ${line:0:1} in
			D)
				for item in ${line:2}; do
					case $item in
						nospace|filenames|nosort) compopt -o "$item" 2>/dev/null ;;
						nodefault) compopt +o default +o bashdefault 2>/dev/null ;;
						files) files=1 ;;
						dirs) dirs=1 ;;
					esac
				done
				;;
			C) reply+=("${line:2}") ; reply[${#reply[@]}-1]=${reply[${#reply[@]}-1]%%$'\t'*} ;;
			X) _mssh_complete_split "${line:2}" ; delegate_fields=("${_mssh_complete_fields[@]}") ; delegate=1 ;;
			E) ended=1 ;;
		esac
	done <<< "$resp"
	(( ended )) || return 0
	if (( files || dirs )); then
		compopt -o filenames 2>/dev/null
		while IFS= read -r item; do
			reply+=("$item")
		done < <(if (( files )); then compgen -f -- "$cur"; else compgen -d -- "$cur"; fi 2>/dev/null)
	fi
	if (( delegate )) && (( ${#delegate_fields[@]} >= 3 )); then
		_mssh_complete_delegate "${delegate_fields[@]}"
		reply+=("${_mssh_complete_delegated[@]}")
	fi
	COMPREPLY=()
	for item in "${reply[@]}"; do
		[[ -n ${seen[x$item]-} ]] && continue
		seen[x$item]=1
		COMPREPLY+=("$item")
	done
	return 0
}

complete -o default -o bashdefault -F _mssh_complete mssh mssh3 multissh multissh3 multiSSH3 2>/dev/null
'''

ZSH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ zsh: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion zsh`. Sourcing it only defines a function and registers it.

_mssh() {
	emulate -L zsh
	zmodload zsh/zselect zsh/system zsh/datetime 2>/dev/null || return 1
	local before after flags resp chunk line item fd kind rest
	local -F end
	local -i remaining files=0 delegate=0 dcword start
	local -a fields texts shown dwords
	before="${(j: :)words[1,CURRENT-1]} ${compstate[quote]}$PREFIX"
	after="$SUFFIX ${(j: :)words[CURRENT+1,-1]}"
	flags="nosort=1 icase=0 zas=$(( ${+functions[_zsh_autosuggest_start]} )) term=$TERM"
	exec {fd}< <(
		{
			print -rn -- "MSSHC1"$'\0'"zsh"$'\0'"$ZSH_VERSION"$'\0'"$flags"$'\0'"$before"$'\0'"$after"$'\0'"$PREFIX"$'\0'
			fc -ln -${MSSH_COMPLETE_SHELL_HISTORY:-1000} 2>/dev/null
		} | @ENGINE@ query 2>/dev/null
	)
	(( end = EPOCHREALTIME + ${MSSH_COMPLETE_TIMEOUT:-0.3} ))
	resp=
	while true; do
		(( remaining = (end - EPOCHREALTIME) * 100 ))
		(( remaining > 0 )) || break
		zselect -t $remaining -r $fd || break
		sysread -i $fd chunk || break
		resp+=$chunk
		[[ $resp == *$'\0' ]] && break
	done
	exec {fd}<&-
	[[ $resp == MSSHC1$'\n'*$'\n'E$'\n'$'\0' ]] || return 1
	for line in "${(@f)${resp%$'\0'}}"; do
		kind=${line[1]}
		rest=${line[3,-1]}
		case $kind in
			(D) for item in ${=rest}; do [[ $item == (files|dirs) ]] && files=1; done ;;
			(C)
				fields=("${(@ps:\t:)rest}")
				texts+=("$fields[1]")
				if [[ -n $fields[2] ]]; then shown+=("$fields[1]  -- $fields[2]"); else shown+=("$fields[1]"); fi
				;;
			(X) fields=("${(@ps:\t:)rest}"); delegate=1; dcword=$fields[1]; dwords=("${(@)fields[3,-1]}") ;;
		esac
	done
	(( ${#texts} )) && compadd -V mssh -l -d shown -- "${texts[@]}"
	(( files )) && _files
	if (( delegate )); then
		[[ -n $compstate[quote] ]] && compset -q
		(( start = CURRENT - dcword ))
		if (( start >= 1 )); then
			words=("${(@)words[start,-1]}")
			(( CURRENT = CURRENT - start + 1 ))
			_normal
		fi
	fi
	return 0
}

(( $+functions[compdef] )) && compdef _mssh mssh mssh3 multissh multissh3 multiSSH3
'''

FISH_GLUE = r'''# MSSH_COMPLETE_GLUE @VERSION@ fish: autocomplete for mssh (multiSSH3), protocol MSSHC1
# Generated by `mssh --completion fish`. Loading it only defines a function and registers it.
switch "$FISH_VERSION"
	case '1.*' '2.*'
		# needs fish 3.0 or later: register nothing
	case '*'
		function __mssh_complete
			set -l before (string join \n -- (commandline -cp))
			set -l full (string join \n -- (commandline -p))
			set -l after (string sub -s (math (string length -- "$before") + 1) -- "$full")
			set -l word (commandline -ct)
			set -l keep 1000
			set -q MSSH_COMPLETE_SHELL_HISTORY; and set keep $MSSH_COMPLETE_SHELL_HISTORY
			set -l timeout_cmd
			if command -sq timeout
				set -l limit 0.3
				set -q MSSH_COMPLETE_TIMEOUT; and set limit $MSSH_COMPLETE_TIMEOUT
				set timeout_cmd timeout $limit
			end
			set -l lines (begin
				command printf '%s\0' MSSHC1 fish $FISH_VERSION "nul=0 term=$TERM" "$before" "$after" "$word"
				history -n $keep 2>/dev/null
			end | $timeout_cmd @ENGINE@ query 2>/dev/null)
			test (count $lines) -ge 2; or return
			test "$lines[1]" = MSSHC1; or return
			test "$lines[-1]" = E; or return
			set -l files 0
			for line in $lines[2..-2]
				set -l rest (string sub -s 3 -- "$line")
				switch (string sub -l 1 -- "$line")
					case D
						for item in (string split ' ' -- "$rest")
							contains -- $item files dirs; and set files 1
						end
					case C
						set -l fields (string split \t -- "$rest")
						printf '%s\t%s\n' $fields[1] $fields[2]
					case X
						set -l fields (string split \t -- "$rest")
						set -l words $fields[3..-1]
						set -l cmdline (string join ' ' -- (string escape -- $words[1..-2]))
						if test -n "$words[-1]"
							set cmdline "$cmdline "(string escape -- $words[-1])
						else
							set cmdline "$cmdline "
						end
						for item in (complete -C (string trim -l -- "$cmdline"))
							printf '%s%s\n' $fields[2] $item
						end
				end
			end
			if test $files = 1
				__fish_complete_path (commandline -ct)
			end
		end
		for name in mssh mssh3 multissh multissh3 multiSSH3
			complete -c $name -f -a '(__mssh_complete)'
		end
end
'''

_GLUES = {'bash': BASH_GLUE, 'zsh': ZSH_GLUE, 'fish': FISH_GLUE}

def engine_command():
	'''How the glue runs the engine: mssh-complete if it is on PATH, else this file with this python.'''
	import shutil
	if shutil.which('mssh-complete'):
		return ['mssh-complete']
	return [sys.executable, '-I', os.path.abspath(__file__)]

def _fish_quote(word):
	return "'" + word.replace('\\', '\\\\').replace("'", "\\'") + "'"

def render_glue(shell, command=None):
	'''The glue script for shell, running the engine with command (a list of words).'''
	import shlex
	if shell not in _GLUES:
		raise ValueError('unsupported shell {!r}, use one of {}'.format(shell, ', '.join(SHELLS)))
	command = engine_command() if command is None else command
	quote = _fish_quote if shell == 'fish' else shlex.quote
	return _GLUES[shell].replace('@VERSION@', version).replace('@ENGINE@', ' '.join(quote(word) for word in command))

````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_shells.py -q`

Expected: `4 passed, 3 skipped` (the skipped tests need zsh or fish, which are not installed here; the Docker matrix runs them)

- [ ] **Step 5: Commit**

````bash
git add tests/complete_shell_harness.py tests/test_complete_shells.py mssh_complete.py
git commit -m "feat: bash, zsh and fish glue for mssh autocomplete

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 10: Install, uninstall and `mssh --completion`
**Files:**
- Modify: `mssh_complete.py` (insert section Install before Command line; extend the CLI)
- Modify: `multiSSH3.py` (`get_parser`, `main`)
- Modify: `tests/test_complete_shells.py`
- Modify: `tests/test_complete_mssh_helpers.py`

**Interfaces:**
- Consumes: `render_glue`, `GLUE_MARK` (Task 9)
- Produces: `RC_BEGIN`, `RC_BEGIN_CREATED`, `RC_END`, `_BASH_COMPLETION_SCRIPTS`; `detect_shell(environ=None)`; `install(shell, home=None, environ=None, command=None) -> (code, messages)`; `uninstall(shell, home=None, environ=None) -> (code, messages)`; `completion_command(values) -> int`; CLI `glue SHELL`, `install [SHELL]`, `uninstall [SHELL]`; in `multiSSH3`: option `--completion ARG [ARG ...]` and `_completion_command(values)`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_complete_shells.py`, replace this text (it occurs exactly once):

````python
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, bash_session, build_index, fish_complete, make_home, zsh_session

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]
````

with:

````python
import os
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, bash_session, build_index, fish_complete, make_home,
	require_shell, zsh_session)

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]
````

Append to the end of `tests/test_complete_shells.py` (the text starts with blank lines that separate it from what is there):

````python


def _interactive_output(shell, env, home):
	'''Everything a fresh interactive shell prints before its first prompt, without the prompt.'''
	argv = {'bash': [shell, '-i'], 'zsh': [shell, '-i'], 'fish': [shell, '-i']}[os.path.basename(shell)]
	result = subprocess.run(argv, input=b'exit\n', env=dict(env, PS1='', PROMPT=''), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	return result.returncode, result.stdout.decode('utf-8', 'replace')


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
@pytest.mark.parametrize('damage', ['none', 'deleted', 'unreadable', 'broken', 'no engine'])
def test_new_shells_stay_silent(tmp_path, monkeypatch, shell, damage):
	path = require_shell(shell)
	env, home = make_home(tmp_path)
	if shell == 'zsh':
		(home / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	baseline = _interactive_output(path, env, home)
	# bash: the rc block (sourced at start) is the path a damaged file could make noisy
	monkeypatch.setattr(mc, '_BASH_COMPLETION_SCRIPTS', ())
	command = ['/nonexistent/engine'] if damage == 'no engine' else ENGINE
	code, messages = mc.install(shell, home=str(home), environ=env, command=command)
	assert code == 0, messages
	glues = [line.split(' ', 1)[1] for line in messages if line.startswith('wrote ')]
	for glue in glues:
		if damage == 'deleted':
			os.unlink(glue)
		elif damage == 'unreadable':
			os.chmod(glue, 0)
		elif damage == 'broken':
			with open(glue, 'a') as f:
				f.write('\n((( broken syntax\n')
	assert _interactive_output(path, env, home) == baseline


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_uninstall_restores_rc_files(tmp_path, shell):
	env, home = make_home(tmp_path)
	(home / '.bashrc').write_text('alias ll="ls -l"')
	(home / '.zshrc').write_text('setopt nobeep\n')
	before = {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')}
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	mc.uninstall(shell, home=str(home), environ=env)
	assert {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')} == before
	left = [os.path.join(root, name) for root, _, names in os.walk(str(home)) for name in names]
	assert sorted(left) == sorted([str(home / '.bashrc'), str(home / '.zshrc'), str(home / '.mssh_history')])


def test_uninstall_deletes_an_rc_file_it_created(tmp_path):
	env, home = make_home(tmp_path)
	mc.install('zsh', home=str(home), environ=env)
	assert (home / '.zshrc').exists()
	mc.uninstall('zsh', home=str(home), environ=env)
	assert not (home / '.zshrc').exists()


def test_install_never_overwrites_foreign_files(tmp_path):
	env, home = make_home(tmp_path)
	target = home / '.config' / 'fish' / 'completions' / 'mssh.fish'
	target.parent.mkdir(parents=True)
	target.write_text('# my own\n')
	code, messages = mc.install('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'
	assert any('skipped' in message for message in messages)
	mc.uninstall('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'


def test_bash_installs_into_the_user_completion_dir_when_supported(tmp_path, monkeypatch):
	env, home = make_home(tmp_path)
	script = tmp_path / 'bash_completion'
	script.write_text('dirs=( ${BASH_COMPLETION_USER_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion}/completions )\n')
	monkeypatch.setattr(mc, '_BASH_COMPLETION_SCRIPTS', (str(script),))
	assert mc.install('bash', home=str(home), environ=env)[0] == 0
	user_dir = home / '.local' / 'share' / 'bash-completion' / 'completions'
	assert (user_dir / 'mssh').read_text().startswith('# MSSH_COMPLETE_GLUE')
	assert [os.readlink(str(user_dir / name)) for name in mc.MSSH_NAMES[1:]] == ['mssh'] * 4
	assert not (home / '.bashrc').exists()
	mc.uninstall('bash', home=str(home), environ=env)
	assert os.listdir(str(user_dir)) == []


def test_old_bash_completion_gets_an_rc_block(tmp_path, monkeypatch):
	env, home = make_home(tmp_path)
	script = tmp_path / 'bash_completion'
	script.write_text('# bash-completion 2.1: no per-user directory\n')
	monkeypatch.setattr(mc, '_BASH_COMPLETION_SCRIPTS', (str(script),))
	assert mc.install('bash', home=str(home), environ=env)[0] == 0
	assert mc.RC_BEGIN_CREATED in (home / '.bashrc').read_text()
````

In `tests/test_complete_mssh_helpers.py`, replace this text (it occurs exactly once):

````python
import socket

import pytest

import multiSSH3
````

with:

````python
import socket
import subprocess
import sys

import pytest

import multiSSH3
from conftest import MULTISSH3_PY
````

Append to the end of `tests/test_complete_mssh_helpers.py` (the text starts with blank lines that separate it from what is there):

````python


def test_completion_option_prints_glue():
	result = subprocess.run([sys.executable, str(MULTISSH3_PY), '--completion', 'bash'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert result.returncode == 0
	assert b'MSSH_COMPLETE_GLUE' in result.stdout
	assert b'complete -o default -o bashdefault -F _mssh_complete mssh' in result.stdout


def test_completion_option_rejects_unknown_action():
	result = subprocess.run([sys.executable, str(MULTISSH3_PY), '--completion', 'tcsh'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert result.returncode == 2
	assert b'usage: mssh --completion' in result.stderr


def test_completion_option_is_completed():
	import mssh_complete as mc
	spec = mc.spec_from_parser(multiSSH3.get_parser())
	context = mc.parse_context('mssh --completion ', '', spec)
	assert (context.slot, context.option.dest) == ('value', 'completion')
	response = mc.Engine(spec).query(mc.Request('bash', 'mssh --completion ', '', ''))
	assert sorted(candidate.text for candidate in response.candidates) == ['bash', 'fish', 'install', 'uninstall', 'zsh']


def test_completion_option_without_module(tmp_path):
	lone = tmp_path / 'multiSSH3.py'
	lone.write_bytes(MULTISSH3_PY.read_bytes())
	result = subprocess.run([sys.executable, '-I', str(lone), '--completion', 'bash'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd=str(tmp_path))
	assert result.returncode == 1
	assert b'autocomplete needs mssh_complete.py' in result.stderr
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_shells.py tests/test_complete_mssh_helpers.py -q`

Expected: FAIL, e.g. `E AttributeError: <module 'mssh_complete' from '/tmp/claude-0/-mnt-klein-work-cas-multiSSH3/eb2a9d3a-b680-44ee-b0cf-b93c6a269058/scratchpad/replay/mssh_complete` (`16 failed, 12 passed, 13 skipped`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Command line ----------------` (the line itself stays):

````python
#%% ------------ Install ----------------
RC_BEGIN = '# >>> mssh completion >>>'
RC_BEGIN_CREATED = '# >>> mssh completion (created this file) >>>'
RC_END = '# <<< mssh completion <<<'
_BASH_COMPLETION_SCRIPTS = ('/usr/share/bash-completion/bash_completion', '/usr/local/share/bash-completion/bash_completion',
	'/opt/homebrew/share/bash-completion/bash_completion', '/etc/bash_completion')

def detect_shell(environ=None):
	'''The shell that ran us (parent process), else $SHELL; None if neither is bash, zsh or fish.'''
	environ = os.environ if environ is None else environ
	name = ''
	try:
		with open('/proc/{}/comm'.format(os.getppid())) as f:
			name = f.read().strip()
	except OSError:
		pass
	name = os.path.basename(name).lstrip('-')
	if name not in SHELLS:
		name = os.path.basename(environ.get('SHELL', '')).lstrip('-')
	return name if name in SHELLS else None

def _bash_completion_user_dir(home, environ):
	'''Where bash-completion lazy-loads per-user completions, or None when no installed version does (< 2.2).'''
	for path in _BASH_COMPLETION_SCRIPTS:
		try:
			with open(path, encoding='utf-8', errors='replace') as f:
				text = f.read()
		except OSError:
			continue
		if 'BASH_COMPLETION_USER_DIR' not in text:
			return None
		base = environ.get('BASH_COMPLETION_USER_DIR') or os.path.join(environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share'), 'bash-completion')
		return os.path.join(base.split(':')[0], 'completions')
	return None

def _fish_major():
	'''The major version of the fish on PATH, or None.'''
	import subprocess
	try:
		output = subprocess.run(['fish', '-c', 'echo $FISH_VERSION'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5).stdout
		return int(output.decode('ascii', 'replace').strip().split('.')[0])
	except (OSError, ValueError, subprocess.SubprocessError):
		return None

def _ours(path):
	try:
		with open(path, encoding='utf-8', errors='replace') as f:
			return GLUE_MARK in f.readline()
	except OSError:
		return False

def _write_glue(path, text, messages):
	'''Write a glue file unless another file is in the way. Returns whether path holds the glue.'''
	if os.path.lexists(path) and not _ours(path):
		messages.append('skipped {}: it exists and mssh did not write it'.format(path))
		return False
	os.makedirs(os.path.dirname(path), exist_ok=True)
	temporary = path + '.mssh-tmp'
	with open(temporary, 'w', encoding='utf-8') as f:
		f.write(text)
	os.replace(temporary, path)
	messages.append('wrote ' + path)
	return True

def _link(path, target, messages):
	if os.path.islink(path) and os.readlink(path) == target:
		return
	if os.path.lexists(path):
		messages.append('skipped {}: it exists and mssh did not write it'.format(path))
		return
	os.symlink(target, path)
	messages.append('linked {} -> {}'.format(path, target))

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

def _remove_rc_block(rc, messages):
	try:
		with open(rc, encoding='utf-8', errors='surrogateescape', newline='') as f:
			text = f.read()
	except FileNotFoundError:
		return
	for begin in (RC_BEGIN_CREATED, RC_BEGIN):
		start = text.find('\n' + begin + '\n')
		end = text.find('\n' + RC_END + '\n', start + 1)
		if start < 0 or end < 0:
			continue
		text = text[:start] + text[end + len(RC_END) + 2:]
		if begin == RC_BEGIN_CREATED and not text:
			os.unlink(rc)
			messages.append('removed ' + rc + ' (mssh had created it)')
		else:
			with open(rc, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
				f.write(text)
			messages.append('removed the mssh block from ' + rc)
		return

def _paths(shell, home, environ):
	data = environ.get('XDG_DATA_HOME') or os.path.join(home, '.local', 'share')
	config = environ.get('XDG_CONFIG_HOME') or os.path.join(home, '.config')
	if shell == 'fish':
		return {'files': [os.path.join(config, 'fish', 'completions', name + '.fish') for name in MSSH_NAMES]}
	if shell == 'zsh':
		return {'files': [os.path.join(data, 'multiSSH3', 'completion.zsh')], 'rc': os.path.join(home, '.zshrc')}
	user_dir = _bash_completion_user_dir(home, environ)
	if user_dir:
		return {'files': [os.path.join(user_dir, 'mssh')], 'links': [os.path.join(user_dir, name) for name in MSSH_NAMES[1:]]}
	return {'files': [os.path.join(data, 'multiSSH3', 'completion.bash')], 'rc': os.path.join(home, '.bashrc')}

def install(shell, home=None, environ=None, command=None):
	'''
	Install the glue for shell for the current user. Never overwrites a file mssh did not write.

	Returns:
		tuple: (exit code, list of messages saying what was done)
	'''
	import shlex
	environ = os.environ if environ is None else environ
	home = home or os.path.expanduser('~')
	messages = []
	if shell == 'fish':
		major = _fish_major()
		if major is not None and major < 3:
			return 1, ['fish {} is too old for mssh autocomplete: it needs fish 3.0 or later'.format(major)]
	text = render_glue(shell, command)
	paths = _paths(shell, home, environ)
	written = [path for path in paths['files'] if _write_glue(path, text, messages)]
	for link in paths.get('links', ()):
		_link(link, 'mssh', messages)
	if paths.get('rc') and written:
		quoted = shlex.quote(written[0])
		# always ends with status 0: a missing or broken file must not even change $? in a new shell
		line = '[[ -r {0} ]] && source {0} 2>/dev/null || :' if shell == 'zsh' else '[ -r {0} ] && . {0} 2>/dev/null || :'
		_add_rc_block(paths['rc'], line.format(quoted), messages)
	return (0 if written else 1), messages

def uninstall(shell, home=None, environ=None):
	'''Remove what install wrote for shell. Returns (exit code, messages).'''
	environ = os.environ if environ is None else environ
	home = home or os.path.expanduser('~')
	messages = []
	paths = _paths(shell, home, environ)
	for link in paths.get('links', ()):
		if os.path.islink(link) and os.readlink(link) == 'mssh':
			os.unlink(link)
			messages.append('removed ' + link)
	for path in paths['files']:
		if _ours(path):
			os.unlink(path)
			messages.append('removed ' + path)
	if paths.get('rc'):
		_remove_rc_block(paths['rc'], messages)
	return 0, messages or ['nothing to remove']

def completion_command(values):
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

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	if command in ('-V', '--version'):
````

with:

````python
	if command in ('glue', 'install', 'uninstall'):
		return completion_command(argv[1:] if command == 'glue' else argv)
	if command in ('-V', '--version'):
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	print('usage: mssh-complete query | rebuild', file=sys.stderr)
````

with:

````python
	print('usage: mssh-complete query | rebuild | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
````

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
	parser.add_argument("-V","--version", action='version',
````

with:

````python
	parser.add_argument('--completion', nargs='+', metavar='ARG', help='Shell autocomplete: print the glue for bash, zsh or fish, or "install [SHELL]" / "uninstall [SHELL]" it for the current user')
	parser.add_argument("-V","--version", action='version',
````

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
def main(args = None):
	global __global_suppress_printout
	global __mainReturnCode
	global __failedHosts
	args = process_args(args)
````

with:

````python
def _completion_command(values):
	'''Run `mssh --completion ...` with mssh_complete, which ships next to this file.'''
	try:
		import mssh_complete
	except ImportError:
		here = os.path.dirname(os.path.abspath(__file__))
		if here not in sys.path:
			sys.path.insert(0, here)
		try:
			import mssh_complete
		except ImportError:
			eprint('Error: autocomplete needs mssh_complete.py next to {} (it ships with the multiSSH3 package)'.format(os.path.abspath(__file__)))
			return 1
	return mssh_complete.completion_command(values)

def main(args = None):
	global __global_suppress_printout
	global __mainReturnCode
	global __failedHosts
	args = process_args(args)
	if args.completion:
		_exit_with_code(_completion_command(args.completion))
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_shells.py tests/test_complete_mssh_helpers.py -q`

Expected: `28 passed, 13 skipped` (the skipped tests need zsh or fish, which are not installed here; the Docker matrix runs them)

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`

Expected: `660 passed, 13 skipped`

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_shells.py tests/test_complete_mssh_helpers.py mssh_complete.py multiSSH3.py
git commit -m "feat: mssh --completion prints, installs and uninstalls the shell glue

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 11: Docker shell matrix
**Files:**
- Create: `tests/shells/Dockerfile.modern`
- Create: `tests/shells/Dockerfile.legacy`
- Create: `tests/shells/Dockerfile.centos7`
- Create: `tests/shells/run_matrix.sh`

**Interfaces:**
- Consumes: all `tests/test_complete_*.py` files
- Produces: `tests/shells/run_matrix.sh [modern] [legacy] [centos7]`, exit status 0 only when every image passes with its required shells.

- [ ] **Step 1: Write the matrix files**

Create `tests/shells/Dockerfile.modern` with exactly this content:

````dockerfile
# Shell matrix image: current shells (see docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md)
FROM debian:trixie-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bash bash-completion zsh fish python3 python3-pytest procps \
 && rm -rf /var/lib/apt/lists/*
ENV LANG=C.UTF-8
````

Create `tests/shells/Dockerfile.legacy` with exactly this content:

````dockerfile
# Shell matrix image: RHEL 8 era shells and Python 3.6 (see the autocomplete spec)
FROM rockylinux:8
RUN dnf -q -y install epel-release \
 && dnf -q -y install bash bash-completion zsh fish python36 procps-ng glibc-langpack-en which \
 && dnf clean all \
 && python3 -m pip install -q --disable-pip-version-check 'pytest==7.0.1'
ENV LANG=en_US.UTF-8
````

Create `tests/shells/Dockerfile.centos7` with exactly this content:

````dockerfile
# Shell matrix image: CentOS 7, bash only (end of life: packages come from the vault and archives)
FROM centos:7
RUN sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's|^#\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-*.repo \
 && yum -y -q install python3 bash-completion which procps-ng \
 && yum clean all \
 && python3 -m pip install -q --disable-pip-version-check 'pip<22' \
 && python3 -m pip install -q --disable-pip-version-check 'pytest==7.0.1'
# no C.UTF-8 here, and the C locale would hide bash 4.2's byte-counted COMP_POINT
ENV LANG=en_US.UTF-8
````

Create `tests/shells/run_matrix.sh` with exactly this content:

````bash
#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, legacy and centos7 images.
# Usage: tests/shells/run_matrix.sh [modern] [legacy] [centos7]   (default: all three)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
images=("$@")
[ ${#images[@]} -gt 0 ] || images=(modern legacy centos7)
status=0
for name in "${images[@]}"; do
	case $name in
		centos7) required=bash ;;
		modern|legacy) required=bash,zsh,fish ;;
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

- [ ] **Step 2: Run the matrix**

Run: `tests/shells/run_matrix.sh` (the first run builds the images, which takes a few minutes; CentOS 7 packages come from the vault and archive mirrors)

Expected (one line per image; CentOS 7 skips the zsh and fish tests and the Python 3.7+ argparse check, legacy skips the argparse check):

````
=== modern (requires bash,zsh,fish)
153 passed in 8.88s
=== legacy (requires bash,zsh,fish)
152 passed, 1 skipped in 8.55s
=== centos7 (requires bash)
139 passed, 14 skipped in 6.28s
````

- [ ] **Step 3: Commit**

````bash
git add tests/shells/Dockerfile.modern tests/shells/Dockerfile.legacy tests/shells/Dockerfile.centos7 tests/shells/run_matrix.sh
git commit -m "test: run the autocomplete tests in a Docker shell matrix

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 12: Replay evaluation and synthetic history
**Files:**
- Modify: `mssh_complete.py` (insert section Replay evaluation before Command line; extend the CLI)
- Create: `tests/test_complete_eval.py`

**Interfaces:**
- Consumes: `Engine`, `Request` (Task 8); `MemoryKnowledge`, `use_weight` (Task 5); `parse_history_line`, `PASSWORD_DESTS` (Task 4)
- Produces: `simulate_slot(engine, before, after, intended, quoted=False, policy="bash", shell="zsh") -> dict`; `slot_cases(entry)`; `evaluate(lines, spec, since=0, limit=300, policies=("bash", "ranked")) -> {(policy, slot): totals}`; `format_report(totals) -> str`; `synthetic_history(seed=1, entries=1500, start=1700000000) -> list`; CLI `eval [HISTORY_FILE] [--since T] [--limit N] [--synthetic]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_complete_eval.py` with exactly this content:

````python
import multiSSH3
import mssh_complete as mc

SPEC = mc.spec_from_parser(multiSSH3.get_parser())


def test_synthetic_history_is_deterministic():
	assert mc.synthetic_history(seed=3, entries=50) == mc.synthetic_history(seed=3, entries=50)
	assert all(mc.parse_history_line(line, SPEC) is not None for line in mc.synthetic_history(entries=200))


def test_tab_never_alters_typed_text():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150)
	assert totals
	assert sum(total['altered'] for total in totals.values()) == 0


def test_bash_tab_never_inserts_the_wrong_thing_on_synthetic_history():
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash',))
	assert all(total['divergent'] == 0 for total in totals.values())


def test_completion_saves_typing_on_synthetic_history():
	# a floor that catches ranking regressions; the real numbers are tuned with `mssh-complete eval`
	totals = mc.evaluate(mc.synthetic_history(entries=600), SPEC, limit=150, policies=('bash',))
	for slot in ('command', 'hosts', 'hosts-back'):
		total = totals[('bash', slot)]
		assert 1 - float(total['keys']) / total['chars'] > 0.5, slot
	assert float(totals[('bash', 'hosts-back')]['top1']) / totals[('bash', 'hosts-back')]['cases'] > 0.85


def test_simulate_slot_counts_keys():
	engine = mc.Engine(SPEC, [])
	result = mc.simulate_slot(engine, 'mssh ', '', 'abc')
	assert (result['keys'], result['chars'], result['rank']) == (3, 3, 0)


def test_since_skips_older_entries():
	lines = mc.synthetic_history(entries=100)
	cutoff = mc.parse_history_line(lines[90], SPEC).ts
	totals = mc.evaluate(lines, SPEC, since=cutoff, policies=('bash',))
	assert totals[('bash', 'hosts')]['cases'] == 10


def test_report_lists_every_slot():
	report = mc.format_report(mc.evaluate(mc.synthetic_history(entries=200), SPEC, limit=20))
	assert report.splitlines()[0].split()[:3] == ['policy', 'slot', 'cases']
	assert 'hosts-back' in report and 'ranked' in report
````

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_complete_eval.py -q`

Expected: FAIL, e.g. `E AttributeError: module 'mssh_complete' has no attribute 'synthetic_history'` (`7 failed`)

- [ ] **Step 3: Implement**

In `mssh_complete.py`, insert this text immediately before the line that starts with `#%% ------------ Command line ----------------` (the line itself stays):

````python
#%% ------------ Replay evaluation ----------------
def _tab(candidates, typed, policy, quoted, nospace):
	'''What one TAB inserts after typed: (text or None if it would change typed text, appended suffix).'''
	texts = [candidate.text for candidate in candidates]
	if not texts:
		return '', ''
	if policy == 'ranked' or len(set(texts)) == 1:
		choice, unique = texts[0], True
	else:
		choice, unique = os.path.commonprefix(texts), False
	if not choice.startswith(typed):
		return None, ''
	suffix = ('"' if quoted else '') + ' ' if unique and not nospace else ''
	return choice[len(typed):], suffix

def simulate_slot(engine, before, after, intended, quoted=False, policy='bash', shell='zsh'):
	'''
	Simulate an operator typing intended after before (with after behind the cursor), using TAB.

	The operator types a character at a time and presses TAB whenever it inserts the intended
	continuation. An appended space or quote that the operator then has to delete costs one key.

	Returns:
		dict: keys, chars, rank (of intended at the start, 0 if absent), visited and divergent
			(positions where TAB would insert something unwanted), altered (candidates not
			extending what was typed: must stay 0), suffix_cost
	'''
	result = {'keys': 0, 'chars': len(intended), 'rank': 0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0}
	position = 0
	while position < len(intended):
		typed = intended[:position]
		response = engine.query(Request(shell, before + typed, after, typed))
		candidates = response.candidates
		result['visited'] += 1
		if position == 0:
			for number, candidate in enumerate(candidates):
				if candidate.text == intended:
					result['rank'] = number + 1
					break
		result['altered'] += sum(1 for candidate in candidates if not candidate.text.startswith(typed))
		inserted, suffix = _tab(candidates, typed, policy, quoted, 'nospace' in response.directives)
		remaining = intended[position:]
		if inserted and remaining.startswith(inserted):
			result['keys'] += 1
			position += len(inserted)
			if suffix and position < len(intended):
				result['keys'] += 1
				result['suffix_cost'] += 1
			continue
		if inserted:
			result['divergent'] += 1
		result['keys'] += 1
		position += 1
	return result

def _quote_command(command):
	'''(quote char, command) for typing command inside quotes, or None when that would need escapes.'''
	if not any(char in command for char in '"\\$`'):
		return '"'
	if "'" not in command:
		return "'"
	return None

def slot_cases(entry):
	'''(slot, before, after, intended, quoted) cases to replay for one history entry.'''
	import shlex
	options = [(option, value, name) for (option, value), name in zip(entry.options, entry.option_texts) if option.dest not in PASSWORD_DESTS]
	option_texts = [name if value is None else '{}={}'.format(name, shlex.quote(value)) for option, value, name in options]
	commands = [command for command in entry.commands if command.strip()]
	quoted_commands = []
	for command in commands:
		quote = _quote_command(command)
		if quote is None:
			commands = []
			quoted_commands = []
			break
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

	Args:
		lines (list): ~/.mssh_history lines
		spec (ParserSpec): The mssh options
		since (int): Only replay entries from this timestamp on (older ones are still learned from)
		limit (int): Replay at most this many of the newest entries

	Returns:
		dict: (policy, slot) -> totals of simulate_slot results plus 'cases'
	'''
	entries = sorted((entry for entry in (parse_history_line(line, spec) for line in lines) if entry is not None), key=lambda entry: entry.ts)
	replay = [number for number, entry in enumerate(entries) if entry.ts >= since][-limit:] if limit else []
	first = replay[0] if replay else len(entries)
	memory = MemoryKnowledge()
	reference = entries[-1].ts if entries else 0
	for entry in entries[:first]:
		memory.add(entry.features(), use_weight(reference - entry.ts))
	totals = {}
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
				total['cases'] += 1
				for key in ('keys', 'chars', 'visited', 'divergent', 'altered', 'suffix_cost'):
					total[key] += result[key]
				if result['rank']:
					total['top1'] += result['rank'] == 1
					total['top3'] += result['rank'] <= 3
					total['mrr'] += 1.0 / result['rank']
		memory.add(entry.features(), use_weight(reference - entry.ts))
	return totals

def format_report(totals):
	'''The evaluation as a text table.'''
	lines = ['{:7} {:10} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9} {:>8} {:>7}'.format(
		'policy', 'slot', 'cases', 'saved', 'top1', 'top3', 'mrr', 'divergent', 'altered', 'suffix')]
	for (policy, slot), total in sorted(totals.items()):
		cases = total['cases'] or 1
		lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%} {:>6.3f} {:>8.1%} {:>8} {:>7}'.format(
			policy, slot, total['cases'], 1 - float(total['keys']) / (total['chars'] or 1),
			float(total['top1']) / cases, float(total['top3']) / cases, total['mrr'] / cases,
			float(total['divergent']) / (total['visited'] or 1), total['altered'], total['suffix_cost']))
	return '\n'.join(lines)

def synthetic_history(seed=1, entries=1500, start=1700000000):
	'''
	A deterministic ~/.mssh_history with known structure: host groups each with their own commands,
	options and users, so ranking can be checked without anyone's real history.
	'''
	import random
	import shlex
	rng = random.Random(seed)
	profiles = [
		('gpu[01-16]', ['-u=root', '-t=30'], ['nvidia-smi', 'systemctl restart slurmd', 'nvidia-smi -q -d TEMPERATURE']),
		('storage[1-4]', ['-u=admin'], ['df -h /data', 'zpool status', 'zfs list']),
		('login[1-2]', [], ['uptime', 'who', 'free -h']),
		('us_east', ['-t=10'], ['systemctl status nginx', 'journalctl -u nginx -n 50']),
	]
	lines = []
	ts = start
	for _ in range(entries):
		ts += rng.randint(60, 7200)
		hosts, options, commands = rng.choices(profiles, [0.4, 0.25, 0.2, 0.15])[0]
		command = rng.choices(commands, [5, 3, 1][:len(commands)])[0]
		if hosts.startswith('gpu') and rng.random() < 0.15:
			hosts = 'gpu{:02d}'.format(rng.randint(1, 16))
		lines.append('{}\t/usr/bin/multiSSH3.py\t{}\t{}\t{}'.format(ts, ' '.join(['-su'] + options), shlex.quote(hosts), shlex.quote(command)))
	return lines

````

In `mssh_complete.py`, insert this text immediately before the line that starts with `def main(argv=None):` (the line itself stays):

````python
def _cmd_eval(args):
	import argparse
	parser = argparse.ArgumentParser(prog='mssh-complete eval', description='Replay mssh history and report how much typing completion saves.')
	parser.add_argument('history_file', nargs='?', help='history to replay (default: the one mssh writes)')
	parser.add_argument('--since', type=int, default=0, help='only replay entries from this unix time on')
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	options = parser.parse_args(args)
	mssh = _import_mssh()
	spec = spec_from_parser(mssh.get_parser())
	if options.synthetic:
		lines = synthetic_history()
	else:
		lines, _, _ = read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
		return _cmd_rebuild(argv[1:])
	if command in ('glue'
````

with:

````python
		return _cmd_rebuild(argv[1:])
	if command == 'eval':
		return _cmd_eval(argv[1:])
	if command in ('glue'
````

In `mssh_complete.py`, replace this text (it occurs exactly once):

````python
	print('usage: mssh-complete query | rebuild | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
````

with:

````python
	print('usage: mssh-complete query | rebuild | eval [HISTORY_FILE] | glue SHELL | install [SHELL] | uninstall [SHELL]', file=sys.stderr)
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_complete_eval.py -q`

Expected: `7 passed`

- [ ] **Step 5: Record the baseline replay report**

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
````

The bash policy must show 0 divergent and 0 altered for every slot. The ranked policy's divergent rates are what SP2's ghost text has to beat with a confidence threshold. Also run `python3 mssh_complete.py eval` on real history if there is any; it reads `~/.mssh_history`.

- [ ] **Step 6: Commit**

````bash
git add tests/test_complete_eval.py mssh_complete.py
git commit -m "feat: replay mssh history to measure how much typing completion saves

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

### Task 13: Benchmark, README, version and spec sync
**Files:**
- Create: `tests/bench_complete.py`
- Modify: `README.md`
- Modify: `multiSSH3.py:38-41`
- Modify: `docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md`

**Interfaces:**
- Consumes: everything
- Produces: multiSSH3 6.28 with autocomplete documented; the spec records the changes made while planning.

- [ ] **Step 1: Add the benchmark script**

Create `tests/bench_complete.py` with exactly this content:

````python
'''
Autocomplete timing and size at the target scale (not a test): 10k hosts, 20k invocations.

Run: python3 tests/bench_complete.py
Prints observations only; nothing passes or fails on them (see the autocomplete spec).
'''
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def synthetic(home, hosts=10000, invocations=20000):
	lines = []
	commands = ['nvidia-smi', 'uptime', 'df -h /data', 'systemctl restart slurmd', 'free -h', 'zpool status']
	for number in range(invocations):
		host = 'node{:05d}'.format(number * 7919 % hosts)
		lines.append('{}\t/x/multiSSH3.py\t-su -u=root\t{}\t"{} {}"'.format(1790000000 + number, host, commands[number % len(commands)], number % 997))
	(home / '.mssh_history').write_text(''.join(line + '\n' for line in lines))
	(home / '.ssh').mkdir()
	(home / '.ssh' / 'config').write_text(''.join('Host node{:05d}\n'.format(number) for number in range(hosts)))


def main():
	tmp = Path(tempfile.mkdtemp())
	try:
		home = tmp / 'home'
		home.mkdir()
		runtime = tmp / 'runtime'
		runtime.mkdir(mode=0o700)
		synthetic(home)
		env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime))
		engine = [sys.executable, '-I', str(REPO / 'mssh_complete.py')]
		started = time.monotonic()
		path = subprocess.run(engine + ['rebuild'], env=env, stdout=subprocess.PIPE, check=True).stdout.decode().strip()
		print('rebuild: {:.0f} ms, index {:.1f} MB'.format((time.monotonic() - started) * 1000, os.path.getsize(path) / 1e6))
		for line in ('mssh ', 'mssh node0', 'mssh node00042 "', 'mssh -u ', 'mssh ', "mssh -u root node1 'nvid"):
			word = '' if line.endswith((' ', '"')) else line.split(' ')[-1].lstrip("'")
			request = 'MSSHC1\0bash\x005.2\0nosort=1\0{}\0\0{}\0'.format(line, word).encode()
			timings = []
			for _ in range(15):
				started = time.monotonic()
				subprocess.run(engine + ['query'], input=request, env=env, stdout=subprocess.DEVNULL, check=True)
				timings.append((time.monotonic() - started) * 1000)
			timings.sort()
			print('query {!r:32} p50 {:6.1f} ms  p95 {:6.1f} ms'.format(line, statistics.median(timings), timings[int(len(timings) * 0.95) - 1]))
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)


if __name__ == '__main__':
	main()
````

Run: `python3 tests/bench_complete.py`

Expected (numbers vary by machine; they are observations, not gates):

````
rebuild: 357 ms, index 3.0 MB
query 'mssh '                          p50   32.4 ms  p95   33.3 ms
query 'mssh node0'                     p50   40.7 ms  p95   41.4 ms
query 'mssh node00042 "'               p50   27.4 ms  p95   28.1 ms
query 'mssh -u '                       p50   25.4 ms  p95   26.4 ms
query 'mssh '                          p50   32.0 ms  p95   33.2 ms
query "mssh -u root node1 'nvid"       p50   25.5 ms  p95   26.9 ms
````

- [ ] **Step 2: Document autocomplete in the README**

In `README.md`, insert this text immediately before the line that starts with `## Options` (the line itself stays):

````markdown
## Autocomplete

mssh completes hosts, options, option values and remote commands when you press TAB, in bash, zsh and fish.

```bash
mssh --completion install     # set it up for the shell you run this from
mssh --completion uninstall   # remove it again
mssh --completion bash        # or print the script (bash, zsh or fish)
```

- **Hosts:** host strings you typed before, env file aliases, `/etc/hosts`, ssh config `Host` entries, `known_hosts` and the ARP table. Large clusters are offered as ranges (`node[0001-2000]`) until what you typed narrows them down. Hosts mssh recently found unreachable come last.
- **Options and values:** option names, and values you used before (`-u`, `-t`, ...). Paths complete as files. Passwords are never completed.
- **Commands:** commands from your mssh history, the rest of a command from this machine's own completion (`mssh grp systemctl rest<TAB>`), and the magic strings (`#HOST#`, ...).

Ranking uses the rest of the line on both sides of the cursor: after `mssh gpu[01-16] "` the commands you run on those hosts come first, and in the hosts of `mssh ▮ "systemctl restart slurmd"` the hosts you restarted slurmd on come first.

Completion never removes what you typed, prints nothing, and falls back to the shell's normal completion when anything is slow or missing.

It learns from an index of your history and hosts, kept in mssh's private cache directory (`$XDG_RUNTIME_DIR/multiSSH3` or `/tmp/multiSSH3-<uid>`) and rebuilt in the background when its sources change. `mssh-complete rebuild` rebuilds it now; `mssh-complete eval` replays your history and shows how much typing completion saves.

| Environment variable | Effect |
| --- | --- |
| `MSSH_COMPLETE_TIMEOUT` | Seconds the shell waits for an answer (default 0.3) |
| `MSSH_COMPLETE_SHELL_HISTORY` | Lines of shell history sent along (default 1000) |
| `MSSH_COMPLETE_DEBUG` | `1` logs errors to `complete.log` in the cache directory |

> Tested with bash 4.2 to 5.2, zsh 5.5 to 5.9 (with `compinit` loaded) and fish 3.3 to 4.0. Since 6.28 mssh records hosts in its history as typed; older history lines hold them expanded.

````

- [ ] **Step 3: Bump the version to 6.28**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
version = '6.27'
````

with:

````python
version = '6.28'
````

- [ ] **Step 4: Set the release date**

In `multiSSH3.py`, replace this text (it occurs exactly once):

````python
COMMIT_DATE = '2026-10-10'
````

with:

````python
COMMIT_DATE = '2026-10-11'
````

Use the date of the release commit (YYYY-MM-DD); the replay used 2026-10-11.

- [ ] **Step 5: Record the deviations in the spec**

Append to the end of `docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md` (the text starts with blank lines that separate it from what is there):

````markdown

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

Measured at the target scale (10k hosts, 20k invocations): a TAB costs 30-45 ms (p50), a rebuild about 0.5 s, the index is 3 MB.
````

- [ ] **Step 6: Run the whole suite and the matrix**

Run: `python3 -m pytest -q && tests/shells/run_matrix.sh`

Expected: `667 passed, 13 skipped`, then

````
=== modern (requires bash,zsh,fish)
160 passed in 9.36s
=== legacy (requires bash,zsh,fish)
159 passed, 1 skipped in 9.23s
=== centos7 (requires bash)
146 passed, 14 skipped in 7.16s
````

- [ ] **Step 7: Commit**

````bash
git add tests/bench_complete.py README.md multiSSH3.py docs/superpowers/specs/2026-10-11-mssh-autocomplete-sp1-design.md
git commit -m "docs: autocomplete in the README; multiSSH3 6.28

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
````

---

## After the plan

- Releasing follows the repository's process: `uvpack` multiSSH3 6.28; in `cas-toolbox/pyproject.toml` add `mssh-complete = "mssh_complete:main"` to `[project.scripts]` and bump the `multissh3` pin in the next Monday roll-up.
- SP2 (ghost text, picker) and SP3 (async probing, diagnostics) get their own brainstorm, spec and plan; `Response.ghost`, `Response.diagnostics`, the request flags and `expand_hostnames_local`'s unresolved list are their hooks.
