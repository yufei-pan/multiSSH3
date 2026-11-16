#!/usr/bin/env python3
'''usage: zsh_shapes_probe.py TREE tests/data/zsh_double_quote_shapes.json > OUT.json

Runs the shapes of the data file (its cases: the typed text and what is in the directory, the history and HOME) in a new zsh for each, in
the line, in $( ) and in backticks, with the glue and the tests of the checkout TREE, and prints {id: {opener: {"line", "remote"}}}: the
line after TAB, and the words the remote shell gets for it (a path of the run's temp directory written {tmp}). It starts zsh sessions
and files: run it in a Docker image of tests/shells, as the matrix does, TREE mounted read-only:
	docker run --rm --init --memory=8g --user 65534:65534 -v TREE:/repo:ro -v $PWD/tests:/t:ro -w /repo mssh-shell-test-modern \
		sh -c 'export HOME=$(mktemp -d); python3 /t/zsh_shapes_probe.py /repo /t/data/zsh_double_quote_shapes.json'
tests/data/zsh_double_quote_shapes_6.46.json is its output for a checkout of v6.46 (the baseline the data file's notes are checked against).'''
import json
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

tree, cases_file = Path(sys.argv[1]), sys.argv[2]
sys.path[:0] = [str(tree), str(tree / 'tests')]
import test_complete_shells as t  # noqa: E402


def one(job):
	case, opener = job
	tmp = Path(tempfile.mkdtemp())
	try:
		kwargs = {key: case[key] for key in ('files', 'dirs', 'history', 'steps', 'home_files', 'home_dirs') if key in case}
		line, remote = t.review_line(tmp, 'zsh', opener + case['typed'], pre='mssh() { :; }', extra=case.get('extra', ''), **kwargs)
		if opener:
			remote = t.substituted_remote(line, tmp / 'work')
		norm = lambda text: text.replace(str(tmp), '{tmp}')
		return case['id'], opener, {'line': norm(line), 'remote': remote and [norm(word) for word in remote]}
	finally:
		shutil.rmtree(str(tmp), ignore_errors=True)


if __name__ == '__main__':
	cases = json.loads(Path(cases_file).read_text(encoding='utf-8'))['cases']
	out = {case['id']: {} for case in cases}
	with ProcessPoolExecutor() as pool:
		for case_id, opener, result in pool.map(one, [(case, opener) for case in cases for opener in case['rows']]):
			out[case_id][opener] = result
	json.dump(out, sys.stdout, ensure_ascii=False, indent='\t')
	print()
