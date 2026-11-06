#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, current (the newest Python), legacy, el9 and centos7 images,
# and bash 5.0, 5.1 and 5.3 alone (readline key bindings change between bash versions: see their Dockerfiles; the test of a
# Ctrl-C right after Ctrl-R runs on bash 5.0 only, no other image has a bash that fails it).
# The images run at once (the tests mostly wait on shells, not the CPU), each in a container capped at 8 GB, and each with
# pytest-xdist workers: the processors divided by the images started, at least 1 and at most 8 (MSSH_MATRIX_JOBS sets it; 1 runs
# the tests one after the other). Each one's output is shown when all are done.
# A test that fails in the parallel run is run again alone (pytest --lf); the second run decides, so a real failure still fails and
# a test that only fails under load passes. The first run's FAILED lines stay in the log, and the summary at the end names each
# test that needed the rerun: a flake stays visible.
# Usage: tests/shells/run_matrix.sh [modern] [current] [legacy] [el9] [centos7] [bash5.0] [bash5.1] [bash5.3]   (default: all eight)
# MSSH_MATRIX_TESTS picks the pytest arguments (default: tests/test_complete_*.py). The whole suite, e.g. on
# Python 3.6: MSSH_MATRIX_TESTS=tests tests/shells/run_matrix.sh legacy centos7
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
images=("$@")
[ ${#images[@]} -gt 0 ] || images=(modern current legacy el9 centos7 bash5.0 bash5.1 bash5.3)
jobs=${MSSH_MATRIX_JOBS:-$(( $(nproc) / ${#images[@]} ))}
(( jobs >= 1 )) || jobs=1
[ -n "${MSSH_MATRIX_JOBS:-}" ] || (( jobs <= 8 )) || jobs=8
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT
required=()
pids=()
for name in "${images[@]}"; do
	case $name in
		centos7) required+=(bash,zsh,blesh) ;;
		bash5.0|bash5.1|bash5.3) required+=(bash) ;;
		modern|current|legacy|el9) required+=(bash,zsh,fish,blesh,zas,zsh-syntax-highlighting) ;;
		*) echo "unknown image: $name" >&2; exit 2 ;;
	esac
	(
		docker build -q -t "mssh-shell-test-$name" -f "$here/Dockerfile.$name" "$here" >/dev/null
		start=$SECONDS
		# the repository is read-only inside: no bytecode; HOME is a fresh directory, which holds pytest's cache for the rerun. Each
		# run is capped (memory, no swap, pids) and runs as nobody, so a runaway test stays inside its own container.
		status=0
		docker run --rm --memory=8g --memory-swap=8g --pids-limit=4096 --user 65534:65534 \
			-v "$repo":/repo:ro -w /repo -e MSSH_REQUIRE_SHELLS="${required[-1]}" -e PYTHONDONTWRITEBYTECODE=1 \
			-e MSSH_MATRIX_TESTS="${MSSH_MATRIX_TESTS:-tests/test_complete_*.py}" -e MSSH_MATRIX_JOBS_RUN="$jobs" \
			"mssh-shell-test-$name" sh -c 'export HOME=$(mktemp -d); python3 -V
				workers=; [ "$MSSH_MATRIX_JOBS_RUN" -le 1 ] || workers="-n $MSSH_MATRIX_JOBS_RUN"
				python3 -m pytest -q -o cache_dir=$HOME/.pc $workers $MSSH_MATRIX_TESTS > $HOME/first.log 2>&1 && status=0 || status=$?
				cat $HOME/first.log
				if [ $status -ne 0 ] && grep -q "^FAILED\|^ERROR" $HOME/first.log; then
					echo "=== run again alone: the tests that failed"
					python3 -m pytest -q -o cache_dir=$HOME/.pc --lf $MSSH_MATRIX_TESTS && status=0 || status=$?
					[ $status -ne 0 ] || { echo "=== NEEDED THE RERUN (passed alone):"; grep "^FAILED\|^ERROR" $HOME/first.log; }
				fi
				exit $status' || status=$?
		echo "=== took $(( SECONDS - start )) s with $jobs workers"
		exit $status
	) > "$logs/$name.log" 2>&1 &
	pids+=($!)
done
status=0
for index in "${!images[@]}"; do
	wait "${pids[index]}" || status=1
	echo "=== ${images[index]} (requires ${required[index]})"
	cat "$logs/${images[index]}.log"
done
echo "=== summary"
for index in "${!images[@]}"; do
	log="$logs/${images[index]}.log"
	echo "${images[index]}: $(grep -E ' passed| failed' "$log" | tail -1) ($(grep '^=== took' "$log"))"
	if grep -q '^=== NEEDED THE RERUN' "$log"; then
		sed -n '/^=== NEEDED THE RERUN/,/^=== took/p' "$log" | grep -v '^=== took' | sed "s/^/${images[index]}: /"
	fi
done
exit $status
