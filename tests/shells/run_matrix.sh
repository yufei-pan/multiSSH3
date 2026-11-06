#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, current (the newest Python), legacy, el9 and centos7 images,
# and bash 5.0, 5.1 and 5.3 alone (readline key bindings change between bash versions: see their Dockerfiles; the test of a
# Ctrl-C right after Ctrl-R runs on bash 5.0 only, no other image has a bash that fails it).
# The images run at once (the tests mostly wait on shells, not the CPU), each in a container capped at 8 GB, and each with
# pytest-xdist workers: the processors divided by the images started, at least 1 and at most 8 (MSSH_MATRIX_JOBS sets it; 1 runs
# the tests one after the other). Each one's output is shown when all are done.
# A test that fails in the parallel run is run again alone (pytest --lf). The first run's FAILED lines stay in the log. A rerun
# that passes is NOT evidence that the test is fine: a race that fails under load can pass alone. So the exit status tells: 0
# when every image passed the first time, 1 when something fails on the rerun too, 3 when all passed but some test needed the
# rerun (1 outranks 3, 3 outranks 0; the CI job takes the status as it is: a rerun turns it red); and the output ends with one "RERUN <image> <test id>" line for each such test.
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
		# The rerun (pytest --lf) runs what the cache lists as failed; the ids the run left failed after it are the ones that fail alone,
		# the others passed only on the rerun (the ids come from the cache, whole: the FAILED lines cut them at a " - ")
		status=0
		docker run --rm --memory=8g --memory-swap=8g --pids-limit=4096 --user 65534:65534 \
			-v "$repo":/repo:ro -w /repo -e MSSH_REQUIRE_SHELLS="${required[-1]}" -e PYTHONDONTWRITEBYTECODE=1 \
			-e MSSH_MATRIX_TESTS="${MSSH_MATRIX_TESTS:-tests/test_complete_*.py}" -e MSSH_MATRIX_JOBS_RUN="$jobs" \
			"mssh-shell-test-$name" sh -c 'export HOME=$(mktemp -d); python3 -V
				failed_ids() { python3 -c "import json, sys; print(*sorted(json.load(open(sys.argv[1]))), sep=chr(10))" "$HOME/.pc/v/cache/lastfailed" 2>/dev/null || :; }
				workers=; [ "$MSSH_MATRIX_JOBS_RUN" -le 1 ] || workers="-n $MSSH_MATRIX_JOBS_RUN"
				python3 -m pytest -q -o cache_dir=$HOME/.pc $workers $MSSH_MATRIX_TESTS > $HOME/first.log 2>&1 && status=0 || status=$?
				cat $HOME/first.log
				if [ $status -ne 0 ]; then
					failed_ids > $HOME/first.ids
					if [ -s $HOME/first.ids ]; then
						echo "=== run again alone: the tests that failed"
						python3 -m pytest -q -o cache_dir=$HOME/.pc --lf $MSSH_MATRIX_TESTS && status=0 || status=$?
						failed_ids > $HOME/second.ids
						grep -vxFf $HOME/second.ids $HOME/first.ids > $HOME/passed.ids || :
						if [ -s $HOME/passed.ids ]; then
							echo "=== NEEDED THE RERUN (passed alone):"
							sed "s/^/RERUNID /" $HOME/passed.ids
						fi
					fi
				fi
				echo "=== exit $status"
				exit $status' || status=$?
		echo "=== took $(( SECONDS - start )) s with $jobs workers"
		exit $status
	) > "$logs/$name.log" 2>&1 &
	pids+=($!)
done
failed=0
reran=0
for index in "${!images[@]}"; do
	code=0
	wait "${pids[index]}" || code=$?
	if [ $code -ne 0 ]; then failed=1; fi
	if grep -q '^=== NEEDED THE RERUN' "$logs/${images[index]}.log"; then reran=1; fi
	echo "=== ${images[index]} (requires ${required[index]})"
	cat "$logs/${images[index]}.log"
done
echo "=== summary"
for index in "${!images[@]}"; do
	log="$logs/${images[index]}.log"
	# pytest's last line of a run: "N passed, ... in 12.3s"; the first run's and, when it was run again, the rerun's
	summaries=$(grep -E '^[0-9]+ [a-z]+.* in [0-9.]+s' "$log" || :)
	first=$(printf '%s\n' "$summaries" | head -1)
	[ -n "$first" ] || first="no pytest summary (the run ended early: see its log)"
	line="${images[index]}: $first"
	if grep -q '^=== run again alone' "$log"; then
		# the rerun's own summary only: when the rerun died before printing one, the first run's would stand there
		again=$(sed -n '/^=== run again alone/,$p' "$log" | { grep -E '^[0-9]+ [a-z]+.* in [0-9.]+s' || :; } | tail -1)
		line="$line; run again alone: ${again:-no pytest summary (the rerun ended early: see its log)}"
	fi
	echo "$line ($(grep '^=== took' "$log" | tail -1 | sed 's/^=== //'), $(grep '^=== exit' "$log" | tail -1 | sed 's/^=== //'))"
done
for index in "${!images[@]}"; do
	{ grep '^RERUNID ' "${logs}/${images[index]}.log" || :; } | sed "s/^RERUNID /RERUN ${images[index]} /"
done
[ $failed -eq 0 ] || exit 1
[ $reran -eq 0 ] || exit 3
exit 0
