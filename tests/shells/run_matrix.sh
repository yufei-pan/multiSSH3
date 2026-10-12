#!/usr/bin/env bash
# Run the autocomplete tests in the Docker shell matrix: modern, current (the newest Python), legacy and centos7 images.
# Usage: tests/shells/run_matrix.sh [modern] [current] [legacy] [centos7]   (default: all four)
# MSSH_MATRIX_TESTS picks the pytest arguments (default: tests/test_complete_*.py)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
images=("$@")
[ ${#images[@]} -gt 0 ] || images=(modern current legacy centos7)
status=0
for name in "${images[@]}"; do
	case $name in
		centos7) required=bash,blesh ;;
		modern|current|legacy) required=bash,zsh,fish,blesh,zas ;;
		*) echo "unknown image: $name" >&2; exit 2 ;;
	esac
	echo "=== $name (requires $required)"
	docker build -q -t "mssh-shell-test-$name" -f "$here/Dockerfile.$name" "$here" >/dev/null
	# the repository is read-only inside: no bytecode, no pytest cache; HOME is a fresh directory
	docker run --rm -v "$repo":/repo:ro -w /repo -e MSSH_REQUIRE_SHELLS="$required" -e PYTHONDONTWRITEBYTECODE=1 \
		-e MSSH_MATRIX_TESTS="${MSSH_MATRIX_TESTS:-tests/test_complete_*.py}" \
		"mssh-shell-test-$name" sh -c 'export HOME=$(mktemp -d); python3 -V; python3 -m pytest -q -p no:cacheprovider $MSSH_MATRIX_TESTS' \
		|| status=1
done
exit $status
