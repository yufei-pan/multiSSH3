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
