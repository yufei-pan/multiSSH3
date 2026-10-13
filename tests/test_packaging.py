"""The packaging: what setup.py puts in the sdist and its metadata, with the setuptools this Python has."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(importlib.util.find_spec("setuptools") is None, reason="needs setuptools to run setup.py")


def run_egg_info(egg_base, env=None):
	"""Run `setup.py egg_info` into egg_base: its SOURCES.txt is the file list `setup.py sdist` ships.
	Nothing is written into the source tree, which the Docker matrix mounts read-only."""
	env = dict(os.environ if env is None else env, PYTHONDONTWRITEBYTECODE="1")
	return subprocess.run([sys.executable, "setup.py", "-q", "egg_info", "--egg-base", str(egg_base)],
		cwd=str(PACKAGE_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)


@pytest.fixture(scope="module")
def egg_info(tmp_path_factory):
	egg_base = tmp_path_factory.mktemp("egg_base")
	result = run_egg_info(egg_base)
	assert result.returncode == 0, result.stderr
	return egg_base / "multiSSH3.egg-info", result


def sdist_files(egg_info):
	return set((egg_info[0] / "SOURCES.txt").read_text(encoding="utf-8").splitlines())


def test_sdist_ships_everything_the_test_suite_needs(egg_info):
	# conftest.py, the harnesses, tests/data and pytest.ini too: without them pytest in an unpacked sdist fails to collect
	wanted = {"setup.py", "README.md", "multiSSH3.py", "mssh_complete.py", "pytest.ini"}
	for path in (PACKAGE_ROOT / "tests").rglob("*"):
		relative = path.relative_to(PACKAGE_ROOT)
		# bytecode and hidden files (caches, editor swap files) are a developer's, not the suite's
		if path.is_file() and path.suffix != ".pyc" and not [part for part in relative.parts if part == "__pycache__" or part.startswith(".")]:
			wanted.add(relative.as_posix())
	shipped = sdist_files(egg_info)
	assert sorted(wanted - shipped) == []
	assert [path for path in shipped if "__pycache__" in path or path.endswith(".pyc")] == []
