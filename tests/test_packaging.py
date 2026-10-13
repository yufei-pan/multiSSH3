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


def metadata_lines(egg_info):
	"""PKG-INFO's header lines: the README that follows them could hold any line."""
	return (egg_info[0] / "PKG-INFO").read_text(encoding="utf-8").split("\n\n", 1)[0].splitlines()


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


def test_setup_runs_in_an_ascii_locale(tmp_path):
	# pip on Python 3.6 with LANG=C: open() without an encoding reads ASCII, and README.md is not ASCII (→, ⚠, —).
	# Python 3.7+ switches to UTF-8 by itself in the C locale; PYTHONUTF8=0 and PYTHONCOERCECLOCALE=0 stop that.
	env = dict(os.environ, LC_ALL="C", LANG="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
	probe = subprocess.run([sys.executable, "-c", "import locale; print(locale.getpreferredencoding(False))"],
		env=env, stdout=subprocess.PIPE, universal_newlines=True, timeout=60)
	if probe.stdout.strip().lower().replace("-", "") == "utf8":
		pytest.skip("the C locale reads UTF-8 here")
	result = run_egg_info(tmp_path, env)
	assert result.returncode == 0, result.stderr


def test_setup_declares_the_license_without_warnings(egg_info):
	# setuptools 77+ (PEP 639) wants an SPDX License-Expression and warns about license classifiers; older ones (the
	# newest for Python 3.8 and earlier) know only the free-text License and the classifier, and warn about unknown options
	warnings = [line for line in egg_info[1].stderr.splitlines() if "Warning" in line and "icense" in line]
	assert warnings == []
	metadata = metadata_lines(egg_info)
	if "License-Expression: GPL-3.0-or-later" in metadata:
		assert [line for line in metadata if line.startswith(("License:", "Classifier: License ::"))] == []
	else:
		assert "License: GPL-3.0-or-later" in metadata
		assert "Classifier: License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)" in metadata
