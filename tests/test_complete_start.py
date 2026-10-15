'''
START_SCRIPT, the POSIX sh zsh and fish run the picker with: it gives the picker
MSSH_COMPLETE_START_TIMEOUT seconds to take the terminal (to create MSSH_COMPLETE_CLAIM), then as
long as the operator takes. At the time limit, or on Ctrl-C, it claims the terminal itself and stops
the picker, which has not touched it: exit 124 (too slow), 130 (Ctrl-C).
'''
import os
import signal
import subprocess
import time

import pytest

import mssh_complete as mc

FAKE_PICKER = r'''
sleep "$1"
mkdir "$MSSH_COMPLETE_CLAIM" 2>/dev/null || exit 2
printf 'picked %s\n' "$(cat)"
sleep "$2"
exit "$3"
'''


def start(tmp_path, limit, delay, picking=0, status=0, request=b'the request', interrupt_after=None, deaf=False, fake_text=FAKE_PICKER):
	'''Run START_SCRIPT on the fake picker; (exit status, stdout, seconds taken, the fake's pids still running).'''
	fake = tmp_path / 'fake-picker'
	fake.write_text(("trap '' INT\n" if deaf else '') + fake_text)
	pids = tmp_path / 'pids'
	command = [os.environ.get('MSSH_TEST_SH', 'sh'), '-c', mc.START_SCRIPT, 'sh', str(limit), 'sh', '-c', 'echo $$ >> "$0"; exec sh "$1" "$2" "$3" "$4" "$5"',
		str(pids), str(fake), str(delay), str(picking), str(status)]
	started = time.monotonic()
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
	process.stdin.write(request)
	process.stdin.close()
	if interrupt_after is not None:
		time.sleep(interrupt_after)
		# Ctrl-C: the terminal signals the whole foreground process group
		os.killpg(process.pid, signal.SIGINT)
	out = process.stdout.read()
	code = process.wait(10)
	taken = time.monotonic() - started
	running = []
	for pid in (pids.read_text().split() if pids.exists() else []):
		try:
			os.kill(int(pid), 0)
			running.append(pid)
		except OSError:
			pass
	return code, out.decode(), taken, running


def test_a_picker_quick_to_start_runs_as_long_as_the_operator_takes(tmp_path):
	code, out, taken, running = start(tmp_path, limit=0.5, delay=0, picking=1.2, status=0)

	assert code == 0 and out == 'picked the request\n' and taken >= 1.2 and not running


@pytest.mark.parametrize('status', [1, 2])
def test_the_picker_s_exit_status_is_the_answer(tmp_path, status):
	assert start(tmp_path, limit=2, delay=0, status=status)[0] == status


def test_a_picker_slow_to_start_is_stopped_at_the_time_limit(tmp_path):
	code, out, taken, running = start(tmp_path, limit=0.3, delay=3)

	# the shell goes on: as soon as the time is up, and the picker is gone without drawing
	assert code == 124 and out == '' and taken < 1.5 and not running


def test_one_that_cannot_start_answers_at_once(tmp_path):
	# nothing to pick, or no terminal: the picker exits 2 without claiming it
	code, out, taken, running = start(tmp_path, limit=2, delay=0, fake_text='cat >/dev/null; exit 2\n')

	assert code == 2 and out == '' and taken < 1.5


@pytest.mark.parametrize('deaf', [False, True])
def test_ctrl_c_while_it_starts_stops_it(tmp_path, deaf):
	# also one that ignores Ctrl-C, as when it waits on a hung file system
	code, out, taken, running = start(tmp_path, limit=5, delay=3, interrupt_after=0.4, deaf=deaf)

	assert code == 130 and out == '' and taken < 1.5 and not running


def test_ctrl_c_once_it_has_the_terminal_is_its_own(tmp_path):
	# the picker reads Ctrl-C as a key then; a signal (another process) does not take the terminal from it
	code, out, taken, running = start(tmp_path, limit=5, delay=0, picking=1, interrupt_after=0.4)

	assert code == 0 and out == 'picked the request\n'


def test_no_helper_keeps_the_answer_open(tmp_path):
	# a command substitution reads until every writer of its pipe has gone: the sleeper must not be one
	code, out, taken, running = start(tmp_path, limit=3, delay=0)

	assert code == 0 and taken < 1.5


@pytest.mark.parametrize('limit', ['0', '0.0'])
def test_no_time_at_all(tmp_path, limit):
	assert start(tmp_path, limit=limit, delay=0.5)[0] == 124
