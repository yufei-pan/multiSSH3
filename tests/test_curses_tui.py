import curses

import pytest

import multiSSH3


def test_get_hosts_to_display_windowing(fake_host):
	hosts = [fake_host(f"127.0.0.{i}", "true") for i in range(1, 6)]
	for host in hosts[:2]:
		host.returncode = 0
		host.output = ["done"]

	displayed, stats, rearranged = multiSSH3._get_hosts_to_display(
		hosts,
		max_num_hosts=2,
		indexOffset=0,
	)

	assert displayed == hosts[:2]
	assert stats == {
		"running": 0,
		"failed": 0,
		"finished": 2,
		"waiting": 3,
	}
	assert rearranged == set(displayed)


@pytest.mark.live_tui
def test_curses_initscr_smoke(curses_harness):
	if curses_harness.mode != "live":
		pytest.skip("curses needs a terminal")

	def _probe(stdscr):
		stdscr.addstr(0, 0, "mssh")
		return True

	assert curses.wrapper(_probe) is True
