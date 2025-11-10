#!/usr/bin/env python3
import curses

# this script logs all the keys pressed in the terminal and print all the keycodes

def main(stdscr):
	stdscr.clear()
	stdscr.nodelay(True)
	stdscr.addstr(0,0,'Press any key to see the keycode. Press q to quit.')
	stdscr.refresh()
	while True:
		key = stdscr.getch()
		if key == -1:
			continue
		if key == ord('q'):
			break
		stdscr.clear()
		stdscr.addstr(0,0,'Press any key to see the keycode. Press q to quit.')
		stdscr.addstr(1,0,f'Key pressed: {key}')
		stdscr.refresh()

if __name__ == '__main__':
	curses.wrapper(main)