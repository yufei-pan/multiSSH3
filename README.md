# multiSSH3
A script that is able to issue commands to multiple hosts while monitoring their progress.
Can be used in bash scripts for automation actions.
Also able to be imported and / or use with Flexec SSH Backend to perform cluster automation actions.

By defualt reads bash env variables for hostname aliases. Also able to read
```
DEFAULT_ENV_FILE = '/etc/profile.d/hosts.sh'
```
as hostname aliases.

For example:
```
export all='192.168.1-2.1-64'
multiSSH3.py all 'echo hi'
```

It is also able to recognize ip blocks / number blocks / hex blocks / character blocks directly.

For example:
```
multiSSH3.py testrig[1-10] lsblk
multiSSH3.py ww[a-c],10.100.0.* 'cat /etc/fstab' 'sed -i "/lustre/d' /etc/fstab' 'cat /etc/fstab'
```

It also supports interactive inputs. ( and able to async boardcast to all supplied hosts )
```
multiSSH3.py www bash
```

By default, it will try to fit everything inside your window. 
```
DEFAULT_CURSES_MINIMUM_CHAR_LEN = 40
DEFAULT_CURSES_MINIMUM_LINE_LEN = 1
```
While leaving minimum 40 characters / 1 line for each host display by default. You can modify this by using -ww and -wh.


Use ```multiSSH3.py --help``` for more info.

```
usage: mssh [-h] [-u USERNAME] [-ea EXTRAARGS] [-p PASSWORD] [-11] [-f FILE] [--file_sync] [--scp] [-t TIMEOUT] [-r REPEAT] [-i INTERVAL] [--ipmi]
            [-pre INTERFACE_IP_PREFIX] [-q] [-ww WINDOW_WIDTH] [-wh WINDOW_HEIGHT] [-sw] [-eo] [-no] [--no_env] [--env_file ENV_FILE] [-m MAXCONNECTIONS] [-j]
            [--success_hosts] [-g] [-nw] [-su] [-sh SKIPHOSTS] [-V]
            hosts commands [commands ...]

Run a command on multiple hosts, Use #HOST# or #HOSTNAME# to replace the host name in the command

positional arguments:
  hosts                 Hosts to run the command on, use "," to seperate hosts
  commands              the command to run on the hosts / the destination of the files #HOST# or #HOSTNAME# will be replaced with the host name.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        The general username to use to connect to the hosts. Will get overwrote by individual username@host if specified. (default: None)
  -ea EXTRAARGS, --extraargs EXTRAARGS
                        Extra arguments to pass to the ssh / rsync / scp command. Put in one string for multiple arguments.Use "=" ! Ex. -ea="--delete" (default:
                        None)
  -p PASSWORD, --password PASSWORD
                        The password to use to connect to the hosts, (default: hermes)
  -11, --oneonone       Run one corresponding command on each host. (default: False)
  -f FILE, --file FILE  The file to be copied to the hosts. Use -f multiple times to copy multiple files
  --file_sync           Operate in file sync mode, sync path in <COMMANDS> from this machine to <HOSTS>. Treat --file <FILE> and <COMMANDS> both as source as source
                        and destination will be the same in this mode. (default: False)
  --scp                 Use scp for copying files instead of rsync. Need to use this on windows. (default: False)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for each command in seconds (default: 0 (disabled))
  -r REPEAT, --repeat REPEAT
                        Repeat the command for a number of times (default: 1)
  -i INTERVAL, --interval INTERVAL
                        Interval between repeats in seconds (default: 0)
  --ipmi                Use ipmitool to run the command. (default: False)
  -pre INTERFACE_IP_PREFIX, --interface_ip_prefix INTERFACE_IP_PREFIX
                        The prefix of the for the interfaces (default: None)
  -q, --quiet           Quiet mode, no curses, only print the output. (default: False)
  -ww WINDOW_WIDTH, --window_width WINDOW_WIDTH
                        The minimum character length of the curses window. (default: 40)
  -wh WINDOW_HEIGHT, --window_height WINDOW_HEIGHT
                        The minimum line height of the curses window. (default: 1)
  -sw, --single_window  Use a single window for all hosts. (default: False)
  -eo, --error_only     Only print the error output. (default: False)
  -no, --nooutput       Do not print the output. (default: False)
  --no_env              Do not load the environment variables. (default: False)
  --env_file ENV_FILE   The file to load the environment variables from. (default: /etc/profile.d/hosts.sh)
  -m MAXCONNECTIONS, --maxconnections MAXCONNECTIONS
                        Max number of connections to use (default: 4 * cpu_count)
  -j, --json            Output in json format. (default: False)
  --success_hosts       Output the hosts that succeeded in summary as wells. (default: False)
  -g, --greppable       Output in greppable format. (default: False)
  -nw, --nowatch        Do not watch the output in curses modem, Use \r. Not implemented yet. (default: False)
  -su, --skipunreachable
                        Skip unreachable hosts while using --repeat. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto
                        skip unreachable hosts. (default: False)
  -sh SKIPHOSTS, --skiphosts SKIPHOSTS
                        Skip the hosts in the list. (default: )
  -V, --version         show program's version number and exit
```
