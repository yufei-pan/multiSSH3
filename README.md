# multiSSH3
A script that is able to issue commands to multiple hosts while monitoring their progress.
Can be used in bash scripts for automation actions.
Also able to be imported and / or use with Flexec SSH Backend to perform cluster automation actions.

Install via
```
pip install multiSSH3
```

multiSSH3 will be available as
```
mssh
mssh3
multissh
multissh3
multiSSH3
```

multissh will read a config file located at ```/etc/multiSSH3.config.json```

To store / generate a config file with the current command line options, you can use

```
mssh --generate_default_config_file
```

You can modify the json file directly after generation and multissh will read from it for loading defaults. 

Note:

If you want to store password, it will be a plain text password in this config file. This will be better to supply it everytime as a CLI argument but you should really consider setting up priv-pub key setup.

This option can also be used to store cli options into the config files. For example.

```
mssh --ipmi_interface_ip_prefix 192 --generate_default_config_file
```
will store 
```
"DEFAULT_IPMI_INTERFACE_IP_PREFIX": "192"
```
into the json file.

By defualt reads bash env variables for hostname aliases. Also able to read
```
DEFAULT_ENV_FILE = '/etc/profile.d/hosts.sh'
```
as hostname aliases.

For example:
```
export all='192.168.1-2.1-64'
mssh all 'echo hi'
```

It is also able to recognize ip blocks / number blocks / hex blocks / character blocks directly.

For example:
```
mssh testrig[1-10] lsblk
mssh ww[a-c],10.100.0.* 'cat /etc/fstab' 'sed -i "/lustre/d' /etc/fstab' 'cat /etc/fstab'
```

It also supports interactive inputs. ( and able to async boardcast to all supplied hosts )
```
mssh www bash
```

By default, it will try to fit everything inside your window. 
```
DEFAULT_CURSES_MINIMUM_CHAR_LEN = 40
DEFAULT_CURSES_MINIMUM_LINE_LEN = 1
```
While leaving minimum 40 characters / 1 line for each host display by default. You can modify this by using -ww and -wh.


Use ```mssh --help``` for more info.

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

Following document is generated courtesy of Mr.ChatGPT-o1 Preview:

# multissh

`multissh` is a powerful Python script that allows you to run commands on multiple hosts concurrently over SSH. It supports various features such as copying files, handling IP address ranges, using IPMI, and more. It's designed to simplify the management of multiple remote systems by automating command execution and file synchronization.

## Table of Contents

- [multiSSH3](#multissh3)
- [multissh](#multissh)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Basic Syntax](#basic-syntax)
    - [Command-Line Options](#command-line-options)
  - [Examples](#examples)
    - [Running a Command on Multiple Hosts](#running-a-command-on-multiple-hosts)
    - [Copying Files to Multiple Hosts](#copying-files-to-multiple-hosts)
    - [Using Hostname Ranges](#using-hostname-ranges)
    - [Using IPMI](#using-ipmi)
    - [Using Password Authentication](#using-password-authentication)
    - [Skipping Unreachable Hosts](#skipping-unreachable-hosts)
    - [JSON Output](#json-output)
    - [Quiet Mode](#quiet-mode)
  - [Environment Variables](#environment-variables)
  - [Notes](#notes)
  - [License](#license)

## Features

- **Concurrent Execution**: Run commands on multiple hosts concurrently with controlled parallelism.
- **File Transfer**: Copy files or synchronize directories to multiple hosts using `rsync` or `scp`.
- **Hostname Expansion**: Support for hostname ranges and wildcards for easy targeting of multiple hosts.
- **IPMI Support**: Execute IPMI commands on remote hosts.
- **Authentication**: Support for SSH password authentication and key-based authentication.
- **Custom SSH Options**: Pass extra arguments to SSH, `rsync`, or `scp` commands.
- **Skip Unreachable Hosts**: Option to skip hosts that are unreachable.
- **Output Formats**: Supports JSON and greppable output formats.
- **Interactive Mode**: Run interactive commands with curses-based UI for monitoring.
- **Quiet Mode**: Suppress output for cleaner automation scripts.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/multissh.git
   ```

2. **Navigate to the Directory**

   ```bash
   cd multissh
   ```

3. **Make the Script Executable**

   ```bash
   chmod +x multissh.py
   ```

4. **Install Dependencies**

   Ensure you have Python 3 and the required modules installed. You may need to install `curses` and `ipaddress` modules if they are not already available.

## Usage

### Basic Syntax

```bash
./multissh.py [options] <hosts> <commands>
```

- `<hosts>`: Comma-separated list of target hosts. Supports ranges and wildcards.
- `<commands>`: Command(s) to execute on the target hosts.

### Command-Line Options

| Short Option | Long Option               | Description                                                                                               |
|--------------|---------------------------|-----------------------------------------------------------------------------------------------------------|
| `-u`         | `--username`              | Username for SSH connections.                                                                             |
| `-ea`        | `--extraargs`             | Extra arguments for SSH/rsync/scp commands.                                                               |
| `-p`         | `--password`              | Password for SSH authentication. Requires `sshpass`.                                                      |
| `-11`        | `--oneonone`              | Run one command per host (commands and hosts lists must have the same length).                            |
| `-f`         | `--file`                  | File(s) to copy to the hosts. Can be used multiple times.                                                 |
|              | `--file_sync`             | Synchronize directories instead of copying files.                                                         |
|              | `--scp`                   | Use `scp` instead of `rsync` for file transfer.                                                           |
| `-t`         | `--timeout`               | Command execution timeout in seconds.                                                                     |
| `-r`         | `--repeat`                | Number of times to repeat the command execution.                                                          |
| `-i`         | `--interval`              | Interval between command repetitions in seconds.                                                          |
|              | `--ipmi`                  | Use IPMI to execute commands.                                                                             |
| `-pre`       | `--interface_ip_prefix`   | IP prefix for interface selection.                                                                        |
| `-q`         | `--quiet`                 | Suppress output.                                                                                          |
| `-ww`        | `--window_width`          | Minimum character width for the curses window.                                                            |
| `-wh`        | `--window_height`         | Minimum line height for the curses window.                                                                |
| `-sw`        | `--single_window`         | Use a single window for all hosts in curses mode.                                                         |
| `-eo`        | `--error_only`            | Only display error outputs.                                                                               |
| `-no`        | `--nooutput`              | Do not print any output.                                                                                  |
|              | `--no_env`                | Do not load environment variables from files.                                                             |
|              | `--env_file`              | Specify a custom environment file.                                                                        |
| `-m`         | `--maxconnections`        | Maximum number of concurrent SSH connections.                                                             |
| `-j`         | `--json`                  | Output results in JSON format.                                                                            |
|              | `--success_hosts`         | Also display hosts where commands succeeded.                                                              |
| `-g`         | `--greppable`             | Output results in a greppable format.                                                                     |
| `-nw`        | `--nowatch`               | Do not use curses mode; use simple output instead.                                                        |
| `-su`        | `--skipunreachable`       | Skip hosts that are unreachable.                                                                          |
| `-sh`        | `--skiphosts`             | Comma-separated list of hosts to skip.                                                                    |
| `-V`         | `--version`               | Display the script version and exit.                                                                      |

## Examples

### Running a Command on Multiple Hosts

```bash
./multissh.py "host1,host2,host3" "uptime"
```

This command runs `uptime` on `host1`, `host2`, and `host3`.

### Copying Files to Multiple Hosts

```bash
./multissh.py -f "/path/to/local/file.txt" "host1,host2,host3" "/remote/path/"
```

This command copies `file.txt` to `/remote/path/` on the specified hosts.

### Using Hostname Ranges

```bash
./multissh.py "host[01-05]" "hostname"
```

This expands to `host01`, `host02`, `host03`, `host04`, `host05` and runs `hostname` on each.

### Using IPMI

```bash
./multissh.py --ipmi "192.168.1.[100-105]" "chassis power status"
```

Runs `ipmitool chassis power status` on the specified IPMI interfaces.

### Using Password Authentication

```bash
./multissh.py -p "yourpassword" "host1,host2" "whoami"
```

Uses `sshpass` to provide the password for SSH authentication.

### Skipping Unreachable Hosts

```bash
./multissh.py -su "host1,host2,host3" "date"
```

Skips hosts that are unreachable during execution.

### JSON Output

```bash
./multissh.py -j "host1,host2" "uname -a"
```

Outputs the results in JSON format, suitable for parsing.

### Quiet Mode

```bash
./multissh.py -q "host1,host2" "ls /nonexistent"
```

Suppresses all output, useful for scripts where you only care about exit codes.

## Environment Variables

- The script can load environment variables from a file (default: `/etc/profile.d/hosts.sh`) to resolve hostnames.
- Use the `--env_file` option to specify a custom environment file.
- Use `--no_env` to prevent loading any environment variables from files.

## Notes

- **SSH Configuration**: The script modifies `~/.ssh/config` to disable `StrictHostKeyChecking`. Ensure this is acceptable in your environment.
- **Dependencies**: Requires Python 3, `sshpass` (if using password authentication), and standard Unix utilities like `ssh`, `scp`, and `rsync`.
- **Signal Handling**: Supports graceful termination with `Ctrl+C`.

## License

This script is provided "as is" without any warranty. Use it at your own risk.

---
