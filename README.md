# multiSSH3

## Introduction

multiSSH3 is a fast, flexible way to run commands and move files across many hosts in parallel, while watching everything live. 

Use it from the CLI for quick fleet actions or import it as a Python module for automation and orchestration. 

multiSSH3 understands host groups from env files, expands ranges, reuses SSH sessions, and presents clean outputs for human or machine (json / table).

### Demo Video
![Video Demo](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/multiSSH3_demo.mp4)

### Screenshots

#### *Running `date` on host group `all`*
![CLI output date](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/cli_date.png "CLI output date")

#### *Running `free` on host group `all`*
![CLI output free](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/cli_free.png "CLI output free")

#### *Running `ping` on host group `all`*
![Curses UI](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/curses_ui.png "Curses UI")

#### *Curses Help Window within curses display*
![Curses Help](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/curses_help.png "Curses Help")

#### *Curses single window mode with key '|'*
![Curses Single Window](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/curses_single_window.png "Curses Single Window")

#### *Running `free -h` on host group `all` with json output*
![JSON Output](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/json_output.png "JSON Output")

#### *Running `free -h` on host group `all` with greppable table output*
![Table Output](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/table_output.png "Table Output")

#### *Broadcasting `./test.txt` to host group `us` at `/tmp/test.txt`*
![File Broadcast](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/file_broadcast.png "File Broadcast")

#### *Syncing `/tmp/test.txt` from local machine to host group `all` (at `/tmp/test.txt`)*
![File Sync](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/file_sync.png "File Sync")

#### *Gathering `/tmp/test.txt` from host group `all` to local machine at `/tmp/test/<hostname>_test.txt`*
![File Gather](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/file_gather.png "File Gather")

#### *Running `power status` using ipmitool on host group `all` with IPMI interface prefixing* 
![IPMI Support](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/ipmi_support.png "IPMI Support")
> Note: `DB6` in image does not have IPMI over ethernet connection. It had failed back to running `ipmitool` over ssh.

#### *Running `date; df -h` on host group `all` showing the N-Host Diff (default threshold at 0.6)* 
![N-Host Diff](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/n_host_diff.png "N-Host Diff")

#### *Running `echo hi` on host range `<hostname>[10-20]*`* 
![Hostname Range Expansion](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/hostname_range_expansion.png "Hostname Range Expansion")

#### *Running `echo hi` on host range `127.0.0.1-100`* 
![IP Range Expansion](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/ip_range_expansion.png "IP Range Expansion")

#### *Summary shown with some hosts reporting error* 
![Return Code Summary](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/return_code_summary.png "Return Code Summary")

#### *Command syntax / output / runtime comparism with Ansible ad-hoc* 
![Compared to Ansible ad-hoc](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/compare_ansible_ad_hoc.png "Compared to Ansible ad-hoc")
> Note: if you like to use ansible, you will likely be running playbooks. This comparison is just for showing ansible is not for running ad-hoc commands.

#### *Command syntax / Runtime comparism with pdsh* 
![Compared to pdsh time](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/compare_pdsh_time.png "Compared to pdsh time")

#### *Output comparism with pdsh* 
![Compared to pdsh output](https://raw.githubusercontent.com/yufei-pan/multiSSH3/refs/heads/main/docs/compare_pdsh_output.png "Compared to pdsh output")

## Highlights

- Run commands on many hosts simultaneously and asynchronously ( configurable max connections )

- Live interactive curses UI with per-host status. ( send input to all hosts asynchronously )

- Broadcast / gather files (rsync -> scp), with --file_sync syntaxic sugar

- Host discovery via env variables, files, ranges, and DNS; smart cached skip of unreachable hosts

- IPMI support with interface IP prefixing and SSH fallback

- Concurrency tuned for large fleets with resource-aware throttling

- Easily persist defaults via config files; ControlMaster config helper for speed

- Importable as a Python module for automation frameworks

- No client side code / dependencies! ( calling system ssh / rsync / scp )

- Support windows with openssh (server and client) !

## Why use it?

- If you think ansible is too slow

- If you think ansible is too clunky / cluttered

- If you think pdsh is too complicated / simple

- If you think pdsh output is too messy

- See progress in real time, not after-the-fact logs

- Operate at scale without drowning your terminal

- Keep your host definitions in simple env files and ranges ( customizable groupable DNS )

- Drop-in for scripts: stable exit codes, compact summaries, and capable to produce machine-friendly output

## Install
Install via
```bash
pip install multiSSH3
```

multiSSH3 will be in cli available as
```bash
mssh
mssh3
multissh
multissh3
multiSSH3
```
Need Python 3.6+

## Configuration
### Config File Chain
multissh treat config files as definable default values. 

Configed values can be inspected by simply running 
```bash
mssh -h
```
to print the help message with current default values.

Defaults are read from the following chain map stored as json files, top ones overwrite the bottom ones.:
| `CONFIG_FILE_CHAIN`                        |
| ------------------------------------------ |
| `./multiSSH3.config.json`                  |
| `~/multiSSH3.config.json`                  |
| `~/.multiSSH3.config.json`                 |
| `~/.config/multiSSH3/multiSSH3.config.json`|
| `/etc/multiSSH3.d/multiSSH3.config.json`   |
| `/etc/multiSSH3.config.json`               |

### Generating / Storing Config File
To store / generate a config file with the current command line options, you can use
```bash
mssh --store_config_file [STORE_CONFIG_FILE_PATH]
```
> `--store_config_file [STORE_CONFIG_FILE]`<br/>
> is equivalent to <br/>
> `--generate_config_file --config_file [CONFIG_FILE]` <br/>
> and <br/>
> `--generate_config_file > [STORE_CONFIG_FILE_PATH]`.
>
>`--generate_config_file` will output to stdout if `--config_file` is not specified. 

> Use `--store_config_file` without a path will store to `multiSSH3.config.json` in the current working directory.

You can modify the json file or use command line arguments to update values and store them as defaults.
```bash
mssh --timeout 180 --store_config_file
```
will store 
```json
...
"DEFAULT_CLI_TIMEOUT": "180"
...
```
into `./multiSSH3.config.json`


> If you want to store password, it will be a plain text password in this config file. This will be better to supply it everytime as a CLI argument but you should really consider setting up public-key authentication.

>On some systems, scp / rsync will require you use public-key authentication to work.<br/>

### SSH ControlMaster Configuration

Note: you probably want to set presistent ssh connections to speed up each connection events. 

You can add the following to your `~/.ssh/config` file to enable ControlMaster with a 1 hour persistence by running

```bash
mssh --add_control_master_config
```

```config
Host *
  ControlMaster auto
  ControlPath /run/user/%i/ssh_sockets_%C
  ControlPersist 3600
```

## Environment Variables for Hostname Aliases

multissh3 is able to read hostname grouping / aliases from environment variables.


By default mssh reads env variables and recursive resolves them if specified with a hostname that is not be able to be resolved from `/etc/hosts`. This functions as a pseudo dns service for hostname grouping.

> Use `[0-9]`, `[0-f]`, `[a-Z]` ranges in the hostname strings for range expansion.

> Use `,` to separate multiple hostnames / hostname groups.

### Hostname Resolution Logic

First, mssh will expand [a-b] ranges in the hostname strings.

- Check if an IPv4 range is given
    - Expand using ipv4 range expansion logic.
    - Return
- Check if range given is all numerical
    - Expand using numerical expansion logic.
    - Resolve hostnames
    - Return
- Check if range given is all hex characters
    - Expand using hex expansion logic.
    - Resolve hostnames
    - Return
- Else
    - Expand using alphanumeric expansion logic.
    - Resolve hostnames
    - Return

When hostname need to be resolved, mssh will check in the following order:
- Return if it is an ipv4 address
- Return if hostname is in /etc/hosts
- If `-C, --no_env` is not specified and hostname is in current terminal environment variables
    - Redo the whole range -> hostname resolution logic with the resolved env variable value.
- hostname is in map generated from env_file(s) specified by `--env_files ENV_FILES`
    - Redo the whole range -> hostname resolution logic with the resolved env variable value.
- Lookup using `socket.gethostbyname()` to query dns server. ( Slow! )

> TLDR:
>
> ipv4 address expansion -> range expansion -> identify ipv4 -> resolve using environment variables ( if not no_env ) -> env map from env_files -> remote hostname resolution


### Default Env Files

> Because command environment variables take precedence over env files, you can specify `-C, --no_env` or set `"DEFAULT_NO_ENV": true` in config file to disable environment variable lookup.

> Use `-ef ENV_FILE, --env_file ENV_FILE` to specify a single env file to replace the default env file lookup chain. ( Only this file will be used. )

> Use `-efs ENV_FILES, --env_files ENV_FILES` to append files to the end of the default env file lookup chain. ( Files will be loaded first to last. )


| `DEFAULT_ENV_FILES` |
| ------------- |
| `/etc/profile.d/hosts.sh` |
| `~/.bashrc` |
| `~/.zshrc` |
| `~/host.env` |
| `~/hosts.env` |
| `.env` |
| `host.env` |
| `hosts.env` |

Later files take precedence over earlier files.

### Example Env Hostname File

An example hostname alias file will look like:
```bash
us_east='100.100.0.1-3,us_east_prod_[1-5]'
us_central=""
us_west="100.101.0.1-2,us_west_prod_[a-c]_[1-3]"
us="$us_east,$us_central,$us_west"
asia="100.90.0-1.1-9"
eu=''
rhel8="$asia,$us_east"
all="$us,$asia,$eu"
```
( You can use bash replacements for grouping. )

### Hostname Range Expansion

mssh is also able to recognize ip blocks / number blocks / hex blocks / character blocks directly.

For example:
```bash
mssh testrig[1-10] lsblk
mssh ww[a-c],10.100.0.* 'cat /etc/fstab' 'sed -i "/lustre/d' /etc/fstab' 'cat /etc/fstab'
```

## Misc Features

### Interactive Inputs

It also supports interactive inputs. ( and able to async boardcast to all supplied hosts )
```bash
mssh www bash
```
mssh cache all inputs and send them to all hosts when they are ready to receive inputs.

### Curses Window Size Control

By default, it will try to fit everything inside your window. 
```bash
DEFAULT_WINDOW_WIDTH = 40
DEFAULT_WINDOW_HEIGHT = 1
```
While leaving minimum 40 characters / 1 line for each host display by default. You can modify this by using `-ww WINDOW_WIDTH, --window_width WINDOW_WIDTH` and `-wh WINDOW_HEIGHT, --window_height WINDOW_HEIGHT`.

> It is also possible to modify the window size within curses display by pressing keys:
> ```
> ?       : Toggle Help Menu   
> _ or +  : Change window hight
> { or }  : Change window width
> < or >  : Change host index  
> |(pipe) : Toggle single host
> Ctrl+D  : Exit               
> Ctrl+R  : Force refresh      
> ↑ or ↓  : Navigate history   
> ← or →  : Move cursor        
> PgUp/Dn : Scroll history by 5
> Home/End: Jump cursor        
> Esc     : Clear line         
> ```
> You can also toggle this help in curses by pressing `?` or `F1`.

### Command String Replacement

mssh will replace some magic strings in the command string with host specific values.

| Magic String    | Description                          |
| -------------   | ------------------------------------ |
| `#HOST#`        | Replaced with the expanded name /IP  |
| `#HOSTNAME#`    | Replaced with the expanded name / IP |
| `#USER#`        | Replaced with the username           |
| `#USERNAME#`    | Replaced with the username           |
| `#ID#`          | Replaced with the ID of the host obj |
| `#I# `          | Replaced with the index of the host  |
| `#PASSWD#`      | Replaced with the password           |
| `#PASSWORD#`    | Replaced with the password           |
| `#UUID#`        | Replaced with the UUID of the host   |
| `#RESOLVEDNAME#`| Replaced with the resolved name      |
| `#IP#`          | Replaced with the resolved IP        |

> Note: `#HOST#` and `#HOSTNAME#` are the supplied hostname / ip before any resolution.

> Note: Resolved name is the IP / Hostname with user appended and ip prefix applied. This is what got used to connect to the host.

## Options

Here details the options for multiSSH3 6.02 @ 2025-11-10

### `-u, --username USERNAME` | _`DEFAULT_USERNAME`_
- You can specify the username for all hosts using this option and / or specifying username@hostname per host in the host list.

### `-p, --password PASSWORD` | _`DEFAULT_PASSWORD`_
- You can specify the password for all hosts using this option. Although it is recommended to use SSH keys / store password in config file for authentication.

### `-k, --key, --identity [KEY]` | _`DEFAULT_IDENTITY_FILE`_
- You can specify the identity file or folder to use for public key authentication. If a folder is specified, it will search for a key file inside the folder.
- This option implies `--use_key`.
- If this option is not specified but `--use_key` is specified, it will search for identity files in `DEFAULT_IDENTITY_FILE`.
- If no value is specified, it will search `DEFAULT_SSH_KEY_SEARCH_PATH`.

### `-uk, --use_key` | _`DEFAULT_USE_KEY`_
- Attempt to use public key authentication to connect to the hosts.
- Will search for identity file in `DEFAULT_IDENTITY_FILE` if `--identity` is not specified.

### `-ea, --extraargs EXTRAARGS` | _`DEFAULT_EXTRA_ARGS`_
- Extra arguments to pass to the ssh / rsync / scp command. Put in one string for multiple arguments.
- Example:
```bash
mssh -ea="--delete" -f ./data/ allServers /tmp/data/
```

### `-11, --oneonone` | _`DEFAULT_ONE_ON_ONE`_
- Run commands in one-on-one mode, where each command corresponds to each host, front to back.
- If command list length is not equal to expanded host list length, an error will be raised.

### `-f, --file FILE` | None
- The file to be copied to the hosts. Use -f multiple times to copy multiple files.
- When file is specified, the command(s) will be treated as the destination path(s) on the remote hosts.
- By default, rsync will be tried first on linux, scp will be used on windows or if rsync have failed to on linux.

### `-s, -fs, --file_sync [FILE_SYNC]` | _`DEFAULT_FILE_SYNC`_
- Operate in file sync mode, sync path in `<COMMANDS>` from this machine to `<HOSTS>`.
- Treat `--file <FILE>` and `<COMMANDS>` both as source and source
- Destination path will be inferred from source path ( Absolute Path ).
- `-fs` can also be followed by a path, a syntaxic sugar for specifying the path after the option.
- Example:
```bash
mssh -fs -- allServers ./data/ # is equivalent to
mssh -fs ./data/ allServers # is equivalent to
mssh -fs -f ./data/ allServers # is equivalent to
# if the cwd is at /tmp,
mssh -f ./data/ allServers /tmp/data/
```

### `-W, --scp` | _`DEFAULT_SCP`_
- Use scp for copying files by default instead of trying rsync.
- Can speed up operation if we know rsync will not be available on remote hosts.

### `-G, -gm, --gather_mode` | False
- Gather files from the hosts instead of sending files to the hosts.
- Will send remote files specified in `<FILE>` to local path specified in `<COMMANDS>`.
- Likely you will need to combine with the [Command String Replacement](#command-string-replacement) feature to let each host transfer to a different local path.

### `-t, --timeout TIMEOUT` | _`DEFAULT_CLI_TIMEOUT`_
- Timeout for each command in seconds.
- When using 0, timeout is disabled.
- For CLI interface, will use `DEFAULT_CLI_TIMEOUT` as default.
- For module interface, will use `DEFAULT_TIMEOUT` as default.

### `-T, --use_script_timeout` | False
- In CLI, use `DEFAULT_TIMEOUT` as timeout value instead of `DEFAULT_CLI_TIMEOUT`.
- This is to emulate the module interface behavior as if using in a script.

### `-r, --repeat REPEAT` | _`DEFAULT_REPEAT`_
- Repeat the commands for a number of times.
- Commands will be repeated in sequence for the specified number of times.
- Between repeats, it will wait for `--interval INTERVAL` seconds.

### `-i, --interval INTERVAL` | _`DEFAULT_INTERVAL`_
- Interval between command repeats in seconds.
- Only effective when `REPEAT` is greater than 1.
- Note: will wait for `INTERVAL` seconds before first run if `REPEAT` is greater than 1.

### `-M, --ipmi` | _`DEFAULT_IPMI`_
- Use ipmitool to run the command instead of ssh.
- Will strip `ipmitool` from the start of the command if it is present.
- Will replace the host's resolved IP address header with `DEFAULT_IPMI_INTERFACE_IP_PREFIX` in this mode
- Ex: `10.0.0.1` + `DEFAULT_IPMI_INTERFACE_IP_PREFIX='192.168'` -> `192.168.0.1`
- Will retry using original ip and run `ipmitool` over ssh if ipmi connection had failed. ( Will append ipmitool to the command if not present )

### `-mpre, --ipmi_interface_ip_prefix IPMI_INTERFACE_IP_PREFIX` | _`DEFAULT_IPMI_INTERFACE_IP_PREFIX`_
- The prefix of the IPMI interfaces. Will replace the resolved IP address with the given prefix when using ipmi mode.
- This will take precedence over `INTERFACE_IP_PREFIX` when in ipmi mode.
- Ex: `10.0.0.1` + `-mpre '192.168'` -> `192.168.0.1`

### `-pre, --interface_ip_prefix INTERFACE_IP_PREFIX` | _`DEFAULT_INTERFACE_IP_PREFIX`_
- The prefix of the for the interfaces. Will replace the resolved IP address with the given prefix when connecting to the host.
- Will prioritize `IPMI_INTERFACE_IP_PREFIX` if it exists when in ipmi mode.
- Ex: `10.0.0.1` + `-pre '172.30'` -> `172.30.0.1`

### `-iu, --ipmi_username IPMI_USERNAME` | _`DEFAULT_IPMI_USERNAME`_
- The username to use to connect to the hosts via ipmi.
- This will be used when `--ipmi` is specified.
- If this is not specified, `DEFAULT_USERNAME` will be used in ipmi mode.

### `-ip, --ipmi_password IPMI_PASSWORD` | _`DEFAULT_IPMI_PASSWORD`_
- The password to use to connect to the hosts via ipmi.
- This will be used when `--ipmi` is specified.
- If this is not specified, `DEFAULT_PASSWORD` will be used in ipmi mode.

### `-S, -q, -nw, --no_watch` | _`DEFAULT_NO_WATCH`_
- Disable the curses terminal display and only print the output.
- Note this will not be 'quiet mode' traditionally, please use `-Q, -no, --quiet, --no_output` to disable output.
- Useful in scripting to reduce runtime and terminal flashing.

### `-ww, --window_width WINDOW_WIDTH` | _`DEFAULT_WINDOW_WIDTH`_
- The minimum character length of the curses window.
- Default is 40 characters.
- Will try to fit as many hosts as possible in the terminal window while leaving at least this many characters for each host display.
- You can modify this value in curses display by pressing `_` or `+`.

### `-wh, --window_height WINDOW_HEIGHT` | _`DEFAULT_WINDOW_HEIGHT`_
- The minimum line height of the curses window.
- Default is 1 line.
- Will try to fit as many hosts as possible in the terminal window while leaving at least this many lines for each host display.
- You can modify this value in curses display by pressing `{` or `}`.
- Terminal will overflow if it is smaller than ww * wh.

### `-B, -sw, --single_window` | _`DEFAULT_SINGLE_WINDOW`_
- Use a single window mode for curses display.
- This shows a single large window for a host for detailed monitoring.
- You can rotate between hosts by pressing `<` or `>` in curses display. ( also works in non single window mode )
- You can toggle single window mode in curses display by pressing `|` ( pipe ).

### `-R, -eo, --error_only` | _`DEFAULT_ERROR_ONLY`_
- Print `Success` if all hosts returns zero.
- Only print output for the hosts that returns non-zero.
- Useful in scripting to reduce output.

### `-Q, -no, --no_output, --quiet` | _`DEFAULT_NO_OUTPUT`_
- Do not print any output.
- Note: if using without `--no_watch`, the curses display will still be shown.
- Useful in scripting when failure is expected.
- Note: return code will still be returned correctly unless `-Z, -rz, --return_zero` is specified.

### `-Z, -rz, --return_zero` | _`DEFAULT_RETURN_ZERO`_
- Return 0 even if there are errors.
- Useful in scripting when failure is expected and bash is set to exit when error occurs.

### `-C, --no_env` | _`DEFAULT_NO_ENV`_
- Do not load the command line environment variables for hostname resolution.
- Only use `/etc/hosts` -> env files specified in `--env_files ENV_FILES` -> DNS for hostname resolution.
- Useful when environment variables can interfere with hostname resolution ( for example not reloading environment variables after refreshing them ).

### `-ef, --env_file ENV_FILE` | None
- Replace the env file look up chain with this env_file. ( Still work with `--no_env` )
- Only this file will be used for env file hostname resolution.
- Useful when you want to use a specific env file for hostname resolution.

### `-efs, --env_files ENV_FILES` | _`DEFAULT_ENV_FILES`_
- The files to load the environment variables for hostname resolution.
- Can specify multiple. Load first to last. ( Still work with `--no_env` )
- Useful when you want to add additional env files for hostname resolution.

### `-m, --max_connections MAX_CONNECTIONS` | _`DEFAULT_MAX_CONNECTIONS`_
- The maximum number of concurrent connections to establish.
- Default is 4 * cpu_count connections.
- Useful for limiting the number of simultaneous SSH connections to avoid overwhelming the compute resources / security limits
- Note: mssh will open at least 3 files per connection. By default some linux systems will only set the ulimit -n to 1024 files. This means about 300 connections can be opened simultaneously. You can increase the ulimit -n value to allow more connections if needed.
  - You will observe `Warning: The number of maximum connections {max_connections} is larger than estimated limit {estimated_limit} .....` if the max connections is larger than estimated limit.
  - mssh will also throttle thread generation if the estimated limit is lower than `2 * max_connections` to avoid hitting the file descriptor limit as python will use some file descriptors when setting up threads.

### `-j, --json` | _`DEFAULT_JSON_OUTPUT`_
- Output in json format.
- Will also respect `-R, -eo, --error_only` and `-Q, -no, --quiet, --no_output` options.

### `-w, --success_hosts` | _`DEFAULT_SUCCESS_HOSTS`_
- By default, a summary of failed hosts is printed.
- Use this option to also print the hosts that succeeded in summary as well.
- Useful when you want to do something with the succeeded hosts later.
- Note: you can directly use the failed / succeeded host list string as it should be fully compatible with mssh host input.

### `-P, -g, --greppable, --table` | _`DEFAULT_GREPPABLE_OUTPUT`_
- Output in greppable table.
- Each line contains: Hostname / Resolved Name / Return Code / Output Type/ Output
- Note a host can have multiple lines if the output contains multiple lines.
- Useful in a script if we are piping the output to a log file for later grepping.

### `-x, -su, --skip_unreachable` | _`DEFAULT_SKIP_UNREACHABLE`_
- Skip unreachable hosts.
- Note: Timedout Hosts are considered unreachable.
- By default mssh set this to true to speed up operations on large host lists with some unreachable hosts.
- Unreachable hosts will be tried again when their timeout expires.
- mssh stores the current run unreachable hosts in memory and if `skip_unreachable` is true, it will store them in a temperary file called __{username}_multiSSH3_UNAVAILABLE_HOSTS.csv in the system temp folder.
- To force mssh to not use unreachable hosts from previous runs, you can use `-a, -nsu, --no_skip_unreachable` to set `skip_unreachable` to false.

### `-a, -nsu, --no_skip_unreachable` | not _`DEFAULT_SKIP_UNREACHABLE`_
- Do not skip unreachable hosts.
- This forms an mutually exclusive pair with `-x, -su, --skip_unreachable`.
- This option sets `skip_unreachable` to false.

### `-uhe, --unavailable_host_expiry UNAVAILABLE_HOST_EXPIRY` | _`DEFAULT_UNAVAILABLE_HOST_EXPIRY`_
- The expiry time in seconds for unreachable hosts stored in the temperary unavailable hosts file.
- Default is 600 seconds ( 10 minutes ).
- Note: because mssh stores a hostname: expire_time pair in the unavailable hosts file, opeartor is able to use different expiry time for different runs to control how long unreachable hosts are skipped and they will be expired at the correct time.
- Note: because mssh stores the expire time in monotonic time. In most systems, this means the expiry time will not persist across system reboots. ( and also the fact it is store in the system temp folder ) although the unavailable hosts can accidentally persist across reboots if the system is rebooted often and the `unavailable_host_expiry` is set to a very large value.

### `-X, -sh, --skip_hosts SKIP_HOSTS` | _`DEFAULT_SKIP_HOSTS`_
- A comma separated list of hosts to skip. 
- This field will be expanded in the same way as the host list.
- Useful when you want to skip some hosts temporarily without modifying the host list.

### `--generate_config_file` | False
- Generate a config file with the current command line options.
- Outputs to stdout if `--config_file` is not specified.

### `--config_file [CONFIG_FILE]` | None
- Additional config file path to load options from.
- Will be loaded last thus overwriting other config file values.
- Use without value to use `multiSSH3.config.json` in the current working directory.
- Also used with `--generate_config_file` to specify output path.

### `--store_config_file [STORE_CONFIG_FILE]` | None
- Store the current command line options to a config file.
- Equivalent to `--generate_config_file --config_file [STORE_CONFIG_FILE]`
- Outputs to `multiSSH3.config.json` in the current working directory if no path is specified.

### `--debug` | False
- Enable debug mode.
- Print host specific debug messages to hosts's stderr.

### `-ci, --copy_id` | False
- `copy_id` mode, use `ssh-copy-id` to copy public key to the hosts.
- Will use the identity file if specified in `-k, --key, --identity [KEY]`
- Will respect `-u, --username` and `-p, --password` options for username and password. ( password will need `sshpass` to be installed, or it will prompt for password interactively )

### `-I, -nh, --no_history` | _`DEFAULT_NO_HISTORY`_
- Do not store command history.
- By default, mssh store command history in `HISTORY_FILE`.
- Useful in scripts when you do not want to store command history.

### `-hf, --history_file HISTORY_FILE` | _`DEFAULT_HISTORY_FILE`_
- The file to store command history.
- By default, mssh store command history in `~/.mssh_history`.
- The history file is a TSV ( tab separated values ) file with each line containing: timestamp, mssh_path, options, hosts, commands.

### `--script` | False
- Script mode, syntatic sugar for `-SCRIPT` or `--no_watch --skip_unreachable --no_env --no_history --greppable --error_only`.
- Useful when using mssh in shell scripts.

### `-e, --encoding ENCODING` | _`DEFAULT_ENCODING`_
- The encoding to use for decoding the output from the hosts.
- Default is `utf-8`.

### `-dt, --diff_display_threshold DIFF_DISPLAY_THRESHOLD` | _`DEFAULT_DIFF_DISPLAY_THRESHOLD`_
- The threshold of different lines to total lines ratio to trigger N-body diff display mode.
- When the output difference ratio exceeds this threshold, mssh will display the diff between outputs instead of the full outputs.
- Useful when the outputs are large and mostly similar.
- Set to 1.0 to always use diff display mode.
- Set to 0.0 to never use diff display mode.
- Note: This uses custom N-body diff algorithm. Uses some memory.

### `--force_truecolor` | _`DEFAULT_FORCE_TRUECOLOR`_
- Force enable truecolor support in curses display.
- Useful when your terminal supports truecolor but is not detected correctly.

### `--add_control_master_config` | False
- Add ControlMaster configuration to your `~/.ssh/config` file to enable persistent ssh connections.
- This will help speed up connections to multiple hosts.
- The configuration added is:
```config
Host *
  ControlMaster auto
  ControlPath /run/user/%i/ssh_sockets_%C
  ControlPersist 3600
```

### `-V, --version` | False
- Print the version of multiSSH3 and exit.
- Will also print the found system binary for calling when setting up connections.

## Usage

Use ```mssh --help``` for more info.

Below is a sample help message output from multiSSH3 6.02 @ 2025-11-10

```bash
$ mssh -h
usage: multiSSH3.py [-h] [-u USERNAME] [-p PASSWORD] [-k [IDENTITY_FILE]] [-uk] [-ea EXTRAARGS] [-11] [-f FILE] [-s [FILE_SYNC]] [-W] [-G] [-t TIMEOUT] [-T] [-r REPEAT] [-i INTERVAL] [-M] [-mpre IPMI_INTERFACE_IP_PREFIX] [-pre INTERFACE_IP_PREFIX] [-iu IPMI_USERNAME] [-ip IPMI_PASSWORD] [-S] [-ww WINDOW_WIDTH] [-wh WINDOW_HEIGHT] [-B] [-R] [-Q] [-Z] [-C] [-ef ENV_FILE] [-efs ENV_FILES] [-m MAX_CONNECTIONS] [-j] [-w] [-P] [-x | -a] [-uhe UNAVAILABLE_HOST_EXPIRY] [-X SKIP_HOSTS] [--generate_config_file] [--config_file [CONFIG_FILE]] [--store_config_file [STORE_CONFIG_FILE]] [--debug] [-ci] [-I] [-hf HISTORY_FILE] [--script] [-e ENCODING] [-dt DIFF_DISPLAY_THRESHOLD] [--force_truecolor] [--add_control_master_config] [-V] [hosts] [commands ...]

Run a command on multiple hosts, Use #HOST# or #HOSTNAME# to replace the host name in the command.

positional arguments:
  hosts                 Hosts to run the command on, use "," to seperate hosts. (default: all)
  commands              the command to run on the hosts / the destination of the files #HOST# or #HOSTNAME# will be replaced with the host name.

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        The general username to use to connect to the hosts. Will get overwrote by individual username@host if specified. (default: None)
  -p, --password PASSWORD
                        The password to use to connect to the hosts, (default: )
  -k, --identity_file, --key, --identity [IDENTITY_FILE]
                        The identity file to use to connect to the hosts. Implies --use_key. Specify a folder for program to search for a key. Use option without value to use ~/.ssh/ (default: None)
  -uk, --use_key        Attempt to use public key file to connect to the hosts. (default: False)
  -ea, --extraargs EXTRAARGS
                        Extra arguments to pass to the ssh / rsync / scp command. Put in one string for multiple arguments.Use "=" ! Ex. -ea="--delete" (default: None)
  -11, --oneonone       Run one corresponding command on each host. (default: False)
  -f, --file FILE       The file to be copied to the hosts. Use -f multiple times to copy multiple files
  -s, -fs, --file_sync [FILE_SYNC]
                        Operate in file sync mode, sync path in <COMMANDS> from this machine to <HOSTS>. Treat --file <FILE> and <COMMANDS> both as source and source and destination will be the same in this mode. Infer destination from source path. (default: False)
  -W, --scp             Use scp for copying files instead of rsync. Need to use this on windows. (default: False)
  -G, -gm, --gather_mode
                        Gather files from the hosts instead of sending files to the hosts. Will send remote files specified in <FILE> to local path specified in <COMMANDS> (default: False)
  -t, --timeout TIMEOUT
                        Timeout for each command in seconds. Set default value via DEFAULT_CLI_TIMEOUT in config file. Use 0 for disabling timeout. (default: 0)
  -T, --use_script_timeout
                        Use shortened timeout suitable to use in a script. Set value via DEFAULT_TIMEOUT field in config file. (current: 50)
  -r, --repeat REPEAT   Repeat the command for a number of times (default: 1)
  -i, --interval INTERVAL
                        Interval between repeats in seconds (default: 0)
  -M, --ipmi            Use ipmitool to run the command. (default: False)
  -mpre, --ipmi_interface_ip_prefix IPMI_INTERFACE_IP_PREFIX
                        The prefix of the IPMI interfaces (default: )
  -pre, --interface_ip_prefix INTERFACE_IP_PREFIX
                        The prefix of the for the interfaces (default: None)
  -iu, --ipmi_username IPMI_USERNAME
                        The username to use to connect to the hosts via ipmi. (default: ADMIN)
  -ip, --ipmi_password IPMI_PASSWORD
                        The password to use to connect to the hosts via ipmi. (default: )
  -S, -q, -nw, --no_watch
                        Quiet mode, no curses watch, only print the output. (default: False)
  -ww, --window_width WINDOW_WIDTH
                        The minimum character length of the curses window. (default: 40)
  -wh, --window_height WINDOW_HEIGHT
                        The minimum line height of the curses window. (default: 1)
  -B, -sw, --single_window
                        Use a single window for all hosts. (default: False)
  -R, -eo, --error_only
                        Only print the error output. (default: False)
  -Q, -no, --no_output, --quiet
                        Do not print the output. (default: False)
  -Z, -rz, --return_zero
                        Return 0 even if there are errors. (default: False)
  -C, --no_env          Do not load the command line environment variables. (default: False)
  -ef, --env_file ENV_FILE
                        Replace the env file look up chain with this env_file. ( Still work with --no_env ) (default: None)
  -efs, --env_files ENV_FILES
                        The files to load the mssh file based environment variables from. Can specify multiple. Load first to last. ( Still work with --no_env ) (default: ['/etc/profile.d/hosts.sh', '~/.bashrc', '~/.zshrc', '~/host.env', '~/hosts.env', '.env', 'host.env', 'hosts.env'])
  -m, --max_connections MAX_CONNECTIONS
                        Max number of connections to use (default: 4 * cpu_count)
  -j, --json            Output in json format. (default: False)
  -w, --success_hosts   Output the hosts that succeeded in summary as well. (default: False)
  -P, -g, --greppable, --table
                        Output in greppable table. (default: False)
  -x, -su, --skip_unreachable
                        Skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: True)
  -a, -nsu, --no_skip_unreachable
                        Do not skip unreachable hosts. Note: Timedout Hosts are considered unreachable. Note: multiple command sequence will still auto skip unreachable hosts. (default: False)
  -uhe, --unavailable_host_expiry UNAVAILABLE_HOST_EXPIRY
                        Time in seconds to expire the unavailable hosts (default: 600)
  -X, -sh, --skip_hosts SKIP_HOSTS
                        Skip the hosts in the list. (default: None)
  --generate_config_file
                        Store / generate the default config file from command line argument and current config at --config_file / stdout
  --config_file [CONFIG_FILE]
                        Additional config file to use, will pioritize over config chains. When using with store_config_file, will store the resulting config file at this location. Use without a path will use multiSSH3.config.json
  --store_config_file [STORE_CONFIG_FILE]
                        Store the default config file from command line argument and current config. Same as --store_config_file --config_file=<path>
  --debug               Print debug information
  -ci, --copy_id        Copy the ssh id to the hosts
  -I, -nh, --no_history
                        Do not record the command to history. Default: False
  -hf, --history_file HISTORY_FILE
                        The file to store the history. (default: ~/.mssh_history)
  --script              Run the command in script mode, short for -SCRIPT or --no_watch --skip_unreachable --no_env --no_history --greppable --error_only
  -e, --encoding ENCODING
                        The encoding to use for the output. (default: utf-8)
  -dt, --diff_display_threshold DIFF_DISPLAY_THRESHOLD
                        The threshold of lines to display the diff when files differ. {0-1} Set to 0 to always display the diff. Set to 1 to disable diff. (Only merge same) (default: 0.6)
  --force_truecolor     Force truecolor output even when not in a truecolor terminal. (default: False)
  --add_control_master_config
                        Add ControlMaster configuration to ~/.ssh/config to speed up multiple connections to the same host.
  -V, --version         show program's version number and exit
```
Note: The default values can be modified / updated in the [Config file](#config).

## Importing as a Module

You can also import multiSSH3 as a module in your python scripts.


### Host Object
The `Host` object represents a host and its command execution state. The main execution function `run_command_on_hosts` returns a list of `Host` objects.

```python
class Host:
	def __init__(self, name, command, files = None,ipmi = False,interface_ip_prefix = None,scp=False,extraargs=None,gatherMode=False,identity_file=None,shell=False,i = -1,uuid=uuid.uuid4(),ip = None):
		self.name = name # the name of the host (hostname or IP address)
		self.command = command # the command to run on the host
		self.returncode = None # the return code of the command
		self.output = [] # the output of the command for curses
		self.stdout = [] # the stdout of the command
		self.stderr = [] # the stderr of the command
		self.lineNumToPrintSet = set() # line numbers to reprint
		self.lastUpdateTime = time.monotonic() # the last time the output was updated
		self.lastPrintedUpdateTime = 0 # the last time the output was printed
		self.files = files # the files to be copied to the host
		self.ipmi = ipmi # whether to use ipmi to connect to the host
		self.shell = shell # whether to use shell to run the command
		self.interface_ip_prefix = interface_ip_prefix # the prefix of the ip address of the interface to be used to connect to the host
		self.scp = scp # whether to use scp to copy files to the host
		self.gatherMode = gatherMode # whether the host is in gather mode
		self.extraargs = extraargs # extra arguments to be passed to ssh
		self.resolvedName = None # the resolved IP address of the host
		# also store a globally unique integer i from 0
		self.i = i if i != -1 else _get_i()
		self.uuid = uuid
		self.identity_file = identity_file
		self.ip = ip if ip else getIP(name)
		self.current_color_pair = [-1, -1, 1]
		self.output_buffer = io.BytesIO()
		self.stdout_buffer = io.BytesIO()
		self.stderr_buffer = io.BytesIO()
		self.thread = None
```

### Example:

```python
import multiSSH3
ethReachableHosts = multiSSH3.run_command_on_hosts(nodesToCheck,['echo hi'],returnUnfinished = True) # returnUnfinished will return the host objects immediately without waiting for all hosts to finish.
ipmiReachableHosts = multiSSH3.run_command_on_hosts(nodesToCheck,['power status'], timeout = timeout, ipmi=True, password=password, skipUnreachable=False) # ipmi command
# You can use blocks like the following block to wait on a specific host list to finish ( That does respect timeout even if the host is hanging )
# Following block also implement an exponential backoff.
sleep_interval = 0.0001
while any([host.returncode is None for host in ethReachableHosts]):
  time.sleep(sleep_interval)  # avoid busy-waiting
  if sleep_interval < 0.01:
    sleep_interval *= 1.1
# You can also use join_threads to wait on all running threads ( including timedout hanging threads )
multiSSH3.join_threads()
...
```

### `run_command_on_hosts` Function

The run_command_on_hosts function includes almost all the options available in the CLI. ( some options modify the [global variables](#all-changable-config-options--global-variables-) and can be set before calling the function. )

```python
def run_command_on_hosts(hosts = DEFAULT_HOSTS,commands = None,oneonone = DEFAULT_ONE_ON_ONE, timeout = DEFAULT_TIMEOUT,password = DEFAULT_PASSWORD,no_watch = DEFAULT_NO_WATCH,json = DEFAULT_JSON_MODE,called = _DEFAULT_CALLED,max_connections=DEFAULT_MAX_CONNECTIONS,file = None,ipmi = DEFAULT_IPMI,interface_ip_prefix = DEFAULT_INTERFACE_IP_PREFIX,returnUnfinished = _DEFAULT_RETURN_UNFINISHED,scp=DEFAULT_SCP,gather_mode = False,username=DEFAULT_USERNAME,extraargs=DEFAULT_EXTRA_ARGS,skipUnreachable=DEFAULT_SKIP_UNREACHABLE,no_env=DEFAULT_NO_ENV,greppable=DEFAULT_GREPPABLE_MODE,willUpdateUnreachableHosts=_DEFAULT_UPDATE_UNREACHABLE_HOSTS,no_start=_DEFAULT_NO_START,skip_hosts = DEFAULT_SKIP_HOSTS, window_width = DEFAULT_WINDOW_WIDTH, window_height = DEFAULT_WINDOW_HEIGHT,single_window = DEFAULT_SINGLE_WINDOW,file_sync = False,error_only = DEFAULT_ERROR_ONLY,quiet = False,identity_file = DEFAULT_IDENTITY_FILE,copy_id = False, unavailable_host_expiry = DEFAULT_UNAVAILABLE_HOST_EXPIRY,no_history = True,history_file = DEFAULT_HISTORY_FILE,
):
	"""
	Run commands on multiple hosts via SSH or IPMI.

	Parameters:
		hosts (str or iterable): Hosts to run the command on. Can be a string (comma/space-separated) or iterable. Default: DEFAULT_HOSTS.
		commands (list or None): List of commands to run on the hosts. If files are used, defines the destination. Default: None.
		oneonone (bool): If True, run each command on the corresponding host (1:1 mapping). Default: DEFAULT_ONE_ON_ONE.
		timeout (int): Timeout for each command in seconds. Default: DEFAULT_TIMEOUT.
		password (str): Password for SSH/IPMI authentication. Default: DEFAULT_PASSWORD.
		no_watch (bool): If True, do not use curses TUI; just print output. Default: DEFAULT_NO_WATCH.
		json (bool): If True, output results in JSON format. Default: DEFAULT_JSON_MODE.
		called (bool): If True, function is called programmatically (not CLI). Default: _DEFAULT_CALLED.
		max_connections (int): Maximum concurrent SSH sessions. Default: 4 * os.cpu_count().
		file (list or None): Files to copy to hosts. Default: None.
		ipmi (bool): Use IPMI instead of SSH. Default: DEFAULT_IPMI.
		interface_ip_prefix (str or None): Override IP prefix for host connection. Default: DEFAULT_INTERFACE_IP_PREFIX.
		returnUnfinished (bool): If True, return hosts even if not finished. Default: _DEFAULT_RETURN_UNFINISHED.
		scp (bool): Use scp for file transfer (instead of rsync). Default: DEFAULT_SCP.
		gather_mode (bool): Gather files from hosts (pull mode). Default: False.
		username (str or None): Username for SSH/IPMI. Default: DEFAULT_USERNAME.
		extraargs (str or list or None): Extra args for SSH/SCP/rsync. Default: DEFAULT_EXTRA_ARGS.
		skipUnreachable (bool): Skip hosts marked as unreachable. Default: DEFAULT_SKIP_UNREACHABLE.
		no_env (bool): Do not load environment variables from shell. Default: DEFAULT_NO_ENV.
		greppable (bool): Output in greppable table format. Default: DEFAULT_GREPPABLE_MODE.
		willUpdateUnreachableHosts (bool): Update global unreachable hosts file. Default: _DEFAULT_UPDATE_UNREACHABLE_HOSTS.
		no_start (bool): If True, return Host objects without running commands. Default: _DEFAULT_NO_START.
		skip_hosts (str or None): Hosts to skip. Default: DEFAULT_SKIP_HOSTS.
		window_width (int): Minimum width per curses window. Default: DEFAULT_WINDOW_WIDTH.
		window_height (int): Minimum height per curses window. Default: DEFAULT_WINDOW_HEIGHT.
		single_window (bool): Use a single curses window for all hosts. Default: DEFAULT_SINGLE_WINDOW.
		file_sync (bool): Enable file sync mode (sync directories). Default: DEFAULT_FILE_SYNC.
		error_only (bool): Only print error output. Default: DEFAULT_ERROR_ONLY.
		quiet (bool): Suppress all output (overrides other output options). Default: False.
		identity_file (str or None): SSH identity file. Default: DEFAULT_IDENTITY_FILE.
		copy_id (bool): Use ssh-copy-id to copy public key to hosts. Default: False.
		unavailable_host_expiry (int): Seconds to keep hosts marked as unavailable. Default: DEFAULT_UNAVAILABLE_HOST_EXPIRY.
		no_history (bool): Do not record command history. Default: True.
		history_file (str): File to store command history. Default: DEFAULT_HISTORY_FILE.

	Returns:
		list: List of Host objects representing each host/command run.
	"""
```

## All Changable Config Options ( Global Variables )

Update these values in the config file to change the default behavior of multiSSH3.

> Values with leading `_` will not be included in the config file generated by mssh but are respected when set in the config file.

```python
AUTHOR = 'Yufei Pan'
AUTHOR_EMAIL = 'pan@zopyr.us'
DEFAULT_HOSTS = 'all'
DEFAULT_USERNAME = None
DEFAULT_PASSWORD = ''
DEFAULT_IDENTITY_FILE = None
DEFAULT_SSH_KEY_SEARCH_PATH = '~/.ssh/'
DEFAULT_USE_KEY = False
DEFAULT_EXTRA_ARGS = None
DEFAULT_ONE_ON_ONE = False
DEFAULT_SCP = False
DEFAULT_FILE_SYNC = False
DEFAULT_TIMEOUT = 50
DEFAULT_CLI_TIMEOUT = 0
DEFAULT_UNAVAILABLE_HOST_EXPIRY = 600
DEFAULT_REPEAT = 1
DEFAULT_INTERVAL = 0
DEFAULT_IPMI = False
DEFAULT_IPMI_INTERFACE_IP_PREFIX = ''
DEFAULT_INTERFACE_IP_PREFIX = None
DEFAULT_IPMI_USERNAME = 'ADMIN'
DEFAULT_IPMI_PASSWORD = ''
DEFAULT_NO_WATCH = False
DEFAULT_WINDOW_WIDTH = 40
DEFAULT_WINDOW_HEIGHT = 1
DEFAULT_SINGLE_WINDOW = False
DEFAULT_ERROR_ONLY = False
DEFAULT_NO_OUTPUT = False
DEFAULT_RETURN_ZERO = False
DEFAULT_NO_ENV = False
DEFAULT_ENV_FILE = ''
DEFAULT_ENV_FILES = ['/etc/profile.d/hosts.sh',
					 '~/.bashrc',
					 '~/.zshrc',
					 '~/host.env',
					 '~/hosts.env',
					 '.env',
					 'host.env',
					 'hosts.env',
					 ]
DEFAULT_NO_HISTORY = False
DEFAULT_HISTORY_FILE = '~/.mssh_history'
DEFAULT_MAX_CONNECTIONS = 4 * os.cpu_count()
DEFAULT_JSON_MODE = False
DEFAULT_PRINT_SUCCESS_HOSTS = False
DEFAULT_GREPPABLE_MODE = False
DEFAULT_SKIP_UNREACHABLE = True
DEFAULT_SKIP_HOSTS = ''
DEFAULT_ENCODING = 'utf-8'
DEFAULT_DIFF_DISPLAY_THRESHOLD = 0.6
SSH_STRICT_HOST_KEY_CHECKING = False
FORCE_TRUECOLOR = False
ERROR_MESSAGES_TO_IGNORE = [
	'Pseudo-terminal will not be allocated because stdin is not a terminal',
	'Connection to .* closed',
	'Warning: Permanently added',
	'mux_client_request_session',
	'disabling multiplexing',
	'Killed by signal',
	'Connection reset by peer',
]
__DEFAULT_COLOR_PALETTE = {
	'cyan': (86, 173, 188),
	'green': (114, 180, 43),
	'magenta': (140, 107, 200),
	'red': (196, 38, 94),
	'white': (227, 227, 221),
	'yellow': (179, 180, 43),
	'blue': (106, 126, 200),
	'bright_black': (102, 102, 102),
	'bright_blue': (129, 154, 255),
	'bright_cyan': (102, 217, 239),
	'bright_green': (126, 226, 46),
	'bright_magenta': (174, 129, 255),
	'bright_red': (249, 38, 114),
	'bright_white': (248, 248, 242),
	'bright_yellow': (226, 226, 46),
}
COLOR_PALETTE = __DEFAULT_COLOR_PALETTE.copy()
_DEFAULT_CALLED = True
_DEFAULT_RETURN_UNFINISHED = False
_DEFAULT_UPDATE_UNREACHABLE_HOSTS = True
_DEFAULT_NO_START = False
_etc_hosts = {}
__ERROR_MESSAGES_TO_IGNORE_REGEX =None
__DEBUG_MODE = False
```
> Note: If color palette need to be changed, please change the `COLOR_PALETTE` values instead of the __DEFAULT_COLOR_PALETTE as if values are missing from __DEFAULT_COLOR_PALETTE, mssh may raise errors.

> When imported and calling as a module, `called` will be set to _DEFAULT_CALLED.<br/>
> When True, it sets several flags to make mssh behave better when called as a module.<br/>
> - if skipUnreachable is not set, it will skip unreachable hosts within one command call
> - Will clear global keyboard input cache
> - Will set global quiet mode to True

> `_DEFAULT_UPDATE_UNREACHABLE_HOSTS` is used to control whether to update the unreachable hosts file when mssh detects unreachable hosts.

> `_DEFAULT_NO_START` is somewhat analogous to "demo mode" where mssh will return Host objects without actually allocating and starting the execution threads. Although they still can be started using `start_run_on_hosts()` but you should really be looking for `returnUnfinished` instead for asynchronicity.

> `_etc_hosts` is a custom dict to use instead of reading /etc/hosts file for hostname resolution.

> `__ERROR_MESSAGES_TO_IGNORE_REGEX` is the compiled regex pattern for error messages to ignore. If custom defined, mssh will ignore `ERROR_MESSAGES_TO_IGNORE` and use supplied regex pattern instead.

> `__DEBUG_MODE` is used to control whether to print host thread execution debug information to its stderr.