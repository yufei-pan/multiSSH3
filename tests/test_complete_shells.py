import errno
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import (ENGINE, REPO, WITH_AND_WITHOUT_DEBUG_LOG, aged, bash_locale, bash_session, blesh_session, build_index,
	debug_log_size, fish_complete, fish_session, hold_lock, make_home, require_shell, with_debug_log, without_command, zsh_session)

HISTORY = [
	'1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"',
	'1790000100\t/x/multiSSH3.py\t-su -u=root\tstorage1\t"df -h /data"',
]


@pytest.fixture
def setup(tmp_path):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	return env, home


def glue_file(home, shell, command=ENGINE):
	path = home / ('glue.' + shell)
	path.write_text(mc.render_glue(shell, command))
	return path


@WITH_AND_WITHOUT_DEBUG_LOG
@pytest.mark.parametrize('bash_completion', [True, False])
def test_bash_completes_in_a_real_shell(setup, bash_completion, debug):
	env, home = setup
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion)
	try:
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h "echo #HO') == 'mssh h "echo #HOST'
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
		assert session.line_after('mssh h "date; fakecmd al') == 'mssh h "date; fakecmd alpha" '
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


def test_bash_ignores_the_heal_a_shell_of_6_38_left_in_an_exported_prompt_command(tmp_path):
	# 6.38 put _mssh_complete_heal; in PROMPT_COMMAND, which a tmux pane or a nested bash inherits when it is exported
	env, home = make_home(tmp_path, HISTORY)
	session = bash_session(home, dict(env, PROMPT_COMMAND='_mssh_complete_heal;history -a'), glue_file(home, 'bash'), False)
	try:
		session.send('true\r')
		session.read_until(b'@@READY@@', 5)
		session.send('true\r')
		session.read_until(b'@@READY@@', 5)
	finally:
		session.close()
	assert b'command not found' not in session.output


def test_bash_ignoring_case_completes_in_any_case(tmp_path):
	# completion-ignore-case on: readline takes a candidate whose case differs from the word, and puts in its spelling
	env, home = make_home(tmp_path, HISTORY)
	(home / 'hosts').write_text('10.0.0.1 Storage-East\n')
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'), extra="bind 'set completion-ignore-case on'")
	try:
		assert session.line_after('mssh storage-e') == 'mssh Storage-East '
		assert session.line_after('mssh GP') == 'mssh gpu[01-16] '
		assert session.line_after('mssh -u ROO') == 'mssh -u root '
		assert session.line_after('mssh --NO_WA') == 'mssh --no_watch '
		# -S, -W and -I start option names as typed (used here): none may become -s, -w or -i
		assert session.line_after('mssh -q -S') == 'mssh -q -S'
		assert session.line_after('mssh --scp -W') == 'mssh --scp -W'
		assert session.line_after('mssh -nh -I') == 'mssh -nh -I'
	finally:
		session.close()


def ignoring_case(tmp_path, history, hosts='', on=True, files=(), commands=(), env_lines='', options='', lang=None, ctype=None):
	'''
	A bash with completion-ignore-case on (off with on False), no bash-completion, in a directory holding
	only files (no other file names among the candidates), with commands found first on its PATH, and
	env_lines in ~/hosts.env (aliases), shell options (set -e), and LANG=lang, LC_CTYPE=ctype if given (the
	index is built in the tests' own).
	'''
	env, home = make_home(tmp_path, history)
	(home / 'hosts').write_text(hosts, encoding='utf-8')
	(home / 'hosts.env').write_text(env_lines)
	build_index(env)
	work = tmp_path / 'work'
	work.mkdir()
	for name in files:
		(work / name).write_text('')
	found = tmp_path / 'bin'
	found.mkdir()
	for name in commands:
		(found / name).write_text('#!/bin/sh\n')
		(found / name).chmod(0o755)
	env = dict(env, PATH=str(found) + os.pathsep + env['PATH'])
	if lang is not None:
		env['LANG'] = lang
	if ctype is not None:
		env['LC_CTYPE'] = ctype
	extra = "cd '{}'; {}".format(work, options)
	if on:
		extra = "bind 'set completion-ignore-case on'; " + extra
	return bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=extra)


def set_ignore_case(session, value):
	'''Turn completion-ignore-case on or off in a running bash, as a bind or a re-read ~/.inputrc does.'''
	session.send("bind 'set completion-ignore-case {}'\r".format(value))
	session.read_until(b'@@READY@@')


def test_bash_ignoring_case_offers_one_of_the_words_differing_only_in_case(tmp_path):
	# readline cannot tell storage-east from Storage-East and would stop at their common start
	history = ['1790000000\t/x/multiSSH3.py\t-su\tstorage-east\t"uptime"']
	history += ['179000000{}\t/x/multiSSH3.py\t-su\tlogin1\t"{}"'.format(number + 1, command)
		for number, command in enumerate(('zzsvc status', 'zzsvc start', 'Zzsvc restart'))]
	session = ignoring_case(tmp_path, history, '10.0.0.1 Storage-East\n')
	try:
		assert session.line_after('mssh storage-e') == 'mssh storage-east '
		assert session.line_after('mssh Storage-E') == 'mssh Storage-East '
		assert session.line_after('mssh STORAGE-E') == 'mssh storage-east '
		assert session.line_after('mssh login1 Zz') == 'mssh login1 Zzsvc '
		assert session.line_after('mssh login1 ZZ') == 'mssh login1 zzsvc '
	finally:
		session.close()


def test_bash_ignoring_case_lists_its_words_differing_only_in_case_beside_a_file_name(tmp_path):
	# the engine kept one of storage-file and Storage-file, not knowing the glue would add storage-other
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"nosuchcmd {}"'.format(number, word)
		for number, word in enumerate(('storage-file', 'Storage-file'))]
	session = ignoring_case(tmp_path, history, files=['storage-other'])
	try:
		assert {'storage-file', 'Storage-file', 'storage-other'} <= set(listed_after(session, 'mssh h nosuchcmd storage-'))
		assert session.line_after('mssh h nosuchcmd storage-f') == 'mssh h nosuchcmd storage-file '
		assert session.line_after('mssh h nosuchcmd Storage-f') == 'mssh h nosuchcmd Storage-file '
	finally:
		session.close()


def test_bash_ignoring_case_keeps_a_host_and_an_alias_differing_only_in_case(tmp_path):
	# the host gpus beside the alias GPUs (an env variable): gpus typed in its case is the host, never the alias
	session = ignoring_case(tmp_path, [], '10.0.0.1 gpus\n10.0.0.2 Node01\n10.0.0.3 node02\n', env_lines='GPUs=Node01,node02\n')
	try:
		assert session.line_after('mssh gpus') == 'mssh gpus '
		assert session.line_after('mssh GPU') == 'mssh GPUs '
	finally:
		session.close()


def test_bash_ignoring_case_puts_in_the_more_used_of_two_aliases_differing_only_in_case(tmp_path):
	# gpus was used ten times, GPUS never: neither in the case typed, the engine's first goes in
	history = ['17900000{:02d}\t/x/multiSSH3.py\t-su\tgpus\t"uptime"'.format(number) for number in range(10)]
	session = ignoring_case(tmp_path, history, '10.0.0.1 a1\n10.0.0.2 a2\n10.0.0.3 b1\n', env_lines='gpus=a1,a2\nGPUS=b1,b1\n')
	try:
		assert session.line_after('mssh Gp') == 'mssh gpus '
	finally:
		session.close()


def listed_after(session, typed):
	'''The words readline lists for typed on a second TAB.'''
	start = len(session.output)
	session.send(typed + '\t\t')
	session.wait_idle()
	session.read_until(b'@@never@@', 0.5)
	text = session.output[start:].decode('utf-8', 'replace')
	session.send('\x15')
	session.read_until(b'@@never@@', 0.3)
	return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', ' ', text).split()


def test_bash_ignoring_case_lists_words_differing_only_in_case_beside_others(tmp_path):
	# Admin and admin are two accounts: beside root readline lists all three, and either goes in when typed
	session = ignoring_case(tmp_path, ['179000000{}\t/x/multiSSH3.py\t-su -u={}\th\t"uptime"'.format(number, name)
		for number, name in enumerate(('Admin', 'admin', 'root'))])
	try:
		assert {'Admin', 'admin', 'root'} <= set(listed_after(session, 'mssh -u '))
		assert session.line_after('mssh -u a') == 'mssh -u admin '
		assert session.line_after('mssh -u A') == 'mssh -u Admin '
	finally:
		session.close()


@pytest.mark.parametrize('first', ['on', 'off'])
def test_bash_follows_completion_ignore_case_as_it_changes(tmp_path, first):
	# read once per shell, the setting went stale after a bind: turned off, the engine still offered Node01 and
	# NODE03 for node0, and readline, now minding case, cut the word back to their common start (mssh N);
	# turned on, words in another case stayed out
	session = ignoring_case(tmp_path, HISTORY, '10.0.0.1 Node01\n10.0.0.3 NODE03\n10.0.0.5 Storage-East\n', on=first == 'on')

	def completes(value):
		if value == 'on':
			assert session.line_after('mssh storage-e') == 'mssh Storage-East '
		else:
			assert session.line_after('mssh node0') == 'mssh node0'
			assert session.line_after('mssh storage-e') == 'mssh storage-e'
	try:
		completes(first)
		other = 'off' if first == 'on' else 'on'
		set_ignore_case(session, other)
		completes(other)
		set_ignore_case(session, first)
		completes(first)
	finally:
		session.close()


def test_bash_ignoring_case_keeps_delegated_words_in_another_case(tmp_path):
	# bash's compgen ignores case too: stor gives Storage-File, ZZT gives zztool; dropped, the history's word
	# alone went in
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(number, command)
		for number, command in enumerate(('nosuchcmd storage-x', 'zzthing'))]
	session = ignoring_case(tmp_path, history, files=['Storage-File'], commands=['zztool'])
	try:
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-'
		assert session.line_after('mssh h ZZT') == 'mssh h zzt'
		assert session.line_after('mssh h nosuchcmd Storage-F') == 'mssh h nosuchcmd Storage-File '
	finally:
		session.close()


@pytest.mark.parametrize('spec, completed', [
	# bash prints the quoted arguments of -G, -W, -P, -S, -X and -C before -F: a " -F " inside one names no
	# function (touch ran, making the files zzsvc and zz here)
	('complete -W "start -F touch stop" -F _zzreal zzsvc', 'mssh h zzsvc zzalp'),
	('complete -C "echo -F touch x" -F _zzreal zzsvc', 'mssh h zzsvc zzalp'),
	('complete -X "zzq -F touch x" -F _zzreal zzsvc', 'mssh h zzsvc zzalp'),
	('complete -F _zzreal zzsvc', 'mssh h zzsvc zzalp'),
	# no function: file names. Nor where the quoted argument ends with a -F and a quoted word (bash 5.2
	# quotes a function name so)
	('complete -W "start -F touch x" zzsvc', 'mssh h zzsvc zzfile '),
	('complete -W "start -F \'touch\'" zzsvc', 'mssh h zzsvc zzfile '),
	('complete -X "! -F \'touch\'" zzsvc', 'mssh h zzsvc zzfile '),
	('complete -C "echo -F \'touch\'" zzsvc', 'mssh h zzsvc zzfile '),
	('complete -W "a -F \'touch\'" -F _zzreal zzsvc', 'mssh h zzsvc zzalp'),
])
def test_bash_delegation_runs_the_function_bash_prints_last(tmp_path, spec, completed):
	options = '_zzreal() { COMPREPLY=(zzalpha zzalpine); }; ' + spec
	session = ignoring_case(tmp_path, [], on=False, files=['zzfile'], options=options)
	try:
		assert session.line_after('mssh h zzsvc zz') == completed
		assert sorted(os.listdir(str(tmp_path / 'work'))) == ['zzfile']
	finally:
		session.close()


@pytest.mark.parametrize('name', ['zzplain', 'zz svc', "zz's", 'zz$b', 'zz"q', '/opt/zz bin/zzgit', "'", '\\'])
def test_bash_delegation_reads_the_function_of_a_command_whatever_its_name(tmp_path, name):
	# complete -p prints the name as it is before bash 5.2, single-quoted from 5.2 where it needs it
	script = ('. "$1"; _zzreal() { COMPREPLY=(zzalpha zzalpine); }; complete -F _zzreal -- "$2"; '
		'_mssh_complete_guard _mssh_complete_delegate zz 1 "" "$2" zz; printf "%s\\n" "${_mssh_complete_delegated[@]}"')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash')), name],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode().split() == ['zzalpha', 'zzalpine'], output


# every character bash 5.2 quotes that a function's name can hold (bash 4.2 to 5.3; "[" from 5.0, "=" from 5.3)
@pytest.mark.parametrize('function', ['zz^f', 'zz!f', 'zz*f', 'zz?f', 'zz]f', 'zz{f}', '~zzf', 'zz%f', 'zz@f', '_zzplain'])
def test_bash_delegation_runs_a_completion_function_whatever_its_name(tmp_path, function):
	# from bash 5.2 complete -p single-quotes a function name holding a shell metacharacter (-F 'zz^f')
	script = ('. "$1"; eval "function $2 { COMPREPLY=(zzalpha zzalpine); }"; complete -F "$2" zzsvc; '
		'_mssh_complete_guard _mssh_complete_delegate zz 1 "" zzsvc zz; printf "%s\\n" "${_mssh_complete_delegated[@]}"')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash')), function],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode().split() == ['zzalpha', 'zzalpine'], output


@pytest.mark.parametrize('name', ["zz'f", 'zzrun'])
def test_bash_delegation_runs_no_command_for_a_completion_function(tmp_path, name):
	# bash runs complete -F's word only as a function (function not found, else): the glue ran a command so
	# named in its place, zzrun, and zz'f, which no function's name can be (bash refuses a quote), and which
	# bash 5.2 prints quoted (-F 'zz'\''f')
	ran = tmp_path / 'ran'
	found = tmp_path / 'bin'
	found.mkdir()
	(found / name).write_text('#!/bin/sh\ntouch {}\n'.format(ran))
	(found / name).chmod(0o755)
	script = ('. "$1"; PATH=$2:$PATH; complete -F "$3" zzsvc; '
		'_mssh_complete_guard _mssh_complete_delegate zz 1 "" zzsvc zz; printf "%s\\n" "${_mssh_complete_delegated[@]}"')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash')), str(found), name],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd=str(tmp_path))
	assert not ran.exists(), output
	assert output.returncode == 0, output


@pytest.mark.parametrize('spec', [
	'complete -F _zzreal zzgit',
	# a loader registers the command's last part (bash-completion's do)
	'_completion_loader() { [[ ${1##*/} == zzgit ]] && complete -F _zzreal zzgit; }',
])
def test_bash_delegation_finds_the_completion_of_a_full_path_by_its_last_part(tmp_path, spec):
	# as bash does: the word as typed, then its last part; file names came instead
	options = '_zzreal() { COMPREPLY=(zzalpha zzalpine); }; ' + spec
	session = ignoring_case(tmp_path, [], on=False, files=['zzfile'], options=options)
	try:
		assert session.line_after('mssh h /usr/local/bin/zzgit zz') == 'mssh h /usr/local/bin/zzgit zzalp'
		assert session.line_after('mssh h zzgit zz') == 'mssh h zzgit zzalp'
	finally:
		session.close()


def delegated(tmp_path, setup, words='zzsvc zz', before='', prefix='', word=None, each=None):
	"""What the bash glue's delegate gives for the remote command line `words` after `setup` (a shell's own commands),
	in a directory holding the file zzfile, the directories zzdir and zzdirb, and the command zzaws_completer, which
	prints what it reads of its environment and arguments. The last word is the one completed. With prefix, the text
	in front of the remote words in a quoted command, and word, the word bash replaces (the last by default). With each (a
	printf format), the results come back as one string with each one in that format, not one per line."""
	work = tmp_path / 'work'
	work.mkdir()
	(work / 'zzfile').write_text('')
	(work / 'zzdir').mkdir()
	(work / 'zzdirb').mkdir()
	found = tmp_path / 'bin'
	found.mkdir()
	(found / 'zzaws_completer').write_text('#!/bin/bash\nprintf "%s\\n" "zzline=$COMP_LINE" "zzpoint=$COMP_POINT" '
		'"zzkey=$COMP_KEY.$COMP_TYPE" "zzargs=$1|$2|$3"\n')
	(found / 'zzaws_completer').chmod(0o755)
	script = ('. "$1"; PATH=$2:$PATH; zzword=$4; zzprefix=$5; zzeach=$6; set -- $3; _zzreal() { COMPREPLY=(zzalpha zzalpine zzbeta); }; ' + before + setup +
		'; _mssh_complete_guard _mssh_complete_delegate "${zzword:-${@: -1}}" $(( $# - 1 )) "$zzprefix" "$@"; '
		'(( ${#_mssh_complete_delegated[@]} )) && printf "${zzeach:-%s\\n}" "${_mssh_complete_delegated[@]}"; true')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash')), str(found), words, word or '', prefix, each or ''],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd=str(work))
	assert output.returncode == 0, output
	return output.stdout.decode() if each else output.stdout.decode().splitlines()


@pytest.mark.parametrize('setup, expected', [
	# -C: the command string with the command name, the word and the one before it, the line in the environment
	('complete -C zzaws_completer zzsvc', ['zzline=zzsvc s3 zz', 'zzpoint=11', 'zzkey=9.9', 'zzargs=zzsvc|zz|s3']),
	('complete -C "zzaws_completer --x" zzsvc', ['zzline=zzsvc s3 zz', 'zzpoint=11', 'zzkey=9.9', 'zzargs=--x|zzsvc|zz']),
	('complete -W "zza zzb other" zzsvc', ['zza', 'zzb']),
	('complete -W "\'zz a\' zzc" zzsvc', ['zz a', 'zzc']),
	('complete -d zzsvc', ['zzdir', 'zzdirb']),
	('complete -A directory zzsvc', ['zzdir', 'zzdirb']),
	('zzfn() { :; }; zzfn2() { :; }; complete -A function zzsvc', ['zzfn', 'zzfn2']),
	('complete -G "zzd*" zzsvc', ['zzdir', 'zzdirb']),
	# -X, -P and -S go to compgen with the rest, which applies them to its words, but not to a function's or a command's
	('complete -W "zza.c zzb.h zzc.c" -X "*.c" zzsvc', ['zzb.h']),
	('complete -W "zza.c zzb.h zzc.c" -X "!*.c" zzsvc', ['zza.c', 'zzc.c']),
	# an & stands for the word, \& for the character
	('complete -W "zz zzb zzbb" -X "&b" zzsvc', ['zz', 'zzbb']),
	('complete -W "zz zzb zz& zz&b" -X "&\\&b" zzsvc', ['zz', 'zzb', 'zz&']),
	('complete -W "zza.c zzb.h" -X "*.c" -S ";" zzsvc', ['zzb.h;']),
	('complete -F _zzreal -X "zza*" zzsvc', ['zzalpha', 'zzalpine', 'zzbeta']),
	# a function and a command give their words after the words
	('complete -W "zzw" -F _zzreal -C "echo zzc" zzsvc', ['zzw', 'zzalpha', 'zzalpine', 'zzbeta', 'zzc zzsvc zz s3']),
	# -o: file names when nothing else is left (dirnames: directories, default: files)
	('complete -W "other" -o default zzsvc', ['zzdir', 'zzdirb', 'zzfile']),
	('complete -W "other" -o dirnames zzsvc', ['zzdir', 'zzdirb']),
	('complete -W "other" -o dirnames -o default zzsvc', ['zzdir', 'zzdirb']),
	('complete -W "zza" -o default zzsvc', ['zza']),
	('complete -W "zza" -o plusdirs zzsvc', ['zza', 'zzdir', 'zzdirb']),
	('complete -W "other" zzsvc', []),
	# a command's blank lines are no results (a lone newline is aws_completer's answer for nothing), so the fallbacks run
	('complete -C "printf \'zza\\n\\nzzb\\n\\n\'" zzsvc', ['zza', 'zzb']),
	('complete -C "printf \'\\n\'" zzsvc', []),
	('complete -o default -C "printf \'\\n\'" zzsvc', ['zzdir', 'zzdirb', 'zzfile']),
	('complete -o dirnames -C "printf \'\\n\\n\'" zzsvc', ['zzdir', 'zzdirb']),
	# a quote or a substitution does not join lines
	('complete -C "printf \'zz\\"a\\nzzb\\n\'" zzsvc', ['zz"a', 'zzb']),
	('complete -C "printf \'zz\\$(a\\nzzb)\\n\'" zzsvc', ['zz$(a', 'zzb)']),
	# the last line needs no newline
	('complete -C "printf zza" zzsvc', ['zza']),
	# a function's empty word, the sentinel that git, grub and pcp give for no completions, is an answer as well
	('_zzs() { COMPREPLY=(""); }; complete -F _zzs zzsvc', []),
	('_zzs() { COMPREPLY=(""); }; complete -o default -F _zzs zzsvc', []),
	('_zzs() { COMPREPLY=(""); }; complete -o dirnames -F _zzs zzsvc', []),
	('_zzs() { COMPREPLY=(""); }; complete -W "zza" -o default -F _zzs zzsvc', ['zza']),
])
def test_bash_delegation_completes_as_the_compspec_of_the_command_says(tmp_path, setup, expected):
	assert sorted(delegated(tmp_path, setup, 'zzsvc s3 zz')) == sorted(expected)


@pytest.mark.parametrize('prefix, words, word, setup, expected', [
	# in a quoted command the results continue the remote word, after what the quoted word holds before it
	('zzsvc ', 'zzsvc zz', 'zzsvc zz', 'complete -W "zzalpha zzb" zzsvc', ['zzsvc zzalpha', 'zzsvc zzb']),
	('cd /x && ls ', 'ls zz', 'cd /x && ls zz', 'complete -W "zzalpha zzb" zzsvc ls', ['cd /x && ls zzalpha', 'cd /x && ls zzb']),
	# bash's word stops at ":" (b for a:b): what comes before it is cut from the results
	('', 'zzsvc a:b', 'b', 'complete -W "a:bx a:by" zzsvc', ['bx', 'by']),
	('zzsvc ', 'zzsvc a:b', 'b', 'complete -W "a:bx a:by" zzsvc', ['bx', 'by']),
	('zzsvc ', 'zzsvc a:b', 'zzsvc a:b', 'complete -W "a:bx a:by" zzsvc', ['zzsvc a:bx', 'zzsvc a:by']),
	# a function's words are not held to the word, as bash does not (bash-completion's colon trimming makes bar for a:ba)
	('', 'zzsvc a:ba', 'ba', '_zztrim() { COMPREPLY=(bar); }; complete -F _zztrim zzsvc', ['bar']),
	# an & in the filter stands for the word with its glob characters quoted, as bash has it
	('', 'zzsvc a*', None, 'complete -W "a* a*x a*y" -X "&" zzsvc', ['a*x', 'a*y']),
])
def test_bash_delegation_puts_the_prefix_and_the_filter_where_bash_does(tmp_path, prefix, words, word, setup, expected):
	assert sorted(delegated(tmp_path, setup, words, prefix=prefix, word=word)) == sorted(expected)


@pytest.mark.parametrize('before, key', [('', '9.9'), ('COMP_KEY=63 COMP_TYPE=33; ', '63.33')])
def test_bash_delegation_gives_a_command_the_key_and_type_of_the_completion(tmp_path, before, key):
	# bash sets them for mssh's own completion (ble.sh too), a tab and a plain completion otherwise
	output = delegated(tmp_path, 'complete -C zzaws_completer zzsvc', 'zzsvc s3 zz', before=before)
	assert 'zzkey=' + key in output


def test_bash_delegation_hands_the_options_of_the_compspec_to_compopt(tmp_path):
	# -o fullquote, new in bash 5.3, is given too (a bash that does not know it never prints it: complete -p)
	log = tmp_path / 'compopt.log'
	setup = ('complete() {{ [[ $1 == -p ]] && echo "complete -W \'zza\' -o filenames -o nospace -o noquote -o nosort -o fullquote -o default zzsvc"; }}; '
		'compopt() {{ echo "$*" >> {}; }}').format(log)
	assert delegated(tmp_path, setup, 'zzsvc zz') == ['zza']
	assert sorted(log.read_text().splitlines()) == sorted('-o ' + name for name in ('filenames', 'nospace', 'noquote', 'nosort', 'fullquote'))


@pytest.mark.parametrize('options', ['set -e', 'set -u', 'set -eu', 'shopt -s nocasematch extglob'])
def test_bash_delegation_by_a_compspec_survives_the_shell_options(tmp_path, options):
	# every source at once, with the fallbacks that find nothing (set -e: a failed process substitution)
	setup = 'complete -W "zza zzb" -F _zzreal -C "echo zzc" -X "zzb*" -o nospace -o dirnames -o default zzsvc'
	assert sorted(delegated(tmp_path, setup, 'zzsvc s3 zz', before=options + '; ')) == [
		'zza', 'zzalpha', 'zzalpine', 'zzbeta', 'zzc zzsvc zz s3']


@pytest.mark.parametrize('setup', ['complete -F _zzreal zzsvc', 'complete -F _zzreal -X "!zz*" zzsvc'])
def test_bash_delegation_keeps_a_function_apart_from_the_options_of_the_command(tmp_path, setup):
	assert delegated(tmp_path, setup) == ['zzalpha', 'zzalpine', 'zzbeta']


def test_bash_delegation_without_a_compspec_offers_file_names(tmp_path):
	assert sorted(delegated(tmp_path, ':')) == ['zzdir', 'zzdirb', 'zzfile']


@pytest.mark.parametrize('shell_ifs', ['IFS=:', 'IFS=', 'unset IFS'])
def test_bash_the_glue_puts_the_shells_ifs_back(tmp_path, shell_ifs):
	script = ('. "$1"; _zzreal() { COMPREPLY=(zzalpha); }; complete -F _zzreal zzsvc; ' + shell_ifs + '; '
		'_mssh_complete_guard _mssh_complete_delegate zz 1 "" zzsvc zz; printf "[%s][%s]" "${IFS+set}" "$IFS"')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode() == {'IFS=:': '[set][:]', 'IFS=': '[set][]', 'unset IFS': '[][]'}[shell_ifs], output


@pytest.mark.parametrize('options, completed', [
	('-W "zzone zztwo" -o nospace', 'mssh h zzsvc zzone'),
	('-W "zzone zztwo"', 'mssh h zzsvc zzone '),
	('-W "zzdir zzdir2" -o filenames', 'mssh h zzsvc zzdir'),
	('-d -o filenames', 'mssh h zzsvc zzdir/'),
])
def test_bash_delegation_gives_the_options_of_the_compspec_to_readline(tmp_path, options, completed):
	session = ignoring_case(tmp_path, [], on=False, options='complete {} zzsvc'.format(options))
	try:
		(tmp_path / 'work' / 'zzdir').mkdir()
		assert session.line_after('mssh h zzsvc zzo' if 'zzone' in options else 'mssh h zzsvc zzd') == completed
	finally:
		session.close()


def completed_and_listed(session, typed, quoted=False):
	"""What a TAB at the end of typed makes of the line, and the words a second TAB lists, sorted: every one that is
	listed, the typed word and a candidate named like the command included, and a word listed twice twice. In a
	quoted command (quoted) the words come with the command in front (zzsvc zza), which is taken off."""
	line = session.line_after(typed)
	# what the line print binding ends with (its newline) is not the list
	session.wait_idle()
	session.read_until(b'@@never@@', 0.3)
	start = len(session.output)
	session.send(typed + '\t\t')
	session.wait_idle()
	session.read_until(b'@@never@@', 0.5)
	text = session.output[start:].decode('utf-8', 'replace')
	session.send('\x15')
	session.read_until(b'@@never@@', 0.3)
	# readline lists on the lines below the one it redraws (with backspaces and a bell where it redraws), and
	# redraws the prompt and the line after the list
	rows = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', ' ', text).split('\r\n')[1:-1]
	listed = ' '.join(rows).split()
	if quoted:
		listed = listed[1::2] if listed[0::2] == ['zzsvc'] * len(listed[0::2]) else listed
		line = line and line.replace('"', '')
	return line.rstrip() if line else line, sorted(listed)


# (the arguments of complete, the word, the shell's setting before it): what bash gives the command itself is what mssh
# gives for it on a remote host, line and list alike, for what compgen takes (a function's words are not filtered or
# wrapped, as bash would). An -o default is there where a filter may leave nothing on some bash (4.2 takes !( for a
# negation of what follows): mssh, registered with it, then offers file names, as bash does for the command
SAME_AS_BASH = [
	(['-W', 'zzalpha zzb', '-S', ']'], 'zz', ''),
	(['-W', 'a* a*x a*y', '-X', '&'], 'a*', ''),
	(['-W', 'a* a*x a*y', '-X', '!&*'], 'a*', ''),
	(['-W', 'a? a?x ab', '-X', '!&*'], 'a?', ''),
	(['-W', 'Zza zzb'], 'zz', 'bind "set completion-ignore-case on"'),
	(['-W', 'zza zzb', '-o', 'plusdirs'], 'ZZ', 'bind "set completion-ignore-case on"'),
	(['-W', 'zza', '-o', 'nospace'], 'zz', ''),
	(['-F', '_zzf'], 'zz', '_zzf() { COMPREPLY=(Zzalpha zzbeta); }; bind "set completion-ignore-case on"'),
]


# with file names as words, in a quoted command the words are not file names (zzsvc zzdir: readline adds no / to a
# directory), and mixed with others they have no start in common: readline cuts the line back to the command prefix
# where bash itself leaves the word
SAME_AS_BASH_UNQUOTED = [
	# not compared with bash: the local file names of the file actions, -G and a command with no compspec, which the
	# glue leaves unquoted and unmarked (no / for a directory) where bash quotes and marks them (6.39: the glue does it
	# itself)
	(['-W', 'zza zzb zzc', '-X', '!(zza)', '-o', 'default'], 'zz', 'shopt -s extglob'),
	(['-W', 'zza zzb zzc', '-X', '!(zza|zzb)', '-o', 'default'], 'zz', 'shopt -s extglob'),
	(['-W', 'zza zzb', '-o', 'dirnames', '-o', 'default'], 'zzd', ''),
]

# and where a filter leaving nothing makes bash offer nothing at all (the unquoted one is above, with -o default)
SAME_AS_BASH_QUOTED = [
	(['-W', 'zza zzb zzc', '-X', '!(zza)'], 'zz', 'shopt -s extglob'),
	(['-W', 'zza zzb zzc', '-X', '!(zza|zzb)'], 'zz', 'shopt -s extglob'),
]


@pytest.mark.parametrize('quoted, spec, word, before', [(False,) + case for case in SAME_AS_BASH + SAME_AS_BASH_UNQUOTED] +
	[(True,) + case for case in SAME_AS_BASH + SAME_AS_BASH_QUOTED])
def test_bash_delegation_gives_what_bash_gives_the_command_itself(tmp_path, spec, word, before, quoted):
	import shlex
	options = '{}; _zzreal() {{ COMPREPLY=(zzalpha zzalpine zzbeta); }}; {}'.format(before or ':',
		'complete {} zzsvc'.format(' '.join(map(shlex.quote, spec))) if spec else ':')
	session = ignoring_case(tmp_path, [], on=False, files=['zzfile', 'a*x', 'ab'], options=options)
	try:
		for name in ('zzdir', 'zzdirb'):
			(tmp_path / 'work' / name).mkdir()
		native = completed_and_listed(session, 'zzsvc ' + word)
		remote = completed_and_listed(session, 'mssh h ' + ('"zzsvc ' if quoted else 'zzsvc ') + word, quoted)
		assert remote == ('mssh h ' + native[0], native[1])
	finally:
		session.close()


def require_bash_printing(option):
	"""Skip unless this bash prints `complete -o option` back, which the glue reads a compspec by: bash 4.2 refuses noquote, 4.3
	and 4.4 take it and never print it (nor 4.4 nosort), and fullquote is new in bash 5.3."""
	output = subprocess.run([require_shell('bash'), '-c', 'complete -o {} -W x zzq && complete -p zzq'.format(option)],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
	if option.encode() not in output:
		pytest.skip('this bash does not print complete -o {}'.format(option))


ENGINES_GLOB = ['1790000000\t/x/multiSSH3.py\t-su\th\t"zzsvc zz*x"']


@pytest.mark.parametrize('options, completed', [
	# readline quotes what the compspec's -o filenames makes it quote, and mssh's own words are handed over unescaped to it
	('-W other -o filenames', 'mssh h zzsvc zz\\*x '),
	# not with -o noquote: readline quotes nothing then, and mssh's words go in as the engine escaped them
	('-W other -o filenames -o noquote', 'mssh h zzsvc zz\\*x '),
	# and the space nospace takes off is put on them, as on the spec's own words
	('-W other -o filenames -o noquote -o nospace', 'mssh h zzsvc zz\\*x '),
	# from bash 5.3, -o fullquote quotes all matches
	('-W other -o fullquote', 'mssh h zzsvc zz\\*x '),
	('-W other -o fullquote -o noquote', 'mssh h zzsvc zz\\*x '),
	('-W other -o fullquote -o filenames', 'mssh h zzsvc zz\\*x '),
])
def test_bash_delegation_hands_the_engines_words_to_readline_as_it_quotes(tmp_path, options, completed):
	for option in ('noquote', 'fullquote'):
		if option in options:
			require_bash_printing(option)
	session = ignoring_case(tmp_path, ENGINES_GLOB, on=False, options='complete {} zzsvc'.format(options))
	try:
		assert session.line_after('mssh h zzsvc zz') == completed
	finally:
		session.close()


def test_bash_a_nospace_spec_lists_mssh_s_own_words_as_they_are(tmp_path):
	history = history_of('zzgit checkout zzbranch', 'zzgit checkout zzbrook')
	session = ignoring_case(tmp_path, history, on=False, options='_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit')
	try:
		assert completed_and_listed(session, 'mssh h zzgit checkout zzbr') == ('mssh h zzgit checkout zzbr', ['zzbranch', 'zzbrook'])
	finally:
		session.close()


@pytest.mark.parametrize('spec, completed', [
	# the engine's word is like the spec's: a space where the spec asks for none
	('-o nospace -W zzx', 'mssh h zzgit zzopt= '),
	('-W zzx', 'mssh h zzgit zzopt= '),
])
def test_bash_a_nospace_spec_gives_an_option_word_of_the_engine_its_space(tmp_path, spec, completed):
	# (the engine never asks for nospace itself: a path or an --opt= word it gives is spaced like any other)
	env, home = make_home(tmp_path, [])
	engine = home / 'engine'
	engine.write_text("#!/bin/sh\nprintf 'MSSHC1\\nC zzopt=\\t\\tx\\nX 1\\t\\tzzgit\\tzzopt\\nE\\n\\0'\n")
	engine.chmod(0o755)
	session = bash_session(home, env, glue_file(home, 'bash', [str(engine)]), bash_completion=False, extra='complete {} zzgit'.format(spec))
	try:
		assert session.line_after('mssh h zzgit zzopt') == completed
	finally:
		session.close()


def test_bash_a_command_giving_a_blank_line_for_nothing_inserts_no_space(tmp_path):
	# aws v1's aws_completer prints a newline when it has nothing: bash reads no result there
	session = ignoring_case(tmp_path, [], on=False, options="complete -C \"printf '\\\\n'\" zzsvc")
	try:
		assert session.line_after('mssh h zzsvc ') == 'mssh h zzsvc '
	finally:
		session.close()


SHELLS = ['readline', 'ble']
BASH_COMPLETION = '/usr/share/bash-completion/bash_completion'
needs_bash_completion = pytest.mark.skipif(not os.path.exists(BASH_COMPLETION), reason='bash-completion is not installed')


def shell_session(tmp_path, shell, history=(), options='', files=()):
	"""A bash with readline ('readline') or with ble.sh ('ble'), the glue loaded, in a directory holding files (and no
	other); options run after the glue loads."""
	if shell == 'readline':
		return ignoring_case(tmp_path, history, on=False, files=files, options=options)
	import test_complete_blesh as ble
	env, home = make_home(tmp_path, history)
	build_index(env)
	work = tmp_path / 'work'
	work.mkdir()
	for name in files:
		(work / name).write_text('')
	return blesh_session(home, env, ble.glue_file(home), extra="cd '{}'; {}".format(work, options))


def fresh_line(tmp_path, name, shell, typed, keys='\t', **kwargs):
	"""The line after typed and keys in a new session of shell_session (kwargs: history, options, files). ble.sh does
	not complete the same word the same way twice in a session: after one that inserted something, the next inserts
	nothing, and the one after the first candidate."""
	(tmp_path / name).mkdir()
	session = shell_session(tmp_path / name, shell, **kwargs)
	try:
		return session.line_after(typed, keys=keys)
	finally:
		session.close()


@needs_bash_completion
@pytest.mark.skipif(not os.path.exists('/usr/share/bash-completion/completions/scp'), reason='no scp completion')
@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('files, typed, completed', [
	# bash-completion's scp gives file names with their spaces escaped, and ends them with the space they want
	(['solo one.txt'], 'so', 'solo\\ one.txt '),
	(['my file.txt', 'my notes.txt'], 'my', 'my\\ '),
])
def test_bash_a_delegated_file_name_with_a_space_reaches_the_line_as_it_does_natively(tmp_path, shell, files, typed, completed):
	# under ble.sh the glue used to strip the space, and ble.sh quoted the escaped name again ('solo\ one.txt'), or, for
	# several, inserted nothing
	given = dict(options='. ' + BASH_COMPLETION, files=files)
	assert fresh_line(tmp_path, 'native', shell, 'scp ' + typed, **given) == 'scp ' + completed
	assert fresh_line(tmp_path, 'mssh', shell, 'mssh h scp ' + typed, **given) == 'mssh h scp ' + completed


@needs_bash_completion
@pytest.mark.skipif(not os.path.exists('/usr/share/bash-completion/completions/git') or not shutil.which('git'), reason='no git completion')
def test_bash_delegation_of_real_completions_gives_what_bash_gives_the_command_itself(tmp_path):
	# bash-completion's own specs, as a remote command meets them: functions with nospace and filenames (git, rsync, cd,
	# scp), -F alone (systemctl, ls)
	options = 'git init -q . && git checkout -q -b main && git -c user.email=a@b -c user.name=a commit -q --allow-empty -m x; . ' + BASH_COMPLETION
	session = ignoring_case(tmp_path, [], on=False, files=['solo one.txt'], options=options)
	try:
		(tmp_path / 'work' / 'zzdir').mkdir()
		for line in ('git checko', 'git checkout ma', 'git log --form', 'git commit --am', 'systemctl rest', 'ls --alm', 'cd zzd',
				'scp so', 'rsync --delete-af'):
			assert session.line_after('mssh h ' + line) == 'mssh h ' + session.line_after(line), line
	finally:
		session.close()


SENTINEL = '_zzs() { COMPREPLY=(""); }; '
# the empty word, as git sparse-checkout, grub and pcp give it for no completions
EMPTY_SPECS = [
	SENTINEL + 'complete -o nospace -F _zzs zzgit',
	SENTINEL + 'complete -F _zzs zzgit',
	SENTINEL + 'complete -o default -F _zzs zzgit',
	SENTINEL + 'complete -o nospace -o default -o bashdefault -F _zzs zzgit',
]


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('options', EMPTY_SPECS)
def test_bash_an_empty_result_is_no_candidate_and_no_unique_match(tmp_path, shell, options):
	# the empty word is not a match readline could add a space to (git sparse-checkout add qq), and not one that lets
	# the file names of -o default in (bash finds an answer there). ble.sh adds file names of its own, to the command
	# itself as to mssh's line
	given = dict(options=options, files=['zzfile'])
	line = fresh_line(tmp_path, 'mssh', shell, 'mssh h zzgit zzf', **given)
	if shell == 'ble':
		assert line == 'mssh h ' + fresh_line(tmp_path, 'native', shell, 'zzgit zzf', **given)
	else:
		# (bash adds a space after the empty word of a function that has no nospace, which mssh does not do)
		if 'nospace' in options:
			assert fresh_line(tmp_path, 'native', shell, 'zzgit zzf', **given) == 'zzgit zzf'
		assert line == 'mssh h zzgit zzf'
	assert fresh_line(tmp_path, 'sparse', shell, 'mssh h zzgit sparse-checkout add qq', **given) == 'mssh h zzgit sparse-checkout add qq'


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('options', EMPTY_SPECS)
def test_bash_an_empty_result_leaves_mssh_s_own_words_to_complete(tmp_path, shell, options):
	# the sentinel kept mssh's own candidates (the history's) from completing
	line = fresh_line(tmp_path, 'mssh', shell, 'mssh h zzgit sparse-checkout add zzp', options=options,
		history=history_of('zzgit sparse-checkout add zzproj/src'))
	assert line == 'mssh h zzgit sparse-checkout add zzproj/src '


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('options, typed, completed', [
	# beside spaced words (or none) the empty word makes the reply neither uniform nor mixed
	(SENTINEL.replace('("")', '("" "zzfeature ")') + 'complete -o nospace -F _zzs zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
	(SENTINEL.replace('("")', '("" "zzopt=")') + 'complete -o nospace -F _zzs zzgit', 'mssh h zzgit checkout zzo', 'mssh h zzgit checkout zzopt='),
	(SENTINEL + 'complete -F _zzs zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
])
def test_bash_an_empty_result_beside_other_words_changes_nothing(tmp_path, shell, options, typed, completed):
	assert fresh_line(tmp_path, 'mssh', shell, typed, options=options, history=history_of('zzgit checkout zzfeature')) == completed


@needs_bash_completion
@pytest.mark.skipif(not os.path.exists('/usr/share/bash-completion/completions/git') or not shutil.which('git'), reason='no git completion')
@pytest.mark.parametrize('shell', SHELLS)
def test_bash_git_sparse_checkout_with_nothing_to_complete_leaves_the_line_as_it_does_natively(tmp_path, shell):
	# git's completion gives COMPREPLY=("") for no completions, under -o nospace
	given = dict(history=history_of('git sparse-checkout add zzproj/src'), options='git init -q . ; . ' + BASH_COMPLETION)
	assert fresh_line(tmp_path, 'native', shell, 'git sparse-checkout add qq', **given) == 'git sparse-checkout add qq'
	assert fresh_line(tmp_path, 'mssh', shell, 'mssh h git sparse-checkout add qq', **given) == 'mssh h git sparse-checkout add qq'
	assert fresh_line(tmp_path, 'history', shell, 'mssh h git sparse-checkout add zzp', **given) == 'mssh h git sparse-checkout add zzproj/src '


def test_blesh_a_nospace_spec_leaves_the_engine_s_words_as_they_are(tmp_path):
	# ble.sh inserts a nospace candidate that ends in a space as it is, and quotes the engine's words (sent unescaped)
	# itself: a space appended to one would go in unquoted (zz*x and the glob it is)
	options = "_zzs() { COMPREPLY=('zzopt=' 'zzfeature '); }; complete -o nospace -F _zzs zzgit"
	# the pick of the engine's word, the first candidate, from the menu
	line = fresh_line(tmp_path, 'mssh', 'ble', 'mssh h zzgit checkout zz', keys='\t\t', options=options, history=history_of('zzgit checkout zz*x'))
	assert line == 'mssh h zzgit checkout zz\\*x'


def history_of(*commands):
	return ['{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(1790000000 + number, command) for number, command in enumerate(commands)]


@pytest.mark.parametrize('options, typed, completed', [
	# a nospace spec: mssh's own words get the space the spec's own words bring themselves (__gitcomp appends it)
	('_zzn() { COMPREPLY=(); }; complete -o bashdefault -o default -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
	('_zzn() { COMPREPLY=(); }; complete -o nospace -W "zzfeature" zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature'),
	# in a quoted command readline closes the quote, nospace or not (4.2 to 5.3), and the space is the operator's: the
	# glue puts none in front of the quote, where it would be part of the word
	('_zzn() { COMPREPLY=(); }; complete -o nospace -W zzfeature zzgit', 'mssh h "zzgit checkout zzf', 'mssh h "zzgit checkout zzfeature"'),
	('_zzn() { COMPREPLY=(); }; complete -o nospace -W zzfeature zzgit', "mssh h 'zzgit checkout zzf", "mssh h 'zzgit checkout zzfeature'"),
	# without nospace it is as before
	('_zzn() { COMPREPLY=(); }; complete -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
	# the spec's words end with a space: both are one word, with the one space
	('_zzn() { COMPREPLY=("zzfeature "); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
	# several: the common start, no space
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzb', 'mssh h zzgit checkout zzbr'),
	# readline quotes the words under filenames: a space would be quoted as well, and there is none
	('_zzn() { COMPREPLY=(); }; complete -o nospace -o filenames -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature'),
])
def test_bash_a_nospace_spec_gives_mssh_s_own_words_their_space(tmp_path, options, typed, completed):
	history = history_of('zzgit checkout zzfeature', 'zzgit checkout zzbranch', 'zzgit checkout zzbrook')
	session = ignoring_case(tmp_path, history, on=False, options=options)
	try:
		assert session.line_after(typed) == completed
	finally:
		session.close()


GIT_STYLE = "_zzs() { COMPREPLY=('zzfeature '); }; complete -o nospace -F _zzs zzgit"
BACK = '\x02' * 5


@pytest.mark.parametrize('options, typed, keys, completed, native', [
	# git style: the spec's words end with the space they want, and nospace takes readline's own off. The glue
	# strips it and turns nospace off, and readline adds the space as bash does for the command itself (the one
	# space, not two)
	(GIT_STYLE, 'mssh h zzgit checkout zzf', '\t', 'mssh h zzgit checkout zzfeature ', 'zzgit checkout zzf'),
	# in the middle of a line readline skips its space over the one there
	(GIT_STYLE, 'mssh h zzgit checkout zzf -- x', BACK + '\t', 'mssh h zzgit checkout zzfeature -- x', None),
	# and a quoted remote command is closed before it
	(GIT_STYLE, 'mssh h "zzgit checkout zzf', '\t', 'mssh h "zzgit checkout zzfeature" ', None),
	(GIT_STYLE, "mssh h 'zzgit checkout zzf", '\t', "mssh h 'zzgit checkout zzfeature' ", None),
	# the engine alone, under a spec that gives nothing: the same
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzf -- x', BACK + '\t', 'mssh h zzgit checkout zzfeature -- x', None),
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h "zzgit checkout zzf', '\t', 'mssh h "zzgit checkout zzfeature" ', None),
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', "mssh h 'zzgit checkout zzf", '\t', "mssh h 'zzgit checkout zzfeature' ", None),
	# the same words without nospace, for comparison
	('_zzn() { COMPREPLY=(); }; complete -F _zzn zzgit', 'mssh h "zzgit checkout zzf', '\t', 'mssh h "zzgit checkout zzfeature" ', None),
	# a remote path keeps its space as in 6.37 and as the engine gives it elsewhere (it asks for no nospace)
	('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit /srv/d', '\t', 'mssh h zzgit /srv/data/ ', None),
	('_zzn() { COMPREPLY=(); }; complete -F _zzn zzgit', 'mssh h zzgit /srv/d', '\t', 'mssh h zzgit /srv/data/ ', None),
])
def test_bash_a_nospace_spec_leaves_the_space_to_readline_where_all_its_words_end_in_one(tmp_path, options, typed, keys, completed, native):
	history = history_of('zzgit checkout zzfeature', 'zzgit /srv/data/')
	session = ignoring_case(tmp_path, history, on=False, options=options)
	try:
		assert session.line_after(typed, keys=keys) == completed
		if native:
			# bash itself, for the same spec
			assert session.line_after(native, keys=keys) == completed[len('mssh h '):]
	finally:
		session.close()


def test_bash_a_nospace_spec_with_words_ending_in_a_space_gives_no_second_space_under_ble(tmp_path):
	# ble.sh inserts a nospace candidate that ends in a space as it is, and drops the space of one identical to a
	# word without it; with the space stripped and nospace off, it adds the one as it does for any spec
	import test_complete_blesh as ble
	for index, (options, typed, completed) in enumerate([
		(GIT_STYLE, 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
		('_zzn() { COMPREPLY=(); }; complete -o nospace -F _zzn zzgit', 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature '),
		("_zzs() { COMPREPLY=('zzfeature' 'zzfeature '); }; complete -o nospace -F _zzs zzgit", 'mssh h zzgit checkout zzf', 'mssh h zzgit checkout zzfeature'),
	]):
		(tmp_path / str(index)).mkdir()
		env, home = make_home(tmp_path / str(index), history_of('zzgit checkout zzfeature'))
		build_index(env)
		session = blesh_session(home, env, ble.glue_file(home), extra=options)
		try:
			assert session.line_after(typed) == completed
		finally:
			session.close()


def unspaced(tmp_path, reply, given, icase=0, ble=0):
	"""What _mssh_complete_unspace makes of the engine's words (reply) beside the delegate's (given): the engine's
	words and the delegate's, each in brackets."""
	import shlex
	script = ('. "$1"; _mssh_complete_reply=({}); _mssh_complete_delegated=({}); _mssh_complete_icase={}; _mssh_complete_ble={}; '
		'_mssh_complete_unspace; printf "[%s]" "${{_mssh_complete_reply[@]}}"; echo; printf "[%s]" "${{_mssh_complete_delegated[@]}}"; echo'
		).format(' '.join(map(shlex.quote, reply)), ' '.join(map(shlex.quote, given)), icase, ble)
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.returncode == 0, output
	lines = output.stdout.decode().splitlines()
	return lines[0], lines[1]


@pytest.mark.parametrize('reply, given, kwargs, engine, delegate', [
	# all spaced, or none: the space comes off the delegate's words (readline adds it)
	(['zzb'], ['zza ', 'zzc '], {}, '[zzb]', '[zza][zzc]'),
	(['zzb'], [], {}, '[zzb]', '[]'),
	# mixed: the words stay as they are
	(['zzb', 'zzd/'], ['zza ', 'zzopt='], {}, '[zzb][zzd/]', '[zza ][zzopt=]'),
	# under ble.sh: the delegate's words as given, the engine's with no space, and the engine's word the delegate gave
	# with one left out (ble.sh would meet both); no delegated word: nothing to keep
	(['zzb', 'zzd/'], ['zza ', 'zzopt='], {'ble': 1}, '[zzb][zzd/]', '[zza ][zzopt=]'),
	(['zzb', 'zzd/'], ['zza ', 'zzc '], {'ble': 1}, '[zzb][zzd/]', '[zza ][zzc ]'),
	(['zzb'], [], {'ble': 1}, '[zzb]', '[]'),
	(['zza', 'zzb'], ['zza ', 'zzopt='], {'ble': 1}, '[zzb]', '[zza ][zzopt=]'),
	(['zza', 'zzb'], ['zza', 'zzopt='], {'ble': 1}, '[zza][zzb]', '[zza][zzopt=]'),
	(['ZZA', 'zzb'], ['zza ', 'zzopt='], {'ble': 1, 'icase': 1}, '[zzb]', '[zza ][zzopt=]'),
	(['ZZA', 'zzb'], ['zza ', 'zzopt='], {'ble': 1}, '[ZZA][zzb]', '[zza ][zzopt=]'),
])
def test_bash_a_nospace_spec_loses_its_space_to_readline_where_all_its_words_end_in_one(tmp_path, reply, given, kwargs, engine, delegate):
	assert unspaced(tmp_path, reply, given, **kwargs) == (engine, delegate)


def test_bash_a_nospace_spec_lists_a_word_of_the_engine_and_the_spec_once(tmp_path):
	# beside a word without a space (--format=) the spec's words keep theirs: the engine's zzfeature is the same word
	history = history_of('zzgit checkout zzfeature')
	options = "_zzs() { COMPREPLY=('zzfeature ' 'zzopt='); }; complete -o nospace -F _zzs zzgit"
	session = ignoring_case(tmp_path, history, on=False, options=options)
	try:
		assert completed_and_listed(session, 'mssh h zzgit checkout zz') == ('mssh h zzgit checkout zz', ['zzfeature', 'zzopt='])
	finally:
		session.close()


@pytest.mark.parametrize('typed', ['mssh -f zznotes', 'mssh h zzcmd zznotes'])
def test_bash_a_file_name_ending_in_a_space_is_listed_beside_the_name_without_it(tmp_path, typed):
	session = ignoring_case(tmp_path, [], on=False, files=['zznotes', 'zznotes '])
	try:
		assert completed_and_listed(session, typed) == (typed, ['zznotes', 'zznotes'])
	finally:
		session.close()


@pytest.mark.parametrize('options, typed', [
	('', 'mssh h othercmd '),
	('complete -f zzsvc', 'mssh h zzsvc '),
	('complete -A file zzsvc', 'mssh h zzsvc '),
	('complete -d zzsvc', 'mssh h zzsvc '),
	('complete -A directory zzsvc', 'mssh h zzsvc '),
	("complete -G '*' zzsvc", 'mssh h zzsvc '),
])
def test_bash_a_remote_home_path_from_history_is_not_left_for_the_local_shell_to_expand(tmp_path, options, typed):
	# readline never quotes a leading ~: the glue keeps the engine's \~ and does not turn readline's file name mode on
	history = history_of('othercmd ~/notes', 'zzsvc ~/notes')
	session = ignoring_case(tmp_path, history, on=False, options=options)
	try:
		assert session.line_after(typed) == typed + '\\~/notes '
	finally:
		session.close()


def test_bash_a_remote_word_matching_a_local_directory_keeps_its_space(tmp_path):
	session = ignoring_case(tmp_path, history_of('othercmd srcx'), on=False)
	try:
		(tmp_path / 'work' / 'srcx').mkdir()
		assert session.line_after('mssh h othercmd sr') == 'mssh h othercmd srcx '
	finally:
		session.close()


def test_bash_a_remote_command_name_matching_a_local_directory_keeps_its_space(tmp_path):
	session = ignoring_case(tmp_path, history_of('zqbuild'), on=False)
	try:
		(tmp_path / 'work' / 'zqbuild').mkdir()
		assert session.line_after('mssh h zqbu') == 'mssh h zqbuild '
	finally:
		session.close()


# names the bash glue's TAB path used unprefixed while the shell's code ran: a command's completion function
# sees and sets the variables of the functions that call it (dynamic scoping). The static test below holds
# every glue function to the prefix
BASH_GLUE_NAMES = ('cur resp line item one flags ble files ended delegate reply raws delegate_fields seen icase '
	'word cword prefix cmd spec func lead words found kept typed keymap previous shown expand')


@pytest.mark.parametrize('on', [True, False])
def test_bash_a_completion_function_setting_names_of_its_own_leaves_the_glue_alone(tmp_path, on):
	# a completion written without local (for word in "${COMP_WORDS[@]}") set the glue's word, and nothing
	# was offered; files='a b' made the glue's (( files || dirs )) a syntax error
	options = '_zzclob() {{ {}; COMPREPLY=(alpha alpine); }}; complete -F _zzclob zzclob'.format(
		' '.join("{}='a b'".format(name) for name in BASH_GLUE_NAMES.split()))
	session = ignoring_case(tmp_path, [], on=on, options=options)
	try:
		# what the shell printed for the TAB alone (CentOS 7's bash warns of a missing locale at its start)
		start = len(session.output)
		assert session.line_after('mssh h zzclob al') == 'mssh h zzclob alp'
		assert b'syntax error' not in session.output[start:] and b'bash: ' not in session.output[start:]
	finally:
		session.close()


@pytest.mark.parametrize('options', ['', 'set -e', 'set -u'])
def test_bash_ignoring_case_puts_in_one_of_its_own_and_delegated_words_differing_only_in_case(tmp_path, options):
	# the history's storage-file and the file Storage-File, both offered, kept readline from completing
	session = ignoring_case(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd storage-file"'], files=['Storage-File'], options=options)
	try:
		assert session.line_after('mssh h nosuchcmd storage-f') == 'mssh h nosuchcmd storage-file '
		assert session.line_after('mssh h nosuchcmd Storage-F') == 'mssh h nosuchcmd Storage-File '
		assert session.line_after('mssh h nosuchcmd STORAGE-F') == 'mssh h nosuchcmd storage-file '
		assert b'unbound variable' not in session.output
	finally:
		session.close()


def nocasematch(session):
	'''Whether the running bash has nocasematch on: 'on' or 'off' (None if it does not say).'''
	start = len(session.output)
	# a space first: bash 4 can drop the first key after a Ctrl-C cut a binding short
	session.send(' shopt -q nocasematch && echo "@@NOCASE""=on@@" || echo "@@NOCASE""=off@@"\r')
	deadline = time.monotonic() + 10
	while time.monotonic() < deadline:
		found = re.search(rb'@@NOCASE=(on|off)@@', session.output[start:])
		if found:
			return found.group(1).decode()
		session.read_until(b'@@NOCASE=', 0.1)
	return None


def test_bash_glue_gives_the_shell_back_its_nocasematch(tmp_path):
	# the glue turns nocasematch off for its own tests, and puts back what the shell had
	history = ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd storage-x"']
	session = ignoring_case(tmp_path, history, files=['Storage-File'])
	try:
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-'
		assert nocasematch(session) == 'off'
		set_ignore_case(session, 'off')
		session.send('shopt -s nocasematch\r')
		session.read_until(b'@@READY@@')
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-x '
		assert nocasematch(session) == 'on'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_directories_of_a_path_as_typed(tmp_path):
	# as readline's own file name completion does: /Zzdata/pro became /zzdata/project/b.txt
	session = ignoring_case(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su -f=/zzdata/project/b.txt\th\t"/zzsrv/Out"'])
	try:
		assert session.line_after('mssh -f /Zzdata/pro') == 'mssh -f /Zzdata/pro'
		assert session.line_after('mssh -f /zzdata/PRO') == 'mssh -f /zzdata/project/b.txt '
		assert session.line_after('mssh -f /x h /ZZSRV/o') == 'mssh -f /x h /ZZSRV/o'
		assert session.line_after('mssh -f /x h /zzsrv/o') == 'mssh -f /x h /zzsrv/Out '
	finally:
		session.close()


def test_bash_ignoring_case_lowers_letters_as_its_locale_does(tmp_path):
	# in the C locale readline lowers ASCII letters only: \u0130stanbul is no word for i there, and offered
	# beside Ix1 it kept readline from completing
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n', lang='C')
	try:
		assert session.line_after('mssh i') == 'mssh Ix1 '
	finally:
		session.close()


def taken_by_bash(lang, ctype=None):
	'''(utf8, turkic): how bash here takes LANG=lang (and LC_CTYPE=ctype), as its glue measures it.'''
	env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': lang}
	if ctype is not None:
		env['LC_CTYPE'] = ctype
	return bash_locale(env)


@pytest.mark.parametrize('lang', ['xx_YY.UTF-8', 'tr_XX.UTF-8'])
def test_bash_ignoring_case_in_a_locale_this_system_lacks_runs_as_in_c(tmp_path, lang):
	# bash runs in C in a locale the system has not, whatever its name says: \u0130stanbul is no word for i
	if taken_by_bash(lang)[0]:
		pytest.skip('this C library takes any locale name')
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n', lang=lang)
	try:
		assert session.line_after('mssh i') == 'mssh Ix1 '
	finally:
		session.close()


@pytest.mark.parametrize('lang, typed, line', [
	('tr_TR.UTF-8', 'mssh i', 'mssh \u0130stanbul '), ('tr_TR.UTF-8', 'mssh I', 'mssh Ix1 '),
	('tr_TR.ISO-8859-9', 'mssh i', 'mssh ix2 '), ('tr_TR.ISO-8859-9', 'mssh I', 'mssh Ix1 '),
	# glibc's alias of tr_TR.ISO-8859-9
	('turkish', 'mssh i', 'mssh ix2 ')])
def test_bash_ignoring_case_in_a_turkish_locale(tmp_path, lang, typed, line):
	# in UTF-8 readline lowers I to the dotless i and the I with a dot to i; in ISO-8859-9 I and i match only
	# themselves (it lowers I to a dotless i that is no ASCII letter, and the I with a dot reaches it as two bytes)
	utf8, turkic = taken_by_bash(lang)
	if not turkic or utf8 != ('UTF-8' in lang):
		pytest.skip('bash here lowers I to i in {} (not there, or musl)'.format(lang))
	hosts = '10.0.0.1 \u0130stanbul\n10.0.0.2 Ix1\n' + ('10.0.0.3 ix2\n' if 'UTF-8' not in lang else '')
	session = ignoring_case(tmp_path, [], hosts, lang=lang)
	try:
		assert session.line_after(typed) == line
	finally:
		session.close()


@pytest.mark.parametrize('lang', ['zh_CN.GB18030', 'ko_KR.EUC-KR'])
def test_bash_ignoring_case_in_a_two_byte_locale_that_is_not_utf8(tmp_path, lang):
	# a two-byte UTF-8 character is one there too: these were taken for UTF-8 (\u00c9clair offered for the
	# bytes of \u00e9 typed, which the locale reads as another character)
	env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': lang}
	if bash_locale(env, multibyte=True) != (False, False, True):
		pytest.skip('no {} locale here'.format(lang))
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u00c9clair\n10.0.0.2 Ix1\n', lang=lang)
	try:
		assert session.line_after('mssh \u00e9') == 'mssh \u00e9'
		assert session.line_after('mssh i') == 'mssh Ix1 '
	finally:
		session.close()


def test_bash_ignoring_case_in_the_locale_bash_takes_from_lang_over_a_bad_lc_ctype(tmp_path):
	# macOS's ssh sends LC_CTYPE=UTF-8, no locale on Linux: bash keeps LANG's, a UTF-8 one, and so does TAB
	if taken_by_bash('C.UTF-8', 'UTF-8') != (True, False):
		pytest.skip('no C.UTF-8 here, or UTF-8 is a locale')
	session = ignoring_case(tmp_path, [], '10.0.0.1 \u00c9clair\n', lang='C.UTF-8', ctype='UTF-8')
	try:
		assert session.line_after('mssh \u00e9') == 'mssh \u00c9clair '
	finally:
		session.close()


def utf8_locale():
	'''A UTF-8 locale bash takes here (C.UTF-8, en_US.UTF-8), None where there is none.'''
	return next((name for name in ('C.UTF-8', 'en_US.UTF-8') if taken_by_bash(name) == (True, False)), None)


def glue_request_flags(tmp_path, shell, env, setting=''):
	'''The flags of a request zsh's or fish's glue prints for the engine in env, setting run in the shell first.'''
	glue = glue_file(tmp_path, shell)
	if shell == 'zsh':
		argv = [require_shell('zsh'), '-f', '-c', setting + '\nsource "$1"; _mssh_complete_request x=1 "mssh " ""', 'probe', str(glue)]
	else:
		argv = [require_shell('fish'), '--no-config', '-c', setting + '\nsource {}; __mssh_complete_request x=1 "mssh " "" ""'.format(mc._fish_quote(str(glue)))]
	output = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	# (zsh's status is fc's, which has no history to give outside an interactive shell)
	assert output.stderr == b'', output
	return mc.parse_request(output.stdout).flags


@pytest.mark.parametrize('lang', ['UTF-8', 'C', 'POSIX', 'tr_TR.UTF-8', 'tr_TR.ISO-8859-9'])
@pytest.mark.parametrize('shell', ['zsh', 'fish'])
def test_zsh_and_fish_requests_say_the_locale_the_shell_runs_in(tmp_path, shell, lang):
	# zsh's glue measures it as bash's does (utf8, turkic); fish's names the variables fish exports, as fish
	# reads text as UTF-8 in C too, which says nothing of the terminal. The engine takes either as bash here
	# takes the locale, whatever its own variables say (they were all it had)
	if lang == 'UTF-8':
		lang = utf8_locale()
		if lang is None:
			pytest.skip('no UTF-8 locale here')
	taken = taken_by_bash(lang)
	if lang.startswith('tr_') and not taken[1]:
		pytest.skip('no {} locale here'.format(lang))
	if lang in ('C', 'POSIX'):
		assert taken == (False, False)
	env, _ = make_home(tmp_path)
	flags = glue_request_flags(tmp_path, shell, dict(env, LANG=lang))
	assert flags['x'] == '1' and flags['term'] == env['TERM']
	if shell == 'zsh':
		assert (flags['utf8'], flags['turkic']) == tuple('1' if value else '0' for value in taken)
	else:
		assert (flags['lc_all'], flags['lc_ctype'], flags['lang']) == ('', '', lang)
	assert mc._measured_utf8(mc.Request(shell, 'mssh ', flags=flags)) is taken[0]


@pytest.mark.parametrize('shell, exported, setting, utf8', [
	# zsh follows an LC_ALL or LC_CTYPE set in the shell and not exported, which the engine never sees
	('zsh', 'UTF-8', 'LC_ALL=C', False),
	('zsh', 'C', 'LC_CTYPE={utf8}', True),
	# fish follows only the variables it exports
	('fish', 'UTF-8', 'set -g LC_ALL C', True),
	('fish', 'UTF-8', 'set -gx LC_ALL C', False),
	('fish', 'C', 'set -gx LC_CTYPE {utf8}', True)])
def test_zsh_and_fish_requests_say_the_locale_the_shell_set_itself(tmp_path, shell, exported, setting, utf8):
	locale = utf8_locale()
	if locale is None:
		pytest.skip('no UTF-8 locale here')
	env, _ = make_home(tmp_path)
	env['LANG'] = locale if exported == 'UTF-8' else exported
	setting = setting.format(utf8=locale)
	assert mc._measured_utf8(mc.Request(shell, 'mssh ', flags=glue_request_flags(tmp_path, shell, env, setting))) is utf8
	if shell == 'fish':
		# fish itself reads text so, once kept from taking a UTF-8 locale for a single-byte one
		script = "set -g fish_allow_singlebyte_locale 1\n" + setting + "\nstring length -- (printf '\\xc3\\xa9')"
		output = subprocess.run([require_shell('fish'), '--no-config', '-c', script], env=env, stdout=subprocess.PIPE, timeout=30)
		assert output.stdout.decode().strip() == ('1' if utf8 else '2')


def test_bash_ignoring_case_keeps_the_directories_of_a_command_word_as_typed(tmp_path):
	# as readline's own file name completion does: /zzsrv/data/o became /zzsrv/Data/out
	history = ['179000000{}\t/x/multiSSH3.py\t-su\th\t"{}"'.format(number, command)
		for number, command in enumerate(('nosuchcmd /zzsrv/Data/out', '/Zzopt/Tool/run.sh'))]
	session = ignoring_case(tmp_path, history)
	try:
		assert session.line_after('mssh h nosuchcmd /zzsrv/data/o') == 'mssh h nosuchcmd /zzsrv/data/o'
		assert session.line_after('mssh h nosuchcmd /zzsrv/Data/O') == 'mssh h nosuchcmd /zzsrv/Data/out '
		assert session.line_after('mssh h "nosuchcmd /zzsrv/data/o') == 'mssh h "nosuchcmd /zzsrv/data/o'
		assert session.line_after('mssh h /zzopt/tool/r') == 'mssh h /zzopt/tool/r'
		assert session.line_after('mssh h /Zzopt/Tool/R') == 'mssh h /Zzopt/Tool/run.sh '
	finally:
		session.close()


@pytest.mark.parametrize('icase', ['on', 'off'])
# registered with the shell's setting off: no nocasematch anywhere, nothing for the test to find
@pytest.mark.parametrize('arrives, setting', [('registered', 'on'), ('loaded', 'on'), ('loaded', 'off')])
def test_bash_tab_runs_no_command_complete_f_names_and_gives_file_names(tmp_path, arrives, setting, icase):
	# with nocasematch on, the glue read "complete -f zzrun" as "complete -F zzrun" and ran zzrun, the remote
	# command, here as its completion function: with the shell's setting on (registered), and with the
	# completion file a loader sources at the first TAB turning it on (loaded: bash-completion's loaders run
	# the shell's code, which ran in the glue's setting). Every test of the glue's own compares exactly, and
	# the shell keeps its setting
	history = ['1790000000\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"']
	if arrives == 'registered':
		options = 'complete -f zzrun'
	else:
		completion = tmp_path / 'zzrun.bash'
		completion.write_text('shopt -s nocasematch\ncomplete -f zzrun\n')
		options = "_completion_loader() {{ [[ $1 == zzrun ]] && . '{}'; }}".format(completion)
	options += '; shopt -{} nocasematch'.format('s' if setting == 'on' else 'u')
	session = ignoring_case(tmp_path, history, on=icase == 'on', commands=['zzrun'], options=options)
	ran = tmp_path / 'zzrun-ran'
	try:
		(tmp_path / 'bin' / 'zzrun').write_text('#!/bin/sh\necho "$@" > {}\n'.format(ran))
		assert session.line_after('mssh h zzrun ab') == 'mssh h zzrun ab'
		assert not ran.exists(), ran.read_text()
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert nocasematch(session) == setting
	finally:
		session.close()


@pytest.mark.parametrize('icase', ['on', 'off'])
def test_bash_a_completion_turning_nocasematch_on_leaves_the_shell_as_it_was(tmp_path, icase):
	# a command's completion function that turns nocasematch on and leaves it so: the glue, which runs it,
	# gives the shell back the setting it had before
	options = '_leaky() { shopt -s nocasematch; COMPREPLY=(storage-y); }; complete -F _leaky leaky'
	session = ignoring_case(tmp_path, [], on=icase == 'on', options=options)
	try:
		assert session.line_after('mssh h leaky stor') == 'mssh h leaky storage-y '
		assert nocasematch(session) == 'off'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_text_before_its_word_as_typed(tmp_path):
	# bash's word stops at ":": the delegated host:file continues HOST:fi only if HOST: is as typed, else
	# file went in after the HOST: typed, a name no file has
	session = ignoring_case(tmp_path, [], files=['host:file', 'Fi:fa.txt'])
	try:
		assert session.line_after('mssh h nosuchcmd HOST:fi') == 'mssh h nosuchcmd HOST:fi'
		assert session.line_after('mssh h nosuchcmd host:FI') == 'mssh h nosuchcmd host:file '
		# nor does a word whose text before bash's word differs from it only in case: it came twice
		# (fi:Fi:fa.txt), and readline's own file names put it twice too
		assert session.line_after('mssh h nosuchcmd fi:f') == 'mssh h nosuchcmd fi:f'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_text_before_its_word_as_typed_for_the_engine_s_words_too(tmp_path):
	# the engine's own candidates (history) as the delegated ones above: bash replaces its word alone, and
	# the text before it as typed stayed with the candidate's rest, naming nothing (HOST:file, fi:fa.txt,
	# /data/A:bc, cc=gcc)
	history = ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd host:file"', '1790000001\t/x/multiSSH3.py\t-su\th\t"cat Fi:fa.txt"',
		'1790000002\t/x/multiSSH3.py\t-su -f=/data/a:bc\th\t"uptime"', '1790000003\t/x/multiSSH3.py\t-su\th\t"make CC=gcc"']
	session = ignoring_case(tmp_path, history)
	try:
		assert session.line_after('mssh h nosuchcmd HOST:fi') == 'mssh h nosuchcmd HOST:fi'
		assert session.line_after('mssh h cat fi:f') == 'mssh h cat fi:f'
		assert session.line_after('mssh -f /data/A:b') == 'mssh -f /data/A:b'
		assert session.line_after('mssh h make cc=Gc') == 'mssh h make cc=Gc'
		# bash's word itself in any case
		assert session.line_after('mssh h nosuchcmd host:FI') == 'mssh h nosuchcmd host:file '
		assert session.line_after('mssh h make CC=GC') == 'mssh h make CC=gcc '
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_hosts_before_the_last_one_of_x_as_typed(tmp_path):
	# -X's history was matched whole in any case: web1,webx became WEB1,webX, root@webz ROOT@webz
	history = ['179000000{}\t/x/multiSSH3.py\t-su -X={}\tweb[1-3]\t"uptime"'.format(number, value)
		for number, value in enumerate(('WEB1,webX', 'ROOT@webz'))]
	session = ignoring_case(tmp_path, history)
	try:
		assert session.line_after('mssh web[1-3] -X web1,webx') == 'mssh web[1-3] -X web1,webx'
		assert session.line_after('mssh web[1-3] -X root@webz') == 'mssh web[1-3] -X root@webz'
		assert session.line_after('mssh web[1-3] -X WEB1,webx') == 'mssh web[1-3] -X WEB1,webX '
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_hosts_before_the_last_one_as_typed_whatever_separates_them(tmp_path):
	# mssh splits hosts on "/", ";", "|", "&" and whitespace too: web1/webx became WEB1/webX
	history = ['179000000{}\t/x/multiSSH3.py\t-su -X={}\tweb[1-3]\t"uptime"'.format(number, value)
		for number, value in enumerate(("WEB1/webX", "'WEB1 webY'", "'WEB1\u00a0webZ'"))]
	session = ignoring_case(tmp_path, history)
	try:
		assert session.line_after('mssh web[1-3] -X web1/webx') == 'mssh web[1-3] -X web1/webx'
		assert session.line_after('mssh web[1-3] -X "web1 weby') == 'mssh web[1-3] -X "web1 weby'
		# any whitespace str.split() splits on, a no-break space too
		assert session.line_after('mssh web[1-3] -X "web1\u00a0webz') == 'mssh web[1-3] -X "web1\u00a0webz'
		assert session.line_after('mssh web[1-3] -X WEB1/webx') == 'mssh web[1-3] -X WEB1/webX '
	finally:
		session.close()


def test_bash_minding_case_keeps_delegated_words_in_their_case_whatever_nocasematch_says(tmp_path):
	# with completion-ignore-case off and the shell's nocasematch on, a command's completion offering Storage-x
	# for stor must not reach readline, which, minding case, would cut the word back to their common start
	options = 'shopt -s nocasematch; _fakeci() { COMPREPLY=(Storage-x storage-y); }; complete -F _fakeci fakeci'
	session = ignoring_case(tmp_path, [], on=False, options=options)
	try:
		assert session.line_after('mssh h fakeci stor') == 'mssh h fakeci storage-y '
		assert nocasematch(session) == 'on'
	finally:
		session.close()


def test_bash_ignoring_case_keeps_the_command_words_typed_before(tmp_path):
	# a quoted command is completed whole: its words typed before the current one stay as typed there too
	session = ignoring_case(tmp_path, ['179000000{}\t/x/multiSSH3.py\t-su\tlogin1\t"{}"'.format(number, command)
		for number, command in enumerate(('zzctl status nginx', 'zzctl STATUS Nginx', 'Zzctl Status sshd'))])
	try:
		assert session.line_after('mssh login1 "zzctl STATUS n') == 'mssh login1 "zzctl STATUS Nginx" '
		assert session.line_after('mssh login1 zzctl STATUS n') == 'mssh login1 zzctl STATUS Nginx '
		assert session.line_after('mssh login1 "ZZCTL STATUS n') == 'mssh login1 "ZZCTL STATUS n'
	finally:
		session.close()


def comments_in_substitutions(script):
	"""
	The line numbers of the comments inside a command or process substitution of a bash script: every $( <(
	and >( followed until it closes, wherever it opens. Quotes, ${...} and $(( )) are no comment and hide
	none; a comment outside is skipped whole (its quotes are none). A case pattern's ) inside a substitution
	would end it early: the glue has none there.
	"""
	found = []
	# [kind, in a substitution, parentheses open]: code (the script, or a substitution's), dq, sq, ansi, brace, arith
	stack = [['code', False, 0]]
	index, line = 0, 1
	while index < len(script):
		char = script[index]
		top = stack[-1]
		if char == '\n':
			line += 1
		if top[0] in ('sq', 'ansi'):
			if top[0] == 'ansi' and char == '\\':
				line += script[index + 1:index + 2] == '\n'
				index += 2
				continue
			if char == "'":
				stack.pop()
			index += 1
			continue
		if char == '\\':
			line += script[index + 1:index + 2] == '\n'
			index += 2
			continue
		if script.startswith('$((', index):
			stack.append(['arith', False, 0])
			index += 3
			continue
		if script.startswith('$(', index) or (top[0] == 'code' and script.startswith(('<(', '>('), index)):
			stack.append(['code', True, 0])
			index += 2
			continue
		if script.startswith('${', index):
			stack.append(['brace', False, 0])
			index += 2
			continue
		if top[0] == 'arith':
			if char == '(':
				top[2] += 1
			elif char == ')' and top[2]:
				top[2] -= 1
			elif char == ')':
				stack.pop()
				index += 1
			index += 1
			continue
		if char == '"':
			if top[0] == 'dq':
				stack.pop()
			else:
				stack.append(['dq', False, 0])
		elif top[0] == 'dq':
			pass
		elif top[0] == 'brace' and char == '}':
			stack.pop()
		elif script.startswith("$'", index):
			stack.append(['ansi', False, 0])
			index += 1
		elif char == "'":
			stack.append(['sq', False, 0])
		elif top[0] == 'code' and char == '#' and (index == 0 or script[index - 1] in ' \t\n;&|(<>'):
			if any(frame[1] for frame in stack):
				found.append(line)
			while index + 1 < len(script) and script[index + 1] != '\n':
				index += 1
		elif top[0] == 'code' and char == '(':
			top[2] += 1
		elif top[0] == 'code' and char == ')':
			if top[2]:
				top[2] -= 1
			elif top[1]:
				stack.pop()
		index += 1
	return found


def test_bash_glue_has_no_comment_inside_a_command_or_process_substitution():
	# bash 4.2 reads a quote or a parenthesis in a comment inside <( ) or $( ) as code: a comment saying
	# "readline's" there broke every TAB ("bad substitution: no closing `)'"), which bash 5 never shows
	assert comments_in_substitutions(mc.render_glue('bash', ENGINE)) == []
	# the scanner finds them wherever the substitution opens, and nothing else
	assert comments_in_substitutions("x=$(\n\t# readline's\n\ty)\n") == [2]
	assert comments_in_substitutions("done < <(if (( files )); then\n\t# readline's\n\tcompgen -f; fi 2>/dev/null || :)\n") == [2]
	assert comments_in_substitutions('a "$(b\n# c\nd)"\n') == [2]
	assert comments_in_substitutions("# readline's (\nx=${#y} z=$(( 10#1 + (2) )) w=$(echo '#(' \"#\" $'\\'#') v=$(a)#b\n") == []
	assert comments_in_substitutions("f() {\n\t# it's ( not inside\n\tx=$(a; b)\n}\n# (\ny=<(c\n# in\n)\n") == [7]


# the variables a glue function may declare unprefixed: names a callee's convention needs
GLUE_LOCAL_EXCEPTIONS = {
	# bash's completion interface, handed to a command's completion function; a locale for one function
	# (its whole point); ble.sh's conventions: its functions return in ret, layer:{selection}/update
	# reads sel and gflags
	'bash': {'COMP_WORDS', 'COMP_CWORD', 'COMP_LINE', 'COMP_POINT', 'COMPREPLY', 'LC_ALL', 'IFS', 'ret', 'sel', 'gflags'},
	# what zsh's pattern matching sets, kept from the shell's own
	'zsh': {'MATCH', 'MBEGIN', 'MEND', 'match', 'mbegin', 'mend'},
}


def glue_locals(text, shell):
	'''(line number, function, name) of every variable a function of a glue declares local.'''
	import shlex
	found = []
	function = None
	for number, line in enumerate(text.splitlines(), 1):
		head = re.match(r'\s*(?:function\s+(\S+)\s*\{|([\w/:.-]+)\s*\(\)\s*\{)', line)
		if head:
			function = head.group(1) or head.group(2)
		if line.lstrip().startswith('#'):
			continue
		declared = re.match(r'\s*(?:\(\(.*\)\)\s*&&\s*)?(local|typeset|declare|integer|float)\s(.*)', line)
		if not declared:
			continue
		try:
			words = shlex.split(declared.group(2))
		except ValueError:
			# a line continued on the next (declare -F a b \)
			words = declared.group(2).split()
		flags = ''.join(word.lstrip('-+') for word in words if word[:1] in '-+')
		# globals; bash's declare -F and -f look functions up
		if 'g' in flags or (shell == 'bash' and set(flags) & set('Ffp')):
			continue
		for word in words:
			name = re.match(r'([A-Za-z_]\w*)(?:=|\[|$)', word)
			if name:
				found.append((number, function, name.group(1)))
	return found


@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_every_variable_a_glue_function_declares_is_prefixed(shell):
	# the shell's code runs inside the glue's functions (completion functions, the bindings taken over,
	# a DEBUG trap under set -T), and bash and zsh scope dynamically: it sees and sets their variables
	# the glue as the shell reads it: render_glue wraps zsh's in an eval string
	text = mc._GLUES[shell].replace('@ENGINE@', 'engine').replace('@START@', "''")
	declared = glue_locals(text, shell)
	assert len(declared) > 50
	assert [(number, function, name) for number, function, name in declared
		if not name.startswith('_mssh_complete_') and name not in GLUE_LOCAL_EXCEPTIONS[shell]] == []
	# the parser finds names wherever a declaration holds them, and skips globals and function lookups
	assert [name for _, _, name in glue_locals("f() {\n\tlocal a b=1 -i c\n\t(( x )) && local LC_ALL=C\n\tlocal -a d=(\"$@\") e=() f\n}", shell)] == [
		'a', 'b', 'c', 'LC_ALL', 'd', 'e', 'f']
	assert glue_locals("f() {\n\ttypeset -g x=1\n\t# local y\n}", shell) == []


def test_bash_tab_inside_an_ansi_c_quote_keeps_the_command(tmp_path):
	# in $'...' a backslash starts an escape: zzfmt "%s\n" x must not be offered there as it is
	# (zzfmt: a name no local command starts with, as the first word is also completed as a command)
	env, home = make_home(tmp_path, ['1790000000\t/x/multiSSH3.py\t-su\tnode1\t\'zzfmt "%s\\n" x\'', '1790000100\t/x/multiSSH3.py\t-su\tnode1\t"zzfmt ok"'])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after("mssh node1 'zzf") == "mssh node1 'zzfmt "
		assert session.line_after("mssh node1 $'zzf") == "mssh node1 $'zzfmt ok' "
	finally:
		session.close()


def test_bash_cursor_in_the_middle_of_a_line_with_multibyte_text(setup):
	# bash 4.2 counts COMP_POINT in bytes: the glue must cut the line in bytes there
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		left = '\x1b[D' * len(' "nvidia-smi"')
		assert session.line_after('mssh -ea=é gp "nvidia-smi"', keys=left + '\t') == 'mssh -ea=é gpu[01-16] "nvidia-smi"'
	finally:
		session.close()


def test_bash_falls_back_to_file_names_when_the_engine_is_slow(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	(home / 'zzfile_unique').write_text('')
	session = bash_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'bash', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		assert time.monotonic() - started < 3
	finally:
		session.close()


@WITH_AND_WITHOUT_DEBUG_LOG
def test_zsh_completes_in_a_real_shell(setup, debug):
	env, home = setup
	env = with_debug_log(env, debug)
	logged = debug_log_size(env)
	session = zsh_session(home, env, glue_file(home, 'zsh'))
	try:
		assert session.line_after('mssh gp') == 'mssh gpu\\[01-16\\] '
		assert session.line_after('mssh gpu[01-16] "nvid') == 'mssh gpu[01-16] "nvidia-smi" '
		assert session.line_after('mssh -u r') == 'mssh -u root '
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
		assert session.line_after('mssh h fakecmd al') == 'mssh h fakecmd alpha '
	finally:
		session.close()
	if debug == '0':
		assert debug_log_size(env) == logged


@pytest.mark.parametrize('engine', ['sleep 5', 'exit 1', r"printf 'MSSHC9\nE\n\0'"], ids=['slow', 'failing', 'other-protocol'])
def test_zsh_falls_back_to_file_names_without_an_answer(setup, engine):
	# no answer: what zsh offers for a command it has no completion for (file names), as bash does
	env, home = setup
	stand_in = home / 'engine'
	stand_in.write_text('#!/bin/sh\n{}\n'.format(engine))
	stand_in.chmod(0o755)
	(home / 'zzfile_unique').write_text('')
	session = zsh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'zsh', [str(stand_in)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		assert time.monotonic() - started < 3
		assert b'_mssh:' not in session.output
	finally:
		session.close()


@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_file_names_when_mssh_has_nothing_to_offer(setup, shell):
	# an answer with nothing in it: bash's -o default offers file names, and zsh does the same,
	# except for a password (nodefault)
	env, home = setup
	(home / 'zzfile_unique').write_text('')
	start = bash_session if shell == 'bash' else zsh_session
	session = start(home, env, glue_file(home, shell))
	try:
		# hosts, then a remote command, that nothing matches
		assert session.line_after('mssh zzf') == 'mssh zzfile_unique '
		assert session.line_after('mssh h zzf') == 'mssh h zzfile_unique '
		# a remote command's own completion that offers nothing
		assert session.line_after('mssh h fakecmd zz') == 'mssh h fakecmd zzfile_unique '
		assert session.line_after('mssh -p zz') == 'mssh -p zz'
		assert session.line_after('mssh h --password=zz') == 'mssh h --password=zz'
	finally:
		session.close()


@pytest.mark.parametrize('ifs', ["$'\\n'", ':'])
@pytest.mark.parametrize('shell', ['bash', 'zsh'])
def test_completion_reads_the_engine_s_answer_whatever_ifs_the_shell_has(setup, shell, ifs):
	# the directives were split with the shell's IFS: with IFS=$'\n' "D files nodefault" was one word, and
	# none of them counted (file names for a password, none for -f)
	env, home = setup
	(home / 'zzfile_unique').write_text('')
	start = bash_session if shell == 'bash' else zsh_session
	session = start(home, env, glue_file(home, shell), extra='IFS=' + ifs)
	try:
		assert session.line_after('mssh gp') == ('mssh gpu[01-16] ' if shell == 'bash' else 'mssh gpu\\[01-16\\] ')
		assert session.line_after('mssh -p zz') == 'mssh -p zz'
		assert session.line_after('mssh -f zzf') == 'mssh -f zzfile_unique '
	finally:
		session.close()


@pytest.mark.parametrize('ifs', ["$'\\n'", ':'])
def test_bash_ignoring_case_reads_the_engine_s_answer_whatever_ifs_the_shell_has(tmp_path, ifs):
	# the icase directive: delegated words in another case are kept (Storage-File for stor)
	history = ['1790000000\t/x/multiSSH3.py\t-su\th\t"nosuchcmd storage-x"']
	session = ignoring_case(tmp_path, history, files=['Storage-File'], options='IFS=' + ifs)
	try:
		assert session.line_after('mssh h nosuchcmd stor') == 'mssh h nosuchcmd storage-'
	finally:
		session.close()


def test_bash_glue_splitter_takes_an_empty_separator_for_a_tab(tmp_path):
	# ${2-...} kept an empty separator, which every remainder holds: the loop never ended
	script = '. "$1"; _mssh_complete_split $\'a b\\tc\' ""; printf "%s|" "${_mssh_complete_fields[@]}"'
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
	assert output.stdout.decode() == 'a b|c|', output


@pytest.mark.parametrize('ifs', ["$'\\n'", ':', "''"])
def test_bash_glue_joins_and_splits_its_own_lists_whatever_ifs_the_shell_has(tmp_path, ifs):
	# COMP_LINE joined the words with IFS's first character; the keymaps to arm again were split with it
	script = ('. "$1"; exec 3>&1; IFS=' + ifs + '; _zzline() { printf "line[%s]\\n" "$COMP_LINE" >&3; }; complete -F _zzline zzcmd; '
		'_mssh_complete_guard _mssh_complete_delegate b 2 "" zzcmd a b >/dev/null; '
		'_mssh_complete_arm() { printf "arm[%s]\\n" "$1"; }; _mssh_complete_unarmed=" emacs vi-insert"; _mssh_complete_rearm_now 0')
	output = subprocess.run([require_shell('bash'), '-c', script, 'probe', str(glue_file(tmp_path, 'bash'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode().splitlines() == ['line[zzcmd a b]', 'arm[emacs]', 'arm[vi-insert]'], output


@pytest.mark.parametrize('strategy, strategies', [
	# zsh-autosuggestions' own form, a list written as one string, none set
	('(history completion)', ['history', 'completion']), ('"history completion"', ['history', 'completion']), ('', ['history'])])
@pytest.mark.parametrize('ifs', ["$'\\n'", ':'])
def test_zsh_glue_splits_the_autosuggestion_strategies_whatever_ifs_the_shell_has(tmp_path, ifs, strategy, strategies):
	# outside the completion system (which sets IFS for itself): (s: :) joined an array with IFS first, and
	# (history completion) became one strategy history:completion, which does not exist
	script = ('source "$1"; IFS=' + ifs + '; ' + ('ZSH_AUTOSUGGEST_STRATEGY=' + strategy if strategy else 'unset ZSH_AUTOSUGGEST_STRATEGY')
		+ '; _mssh_complete_zas_strategy; print -r -- "${(j:|:)ZSH_AUTOSUGGEST_STRATEGY}"')
	output = subprocess.run([require_shell('zsh'), '-f', '-c', script, 'probe', str(glue_file(tmp_path, 'zsh'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode() == '|'.join(['mssh'] + strategies) + '\n', output


@pytest.mark.parametrize('strategy, strategies', [
	('(mssh)', 'mssh'), ('mssh', 'mssh'), ('(history mssh)', 'history|mssh'),
	('(xmssh)', 'mssh|xmssh'), ('mssh_old', 'mssh|mssh_old'), ('"history mssh_old"', 'mssh|history|mssh_old')])
def test_zsh_glue_finds_mssh_among_the_autosuggestion_strategies_as_a_whole_word(tmp_path, strategy, strategies):
	# one strategy was a scalar to the subscript, which looked for mssh inside it: zsh 5.9 found it in
	# xmssh and mssh_old (mssh never asked), zsh 5.5 not in mssh (asked twice)
	script = 'source "$1"; ZSH_AUTOSUGGEST_STRATEGY=' + strategy + '; _mssh_complete_zas_strategy; print -r -- "${(j:|:)ZSH_AUTOSUGGEST_STRATEGY}"'
	output = subprocess.run([require_shell('zsh'), '-f', '-c', script, 'probe', str(glue_file(tmp_path, 'zsh'))],
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert output.stdout.decode() == strategies + '\n', output


# a command whose completion is built on _arguments, as most of zsh's are
ZSH_FAKEOPTS = "_fakeopts() { _arguments '--apparent-size[sizes as seen]' '--block-size=[unit]:unit:' }\ncompdef _fakeopts fakeopts"


def test_zsh_runs_delegated_completions_as_zsh_runs_them(setup):
	# the remote command's completion runs as zsh runs it: with the completion system's options
	# (_arguments misreads its specs without them) and with the operator's own (glob_dots)
	env, home = setup
	(home / 'dots').mkdir()
	(home / 'dots' / '.zzhidden').write_text('')
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=ZSH_FAKEOPTS + '\nsetopt glob_dots')
	try:
		assert session.line_after('fakeopts --appa') == 'fakeopts --apparent-size '
		assert session.line_after('mssh h fakeopts --appa') == 'mssh h fakeopts --apparent-size '
		assert session.line_after('ls dots/') == 'ls dots/.zzhidden '
		assert session.line_after('mssh h ls dots/') == 'mssh h ls dots/.zzhidden '
		assert b'_mssh:' not in session.output
	finally:
		session.close()


def test_zsh_a_completion_function_setting_names_of_its_own_leaves_the_glue_alone(setup):
	# zsh scopes as bash does. A completion setting matches made _mssh think nothing was offered, and file
	# names came in beside the command's words (alzzfile); one setting nodefault and offering nothing kept
	# out the file names zsh offers then (zzfile_unique). Each sets the other name as the glue had it
	env, home = setup
	(home / 'alzzfile').write_text('')
	(home / 'zzfile_unique').write_text('')
	names = ('before after flags resp chunk line item name fd kind rest fields texts shown dwords compsys_options',
		'end remaining files delegate dcword start')
	clobber = (' '.join("{}='a b'".format(name) for name in names[0].split()) + '; '
		+ ' '.join('{}=1000'.format(name) for name in names[1].split()))
	extra = ('_zzclob() {{ {0}; matches=1000 nodefault=0; compadd alpha alpine }}\ncompdef _zzclob zzclob\n'
		'_zzquiet() {{ {0}; matches=0 nodefault=1 }}\ncompdef _zzquiet zzquiet').format(clobber)
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=extra)
	try:
		assert session.line_after('zzclob al') == 'zzclob alp'
		assert session.line_after('mssh h zzclob al') == 'mssh h zzclob alp'
		assert session.line_after('mssh h zzquiet zz') == 'mssh h zzquiet zzfile_unique '
		assert b'_mssh:' not in session.output
	finally:
		session.close()


def test_zsh_a_post_pattern_completion_adds_nothing_to_the_words_of_the_remote_command(setup):
	# python-argcomplete installs `#compdef -P *`, a completion zsh runs after the command's own. For an mssh line
	# that command is _mssh, whose _normal cleared the _compskip that keeps _dispatch from going on to it: it added
	# local file names beside the remote command's words
	env, home = setup
	extra = '_zzdel() { compadd alpha alpine }\ncompdef _zzdel zzdel\n_zzpost() { compadd alzzpost }\ncompdef -P _zzpost "*"'
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra=extra)
	try:
		assert session.line_after('zzdel al') == 'zzdel alp'
		assert session.line_after('mssh h zzdel al') == 'mssh h zzdel alp'
	finally:
		session.close()


@pytest.mark.parametrize('option', ['ignore_braces', 'ignore_close_braces'])
def test_zsh_glue_loads_with_brace_options(tmp_path, option):
	# with either option a } closes a group only in command position: the glue must parse all the same
	zsh = require_shell('zsh')
	env, home = make_home(tmp_path)
	script = 'autoload -Uz compinit && compinit -u -D; setopt {}; source {}; print -r -- "$+functions[_mssh] $_comps[mssh]"'
	result = subprocess.run([zsh, '-f', '-c', script.format(option, glue_file(home, 'zsh'))], env=env,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
	assert (result.stdout.decode().split(), result.stderr.decode()) == (['1', '_mssh'], '')


def test_zsh_gives_up_on_a_slow_engine(setup):
	env, home = setup
	slow = home / 'slow-engine'
	slow.write_text('#!/bin/sh\nsleep 5\n')
	slow.chmod(0o755)
	session = zsh_session(home, dict(env, MSSH_COMPLETE_TIMEOUT='0.3'), glue_file(home, 'zsh', [str(slow)]))
	try:
		started = time.monotonic()
		assert session.line_after('mssh gp') == 'mssh gp'
		assert time.monotonic() - started < 3
	finally:
		session.close()


@pytest.fixture
def first_build(tmp_path):
	'''No index yet, and the first build is running (its lock is taken and it never ends).'''
	env, home = make_home(tmp_path, HISTORY)
	fd = hold_lock(str(tmp_path / 'runtime' / 'multiSSH3' / mc.LOCK_NAME))
	# more than the engine needs, less than the 2 s it used to wait for the first build
	yield dict(env, MSSH_COMPLETE_TIMEOUT='1'), home
	os.close(fd)


def test_bash_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
	finally:
		session.close()


def test_zsh_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	session = zsh_session(home, env, glue_file(home, 'zsh'))
	try:
		assert session.line_after('mssh --no_wa') == 'mssh --no_watch '
	finally:
		session.close()


def test_fish_first_tab_answers_while_the_first_build_runs(first_build):
	env, home = first_build
	assert [text for text, _ in fish_complete(env, glue_file(home, 'fish'), 'mssh --no_wa')] == ['--no_watch']


# compinit as rc files run it, with its dump file
COMPINIT = 'autoload -Uz compinit && compinit -u'
# compinit as zinit turbo and zsh-defer run it: after the first prompt
LATE_COMPINIT = '''_mssh_test_late() { add-zsh-hook -d precmd _mssh_test_late; autoload -Uz compinit && compinit -u }
autoload -Uz add-zsh-hook; add-zsh-hook precmd _mssh_test_late'''


@pytest.mark.parametrize('before, after, prompts', [
	('', COMPINIT, 1),
	('', LATE_COMPINIT, 2),
	(COMPINIT, COMPINIT, 1),
], ids=['later-in-the-rc-file', 'after-the-first-prompt', 'again-from-its-dump'])
def test_zsh_completes_whenever_compinit_runs(setup, before, after, prompts):
	# compdef only exists once compinit ran, and a compinit that loads its dump forgets what was registered before it
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'), compinit=before, extra=after)
	try:
		for _ in range(prompts - 1):
			session.send('true\r')
			session.read_until(b'@@READY@@')
		assert session.line_after('mssh gp') == 'mssh gpu\\[01-16\\] '
	finally:
		session.close()


def test_zsh_keeps_a_completion_set_for_mssh_by_hand(setup):
	env, home = setup
	session = zsh_session(home, env, glue_file(home, 'zsh'), extra='compdef _fakecmd mssh')
	try:
		session.send('true\r')
		session.read_until(b'@@READY@@')
		assert session.line_after('mssh al') == 'mssh alpha '
	finally:
		session.close()


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
def test_fish_completes(setup, tmp_path, timeout):
	# with coreutils' timeout(1) and without it (macOS): the glue keeps its time limit either way
	require_shell('fish')
	env, home = setup
	if timeout == 'no timeout':
		env = without_command(env, 'timeout', tmp_path / 'bin')
	glue = glue_file(home, 'fish')
	assert fish_complete(env, glue, 'mssh gp') == [('gpu[01-16]', 'used before')]
	assert fish_complete(env, glue, 'mssh gpu[01-16] "nvid')[0] == ('nvidia-smi', '')
	# fish sets $USER from the user database, and mssh-complete offers it: the name of whoever runs the
	# tests (runner, on GitHub's machines) may start with r too
	me = pwd.getpwuid(os.getuid()).pw_name
	assert [pair for pair in fish_complete(env, glue, 'mssh -u r') if pair != (me, 'user')] == [('root', 'used before')]
	assert fish_complete(env, glue, 'mssh h fakecmd al') == [('alpha', '')]
	assert fish_complete(env, glue, 'mssh h "date; fakecmd al') == [('date; fakecmd alpha', '')]


# engines that give no answer: the glue must fall back to file names, on time and quietly
NO_ANSWER = {
	'slow': '#!/bin/sh\nsleep 5\n',
	'failing': '#!/bin/sh\nexit 1\n',
	'missing': None,
	'without its interpreter': '#!/nonexistent/python3\n',
}


def no_answer_engine(home, kind):
	path = home / 'engine'
	if NO_ANSWER[kind] is not None:
		path.write_text(NO_ANSWER[kind])
		path.chmod(0o755)
	return [str(path)]


@pytest.mark.parametrize('timeout', ['timeout', 'no timeout'])
@pytest.mark.parametrize('engine', sorted(NO_ANSWER))
def test_fish_falls_back_to_file_names_without_an_answer(setup, tmp_path, engine, timeout):
	# as bash does (-o default): fish's own file names, within the time limit, and nothing printed
	require_shell('fish')
	env, home = setup
	env = dict(env, MSSH_COMPLETE_TIMEOUT='0.3')
	if timeout == 'no timeout':
		env = without_command(env, 'timeout', tmp_path / 'bin')
	(home / 'zzfile_unique').write_text('')
	glue = glue_file(home, 'fish', no_answer_engine(home, engine))
	started = time.monotonic()
	assert fish_complete(env, glue, 'mssh h zzf', cwd=home) == [('zzfile_unique', '')]
	assert time.monotonic() - started < 3


# what fish prints when a command fails to start or a background job ends
FISH_MESSAGES = ('job', 'signal', 'error', 'unknown command', 'expanded command', 'fish:')


@pytest.mark.parametrize('engine', ['answering', 'slow'])
def test_fish_without_timeout_shows_nothing_but_the_completion(setup, tmp_path, engine):
	# without timeout(1) the glue keeps the time limit with a timer of its own: on screen, only the
	# completion, whether the engine answers or is stopped (TAB, and on fish 4 the check at each space)
	require_shell('fish')
	env, home = setup
	env = without_command(env, 'timeout', tmp_path / 'bin')
	(home / 'zzfile_unique').write_text('')
	# more shell history than a pipe holds: the slow engine never reads it, and fish must not wait to write it
	history = home / '.local' / 'share' / 'fish'
	history.mkdir(parents=True)
	(history / 'fish_history').write_text(''.join('- cmd: echo {} {}\n  when: {}\n'.format(number, 'x' * 300, aged(1790000000 + number)) for number in range(1000)))
	if engine == 'answering':
		command, typed, expected = ENGINE, 'mssh gp', 'mssh gpu\\[01-16\\] '
	else:
		command, typed, expected = no_answer_engine(home, 'slow'), 'mssh h zzf', 'mssh h zzfile_unique '
		env['MSSH_COMPLETE_TIMEOUT'] = '0.3'
	# fish completes only commands that exist
	pre = 'function mssh; end\nsource {}'.format(glue_file(home, 'fish', command))
	session = fish_session(home, env, mc.render_glue('fish-keys', command), pre=pre)
	try:
		start = len(session.output)
		started = time.monotonic()
		assert session.line_after(typed) == expected
		if engine == 'slow':
			assert time.monotonic() - started < 3
		# fish reports ended background jobs before its next prompt
		session.send('\r')
		session.read_until(b'@@READY@@')
		session.read_until(b'@@never@@', 1.0)
		shown = session.output[start:].decode('utf-8', 'replace').lower()
		assert [message for message in FISH_MESSAGES if message in shown] == []
	finally:
		session.close()


def _interactive_output(shell, env, home):
	'''Everything a fresh interactive shell prints before its first prompt, without the prompt.'''
	argv = {'bash': [shell, '-i'], 'zsh': [shell, '-i'], 'fish': [shell, '-i']}[os.path.basename(shell)]
	result = subprocess.run(argv, input=b'exit\n', env=dict(env, PS1='', PROMPT=''), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	# bash 4.2's readline turns on xterm's meta key mode again when keys were bound at the first
	# prompt: the same invisible mode, sent twice
	return result.returncode, re.sub('(\x1b\\[\\?1034h)+', '\x1b[?1034h', result.stdout.decode('utf-8', 'replace'))


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
@pytest.mark.parametrize('damage', ['none', 'deleted', 'unreadable', 'broken', 'no engine'])
def test_new_shells_stay_silent(tmp_path, shell, damage):
	path = require_shell(shell)
	env, home = make_home(tmp_path)
	if shell == 'zsh':
		(home / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	baseline = _interactive_output(path, env, home)
	command = ['/nonexistent/engine'] if damage == 'no engine' else ENGINE
	code, messages = mc.install(shell, home=str(home), environ=env, command=command)
	assert code == 0, messages
	# fish sources its conf.d file itself, as bash and zsh source the rc block: mssh writes both whole
	glues = [line.split(' ', 1)[1] for line in messages if line.startswith('wrote ') and '/conf.d/' not in line]
	for glue in glues:
		if damage == 'deleted':
			os.unlink(glue)
		elif damage == 'unreadable':
			os.chmod(glue, 0)
		elif damage == 'broken':
			with open(glue, 'a') as f:
				f.write('\n((( broken syntax\n')
	assert _interactive_output(path, env, home) == baseline


@pytest.mark.parametrize('compinit', ['none', 'after the block'])
def test_new_zsh_stays_silent_whenever_compinit_runs(tmp_path, compinit):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	rc = home / '.zshrc'
	tail = COMPINIT + '\n' if compinit == 'after the block' else ''
	rc.write_text('setopt nobeep\n' + tail)
	baseline = _interactive_output(path, env, home)
	rc.write_text('setopt nobeep\n')
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	with rc.open('a') as f:
		f.write(tail)
	assert _interactive_output(path, env, home) == baseline


def test_new_bash_with_the_editor_stays_silent(tmp_path):
	path = require_shell('bash')
	env, home = make_home(tmp_path)
	baseline = _interactive_output(path, env, home)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)[0] == 0
	assert _interactive_output(path, env, home) == baseline


def test_install_turns_the_editor_on_and_keeps_it_on(tmp_path):
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	mc.install('bash', home=str(home), environ=env, editor=True)
	assert 'export MSSH_COMPLETE_EDITOR=1\n' in rc.read_text()
	# installing again after an upgrade, without the word, keeps it on and says how to turn it off
	code, messages = mc.install('bash', home=str(home), environ=env)
	text = rc.read_text()
	assert 'export MSSH_COMPLETE_EDITOR=1\n' in text and text.count('# >>> mssh completion >>>') == 1
	# after the glue file it wrote, before the note about login shells
	assert messages[1:3] == ['kept the mssh line editor on (to turn it off: mssh --completion uninstall bash, then install bash)', '{} already loads it'.format(rc)]
	mc.uninstall('bash', home=str(home), environ=env)
	mc.install('bash', home=str(home), environ=env)
	assert 'MSSH_COMPLETE_EDITOR' not in rc.read_text()


@pytest.mark.parametrize('change', ['no final newline', 'crlf', 'moved to the top'])
def test_install_finds_its_block_however_the_file_was_edited(tmp_path, change):
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	mc.install('bash', home=str(home), environ=env)
	text = rc.read_text()
	if change == 'no final newline':
		text = text.rstrip('\n')
	elif change == 'crlf':
		text = text.replace('\n', '\r\n')
	else:
		begin = text.index('# >>> mssh')
		text = text[begin:] + text[:begin]
	rc.write_bytes(text.encode())
	mc.install('bash', home=str(home), environ=env)
	assert rc.read_text().count('# <<< mssh completion <<<') == 1
	mc.uninstall('bash', home=str(home), environ=env)
	assert 'mssh completion' not in rc.read_text() and 'alias ll="ls -l"' in rc.read_text()


@pytest.fixture
def install_env(tmp_path, monkeypatch):
	'''HOME and XDG_RUNTIME_DIR of a test home in os.environ, and install() writing nothing.'''
	env, home = make_home(tmp_path, HISTORY)
	monkeypatch.setenv('HOME', env['HOME'])
	monkeypatch.setenv('XDG_RUNTIME_DIR', env['XDG_RUNTIME_DIR'])
	monkeypatch.setattr(mc, 'install', lambda shell, editor=False: (0, ['wrote the glue']))
	return home


def test_install_builds_the_index_right_away(install_env, capsys):
	# the first TAB in a new shell then answers from the index instead of starting its build
	assert mc.completion_command(['install', 'bash']) == 0
	path = os.path.join(mc.cache_dir(), mc.INDEX_NAME)
	assert capsys.readouterr().out.splitlines() == ['wrote the glue', 'built the completion index ' + path]
	assert 'storage1' in mc.HostTable(mc.NsvIndex.load(path)).names


def test_install_says_when_it_cannot_build_the_index(install_env, monkeypatch, capsys):
	def fail(directory):
		raise OSError(28, 'No space left on device')
	monkeypatch.setattr(mc, 'build_index', fail)
	assert mc.completion_command(['install', 'bash']) == 0
	assert capsys.readouterr().out.splitlines()[-1] == 'could not build the completion index now ([Errno 28] No space left on device): the first TAB tries again'
	monkeypatch.setattr(mc, 'cache_dir', lambda create=True: None)
	assert mc.completion_command(['install', 'bash']) == 0
	assert capsys.readouterr().out.splitlines()[-1] == 'no private runtime directory for the completion index: TAB offers options and shell history only'


def test_uninstall_builds_nothing(install_env, monkeypatch):
	monkeypatch.setattr(mc, 'uninstall', lambda shell: (0, []))
	monkeypatch.setattr(mc, 'build_index', lambda directory: pytest.fail('built an index'))
	assert mc.completion_command(['uninstall', 'bash']) == 0


def test_completion_command_takes_the_editor_word(monkeypatch):
	calls = []
	monkeypatch.setattr(mc, 'prepare_index', lambda: 'built the completion index')
	monkeypatch.setattr(mc, 'install', lambda shell, editor=False: (calls.append((shell, editor)), (0, []))[1])
	assert mc.completion_command(['install', 'bash', 'editor']) == 0
	assert mc.completion_command(['install', 'bash', '--editor']) == 0
	assert mc.completion_command(['install', 'zsh', 'editor']) == 2
	assert calls == [('bash', True), ('bash', True)]


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_uninstall_restores_rc_files(tmp_path, shell):
	env, home = make_home(tmp_path)
	(home / '.bashrc').write_text('alias ll="ls -l"')
	(home / '.zshrc').write_text('setopt nobeep\n')
	before = {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')}
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	assert mc.install(shell, home=str(home), environ=env)[0] == 0
	mc.uninstall(shell, home=str(home), environ=env)
	assert {name: (home / name).read_bytes() for name in ('.bashrc', '.zshrc')} == before
	left = [os.path.join(root, name) for root, _, names in os.walk(str(home)) for name in names]
	assert sorted(left) == sorted([str(home / '.bashrc'), str(home / '.zshrc'), str(home / '.mssh_history'), str(home / '.multiSSH3.config.json')])


def test_uninstall_deletes_an_rc_file_it_created(tmp_path):
	env, home = make_home(tmp_path)
	mc.install('zsh', home=str(home), environ=env)
	assert (home / '.zshrc').exists()
	mc.uninstall('zsh', home=str(home), environ=env)
	assert not (home / '.zshrc').exists()


@pytest.mark.parametrize('zshrc, noted', [
	(None, True),
	('setopt nobeep\n', True),
	('# autoload -Uz compinit && compinit\n', True),
	('autoload -Uz compinit\ncompinit -i\n', False),
	('source $ZSH/oh-my-zsh.sh\n', False),
	('zinit light zsh-users/zsh-completions\nzicompinit; zicdreplay\n', False),
], ids=['no-zshrc', 'no-compinit', 'commented-out', 'compinit', 'oh-my-zsh', 'zinit'])
def test_zsh_install_says_when_the_rc_file_does_not_start_completion(tmp_path, zshrc, noted):
	# TAB needs zsh's completion system, which zsh starts only when told to
	env, home = make_home(tmp_path)
	rc = home / '.zshrc'
	if zshrc is not None:
		rc.write_text(zshrc)
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	notes = [message for message in messages if 'compinit' in message]
	note = "TAB needs zsh's completion system, which {0} does not seem to start: if TAB does not complete mssh in a new zsh, add this line to {0}: autoload -Uz compinit && compinit".format(rc)
	assert notes == ([note] if noted else []), messages
	# installing again says it again
	assert [message for message in mc.install('zsh', home=str(home), environ=env, command=ENGINE)[1] if 'compinit' in message] == notes


def test_install_never_overwrites_foreign_files(tmp_path):
	env, home = make_home(tmp_path)
	target = home / '.config' / 'fish' / 'completions' / 'mssh.fish'
	target.parent.mkdir(parents=True)
	target.write_text('# my own\n')
	code, messages = mc.install('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'
	assert any('skipped' in message for message in messages)
	mc.uninstall('fish', home=str(home), environ=env)
	assert target.read_text() == '# my own\n'


def test_bash_always_loads_from_bashrc(tmp_path, monkeypatch):
	# bash-completion being installed does not mean it runs in the user's shells (stock Debian root):
	# the ~/.bashrc hook works either way
	env, home = make_home(tmp_path)
	assert mc.install('bash', home=str(home), environ=env)[0] == 0
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	assert glue.read_text().startswith('# MSSH_COMPLETE_GLUE')
	assert mc.RC_BEGIN_CREATED in (home / '.bashrc').read_text()
	assert not (home / '.local' / 'share' / 'bash-completion').exists()


# With HOME empty, expanduser('~') is '/', and install wrote /.bashrc. These tests never let it get there:
# expanduser, the user database, os.environ's HOME and the working directory all point into tmp_path,
# and the '/' cases go only to the function that names the home directory, which writes nothing.
def _no_real_home(tmp_path, monkeypatch, user_home):
	import pwd
	for name in ('expanded', 'environ', 'cwd'):
		(tmp_path / name).mkdir()
	monkeypatch.setattr(os.path, 'expanduser', lambda path: str(tmp_path / 'expanded') + path[1:] if path.startswith('~') else path)
	monkeypatch.setenv('HOME', str(tmp_path / 'environ'))
	monkeypatch.chdir(str(tmp_path / 'cwd'))
	def getpwuid(uid):
		if user_home is None:
			raise KeyError(uid)
		return pwd.struct_passwd(('u', 'x', uid, 0, '', user_home, '/bin/sh'))
	monkeypatch.setattr(pwd, 'getpwuid', getpwuid)


@pytest.mark.parametrize('environ_home, user_home, expected', [
	('/', '/', None),
	('//', '/', None),
	('', '/', None),
	('', None, None),
	('', 'USER', 'USER'),
	('ENV', '/', 'ENV'),
])
def test_the_home_directory_is_never_slash(tmp_path, monkeypatch, environ_home, user_home, expected):
	names = {'USER': str(tmp_path / 'user'), 'ENV': str(tmp_path / 'env')}
	_no_real_home(tmp_path, monkeypatch, names.get(user_home, user_home))
	environ = {'HOME': names.get(environ_home, environ_home)}
	if expected is None:
		with pytest.raises(mc.InstallError):
			mc._home_directory(None, environ)
	else:
		assert mc._home_directory(None, environ) == names[expected]


def test_install_with_an_empty_home_uses_the_user_database(tmp_path, monkeypatch):
	_no_real_home(tmp_path, monkeypatch, str(tmp_path / 'user'))
	(tmp_path / 'user').mkdir()
	environ = {'HOME': '', 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'XDG_RUNTIME_DIR': str(tmp_path)}
	assert mc.install('bash', environ=environ, command=ENGINE)[0] == 0
	assert mc.RC_BEGIN_CREATED in (tmp_path / 'user' / '.bashrc').read_text()
	assert [os.listdir(str(tmp_path / name)) for name in ('expanded', 'environ', 'cwd')] == [[], [], []]
	assert mc.uninstall('bash', environ=environ)[0] == 0
	assert os.listdir(str(tmp_path / 'user')) == ['.local']


@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_install_without_a_home_directory_changes_nothing(tmp_path, monkeypatch, action):
	_no_real_home(tmp_path, monkeypatch, None)
	environ = {'HOME': '', 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'XDG_RUNTIME_DIR': str(tmp_path)}
	code, messages = mc.install('bash', environ=environ, command=ENGINE) if action == 'install' else mc.uninstall('bash', environ=environ)
	assert (code, messages) == (1, ['did not change anything: HOME is empty and the user database names no home directory; set HOME and run this again'])
	assert [os.listdir(str(tmp_path / name)) for name in ('expanded', 'environ', 'cwd')] == [[], [], []]


def _latin1_locale():
	'''A Latin-1 (ISO 8859-1 or -15) locale this machine has, or None.'''
	try:
		names = subprocess.run(['locale', '-a'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('ascii', 'replace').split()
	except OSError:
		return None
	return next((name for name in names if 'iso88591' in name.lower().replace('-', '').replace('_', '')), None)


def test_install_under_a_latin1_locale_writes_paths_as_they_are_on_disk(tmp_path):
	# Python decodes a non-ASCII HOME as Latin-1 there: written as UTF-8, the glue path in the rc
	# block was re-encoded (c3 83 c2 a9 for c3 a9 on disk), and [ -r ... ] skipped loading it
	bash = require_shell('bash')
	locale = _latin1_locale()
	if locale is None:
		pytest.skip('no Latin-1 locale here')
	env, _ = make_home(tmp_path)
	home = os.fsencode(str(tmp_path)) + b'/h\xc3\xa9'
	os.mkdir(home)
	env = dict(env, HOME=home, LC_ALL=locale)
	script = 'import mssh_complete as mc; mc.completion_command(["install", "bash"])'
	subprocess.run([sys.executable, '-c', script], env=env, cwd=str(REPO), stdout=subprocess.DEVNULL, check=True, timeout=60)
	with open(home + b'/.bashrc', 'rb') as f:
		assert home + b'/.local/share/multiSSH3/completion.bash' in f.read()
	result = subprocess.run([bash, '-i', '-c', 'type -t _mssh_complete || :'], env=env, cwd=home,
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
	assert result.stdout.decode().strip() == 'function'


LOGIN_LINE = '[ -f ~/.bashrc ] && . ~/.bashrc'

@pytest.mark.parametrize('files, reads', [
	({}, None),
	({'.profile': 'PATH=$HOME/bin:$PATH\n'}, '.profile'),
	({'.profile': 'if [ -n "$BASH_VERSION" ]; then . "$HOME/.bashrc"; fi\n'}, ''),
	({'.bash_login': LOGIN_LINE + '\n'}, ''),
	# bash reads the first of the three that exists
	({'.bash_profile': 'export EDITOR=vi\n', '.profile': LOGIN_LINE + '\n'}, '.bash_profile'),
	# a login file that sources another one which loads ~/.bashrc (one level deep)
	({'.bash_profile': '. ~/.profile\n', '.profile': LOGIN_LINE + '\n'}, ''),
	({'.bash_profile': '[ -f "$HOME/.profile" ] && source "$HOME/.profile"\n', '.profile': 'if [ -n "$BASH_VERSION" ]; then . "$HOME/.bashrc"; fi\n'}, ''),
	({'.bash_profile': '# . ~/.profile\n', '.profile': LOGIN_LINE + '\n'}, '.bash_profile'),
	({'.bash_profile': '. ~/.profile\n', '.profile': 'PATH=$HOME/bin:$PATH\n'}, '.bash_profile'),
])
def test_bash_install_says_when_login_shells_do_not_load_bashrc(tmp_path, files, reads):
	# login shells (ssh logins, macOS terminals) read ~/.bash_profile, ~/.bash_login or ~/.profile,
	# not ~/.bashrc: most of those load ~/.bashrc, and where none does the glue never loads there
	env, home = make_home(tmp_path)
	for name, text in files.items():
		(home / name).write_text(text)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	if reads is None:
		assert messages[-1] == ('note: bash login shells (ssh logins, macOS terminals) read {0}/.bash_profile, .bash_login or .profile,'
			' and there is none to load {0}/.bashrc; for autocomplete there too, create {0}/.bash_profile holding: {1}').format(home, LOGIN_LINE)
	elif reads:
		assert messages[-1] == ('note: bash login shells (ssh logins, macOS terminals) read {}, which does not seem to load {};'
			' for autocomplete there too, add this line to it: {}').format(home / reads, home / '.bashrc', LOGIN_LINE)
	else:
		assert messages[-1] == 'added a block loading it to {}'.format(home / '.bashrc')


def test_the_line_the_login_note_suggests_loads_the_glue(tmp_path):
	path = require_shell('bash')
	env, home = make_home(tmp_path)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[1][-1].endswith(LOGIN_LINE)
	def loaded():
		result = subprocess.run([path, '-l', '-i', '-c', 'type -t _mssh_complete || :'], env=env, cwd=str(home),
			stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
		return result.stdout.decode().strip() == 'function'
	assert not loaded()
	(home / '.bash_profile').write_text(LOGIN_LINE + '\n')
	assert loaded()


# one install or uninstall in a child process, which may not write a file past a size limit (as a full
# disk or a quota would stop it part way); prints what the call returned, or what it raised
LIMITED_CALL = r'''
import json, resource, sys
import mssh_complete as mc
limit, call, arguments = int(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
if limit >= 0:
	resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
try:
	print(json.dumps(getattr(mc, call)(**arguments)))
except Exception as error:
	print(json.dumps(['raised', repr(error)]))
'''

def _with_a_file_size_limit(limit, call, **arguments):
	result = subprocess.run([sys.executable, '-c', LIMITED_CALL, str(limit), call, json.dumps(arguments)],
		cwd=str(REPO), stdout=subprocess.PIPE, timeout=60)
	return json.loads(result.stdout.decode())

def _in_a_child(call, **arguments):
	'''What the call returns in a child process, or ['hung', []] when it did not end within 10 s.'''
	try:
		result = subprocess.run([sys.executable, '-c', LIMITED_CALL, '-1', call, json.dumps(arguments)],
			cwd=str(REPO), stdout=subprocess.PIPE, timeout=10)
	except subprocess.TimeoutExpired:
		return ['hung', []]
	return json.loads(result.stdout.decode())


@pytest.mark.parametrize('kind', ['fifo', 'device'])
def test_an_rc_file_that_is_not_a_regular_file_is_left_alone(tmp_path, kind):
	# ~/.bashrc linked to /dev/null turns it off: install as root replaced /dev/null with a file
	# holding the block (the node here is the test's own, in tmp_path), and reading a FIFO waited forever
	env, home = make_home(tmp_path)
	node = tmp_path / 'node'
	if kind == 'fifo':
		os.mkfifo(str(node))
	elif os.geteuid() == 0:
		os.mknod(str(node), 0o666 | stat.S_IFCHR, os.makedev(1, 3))
	else:
		pytest.skip('only root may make a device node')
	rc = home / '.bashrc'
	os.symlink(str(node), str(rc))
	code, messages = _in_a_child('install', shell='bash', home=str(home), environ=env, command=ENGINE)
	is_node = stat.S_ISFIFO if kind == 'fifo' else stat.S_ISCHR
	assert is_node(os.stat(str(node)).st_mode)
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	assert (code, messages[1:]) == (1, ['did not change {} (a link to {}): not a regular file'.format(rc, node),
		'to load it anyway, add these lines to it yourself:', mc.RC_BEGIN, '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue), mc.RC_END])
	# nothing of mssh's can be in it
	assert _in_a_child('uninstall', shell='bash', home=str(home), environ=env) == [0, ['removed {}'.format(glue)]]
	assert is_node(os.stat(str(node)).st_mode)


@pytest.mark.parametrize('change', ['add', 'update', 'remove'])
def test_a_failed_rc_write_leaves_the_rc_file_as_it_was(tmp_path, change):
	# install after an upgrade rewrote ~/.bashrc in place: what did not fit on the disk was lost
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text(''.join('alias x{0}="echo {0}"  # user line {0}\n'.format(number) for number in range(6000)))
	if change != 'add':
		assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	before = rc.read_bytes()
	# what is beside the rc file, but the glue's directory (adding writes it first)
	names = set(os.listdir(str(home))) - {'.local'}
	arguments = dict(shell='bash', home=str(home), environ=env)
	if change == 'remove':
		code, messages = _with_a_file_size_limit(len(before) // 2, 'uninstall', **arguments)
	else:
		# adding: the old text fits under the limit, the block does not
		limit = len(before) + 20 if change == 'add' else len(before) // 2
		code, messages = _with_a_file_size_limit(limit, 'install', command=ENGINE, editor=change == 'update', **arguments)
	assert rc.read_bytes() == before
	assert code == 1
	assert messages[-1].startswith('could not change {}: '.format(rc)) and messages[-1].endswith('; it is as it was')
	# and no temporary file is left behind
	assert set(os.listdir(str(home))) - {'.local'} == names


BLOCK_LINE = '[ -r /x/completion.bash ] && . /x/completion.bash 2>/dev/null || :\n'
USER_LINES = 'export PATH=$HOME/bin:$PATH\nalias ll="ls -l"\n'
BEGIN, CREATED, END = mc.RC_BEGIN + '\n', mc.RC_BEGIN_CREATED + '\n', mc.RC_END + '\n'
BROKEN_MARKERS = {
	'end deleted': ('export A=1\n\n' + BEGIN + BLOCK_LINE + USER_LINES, '(begin at line 3, no end)'),
	'begin deleted': ('export A=1\n\n' + BLOCK_LINE + END + USER_LINES, '(end at line 4, no begin)'),
	'end before begin': (END + USER_LINES + BEGIN + BLOCK_LINE, '(end at line 1, begin at line 4)'),
	'begin twice': (BEGIN + BLOCK_LINE + USER_LINES + BEGIN + BLOCK_LINE + END, '(begin at line 1, begin at line 5, end at line 7)'),
	'block twice': (CREATED + BLOCK_LINE + END + USER_LINES + BEGIN + BLOCK_LINE + END,
		'(begin at line 1, end at line 3, begin at line 6, end at line 8)'),
}

@pytest.mark.parametrize('damage', sorted(BROKEN_MARKERS))
@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_rc_files_with_broken_markers_are_left_alone(tmp_path, action, damage):
	# with its end line deleted, install appended a second block, and the next install replaced
	# everything from the first begin line to the new end line: the user's lines in between too
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	text, markers = BROKEN_MARKERS[damage]
	rc.write_text(text)
	for _ in range(2):
		if action == 'install':
			code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
		else:
			code, messages = mc.uninstall('bash', home=str(home), environ=env)
		assert rc.read_text() == text
		assert code == 1
		assert messages[-2:] == [
			'did not change {}: its mssh completion markers {} are not one block, so mssh cannot tell its lines from yours'.format(rc, markers),
			'fix them by hand (leave one block or none), then run this again']


def test_marker_lines_are_found_however_they_were_edited(tmp_path):
	# a marker with spaces around it, or as the last line without a line end, still counts:
	# a block it opens or closes is not mistaken for no block at all
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	text = USER_LINES + '  ' + mc.RC_BEGIN + ' \n' + BLOCK_LINE + USER_LINES + mc.RC_BEGIN
	rc.write_text(text)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 1 and '(begin at line 3, begin at line 7, no end)' in messages[-2]
	assert rc.read_text() == text


@pytest.mark.parametrize('zdotdir', ['set', 'empty'])
def test_zsh_installs_where_zsh_reads_its_rc_file(tmp_path, zdotdir):
	# zsh reads $ZDOTDIR/.zshrc when ZDOTDIR is set: install wrote ~/.zshrc, which zsh never read
	env, home = make_home(tmp_path)
	directory = home / '.config' / 'zsh' if zdotdir == 'set' else home
	directory.mkdir(parents=True, exist_ok=True)
	rc = directory / '.zshrc'
	rc.write_text('setopt nobeep\n')
	env = dict(env, ZDOTDIR=str(directory) if zdotdir == 'set' else '')
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	# other notes may follow it
	assert 'added a block loading it to {}'.format(rc) in messages
	assert mc.RC_BEGIN in rc.read_text()
	assert sorted(name for name in os.listdir(str(home)) if name.startswith('.zsh')) == (['.zshrc'] if zdotdir == 'empty' else [])
	mc.uninstall('zsh', home=str(home), environ=env)
	assert rc.read_text() == 'setopt nobeep\n'


# a stand-in zsh: the answer goes to the file named by its last argument (`print ... >| "$1"`),
# and to stdout as an `mssh-zdotdir:` line (how the first version asked)
FAKE_ZSH = '''#!/bin/sh
for last; do :; done
answer() {{
	echo "mssh-zdotdir:$1"
	case $last in /*) printf '%s\n' "$1" > "$last" ;; esac
}}
{}
'''

@pytest.mark.parametrize('answer', ['zdotdir', 'chatty zshenv', 'holds stdout', 'none', 'fails'])
def test_zsh_install_asks_zsh_for_zdotdir(tmp_path, answer):
	# ZDOTDIR set in ~/.zshenv without export is not in mssh's environment: zsh itself knows it
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	(home / 'bin').mkdir()
	fake = home / 'bin' / 'zsh'
	fake.write_text(FAKE_ZSH.format({
		'zdotdir': 'answer {}'.format(zdotdir),
		'chatty zshenv': 'echo "mssh-zdotdir:/wrong"; echo hello from zshenv; answer {}'.format(zdotdir),
		# a zshenv that starts a background job without redirecting it: reading zsh's output waited for the job
		'holds stdout': '(sleep 8) & answer {}'.format(zdotdir),
		'none': 'answer ""',
		'fails': 'exit 1'}[answer]))
	fake.chmod(0o755)
	env = dict(env, PATH=str(home / 'bin') + os.pathsep + env['PATH'])
	started = time.monotonic()
	code, messages = mc.install('zsh', home=str(home), environ=env, command=ENGINE)
	assert code == 0 and time.monotonic() - started < 4
	rc = home / '.zshrc' if answer in ('none', 'fails') else zdotdir / '.zshrc'
	assert mc.RC_BEGIN_CREATED in rc.read_text()
	# when zsh does not answer, the operator is told which file was used
	note = 'note: zsh did not say whether ZDOTDIR is set (it exited with status 1): using {}'.format(rc)
	assert [message for message in messages if message.startswith('note: zsh')] == ([note] if answer == 'fails' else [])
	assert mc.uninstall('zsh', home=str(home), environ=env)[0] == 0
	assert not rc.exists()


def test_zsh_install_says_when_there_is_no_zsh_to_ask(tmp_path):
	env, home = make_home(tmp_path)
	(home / 'bin').mkdir()
	code, messages = mc.install('zsh', home=str(home), environ=dict(env, PATH=str(home / 'bin')), command=ENGINE)
	assert code == 0 and 'note: zsh did not say whether ZDOTDIR is set (zsh is not on PATH): using {}'.format(home / '.zshrc') in messages


@pytest.mark.parametrize('job', ['', '(sleep 8) &\n'])
def test_a_new_zsh_loads_the_glue_from_an_unexported_zdotdir(tmp_path, job):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	# a background job started by ~/.zshenv keeps zsh's stdout open after zsh is done
	(home / '.zshenv').write_text('ZDOTDIR=$HOME/.config/zsh\n' + job)
	(zdotdir / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	assert 'ZDOTDIR' not in env
	started = time.monotonic()
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert time.monotonic() - started < 4
	assert not (home / '.zshrc').exists()
	result = subprocess.run([path, '-i', '-c', 'print -r -- "loaded=${+functions[_mssh]}"'], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	assert 'loaded=1' in result.stdout.decode('utf-8', 'replace')


def test_a_new_zsh_loads_the_glue_from_zdotdir(tmp_path):
	path = require_shell('zsh')
	env, home = make_home(tmp_path)
	zdotdir = home / '.config' / 'zsh'
	zdotdir.mkdir(parents=True)
	(zdotdir / '.zshrc').write_text('autoload -Uz compinit && compinit -u -D\n')
	env = dict(env, ZDOTDIR=str(zdotdir))
	assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	result = subprocess.run([path, '-i', '-c', 'print -r -- "loaded=${+functions[_mssh]}"'], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	assert 'loaded=1' in result.stdout.decode('utf-8', 'replace')


def test_fish_installs_into_its_config_directory(tmp_path):
	# fish's configuration directory is $XDG_CONFIG_HOME/fish when that is set
	env, home = make_home(tmp_path)
	config = home / 'xdg'
	env = dict(env, XDG_CONFIG_HOME=str(config))
	code, messages = mc.install('fish', home=str(home), environ=env, command=ENGINE)
	assert code == 0
	wrote = sorted(message.split(' ', 1)[1] for message in messages if message.startswith('wrote '))
	assert wrote == sorted([str(config / 'fish' / 'conf.d' / 'mssh-complete.fish')]
		+ [str(config / 'fish' / 'completions' / (name + '.fish')) for name in mc.MSSH_NAMES])
	assert not (home / '.config').exists()
	mc.uninstall('fish', home=str(home), environ=env)
	assert [name for _, _, names in os.walk(str(config)) for name in names] == []


def test_a_new_fish_loads_the_glue_from_xdg_config_home(setup):
	fish = require_shell('fish')
	env, home = setup
	# fish loads a command's completions only when the command exists
	(home / 'bin').mkdir()
	(home / 'bin' / 'mssh').write_text('#!/bin/sh\n')
	(home / 'bin' / 'mssh').chmod(0o755)
	env = dict(env, XDG_CONFIG_HOME=str(home / 'xdg'), PATH=str(home / 'bin') + os.pathsep + env['PATH'])
	assert mc.install('fish', home=str(home), environ=env, command=ENGINE)[0] == 0
	script = 'complete -C"mssh --no_wa"; functions -q __mssh_complete_ctrl_r; and echo keys loaded'
	result = subprocess.run([fish, '-c', script], env=env, cwd=str(home),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	output = result.stdout.decode('utf-8', 'replace')
	assert '--no_watch' in output and 'keys loaded' in output


def test_rc_files_that_are_links_stay_links(tmp_path):
	# dotfile managers link ~/.bashrc into a repository: the file in the repository is the one changed
	env, home = make_home(tmp_path)
	(home / 'dotfiles').mkdir()
	target = home / 'dotfiles' / 'bashrc'
	target.write_text('alias ll="ls -l"\n')
	target.chmod(0o640)
	rc = home / '.bashrc'
	os.symlink(os.path.join('dotfiles', 'bashrc'), str(rc))
	shown = '{} (a link to {})'.format(rc, target)
	assert 'added a block loading it to ' + shown in mc.install('bash', home=str(home), environ=env, command=ENGINE)[1]
	assert 'updated the mssh block in ' + shown in mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)[1]
	assert rc.is_symlink() and 'export MSSH_COMPLETE_EDITOR=1\n' in target.read_text()
	assert stat.S_IMODE(target.stat().st_mode) == 0o640
	assert mc.uninstall('bash', home=str(home), environ=env) == (0, [
		'removed ' + str(home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'), 'removed the mssh block from ' + shown])
	assert rc.is_symlink() and target.read_text() == 'alias ll="ls -l"\n'
	assert os.listdir(str(home / 'dotfiles')) == ['bashrc']


@pytest.mark.skipif(os.geteuid() != 0, reason='only root may give a file to another user')
def test_rc_files_keep_their_owner(tmp_path):
	# root installing with HOME set to a user's home (sudo -E): the file must stay the user's
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	os.chown(str(rc), 4321, 4322)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322) and mc.RC_BEGIN in rc.read_text()
	assert mc.uninstall('bash', home=str(home), environ=env)[0] == 0
	assert (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322) and rc.read_text() == 'alias ll="ls -l"\n'


@pytest.mark.skipif(os.geteuid() != 0, reason='only root may give a file to another user')
def test_an_rc_file_whose_owner_cannot_be_kept_is_not_replaced(tmp_path, monkeypatch):
	# a group-writable ~/.bashrc of another user: replacing it made it the installing user's
	# (fchown fails without root, here made to fail)
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	os.chown(str(rc), 4321, 4322)
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	before = rc.read_text()
	def not_permitted(*args):
		raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
	monkeypatch.setattr(os, 'fchown', not_permitted)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:-4] == ['could not change {}: replacing it would change its owner; it is as it was'.format(rc),
		'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:']
	assert rc.read_text() == before and (rc.stat().st_uid, rc.stat().st_gid) == (4321, 4322)
	assert sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history', '.multiSSH3.config.json']


def test_a_created_rc_file_gets_the_usual_permissions(tmp_path):
	env, home = make_home(tmp_path)
	mask = os.umask(0o027)
	try:
		assert mc.install('zsh', home=str(home), environ=env, command=ENGINE)[0] == 0
	finally:
		os.umask(mask)
	assert stat.S_IMODE((home / '.zshrc').stat().st_mode) == 0o640


@pytest.mark.parametrize('change', ['create', 'add', 'update', 'remove'])
def test_an_rc_file_mssh_may_not_change_gets_the_lines_to_change_by_hand(tmp_path, monkeypatch, change):
	# home-manager links ~/.bashrc into the read-only Nix store, and managed dotfiles may be read-only:
	# install ended in a traceback there; the operator needs the lines to put in by hand instead
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	if change != 'create':
		rc.write_text('alias ll="ls -l"\n')
	if change in ('update', 'remove'):
		assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	for name in ('_replace_file', '_append_file'):
		def read_only(path, text, write=getattr(mc, name)):
			if path == str(rc):
				raise OSError(errno.EROFS, os.strerror(errno.EROFS))
			write(path, text)
		monkeypatch.setattr(mc, name, read_only)
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	failed = 'could not change {}: {}; it is as it was'.format(rc, os.strerror(errno.EROFS))
	if change == 'remove':
		code, messages = mc.uninstall('bash', home=str(home), environ=env)
		advice = ['to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	else:
		code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=change == 'update')
		if change == 'update':
			advice = ['to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
				mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
		else:
			advice = ['to load it anyway, add these lines to it yourself:', mc.RC_BEGIN, load, mc.RC_END]
	assert code == 1
	assert messages[-len(advice) - 1:] == [failed] + advice


def test_hard_linked_rc_files_stay_linked(tmp_path):
	# replacing a hard-linked ~/.bashrc split it from the dotfiles copy, which kept the old text
	env, home = make_home(tmp_path)
	(home / 'dotfiles').mkdir()
	dotfile = home / 'dotfiles' / 'bashrc'
	dotfile.write_text('alias ll="ls -l"\n')
	rc = home / '.bashrc'
	os.link(str(dotfile), str(rc))
	assert mc.install('bash', home=str(home), environ=env, command=ENGINE)[0] == 0
	assert mc.RC_BEGIN in dotfile.read_text() and rc.stat().st_ino == dotfile.stat().st_ino
	before = rc.read_text()
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	split = 'did not change {}: it has 2 hard links, which replacing it would split'.format(rc)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:] == [split, 'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
		mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
	code, messages = mc.uninstall('bash', home=str(home), environ=env)
	assert code == 1 and messages[-2:] == [split, 'to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	assert rc.read_text() == before and rc.stat().st_ino == dotfile.stat().st_ino


@pytest.mark.parametrize('obstacle', ['bind mount', 'directory not writable'])
def test_rc_files_that_cannot_be_replaced_still_get_a_new_block(tmp_path, monkeypatch, obstacle):
	# a bind-mounted ~/.bashrc (docker -v, devcontainers, Kubernetes subPath) cannot be renamed over
	# (EBUSY), and a home directory the user may not write takes no temporary file: the first install
	# appends in place as it always did; editing an existing block says what to change by hand
	import tempfile
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	if obstacle == 'bind mount':
		replace = os.replace
		def busy(source, target):
			if target == str(rc):
				raise OSError(errno.EBUSY, os.strerror(errno.EBUSY), source, target)
			replace(source, target)
		monkeypatch.setattr(os, 'replace', busy)
		reason = 'cannot replace it ({})'.format(os.strerror(errno.EBUSY))
	else:
		mkstemp = tempfile.mkstemp
		def denied(*args, **kwargs):
			if kwargs.get('dir') == str(home):
				raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), os.path.join(str(home), '.bashrc.x.mssh-tmp'))
			return mkstemp(*args, **kwargs)
		monkeypatch.setattr(tempfile, 'mkstemp', denied)
		reason = 'cannot make a file beside it ({})'.format(os.strerror(errno.EACCES))
	glue = home / '.local' / 'share' / 'multiSSH3' / 'completion.bash'
	load = '[ -r {0} ] && . {0} 2>/dev/null || :'.format(glue)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	assert code == 0 and 'added a block loading it to {}'.format(rc) in messages
	assert rc.read_text() == 'alias ll="ls -l"\n\n{}\n{}\n{}\n'.format(mc.RC_BEGIN, load, mc.RC_END)
	before = rc.read_text()
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE, editor=True)
	assert code == 1 and messages[-6:] == ['could not change {}: {}; it is as it was'.format(rc, reason),
		'to load it anyway, replace lines 3 to 5 of it (the mssh block) with these yourself:',
		mc.RC_BEGIN, 'export MSSH_COMPLETE_EDITOR=1', load, mc.RC_END]
	code, messages = mc.uninstall('bash', home=str(home), environ=env)
	assert code == 1 and messages[-2:] == ['could not change {}: {}; it is as it was'.format(rc, reason),
		'to remove it anyway, delete lines 3 to 5 of it (the mssh block) yourself']
	# never a temporary file: not in the messages, not left behind
	assert rc.read_text() == before and sorted(os.listdir(str(home))) == ['.bashrc', '.local', '.mssh_history', '.multiSSH3.config.json']


@pytest.mark.skipif(os.geteuid() == 0, reason='root may write any file')
def test_install_leaves_a_read_only_rc_file_alone(tmp_path):
	# replacing the file would work (the directory is writable), but the user made it read-only
	env, home = make_home(tmp_path)
	rc = home / '.bashrc'
	rc.write_text('alias ll="ls -l"\n')
	rc.chmod(0o444)
	code, messages = mc.install('bash', home=str(home), environ=env, command=ENGINE)
	failed = 'could not change {}: Permission denied; it is as it was'.format(rc)
	assert code == 1 and messages[messages.index(failed) + 1] == 'to load it anyway, add these lines to it yourself:'
	assert rc.read_text() == 'alias ll="ls -l"\n'


def test_bash_delegation_keeps_text_before_word_breaks(setup):
	# bash's word ($2) stops at ":" and "=", the delegated results start at the whole word
	env, home = setup
	(home / 'a:bfile').write_text('')
	(home / 'x=abc').write_text('')
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh h nosuchcmd a:b') == 'mssh h nosuchcmd a:bfile '
		assert session.line_after('mssh h nosuchcmd x=a') == 'mssh h nosuchcmd x=abc '
	finally:
		session.close()


def test_bash_history_paths_are_escaped_once(tmp_path):
	path = str(tmp_path / 'home' / 'my hist.txt')
	env, home = make_home(tmp_path, ["1790000000\t/x/multiSSH3.py\t-su -hf='{}'\th\t\"uptime\"".format(path)])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh -hf ' + path[:-len(' hist.txt')]) == 'mssh -hf ' + path.replace(' ', '\\ ') + ' '
	finally:
		session.close()


def test_bash_delegation_that_turns_on_filenames_does_not_escape_twice(tmp_path):
	env, home = make_home(tmp_path, ["1790000000\t/x/multiSSH3.py\t-su\th\t'fakefile ab;cd'"])
	build_index(env)
	session = bash_session(home, env, glue_file(home, 'bash'))
	try:
		assert session.line_after('mssh h fakefile ab') == 'mssh h fakefile ab\\;cd '
	finally:
		session.close()


@pytest.mark.parametrize('option', ['set -e', 'set -u'])
def test_bash_shell_options_do_not_break_tab(setup, option):
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=option)
	try:
		assert session.line_after('mssh h nosuchcmd zzq') == 'mssh h nosuchcmd zzq'
		assert session.line_after('mssh gp') == 'mssh gpu[01-16] '
		assert b'unbound variable' not in session.output
	finally:
		session.close()


def test_bash_set_e_survives_a_missing_engine(setup):
	# bash 4.4 exits a set -e shell after a process substitution whose command failed
	env, home = setup
	session = bash_session(home, env, glue_file(home, 'bash', ['/nonexistent/engine']), bash_completion=False, extra='set -e')
	try:
		assert session.line_after('mssh h zzq') == 'mssh h zzq'
	finally:
		session.close()


# as mssh records `mssh web1 "nosuchcmd status 'ssh*'"` and the same with fakefile
QUOTED_WORD_HISTORY = ['1790000000\t/x/multiSSH3.py\t-su\tweb1\t\'{} status \'"\'"\'ssh*\'"\'"\'\''.format(name) for name in ('nosuchcmd', 'fakefile')]


def words(line):
	'''The words a line means, whatever quoting the shell chose.'''
	return None if line is None else [token.text for token in mc.lex(line)]


@pytest.mark.parametrize('shell', ['bash', 'zsh', 'fish'])
def test_command_words_are_inserted_with_their_quotes(tmp_path, shell):
	# mssh passes the quotes of 'ssh*' on to the remote shell only when the local word holds them
	env, home = make_home(tmp_path, QUOTED_WORD_HISTORY)
	build_index(env)
	# an empty working directory: the shells add its files to the words of a remote command
	empty = tmp_path / 'empty'
	empty.mkdir()
	cd = "cd '{}'".format(empty)
	typed = ['mssh web1 nosuchcmd status ']
	if shell == 'bash':
		session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=cd)
		# a delegated completion turns on file name quoting: bash quotes the word itself
		typed.append('mssh web1 fakefile status ')
	elif shell == 'zsh':
		session = zsh_session(home, env, glue_file(home, 'zsh'), extra=cd)
		typed.append("mssh web1 nosuchcmd status \\'ss")
	else:
		session = fish_session(home, env, '', pre="source '{}'; {}".format(glue_file(home, 'fish'), cd))
		typed.append("mssh web1 nosuchcmd status \\'ss")
	try:
		for line in typed:
			assert words(session.line_after(line)) == words(line)[:4] + ["'ssh*'"], line
	finally:
		session.close()


def test_bash_with_blesh_loaded_but_not_attached_gets_escaped_words(tmp_path):
	# readline completes, not ble.sh: the words must come escaped as for plain bash
	env, home = make_home(tmp_path, QUOTED_WORD_HISTORY)
	build_index(env)
	empty = tmp_path / 'empty'
	empty.mkdir()
	extra = "BLE_VERSION=0.4.0; BLE_ATTACHED=; cd '{}'".format(empty)
	session = bash_session(home, env, glue_file(home, 'bash'), bash_completion=False, extra=extra)
	try:
		assert words(session.line_after('mssh web1 nosuchcmd status ')) == ['mssh', 'web1', 'nosuchcmd', 'status', "'ssh*'"]
	finally:
		session.close()


DUMP_WITH_MSSH = "#files: 812\t#version: 5.9\n_comps=(\n'git' '_git'\n'mssh' '_mssh'\n'mssh3' '_mssh'\n)\n"


@pytest.mark.parametrize('dump_dir, name', [('home', '.zcompdump'), ('home', '.zcompdump-node1-5.9'),
	('zdotdir', '.zcompdump'), ('elsewhere', 'zcompdump-5.9')])
def test_uninstall_zsh_says_to_remove_a_dump_that_still_maps_mssh(tmp_path, dump_dir, name):
	# zsh's dump keeps mssh=_mssh after the glue is gone: the next TAB said "command not found: _mssh"
	env, home = make_home(tmp_path)
	zdotdir = tmp_path / 'zdot'
	zdotdir.mkdir()
	env = dict(env, ZDOTDIR=str(zdotdir))
	directory = {'home': home, 'zdotdir': zdotdir, 'elsewhere': tmp_path / 'cache'}[dump_dir]
	directory.mkdir(exist_ok=True)
	dump = directory / name
	dump.write_text(DUMP_WITH_MSSH)
	if dump_dir == 'elsewhere':
		env['ZSH_COMPDUMP'] = str(dump)
	assert mc.install('zsh', home=str(home), environ=env)[0] == 0

	status, messages = mc.uninstall('zsh', home=str(home), environ=env)

	assert status == 0
	assert messages[-1] == ("zsh's completion dump {0} still maps mssh to _mssh, which is gone: "
		"remove it (rm {0}) and zsh makes a new one".format(dump))
	# mssh leaves zsh's own file alone
	assert dump.read_text() == DUMP_WITH_MSSH


@pytest.mark.parametrize('shell, dump', [('zsh', "_comps=(\n'git' '_git'\n)\n"), ('bash', DUMP_WITH_MSSH)])
def test_uninstall_says_nothing_of_a_dump_without_mssh(tmp_path, shell, dump):
	env, home = make_home(tmp_path)
	(home / '.zcompdump').write_text(dump)
	assert mc.install(shell, home=str(home), environ=env)[0] == 0

	_, messages = mc.uninstall(shell, home=str(home), environ=env)

	assert not [message for message in messages if 'zcompdump' in message]
