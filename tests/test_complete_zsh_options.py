'''
The zsh glue in whatever options the operator's .zshrc set before the mssh block.

zsh parses what it sources in the options of the moment: sh_glob, ignore_braces or ksh_arrays set
earlier changed what the glue meant (a parse error, an `exec {fd}<` that ran a command named {fd},
a compdef never called). Loading the glue must leave the operator's options and aliases as they were.
'''
import os
import re
import subprocess
import time

import pytest

import mssh_complete as mc
from complete_shell_harness import ENGINE, Session, build_index, make_home, require_shell

HISTORY = ['17900000{:02d}\t/x/multiSSH3.py\t-su\tgpu[01-16]\t"nvidia-smi"'.format(number) for number in range(6)]

# what an operator's .zshrc may set before the mssh block (prezto's utility module defines the fc alias)
SETTINGS = [
	'setopt sh_glob', 'setopt ksh_arrays', 'setopt ignore_braces', 'setopt rc_quotes', 'unsetopt short_loops',
	'setopt sh_word_split', 'setopt ksh_glob', 'unsetopt multibyte', 'setopt posix_identifiers',
	'setopt posix_builtins', 'unsetopt equals', 'unsetopt function_argzero', 'emulate sh',
	"alias fc='noglob fc'",
]

# loads the glue after compinit and the setting; prints what changed, then the glue's functions as
# zsh reads them (printed in zsh's options, so that only how they were read can differ)
LOAD_SCRIPT = r'''
autoload -Uz compinit && compinit -u -D
{setting}
_test_before="${{(kv)options[@]}} ${{(kv)aliases[@]}}"
source {glue}
_test_after="${{(kv)options[@]}} ${{(kv)aliases[@]}}"
emulate zsh
[[ $_test_before == "$_test_after" ]] || print -r -- 'the options or aliases changed'
print -r -- "TAB: ${{_comps[mssh]-none}}"
for _test_name in ${{(ok)functions}}; do
	[[ $_test_name == (_mssh*|_zsh_autosuggest_strategy_mssh) ]] && functions -- $_test_name
done
'''


def load(tmp_path, setting):
	'''Load the glue in a zsh with setting made first: (what it printed on stdout, on stderr).'''
	zsh = require_shell('zsh')
	tmp_path.mkdir()
	env, home = make_home(tmp_path)
	glue = home / 'glue.zsh'
	glue.write_text(mc.render_glue('zsh', ENGINE))
	script = home / 'load.zsh'
	script.write_text(LOAD_SCRIPT.format(setting=setting, glue=glue))
	result = subprocess.run([zsh, '-f', str(script)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
	return result.stdout.decode('utf-8', 'replace'), result.stderr.decode('utf-8', 'replace')


@pytest.mark.parametrize('setting', SETTINGS)
def test_zsh_glue_reads_the_same_whatever_the_operator_set(tmp_path, setting):
	expected, _ = load(tmp_path / 'reference', '')
	assert 'TAB: _mssh' in expected and '_mssh_complete_setup' in expected
	output, errors = load(tmp_path / 'set', setting)
	assert errors == ''
	assert output == expected


# as the harness's rc, with braces that ignore_braces reads the same, and the setting just before the
# glue; the glue's errors are left on screen
OPTIONS_RC = r'''
PS1='@@READY@@ '
autoload -Uz compinit && compinit -u -D
_mssh_test_print() {{
	print -r -- "@@LINE[$BUFFER]@@"
}}
zle -N _mssh_test_print
bindkey '^X^P' _mssh_test_print
_fakecmd() {{
	compadd alpha beta
}}
compdef _fakecmd fakecmd
HISTFILE=~/.zsh_history; SAVEHIST=100; HISTSIZE=100; fc -R
{setting}
source {glue}
'''


def plain(text):
	'''Terminal output without escape sequences and carriage returns.'''
	return re.sub(r'\x1b(\[[0-9;?<=>]*[ -/]*[@-~]|[()][A-Z0-9]|[=>78])', '', text).replace('\r', '')


def line_after(session, keys, wait=1.0):
	'''Send keys, then the print key; the command line the shell printed (None if it did not), then clear it.'''
	session.send(keys)
	time.sleep(wait)
	session.send(session.print_key)
	text = session.read_until(b']@@', 10)
	start = text.rfind('@@LINE[')
	end = text.find(']@@', start)
	session.send('\x15')
	return text[start + 7:end] if start >= 0 and end > start else None


def zsh_version():
	output = subprocess.run([require_shell('zsh'), '-fc', 'print -r -- $ZSH_VERSION'], stdout=subprocess.PIPE, timeout=30).stdout
	return tuple(int(part) for part in re.findall(r'\d+', output.decode('ascii', 'replace'))[:2])


@pytest.mark.parametrize('option', ['sh_glob', 'ksh_arrays', 'ignore_braces'])
def test_zsh_works_whatever_options_the_operator_set(tmp_path, option):
	env, home = make_home(tmp_path, HISTORY)
	build_index(env)
	mc.write_host_states(str(tmp_path / 'runtime' / 'multiSSH3'), {'gpu017': mc.HostState('invalid', time.time())})
	glue = home / 'glue.zsh'
	glue.write_text(mc.render_glue('zsh', ENGINE))
	(home / '.zsh_history').write_text('echo aa1\n')
	(home / '.zshrc').write_text(OPTIONS_RC.format(setting='setopt ' + option, glue=glue))
	session = Session([require_shell('zsh'), '-i'], dict(env, ZDOTDIR=str(home), HISTFILE=str(home / '.zsh_history')), cwd=home)
	try:
		session.read_until(b'@@READY@@')
		# TAB completes mssh wherever zsh's own TAB works (before zsh 5.9, its completion system does
		# not run under sh_glob)
		if line_after(session, 'fakecmd al\t') == 'fakecmd alpha ':
			assert line_after(session, 'mssh gp\t') == 'mssh gpu\\[01-16\\] '
			assert line_after(session, 'mssh h fakecmd al\t') == 'mssh h fakecmd alpha '
		session.send('mssh gpu[01-16] ')
		time.sleep(0.5)
		session.send('\x12')
		assert 'commands for gpu[01-16]' in session.read_until(b'commands for', 10)
		picked = line_after(session, '\r')
		assert picked is not None and [token.text for token in mc.lex(picked)] == ['mssh', 'gpu[01-16]', 'nvidia-smi']
		if option != 'sh_glob' and zsh_version() >= (5, 3):
			# grey text and warnings (zsh 5.3 and later; zsh's add-zle-hook-widget finds no hooks under
			# sh_glob: see the glue)
			session.send('mssh gp')
			assert 'nvidia-smi' in session.read_until(b'nvidia-smi', 10)
			session.send('\x15mssh gpu017 ')
			assert 'unknown host' in plain(session.read_until(b'unknown host', 10))
			session.send('\x15')
		# the shell is still there, and the glue printed no error on the way (zsh names the file, eval or
		# function; before 5.9, zsh's completion system says `_main_complete: parse error` under sh_glob)
		session.send('print -r -- @@ALIVE@@\r')
		assert '@@ALIVE@@\r\n' in session.read_until(b'@@ALIVE@@\r\n', 10)
		shown = plain(session.output.decode('utf-8', 'replace'))
		for error in ('glue.zsh:', '(eval):', '_mssh', 'No such widget', 'command not found'):
			assert error not in shown
	finally:
		session.close()


ZAS = '/opt/zsh-autosuggestions/zsh-autosuggestions.zsh'


def test_zsh_keeps_the_operators_suggestion_strategies_under_ksh_arrays(tmp_path):
	# the glue puts mssh first among zsh-autosuggestions' strategies at the first prompt, in the
	# operator's options: ksh_arrays kept only the first of theirs
	if not os.path.isfile(ZAS):
		if 'zas' in os.environ.get('MSSH_REQUIRE_SHELLS', '').split(','):
			pytest.fail('zsh-autosuggestions is required here but not at ' + ZAS)
		pytest.skip('zsh-autosuggestions is not installed at ' + ZAS)
	zsh = require_shell('zsh')
	env, home = make_home(tmp_path)
	glue = home / 'glue.zsh'
	glue.write_text(mc.render_glue('zsh', ENGINE))
	(home / '.zshrc').write_text('source {}\nZSH_AUTOSUGGEST_STRATEGY=(history completion)\nsetopt ksh_arrays\nsource {}\n'.format(ZAS, glue))
	result = subprocess.run([zsh, '-i'], input=b'print -r -- "@@STRATEGY[${ZSH_AUTOSUGGEST_STRATEGY[@]}]@@"\nexit\n',
		env=dict(env, ZDOTDIR=str(home)), cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
	assert '@@STRATEGY[mssh history completion]@@' in result.stdout.decode('utf-8', 'replace')
