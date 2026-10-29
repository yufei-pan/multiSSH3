'''
Replay mssh history through the completion engine and report how much typing it saves (the yardstick the ranking
thresholds are tuned with), or through the warnings (--diagnostics). Run from a checkout:

	python3 tests/replay.py [--synthetic | --diagnostics] [--since T] [--limit N] [HISTORY]
'''
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mssh_complete as mc

def _tab(candidates, typed, policy, quoted, nospace):
	'''What one TAB inserts after typed: (text or None if it would change typed text, appended suffix).'''
	texts = [candidate.text for candidate in candidates]
	if not texts:
		return '', ''
	if policy == 'ranked' or len(set(texts)) == 1:
		choice, unique = texts[0], True
	else:
		choice, unique = mc._common_prefix(texts), False
	if not choice.startswith(typed):
		return None, ''
	suffix = ('"' if quoted else '') + ' ' if unique and not nospace else ''
	return choice[len(typed):], suffix

def simulate_slot(engine, before, after, intended, quoted=False, policy='bash', shell='zsh', equivalents=()):
	'''
	Simulate an operator typing intended after before (with after behind the cursor), using TAB.

	The operator types a character at a time and presses TAB whenever it inserts the intended
	continuation. An appended space or quote that the operator then has to delete costs one key.
	equivalents are texts that do what intended does (the other strings of an option): a candidate
	that is one of them ranks as intended does, and a TAB toward one is taken, the operator typing
	on to its end.

	Returns:
		dict: keys, chars, rank (of intended at the start, 0 if absent), visited and divergent
			(positions where TAB would insert something unwanted), altered (candidates not
			extending what was typed: must stay 0), suffix_cost
	'''
	result = {'keys': 0, 'chars': len(intended), 'rank': 0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0}
	targets = [intended] + [text for text in equivalents if text != intended]
	target = intended
	position = 0
	while position < len(target):
		typed = target[:position]
		response = engine.query(mc.Request(shell, before + typed, after, typed))
		candidates = response.candidates
		result['visited'] += 1
		if position == 0:
			for number, candidate in enumerate(candidates):
				if candidate.text in targets:
					result['rank'] = number + 1
					break
		result['altered'] += sum(1 for candidate in candidates if not candidate.text.startswith(typed))
		inserted, suffix = _tab(candidates, typed, policy, quoted, 'nospace' in response.directives)
		if inserted and not target.startswith(typed + inserted):
			target = next((text for text in targets if text.startswith(typed + inserted)), target)
		remaining = target[position:]
		if inserted and remaining.startswith(inserted):
			result['keys'] += 1
			position += len(inserted)
			if suffix and position < len(target):
				result['keys'] += 1
				result['suffix_cost'] += 1
			continue
		if inserted:
			result['divergent'] += 1
		result['keys'] += 1
		position += 1
	return result

def simulate_ghost(engine, before, intended, quoted=False, ahead='', shell='bash', tab=True):
	'''
	Simulate an operator typing intended after before (nothing behind the cursor) with grey suggestions.

	At each position the operator takes the suggestion when it is what they mean: all of it when the
	rest of their line starts with it (ahead is what they would type after the slot), else its first
	word when that matches; otherwise, with tab, they press TAB when bash's TAB would insert what they
	mean (as simulate_slot's bash policy), else they type a character.

	Returns:
		dict: keys, chars, visited, shown (positions with a suggestion), divergent (shown but not
			what the operator means), altered (TAB candidates not extending what was typed: must stay 0)
	'''
	result = {'keys': 0, 'chars': len(intended), 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0}
	target = intended + ('"' if quoted else '') + ahead
	position = 0
	while position < len(intended):
		ghost = engine.suggest(mc.Request(shell, before + intended[:position], '', ''))
		result['visited'] += 1
		if ghost is not None:
			result['shown'] += 1
			remaining = target[position:]
			word = ghost.text.split(' ', 1)[0] if not ghost.text.startswith(' ') else ''
			if remaining.startswith(ghost.text):
				result['keys'] += 1
				position += len(ghost.text)
				continue
			if word and remaining.startswith(word):
				result['keys'] += 1
				position += len(word)
				continue
			result['divergent'] += 1
		if tab:
			typed = intended[:position]
			response = engine.query(mc.Request('zsh', before + typed, '', typed))
			result['altered'] += sum(1 for candidate in response.candidates if not candidate.text.startswith(typed))
			inserted, suffix = _tab(response.candidates, typed, 'bash', quoted, 'nospace' in response.directives)
			if inserted and intended[position:].startswith(inserted):
				result['keys'] += 1
				position += len(inserted)
				if suffix and position < len(intended):
					result['keys'] += 1
				continue
		result['keys'] += 1
		position += 1
	return result

def slot_cases(entry):
	'''
	(slot, before, after, intended, quoted, ahead) cases to replay for one history entry.

	ahead is how the positional slots after this one read when nothing follows the cursor yet
	(the grey suggestions' continuation), '' when they are not suggested.
	'''
	import shlex
	options = [(option, value, name) for (option, value), name in zip(entry.options, entry.option_texts) if option.dest not in mc.PASSWORD_DESTS]
	option_texts = [name if value is None else '{}={}'.format(name, shlex.quote(value)) for option, value, name in options]
	commands = [command for command in entry.commands if command.strip()]
	quoted_commands = []
	for command in commands:
		# the replay types as an operator does in bash
		quote = mc._quote_command(command, 'bash')
		if quote is None:
			commands = []
			quoted_commands = []
			break
		quoted_commands.append(quote + command + quote)
	head = ' '.join(['mssh'] + option_texts) + ' '
	tail = (' ' + ' '.join(quoted_commands)) if quoted_commands else ''
	first_command = (' ' + quoted_commands[0]) if quoted_commands else ''
	plain = not any(option.dest in ('file', 'file_sync', 'gather_mode', 'ipmi') for option, _, _ in options)
	cases = []
	if entry.hosts and not any(char in entry.hosts for char in ' \'"\\$`'):
		cases.append(('hosts', head, '', entry.hosts, False, first_command if plain else ''))
		if tail:
			cases.append(('hosts-back', head, tail, entry.hosts, False, ''))
		if commands and mc._quote_command(commands[0], 'bash') == '"':
			cases.append(('command', head + entry.hosts + ' "', '', commands[0], True, ''))
	for number, (_, value, name) in enumerate(options):
		others = ' '.join(['mssh'] + option_texts[:number] + option_texts[number + 1:]) + ' '
		rest = (' ' + entry.hosts + tail) if entry.hosts else ''
		cases.append(('option', others + '-', rest, name[1:], False, ''))
		if value and not any(char in value for char in ' \'"\\$`\t'):
			ahead = ((' ' + entry.hosts) if entry.hosts else '') + first_command if plain else ''
			cases.append(('value', others + name + ' ', rest, value, False, ahead))
	return cases

def _newest(items, limit):
	'''The last limit items (the newest of a history), none when limit is 0 or less.'''
	return items[-limit:] if limit > 0 else []

def evaluate(lines, spec, since=0, limit=300, policies=('bash', 'ranked', 'ghost')):
	'''
	Replay history lines in time order: each entry is typed with only the entries before it known.

	Args:
		lines (list): ~/.mssh_history lines
		spec (ParserSpec): The mssh options
		since (int): Only replay entries from this timestamp on (older ones are still learned from)
		limit (int): Replay at most this many of the newest entries

	Returns:
		dict: (policy, slot) -> totals of simulate_slot (or, for the ghost policy, simulate_ghost)
			results plus 'cases'
	'''
	entries = sorted((entry for entry in (mc.parse_history_line(line, spec) for line in lines) if entry is not None), key=lambda entry: entry.ts)
	replay = _newest([number for number, entry in enumerate(entries) if entry.ts >= since], limit)
	first = replay[0] if replay else len(entries)
	memory = mc.MemoryKnowledge()
	reference = entries[-1].ts if entries else 0
	for entry in entries[:first]:
		memory.add(entry.features(), mc.use_weight(reference - entry.ts))
	totals = {}
	for number in replay:
		entry = entries[number]
		engine = mc.Engine(spec, [memory])
		for slot, before, after, intended, quoted, ahead in slot_cases(entry):
			if not intended:
				continue
			equivalents = ()
			if slot == 'option':
				# every string of the option typed does what it does (-u, --username): offering another
				# is no miss. Strings of one action, not of one dest: -su and -nsu share their dest
				option, _ = spec.lookup('-' + intended)
				if option is not None:
					equivalents = tuple(string[1:] for string in option.strings)
			for policy in policies:
				if policy == 'ghost':
					# suggestions need the cursor at the end of the line: replay the slot typed last
					if slot in ('hosts-back', 'option'):
						continue
					result = simulate_ghost(engine, before, intended, quoted, ahead)
					total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'visited': 0, 'shown': 0, 'divergent': 0, 'altered': 0})
					total['cases'] += 1
					for key in ('keys', 'chars', 'visited', 'shown', 'divergent', 'altered'):
						total[key] += result[key]
					continue
				result = simulate_slot(engine, before, after, intended, quoted, policy, equivalents=equivalents)
				total = totals.setdefault((policy, slot), {'cases': 0, 'keys': 0, 'chars': 0, 'top1': 0, 'top3': 0,
					'mrr': 0.0, 'visited': 0, 'divergent': 0, 'altered': 0, 'suffix_cost': 0})
				total['cases'] += 1
				for key in ('keys', 'chars', 'visited', 'divergent', 'altered', 'suffix_cost'):
					total[key] += result[key]
				if result['rank']:
					total['top1'] += result['rank'] == 1
					total['top3'] += result['rank'] <= 3
					total['mrr'] += 1.0 / result['rank']
		memory.add(entry.features(), mc.use_weight(reference - entry.ts))
	return totals

def format_report(totals):
	'''The evaluation as text tables: TAB policies, then grey suggestions.'''
	ghost = {key: total for key, total in totals.items() if key[0] == 'ghost'}
	totals = {key: total for key, total in totals.items() if key[0] != 'ghost'}
	lines = ['{:7} {:10} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9} {:>8} {:>7}'.format(
		'policy', 'slot', 'cases', 'saved', 'top1', 'top3', 'mrr', 'divergent', 'altered', 'suffix')]
	for (policy, slot), total in sorted(totals.items()):
		cases = total['cases'] or 1
		lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%} {:>6.3f} {:>8.1%} {:>8} {:>7}'.format(
			policy, slot, total['cases'], 1 - float(total['keys']) / (total['chars'] or 1),
			float(total['top1']) / cases, float(total['top3']) / cases, total['mrr'] / cases,
			float(total['divergent']) / (total['visited'] or 1), total['altered'], total['suffix_cost']))
	if ghost:
		lines.append('')
		lines.append('{:7} {:10} {:>6} {:>7} {:>7} {:>7}'.format('policy', 'slot', 'cases', 'saved', 'shown', 'wrong'))
		for (policy, slot), total in sorted(ghost.items()):
			lines.append('{:7} {:10} {:>6} {:>6.1%} {:>6.1%} {:>6.1%}'.format(policy, slot, total['cases'],
				1 - float(total['keys']) / (total['chars'] or 1), float(total['shown']) / (total['visited'] or 1),
				float(total['divergent']) / (total['shown'] or 1)))
	return '\n'.join(lines)

def diagnostics_replay(lines, spec, validity, hosts=None, now=None):
	'''
	Replay history lines through the warnings. validity(name) -> 'valid', 'invalid' or 'unsure'
	stands in for the prober (asked once per host); there is no ping and no unavailable list.

	Returns:
		dict: lines (replayed), warned (kind -> lines with such a warning), unknown (host -> {'lines':
			lines naming it, 'meant': the host suggested or None}), checked (verdict -> hosts)
	'''
	now = time.time() if now is None else now
	engine = mc.Engine(spec, [], hosts)
	verdicts = {}

	class Answers(object):
		'''host -> HostState, as the prober would have found it: validity(name), could not ping.'''
		def get(self, name, default=None):
			if name not in verdicts:
				verdicts[name] = validity(name)
			return mc.HostState(verdicts[name], now, 'none', now)

	answers = Answers()
	report = {'lines': 0, 'warned': {kind: 0 for kind in mc.DIAGNOSTIC_KINDS}, 'unknown': {}, 'checked': {}}
	for line in lines:
		fields = line.rstrip('\r\n').split('\t')
		if len(fields) != 5:
			continue
		text = ' '.join(['mssh'] + [part for part in fields[2:5] if part and part != 'EMPTY_HOSTS']) + ' '
		found, _ = engine.diagnose(mc.Request('bash', text, '', ''), probe=False, now=now, states=answers)
		report['lines'] += 1
		for kind in set(item.kind for item in found):
			report['warned'][kind] += 1
		for item in found:
			if item.kind == 'unknown':
				name = item.message.split(':', 1)[0]
				entry = report['unknown'].setdefault(name, {'lines': 0, 'meant': engine._did_you_mean(name, answers, now)})
				entry['lines'] += 1
	for verdict in verdicts.values():
		report['checked'][verdict] = report['checked'].get(verdict, 0) + 1
	return report

def format_diagnostics_report(report):
	'''The diagnostics replay as text: what was checked, which lines would warn, the hosts mssh would reject.'''
	checked = report['checked']
	out = ['warnings over {} history lines (DNS, no ping)'.format(report['lines']),
		'  hosts checked: {} (valid {}, unsure {}, invalid {})'.format(sum(checked.values()), checked.get('valid', 0), checked.get('unsure', 0), checked.get('invalid', 0)),
		'  lines warned: ' + ', '.join('{} {}'.format(kind, report['warned'][kind]) for kind in mc.DIAGNOSTIC_KINDS)]
	if report['unknown']:
		out.append('  hosts mssh would reject:')
		for name, entry in sorted(report['unknown'].items(), key=lambda item: (-item[1]['lines'], item[0])):
			meant = '  (did you mean {}?)'.format(entry['meant']) if entry['meant'] else ''
			out.append('    {}  {} line{}{}'.format(name, entry['lines'], '' if entry['lines'] == 1 else 's', meant))
	return '\n'.join(out) + '\n'

def synthetic_history(seed=1, entries=1500, start=1700000000):
	'''
	A deterministic ~/.mssh_history with known structure: host groups each with their own commands,
	options and users, so ranking can be checked without anyone's real history.
	'''
	import random
	import shlex
	rng = random.Random(seed)
	profiles = [
		('gpu[01-16]', ['-u=root', '-t=30'], ['nvidia-smi', 'systemctl restart slurmd', 'nvidia-smi -q -d TEMPERATURE']),
		('storage[1-4]', ['-u=admin'], ['df -h /data', 'zpool status', 'zfs list']),
		('login[1-2]', [], ['uptime', 'who', 'free -h']),
		('us_east', ['-t=10'], ['systemctl status nginx', 'journalctl -u nginx -n 50']),
	]
	lines = []
	ts = start
	for _ in range(entries):
		ts += rng.randint(60, 7200)
		hosts, options, commands = rng.choices(profiles, [0.4, 0.25, 0.2, 0.15])[0]
		command = rng.choices(commands, [5, 3, 1][:len(commands)])[0]
		if hosts.startswith('gpu') and rng.random() < 0.15:
			hosts = 'gpu{:02d}'.format(rng.randint(1, 16))
		lines.append('{}\t/usr/bin/multiSSH3.py\t{}\t{}\t{}'.format(ts, ' '.join(['-su'] + options), shlex.quote(hosts), shlex.quote(command)))
	return lines

def _entry_time(line):
	'''The unix time an mssh history line starts with, 0 when it has none.'''
	head = line.split('\t', 1)[0]
	return int(head) if mc._is_digits(head) else 0

def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(prog='tests/replay.py', description='Replay mssh history and report how much typing completion saves.')
	parser.add_argument('history_file', nargs='?', help='history to replay (default: the one mssh writes)')
	parser.add_argument('--since', type=int, default=0, help='only replay entries from this unix time on')
	parser.add_argument('--limit', type=int, default=300, help='replay at most this many of the newest entries')
	parser.add_argument('--synthetic', action='store_true', help='replay a generated history instead')
	parser.add_argument('--diagnostics', action='store_true', help='replay the warnings instead, looking hosts up in DNS (no ping): lists the hosts mssh would reject')
	options = parser.parse_args(argv)
	mssh = mc._import_mssh()
	spec = mc.spec_from_parser(mssh.get_parser())
	if options.synthetic:
		lines = synthetic_history()
	else:
		lines, _, _ = mc.read_history(os.path.expanduser(options.history_file or mssh.DEFAULT_HISTORY_FILE))
	if options.diagnostics:
		lines = _newest([line for line in lines if _entry_time(line) >= options.since], options.limit)
		hosts = mc.engine_for(mc.Request('bash', 'mssh ', '', '')).hosts
		report = format_diagnostics_report(diagnostics_replay(lines, spec, mssh.host_validity, hosts))
		# host names come from the history: what stdout cannot encode (the C locale on Python 3.6, bytes that are not UTF-8) as escapes
		encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
		sys.stdout.write(report.encode(encoding, 'backslashreplace').decode(encoding))
		return 0
	print(format_report(evaluate(lines, spec, options.since, options.limit)))
	return 0

if __name__ == '__main__':
	sys.exit(main())
