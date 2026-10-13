'''OPTION_NO_EFFECT: every entry is an option combination main() really ignores.'''
import pytest

import multiSSH3

ENTRIES = {entry[0]: entry for entry in multiSSH3.OPTION_NO_EFFECT}
IPMI_SETTINGS = ['-mpre=10.0.', '-iu=admin', '-ip=secret', '-ia=-I lanplus', '-im=redfish', '-irlt=30']


def test_entries_name_real_options():
	parser = multiSSH3.get_parser()
	strings = {string for action in parser._actions for string in action.option_strings}
	for option, kind, others, message in multiSSH3.OPTION_NO_EFFECT:
		assert option in strings and set(others) <= strings and kind in ('with', 'without') and message


@pytest.fixture
def ipmi_definitions(monkeypatch):
	'''process_args rewrites DEFAULT_IPMI_DEFINITIONS: start each call from the same list.'''
	saved = [dict(definition) for definition in multiSSH3.DEFAULT_IPMI_DEFINITIONS]

	def processed(argv):
		monkeypatch.setattr(multiSSH3, 'DEFAULT_IPMI_DEFINITIONS', [dict(definition) for definition in saved])
		return multiSSH3.process_args(argv)
	return processed


def built(processed, argv):
	'''What mssh would run for the first host of argv.'''
	args = processed(argv)
	host = multiSSH3.Host(args.hosts, ' '.join(args.commands), ipmi=args.ipmi)
	attempt = multiSSH3._build_command(host, None, list(multiSSH3.DEFAULT_IPMI_DEFINITIONS))
	return attempt.action, attempt.argv


def test_no_skip_unreachable_does_nothing_with_script(ipmi_definitions):
	assert ENTRIES['--no_skip_unreachable'][1:3] == ('with', ('--script',))
	assert vars(ipmi_definitions(['node1', 'true', '--script', '-nsu'])) == vars(ipmi_definitions(['node1', 'true', '--script']))
	# without --script it does something
	assert ipmi_definitions(['node1', 'true', '-nsu']).skip_unreachable is False


@pytest.mark.parametrize('setting', IPMI_SETTINGS)
def test_ipmi_settings_do_nothing_without_ipmi(ipmi_definitions, setting):
	option = next(action.option_strings[-1] for action in multiSSH3.get_parser()._actions if setting.split('=')[0] in action.option_strings)
	assert ENTRIES[option][1:3] == ('without', ('--ipmi', '--store_config_file', '--generate_config_file'))
	assert built(ipmi_definitions, ['node1', 'true', setting]) == built(ipmi_definitions, ['node1', 'true'])


def test_ipmi_changes_what_runs(ipmi_definitions):
	# the comparison above can see a difference
	assert built(ipmi_definitions, ['node1', 'true', '-M']) != built(ipmi_definitions, ['node1', 'true'])
