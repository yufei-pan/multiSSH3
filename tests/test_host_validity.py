'''host_validity: mssh's own rule for a host name, with "does not exist" told apart from "no answer".'''
import shutil
import socket
import threading
import time

import pytest

import multiSSH3


@pytest.fixture
def hermetic(monkeypatch, tmp_path):
	'''No hosts file, env or env-file aliases, no ssh: names only go to (fake) DNS.'''
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(tmp_path / 'no-hosts'))
	monkeypatch.setattr(multiSSH3, '_etc_hosts', {})
	monkeypatch.setattr(multiSSH3, '_no_env', True)
	monkeypatch.setattr(multiSSH3, '_env_files', [str(tmp_path / 'no-env')])
	monkeypatch.delitem(multiSSH3._binPaths, 'ssh', raising=False)
	multiSSH3.readEnvFromFile.cache_clear()
	multiSSH3.getIP.cache_clear()
	yield tmp_path
	multiSSH3.getIP.cache_clear()
	multiSSH3.readEnvFromFile.cache_clear()


def fake_dns(monkeypatch, answers):
	'''getaddrinfo answering from answers: name -> an address, a gaierror code, or 'hang'; others do not exist.'''
	def getaddrinfo(host, *args, **kwargs):
		answer = answers.get(host, socket.EAI_NONAME)
		if answer == 'hang':
			threading.Event().wait(5)
			raise socket.gaierror(socket.EAI_AGAIN, 'timed out')
		if isinstance(answer, int):
			raise socket.gaierror(answer, 'fake')
		return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (answer, 0))]
	monkeypatch.setattr(multiSSH3.socket, 'getaddrinfo', getaddrinfo)


@pytest.mark.parametrize('answer, verdict', [
	('10.0.0.5', 'valid'),
	(socket.EAI_NONAME, 'invalid'),
	# no answer, a broken resolver: nothing is known about the name
	(socket.EAI_AGAIN, 'unsure'),
	(socket.EAI_FAIL, 'unsure'),
])
def test_dns_answers_in_three_ways(hermetic, monkeypatch, answer, verdict):
	fake_dns(monkeypatch, {'gpu17': answer})
	assert multiSSH3.host_validity('gpu17') == verdict


def test_a_lookup_that_hangs_is_unsure(hermetic, monkeypatch):
	fake_dns(monkeypatch, {'slow': 'hang'})
	started = time.monotonic()
	assert multiSSH3.host_validity('slow', timeout=0.2) == 'unsure'
	assert time.monotonic() - started < 2


def test_local_names_need_no_dns(hermetic, monkeypatch):
	hosts = hermetic / 'hosts'
	hosts.write_text('10.0.0.9 node9\n')
	monkeypatch.setattr(multiSSH3, 'DEFAULT_HOST_FILE', str(hosts))
	fake_dns(monkeypatch, {})
	assert [multiSSH3.host_validity(name) for name in ('node9', 'root@node9', '10.1.2.3')] == ['valid'] * 3


def test_an_env_alias_is_valid(hermetic, monkeypatch):
	monkeypatch.setattr(multiSSH3, '_no_env', False)
	monkeypatch.setenv('MSSHTESTGROUP', 'node1,node2')
	fake_dns(monkeypatch, {})
	assert multiSSH3.host_validity('MSSHTESTGROUP') == 'valid'


def ssh_with_config(hermetic, monkeypatch, text):
	'''The real ssh reading only an ssh config with text (ssh -G does not connect).'''
	real_ssh = shutil.which('ssh')
	if not real_ssh:
		pytest.skip('ssh not installed')
	config = hermetic / 'ssh_config'
	config.write_text(text)
	wrapper = hermetic / 'ssh'
	wrapper.write_text('#!/bin/sh\nexec {} -F {} "$@"\n'.format(real_ssh, config))
	wrapper.chmod(0o755)
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', str(wrapper))


def test_ssh_config_mapping_is_mssh_s_rule(hermetic, monkeypatch):
	# ssh -G only reads the config: a HostName or a ProxyJump makes a name valid, a catch-all block does not
	ssh_with_config(hermetic, monkeypatch, 'Host gpu-alias\n  HostName 127.0.0.7\nHost jump-*\n  ProxyJump bastion2\nHost *\n  ProxyJump bastion\n')
	fake_dns(monkeypatch, {})
	assert [multiSSH3.host_validity(name) for name in ('gpu-alias', 'jump-a', 'nodee1-typo')] == ['valid', 'valid', 'invalid']


@pytest.mark.parametrize('target_answer, verdict', [
	('10.9.9.1', 'valid'),
	(socket.EAI_NONAME, 'invalid'),
	# the target's lookup failing or hanging says nothing about the name
	(socket.EAI_AGAIN, 'unsure'),
	('hang', 'unsure'),
])
def test_a_hostname_template_counts_when_its_target_resolves(hermetic, monkeypatch, target_answer, verdict):
	# a catch-all HostName template applies to typos too: a name counts when its target resolves, and
	# that lookup has the same timeout as the name's own (the prober's batches must not hang on it)
	ssh_with_config(hermetic, monkeypatch, 'Host *\n  HostName %h.corp.example\n')
	fake_dns(monkeypatch, {'node1.corp.example': target_answer})
	started = time.monotonic()
	assert multiSSH3.host_validity('node1', timeout=0.2) == verdict
	assert time.monotonic() - started < 2


def test_an_ssh_config_that_cannot_be_read_is_unsure(hermetic, monkeypatch):
	monkeypatch.setitem(multiSSH3._binPaths, 'ssh', shutil.which('false') or '/bin/false')
	fake_dns(monkeypatch, {})
	assert multiSSH3.host_validity('gpu17') == 'unsure'
