import pytest

import mssh_complete as mc


@pytest.mark.parametrize('line, expected', [
	('mssh -u root', [('mssh', False, ''), ('-u', False, ''), ('root', False, '')]),
	('a "b c" d\\ e', [('a', False, ''), ('b c', True, ''), ('d e', False, '')]),
	("x 'it''s'", [('x', False, ''), ('its', True, '')]),
	('"a\\"b" "\\$x"', [('a"b', True, ''), ('$x', True, '')]),
	("$'a\\nb\\x41\\101'", [('a\nbAA', True, '')]),
	('mssh grp "lscp', [('mssh', False, ''), ('grp', False, ''), ('lscp', True, '"')]),
	("mssh 'abc", [('mssh', False, ''), ('abc', True, "'")]),
	("$'ab", [('ab', True, "$'")]),
	('a"b c"d', [('ab cd', True, '')]),
	('tail\\', [('tail', False, '')]),
	('  ', []),
])
def test_lex(line, expected):
	assert [(token.text, token.quoted, token.open_quote) for token in mc.lex(line)] == expected


def test_lex_keeps_raw_text():
	assert [token.raw for token in mc.lex('a "b c" d\\ e')] == ['a', '"b c"', 'd\\ e']


@pytest.mark.parametrize('before, after, words, current, prefix, open_quote, rest', [
	('mssh ', '', ['mssh'], '', '', '', []),
	('mssh gp', '', ['mssh'], 'gp', 'gp', '', []),
	('mssh ho', 'st cmd', ['mssh'], 'host', 'ho', '', ['cmd']),
	('mssh grp "a | gre', '', ['mssh', 'grp'], 'a | gre', 'a | gre', '"', []),
	('mssh h "sys', 'tem ctl"', ['mssh', 'h'], 'system ctl', 'sys', '"', []),
	('mssh h ', ' "uptime"', ['mssh', 'h'], '', '', '', ['uptime']),
	('mssh -f=/et', '', ['mssh'], '-f=/et', '-f=/et', '', []),
	('mssh foo\\', '', ['mssh'], 'foo', 'foo', '', []),
])
def test_split_at_cursor(before, after, words, current, prefix, open_quote, rest):
	cursor = mc.split_at_cursor(before, after)
	assert [token.text for token in cursor.before] == words
	assert cursor.current.text == current
	assert cursor.prefix == prefix
	assert cursor.open_quote == open_quote
	assert [token.text for token in cursor.after] == rest
