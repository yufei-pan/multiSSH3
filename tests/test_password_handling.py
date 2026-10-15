'''
A -p password is never shown or stored by mssh: the "> mssh" echo and the history list it as -p -,
which asks for it when replayed. `-p -` asks for the password on the terminal; MSSH_PASSWORD gives it
without the command line (where ps and the shell history see it). The command line wins over
MSSH_PASSWORD, MSSH_PASSWORD over DEFAULT_PASSWORD.
'''
import pytest

import multiSSH3

SECRET = "S3cret pw"


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
	'''main(argv) with run_command_on_hosts faked: (the password it got, stderr, the history line).'''
	history = tmp_path / "history"

	def fake_run(**kwargs):
		ran.append(kwargs.get("password"))
		return []

	monkeypatch.setattr(multiSSH3, "run_command_on_hosts", fake_run)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	monkeypatch.setattr(multiSSH3, "__global_suppress_printout", False)
	ran = []

	def main(*argv):
		ran.clear()
		capsys.readouterr()
		with pytest.raises(SystemExit) as exit:
			multiSSH3.main(["-hf", str(history), "-ef", "/dev/null"] + list(argv))
		err = capsys.readouterr().err
		line = history.read_text().splitlines()[-1] if history.exists() else None
		return exit.value.code, (ran[0] if ran else None), err, line

	return main


@pytest.fixture
def terminal(monkeypatch):
	'''The terminal -p - asks on: the answers it gives, and the prompts it showed.'''
	asked = []
	answers = []
	monkeypatch.setattr(multiSSH3, "_terminal_to_ask_on", lambda: True)

	def getpass(prompt):
		asked.append(prompt)
		answer = answers.pop(0)
		if isinstance(answer, BaseException):
			raise answer
		return answer

	monkeypatch.setattr(multiSSH3.getpass, "getpass", getpass)
	return answers, asked


def test_a_typed_password_is_neither_echoed_nor_stored(run):
	code, password, err, line = run("-p", SECRET, "127.0.0.1", "true")

	assert code == 0 and password == SECRET
	assert "S3cret" not in err and "S3cret" not in line
	assert "--password=- " in err
	# a replay asks for it
	assert "\t-p=- " in line


def test_dash_asks_on_the_terminal(run, terminal):
	answers, asked = terminal
	answers.append(SECRET)

	code, password, err, line = run("-p", "-", "127.0.0.1", "true")

	assert code == 0 and password == SECRET and len(asked) == 1
	assert "S3cret" not in err + line and "\t-p=- " in line


def test_dash_without_a_terminal_stops_before_running(run, monkeypatch):
	monkeypatch.setattr(multiSSH3, "_terminal_to_ask_on", lambda: False)

	code, password, err, line = run("-p", "-", "127.0.0.1", "true")

	assert code == 2 and password is None and line is None
	assert "MSSH_PASSWORD" in err


@pytest.mark.parametrize("answer, code", [("", 1), (EOFError(), 1), (KeyboardInterrupt(), 130)])
def test_no_answer_runs_nothing(run, terminal, answer, code):
	# an empty password would be one failed login on every host (fail2ban)
	terminal[0].append(answer)

	assert run("-p", "-", "127.0.0.1", "true")[:2] == (code, None)


def test_mssh_password_is_used_and_not_listed(run, monkeypatch):
	monkeypatch.setenv("MSSH_PASSWORD", SECRET)

	code, password, err, line = run("127.0.0.1", "true")

	assert password == SECRET
	# a replay gets it from the environment again
	assert "--password" not in err and "-p=" not in line and "S3cret" not in err + line


def test_the_command_line_wins_over_mssh_password(run, monkeypatch):
	monkeypatch.setenv("MSSH_PASSWORD", "from-env")

	assert run("-p", SECRET, "127.0.0.1", "true")[1] == SECRET


def test_mssh_password_wins_over_the_config(run, monkeypatch):
	monkeypatch.setattr(multiSSH3, "DEFAULT_PASSWORD", "from-config")
	monkeypatch.setenv("MSSH_PASSWORD", "from-env")

	assert run("127.0.0.1", "true")[1] == "from-env"


def test_the_config_password_is_used_without_mssh_password(run, monkeypatch):
	monkeypatch.setattr(multiSSH3, "DEFAULT_PASSWORD", "from-config")
	monkeypatch.delenv("MSSH_PASSWORD", raising=False)

	code, password, err, line = run("127.0.0.1", "true")

	assert password == "from-config" and "from-config" not in err + line


def test_a_password_given_to_the_module_is_not_recorded(tmp_path, monkeypatch):
	monkeypatch.setattr(multiSSH3, "processRunOnHosts", lambda **kwargs: None)
	monkeypatch.setattr(multiSSH3, "getIP", lambda hostname, local=False: hostname)
	history = tmp_path / "history"

	multiSSH3.run_command_on_hosts("127.0.0.1", ["true"], password=SECRET, no_history=False, history_file=str(history),
		called=True, quiet=True)

	line = history.read_text()
	assert "S3cret" not in line and "-p=-" in line.split("\t")[2].split()


def test_the_shown_command_line_never_has_the_password():
	assert "S3cret" not in multiSSH3.getStrCommand(hosts="node1", commands=["true"], password=SECRET)
