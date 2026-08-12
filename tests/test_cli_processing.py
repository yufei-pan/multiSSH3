import multiSSH3


def test_form_command_arg_str_common_flags():
	s = multiSSH3.__formCommandArgStr(
		scp=True,
		ipmi=True,
		json=True,
		no_watch=True,
		no_env=True,
		no_history=True,
		oneonone=True,
		gather_mode=True,
		file=["/tmp/a"],
		timeout=9,
		repeat=2,
		interval=1,
	)
	assert "--scp" in s
	assert "--ipmi" in s
	assert "--json" in s or "-j" in s
	assert "--no_watch" in s or "-q" in s
	assert "--no_env" in s
	assert "--oneonone" in s or "-11" in s
	assert "--timeout=9" in s or "-t=9" in s
	assert "--file=" in s or "-f=" in s


def test_form_command_arg_str_shortend():
	s = multiSSH3.__formCommandArgStr(shortend=True, scp=True, no_watch=True, json=True)
	assert "--scp" in s
	assert "-q" in s
	assert "-j" in s


def test_process_args_basic():
	args = multiSSH3.process_args(["127.0.0.1", "echo", "hi", "-q", "-I"])
	assert args.hosts == "127.0.0.1"
	assert args.commands == ["echo", "hi"]
	assert args.no_watch is True
	assert args.no_history is True


def test_process_commands_joins_one_word_default(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "echo", "hi"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *a, **k: "1")
	args = multiSSH3.process_commands(args)
	assert args.commands == ["echo hi"]


def test_process_commands_keeps_multiple(monkeypatch):
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "echo", "hi"])
	monkeypatch.setattr(multiSSH3, "input_with_timeout_and_countdown", lambda *a, **k: "m")
	args = multiSSH3.process_commands(args)
	assert args.commands == ["echo", "hi"]


def test_set_global_with_args():
	args = multiSSH3.get_parser().parse_args(
		["127.0.0.1", "true", "--debug", "-e", "latin-1", "-Z", "--force_truecolor", "-dt", "0.5"]
	)
	multiSSH3.set_global_with_args(args)
	assert multiSSH3.__DEBUG_MODE is True
	assert multiSSH3._encoding == "latin-1"
	assert multiSSH3.__returnZero is True
	assert multiSSH3.FORCE_TRUECOLOR is True
	assert multiSSH3.DEFAULT_DIFF_DISPLAY_THRESHOLD == 0.5


def test_generate_default_config_keys():
	args = multiSSH3.get_parser().parse_args(["127.0.0.1", "true"])
	cfg = multiSSH3.generate_default_config(args)
	assert cfg["DEFAULT_HOSTS"] == "127.0.0.1"
	assert "DEFAULT_TIMEOUT" in cfg
	assert cfg["AUTHOR"] == multiSSH3.AUTHOR
	assert "DEFAULT_IPMI_ARGS" in cfg
	assert "DEAFULT_IPMI_ARGS" not in cfg
