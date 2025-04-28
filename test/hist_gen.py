# hist_gen.py
"""
Generate a synthetic shell-history list (~10 k lines by default).

The mix is biased toward the sort of commands that actually appear in
developer / DevOps sessions so your search benchmark behaves realistically.
Feel free to tweak the command buckets or counts.
"""

from __future__ import annotations
import random
import string
from typing import List


# --------------------------------------------------------------------------- #
def _word(min_len: int = 3, max_len: int = 10) -> str:
    """Random a-z word, useful for file- or dir-names."""
    return "".join(random.choices(string.ascii_lowercase, k=random.randint(min_len, max_len)))


def _file(ext: str | None = None) -> str:
    """Random filename with an optional extension."""
    base = _word()
    return f"{base}.{ext.lstrip('.')}" if ext else base


# --------------------------------------------------------------------------- #
def generate_history(n: int = 10_000, seed: int | None = None) -> List[str]:
    """
    Return a list of *n* synthetic shell commands.

    :param n:    number of lines to create
    :param seed: pass a value for reproducible output
    """
    if seed is not None:
        random.seed(seed)

    history: List[str] = []

    # static pools ---------------------------------------------------------- #
    git_actions   = ["status", "pull", "push", "checkout", "branch",
                     "commit -m '{}'".format(random.choice(
                         ["fix", "initial", "update", "refactor",
                          "feat: add {}".format(_word())]))]
    docker_actions = ["build .", "run busybox sh", "compose up -d",
                      "pull alpine", "push myrepo/app:latest"]
    kub_actions   = ["get pods", "logs web-{} ".format(random.randint(1, 4)),
                     "apply -f k8s/{}.yaml".format(_file("yaml")),
                     "delete pod web-{}".format(random.randint(1, 4))]
    python_actions = ["main.py", "benchmark.py", "-m unittest", "setup.py install"]
    sudo_apt      = ["update", "upgrade", "install {}".format(_word())]

    base_cmds = (
        ["git"] * 6 + ["docker"] * 4 + ["kubectl"] * 3 +
        ["python"] * 3 + ["grep", "ls", "cd", "cp", "mv", "rm",
        "curl", "wget", "ssh", "tar", "sudo", "conda", "pip"]
    )

    # generators ------------------------------------------------------------ #
    for _ in range(n):
        cmd = random.choice(base_cmds)

        if cmd == "git":
            line = f"git {random.choice(git_actions)}"
        elif cmd == "docker":
            line = f"docker {random.choice(docker_actions)}"
        elif cmd == "kubectl":
            line = f"kubectl {random.choice(kub_actions)}"
        elif cmd == "python":
            line = f"python {random.choice(python_actions)}"
        elif cmd == "grep":
            line = f"grep -R {_word().upper()} {random.choice(['src/', 'lib/', 'tests/'])}"
        elif cmd == "ls":
            line = f"ls -l {_word()}"
        elif cmd == "cd":
            line = f"cd /{'/'.join(_word() for _ in range(random.randint(1, 3)))}"
        elif cmd == "cp":
            line = f"cp {_file('txt')} /tmp/{_file()}"
        elif cmd == "mv":
            line = f"mv {_file()} {_file()}"
        elif cmd == "rm":
            line = f"rm -rf {_file()}"
        elif cmd == "curl":
            line = f"curl https://{_word()}.com/{_file()}"
        elif cmd == "wget":
            line = f"wget https://{_word()}.net/{_file('tar.gz')}"
        elif cmd == "ssh":
            line = f"ssh user@{_word()}.local"
        elif cmd == "tar":
            line = f"tar -xzf {_file('tar.gz')}"
        elif cmd == "sudo":
            line = f"sudo apt-get {random.choice(sudo_apt)}"
        elif cmd == "conda":
            line = f"conda install {_word()}"
        elif cmd == "pip":
            line = f"pip install {_word()}"
        else:                              # fallback (shouldn't happen)
            line = "echo noop"

        history.append(line)

    return history


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    hist = generate_history()           # 10 000 lines, reproducible w/ seed=
    print(len(hist), "commands generated; first 5 examples:")
    print(*hist[:5], sep="\n")
