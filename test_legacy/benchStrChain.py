import textwrap
import itertools
import timeit

# Prepare a realistic test string: many lines of varying length
lines = [
    "This is a sample line of text that will be wrapped by textwrap.",
    "Short line.",
    "Another somewhat longer line that might wrap around multiple times."
]
# Repeat to get a large block
host_command = "\n".join(lines * 1000)

# Common wrapper
text_wrapper = textwrap.TextWrapper(width=40)

# 1) Original nested loops
def orig_nested():
    out = []
    for line in host_command.splitlines():
        for sub in text_wrapper.wrap(line):
            out.append(sub)
    return out

# 2) List comprehension + extend
def list_comp():
    out = []
    out.extend(
        sub
        for line in host_command.splitlines()
        for sub in text_wrapper.wrap(line)
    )
    return out

# 3) itertools.chain.from_iterable + extend
def using_chain():
    out = []
    out.extend(
        itertools.chain.from_iterable(
            text_wrapper.wrap(line)
            for line in host_command.splitlines()
        )
    )
    return out

if __name__ == "__main__":
    funcs = [orig_nested, list_comp, using_chain]
    names = ["nested", "list_comp", "chain"]
    number = 20  # how many repetitions per timing

    for name, fn in zip(names, funcs):
        # timeit.repeat returns a list of runtimes; take the fastest
        times = timeit.repeat(
            stmt=fn,
            setup="from __main__ import " + fn.__name__,
            repeat=5,
            number=number,
        )
        best = sum(times) / len(times) / number
        print(f"{name:10s}: {best*1000:8.3f} ms per run")