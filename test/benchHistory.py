from timeit import timeit
from hist_gen import generate_history
from multiSSH3TUI import CommandSearcher   # the n‑gram index we built earlier
import time

hist = generate_history(1000000, seed=0)

# naïve scan
t_simple = timeit("['rm' in c for c in hist]", number=20000,
                  globals={"hist": hist})

starttime = time.monotonic_ns()
index = CommandSearcher(hist, k =3)
print(f'index built in {(time.monotonic_ns() - starttime) / 1e6:.3f}ms')
t_index_2 = timeit("index.search('grep')", number=20000,
                 globals={"index": index})


print(f"simple: {t_simple:.3f}s  indexed_2: {t_index_2:.3f}s")
