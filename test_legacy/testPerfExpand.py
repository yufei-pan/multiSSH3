#!/usr/bin/env python3
import multiSSH3
import time

ipRangeHosts = frozenset(['admin[1-10]@10.251.*.1-253','localhost'])
print(f'len of ipRangeHosts: {len(ipRangeHosts)}')
startTime = time.perf_counter()
results = multiSSH3.expand_hostnames(ipRangeHosts)
print(f'Time: {time.perf_counter() - startTime}')
print(len(results))
for i, result in enumerate(results.items()):
	print(result)
	if i > 10:
		break
