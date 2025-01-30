import multiSSH3		
import time

print(multiSSH3.compact_hostnames(frozenset([f'PC{i}-{j:03d}' for i in range(8,11) for j in range(1, 3) ])))

# bigZeroPaddedHosts = frozenset([f'PC{i:02d}-{j:02d}' for i in range(1, 200) for j in range(1, 3102)] + ['3-3PC','nebulamaster'])
# print(f'len of bigZeroPaddedHosts: {len(bigZeroPaddedHosts)}')
# startTime = time.perf_counter()
# print(compact_hostnames(bigZeroPaddedHosts))
# print(f'Time: {time.perf_counter() - startTime}')

# hugeHosts = frozenset([f'PC{i}-{j:03d}-{k:05d}' for i in range(3, 40) for j in range(1, 50) for k in range(1, 100)] + ['3-3-3PC','nebulamaster'])
# print(f'len of hugeHosts: {len(hugeHosts)}')
# startTime = time.perf_counter()
# print(compact_hostnames(hugeHosts))
# print(f'Time: {time.perf_counter() - startTime}')

# # %%
# hugeHosts = frozenset([f'PC{i:01d}-{j:03d}-{k:03d}' for i in range(1, 100) for j in range(1, 50) for k in range(1, 100) if j != 8 if i != 35] + ['3-3-3PC','nebulamaster'])
# startTime = time.perf_counter()
# print(f'len of skipping hugerHosts: {len(hugeHosts)}')
# print(compact_hostnames(hugeHosts))
# print(f'Time: {time.perf_counter() - startTime}')


ipRangeHosts = frozenset([f'10.{i}.{j}.{k}' for i in range(6, 13) for j in range(100, 255) for k in range(1, 255)] +[f'192.168.{j}.{k}' for k in range(100, 200) for j in range(1, 255) ]+ ['localhost'])
print(f'len of ipRangeHosts: {len(ipRangeHosts)}')
startTime = time.perf_counter()
print(multiSSH3.compact_hostnames(ipRangeHosts))
print(f'Time: {time.perf_counter() - startTime}')

