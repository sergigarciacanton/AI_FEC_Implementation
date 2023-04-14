import psutil
memory = psutil.virtual_memory().total / (1024.0 ** 3)
# memory = psutil.virtual_memory().free / 1024
print('MemTotal: ', int(memory), ' GB')
