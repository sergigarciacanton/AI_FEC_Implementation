import subprocess
result = subprocess.run(['ping', '-c', '1', '147.83.118.1'], stdout = subprocess.PIPE)
splitted = str(result.stdout).split("/")
#print(result.stdout.decode('utf-8'))
print(type(float(splitted[4])))
