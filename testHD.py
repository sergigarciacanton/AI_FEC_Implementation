import psutil

hdd = psutil.disk_usage('/')

print ("Total: ", hdd.total / (2**30))
print ("Used: ", hdd.used / (2**30))
print ("Free: ", hdd.free / (2**30))
