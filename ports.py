import socket
import time
import threading

TARGET = "192.168.3.34"
socket.setdefaulttimeout(0.1)

def scan(ip, min, max):
    for port in range(min, max):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        s.close()
        
        # print(f"Result {port} = {result}")
        
        if result == 0:
            print("Port {} is open".format(port))

start = time.time()

threads = []
for i in range(10):
    t = threading.Thread(target=scan, args=(TARGET, 100*i, 100*(i+1)))
    t.start()
    threads.append(t)
    
for t in threads:
    t.join()

end = time.time()

print(f"Scan took {end - start} seconds")
