from scapy.all import srp, ARP, Ether
import datetime
import time
import json

start_time = time.time()

up_hosts = []

class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac

# Print date and time
current_time = datetime.datetime.now()
print(f"Started at {current_time.strftime('%Y-%m-%d %H:%M:%S')}")

# Scan using ARP Ping
print("Scanning...")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.178.0/24"), timeout=2, verbose=0)

# Save up hosts
up_hosts = [Host(response[1].psrc, response[1].src) for response in answered.res]

# Print results
print("Results:")
for i, host in enumerate(up_hosts):
    print(f"Host {host.ip} is up ({host.mac})")

# Print statistics
total = len(answered) + len(unanswered)
print(f"Found {len(up_hosts)} hosts are up out of {total}")

duration = round(time.time() - start_time, 2)
print(f"Finished in {duration} seconds")

# Save results to JSON output file
filename = f"scan_{current_time.strftime('%Y-%m-%d_%H-%M-%S')}.json"
with open(filename, "w") as f:
    output = {
        "start_time": int(current_time.timestamp()),
        "duration": duration,
        "total_scanned": total,
        "up_hosts": []
    }
    
    for host in up_hosts:
        output["up_hosts"].append({
            "ip": host.ip,
            "mac": host.mac
        })
    
    f.write(json.dumps(output, indent=4))
