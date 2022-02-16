from scapy.all import srp, ARP, Ether
from colorama import Fore, Back, Style
import datetime
import time
import json

IP_RANGE = "192.168.178.0/24"

start_time = time.time()
up_hosts = []

with open("mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)

class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        
    def find_vendor(self):
        for prefix in mac_prefixes:
            if self.mac.upper().startswith(prefix):
                return mac_prefixes[prefix]

# Print date and time
current_time = datetime.datetime.now()
print(f"Started scan of {Fore.LIGHTBLUE_EX}{IP_RANGE}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

# Scan using ARP Ping
# print(f"{Fore.LIGHTBLACK_EX}Scanning: [################################] 256/256{Style.RESET_ALL}")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP_RANGE), timeout=2, verbose=0)

# Save up hosts
for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))

# Print results
for i, host in enumerate(up_hosts):
    vendor = host.find_vendor()
    vendor = " => " + vendor if vendor else ""
    ip = f"{host.ip:15}".replace(".", f"{Fore.LIGHTBLACK_EX}.{Fore.WHITE}")
    mac = host.mac.replace(":", f"{Fore.LIGHTBLACK_EX}:{Fore.YELLOW}")
    print(f"{Fore.GREEN}⬤{Style.RESET_ALL}  Host {Style.BRIGHT}{ip}{Style.RESET_ALL} is {Fore.LIGHTGREEN_EX}up{Style.RESET_ALL} " + \
        f"{Fore.LIGHTBLACK_EX}({Fore.YELLOW}{mac}{Style.RESET_ALL}{vendor}{Fore.LIGHTBLACK_EX}){Style.RESET_ALL}")

# Print statistics
total = len(answered) + len(unanswered)
print(f"Found {Style.BRIGHT}{len(up_hosts)}{Style.RESET_ALL} out of {Fore.LIGHTWHITE_EX}{total}{Style.RESET_ALL} hosts are up")

duration = round(time.time() - start_time, 2)
print(f"Finished in {Fore.LIGHTWHITE_EX}{duration}{Style.RESET_ALL} seconds")

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
