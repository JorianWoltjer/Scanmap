import argparse

parser = argparse.ArgumentParser()
parser.add_argument("network", help="network to scan, or single host (ex. 192.168.1.0/24 or 192.168.1.42)")
parser.add_argument('-p', '--ports', help="ports to scan for all hosts. 'top', 'all', or a comma-separated list (ex. 22,80,443)")
parser.add_argument('-o', '--output', help="save output to file in JSON format", type=argparse.FileType('w', encoding='UTF-8'))
parser.add_argument('--json', help="output to stdout in JSON format", action="store_true")
ARGS = parser.parse_args()

from scapy.all import srp, ARP, Ether
from colorama import Fore, Style
from pyfiglet import print_figlet
import datetime
import time
import json
import random

def print_(*args, **kwargs):
    if not ARGS.json:
        print(*args, **kwargs)

# Header
if not ARGS.json: print_figlet("Scanmap", font="slant", colors="LIGHT_RED")
print_("© 2022 Jorian Woltjer & Giovanni Aramu - All rights reserved")
print_()

start_time = time.time()
up_hosts = []

with open("mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)

class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.ports = [random.randrange(1, 1024) for i in range(random.randrange(1, 10))]
        
    def find_vendor(self):
        if hasattr(self, 'vendor'):
            return self.vendor
        
        for prefix in mac_prefixes:
            if self.mac.upper().startswith(prefix):
                self.vendor = mac_prefixes[prefix]
                return self.vendor
            
# print start time
current_time = datetime.datetime.now()
print_(f"Started scan of {Fore.LIGHTBLUE_EX}{ARGS.network}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

# Scan using ARP Ping
print_(Fore.LIGHTBLACK_EX, end="")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ARGS.network), timeout=2, verbose=(not ARGS.json))
print_(Style.RESET_ALL, end="")

# Save up hosts
for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))

# print results
print_(f"{Style.BRIGHT}Results:{Style.RESET_ALL}")
for i, host in enumerate(up_hosts):
    vendor = host.find_vendor()
    vendor = " => " + vendor if vendor else ""
    ip = f"{host.ip:15}".replace(".", f"{Fore.LIGHTBLACK_EX}.{Fore.WHITE}")
    mac = host.mac.replace(":", f"{Fore.LIGHTBLACK_EX}:{Fore.YELLOW}")
    
    print_(f"{Fore.GREEN}⬤{Style.RESET_ALL}  Host {Style.BRIGHT}{ip}{Style.RESET_ALL} is {Fore.LIGHTGREEN_EX}up{Style.RESET_ALL} " + \
        f"{Fore.LIGHTBLACK_EX}({Fore.YELLOW}{mac}{Style.RESET_ALL}{vendor}{Fore.LIGHTBLACK_EX}){Style.RESET_ALL}")
    
    ports_str = (Fore.LIGHTBLACK_EX+', ').join([Fore.LIGHTBLUE_EX+str(p) for p in host.ports])
    print_(f"     {Fore.LIGHTBLACK_EX}┗╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Ports{Style.RESET_ALL}: {ports_str}{Style.RESET_ALL}")
print_()

# print statistics
total = len(answered) + len(unanswered)
print_(f"Found {Style.BRIGHT}{len(up_hosts)}{Style.RESET_ALL} out of {Fore.LIGHTWHITE_EX}{total}{Style.RESET_ALL} hosts are up")

duration = round(time.time() - start_time, 2)
print_(f"Finished in {Fore.LIGHTWHITE_EX}{duration}{Style.RESET_ALL} seconds")

# JSON
def to_json():
    output = {
        "network": ARGS.network,
        "start_time": int(current_time.timestamp()),
        "duration": duration,
        "total_scanned": total,
        "up_hosts": []
    }
        
    for host in up_hosts:
        output["up_hosts"].append({
            "ip": host.ip,
            "mac": host.mac,
            "vendor": host.find_vendor()
        })
    
    return json.dumps(output, indent=4)

if ARGS.output:
    print_(f"Results saved to {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}")
    with ARGS.output as f:
        f.write(to_json())
        
if ARGS.json:
    print(to_json())
