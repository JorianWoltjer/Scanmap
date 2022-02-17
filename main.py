import argparse

parser = argparse.ArgumentParser()
parser.add_argument("network", help="network to scan, or single host (ex. 192.168.1.0/24 or 192.168.1.42)")
parser.add_argument('-p', '--ports', help="ports to scan for all found hosts. 'top', 'all', a range (ex. 1-1024), or a comma-separated list (ex. 22,80,443)")
parser.add_argument('-o', '--output', help="save output to file in JSON format", type=argparse.FileType('w', encoding='UTF-8'))
parser.add_argument('-n', '--hostname', help="get hostname for each host", action='store_true')
parser.add_argument('-t', '--threads', help="number of threads to use for port scanning", type=int, default=10)
parser.add_argument('--json', help="output to stdout in JSON format", action="store_true")
ARGS = parser.parse_args()

from scapy.all import srp, ARP, Ether
from colorama import Fore, Style
from pyfiglet import print_figlet
from threading import Thread
import socket
import datetime
import time
import json
import re

def print_(*args, **kwargs):
    if not ARGS.json:
        print(*args, **kwargs)

# Header
if not ARGS.json: print_figlet("Scanmap", font="slant", colors="LIGHT_RED")
print_("© 2022 Jorian Woltjer & Giovanni Aramu - All rights reserved")
print_()

# Initialize
start_time = time.time()
up_hosts = []
socket.setdefaulttimeout(0.2)

with open("data/mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)
    
def get_ports(s):
    if s == "all":
        return range(1, 65536)
    elif s == "top":
        with open("data/tcp-top100.txt") as f:
            return [int(port) for port in f.read().splitlines()]
    elif re.match("\d+-\d+", s):
        a, b = s.split("-")
        return range(int(a), int(b) + 1)
    elif re.match("\d+(,\d+)*", s):
        return [int(port) for port in s.split(",")]
    
if ARGS.ports:
    ARGS.ports = get_ports(ARGS.ports)

class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.ports = []
        
    def find_vendor(self):
        if hasattr(self, 'vendor'):
            return self.vendor
        
        matches = list(filter(self.mac.upper().startswith, mac_prefixes))
        if len(matches) > 0:
            return mac_prefixes[max(matches, key=len)]  # Return longest match
    
    def get_hostname(self):
        try:
            return socket.gethostbyaddr(self.ip)[0]
        except socket.herror:  # If not found
            return ""
        
    def scan_ports(self, ports_to_scan):
        for port in ports_to_scan:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((self.ip, port))
            s.close()
            
            if result == 0:
                self.ports.append(port)
                
    def scan_ports_fast(self, ports_to_scan, threads):
        chunk_size = len(ports_to_scan) // threads + 1
        thread_list = []
        for i in range(threads):
            start = i * chunk_size
            end = start + chunk_size
            t = Thread(target=self.scan_ports, args=(ports_to_scan[start:min(end, len(ports_to_scan))],))
            thread_list.append(t)
            t.start()
        
        for t in thread_list:
            t.join()
        

# Print start time
current_time = datetime.datetime.now()
print_(f"Started scan of {Style.BRIGHT}{Fore.LIGHTBLUE_EX}{ARGS.network}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

# Scan using ARP Ping
print_(Fore.LIGHTBLACK_EX, end="")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ARGS.network), timeout=2, verbose=(not ARGS.json))
print_(Style.RESET_ALL, end="")

# Save up hosts
for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))

def find_hostname(host):
    host.hostname = host.get_hostname()

# Find hostnames
if ARGS.hostname:
    threads = []
    print_(f"{Fore.LIGHTBLACK_EX}Finding hostnames...{Style.RESET_ALL}")  # TODO: Progress bar
    for host in up_hosts:
        t = Thread(target=find_hostname, args=(host,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# Scan ports
if ARGS.ports:
    print_(f"{Fore.LIGHTBLACK_EX}Scanning ports...{Style.RESET_ALL}")  # TODO: Progress bar
    threads = []
    for host in up_hosts:
        t = Thread(target=host.scan_ports_fast, args=(ARGS.ports,ARGS.threads))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

# Print results
print_(f"{Style.BRIGHT}Results:{Style.RESET_ALL}")
for i, host in enumerate(up_hosts):
    vendor = host.find_vendor()
    vendor_str = " => " + vendor if vendor else ""
    ip_len = len(host.ip)
    ip = host.ip.replace(".", f"{Fore.LIGHTBLACK_EX}.{Fore.WHITE}")
    mac = host.mac.replace(":", f"{Fore.LIGHTBLACK_EX}:{Fore.YELLOW}")
    
    print_(f"{Fore.GREEN}⬤ {Style.RESET_ALL} Host {Style.BRIGHT}{ip}{Style.RESET_ALL} is {Fore.LIGHTGREEN_EX}up{Style.RESET_ALL} " + " "*(15-ip_len) + \
        f"{Fore.LIGHTBLACK_EX}({Fore.YELLOW}{mac}{Style.RESET_ALL}{vendor_str}{Fore.LIGHTBLACK_EX}){Style.RESET_ALL}")
    
    if ARGS.hostname and host.hostname:
        print_(f"     {Fore.LIGHTBLACK_EX}┣╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Hostname{Style.RESET_ALL}: {Fore.LIGHTWHITE_EX}\"{host.hostname}\"{Style.RESET_ALL}")
    
    if len(host.ports) > 0:
        ports_str = (Fore.LIGHTBLACK_EX+', ').join([Fore.LIGHTBLUE_EX+str(p) for p in host.ports])
        print_(f"     {Fore.LIGHTBLACK_EX}┗╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Ports{Style.RESET_ALL}: {ports_str}{Style.RESET_ALL}")
print_()

# Print statistics
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
        data = {
            "ip": host.ip,
            "mac": host.mac,
            "vendor": host.find_vendor()
        }
        if ARGS.hostname and host.hostname:
            data["hostname"] = host.hostname
        if ARGS.ports:
            data["ports"] = host.ports
        
        output["up_hosts"].append(data)
    
    return json.dumps(output, indent=4)

if ARGS.output:
    print_(f"Results saved to {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}")
    with ARGS.output as f:
        f.write(to_json())
        
if ARGS.json:
    print(to_json())
