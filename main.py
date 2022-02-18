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

def format_highlight(text, color, other_color=Fore.LIGHTBLACK_EX):
    if text:
        return re.sub(rf'(\w+)(\W*)', rf'{color}\1{other_color}\2', text) + Style.RESET_ALL

class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.ports = []
        
    def get_vendor(self):
        if hasattr(self, 'vendor'):
            return self.vendor
        
        matches = list(filter(self.mac.upper().startswith, mac_prefixes))
        if len(matches) > 0:
            self.vendor =  mac_prefixes[max(matches, key=len)]  # Return longest match
        else:
            self.vendor = None
        
        return self.vendor
    
    def get_hostname(self):
        if hasattr(self, 'hostname'):
            return self.hostname
        
        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:  # If not found
            self.hostname = None
        
        return self.hostname
        
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
            
    def summary(self):  # JSON summary
        data = {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.get_vendor()
        }
        if ARGS.hostname and self.hostname:
            data["hostname"] = self.hostname
        if ARGS.ports:
            data["ports"] = self.ports
            
        return data
    
    def __str__(self):
        result = ""
        attributes = {
            "Hostname": self.hostname,
            "Ports": format_highlight(', '.join(str(p) for p in self.ports), Fore.LIGHTBLUE_EX),
        }
        vendor_str = " => " + self.get_vendor() if self.get_vendor() else ""
        ip = format_highlight(self.ip, Fore.LIGHTWHITE_EX)
        mac = format_highlight(self.mac, Fore.YELLOW)
        
        result += f"{Fore.GREEN}⬤ {Style.RESET_ALL} Host {Style.BRIGHT}{ip}{Style.RESET_ALL} is up " + " "*(15-len(self.ip)) + \
            f"{Fore.LIGHTBLACK_EX}({Fore.YELLOW}{mac}{Style.RESET_ALL}{vendor_str}{Fore.LIGHTBLACK_EX}){Style.RESET_ALL}"
        
        # Filter out empty attributes
        attributes = {k: v for k, v in attributes.items() if v}
        
        items = list(attributes.items())
        for attribute, value in items:
            if (attribute, value) != items[-1]:
                result += f"\n     {Fore.LIGHTBLACK_EX}┣╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}{attribute}: {Fore.LIGHTBLUE_EX}{value}{Style.RESET_ALL}"
            else:  # If last attribute
                result += f"\n     {Fore.LIGHTBLACK_EX}┗╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}{attribute}: {Fore.LIGHTBLUE_EX}{value}{Style.RESET_ALL}"

        return result
        

# Print start time
current_time = datetime.datetime.now()
print_(f"Started scan of {Style.BRIGHT}{Fore.LIGHTBLUE_EX}{ARGS.network}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

# Scan using ARP Ping
print_(Fore.LIGHTBLACK_EX, end="")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ARGS.network), timeout=2, verbose=(not ARGS.json))
print_(Style.RESET_ALL, end="")

# Save hosts
for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))



# Find hostnames
if ARGS.hostname:
    threads = []
    print_(f"{Fore.LIGHTBLACK_EX}Finding hostnames...{Style.RESET_ALL}")  # TODO: Progress bar
    for host in up_hosts:
        t = Thread(target=host.get_hostname)
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
for host in up_hosts:
    print_(host)
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
        data = host.summary()
        output["up_hosts"].append(data)
    
    return json.dumps(output, indent=4)

if ARGS.output:
    print_(f"Results saved to {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}")
    with ARGS.output as f:
        f.write(to_json())
        
if ARGS.json:
    print(to_json())
