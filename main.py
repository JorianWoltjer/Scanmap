import argparse
import sys

# Parse arguments, before loading any other modules
parser = argparse.ArgumentParser()
parser.add_argument("network", help="'auto' for automatic detection, subnet, or single host (ex. 192.168.1.0/24 or 192.168.1.42)")
parser.add_argument("-a", "--all", help="enable all options, try to find everything", action="store_true")
parser.add_argument('-p', '--ports', required="--os" in " ".join(sys.argv), help="ports to scan for all found hosts. 'top', 'all', a range (ex. 1-1024), or a comma-separated list (ex. 22,80,443)")
parser.add_argument('-o', '--output', help="save output to file in JSON format", type=argparse.FileType('w', encoding='UTF-8'))
parser.add_argument('-n', '--hostname', help="get hostname for all found hosts", action='store_true')
parser.add_argument('-t', '--timeout', help="timeout for socket connections (in seconds)", type=float, default=0.2)
parser.add_argument('-T', '--threads', help="number of threads to use for port scanning", type=int, default=10)
parser.add_argument('--os', help="scan for operating system on all found hosts (requires ports)", action="store_true")
parser.add_argument('--json', help="output to stdout in JSON format", action="store_true")
ARGS = parser.parse_args()

from scapy.all import srp, ARP, Ether  # Sending ARP requests
from colorama import Fore, Style  # Printing colors
from pyfiglet import print_figlet  # Printing ascii art header
from threading import Thread  # Threading to improve performance
import datetime 
import time
import json
import re

from host import Host, set_timeout

# Overwrite print function, to not print during JSON output
def print_(*args, **kwargs):
    if not ARGS.json:
        print(*args, **kwargs)

# Convert string to list of ports
def parse_ports(s):
    if s == "all":  # All ports
        return range(1, 65536)
    elif s == "top":  # Top 100 ports
        with open("data/tcp-top100.txt") as f:
            return [int(port) for port in f.read().splitlines()]
    elif re.fullmatch("\d+-\d+", s):  # Range of ports
        a, b = s.split("-")
        return range(int(a), int(b) + 1)
    elif re.fullmatch("\d+(,\d+)*", s):  # Comma-separated list of ports
        return [int(port) for port in s.split(",")]
    else:
        parser.error(f"Invalid --ports range or list: {s}")

# Convert ip and subnet mask to CIDR notation
def to_subnet(ip, mask):
    import ipaddress
    
    cidr = sum([bin(int(x)).count('1') for x in mask.split('.')])  # Count bits
    return str(ipaddress.ip_network(f"{ip}/{cidr}", strict=False))  # Convert to network range

# Automatically find subnet from interfaces
def auto_get_subnet():
    import netifaces

    gateway = netifaces.gateways()['default'][netifaces.AF_INET]
    interface = netifaces.ifaddresses(gateway[1])
    info = interface[netifaces.AF_INET][0]

    return to_subnet(info['addr'], info['netmask'])

# Run function for each host in a thread
def do_all_threaded(target, *args):
    threads = []
    for host in up_hosts:
        t = Thread(target=target, args=(host,) + args)
        threads.append(t)
        t.start()
    
    for t in threads:  # Wait for all threads to finish
        t.join()

# Initialize
start_time = time.time()
up_hosts = []
set_timeout(ARGS.timeout)

# Parse arguments
if ARGS.ports:  # Parse string to list of ports
    ARGS.ports = parse_ports(ARGS.ports)
if ARGS.network == "auto":  # Automatically find subnet
    ARGS.network = auto_get_subnet()
if ARGS.all:  # Enable all options
    if not ARGS.ports:
        ARGS.ports = parse_ports("top")
    ARGS.os = True
    ARGS.hostname = True

# Header
if not ARGS.json: print_figlet("Scanmap", font="slant", colors="LIGHT_RED")
print_("© 2022 Jorian Woltjer & Giovanni Aramu - All rights reserved")
print_()

def small_list(l):
    l = [str(x) for x in l]
    return " ".join(l[:3]) + "..." + " ".join(l[-3:]) if len(l) > 6 else " ".join(l)

# Start info
current_time = datetime.datetime.now()
print_(f"Started scan of {Style.BRIGHT}{Fore.LIGHTBLUE_EX}{ARGS.network}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
# Print options
print_(f"{Fore.LIGHTBLACK_EX} ┣╸{Style.RESET_ALL} Ports: {Fore.LIGHTWHITE_EX}{small_list(ARGS.ports)}{Style.RESET_ALL}") if ARGS.ports else None
print_(f"{Fore.LIGHTBLACK_EX} ┣╸{Style.RESET_ALL} Output file: {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}") if ARGS.output else None
print_(f"{Fore.LIGHTBLACK_EX} ┣╸{Style.RESET_ALL} OS scan: {Fore.LIGHTWHITE_EX}enabled{Style.RESET_ALL}") if ARGS.os else None
print_(f"{Fore.LIGHTBLACK_EX} ┣╸{Style.RESET_ALL} Hostname scan: {Fore.LIGHTWHITE_EX}enabled{Style.RESET_ALL}") if ARGS.hostname else None
print_(f"{Fore.LIGHTBLACK_EX} ┣╸{Style.RESET_ALL} Threads: {Fore.LIGHTWHITE_EX}{ARGS.threads}{Style.RESET_ALL}")
print_(f"{Fore.LIGHTBLACK_EX} ┗╸{Style.RESET_ALL} Timeout: {Fore.LIGHTWHITE_EX}{ARGS.timeout}s{Style.RESET_ALL}")

# Scan using ARP Ping
print_(Fore.LIGHTBLACK_EX, end="")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ARGS.network), timeout=2, verbose=(not ARGS.json))
print_(Style.RESET_ALL, end="")

for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))

# Find hostnames (threaded)
if ARGS.hostname:
    print_(f"{Fore.LIGHTBLACK_EX}Finding hostnames... (± 10s){Style.RESET_ALL}")
    do_all_threaded(Host.get_hostname)

# Scan ports (threaded)
if ARGS.ports:
    estimate = round((len(ARGS.ports) * ARGS.timeout) / ARGS.threads, 1)
    print_(f"{Fore.LIGHTBLACK_EX}Scanning ports... (± {estimate}s){Style.RESET_ALL}")
    do_all_threaded(Host.scan_ports_fast, ARGS.ports, ARGS.threads)

# Operating system detection (threaded)
if ARGS.os:
    estimate = max(len(host.ports) for host in up_hosts)*1.5  # 1.5 = average time to scan 1 port
    print_(f"{Fore.LIGHTBLACK_EX}Detecting operating systems... (± {estimate}s){Style.RESET_ALL}")
    do_all_threaded(Host.get_os)

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

# JSON output
def to_json():
    output = {  # Main options
        "network": ARGS.network,
        "start_time": int(current_time.timestamp()),
        "duration": duration,
        "total_scanned": total,
        "up_hosts": []
    }
    
    for host in up_hosts:
        data = host.summary(ARGS)  # Get summary of attributes for all hosts
        output["up_hosts"].append(data)
    
    return json.dumps(output, indent=4)

if ARGS.output:  # Output to file
    print_(f"Results saved to {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}")
    with ARGS.output as f:
        f.write(to_json())
        
if ARGS.json:  # Output to stdout
    print(to_json())
