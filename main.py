import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("network", help="network to scan, or single host (ex. 192.168.1.0/24 or 192.168.1.42)")
parser.add_argument('-p', '--ports', required="--os" in " ".join(sys.argv), help="ports to scan for all found hosts. 'top', 'all', a range (ex. 1-1024), or a comma-separated list (ex. 22,80,443)")
parser.add_argument('-o', '--output', help="save output to file in JSON format", type=argparse.FileType('w', encoding='UTF-8'))
parser.add_argument('-n', '--hostname', help="get hostname for all found hosts", action='store_true')
parser.add_argument('-t', '--threads', help="number of threads to use for port scanning", type=int, default=10)
parser.add_argument('--os', help="scan for operating system on all found hosts", action="store_true")
parser.add_argument('--json', help="output to stdout in JSON format", action="store_true")
ARGS = parser.parse_args()

from scapy.all import srp, ARP, Ether
from colorama import Fore, Style
from pyfiglet import print_figlet
from threading import Thread
import datetime
import time
import json
import re

from host import Host

def print_(*args, **kwargs):
    if not ARGS.json:
        print(*args, **kwargs)

# Header
if not ARGS.json: print_figlet("Scanmap", font="slant", colors="LIGHT_RED")
print_("© 2022 Jorian Woltjer & Giovanni Aramu - All rights reserved")
print_()

def parse_ports(s):
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

def do_all_threaded(target, *args):
    threads = []
    for host in up_hosts:
        t = Thread(target=target, args=(host,) + args)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

# Initialize
start_time = time.time()
up_hosts = []

if ARGS.ports:
    ARGS.ports = parse_ports(ARGS.ports)

# Start info
current_time = datetime.datetime.now()
print_(f"Started scan of {Style.BRIGHT}{Fore.LIGHTBLUE_EX}{ARGS.network}{Style.RESET_ALL} at {Fore.LIGHTWHITE_EX}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
# TODO: Echo options here

# Scan using ARP Ping
print_(Fore.LIGHTBLACK_EX, end="")
answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ARGS.network), timeout=2, verbose=(not ARGS.json))
print_(Style.RESET_ALL, end="")

# Save hosts
for host in answered.res:
    up_hosts.append(Host(host[1].psrc, host[1].hwsrc))

# Find hostnames (threaded)
if ARGS.hostname:
    print_(f"{Fore.LIGHTBLACK_EX}Finding hostnames...{Style.RESET_ALL}")  # TODO: Progress bar, or estimate
    do_all_threaded(Host.get_hostname)

# Scan ports (threaded)
if ARGS.ports:
    print_(f"{Fore.LIGHTBLACK_EX}Scanning ports...{Style.RESET_ALL}")  # TODO: Progress bar, or estimate
    do_all_threaded(Host.scan_ports_fast, ARGS.ports, ARGS.threads)

# Operating system detection (threaded)
if ARGS.os:
    print_(f"{Fore.LIGHTBLACK_EX}Detecting operating systems...{Style.RESET_ALL}")  # TODO: Progress bar, or estimate
    do_all_threaded(Host.get_os)

# Results
print_(f"{Style.BRIGHT}Results:{Style.RESET_ALL}")
for host in up_hosts:
    print_(host)
print_()

# Statistics
total = len(answered) + len(unanswered)
print_(f"Found {Style.BRIGHT}{len(up_hosts)}{Style.RESET_ALL} out of {Fore.LIGHTWHITE_EX}{total}{Style.RESET_ALL} hosts are up")

duration = round(time.time() - start_time, 2)
print_(f"Finished in {Fore.LIGHTWHITE_EX}{duration}{Style.RESET_ALL} seconds")

# JSON output
def to_json():
    output = {
        "network": ARGS.network,
        "start_time": int(current_time.timestamp()),
        "duration": duration,
        "total_scanned": total,
        "up_hosts": []
    }
    
    for host in up_hosts:
        data = host.summary(ARGS)
        output["up_hosts"].append(data)
    
    return json.dumps(output, indent=4)

if ARGS.output:
    print_(f"Results saved to {Fore.LIGHTWHITE_EX}{ARGS.output.name}{Style.RESET_ALL}")
    with ARGS.output as f:
        f.write(to_json())
        
if ARGS.json:
    print(to_json())
