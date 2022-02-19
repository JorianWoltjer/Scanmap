from colorama import Fore, Style
from threading import Thread
import socket
import nmap
import json
import re

# Load mac prefixes for vendor lookup
with open("data/mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)

# Time to wait for a response from a host (default = 0.2 seconds)
def set_timeout(timeout):
    socket.setdefaulttimeout(timeout)

# Format seperated text with color with ANSI escape codes
def format_highlight(text, color, other_color=Fore.LIGHTBLACK_EX):
    return re.sub(rf'(\w+)(\W*)', rf'{color}\1{other_color}\2', text) + Style.RESET_ALL

# Class for storing and analysing hosts found to be up
class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.vendor = self.get_vendor()
        self.hostname = None
        self.os = None
        self.ports = []

    # Get vendor from mac address using mac-prefix-table.json
    def get_vendor(self):
        matches = list(filter(self.mac.upper().startswith, mac_prefixes))
        if len(matches) > 0:  # Return longest match if found
            return mac_prefixes[max(matches, key=len)]

    # Get hostname from IP using sockets
    def get_hostname(self):
        if self.hostname: return self.hostname

        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:  # If not found
            self.hostname = None

        return self.hostname

    # Get OS information using nmap
    def get_os(self):
        if self.os: return self.os

        nm = nmap.PortScanner()
        ports = ",".join(str(p) for p in self.ports)
        result = nm.scan(self.ip, ports, arguments="-n -O")  # Arguments: -n = no DNS, -O = OS detection
        try:
            match = result['scan'][self.ip]['osmatch'][0]
            self.os = {"name": match['name'], "accuracy": match['accuracy']}  # Only store name and accuracy
        except (KeyError, IndexError):  # If not found
            self.os = None

        return self.os

    # Scan TCP ports on host
    def scan_ports(self, ports_to_scan):
        for port in ports_to_scan:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((self.ip, port))  # Try to connect to port
            s.close()

            if result == 0:  # If port is open
                self.ports.append(port)

    # Scan TCP ports with threading
    def scan_ports_fast(self, ports_to_scan, threads):
        """
        Splits ports_to_scan into chunks, and runs scan_ports() on each chunk in a thread. 
        Example (ports_to_scan: range(1, 1000), threads: 10):
            Port chunks: [range(1, 100), range(100, 200), range(200, 300), ..., range(900, 1000)]
        """
        chunk_size = len(ports_to_scan) // threads + 1  # Size devided by number of threads, rounded up
        thread_list = []
        for i in range(threads):
            start = i * chunk_size
            end = start + chunk_size
            t = Thread(target=self.scan_ports, args=(ports_to_scan[start:min(end, len(ports_to_scan))],))
            thread_list.append(t)
            t.start()

        for t in thread_list:  # Wait for all threads to finish
            t.join()

    # Gives a list of all attributes of the host (used for JSON)
    def summary(self, ARGS):
        data = self.__dict__
        data = {k: v for k, v in data.items() if k in ["ip", "mac", "vendor"] or ARGS.__dict__[k]}  # Filter out not scanned attributes
        return data

    # Get formatted string of host information
    def __str__(self):
        result = ""
        attributes = {  # Attributes displayed below host
            "Hostname": self.hostname,
            "Operating System": f"{self.os['name']} {Fore.LIGHTWHITE_EX}({self.os['accuracy']}%)" if self.os else None,
            "Ports": format_highlight(', '.join(str(p) for p in self.ports), Fore.LIGHTBLUE_EX) if self.ports else None,
        }
        vendor_str = " => " + self.vendor if self.vendor else ""  # Add vendor if found (with arrow)
        ip = format_highlight(self.ip, Fore.LIGHTWHITE_EX)
        mac = format_highlight(self.mac, Fore.YELLOW)

        # Main host information
        result += f"{Fore.GREEN}⬤ {Style.RESET_ALL} Host {Style.BRIGHT}{ip}{Style.RESET_ALL} is up " + " "*(15-len(self.ip)) + \
            f"{Fore.LIGHTBLACK_EX}({Fore.YELLOW}{mac}{Style.RESET_ALL}{vendor_str}{Fore.LIGHTBLACK_EX}){Style.RESET_ALL}"

        # Filter out empty attributes
        attributes = {k: v for k, v in attributes.items() if v}

        # Attributes below host, found during scan
        items = list(attributes.items())
        for attribute, value in items:
            if (attribute, value) != items[-1]:
                result += f"\n     {Fore.LIGHTBLACK_EX}┣╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}{attribute}: {Fore.LIGHTBLUE_EX}{value}{Style.RESET_ALL}"
            else:  # If last attribute
                result += f"\n     {Fore.LIGHTBLACK_EX}┗╸{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}{attribute}: {Fore.LIGHTBLUE_EX}{value}{Style.RESET_ALL}"

        return result
