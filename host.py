from colorama import Fore, Style
from threading import Thread
import socket
import nmap
import json
import re

# default timer per socket faster is better for scanning time
socket.setdefaulttimeout(0.2)

# Opening joson mac prefix database  
with open("data/mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)


def format_highlight(text, color, other_color=Fore.LIGHTBLACK_EX):
    return re.sub(rf'(\w+)(\W*)', rf'{color}\1{other_color}\2', text) + Style.RESET_ALL   

# Class for object storage per host that has been detected as up 
class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.vendor = None
        self.hostname = None
        self.os = None
        self.ports = []
        # self.applications
        # self.services
        
    def get_vendor(self):
        if self.vendor: return self.vendor
        
        matches = list(filter(self.mac.upper().startswith, mac_prefixes))
        if len(matches) > 0:
            self.vendor =  mac_prefixes[max(matches, key=len)]  # Return longest match
        else:
            self.vendor = None
        
        return self.vendor
    # Grabs the hostname from the found host
    def get_hostname(self):
        if self.hostname: return self.hostname
        
        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:  # If not found
            self.hostname = None
        
        return self.hostname
    
    # Grabs the OS from the found host
    def get_os(self):
        if self.os: return self.os
        
        nm = nmap.PortScanner()
        result = nm.scan(self.ip, ','.join(str(p) for p in self.ports), arguments="-n -O")
        try:
            self.os = result['scan'][self.ip]['osmatch'][0]
        except (KeyError, IndexError):
            self.os = None
        
        return self.os

    # scans the ports on TCP status    
    def scan_ports(self, ports_to_scan):
        for port in ports_to_scan:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((self.ip, port))
            s.close()
            
            if result == 0:
                self.ports.append(port)
    
    # scans the ports through multithreading on TCP status              
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
    
    #  summary function which captures all class object data      
    def summary(self, ARGS):  # JSON summary
        data = {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.get_vendor()
            # "os": self.os   
            # "ports": self.ports
        }
        if ARGS.hostname:
            data["hostname"] = self.hostname
        if ARGS.ports:
            data["ports"] = self.ports
        
        return data
    
    # constructor object for the network scan
    def __str__(self):
        result = ""
        attributes = {
            "Hostname": self.hostname,
            "Operating System": f"{self.os['name']} {Fore.LIGHTWHITE_EX}({self.os['accuracy']}%)" if self.os else None,
            "Ports": format_highlight(', '.join(str(p) for p in self.ports), Fore.LIGHTBLUE_EX) if self.ports else None,
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
