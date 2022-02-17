import nmap

scanner = nmap.PortScanner()

ip_addr = '192.168.3.34'
print(scanner.scan(ip_addr, arguments="-O")['scan'][ip_addr]['osmatch'][1])
