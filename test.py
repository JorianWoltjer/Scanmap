from scapy.all import srp, ARP, Ether

IP_RANGE = "192.168.178."
# IP_RANGE = "192.168.178.0/24"

answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP_RANGE+str(i)), timeout=2)

print(answered, unanswered)

# for host in answered.res:
    # print(host[1].psrc, host[1].hwsrc)
