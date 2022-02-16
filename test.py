import json

with open("mac-prefix-table.json") as f:
    mac_prefixes = json.load(f)

mac = "00:50:56:a0:13:78"

def find_vendor(mac):
    for prefix in mac_prefixes:
        if mac.upper().startswith(prefix):
            return mac_prefixes[prefix]


print(find_vendor(mac))
