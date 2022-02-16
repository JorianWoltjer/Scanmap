import json

with open("mac-vendors-export.json", encoding="utf8") as f:
    mac_vendors = json.load(f)

new_list = {}

for item in mac_vendors:
    new_list[item["macPrefix"]] = item["vendorName"]
    
# print(new_list)
json.dump(new_list, open("mac-vendors-export-new.json", "w"))
