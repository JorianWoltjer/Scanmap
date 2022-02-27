import json

# Uses https://maclookup.app/downloads/json-database
with open("mac-vendors-export.json", encoding="utf8") as f:
    mac_vendors = json.load(f)

new_list = {}

for item in mac_vendors:
    new_list[item["macPrefix"]] = item["vendorName"]

json.dump(new_list, open("mac-prefix-table.json", "w"))
