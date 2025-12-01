import yaml
from collections import defaultdict

with open("configs/honeypots.yaml", "r") as f:
    config = yaml.safe_load(f)

ips = defaultdict(list)
macs = defaultdict(list)
ports = defaultdict(list)

for h in config["honeypots"]:
    ips[h["ip"]].append(h["name"])
    macs[h["mac"]].append(h["name"])

for ip, names in ips.items():
    if len(names) > 1:
        print("Duplicate IPs:" f"  {ip}: {names}")

for mac, names in macs.items():
    if len(names) > 1:
        print("Duplicate MACs:" f"  {mac}: {names}")
