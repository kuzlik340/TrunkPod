import yaml
from collections import defaultdict

with open("configs/honeypots.yaml", "r") as f:
    config = yaml.safe_load(f)
    
ips = defaultdict(list)
macs = defaultdict(list)

errors = False

# -----------------------------
# IP and MAC uniqueness
# -----------------------------
for h in config["honeypots"]:
    ips[h["ip"]].append(h["name"])
    macs[h["mac"]].append(h["name"])

for ip, names in ips.items():
    if len(names) > 1:
        print(f"Duplicate IP address {ip} used by honeypots: {names}")
        errors = True

for mac, names in macs.items():
    if len(names) > 1:
        print(f"Duplicate MAC address {mac} used by honeypots: {names}")
        errors = True

# -----------------------------
# Port uniqueness per honeypot
# -----------------------------
for h in config["honeypots"]:
    port_map = defaultdict(list)

    for svc in h.get("services", []):
        port_map[svc["port"]].append(svc["name"])

    for port, services in port_map.items():
        if len(services) > 1:
            print(
                f"Duplicate port {port} in honeypot '{h['name']}': "
                f"used by services {services}"
            )
            errors = True

# -----------------------------
# Final result
# -----------------------------
if errors:
    print("\nConfiguration validation FAILED.")
    exit(1)
else:
    print("Configuration validation OK.")
