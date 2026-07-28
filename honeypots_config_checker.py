# =================================================
# Validates honeypots.yaml to ensure there are no |
# port conflicts, duplicate MAC/IP addresses, or  |
# other network configuration conflicts between   |
# honeypot instances.                             |
# =================================================

import yaml
import sys
import os
from collections import defaultdict
from yaml.error import YAMLError

ERROR = "[\033[31m!\033[0m] \033[31mERROR:\033[0m "
INFO  = "[\033[35m*\033[0m] \033[35mINFO:\033[0m "
    
ips = defaultdict(list)
macs = defaultdict(list)
name_map = defaultdict(list)

errors = False
PROJECT_ROOT = os.environ.get('PROJECT_ROOT')

def load_yaml(path):
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"{ERROR}Config file '{path}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"{ERROR}No permission to read '{path}'")
        sys.exit(1)
    except YAMLError as e:
        print(f"{ERROR}YAML syntax error in '{path}':")
        print(f"    {e}")
        sys.exit(1)

    if data is None:
        print(f"{ERROR}YAML file '{path}' is empty")
        sys.exit(1)

    if not isinstance(data, dict):
        print(f"{ERROR}Top-level YAML structure must be a mapping (dict)")
        sys.exit(1)

    return data

config_path = os.path.join(PROJECT_ROOT, "configs", "honeypots.yaml")
config = load_yaml(config_path)
# -----------------------------
# IP and MAC uniqueness
# -----------------------------
for honeypot in config["honeypots"]:
    name_map[honeypot["name"]].append(honeypot)

for name, entries in name_map.items():
    if len(entries) > 1:
        print(f"{ERROR}Duplicate honeypot name '{name}' found "
              f"{len(entries)} times.")
        errors = True
        
for honeypot in config["honeypots"]:
    ips[honeypot["ip"]].append(honeypot["name"])
    macs[honeypot["mac"]].append(honeypot["name"])

for ip, names in ips.items():
    if len(names) > 1:
        print(f"{ERROR}Duplicate IP address {ip} used by honeypots: {names}")
        errors = True

for mac, names in macs.items():
    if len(names) > 1:
        print(f"{ERROR}Duplicate MAC address {mac} used by honeypots: {names}")
        errors = True

# -----------------------------
# Port uniqueness per honeypot
# -----------------------------
for h in config["honeypots"]:
    port_map = defaultdict(list)

    for service in h.get("services", []):
        port_map[service["port"]].append(service["name"])

    for port, services in port_map.items():
        if len(services) > 1:
            print(f"{ERROR}Duplicate port {port} in honeypot '{h['name']}': "
                f"used by services {services}"
            )
            errors = True

# -----------------------------
# Final result
# -----------------------------
if errors:
    print(f"{ERROR}Configuration validation FAILED.")
    exit(1)
else:
    print(f"{INFO}config/honeypots.yaml validation OK.")
