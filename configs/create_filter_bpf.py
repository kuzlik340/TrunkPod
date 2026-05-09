#!/usr/bin/env python3
"""
gen_bpf_filter.py  <honeypots.yaml>

Reads a honeypots YAML file and prints a C #define BPF_FILTER block
ready to paste into traffic_parser.c.

YAML format:
    honeypots:
      - ip: 10.0.100.193
        mac: 02:1a:2b:3c:4d:01
      - ip: 10.0.110.58
        mac: 02:1a:2b:3c:4d:03
"""

import sys
import yaml


def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} honeypots.yaml", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    honeypots = data.get("honeypots", [])
    ips  = uniq(hp["ip"].strip()          for hp in honeypots if hp.get("ip"))
    macs = uniq(hp["mac"].strip().lower() for hp in honeypots if hp.get("mac"))

    parts = []

    # One "ether dst <mac>" clause per honeypot MAC
    for mac in macs:
        parts.append(f"(ether dst {mac})")

    # IP: BPF requires "dst host X" per atom — "dst (host A or host B)" is invalid
    if ips:
        ip_inner = " or ".join(f"dst host {ip}" for ip in ips)
        ip_expr  = ip_inner if len(ips) == 1 else f"({ip_inner})"
        parts.append(f"(ip and {ip_expr})")

        # ARP: BPF has no "arp dst host" qualifier; use plain "host" which matches
        # both sender and target protocol address fields in the ARP payload
        arp_inner = " or ".join(f"host {ip}" for ip in ips)
        arp_expr  = arp_inner if len(ips) == 1 else f"({arp_inner})"
        parts.append(f"(arp and {arp_expr})")

    if not parts:
        print("/* WARNING: no honeypots found — empty filter */", file=sys.stderr)
        print('#define BPF_FILTER ""')
        sys.exit(0)

    # Print as a C multi-line #define
    print("#define BPF_FILTER \\")
    for i, part in enumerate(parts):
        is_last = (i == len(parts) - 1)
        sep  = ""   if is_last else " or "
        cont = ""   if is_last else " \\"
        print(f'"{part}{sep}"{cont}')


if __name__ == "__main__":
    main()