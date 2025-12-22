#!/bin/bash

# ==============================================
# Module that checks if desired IPs are not    |
# already in use in the network where honeypot |
# will be added                                |
# ==============================================
set -euo pipefail
source global_functions.sh

set +e
len=$(yq '.honeypots | length' "$HONEYPOT_CONF")
echo "MEOW"
set -e

print_stage "STAGE 2: IP Checker"
print_info "Checking if desired IPs for honeypots are already in use. This will take some time..."
rc=0

for i in $(seq 0 $((len - 1))); do
    # Read from .yaml config
    honeypot_ip_addr=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')

    # Check IPs via arping
    if sudo arping -c 10 -w 1 -I  eth0."$honeypot_vlan_id" -S "$honeypot_ip_addr" "$honeypot_ip_addr" > /dev/null; then # Using same IP for source and destination since eth0 does not have its own IP
        print_error "IP ${RED}$honeypot_ip_addr${NC} for $honeypot_name on VLAN:$honeypot_vlan_id is ${RED}already in use${NC}. Please change it in the config"
        rc=1
    else
        print_info "IP $honeypot_ip_addr for $honeypot_name on VLAN:$honeypot_vlan_id is ${GREEN}free${NC}"
    fi
done
if [[ $rc -eq 0 ]]; then
    print_success "All IP addresses are free"
fi
exit $rc