#!/bin/bash

# ==============================================
# Module that checks if desired IPs are not    |
# already in use in the network where honeypot |
# will be added                                |
# ==============================================
set -euo pipefail

source "$PROJECT_ROOT"/global_functions.sh

print_info "Checking if desired IPs for honeypots are already in use. This will take some time..."
rc=0
yq_safe len '.honeypots | length' "$HONEYPOT_CONF"

for i in $(seq 0 $((len - 1))); do
    # Read from .yaml config
    yq_safe honeypot_ip_addr -r ".honeypots[$i].ip" "$HONEYPOT_CONF" 
    yq_safe honeypot_vlan_id -r ".honeypots[$i].vlan" "$HONEYPOT_CONF" 
    yq_safe honeypot_name -r ".honeypots[$i].name" "$HONEYPOT_CONF"

    # Check IPs via arping
    if arping -c 10 -w 1 -I  eth0."$honeypot_vlan_id" -S "$honeypot_ip_addr" "$honeypot_ip_addr" > /dev/null; then # Using same IP for source and destination since eth0 does not have its own IP
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