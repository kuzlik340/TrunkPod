#!/bin/bash

GREEN='\033[0;32m'
NC='\033[0m' 
RED='\033[0;31m'

HONEYPOT_CONF="configs/honeypots.yaml"
len=$(yq '.honeypots | length' "$HONEYPOT_CONF")

echo "======================================= STAGE 2: IP Checker =========================================="
echo "[*] Checking if desired IPs for honeypots are already in use. This will take some time..."
pr_exit_code=0
for i in $(seq 0 $((len - 1))); do
    honeypot_ip_addr=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')

    if sudo arping -c 3 -w 2 -I  eth0."$honeypot_vlan_id" -S "$honeypot_ip_addr" "$honeypot_ip_addr" > /dev/null; then # Using same IP for source and destination since eth0 does not have its own IP
        echo -e "[!] IP ${RED}$honeypot_ip_addr${NC} for $honeypot_name on VLAN:$honeypot_vlan_id is ${RED}already in use${NC}. Please change it in the config"
        pr_exit_code=1
    else
        echo -e "[*] IP $honeypot_ip_addr for $honeypot_name on VLAN:$honeypot_vlan_id is ${GREEN}free${NC}"
    fi
done
if [[ $pr_exit_code -eq 0 ]]; then
    echo -e "[*] ${GREEN}All IP addresses are free ${NC}"
fi
exit $pr_exit_code