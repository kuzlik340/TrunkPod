#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 
YAML_FILE="configs/network.yaml"
len=$(yq '.vlans | length' "$YAML_FILE")
# Array for rollback function
CREATED_INTERFACES=()

echo "================================= STAGE 1: Interface configuration ==================================="
echo "[*] Configuring interfaces based on the network.yaml"

# Function to handle rollback if error occures during setup
rollback() {
    echo -e "${RED}[!] ERROR occurred.${NC} Rolling back..."
    for iface in "${CREATED_INTERFACES[@]}"; do
        echo "[*] Deleting $iface"
        sudo ip link delete "$iface" 2>/dev/null || true
    done
    echo "[*] Rollback finished"
    exit 1
}
trap rollback ERR


for i in $(seq 0 $((len - 1))); do
    # Reading configuration
    vlan_id=$(yq ".vlans[$i].id" "$YAML_FILE" | tr -d '"')
    iface="eth0.$vlan_id"
    
    # Check if interface already exists
    if ip link show "$iface" &>/dev/null; then
        echo -e "[!] ${YELLOW}WARNING:${NC} $iface already exists"

        while true; do
            read -rp "[?] Do you want to (k)eep or (o)verride this interface? [k/o]: " choice
            case "$choice" in
                    k|K)
                        echo "[*] Keeping existing $iface"
                        continue 2   # go to next iteration of outer loop
                        ;;
                    o|O)
                        echo "[*] Overriding existing $iface"
                        sudo ip link delete "$iface" || true
                        break        # break inner loop and create interface
                        ;;
                    *)
                        echo -e "[!] ${RED}ERROR:${NC} Invalid choice. Enter k, o, or s"
                        ;;
            esac
        done
    fi

    echo "[*] Creating $iface (VLAN $vlan_id)..."

    sudo ip link add link eth0 name eth0."$vlan_id" type vlan id "$vlan_id"
    CREATED_INTERFACES+=("$iface")
    sudo ip link set eth0."$vlan_id" up
    sudo ip link set eth0."$vlan_id" promisc on
    if ! ip link show "$iface" | grep -q "state UP"; then
        echo -e "${RED}[!] ERROR:${NC} $iface failed to come UP!"
        exit 1
    fi
    echo -e "[+] $iface created successfully and is UP in PROMISC mode"
done

echo -e "[*] ${GREEN}All VLAN interfaces configured successfully${NC}"
echo ""