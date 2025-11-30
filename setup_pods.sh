#!/bin/bash

set -euo pipefail
# Configs
HONEYPOT_CONF="configs/honeypots.yaml" 
NETWORK_CONF="configs/network.yaml"

STATE_FILE="/run/honeybridge.d/honeybridge_pods_stage"
# The directory with all services that could be bundled into honeypot
SERVICES_DIR="honeypots/"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

# Length of the honeypots.yaml
len=$(yq '.honeypots | length' "$HONEYPOT_CONF")
# Directory in which this script is placed
SCRIPT_DIR="$(dirname "$(realpath "$0")")"

echo "=================================== STAGE 3: Pods configuration ======================================"

macvlan_moved=0             # For safe rollback, shows if the macvlan is under hosts control or already in pod
container_running=0         # For safe rollback, shows if the pod already runs
current_container_name=""   # For safe rollback, shows name of honeypot that caused error
current_pos=0               # For state managment, shows what was the index of honeypot that caused error

# =================================== FUNCTIONS =========================================

save_pods_stage() {
    echo "$1" | sudo tee "$STATE_FILE" >/dev/null
}

load_pods_stage() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo 0
    fi
}

rollback() {
    echo -e "${RED}[!] ERROR occurred${NC}"
    if [[ $macvlan_moved -eq 0 ]]; then
        echo -e "[!] Rolling back..."
        echo "[*] Deleting macvlan_temp"
        sudo ip link delete macvlan_temp 2>/dev/null || true
    fi
    if [[ $container_running -eq 1 ]]; then
        echo -e "[!] Rolling back..."
        echo "[*] Deleting pod"
        sudo podman rm -f "$current_container_name" || true
    fi
    echo "[*] Rollback finished"
    save_pods_stage "$current_pos"
    exit 1
}
trap rollback ERR # Will be called if error occurs

# =======================================================================================

# Load last stage
start_pos=$(load_pods_stage) 

# Build base image
sudo ./build_services/build_base.sh 

for i in $(seq "${start_pos}" $((len - 1))); do
    # Updating variables for safe rollback
    macvlan_moved=0
    container_running=0
    # ==================== Reading configuration ========================
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_ip=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_mac_addr=$(yq ".honeypots[$i].mac" "$HONEYPOT_CONF" | tr -d '"')
    network_range=$(yq ".vlans[] | select(.id == $honeypot_vlan_id) | .range" $NETWORK_CONF | tr -d '"')
    mapfile -t service_names < <(yq -r ".honeypots[$i].services[].name" "$HONEYPOT_CONF")
    mapfile -t service_ports < <(yq -r ".honeypots[$i].services[].port" "$HONEYPOT_CONF")
    # ===================================================================
    # Deleting old supervisor config since it was overwritten and starting with template 
    rm -rf build_services/configs/supervisor
    cp -r build_services/configs/supervisor_templates build_services/configs/supervisor

    echo "[*] Updating supervisor service ports"
    for idx in "${!service_names[@]}"; do
        name="${service_names[$idx]}"
        port="${service_ports[$idx]}"
        conf_path="build_services/configs/supervisor/${name}.conf"
        if [[ -f "$conf_path" ]]; then
            # Replace "insert_port" with the actual port
            sed -i "s/insert_port/${port}/g" "$conf_path"
        else
            echo -e "[!] ${YELLOW}WARNING:${NC} No supervisor config for service '$name' (${conf_path})"
        fi
    done

    # This will create an image with all neccessary tools to run services
    echo "[+] Building image"
    # Passing all services so the chain of build_"services".sh scripts will build the desired image
    ./build_services/start.sh $honeypot_name ${service_names[@]}
    cd "$SCRIPT_DIR"
    # Update already deployed honeypot counter
    current_pos=${i}

    echo "[*] Creating macvlan interface: macvlan_temp for $honeypot_name"
    sudo ip link add macvlan_temp link eth0."$honeypot_vlan_id" type macvlan mode bridge
    sudo ip link set macvlan_temp address "$honeypot_mac_addr"
    echo "[+] Created macvlan_temp with honeypot MAC $honeypot_mac_addr"

    echo "[*] Starting honeypot $honeypot_name"
    container_hash=$(sudo bash -c "./run_honeypot.sh $honeypot_name")
    echo -e  "[+] ${GREEN}Container $honeypot_name started:${NC} $container_hash"
    current_container_name="$honeypot_name"
    container_running=1 # Safe rollback if error occurs

    # Finding the pid to insert macvlan into its namespace
    pid=$(sudo podman inspect -f '{{.State.Pid}}' "$honeypot_name")
    # Wait for container initializing
    sleep 0.5

    # Move macvlan interface into container namespace
    echo "[*] Moving macvlan_temp into $honeypot_name namespace"
    sudo ip link set macvlan_temp netns "$pid"
    macvlan_moved=1

    # Configure macvlan inside container
    echo "[*] Configuring pod networking"
    sudo nsenter -t "$pid" -n ip link set macvlan_temp name eth0
    # Read the network mask (Example: 192.168.20.0/24)
    IFS=/ read -r _ mask <<< "$network_range"
    sudo nsenter -t "$pid" -n ip addr add "${honeypot_ip}"/"${mask}" dev eth0
    sudo nsenter -t "$pid" -n ip link set eth0 up

    # Output info about the running honeypot
    echo -e "[+] ${GREEN}Honeypot $honeypot_name ready ${NC}"
    echo -e "    MAC: ${YELLOW}$honeypot_mac_addr${NC}"
    echo -e "    IP: ${YELLOW}$honeypot_ip${NC}"
    echo -ne "    SERVICES: ${YELLOW}"
    printf "%s " "${service_names[@]}"
    echo -e "${NC}"

    echo ""
done
