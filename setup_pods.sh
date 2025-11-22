#!/bin/bash

HONEYPOT_CONF="configs/honeypots.yaml"
NETWORK_CONF="configs/network.yaml"
STATE_FILE="/run/honeybridge.d/honeybridge_pods_stage"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

len=$(yq '.honeypots | length' "$HONEYPOT_CONF")


echo "=================================== STAGE 3: Pods configuration ======================================"

set -euo pipefail
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0 # MAYBE NOT?
macvlan_moved=0
container_running=0
current_container_name=""
current_pos=0

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
        sudo podman rm -f $current_container_name || true
    fi
    echo "[*] Rollback finished"
    save_pods_stage current_pos
    exit 1
}
trap rollback ERR

start_pos=$(load_pods_stage)


for i in $(seq ${start_pos} $((len - 1))); do
    # Reading configuration
    macvlan_moved=0
    container_running=0
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_ip=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_service=$(yq ".honeypots[$i].service" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_mac_addr=$(yq ".honeypots[$i].mac" "$HONEYPOT_CONF" | tr -d '"')
    network_range=$(yq ".vlans[] | select(.id == $honeypot_vlan_id) | .range" $NETWORK_CONF | tr -d '"')
    current_pos=${i}
    echo "[*] Creating macvlan interface: macvlan_temp for $honeypot_name"

    sudo ip link add macvlan_temp link eth0.$honeypot_vlan_id type macvlan mode bridge
    sudo ip link set macvlan_temp address $honeypot_mac_addr
    #sudo ip link set macvlan_temp up
    echo "[+] Created macvlan_temp with MAC $honeypot_mac_addr"
    #sudo ip addr add ${honeypot_ip}/${mask} dev macvlan_temp 2>/dev/null || true

    echo "[*] Starting honeypot $honeypot_name"
    sudo bash -c "./run_honeypot.sh $honeypot_name"
    current_container_name="$honeypot_name"
    container_running=1

    pid=$(sudo podman inspect -f '{{.State.Pid}}' $honeypot_name)
    sleep 0.5 # Wait for container initializing
    # Move macvlan interface into container namespace
    echo "[*] Moving macvlan_temp into honeypot namespace"
    sudo ip link set macvlan_temp netns $pid
    macvlan_moved=1
    # Configure inside container
    echo "[*] Configuring container networking"
    sudo nsenter -t $pid -n ip link set macvlan_temp name eth0
    IFS=/ read -r _ mask <<< "$network_range"
    sudo nsenter -t $pid -n ip addr add ${honeypot_ip}/${mask} dev eth0
    sudo nsenter -t $pid -n ip link set eth0 up

    echo "[+] Honeypot $honeypot_name ready"
    echo "    MAC: $honeypot_mac_addr"
    echo "    IP: $honeypot_ip"
    echo ""
done


# TODO: add already running containers into some file(same as stage)
# TODO: add services












