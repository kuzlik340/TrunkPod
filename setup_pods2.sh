#!/bin/bash

HONEYPOT_CONF="configs/honeypots.yaml"
NETWORK_CONF="configs/network.yaml"

len=$(yq '.honeypots | length' "$HONEYPOT_CONF")

set -euo pipefail
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0

for i in $(seq 0 $((len - 1))); do
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_external_ip=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_service=$(yq ".honeypots[$i].service" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_mac_addr=$(yq ".honeypots[$i].mac" "$HONEYPOT_CONF" | tr -d '"')
    network_range=$(yq ".vlans[] | select(.id == $honeypot_vlan_id) | .range" $NETWORK_CONF | tr -d '"')
    network_gateway=$(yq ".vlans[] | select(.id == $honeypot_vlan_id) | .gateway" $NETWORK_CONF | tr -d '"')

    macvlan_name="macvlan${i}"
    echo "[*] ========== Honeypot: $honeypot_name =========="
    echo "[*] VLAN: $honeypot_vlan_id, IP: $honeypot_external_ip, MAC: $honeypot_mac_addr"


    echo "[*] Creating macvlan interface: $macvlan_name"
    sudo ip link add $macvlan_name link eth0.$honeypot_vlan_id type macvlan mode bridge
    sudo ip link set $macvlan_name address $honeypot_mac_addr
    sudo ip link set $macvlan_name up
    echo "[+] Created $macvlan_name with MAC $honeypot_mac_addr"
    sudo ip addr add ${honeypot_external_ip}/24 dev $macvlan_name 2>/dev/null || true #maybe not?

    echo "RUNNING sudo ./run_honeypot.sh $honeypot_name"
    sudo ./run_honeypot2.sh $honeypot_name

    pid=$(sudo podman inspect -f '{{.State.Pid}}' $honeypot_name)
    echo "[*] Container PID: $pid"

    sleep 0.5

    # Move macvlan interface into container namespace
    echo "[*] Moving $macvlan_name into container namespace"
    sudo ip link set $macvlan_name netns $pid

    # Configure inside container
    echo "[*] Configuring container networking"
    sudo nsenter -t $pid -n ip link set $macvlan_name name eth0
    sudo nsenter -t $pid -n ip addr add ${honeypot_external_ip}/24 dev eth0
    sudo nsenter -t $pid -n ip link set eth0 up
    #sudo nsenter -t $pid -n ip route add default via $network_gateway


    echo "[+] ✓ Honeypot $honeypot_name ready"
    echo "    MAC: $honeypot_mac_addr"
    echo "    IP: $honeypot_external_ip"
    echo "    Gateway: $network_gateway"
    echo ""
done

#TODO add checks if VLAN already exists and checks if the interface was really created and is UP













