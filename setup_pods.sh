#!/bin/bash
podman network exists internal || podman network create --subnet 175.20.0.0/24 --gateway 175.20.0.1 internal

HONEYPOT_CONF="configs/honeypots.yaml"
NETWORK_CONF="configs/network.yaml"
INTERNAL_NETWORK_START_IP="175.20.0.5"

len=$(yq '.honeypots | length' "$HONEYPOT_CONF")
current_internal_ip=$INTERNAL_NETWORK_START_IP
set -euo pipefail
sudo sysctl -w net.ipv4.ip_forward=1

for i in $(seq 0 $((len - 1))); do
    IFS=. read -r o1 o2 o3 o4 <<< "$current_internal_ip"
    ((o4++))
    current_internal_ip="$o1.$o2.$o3.$o4"
    honeypot_name=$(yq ".honeypots[$i].name" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_external_ip=$(yq ".honeypots[$i].ip" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_vlan_id=$(yq ".honeypots[$i].vlan" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_service=$(yq ".honeypots[$i].service" "$HONEYPOT_CONF" | tr -d '"')
    honeypot_mac_addr=$(yq ".honeypots[$i].mac" "$HONEYPOT_CONF" | tr -d '"')
    network_range=$(yq ".vlans[] | select(.id == $honeypot_vlan_id) | .range" $NETWORK_CONF | tr -d '"')
    IFS=. read -r o1 o2 o3 o4 <<< "$current_internal_ip"
    #honeypot_mac_address=$(hexdump -n6 -v -e '/1 "%02X:"' /dev/urandom | sed 's/:$//')
    #sudo ip addr add $honeypot_external_ip/32 dev eth0.$honeypot_vlan_id
    sudo iptables -t nat -A PREROUTING -d $honeypot_external_ip -j DNAT --to-destination $current_internal_ip # here the eth0 will be eth0.20 or other respectfully by its vlan id
    sudo iptables -t nat -A POSTROUTING -s $current_internal_ip -d $network_range -j SNAT --to-source $honeypot_external_ip
    echo "RUNNING sudo ./run_honeypot.sh $current_internal_ip $honeypot_mac_addr $honeypot_name"
    
    sudo ip link add macvlan$i link eth0.$honeypot_vlan_id type macvlan mode bridge
    sudo ip link set dev macvlan$i address $honeypot_mac_addr
    sudo ip addr add $honeypot_external_ip/32 dev macvlan$i

    sudo ip link set macvlan$i up
    #sudo ip route add $network_range dev macvlan$i

    sudo ./run_honeypot.sh $current_internal_ip $honeypot_mac_addr $honeypot_name
    #MAYBEEE sudo ip link set dev eth0.20 promisc on
    echo "$honeypot_external_ip"
    echo "$current_internal_ip"
    echo "$network_range"
done

#TODO add checks if VLAN already exists and checks if the interface was really created and is UP













