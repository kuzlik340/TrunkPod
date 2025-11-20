#!/bin/bash

YAML_FILE="configs/network.yaml"

len=$(yq '.vlans | length' "$YAML_FILE")

for i in $(seq 0 $((len - 1))); do
    vlan_id=$(yq ".vlans[$i].id" "$YAML_FILE" | tr -d '"')
    vlan_range=$(yq ".vlans[$i].range" "$YAML_FILE" | tr -d '"')

    sudo ip link add link eth0 name eth0.$vlan_id type vlan id $vlan_id
    sudo ip link set eth0.$vlan_id up
    sudo ip link set eth0.$vlan_id promisc on
    echo "Interface eth0.$vlan_id is UP for vlan_id = $vlan_id in PROMISC"
done

#TODO add checks if VLAN already exists and checks if the interface was really created and is UP