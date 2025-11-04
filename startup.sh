sudo ip link set eth0 promisc on
sudo podman network create   --subnet 10.20.0.0/24   --gateway 10.20.0.1   vlan20
