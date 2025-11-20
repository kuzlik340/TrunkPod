podman network exists internal || podman network create --subnet 175.20.0.0/24 --gateway 175.20.0.1 internal

sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip link add link eth0 name eth0.30 type vlan id 30

sudo ip link set eth0.20 up
sudo ip link set eth0.30 up

sudo ip addr add 192.168.20.20/32 dev eth0.20
sudo ip addr add 192.168.30.30/32 dev eth0.30
sudo ip addr add 192.168.30.35/32 dev eth0.30

sudo ip route add 192.168.20.0/24 dev eth0.20
sudo ip route add 192.168.30.0/24 dev eth0.30

iptables -t nat -A PREROUTING -i eth0.20 -d 192.168.20.20 -j DNAT --to-destination 175.20.0.20 # here the eth0 will be eth0.20 or other respectfully by its vlan id
iptables -t nat -A POSTROUTING -s 175.20.0.20 -d 192.168.20.0/24 -j SNAT --to-source 192.168.20.20

iptables -t nat -A PREROUTING -i eth0.30 -d 192.168.30.30 -j DNAT --to-destination 175.20.0.21 # here the eth0 will be eth0.20 or other respectfully by its vlan id
iptables -t nat -A POSTROUTING -s 175.20.0.21 -d 192.168.30.0/24 -j SNAT --to-source 192.168.30.30

iptables -t nat -A PREROUTING -i eth0.30 -d 192.168.30.35 -j DNAT --to-destination 175.20.0.22 # here the eth0 will be eth0.20 or other respectfully by its vlan id
iptables -t nat -A POSTROUTING -s 175.20.0.22 -d 192.168.30.0/24 -j SNAT --to-source 192.168.30.35

sudo sysctl -w net.ipv4.ip_forward=1


#TODO JSON parser / CLI (Example docker-compose -> yaml) DONE
#TODO 2-3 services (Simple HTTP server, LDAP, SSH). PORT THAT SENDS BANNER (SSH BANNER) SIMPLE SCRIPTS
#TODO IP checker in use 
#TODO make every IPTABLE entry perfect with the interfaces and other things
#TODO create a directory with honeypots
#TODO deletion of interfaces if misocnfigured LIKE TRANSACTION COMMIT

#TODO LOGS ENTIRELY NETFLOWS
#TODO NETWORK TELESCOPE
#TODO FIREWALL BETWEEN DEVICES ON PODMAN INTERNAL NETWORK
#TODO CAPABLITIES on the podman
#TODO EVERYTHING THAT GOES NOT TO CONTAINERS IP WE HAVE TO SEE IT AND LOG (stealth scan TCP:SYN) SOMETHING LIKE IDS
