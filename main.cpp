#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <thread>
#include "arp.cpp"


/****** Global variables  ******/
uint8_t FAKE_MAC[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }; 
uint8_t FAKE_IP[4]  = { 192, 168, 0, 202 };
uint8_t REAL_CONTAINER_IP[4]  = {10, 20, 0, 20};

const char *IFACE1 = "eth0";
const char *IFACE2 = "podman1"; /* Contain entire network */ //podman1

/* Helper functions to print out info  */
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t *ip) {
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/* Function to recompute the ip checksum */
static uint16_t ip_checksum(const void *vdata, size_t length)
{
    const uint8_t *data = (const uint8_t*)vdata;   // Reinterpret as byte sequence
    uint32_t acc = 0;                              // 32-bit accumulator for the sum
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word = (data[i] << 8) | data[i+1];
        acc += word;
    }
    if (length & 1) {
        acc += data[length-1] << 8;
    }
    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);
    return htons(~acc);                            // convert to network (big-endian) byte order
}


// --- Ethernet header definitions ---
#pragma pack(push, 1) // Set the 1 byte boundary (not alligned)
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
};

struct ipv4_hdr {
    uint8_t  ihl_version;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src[4];
    uint8_t  dst[4];
};
#pragma pack(pop)


static uint16_t csum16(const uint8_t* data, size_t len, uint32_t start = 0)
{
    uint32_t acc = start;
    for (size_t i = 0; i + 1 < len; i += 2)
        acc += (data[i] << 8) | data[i+1];
    if (len & 1)
        acc += data[len-1] << 8;
    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;  
}

static uint16_t tcp_checksum(const ipv4_hdr* ip, const tcp_hdr* tcp, size_t tcp_len)
{
    uint32_t acc = 0;
    acc += (ip->src[0] << 8) | ip->src[1];
    acc += (ip->src[2] << 8) | ip->src[3];
    acc += (ip->dst[0] << 8) | ip->dst[1];
    acc += (ip->dst[2] << 8) | ip->dst[3];
    acc += 0x0006;           
    acc += tcp_len;          
    return csum16((const uint8_t*)tcp, tcp_len, acc);
}

int send_to_interface(const uint8_t *frame, size_t len, const char *veth_name) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_ll device{};
    device.sll_ifindex = if_nametoindex(veth_name);
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_ALL);

    if (sendto(sock, frame, len, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}


/* Changing SRC IP and MAC and DST MAC */
/* Callback for every capture packet on the veth0 (container endpoint in OS) */
void packet_handler_veth0(u_char *user,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    pcap_t *handle = *reinterpret_cast<pcap_t**>(user);

    if (header->len > 1500) return;     // Ignore JUMBO frames
    uint8_t buf[1500];
    size_t len = header->len;
    memcpy(buf, packet, len);           // Make a writeable copy of the packet since its const 

    eth_hdr *eth = (eth_hdr*)buf;       // Interpret the first 14 bytes as Ethernet header.
    uint16_t ethertype = ntohs(eth->ethertype); // Get EtherType and convert from network (big-endian) to host.

    // If just an IPV4 then rewrite the IP of destination (the container runs in its own network)
    if (ethertype == 0x0800) {
        ipv4_hdr *ip = (ipv4_hdr*)(buf + sizeof(eth_hdr));
        
        if (memcmp(ip->src, REAL_CONTAINER_IP, 4) != 0){ // The packet is from unknown ip
            return; // not from 10.20.0.20
        }

        if (memcmp(ip->dst, REAL_CONTAINER_IP, 4) == 0){ // The packet is in direction to veth 
            return; 
        }
        

        uint8_t dst_mac[6];
        bool have_mac = arp_lookup(ip->dst, dst_mac);
        if (have_mac) {
            std::memcpy(eth->dst, dst_mac, 6);
        } else {
            std::cout << "No entry in arp table for IP: ";
            print_ip(ip->dst);
            std::cout << std::endl;
            // TODO SEND ARP REQUEST
        }

        // rewrite to 192.168.0.202
        memcpy(ip->src, FAKE_IP, 4);
        memcpy(eth->src, FAKE_MAC, 6);

        std::cout << "PACKET HANDLER DIRECTION FROM PODMAN TO ETH0" << std::endl << std::endl;
        std::cout << "SRC MAC: ";
        print_mac(eth->src);
        std::cout << std::endl;

        std::cout << "DST MAC: ";
        print_mac(eth->dst);
        std::cout << std::endl;

        std::cout << "SRC IP: ";
        print_ip(ip->src);
        std::cout << std::endl;

        std::cout << "DST IP: ";
        print_ip(ip->dst);
        std::cout << std::endl;
        std::cout << "-----------------------------------" << std::endl << std::endl;

        ip->checksum = 0;
        size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
        ip->checksum = ip_checksum(ip, ip_hdr_len);
        if (ip->protocol == 6) { // TCP
            tcp_hdr *tcp = (tcp_hdr*)((uint8_t*)ip + ((ip->ihl_version & 0x0F) * 4));
            size_t tcp_len = ntohs(ip->total_length) - ((ip->ihl_version & 0x0F) * 4);
            tcp->checksum = 0;
            tcp->checksum = htons(tcp_checksum(ip, tcp, tcp_len));
        }
        send_to_interface(buf, len, IFACE1);
        return;
    }
}

/* Changing DST IP */
/* Callback for every capture packet on the physical eth0 */
void packet_handler_eth0(u_char *user,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    pcap_t *handle = *reinterpret_cast<pcap_t**>(user);

    if (header->len > 1500) return;     // Ignore JUMBO frames
    uint8_t buf[1500];
    size_t len = header->len;
    memcpy(buf, packet, len);           // Make a writeable copy of the packet since its const 

    eth_hdr *eth = (eth_hdr*)buf;       // Interpret the first 14 bytes as Ethernet header.
    uint16_t ethertype = ntohs(eth->ethertype); // Get EtherType and convert from network (big-endian) to host.

    // Check if the packet is ARP. If it is then the program itself has to answer
    if (ethertype == 0x0806) {
        arp_hdr *arp = (arp_hdr*)(buf + sizeof(eth_hdr));
        
        arp_update(arp->spa, arp->sha);

        if (ntohs(arp->oper) == 1 && memcmp(arp->tpa, FAKE_IP, 4) == 0) {
            std::cout << "\n[ARP] who-has 192.168.0.202 from ";
            print_ip(arp->spa); std::cout << "\n";
            send_arp_reply(handle, arp->sha, arp->spa);
        }
        return;
    }


    // If just an IPV4 then rewrite the IP of destination (the container runs in its own network)
    if (ethertype == 0x0800) {
        ipv4_hdr *ip = (ipv4_hdr*)(buf + sizeof(eth_hdr));

        if (memcmp(ip->dst, FAKE_IP, 4) != 0)
            return; // not for 192.168.0.202
        // rewrite to 10.20.0.20
        memcpy(ip->dst, REAL_CONTAINER_IP, 4);

        ip->checksum = 0;
        size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
        ip->checksum = ip_checksum(ip, ip_hdr_len);

        std::cout << "PACKET HANDLER DIRECTION FROM ETH0 TO PODMAN" << std::endl << std::endl;
        std::cout << "SRC MAC: ";
        print_mac(eth->src);
        std::cout << std::endl;

        std::cout << "DST MAC: ";
        print_mac(eth->dst);
        std::cout << std::endl;

        std::cout << "SRC IP: ";
        print_ip(ip->src);
        std::cout << std::endl;

        std::cout << "DST IP: ";
        print_ip(ip->dst);
        std::cout << std::endl;
        std::cout << "-----------------------------------" << std::endl << std::endl;
        if (ip->protocol == 6) { // TCP
            tcp_hdr *tcp = (tcp_hdr*)((uint8_t*)ip + ((ip->ihl_version & 0x0F) * 4));
            size_t tcp_len = ntohs(ip->total_length) - ((ip->ihl_version & 0x0F) * 4);
            tcp->checksum = 0;
            tcp->checksum = htons(tcp_checksum(ip, tcp, tcp_len));
        }
        send_to_interface(buf, len, IFACE2);
        return;
    }
}



int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_eth0 = pcap_open_live(IFACE1, BUFSIZ, 1, 2, errbuf);   // Open interface IFACE1 for capturing in PROMISC mode
    pcap_t *handle_veth = pcap_open_live(IFACE2, BUFSIZ, 1, 2, errbuf);   // Open interface IFACE2 for capturing in PROMISC mode

    if (!handle_eth0 || !handle_veth) {
        std::cerr << "Error opening interfaces\n";
        return 1;
    }

    // Compile filters: only packets for my IP on eth0; only packets from container IP on veth
    struct bpf_program fp1, fp2;
    const char *filter_eth0 = "arp or ip dst 192.168.0.202"; 
    const char *filter_veth = "ip";  // capture all IP replies

    pcap_compile(handle_eth0, &fp1, filter_eth0, 1, PCAP_NETMASK_UNKNOWN); // Compile text filter fro eth0
    pcap_setfilter(handle_eth0, &fp1);                                     // Set compiled filter to eth0
    pcap_freecode(&fp1);                                                   // Free the compile code
    pcap_setdirection(handle_eth0, PCAP_D_IN);

    pcap_compile(handle_veth, &fp2, filter_veth, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle_veth, &fp2);
    pcap_freecode(&fp2); 

    std::thread t1([&]() {
        pcap_loop(handle_eth0, 0, packet_handler_eth0, reinterpret_cast<u_char*>(&handle_eth0));
    });

    std::thread t2([&]() {
        pcap_loop(handle_veth, 0, packet_handler_veth0, reinterpret_cast<u_char*>(&handle_veth));
    });

    t1.join();
    t2.join();

    pcap_close(handle_eth0);
    pcap_close(handle_veth);
    return 0;
}

