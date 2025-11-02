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
static uint8_t LAST_PEER_MAC[6];
const char *IFACE1 = "eth0";
const char *IFACE2 = "veth0";

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

        if (memcmp(ip->src, REAL_CONTAINER_IP, 4) != 0){
            return; // not from 10.20.0.20
            std::cout << "Disabling mirroring" << std::endl;
        }
            
        // rewrite to 192.168.0.202
        memcpy(ip->src, FAKE_IP, 4);
        memcpy(eth->src, FAKE_MAC, 6);
        memcpy(eth->dst, LAST_PEER_MAC, 6);

        std::cout << std::endl << "PACKET HANDLER DIRECTION FROM VETH" << std::endl << std::endl;
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

        send_to_interface(buf, len, "eth0");
        return;
    }
}


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
        memcpy(LAST_PEER_MAC, arp->sha, 6);
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
        memcpy(LAST_PEER_MAC, eth->src, 6);
        // rewrite to 10.20.0.20
        memcpy(ip->dst, REAL_CONTAINER_IP, 4);

        ip->checksum = 0;
        size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
        ip->checksum = ip_checksum(ip, ip_hdr_len);

        std::cout << "PACKET HANDLER DIRECTION FROM VETH" << std::endl << std::endl;
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
        send_to_interface(buf, len, "veth0");
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






































// // --- Packet handler ---
// void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
//     pcap_t *handle = *reinterpret_cast<pcap_t**>(user);
//     if (header->len < sizeof(eth_hdr)) return;

//     const eth_hdr *eth = reinterpret_cast<const eth_hdr*>(packet);
//     uint16_t ethertype = ntohs(eth->ethertype);

//     // ARP
//     if (ethertype == 0x0806) {
//         const arp_hdr *arp = reinterpret_cast<const arp_hdr*>(packet + sizeof(eth_hdr));
//         if (ntohs(arp->oper) == 1 && memcmp(arp->tpa, FAKE_IP, 4) == 0) {
//             std::cout << "\n[ARP] Request for my IP from ";
//             print_ip(arp->spa); std::cout << " ("; print_mac(arp->sha); std::cout << ")\n";
//             send_arp_reply(handle, arp->sha, arp->spa);
//         }
//         return;
//     }

//     // IPv4
//     if (ethertype == 0x0800) {
//         const ipv4_hdr *ip = reinterpret_cast<const ipv4_hdr*>(packet + sizeof(eth_hdr));

//         // Check destination IP == FAKE_IP
//         if (memcmp(ip->dst, FAKE_IP, 4) != 0) return;

//         std::cout << "\n[IPv4] Packet to me | From ";
//         print_ip(ip->src);
//         std::cout << " -> ";
//         print_ip(ip->dst);

//         switch (ip->protocol) {
//             case 1:  std::cout << " (ICMP)"; break;
//             case 6:  std::cout << " (TCP)"; break;
//             case 17: std::cout << " (UDP)"; break;
//             default: std::cout << " (Proto " << (int)ip->protocol << ")"; break;
//         }
//         std::cout << " | Length: " << ntohs(ip->total_length) << " bytes\n";
//                 // we know it's IPv4 and destined to us
//         ipv4_hdr *ip = (ipv4_hdr*)(packet + sizeof(eth_hdr));

//         // rewrite dst IP to 10.20.0.20
//         uint8_t new_dst[4] = {10, 20, 0, 20};
//         memcpy(ip->dst, new_dst, 4);

//         // recalc IP header checksum
//         ip->checksum = 0;
//         size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
//         ip->checksum = ip_checksum(ip, ip_hdr_len);
//         send_to_veth(packet, header->len, "veth0");

//         return;
//     }

//     // Other protocols (IPv6, etc.)
//     std::cout << "[Other ethertype 0x" << std::hex << ethertype << std::dec << "]\n";
// }


// void packet_handler_from_container(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
//     std::cout << "Traffic from container" << std::endl;
//     const char *out_iface = "eth0";  // where to send it back
//     send_to_veth(packet, header->len, out_iface);
// }

// void packet_handler_from_container(u_char *user,
//                                    const struct pcap_pkthdr *header,
//                                    const u_char *packet)
// {
//     if (header->len > 1500 || header->len < sizeof(eth_hdr)) return;

//     // make writable copy
//     uint8_t buf[1500];
//     size_t len = header->len;
//     memcpy(buf, packet, len);

//     eth_hdr *eth = (eth_hdr*)buf;
//     uint16_t ethertype = ntohs(eth->ethertype);

//     std::cout << "\n[From container] ";

//     if (ethertype == 0x0800) {          // IPv4
//         ipv4_hdr *ip = (ipv4_hdr*)(buf + sizeof(eth_hdr));

//         // print before rewrite
//         std::cout << "IPv4 | From ";
//         print_ip(ip->src);
//         std::cout << " -> ";
//         print_ip(ip->dst);
//         std::cout << " | Proto: " << (int)ip->protocol
//                   << " | Length: " << ntohs(ip->total_length) << " bytes\n";

//         // --- SNAT: make it look like it comes from our fake IP ---
//         memcpy(ip->src, FAKE_IP, 4);
//         ip->checksum = 0;
//         size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
//         ip->checksum = ip_checksum(ip, ip_hdr_len);

//         // optional: also spoof MAC
//         memcpy(eth->src, FAKE_MAC, 6);

//         // send out
//         if (send_to_interface(buf, len, "eth0") == 0)
//             std::cout << "[Forwarded] to eth0\n";
//         else
//             std::cerr << "[Error] Failed to send to eth0\n";
//     }
//     else if (ethertype == 0x0806) {  // ARP
//         const arp_hdr *arp = reinterpret_cast<const arp_hdr*>(packet + sizeof(eth_hdr));
//         std::cout << "ARP | " 
//                   << (ntohs(arp->oper) == 1 ? "Request" : "Reply") 
//                   << " | From ";
//         print_ip(arp->spa);
//         std::cout << " ("; print_mac(arp->sha); std::cout << ")";
//         std::cout << " -> ";
//         print_ip(arp->tpa);
//         std::cout << " ("; print_mac(arp->tha); std::cout << ")" << std::endl;
//     }
    
//     else {
//         std::cout << "Other ethertype: 0x" << std::hex << ethertype << std::dec 
//                   << " | Packet length: " << header->len << " bytes" << std::endl;
//     }

//     // Forward packet back to host side (eth0)
//     const char *out_iface = "eth0";
//     if (send_to_interface(packet, header->len, out_iface) == 0) {
//         std::cout << "[Forwarded] to " << out_iface << std::endl;
//     } else {
//         std::cerr << "[Error] Failed to send to " << out_iface << std::endl;
//     }
// }