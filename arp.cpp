// arp_utils.h
#ifndef ARP_UTILS_H
#define ARP_UTILS_H

#include <cstdint>
#include <pcap.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

// these must be defined in your main .cpp
extern uint8_t FAKE_MAC[6];
extern uint8_t FAKE_IP[4];
void print_ip(const uint8_t *ip);
void print_mac(const uint8_t *mac);

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
};
#pragma pack(pop)

inline bool send_arp_reply(pcap_t *handle,
                           const uint8_t sender_mac[6],
                           const uint8_t sender_ip[4])
{
    uint8_t packet[42] = {0};

    eth_hdr *eth = reinterpret_cast<eth_hdr*>(packet);
    std::memcpy(eth->dst, sender_mac, 6);
    std::memcpy(eth->src, FAKE_MAC, 6);
    eth->ethertype = htons(0x0806);

    arp_hdr *arp = reinterpret_cast<arp_hdr*>(packet + sizeof(eth_hdr));
    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(2);

    std::memcpy(arp->sha, FAKE_MAC, 6);
    std::memcpy(arp->spa, FAKE_IP, 4);
    std::memcpy(arp->tha, sender_mac, 6);
    std::memcpy(arp->tpa, sender_ip, 4);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        std::cerr << "pcap_sendpacket failed: " << pcap_geterr(handle) << "\n";
        return false;
    }

    std::cout << "Sent ARP reply to ";
    print_ip(sender_ip);
    std::cout << " ("; print_mac(sender_mac); std::cout << ")\n";
    return true;
}

#endif // ARP_UTILS_H
