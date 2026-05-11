/*
 * traffic_parser.c
 *
 * Packet capture logger using libpcap.
 * Output: pipe-separated, one line per packet, fixed column positions
 * matching the tshark -e field order:
 *
 * Col  1  frame.time_epoch
 * Col  2  frame.len
 * Col  3  eth.src
 * Col  4  eth.dst
 * Col  5  eth.type
 * Col  6  vlan.id
 * Col  7  vlan.etype
 * Col  8  ip.src
 * Col  9  ip.dst
 * Col 10  ip.proto
 * Col 11  tcp.srcport
 * Col 12  tcp.dstport
 * Col 13  tcp.flags
 * Col 14  udp.srcport
 * Col 15  udp.dstport
 * Col 16  icmp.type
 * Col 17  icmp.code
 * Col 18  arp.opcode
 * Col 19  arp.src.hw_mac
 * Col 20  arp.src.proto_ipv4
 * Col 21  arp.dst.hw_mac
 * Col 22  arp.dst.proto_ipv4
 *
 * Empty fields are left blank (two adjacent pipes: ||).
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -std=gnu11 -o traffic_parser traffic_parser.c -lpcap
 *   or just use a Makefile
 *
 * Run (requires root or CAP_NET_RAW):
 *   sudo ./traffic_parser eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <unistd.h> 

/* ─── Configuration ─────────────────────────────────────────────────────── */

#define LOG_DIR       "/var/log/traffic_parser"
#define LOG_PREFIX    "traffic_"
#define LOG_SUFFIX    ".log"
#define BPF_FILTER    "GENERATE USING configs/createbpf_filter.py"
#define SNAPLEN       256
#define PROMISC       1
#define TIMEOUT_MS    1000
#define MAX_LOGS      10

/* Total number of output columns */
#define NUM_COLS      22

/************** Globals *************/

static pcap_t *g_handle  = NULL;
static FILE   *g_logfile = NULL;
static char   g_log_path[] = "/var/log/traffic_parser/traffic_parser.log";
static size_t g_max_size = 1048576;  // bytes
static size_t g_current_size = 0;    // tracked size
static int    g_rotate_index = 0;
static time_t g_last_flush = 0;

/************** Row struct *************/

/*
 * Each field is a small fixed-size string.
 * Empty string means "not present" -> printed as blank between pipes.
 */
typedef struct {
    char f[NUM_COLS][128];
} row_t;

typedef struct {
    FILE **fp;
} ctx_t;

static void row_clear(row_t *r)
{
    memset(r, 0, sizeof(*r));
}

/* Indices into row_t.f[] */
enum {
    C_TIMESTAMP = 0,
    C_FRAME_LEN,
    C_ETH_SRC,
    C_ETH_DST,
    C_ETH_TYPE,
    C_VLAN_ID,
    C_VLAN_ETYPE,
    C_IP_SRC,
    C_IP_DST,
    C_IP_PROTO,
    C_TCP_SPORT,
    C_TCP_DPORT,
    C_TCP_FLAGS,
    C_UDP_SPORT,
    C_UDP_DPORT,
    C_ICMP_TYPE,
    C_ICMP_CODE,
    C_ARP_OPCODE,
    C_ARP_SRC_MAC,
    C_ARP_SRC_IP,
    C_ARP_DST_MAC,
    C_ARP_DST_IP,
};

struct pcap_stat stats;

/************* Output *************/

static size_t row_print(FILE *f, const row_t *r)
{
    char line[NUM_COLS * 128 + NUM_COLS + 2];
    char *p = line;

    for (int i = 0; i < NUM_COLS; i++) {
        if (i > 0) *p++ = '|';
        size_t len = strlen(r->f[i]);
        memcpy(p, r->f[i], len);
        p += len;
    }
    *p++ = '\n';

    size_t total = p - line;
    fwrite(line, 1, total, f);
    return total;
}

static void rotate_logs(void)
{
    char old[600], new_path[600];
    pcap_stats(g_handle, &stats);
    fprintf(stderr, "received=%u dropped=%u\n",
        stats.ps_recv, stats.ps_drop);
    
    /* Delete oldest if at max */
    if (g_rotate_index >= MAX_LOGS) {
        snprintf(old, sizeof(old), "%s.%d", g_log_path, MAX_LOGS);
        remove(old);
    }

    /* Shift upward using known max */
    int shift_max = (g_rotate_index < MAX_LOGS) ? g_rotate_index : MAX_LOGS - 1;
    for (int i = shift_max; i >= 1; i--) {
        snprintf(old,      sizeof(old),      "%s.%d", g_log_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", g_log_path, i + 1);
        rename(old, new_path);
    }


    snprintf(new_path, sizeof(new_path), "%s.1", g_log_path);
    fflush(g_logfile);
    fsync(fileno(g_logfile));
    fclose(g_logfile);
    rename(g_log_path, new_path);
    if (g_rotate_index < MAX_LOGS)
        g_rotate_index++;

    g_logfile = fopen(g_log_path, "w");
    if (!g_logfile) { perror("reopen after rotate"); exit(EXIT_FAILURE); }

    g_current_size = 0;
    fprintf(stderr, "[*] Log rotated (index now %d)\n", g_rotate_index);
}
/************** File management *************/

static FILE *open_logfile(const char *path)
{
    FILE *fh = fopen(path, "a");
    if (!fh) {
        perror(path);
        return NULL;
    }

    fseek(fh, 0, SEEK_END);
    g_current_size = ftell(fh);

    fprintf(stderr, "[*] Logging to %s (size=%zu)\n", path, g_current_size);
    return fh;
}

/************** Helpers **************/

static void set_mac(row_t *r, int col, const uint8_t *mac)
{
    snprintf(r->f[col], sizeof(r->f[col]),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/************** Transport parsers **************/

static void parse_udp(row_t *r, const uint8_t *data, int len)
{
    if (len < (int)sizeof(struct udphdr)) return;

    const struct udphdr *udp = (const struct udphdr *)data;
    uint16_t sport = ntohs(udp->uh_sport);
    uint16_t dport = ntohs(udp->uh_dport);

    snprintf(r->f[C_UDP_SPORT], sizeof(r->f[C_UDP_SPORT]), "%u", sport);
    snprintf(r->f[C_UDP_DPORT], sizeof(r->f[C_UDP_DPORT]), "%u", dport);
}

static void parse_tcp(row_t *r, const uint8_t *data, int len)
{
    if (len < (int)sizeof(struct tcphdr)) return;

    const struct tcphdr *tcp = (const struct tcphdr *)data;

    snprintf(r->f[C_TCP_SPORT], sizeof(r->f[C_TCP_SPORT]), "%u", ntohs(tcp->th_sport));
    snprintf(r->f[C_TCP_DPORT], sizeof(r->f[C_TCP_DPORT]), "%u", ntohs(tcp->th_dport));
    snprintf(r->f[C_TCP_FLAGS], sizeof(r->f[C_TCP_FLAGS]), "0x%04x", tcp->th_flags);
}

static void parse_icmp(row_t *r, const uint8_t *data, int len)
{
    if (len < (int)sizeof(struct icmphdr)) return;

    const struct icmphdr *icmp = (const struct icmphdr *)data;
    snprintf(r->f[C_ICMP_TYPE], sizeof(r->f[C_ICMP_TYPE]), "%u", icmp->type);
    snprintf(r->f[C_ICMP_CODE], sizeof(r->f[C_ICMP_CODE]), "%u", icmp->code);
}

/************** ARP parser ***************/

static void parse_arp(row_t *r, const uint8_t *data, int len)
{
    if (len < 28) return;

    uint16_t op = (data[6] << 8) | data[7];
    snprintf(r->f[C_ARP_OPCODE],  sizeof(r->f[C_ARP_OPCODE]),  "%u", op);
    snprintf(r->f[C_ARP_SRC_MAC], sizeof(r->f[C_ARP_SRC_MAC]),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             data[8],data[9],data[10],data[11],data[12],data[13]);
    snprintf(r->f[C_ARP_SRC_IP],  sizeof(r->f[C_ARP_SRC_IP]),
             "%u.%u.%u.%u", data[14],data[15],data[16],data[17]);
    snprintf(r->f[C_ARP_DST_MAC], sizeof(r->f[C_ARP_DST_MAC]),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             data[18],data[19],data[20],data[21],data[22],data[23]);
    snprintf(r->f[C_ARP_DST_IP],  sizeof(r->f[C_ARP_DST_IP]),
             "%u.%u.%u.%u", data[24],data[25],data[26],data[27]);
}

/************** VLAN (802.1Q) **************/

static uint16_t parse_vlan(row_t *r, const uint8_t *tag, int len)
{
    if (len < 4) return 0;

    uint16_t tci        = (tag[0] << 8) | tag[1];
    uint16_t vlan_id    = tci & 0x0FFF;
    uint16_t inner_type = (tag[2] << 8) | tag[3];

    snprintf(r->f[C_VLAN_ID],    sizeof(r->f[C_VLAN_ID]),    "%u",     vlan_id);
    snprintf(r->f[C_VLAN_ETYPE], sizeof(r->f[C_VLAN_ETYPE]), "0x%04x", inner_type);

    return inner_type;
}

/*************** IPv4 parser ***************/

static void parse_ipv4(row_t *r, const uint8_t *data, int len)
{
    if (len < (int)sizeof(struct ip)) return;

    const struct ip *iph = (const struct ip *)data;
    int ip_hlen = iph->ip_hl * 4;
    if (ip_hlen < 20 || ip_hlen > len) return;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

    snprintf(r->f[C_IP_SRC],   sizeof(r->f[C_IP_SRC]),   "%s", src);
    snprintf(r->f[C_IP_DST],   sizeof(r->f[C_IP_DST]),   "%s", dst);
    snprintf(r->f[C_IP_PROTO], sizeof(r->f[C_IP_PROTO]), "%u", iph->ip_p);

    const uint8_t *transport = data + ip_hlen;
    int            tlen      = len  - ip_hlen;

    switch (iph->ip_p) {
        case IPPROTO_TCP:  parse_tcp(r,  transport, tlen); break;
        case IPPROTO_UDP:  parse_udp(r,  transport, tlen); break;
        case IPPROTO_ICMP: parse_icmp(r, transport, tlen); break;
    }
}

/************** Main packet callback **************/

static void packet_handler(u_char *u,
                            const struct pcap_pkthdr *hdr,
                            const u_char *pkt)
{
    (void)u;  /* ctx no longer needed */
    row_t r;
    row_clear(&r);

    snprintf(r.f[C_TIMESTAMP], sizeof(r.f[C_TIMESTAMP]),
             "%ld.%09ld", (long)hdr->ts.tv_sec, (long)hdr->ts.tv_usec * 1000);

    snprintf(r.f[C_FRAME_LEN], sizeof(r.f[C_FRAME_LEN]), "%u", hdr->len);

    if (hdr->caplen < sizeof(struct ether_header)) {
        g_current_size += row_print(g_logfile, &r);
        if (g_max_size > 0 && g_current_size >= g_max_size)
            rotate_logs();
        return;
    }

    const struct ether_header *eth = (const struct ether_header *)pkt;
    set_mac(&r, C_ETH_SRC, eth->ether_shost);
    set_mac(&r, C_ETH_DST, eth->ether_dhost);

    uint16_t etype         = ntohs(eth->ether_type);
    const uint8_t *payload = pkt + sizeof(struct ether_header);
    int            plen    = (int)hdr->caplen - (int)sizeof(struct ether_header);

    snprintf(r.f[C_ETH_TYPE], sizeof(r.f[C_ETH_TYPE]), "0x%04x", etype);

    if (etype == 0x8100 && plen >= 4) {
        etype    = parse_vlan(&r, payload, plen);
        payload += 4;
        plen    -= 4;
    }

    switch (etype) {
        case ETHERTYPE_IP:   parse_ipv4(&r, payload, plen); break;
        case ETHERTYPE_ARP:  parse_arp(&r,  payload, plen); break;
    }

    g_current_size += row_print(g_logfile, &r);
    if (hdr->ts.tv_sec != g_last_flush) {
        fflush(g_logfile);
        g_last_flush = hdr->ts.tv_sec;
    }
    if (g_max_size > 0 && g_current_size >= g_max_size)
        rotate_logs();
}

/*************** Signal handler ***************/

static void handle_signal(int sig)
{
    (void)sig;
    if (g_handle) pcap_breakloop(g_handle);
}

/*************** Entry point ***************/
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    /*************** Detect existing rotated logs ***************/
    {
        char probe[600];
        g_rotate_index = 0;
        for (;;) {
            snprintf(probe, sizeof(probe), "%s.%d",
                     g_log_path, g_rotate_index + 1);
            struct stat st;
            if (stat(probe, &st) != 0) break;
            g_rotate_index++;
        }
    }

    g_logfile = open_logfile(g_log_path);
    if (!g_logfile) return EXIT_FAILURE;

    /* Increase stdio buffer (important for throughput) */
    setvbuf(g_logfile, NULL, _IOFBF, 1 << 20); // 1 MB buffer

    /* libpcap setup */
    pcap_t *h = pcap_create(iface, errbuf);
    if (!h) {
        fprintf(stderr, "pcap_create(%s) failed: %s\n", iface, errbuf);
        fclose(g_logfile);
        return EXIT_FAILURE;
    }

    if (pcap_set_snaplen(h, SNAPLEN) != 0)
        fprintf(stderr, "snaplen warning: %s\n", pcap_geterr(h));

    if (pcap_set_promisc(h, PROMISC) != 0)
        fprintf(stderr, "promisc warning: %s\n", pcap_geterr(h));

    /* For better burst handling */
    if (pcap_set_timeout(h, 10) != 0)
        fprintf(stderr, "timeout warning: %s\n", pcap_geterr(h));

    /* Larger kernel buffer */
    if (pcap_set_buffer_size(h, 16 * 1024 * 1024) != 0)
        fprintf(stderr, "buffer warning: %s\n", pcap_geterr(h));

    /* Avoids internal batching delays */
    if (pcap_set_immediate_mode(h, 1) != 0)
        fprintf(stderr, "immediate mode warning: %s\n", pcap_geterr(h));

    int rc = pcap_activate(h);
    if (rc < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(h));
        pcap_close(h);
        fclose(g_logfile);
        return EXIT_FAILURE;
    } else if (rc > 0) {
        fprintf(stderr, "pcap_activate warning: %s\n", pcap_geterr(h));
    }

    g_handle = h;

    /* Validate link type */
    if (pcap_datalink(g_handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface %s is not Ethernet\n", iface);
        pcap_close(g_handle);
        fclose(g_logfile);
        return EXIT_FAILURE;
    }

    /* Apply BPF filter */
    if (strlen(BPF_FILTER) > 0) {
        struct bpf_program fp;
        if (pcap_compile(g_handle, &fp, BPF_FILTER, 1,
                         PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(g_handle, &fp) < 0) {
            fprintf(stderr, "BPF filter error: %s\n",
                    pcap_geterr(g_handle));
            pcap_close(g_handle);
            fclose(g_logfile);
            return EXIT_FAILURE;
        }
        pcap_freecode(&fp);
    }

    /* Signals */
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stderr, "[*] Capturing on %s — Ctrl+C to stop\n", iface);

    /* Capture loop */
    pcap_loop(g_handle, 0, packet_handler, NULL);

    pcap_close(g_handle);
    fclose(g_logfile);

    fprintf(stderr, "[*] Done.\n");
    return EXIT_SUCCESS;
}
