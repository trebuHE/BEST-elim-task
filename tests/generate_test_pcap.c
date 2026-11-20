#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

static uint16_t checksum(const void *b, int len) {
    const uint16_t *buf = (const uint16_t *)b;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static void write_packet(pcap_dumper_t *dumper,
                         struct timeval *ts,
                         const char *src_ip_str,
                         const char *dst_ip_str,
                         uint16_t src_port,
                         uint16_t dst_port,
                         uint8_t protocol,
                         uint8_t tcp_flags,
                         uint32_t payload_len) {
    uint8_t buffer[2048] = {0};
    uint32_t offset = 0;

    /* 1. Ethernet Header */
    struct ether_header *eth = (struct ether_header *)buffer;
    memset(eth->ether_dhost, 0xAA, 6);
    memset(eth->ether_shost, 0xBB, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    offset += sizeof(struct ether_header);

    /* 2. IPv4 Header */
    struct iphdr *ip = (struct iphdr *)(buffer + offset);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    uint32_t l4_total = (protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) + payload_len;
    ip->tot_len = htons(sizeof(struct iphdr) + l4_total);
    ip->id = htons(1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = protocol;
    inet_pton(AF_INET, src_ip_str, &ip->saddr);
    inet_pton(AF_INET, dst_ip_str, &ip->daddr);
    ip->check = checksum(ip, sizeof(struct iphdr));
    offset += sizeof(struct iphdr);

    /* 3. Transport Header */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(buffer + offset);
        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
        tcp->seq = htonl(1000);
        tcp->ack_seq = (tcp_flags & TH_ACK) ? htonl(2000) : 0;
        tcp->doff = 5;
        tcp->th_flags = tcp_flags;
        tcp->window = htons(65535);
        offset += sizeof(struct tcphdr);
    } else {
        struct udphdr *udp = (struct udphdr *)(buffer + offset);
        udp->source = htons(src_port);
        udp->dest = htons(dst_port);
        udp->len = htons(sizeof(struct udphdr) + payload_len);
        offset += sizeof(struct udphdr);
    }

    /* 4. Payload fill */
    for (uint32_t i = 0; i < payload_len && (offset + i) < sizeof(buffer); i++) {
        buffer[offset + i] = (uint8_t)('A' + (i % 26));
    }
    offset += payload_len;

    struct pcap_pkthdr hdr;
    hdr.ts = *ts;
    hdr.caplen = offset;
    hdr.len = offset;

    pcap_dump((u_char *)dumper, &hdr, buffer);
}

int main(int argc, char *argv[]) {
    const char *out_path = (argc > 1) ? argv[1] : "sample_traffic.pcap";
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) {
        fprintf(stderr, "Failed to create dead pcap handle\n");
        return 1;
    }

    pcap_dumper_t *dumper = pcap_dump_open(dead, out_path);
    if (!dumper) {
        fprintf(stderr, "Failed to open dump file: %s\n", out_path);
        pcap_close(dead);
        return 1;
    }

    struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 0 };

    /* 1. Simulate TCP HTTP/HTTPS flows */
    for (int i = 0; i < 50; i++) {
        tv.tv_usec += 10000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        /* SYN */
        write_packet(dumper, &tv, "192.168.1.10", "142.250.190.46", 45000 + i, 443, IPPROTO_TCP, TH_SYN, 0);
        /* SYN+ACK */
        write_packet(dumper, &tv, "142.250.190.46", "192.168.1.10", 443, 45000 + i, IPPROTO_TCP, TH_SYN | TH_ACK, 0);
        /* ACK */
        write_packet(dumper, &tv, "192.168.1.10", "142.250.190.46", 45000 + i, 443, IPPROTO_TCP, TH_ACK, 0);
        /* DATA */
        write_packet(dumper, &tv, "192.168.1.10", "142.250.190.46", 45000 + i, 443, IPPROTO_TCP, TH_ACK | TH_PUSH, 512 + (i * 10));
    }

    /* 2. Simulate UDP DNS queries */
    for (int i = 0; i < 30; i++) {
        tv.tv_usec += 15000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        write_packet(dumper, &tv, "192.168.1.15", "8.8.8.8", 53000 + i, 53, IPPROTO_UDP, 0, 64);
        write_packet(dumper, &tv, "8.8.8.8", "192.168.1.15", 53, 53000 + i, IPPROTO_UDP, 0, 128);
    }

    /* 3. Simulate Port Scan from an attacker (SYN scan across ports 20..45) */
    for (int port = 20; port <= 45; port++) {
        tv.tv_usec += 5000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        write_packet(dumper, &tv, "10.0.0.99", "192.168.1.1", 33333, (uint16_t)port, IPPROTO_TCP, TH_SYN, 0);
    }

    /* 4. Threat 1 Simulation: Stealth & Malformed Scans */
    /* 4a. NULL Scan (no flags set) */
    for (int port = 80; port <= 82; port++) {
        tv.tv_usec += 4000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        write_packet(dumper, &tv, "10.0.0.66", "192.168.1.1", 44444, (uint16_t)port, IPPROTO_TCP, 0, 0);
    }

    /* 4b. XMAS Scan (FIN + PSH + URG) */
    for (int port = 135; port <= 139; port++) {
        tv.tv_usec += 4000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        write_packet(dumper, &tv, "10.0.0.77", "192.168.1.1", 55555, (uint16_t)port,
                     IPPROTO_TCP, TH_FIN | TH_PUSH | TH_URG, 0);
    }

    /* 4c. SYN-FIN Malformed Scan */
    for (int port = 21; port <= 23; port++) {
        tv.tv_usec += 4000;
        if (tv.tv_usec >= 1000000) { tv.tv_sec++; tv.tv_usec -= 1000000; }
        write_packet(dumper, &tv, "10.0.0.88", "192.168.1.1", 56666, (uint16_t)port,
                     IPPROTO_TCP, TH_SYN | TH_FIN, 0);
    }

    pcap_dump_close(dumper);
    pcap_close(dead);
    printf("[+] Generated test PCAP: %s\n", out_path);
    return 0;
}
