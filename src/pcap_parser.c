#include "pcap_parser.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#ifndef ETHERTYPE_QINQ
#define ETHERTYPE_QINQ 0x88a8
#endif

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

static bool parse_l4_tcp(const uint8_t *payload, uint32_t len, packet_record_t *pkt) {
    if (len < sizeof(struct tcphdr)) {
        return false;
    }

    const struct tcphdr *tcp = (const struct tcphdr *)payload;
    pkt->protocol   = PROTO_TCP;
    pkt->src_port   = ntohs(tcp->source);
    pkt->dst_port   = ntohs(tcp->dest);
    pkt->tcp_seq    = ntohl(tcp->seq);
    pkt->tcp_ack    = ntohl(tcp->ack_seq);
    pkt->tcp_window = ntohs(tcp->window);

    /* TCP data offset is in 32-bit words */
    uint32_t tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > len) {
        return false;
    }

    /* Extract standard TCP flags */
    uint8_t flags = 0;
    if (tcp->fin) flags |= FLAG_FIN;
    if (tcp->syn) flags |= FLAG_SYN;
    if (tcp->rst) flags |= FLAG_RST;
    if (tcp->psh) flags |= FLAG_PSH;
    if (tcp->ack) flags |= FLAG_ACK;
    if (tcp->urg) flags |= FLAG_URG;
#ifdef __USE_MISC
    if (tcp->res2 & 0x01) flags |= FLAG_ECE;
    if (tcp->res2 & 0x02) flags |= FLAG_CWR;
#endif

    pkt->tcp_flags   = flags;
    pkt->payload_len = len - tcp_hdr_len;
    return true;
}

static bool parse_l4_udp(const uint8_t *payload, uint32_t len, packet_record_t *pkt) {
    if (len < sizeof(struct udphdr)) {
        return false;
    }

    const struct udphdr *udp = (const struct udphdr *)payload;
    pkt->protocol   = PROTO_UDP;
    pkt->src_port   = ntohs(udp->source);
    pkt->dst_port   = ntohs(udp->dest);
    pkt->tcp_flags  = 0;
    pkt->tcp_seq    = 0;
    pkt->tcp_ack    = 0;
    pkt->tcp_window = 0;

    uint32_t udp_len = ntohs(udp->len);
    if (udp_len >= sizeof(struct udphdr) && udp_len <= len) {
        pkt->payload_len = udp_len - sizeof(struct udphdr);
    } else {
        pkt->payload_len = len - sizeof(struct udphdr);
    }

    return true;
}

static bool parse_ipv4(const uint8_t *ip_bytes, uint32_t caplen, packet_record_t *pkt) {
    if (caplen < sizeof(struct iphdr)) {
        return false;
    }

    const struct iphdr *ip = (const struct iphdr *)ip_bytes;
    if (ip->version != 4) {
        return false;
    }

    uint32_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > caplen) {
        return false;
    }

    uint32_t total_len = ntohs(ip->tot_len);
    uint32_t available_l4_len = (caplen < total_len) ? (caplen - ip_hdr_len) : (total_len - ip_hdr_len);

    /* Check if packet is fragmented (not first fragment) */
    uint16_t frag_off = ntohs(ip->frag_off);
    if ((frag_off & 0x1fff) != 0) {
        /* Fragment offset > 0: Cannot reliably extract L4 ports */
        return false;
    }

    pkt->af = AF_INET;
    pkt->src_ip_v4 = ntohl(ip->saddr);
    pkt->dst_ip_v4 = ntohl(ip->daddr);

    struct in_addr src_addr = { .s_addr = ip->saddr };
    struct in_addr dst_addr = { .s_addr = ip->daddr };
    inet_ntop(AF_INET, &src_addr, pkt->src_ip, sizeof(pkt->src_ip));
    inet_ntop(AF_INET, &dst_addr, pkt->dst_ip, sizeof(pkt->dst_ip));

    const uint8_t *l4_bytes = ip_bytes + ip_hdr_len;
    if (ip->protocol == IPPROTO_TCP) {
        return parse_l4_tcp(l4_bytes, available_l4_len, pkt);
    } else if (ip->protocol == IPPROTO_UDP) {
        return parse_l4_udp(l4_bytes, available_l4_len, pkt);
    }

    return false;
}

static bool parse_ipv6(const uint8_t *ip_bytes, uint32_t caplen, packet_record_t *pkt) {
    if (caplen < sizeof(struct ip6_hdr)) {
        return false;
    }

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_bytes;
    if ((ip6->ip6_vfc >> 4) != 6) {
        return false;
    }

    pkt->af = AF_INET6;
    pkt->src_ip_v4 = 0;
    pkt->dst_ip_v4 = 0;

    inet_ntop(AF_INET6, &ip6->ip6_src, pkt->src_ip, sizeof(pkt->src_ip));
    inet_ntop(AF_INET6, &ip6->ip6_dst, pkt->dst_ip, sizeof(pkt->dst_ip));

    uint8_t nexthdr = ip6->ip6_nxt;
    uint32_t offset = sizeof(struct ip6_hdr);
    uint32_t available_l4_len = caplen - offset;

    const uint8_t *l4_bytes = ip_bytes + offset;
    if (nexthdr == IPPROTO_TCP) {
        return parse_l4_tcp(l4_bytes, available_l4_len, pkt);
    } else if (nexthdr == IPPROTO_UDP) {
        return parse_l4_udp(l4_bytes, available_l4_len, pkt);
    }

    return false;
}

static int get_l3_offset_and_type(int datalink, const uint8_t *packet, uint32_t caplen,
                                  uint32_t *l3_offset, uint16_t *ethertype) {
    switch (datalink) {
        case DLT_EN10MB: {
            if (caplen < sizeof(struct ether_header)) return -1;
            const struct ether_header *eth = (const struct ether_header *)packet;
            uint16_t type = ntohs(eth->ether_type);
            uint32_t offset = sizeof(struct ether_header);

            /* Handle single 802.1Q or double (QinQ) VLAN tagging */
            if (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ) {
                if (caplen < offset + 4) return -1;
                type = ntohs(*(const uint16_t *)(packet + offset + 2));
                offset += 4;
                if (type == ETHERTYPE_VLAN && caplen >= offset + 4) {
                    type = ntohs(*(const uint16_t *)(packet + offset + 2));
                    offset += 4;
                }
            }

            *l3_offset = offset;
            *ethertype = type;
            return 0;
        }

        case DLT_LINUX_SLL: {
            /* Linux cooked capture v1: 16-byte header */
            if (caplen < 16) return -1;
            *ethertype = ntohs(*(const uint16_t *)(packet + 14));
            *l3_offset = 16;
            return 0;
        }

        case DLT_LINUX_SLL2: {
            /* Linux cooked capture v2: 20-byte header */
            if (caplen < 20) return -1;
            *ethertype = ntohs(*(const uint16_t *)(packet + 0));
            *l3_offset = 20;
            return 0;
        }

        case DLT_NULL:
        case DLT_LOOP: {
            /* BSD loopback: 4-byte family */
            if (caplen < 4) return -1;
            uint32_t family = *(const uint32_t *)packet;
            *l3_offset = 4;
            if (family == 2) {
                *ethertype = ETHERTYPE_IP;
            } else if (family == 24 || family == 28 || family == 30) {
                *ethertype = ETHERTYPE_IPV6;
            } else {
                return -1;
            }
            return 0;
        }

        case DLT_RAW: {
            /* Raw IP: determine version from first nibble */
            if (caplen < 1) return -1;
            uint8_t version = (packet[0] >> 4);
            *l3_offset = 0;
            if (version == 4) {
                *ethertype = ETHERTYPE_IP;
            } else if (version == 6) {
                *ethertype = ETHERTYPE_IPV6;
            } else {
                return -1;
            }
            return 0;
        }

        default:
            return -1;
    }
}

int pcap_parser_process_file(const char *pcap_path,
                             packet_handler_fn handler,
                             void *user_data,
                             parser_stats_t *session_stats,
                             char *errbuf,
                             size_t errbuf_size) {
    if (!pcap_path || !errbuf || errbuf_size == 0) {
        return -1;
    }

    char pcap_err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_offline(pcap_path, pcap_err);
    if (!handle) {
        snprintf(errbuf, errbuf_size, "Failed to open PCAP '%s': %s", pcap_path, pcap_err);
        return -1;
    }

    int datalink = pcap_datalink(handle);

    parser_stats_t local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    struct pcap_pkthdr *header = NULL;
    const uint8_t *packet = NULL;
    int res = 0;
    bool first_packet = true;

    while ((res = pcap_next_ex(handle, &header, &packet)) == 1) {
        local_stats.total_packets++;
        local_stats.total_bytes += header->len;

        if (first_packet) {
            local_stats.start_time = header->ts;
            local_stats.end_time = header->ts;
            first_packet = false;
        } else {
            if (timercmp(&header->ts, &local_stats.start_time, <)) {
                local_stats.start_time = header->ts;
            }
            if (timercmp(&header->ts, &local_stats.end_time, >)) {
                local_stats.end_time = header->ts;
            }
        }

        uint32_t l3_offset = 0;
        uint16_t ethertype = 0;
        if (get_l3_offset_and_type(datalink, packet, header->caplen, &l3_offset, &ethertype) != 0 ||
            l3_offset >= header->caplen) {
            local_stats.dropped_or_corrupt++;
            continue;
        }

        packet_record_t record;
        memset(&record, 0, sizeof(record));
        record.timestamp = header->ts;
        record.caplen    = header->caplen;
        record.wirelen   = header->len;

        bool parsed = false;
        const uint8_t *l3_bytes = packet + l3_offset;
        uint32_t l3_caplen = header->caplen - l3_offset;

        if (ethertype == ETHERTYPE_IP) {
            local_stats.ipv4_packets++;
            parsed = parse_ipv4(l3_bytes, l3_caplen, &record);
        } else if (ethertype == ETHERTYPE_IPV6) {
            local_stats.ipv6_packets++;
            parsed = parse_ipv6(l3_bytes, l3_caplen, &record);
        }

        if (parsed) {
            if (record.protocol == PROTO_TCP) {
                local_stats.tcp_packets++;
            } else if (record.protocol == PROTO_UDP) {
                local_stats.udp_packets++;
            }

            if (handler) {
                handler(&record, user_data);
            }
        } else {
            local_stats.other_l4_packets++;
        }
    }

    if (res == -1) {
        snprintf(errbuf, errbuf_size, "Error reading packets: %s", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);

    if (session_stats) {
        *session_stats = local_stats;
    }

    return 0;
}
