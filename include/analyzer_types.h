#ifndef ANALYZER_TYPES_H
#define ANALYZER_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_IP_STR_LEN INET6_ADDRSTRLEN

/* TCP flag bitmasks */
#define FLAG_FIN 0x01
#define FLAG_SYN 0x02
#define FLAG_RST 0x04
#define FLAG_PSH 0x08
#define FLAG_ACK 0x10
#define FLAG_URG 0x20
#define FLAG_ECE 0x40
#define FLAG_CWR 0x80

/* Protocol identifiers */
typedef enum {
    PROTO_OTHER = 0,
    PROTO_TCP   = 6,
    PROTO_UDP   = 17
} proto_type_t;

/* Normalized parsed packet record passed to analysis consumers */
typedef struct {
    struct timeval timestamp;      /* Packet capture timestamp */
    uint32_t       caplen;         /* Captured wire length */
    uint32_t       wirelen;        /* Original packet length */
    
    int            af;             /* AF_INET or AF_INET6 */
    char           src_ip[MAX_IP_STR_LEN];
    char           dst_ip[MAX_IP_STR_LEN];
    uint32_t       src_ip_v4;      /* Host byte order for fast indexing if IPv4 */
    uint32_t       dst_ip_v4;      /* Host byte order for fast indexing if IPv4 */
    
    uint16_t       src_port;
    uint16_t       dst_port;
    proto_type_t   protocol;       /* PROTO_TCP or PROTO_UDP */

    /* TCP specific fields (valid if protocol == PROTO_TCP) */
    uint8_t        tcp_flags;      /* Bitwise OR of FLAG_* */
    uint32_t       tcp_seq;
    uint32_t       tcp_ack;
    uint16_t       tcp_window;

    /* Payload information */
    uint32_t       payload_len;    /* L4 payload bytes */
} packet_record_t;

/* Summary statistics for PCAP parsing session */
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t other_l4_packets;
    uint64_t dropped_or_corrupt;
    struct timeval start_time;
    struct timeval end_time;
} parser_stats_t;

#endif /* ANALYZER_TYPES_H */
