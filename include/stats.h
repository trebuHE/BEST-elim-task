#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stddef.h>
#include "analyzer_types.h"

#define HISTO_BIN_COUNT 7
extern const char *const HISTO_BIN_LABELS[HISTO_BIN_COUNT];

/* Time-sliced throughput metric (1-second intervals) */
typedef struct {
    uint64_t timestamp_sec;
    uint64_t total_bytes;
    uint64_t total_pkts;
    uint64_t tcp_bytes;
    uint64_t tcp_pkts;
    uint64_t udp_bytes;
    uint64_t udp_pkts;
} time_bucket_t;

/* IP talker statistics */
typedef struct {
    char ip[MAX_IP_STR_LEN];
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t pkts_sent;
    uint64_t pkts_recv;
    uint64_t total_bytes;
    uint64_t total_pkts;
} ip_talker_stat_t;

/* Destination port statistics */
typedef struct {
    uint16_t port;
    proto_type_t proto;
    uint64_t packet_count;
    uint64_t byte_count;
} port_stat_t;

/* TCP flag distribution */
typedef struct {
    uint64_t syn;
    uint64_t syn_ack;
    uint64_t ack;
    uint64_t psh_ack;
    uint64_t fin_ack;
    uint64_t rst;
    uint64_t null_scan;  /* flags == 0 */
    uint64_t xmas_scan;  /* FIN | PSH | URG */
    uint64_t syn_fin;    /* SYN | FIN */
    uint64_t other;
} flag_stats_t;

/* Opaque container for traffic aggregator */
typedef struct traffic_stats traffic_stats_t;

/* Allocate and initialize aggregator */
traffic_stats_t *traffic_stats_init(void);

/* Free aggregator and all internal data structures */
void traffic_stats_free(traffic_stats_t *stats);

/* Packet handler callback compatible with pcap_parser */
void traffic_stats_process_packet(const packet_record_t *pkt, void *user_data);

/* Retrieve time-series data */
const time_bucket_t *traffic_stats_get_time_series(const traffic_stats_t *stats, size_t *count);

/* Retrieve histogram bin counts (HISTO_BIN_COUNT entries) */
const uint64_t *traffic_stats_get_histogram(const traffic_stats_t *stats);

/* Retrieve flag statistics */
flag_stats_t traffic_stats_get_flag_stats(const traffic_stats_t *stats);

/* Retrieve top N talkers sorted descending by total_bytes */
size_t traffic_stats_get_top_talkers(const traffic_stats_t *stats, ip_talker_stat_t *out_talkers, size_t max_count);

/* Retrieve top N destination ports sorted descending by packet_count */
size_t traffic_stats_get_top_ports(const traffic_stats_t *stats, port_stat_t *out_ports, size_t max_count);

/* Get aggregate counts */
uint64_t traffic_stats_get_total_packets(const traffic_stats_t *stats);
uint64_t traffic_stats_get_total_bytes(const traffic_stats_t *stats);
uint64_t traffic_stats_get_tcp_packets(const traffic_stats_t *stats);
uint64_t traffic_stats_get_udp_packets(const traffic_stats_t *stats);

#endif /* STATS_H */
