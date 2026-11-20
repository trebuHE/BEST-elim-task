#include "stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *const HISTO_BIN_LABELS[HISTO_BIN_COUNT] = {
    "< 64 B",
    "64-127 B",
    "128-255 B",
    "256-511 B",
    "512-1023 B",
    "1024-1518 B",
    "> 1518 B"
};

#define IP_HASH_SIZE   2048
#define PORT_HASH_SIZE 1024

typedef struct ip_node {
    ip_talker_stat_t stat;
    struct ip_node  *hash_next;
    struct ip_node  *list_next;
} ip_node_t;

typedef struct port_node {
    port_stat_t       stat;
    struct port_node *hash_next;
    struct port_node *list_next;
} port_node_t;

struct traffic_stats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;

    uint64_t size_histogram[HISTO_BIN_COUNT];
    flag_stats_t flag_stats;

    /* Time series */
    time_bucket_t *time_series;
    size_t         time_series_count;
    size_t         time_series_cap;
    uint64_t       base_sec;
    bool           has_base_sec;

    /* IP talkers */
    ip_node_t *ip_buckets[IP_HASH_SIZE];
    ip_node_t *ip_list_head;
    size_t     ip_count;

    /* Destination ports */
    port_node_t *port_buckets[PORT_HASH_SIZE];
    port_node_t *port_list_head;
    size_t       port_count;
};

static uint32_t hash_str(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % IP_HASH_SIZE;
}

static uint32_t hash_port(uint16_t port, proto_type_t proto) {
    return ((uint32_t)port ^ ((uint32_t)proto << 11)) % PORT_HASH_SIZE;
}

traffic_stats_t *traffic_stats_init(void) {
    traffic_stats_t *s = calloc(1, sizeof(traffic_stats_t));
    if (!s) return NULL;

    s->time_series_cap = 64;
    s->time_series = calloc(s->time_series_cap, sizeof(time_bucket_t));
    if (!s->time_series) {
        free(s);
        return NULL;
    }
    return s;
}

void traffic_stats_free(traffic_stats_t *s) {
    if (!s) return;

    free(s->time_series);

    ip_node_t *ip_cur = s->ip_list_head;
    while (ip_cur) {
        ip_node_t *next = ip_cur->list_next;
        free(ip_cur);
        ip_cur = next;
    }

    port_node_t *port_cur = s->port_list_head;
    while (port_cur) {
        port_node_t *next = port_cur->list_next;
        free(port_cur);
        port_cur = next;
    }

    free(s);
}

static ip_node_t *find_or_create_ip(traffic_stats_t *s, const char *ip) {
    uint32_t idx = hash_str(ip);
    ip_node_t *cur = s->ip_buckets[idx];
    while (cur) {
        if (strncmp(cur->stat.ip, ip, sizeof(cur->stat.ip)) == 0) {
            return cur;
        }
        cur = cur->hash_next;
    }

    ip_node_t *node = calloc(1, sizeof(ip_node_t));
    if (!node) return NULL;
    strncpy(node->stat.ip, ip, sizeof(node->stat.ip) - 1);

    node->hash_next = s->ip_buckets[idx];
    s->ip_buckets[idx] = node;

    node->list_next = s->ip_list_head;
    s->ip_list_head = node;
    s->ip_count++;

    return node;
}

static port_node_t *find_or_create_port(traffic_stats_t *s, uint16_t port, proto_type_t proto) {
    uint32_t idx = hash_port(port, proto);
    port_node_t *cur = s->port_buckets[idx];
    while (cur) {
        if (cur->stat.port == port && cur->stat.proto == proto) {
            return cur;
        }
        cur = cur->hash_next;
    }

    port_node_t *node = calloc(1, sizeof(port_node_t));
    if (!node) return NULL;
    node->stat.port = port;
    node->stat.proto = proto;

    node->hash_next = s->port_buckets[idx];
    s->port_buckets[idx] = node;

    node->list_next = s->port_list_head;
    s->port_list_head = node;
    s->port_count++;

    return node;
}

static void record_histogram(traffic_stats_t *s, uint32_t wirelen) {
    if (wirelen < 64) {
        s->size_histogram[0]++;
    } else if (wirelen <= 127) {
        s->size_histogram[1]++;
    } else if (wirelen <= 255) {
        s->size_histogram[2]++;
    } else if (wirelen <= 511) {
        s->size_histogram[3]++;
    } else if (wirelen <= 1023) {
        s->size_histogram[4]++;
    } else if (wirelen <= 1518) {
        s->size_histogram[5]++;
    } else {
        s->size_histogram[6]++;
    }
}

static void record_flags(traffic_stats_t *s, uint8_t flags) {
    /* Check for anomalous or distinct combinations */
    if (flags == 0) {
        s->flag_stats.null_scan++;
    } else if ((flags & (FLAG_FIN | FLAG_PSH | FLAG_URG)) == (FLAG_FIN | FLAG_PSH | FLAG_URG)) {
        s->flag_stats.xmas_scan++;
    } else if ((flags & (FLAG_SYN | FLAG_FIN)) == (FLAG_SYN | FLAG_FIN)) {
        s->flag_stats.syn_fin++;
    } else if (flags == FLAG_SYN) {
        s->flag_stats.syn++;
    } else if (flags == (FLAG_SYN | FLAG_ACK)) {
        s->flag_stats.syn_ack++;
    } else if (flags == FLAG_ACK) {
        s->flag_stats.ack++;
    } else if (flags == (FLAG_PSH | FLAG_ACK)) {
        s->flag_stats.psh_ack++;
    } else if (flags == (FLAG_FIN | FLAG_ACK)) {
        s->flag_stats.fin_ack++;
    } else if (flags & FLAG_RST) {
        s->flag_stats.rst++;
    } else {
        s->flag_stats.other++;
    }
}

static void record_time_series(traffic_stats_t *s, const packet_record_t *pkt) {
    uint64_t sec = pkt->timestamp.tv_sec;
    if (!s->has_base_sec) {
        s->base_sec = sec;
        s->has_base_sec = true;
    }

    if (sec < s->base_sec) {
        /* Disordered capture: fallback to base_sec */
        sec = s->base_sec;
    }

    size_t index = (size_t)(sec - s->base_sec);
    if (index >= s->time_series_cap) {
        size_t new_cap = (index + 1) * 2;
        time_bucket_t *resized = realloc(s->time_series, new_cap * sizeof(time_bucket_t));
        if (!resized) return;

        memset(resized + s->time_series_cap, 0, (new_cap - s->time_series_cap) * sizeof(time_bucket_t));
        s->time_series = resized;
        s->time_series_cap = new_cap;
    }

    if (index >= s->time_series_count) {
        /* Initialize timestamp_sec for any intervening empty seconds */
        for (size_t i = s->time_series_count; i <= index; i++) {
            s->time_series[i].timestamp_sec = s->base_sec + i;
        }
        s->time_series_count = index + 1;
    }

    time_bucket_t *b = &s->time_series[index];
    b->total_bytes += pkt->wirelen;
    b->total_pkts++;
    if (pkt->protocol == PROTO_TCP) {
        b->tcp_bytes += pkt->wirelen;
        b->tcp_pkts++;
    } else if (pkt->protocol == PROTO_UDP) {
        b->udp_bytes += pkt->wirelen;
        b->udp_pkts++;
    }
}

void traffic_stats_process_packet(const packet_record_t *pkt, void *user_data) {
    traffic_stats_t *s = (traffic_stats_t *)user_data;
    if (!s || !pkt) return;

    s->total_packets++;
    s->total_bytes += pkt->wirelen;

    if (pkt->protocol == PROTO_TCP) {
        s->tcp_packets++;
        record_flags(s, pkt->tcp_flags);
    } else if (pkt->protocol == PROTO_UDP) {
        s->udp_packets++;
    }

    record_histogram(s, pkt->wirelen);
    record_time_series(s, pkt);

    /* Track IPs */
    ip_node_t *src_node = find_or_create_ip(s, pkt->src_ip);
    if (src_node) {
        src_node->stat.bytes_sent += pkt->wirelen;
        src_node->stat.pkts_sent++;
        src_node->stat.total_bytes += pkt->wirelen;
        src_node->stat.total_pkts++;
    }

    ip_node_t *dst_node = find_or_create_ip(s, pkt->dst_ip);
    if (dst_node) {
        dst_node->stat.bytes_recv += pkt->wirelen;
        dst_node->stat.pkts_recv++;
        dst_node->stat.total_bytes += pkt->wirelen;
        dst_node->stat.total_pkts++;
    }

    /* Track destination ports */
    port_node_t *port_node = find_or_create_port(s, pkt->dst_port, pkt->protocol);
    if (port_node) {
        port_node->stat.packet_count++;
        port_node->stat.byte_count += pkt->wirelen;
    }
}

const time_bucket_t *traffic_stats_get_time_series(const traffic_stats_t *s, size_t *count) {
    if (!s) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = s->time_series_count;
    return s->time_series;
}

const uint64_t *traffic_stats_get_histogram(const traffic_stats_t *s) {
    return s ? s->size_histogram : NULL;
}

flag_stats_t traffic_stats_get_flag_stats(const traffic_stats_t *s) {
    flag_stats_t zero = {0};
    return s ? s->flag_stats : zero;
}

static int compare_ip_talkers(const void *a, const void *b) {
    const ip_talker_stat_t *ta = (const ip_talker_stat_t *)a;
    const ip_talker_stat_t *tb = (const ip_talker_stat_t *)b;
    if (tb->total_bytes > ta->total_bytes) return 1;
    if (tb->total_bytes < ta->total_bytes) return -1;
    return 0;
}

size_t traffic_stats_get_top_talkers(const traffic_stats_t *s, ip_talker_stat_t *out_talkers, size_t max_count) {
    if (!s || !out_talkers || max_count == 0 || s->ip_count == 0) return 0;

    ip_talker_stat_t *all = malloc(s->ip_count * sizeof(ip_talker_stat_t));
    if (!all) return 0;

    size_t i = 0;
    ip_node_t *cur = s->ip_list_head;
    while (cur && i < s->ip_count) {
        all[i++] = cur->stat;
        cur = cur->list_next;
    }

    qsort(all, i, sizeof(ip_talker_stat_t), compare_ip_talkers);

    size_t copy_count = (i < max_count) ? i : max_count;
    memcpy(out_talkers, all, copy_count * sizeof(ip_talker_stat_t));
    free(all);

    return copy_count;
}

static int compare_ports(const void *a, const void *b) {
    const port_stat_t *pa = (const port_stat_t *)a;
    const port_stat_t *pb = (const port_stat_t *)b;
    if (pb->packet_count > pa->packet_count) return 1;
    if (pb->packet_count < pa->packet_count) return -1;
    return 0;
}

size_t traffic_stats_get_top_ports(const traffic_stats_t *s, port_stat_t *out_ports, size_t max_count) {
    if (!s || !out_ports || max_count == 0 || s->port_count == 0) return 0;

    port_stat_t *all = malloc(s->port_count * sizeof(port_stat_t));
    if (!all) return 0;

    size_t i = 0;
    port_node_t *cur = s->port_list_head;
    while (cur && i < s->port_count) {
        all[i++] = cur->stat;
        cur = cur->list_next;
    }

    qsort(all, i, sizeof(port_stat_t), compare_ports);

    size_t copy_count = (i < max_count) ? i : max_count;
    memcpy(out_ports, all, copy_count * sizeof(port_stat_t));
    free(all);

    return copy_count;
}

uint64_t traffic_stats_get_total_packets(const traffic_stats_t *s) {
    return s ? s->total_packets : 0;
}

uint64_t traffic_stats_get_total_bytes(const traffic_stats_t *s) {
    return s ? s->total_bytes : 0;
}

uint64_t traffic_stats_get_tcp_packets(const traffic_stats_t *s) {
    return s ? s->tcp_packets : 0;
}

uint64_t traffic_stats_get_udp_packets(const traffic_stats_t *s) {
    return s ? s->udp_packets : 0;
}
