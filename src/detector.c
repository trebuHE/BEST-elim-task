#include "detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERTICAL_SCAN_THRESHOLD   15
#define HORIZONTAL_SCAN_THRESHOLD 10
#define TRACKER_HASH_SIZE 512
#define SWEEP_HASH_SIZE   512

typedef struct host_pair_tracker {
    char      src_ip[MAX_IP_STR_LEN];
    char      dst_ip[MAX_IP_STR_LEN];
    uint16_t *scanned_ports;
    size_t    port_count;
    size_t    port_cap;
    bool      alerted;
    struct host_pair_tracker *next;
} host_pair_tracker_t;

typedef struct sweep_tracker {
    char         src_ip[MAX_IP_STR_LEN];
    uint16_t     dst_port;
    proto_type_t protocol;
    char       (*target_ips)[MAX_IP_STR_LEN];
    size_t       target_count;
    size_t       target_cap;
    bool         alerted;
    struct sweep_tracker *next;
} sweep_tracker_t;

struct threat_detector {
    threat_alert_t      *alerts;
    size_t               alert_count;
    size_t               alert_cap;

    /* Threat 2: Vertical scan tracking per host pair */
    host_pair_tracker_t *trackers[TRACKER_HASH_SIZE];

    /* Threat 3: Horizontal sweep tracking per (src_ip, port, proto) */
    sweep_tracker_t     *sweeps[SWEEP_HASH_SIZE];
};

const char *threat_severity_to_string(threat_severity_t sev) {
    switch (sev) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

const char *threat_type_to_string(threat_type_t type) {
    switch (type) {
        case THREAT_STEALTH_SCAN:         return "Stealth / Malformed Scan";
        case THREAT_PORT_SCAN_VERTICAL:   return "Vertical Port Scan";
        case THREAT_PORT_SCAN_HORIZONTAL: return "Horizontal Network Sweep";
        case THREAT_SYN_FLOOD:            return "SYN Flood DoS";
        case THREAT_UDP_FLOOD:            return "UDP Flood / Burst";
        case THREAT_ANOMALOUS_TRAFFIC:    return "Anomalous Traffic";
        default:                          return "Unknown Threat";
    }
}

threat_detector_t *threat_detector_init(void) {
    threat_detector_t *d = calloc(1, sizeof(threat_detector_t));
    if (!d) return NULL;

    d->alert_cap = 32;
    d->alerts = calloc(d->alert_cap, sizeof(threat_alert_t));
    if (!d->alerts) {
        free(d);
        return NULL;
    }
    return d;
}

void threat_detector_free(threat_detector_t *d) {
    if (!d) return;

    for (size_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        host_pair_tracker_t *cur = d->trackers[i];
        while (cur) {
            host_pair_tracker_t *next = cur->next;
            free(cur->scanned_ports);
            free(cur);
            cur = next;
        }
    }

    for (size_t i = 0; i < SWEEP_HASH_SIZE; i++) {
        sweep_tracker_t *cur = d->sweeps[i];
        while (cur) {
            sweep_tracker_t *next = cur->next;
            free(cur->target_ips);
            free(cur);
            cur = next;
        }
    }

    free(d->alerts);
    free(d);
}

static uint32_t hash_host_pair(const char *src, const char *dst) {
    uint32_t h = 5381;
    while (*src) h = ((h << 5) + h) + (unsigned char)*src++;
    while (*dst) h = ((h << 5) + h) + (unsigned char)*dst++;
    return h % TRACKER_HASH_SIZE;
}

static host_pair_tracker_t *find_or_create_tracker(threat_detector_t *d, const char *src, const char *dst) {
    uint32_t idx = hash_host_pair(src, dst);
    host_pair_tracker_t *cur = d->trackers[idx];
    while (cur) {
        if (strncmp(cur->src_ip, src, sizeof(cur->src_ip)) == 0 &&
            strncmp(cur->dst_ip, dst, sizeof(cur->dst_ip)) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    host_pair_tracker_t *node = calloc(1, sizeof(host_pair_tracker_t));
    if (!node) return NULL;
    snprintf(node->src_ip, sizeof(node->src_ip), "%s", src);
    snprintf(node->dst_ip, sizeof(node->dst_ip), "%s", dst);
    node->port_cap = 16;
    node->scanned_ports = malloc(node->port_cap * sizeof(uint16_t));
    if (!node->scanned_ports) {
        free(node);
        return NULL;
    }

    node->next = d->trackers[idx];
    d->trackers[idx] = node;
    return node;
}

static uint32_t hash_sweep(const char *src, uint16_t port, proto_type_t proto) {
    uint32_t h = 5381;
    while (*src) h = ((h << 5) + h) + (unsigned char)*src++;
    h = h ^ ((uint32_t)port << 5) ^ ((uint32_t)proto << 13);
    return h % SWEEP_HASH_SIZE;
}

static sweep_tracker_t *find_or_create_sweep(threat_detector_t *d, const char *src, uint16_t port, proto_type_t proto) {
    uint32_t idx = hash_sweep(src, port, proto);
    sweep_tracker_t *cur = d->sweeps[idx];
    while (cur) {
        if (cur->dst_port == port && cur->protocol == proto &&
            strncmp(cur->src_ip, src, sizeof(cur->src_ip)) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    sweep_tracker_t *node = calloc(1, sizeof(sweep_tracker_t));
    if (!node) return NULL;
    snprintf(node->src_ip, sizeof(node->src_ip), "%s", src);
    node->dst_port = port;
    node->protocol = proto;
    node->target_cap = 16;
    node->target_ips = malloc(node->target_cap * sizeof(*node->target_ips));
    if (!node->target_ips) {
        free(node);
        return NULL;
    }

    node->next = d->sweeps[idx];
    d->sweeps[idx] = node;
    return node;
}

static void record_horizontal_sweep_alert(threat_detector_t *d,
                                          const packet_record_t *pkt,
                                          size_t host_count) {
    for (size_t i = 0; i < d->alert_count; i++) {
        threat_alert_t *a = &d->alerts[i];
        if (a->type == THREAT_PORT_SCAN_HORIZONTAL &&
            a->dst_port == pkt->dst_port &&
            strncmp(a->src_ip, pkt->src_ip, sizeof(a->src_ip)) == 0) {
            
            a->packet_count = host_count;
            a->timestamp = pkt->timestamp;
            snprintf(a->dst_ip, sizeof(a->dst_ip), "%lu target hosts", (unsigned long)host_count);
            snprintf(a->description, sizeof(a->description),
                     "Horizontal sweep (probed port %u across %lu hosts via %s)",
                     pkt->dst_port, (unsigned long)host_count,
                     pkt->protocol == PROTO_TCP ? "TCP SYN" : "UDP");
            return;
        }
    }

    /* Add new alert */
    if (d->alert_count >= d->alert_cap) {
        size_t new_cap = d->alert_cap * 2;
        threat_alert_t *resized = realloc(d->alerts, new_cap * sizeof(threat_alert_t));
        if (!resized) return;
        d->alerts = resized;
        d->alert_cap = new_cap;
    }

    threat_alert_t *new_alert = &d->alerts[d->alert_count++];
    memset(new_alert, 0, sizeof(threat_alert_t));
    new_alert->timestamp = pkt->timestamp;
    new_alert->type = THREAT_PORT_SCAN_HORIZONTAL;
    new_alert->severity = SEV_HIGH;
    snprintf(new_alert->src_ip, sizeof(new_alert->src_ip), "%s", pkt->src_ip);
    snprintf(new_alert->dst_ip, sizeof(new_alert->dst_ip), "%lu target hosts", (unsigned long)host_count);
    new_alert->src_port = pkt->src_port;
    new_alert->dst_port = pkt->dst_port;
    new_alert->protocol = pkt->protocol;
    new_alert->packet_count = host_count;
    snprintf(new_alert->description, sizeof(new_alert->description),
             "Horizontal sweep (probed port %u across %lu hosts via %s)",
             pkt->dst_port, (unsigned long)host_count,
             pkt->protocol == PROTO_TCP ? "TCP SYN" : "UDP");
}

static void add_or_update_alert(threat_detector_t *d,
                                const packet_record_t *pkt,
                                threat_type_t type,
                                threat_severity_t sev,
                                const char *desc_prefix) {
    /* Check if an alert for this threat type and IP pair already exists */
    for (size_t i = 0; i < d->alert_count; i++) {
        threat_alert_t *a = &d->alerts[i];
        if (a->type == type &&
            strncmp(a->src_ip, pkt->src_ip, sizeof(a->src_ip)) == 0 &&
            strncmp(a->dst_ip, pkt->dst_ip, sizeof(a->dst_ip)) == 0) {
            
            a->packet_count++;
            a->timestamp = pkt->timestamp; /* latest occurrence */
            snprintf(a->description, sizeof(a->description),
                     "%s (%lu probes recorded)", desc_prefix, (unsigned long)a->packet_count);
            return;
        }
    }

    /* Expand capacity if needed */
    if (d->alert_count >= d->alert_cap) {
        size_t new_cap = d->alert_cap * 2;
        threat_alert_t *resized = realloc(d->alerts, new_cap * sizeof(threat_alert_t));
        if (!resized) return;
        d->alerts = resized;
        d->alert_cap = new_cap;
    }

    /* Add new alert */
    threat_alert_t *new_alert = &d->alerts[d->alert_count++];
    memset(new_alert, 0, sizeof(threat_alert_t));
    new_alert->timestamp = pkt->timestamp;
    new_alert->type = type;
    new_alert->severity = sev;
    snprintf(new_alert->src_ip, sizeof(new_alert->src_ip), "%s", pkt->src_ip);
    snprintf(new_alert->dst_ip, sizeof(new_alert->dst_ip), "%s", pkt->dst_ip);
    new_alert->src_port = pkt->src_port;
    new_alert->dst_port = pkt->dst_port;
    new_alert->protocol = pkt->protocol;
    new_alert->packet_count = 1;
    snprintf(new_alert->description, sizeof(new_alert->description), "%s", desc_prefix);
}

/*
 * Threat 1: Stealth & Malformed TCP Scans
 * Detects NULL scans (0 flags), XMAS scans (FIN+PSH+URG), and SYN-FIN illegal combos.
 */
static void check_stealth_scans(threat_detector_t *d, const packet_record_t *pkt) {
    if (pkt->protocol != PROTO_TCP) {
        return;
    }

    uint8_t flags = pkt->tcp_flags;

    /* A. NULL Scan (No flags set) */
    if (flags == 0) {
        add_or_update_alert(d, pkt, THREAT_STEALTH_SCAN, SEV_MEDIUM, "TCP NULL scan (no flags set)");
        return;
    }

    /* B. XMAS Scan (FIN, PSH, and URG set) */
    if ((flags & (FLAG_FIN | FLAG_PSH | FLAG_URG)) == (FLAG_FIN | FLAG_PSH | FLAG_URG)) {
        add_or_update_alert(d, pkt, THREAT_STEALTH_SCAN, SEV_HIGH, "TCP XMAS scan (FIN+PSH+URG set)");
        return;
    }

    /* C. SYN-FIN Malformed Combination */
    if ((flags & (FLAG_SYN | FLAG_FIN)) == (FLAG_SYN | FLAG_FIN)) {
        add_or_update_alert(d, pkt, THREAT_STEALTH_SCAN, SEV_HIGH, "TCP SYN-FIN malformed scan");
        return;
    }
}

/*
 * Threat 2: Vertical Port Scan
 * Detects single source scanning >= VERTICAL_SCAN_THRESHOLD distinct ports on a single host.
 */
static void check_vertical_scan(threat_detector_t *d, const packet_record_t *pkt) {
    /* If source port is a well-known service (< 1024), this is a server responding, not a scanner */
    if (pkt->src_port < 1024) {
        return;
    }

    /* For TCP: Only pure SYN packets initiate scans (exclude SYN-ACK responses) */
    if (pkt->protocol == PROTO_TCP) {
        if ((pkt->tcp_flags & FLAG_SYN) == 0 || (pkt->tcp_flags & FLAG_ACK) != 0) {
            return;
        }
    }

    host_pair_tracker_t *tr = find_or_create_tracker(d, pkt->src_ip, pkt->dst_ip);
    if (!tr) return;

    /* Check if dst_port has already been recorded */
    for (size_t i = 0; i < tr->port_count; i++) {
        if (tr->scanned_ports[i] == pkt->dst_port) {
            return;
        }
    }

    /* Record new distinct target port */
    if (tr->port_count >= tr->port_cap) {
        size_t new_cap = tr->port_cap * 2;
        uint16_t *resized = realloc(tr->scanned_ports, new_cap * sizeof(uint16_t));
        if (!resized) return;
        tr->scanned_ports = resized;
        tr->port_cap = new_cap;
    }
    tr->scanned_ports[tr->port_count++] = pkt->dst_port;

    if (tr->port_count >= VERTICAL_SCAN_THRESHOLD) {
        char desc[128];
        snprintf(desc, sizeof(desc), "Vertical port scan (%lu distinct ports probed via %s)",
                 (unsigned long)tr->port_count,
                 pkt->protocol == PROTO_TCP ? "TCP SYN" : "UDP");

        add_or_update_alert(d, pkt, THREAT_PORT_SCAN_VERTICAL, SEV_HIGH, desc);
    }
}

/*
 * Threat 3: Horizontal Port Scan (Network Sweep)
 * Detects single source scanning the same port across >= HORIZONTAL_SCAN_THRESHOLD distinct hosts.
 */
static void check_horizontal_scan(threat_detector_t *d, const packet_record_t *pkt) {
    /* If source port is a well-known service (< 1024), this is a server responding, not a scanner */
    if (pkt->src_port < 1024) {
        return;
    }

    /* For TCP: Only pure SYN packets initiate scans */
    if (pkt->protocol == PROTO_TCP) {
        if ((pkt->tcp_flags & FLAG_SYN) == 0 || (pkt->tcp_flags & FLAG_ACK) != 0) {
            return;
        }
    }

    sweep_tracker_t *sw = find_or_create_sweep(d, pkt->src_ip, pkt->dst_port, pkt->protocol);
    if (!sw) return;

    /* Check if target dst_ip already recorded */
    for (size_t i = 0; i < sw->target_count; i++) {
        if (strncmp(sw->target_ips[i], pkt->dst_ip, MAX_IP_STR_LEN) == 0) {
            return;
        }
    }

    /* Record new distinct target host */
    if (sw->target_count >= sw->target_cap) {
        size_t new_cap = sw->target_cap * 2;
        char (*resized)[MAX_IP_STR_LEN] = realloc(sw->target_ips, new_cap * sizeof(*sw->target_ips));
        if (!resized) return;
        sw->target_ips = resized;
        sw->target_cap = new_cap;
    }
    snprintf(sw->target_ips[sw->target_count++], MAX_IP_STR_LEN, "%s", pkt->dst_ip);

    if (sw->target_count >= HORIZONTAL_SCAN_THRESHOLD) {
        record_horizontal_sweep_alert(d, pkt, sw->target_count);
    }
}

void threat_detector_process_packet(threat_detector_t *detector, const packet_record_t *pkt) {
    if (!detector || !pkt) return;

    /* Threat 1: Stealth & Malformed TCP scans */
    check_stealth_scans(detector, pkt);

    /* Threat 2: Vertical Port Scan */
    check_vertical_scan(detector, pkt);

    /* Threat 3: Horizontal Port Scan (Network Sweep) */
    check_horizontal_scan(detector, pkt);
}

void threat_detector_finalize(threat_detector_t *detector) {
    if (!detector) return;
    /* Will be used for sliding window flushes in subsequent threats */
}

size_t threat_detector_get_alerts(const threat_detector_t *detector, const threat_alert_t **out_alerts) {
    if (!detector || !out_alerts) return 0;
    *out_alerts = detector->alerts;
    return detector->alert_count;
}
