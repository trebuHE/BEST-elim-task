#include "detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERTICAL_SCAN_THRESHOLD 15
#define TRACKER_HASH_SIZE 512

typedef struct host_pair_tracker {
    char      src_ip[MAX_IP_STR_LEN];
    char      dst_ip[MAX_IP_STR_LEN];
    uint16_t *scanned_ports;
    size_t    port_count;
    size_t    port_cap;
    bool      alerted;
    struct host_pair_tracker *next;
} host_pair_tracker_t;

struct threat_detector {
    threat_alert_t      *alerts;
    size_t               alert_count;
    size_t               alert_cap;

    /* Threat 2: Vertical scan tracking per host pair */
    host_pair_tracker_t *trackers[TRACKER_HASH_SIZE];
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

void threat_detector_process_packet(threat_detector_t *detector, const packet_record_t *pkt) {
    if (!detector || !pkt) return;

    /* Threat 1: Stealth & Malformed TCP scans */
    check_stealth_scans(detector, pkt);

    /* Threat 2: Vertical Port Scan */
    check_vertical_scan(detector, pkt);
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
