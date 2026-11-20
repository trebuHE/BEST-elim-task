#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include "analyzer_types.h"

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} threat_severity_t;

typedef enum {
    THREAT_STEALTH_SCAN = 1,      /* Threat 1: NULL, XMAS, SYN-FIN */
    THREAT_PORT_SCAN_VERTICAL,    /* Threat 2 */
    THREAT_PORT_SCAN_HORIZONTAL,  /* Threat 3 */
    THREAT_SYN_FLOOD,             /* Threat 4 */
    THREAT_UDP_FLOOD,             /* Threat 5 */
    THREAT_ANOMALOUS_TRAFFIC
} threat_type_t;

typedef struct {
    struct timeval    timestamp;
    threat_type_t     type;
    threat_severity_t severity;
    char              src_ip[MAX_IP_STR_LEN];
    char              dst_ip[MAX_IP_STR_LEN];
    uint16_t          src_port;
    uint16_t          dst_port;
    proto_type_t      protocol;
    char              description[128];
    uint64_t          packet_count;
} threat_alert_t;

typedef struct threat_detector threat_detector_t;

/* Initialize threat detection engine */
threat_detector_t *threat_detector_init(void);

/* Free detector and recorded alerts */
void threat_detector_free(threat_detector_t *detector);

/* Process a packet record through heuristic checks */
void threat_detector_process_packet(threat_detector_t *detector, const packet_record_t *pkt);

/* Finalize detection (evaluates any remaining sliding windows or rate limits) */
void threat_detector_finalize(threat_detector_t *detector);

/* Retrieve pointer to alerts array and total alert count */
size_t threat_detector_get_alerts(const threat_detector_t *detector, const threat_alert_t **out_alerts);

/* Helper to convert severity enum to string */
const char *threat_severity_to_string(threat_severity_t sev);

/* Helper to convert threat type enum to string */
const char *threat_type_to_string(threat_type_t type);

#endif /* DETECTOR_H */
