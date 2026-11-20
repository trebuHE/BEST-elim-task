#ifndef REPORT_H
#define REPORT_H

#include "analyzer_types.h"
#include "stats.h"
#include "detector.h"

int report_generate_pdf(const char *pcap_path,
                        const parser_stats_t *parser_stats,
                        const traffic_stats_t *stats,
                        const threat_detector_t *detector,
                        const char *output_path);

#endif /* REPORT_H */
