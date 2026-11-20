#ifndef CHARTS_H
#define CHARTS_H

#include "stats.h"

int charts_generate_throughput(const traffic_stats_t *stats, const char *output_path);
int charts_generate_packet_size_histogram(const traffic_stats_t *stats, const char *output_path);
int charts_generate_top_talkers(const traffic_stats_t *stats, const char *output_path);

#endif /* CHARTS_H */
