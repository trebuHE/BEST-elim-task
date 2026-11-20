#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include "analyzer_types.h"
#include "pcap_parser.h"
#include "stats.h"
#include "detector.h"
#include "charts.h"

typedef struct {
    traffic_stats_t   *stats;
    threat_detector_t *detector;
    bool               verbose;
} analysis_context_t;

static int ensure_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, 0755) == 0) {
        return 0;
    }
    return -1;
}

static void write_chart(const traffic_stats_t *stats, const char *charts_dir,
                        const char *filename,
                        int (*generate)(const traffic_stats_t *, const char *),
                        const char *description) {
    char chart_path[1024];
    int written = snprintf(chart_path, sizeof(chart_path), "%s/%s", charts_dir, filename);

    if (written < 0 || (size_t)written >= sizeof(chart_path)) {
        fprintf(stderr, "[-] Chart output path is too long\n");
    } else if (generate(stats, chart_path) == 0) {
        printf("[+] Chart saved: %s\n", chart_path);
    } else {
        fprintf(stderr, "[-] Failed to generate %s chart\n", description);
    }
}

static void packet_dispatcher_cb(const packet_record_t *pkt, void *user_data) {
    analysis_context_t *ctx = (analysis_context_t *)user_data;

    traffic_stats_process_packet(pkt, ctx->stats);
    threat_detector_process_packet(ctx->detector, pkt);

    if (ctx->verbose) {
        printf("[%ld.%06ld] %s:%u -> %s:%u [%s] len=%u\n",
               (long)pkt->timestamp.tv_sec, (long)pkt->timestamp.tv_usec,
               pkt->src_ip, pkt->src_port,
               pkt->dst_ip, pkt->dst_port,
               pkt->protocol == PROTO_TCP ? "TCP" : "UDP",
               pkt->wirelen);
    }
}

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] <file.pcap>\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help            Show this help message\n");
    printf("  -v, --verbose         Enable verbose packet stream output\n");
    printf("  -c, --charts-dir DIR  Write PNG charts into DIR\n");
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"help",       no_argument,       0, 'h'},
        {"verbose",    no_argument,       0, 'v'},
        {"charts-dir", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    bool verbose = false;
    const char *charts_dir = NULL;
    int opt = 0;
    while ((opt = getopt_long(argc, argv, "hvc:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            case 'c':
                charts_dir = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: missing input .pcap file.\n");
        print_usage(argv[0]);
        return 1;
    }

    const char *pcap_file = argv[optind];
    char errbuf[512] = {0};
    parser_stats_t stats;

    traffic_stats_t *tstats = traffic_stats_init();
    if (!tstats) {
        fprintf(stderr, "Error: failed to initialize traffic statistics engine.\n");
        return 1;
    }

    threat_detector_t *detector = threat_detector_init();
    if (!detector) {
        fprintf(stderr, "Error: failed to initialize threat detection engine.\n");
        traffic_stats_free(tstats);
        return 1;
    }

    analysis_context_t ctx = {
        .stats = tstats,
        .detector = detector,
        .verbose = verbose
    };

    printf("[*] Analyzing PCAP file: %s\n", pcap_file);

    int ret = pcap_parser_process_file(pcap_file,
                                       packet_dispatcher_cb,
                                       &ctx,
                                       &stats,
                                       errbuf,
                                       sizeof(errbuf));

    if (ret != 0) {
        fprintf(stderr, "[-] Parsing failed: %s\n", errbuf);
        threat_detector_free(detector);
        traffic_stats_free(tstats);
        return 1;
    }

    threat_detector_finalize(detector);

    double duration = (stats.end_time.tv_sec - stats.start_time.tv_sec) +
                      (stats.end_time.tv_usec - stats.start_time.tv_usec) / 1000000.0;
    if (duration < 0) duration = 0.0;

    printf("\n=== Summary Metrics ===\n");
    printf("  - Total packets:        %lu\n", (unsigned long)stats.total_packets);
    printf("  - Total volume:         %.2f KB (%lu bytes)\n",
           stats.total_bytes / 1024.0, (unsigned long)stats.total_bytes);
    printf("  - Protocol breakdown:   TCP: %lu, UDP: %lu\n",
           (unsigned long)stats.tcp_packets, (unsigned long)stats.udp_packets);
    printf("  - Duration:             %.3f seconds\n", duration);
    if (duration > 0.0) {
        printf("  - Average rate:         %.2f packets/s (%.2f KB/s)\n",
               stats.total_packets / duration,
               (stats.total_bytes / 1024.0) / duration);
    }

    /* Top Talkers */
    ip_talker_stat_t top_talkers[5];
    size_t talker_count = traffic_stats_get_top_talkers(tstats, top_talkers, 5);
    printf("\n--- Top %zu Talkers ---\n", talker_count);
    printf("  %-18s %-12s %-12s %-12s\n", "IP Address", "Total Bytes", "Sent (pkts)", "Recv (pkts)");
    for (size_t i = 0; i < talker_count; i++) {
        printf("  %-18s %-12lu %lu (%lu)     %lu (%lu)\n",
               top_talkers[i].ip,
               (unsigned long)top_talkers[i].total_bytes,
               (unsigned long)top_talkers[i].bytes_sent,
               (unsigned long)top_talkers[i].pkts_sent,
               (unsigned long)top_talkers[i].bytes_recv,
               (unsigned long)top_talkers[i].pkts_recv);
    }

    /* Top Destination Ports */
    port_stat_t top_ports[5];
    size_t port_cnt = traffic_stats_get_top_ports(tstats, top_ports, 5);
    printf("\n--- Top %zu Target Ports ---\n", port_cnt);
    printf("  %-10s %-8s %-12s %-12s\n", "Port", "Proto", "Packets", "Bytes");
    for (size_t i = 0; i < port_cnt; i++) {
        printf("  %-10u %-8s %-12lu %-12lu\n",
               top_ports[i].port,
               top_ports[i].proto == PROTO_TCP ? "TCP" : "UDP",
               (unsigned long)top_ports[i].packet_count,
               (unsigned long)top_ports[i].byte_count);
    }

    /* Packet Size Histogram */
    const uint64_t *histo = traffic_stats_get_histogram(tstats);
    printf("\n--- Packet Size Histogram ---\n");
    for (int b = 0; b < HISTO_BIN_COUNT; b++) {
        printf("  %-12s: %lu packets\n", HISTO_BIN_LABELS[b], (unsigned long)histo[b]);
    }

    /* TCP Flags */
    flag_stats_t flags = traffic_stats_get_flag_stats(tstats);
    printf("\n--- TCP Flag Breakdown ---\n");
    printf("  SYN: %lu | SYN-ACK: %lu | ACK: %lu | PSH-ACK: %lu | FIN-ACK: %lu | RST: %lu\n",
           (unsigned long)flags.syn, (unsigned long)flags.syn_ack,
           (unsigned long)flags.ack, (unsigned long)flags.psh_ack,
           (unsigned long)flags.fin_ack, (unsigned long)flags.rst);

    /* Threat Intelligence & Malicious Alerts */
    const threat_alert_t *alerts = NULL;
    size_t alert_count = threat_detector_get_alerts(detector, &alerts);

    printf("\n=== Security Threat Alerts (%zu detected) ===\n", alert_count);
    if (alert_count == 0) {
        printf("  [+] No malicious or suspicious activity detected.\n");
    } else {
        printf("  %-10s %-26s %-16s -> %-16s %s\n",
               "Severity", "Threat Type", "Source IP", "Target IP", "Description");
        for (size_t i = 0; i < alert_count; i++) {
            printf("  [%-7s] %-26s %-16s -> %-16s %s\n",
                   threat_severity_to_string(alerts[i].severity),
                   threat_type_to_string(alerts[i].type),
                   alerts[i].src_ip,
                   alerts[i].dst_ip,
                   alerts[i].description);
        }
    }

    if (charts_dir) {
        if (ensure_directory(charts_dir) != 0) {
            fprintf(stderr, "[-] Cannot create charts directory '%s': %s\n",
                    charts_dir, strerror(errno));
        } else {
            write_chart(tstats, charts_dir, "throughput_timeline.png",
                        charts_generate_throughput, "throughput");
            write_chart(tstats, charts_dir, "packet_size_histogram.png",
                        charts_generate_packet_size_histogram, "packet size histogram");
            write_chart(tstats, charts_dir, "top_talkers.png",
                        charts_generate_top_talkers, "top talkers");
            write_chart(tstats, charts_dir, "top_ports.png",
                        charts_generate_top_ports, "top ports");
            write_chart(tstats, charts_dir, "tcp_flags.png",
                        charts_generate_tcp_flags, "TCP flags");
        }
    }

    threat_detector_free(detector);
    traffic_stats_free(tstats);
    return 0;
}
