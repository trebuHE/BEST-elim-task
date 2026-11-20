#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "analyzer_types.h"
#include "pcap_parser.h"

static void packet_printer_cb(const packet_record_t *pkt, void *user_data) {
    (void)user_data;
    /* Optional verbose debug display if needed */
    (void)pkt;
}

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] <file.pcap>\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help            Show this help message\n");
    printf("  -v, --verbose         Enable verbose packet stream output\n");
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"help",    no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    bool verbose = false;
    int opt = 0;
    while ((opt = getopt_long(argc, argv, "hv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
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

    printf("[*] Analyzing PCAP file: %s\n", pcap_file);

    int ret = pcap_parser_process_file(pcap_file,
                                       verbose ? packet_printer_cb : NULL,
                                       NULL,
                                       &stats,
                                       errbuf,
                                       sizeof(errbuf));

    if (ret != 0) {
        fprintf(stderr, "[-] Parsing failed: %s\n", errbuf);
        return 1;
    }

    double duration = (stats.end_time.tv_sec - stats.start_time.tv_sec) +
                      (stats.end_time.tv_usec - stats.start_time.tv_usec) / 1000000.0;
    if (duration < 0) duration = 0.0;

    printf("[+] Successfully parsed PCAP:\n");
    printf("    - Total packets:      %lu\n", (unsigned long)stats.total_packets);
    printf("    - Total volume:       %.2f KB (%lu bytes)\n",
           stats.total_bytes / 1024.0, (unsigned long)stats.total_bytes);
    printf("    - IPv4 packets:       %lu\n", (unsigned long)stats.ipv4_packets);
    printf("    - IPv6 packets:       %lu\n", (unsigned long)stats.ipv6_packets);
    printf("    - TCP packets:        %lu\n", (unsigned long)stats.tcp_packets);
    printf("    - UDP packets:        %lu\n", (unsigned long)stats.udp_packets);
    printf("    - Duration:           %.3f seconds\n", duration);
    if (duration > 0.0) {
        printf("    - Average rate:       %.2f packets/s (%.2f KB/s)\n",
               stats.total_packets / duration,
               (stats.total_bytes / 1024.0) / duration);
    }

    return 0;
}
