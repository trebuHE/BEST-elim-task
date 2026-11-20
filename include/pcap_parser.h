#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include <stddef.h>
#include "analyzer_types.h"

/* Callback signature for each parsed TCP or UDP packet */
typedef void (*packet_handler_fn)(const packet_record_t *pkt, void *user_data);

/*
 * Reads a .pcap file, parses packets, extracts TCP/UDP records,
 * and calls the provided packet_handler_fn callback for each valid record.
 * Populates session_stats if not NULL.
 *
 * Returns 0 on success, negative value on error with error message in errbuf.
 */
int pcap_parser_process_file(const char *pcap_path,
                             packet_handler_fn handler,
                             void *user_data,
                             parser_stats_t *session_stats,
                             char *errbuf,
                             size_t errbuf_size);

#endif /* PCAP_PARSER_H */
