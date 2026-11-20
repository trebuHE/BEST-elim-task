#include "report.h"
#include "charts.h"
#include <cairo.h>
#include <cairo-pdf.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define A4_WIDTH  595.0
#define A4_HEIGHT 842.0

#define MARGIN          42.0
#define CONTENT_LEFT    MARGIN
#define CONTENT_RIGHT   (A4_WIDTH - MARGIN)
#define CONTENT_WIDTH   (A4_WIDTH - 2.0 * MARGIN)
#define CONTENT_TOP     62.0
#define CONTENT_BOTTOM  790.0

#define COLOR_TEXT     0x111827
#define COLOR_MUTED    0x6b7280
#define COLOR_BORDER   0xe5e7eb
#define COLOR_PANEL    0xf3f4f6
#define COLOR_ACCENT   0x2563eb
#define COLOR_GREEN    0x16a34a
#define COLOR_AMBER    0xd97706
#define COLOR_ORANGE   0xea580c
#define COLOR_RED      0xdc2626
#define COLOR_GREEN_BG 0xecfdf3

#define REPORT_CHART_COUNT 5

typedef struct {
    cairo_t   *cr;
    int        page;
    double     y;
    const char *pcap_name;
    time_t     generated_at;
} report_ctx_t;

static void set_color(cairo_t *cr, uint32_t rgb) {
    cairo_set_source_rgb(cr,
                         ((rgb >> 16) & 0xff) / 255.0,
                         ((rgb >> 8) & 0xff) / 255.0,
                         (rgb & 0xff) / 255.0);
}

static void set_font(cairo_t *cr, double size, bool bold) {
    cairo_select_font_face(cr, "sans", CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

static double text_width(cairo_t *cr, const char *text, double size, bool bold) {
    set_font(cr, size, bold);
    cairo_text_extents_t extents;
    cairo_text_extents(cr, text, &extents);
    return extents.x_advance;
}

static void draw_text(cairo_t *cr, const char *text, double x, double y,
                      double size, bool bold, uint32_t color) {
    set_font(cr, size, bold);
    set_color(cr, color);
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, text);
}

static void draw_text_aligned(cairo_t *cr, const char *text, double x, double y,
                              double size, bool bold, uint32_t color, double align) {
    double width = text_width(cr, text, size, bold);
    draw_text(cr, text, x - width * align, y, size, bold, color);
}

static void draw_hline(cairo_t *cr, double x1, double x2, double y,
                       uint32_t color, double line_width) {
    set_color(cr, color);
    cairo_set_line_width(cr, line_width);
    cairo_move_to(cr, x1, y);
    cairo_line_to(cr, x2, y);
    cairo_stroke(cr);
}

static const char *path_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uint32_t severity_color(threat_severity_t severity) {
    switch (severity) {
        case SEV_INFO:     return COLOR_ACCENT;
        case SEV_LOW:      return COLOR_GREEN;
        case SEV_MEDIUM:   return COLOR_AMBER;
        case SEV_HIGH:     return COLOR_ORANGE;
        case SEV_CRITICAL: return COLOR_RED;
        default:           return COLOR_MUTED;
    }
}

static void format_bytes(uint64_t bytes, char *buffer, size_t size) {
    double value = (double)bytes;

    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        snprintf(buffer, size, "%.2f GB", value / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024ULL * 1024ULL) {
        snprintf(buffer, size, "%.2f MB", value / (1024.0 * 1024.0));
    } else if (bytes >= 1024ULL) {
        snprintf(buffer, size, "%.1f KB", value / 1024.0);
    } else {
        snprintf(buffer, size, "%.0f B", value);
    }
}

static void format_timeval(const struct timeval *tv, char *buffer, size_t size) {
    time_t seconds = tv->tv_sec;
    struct tm tm_value;
    localtime_r(&seconds, &tm_value);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_value);
}

static double capture_duration(const parser_stats_t *stats) {
    double duration = (double)(stats->end_time.tv_sec - stats->start_time.tv_sec) +
                      (double)(stats->end_time.tv_usec - stats->start_time.tv_usec) / 1000000.0;
    return duration > 0.0 ? duration : 0.0;
}

static void start_page(report_ctx_t *ctx) {
    if (ctx->page > 0) {
        cairo_show_page(ctx->cr);
    }
    ctx->page++;

    set_color(ctx->cr, 0xffffff);
    cairo_rectangle(ctx->cr, 0.0, 0.0, A4_WIDTH, A4_HEIGHT);
    cairo_fill(ctx->cr);

    draw_text(ctx->cr, "PCAP Traffic Analysis Report", MARGIN, 30.0, 8.5, false, COLOR_MUTED);
    draw_text_aligned(ctx->cr, ctx->pcap_name, CONTENT_RIGHT, 30.0, 8.5, false,
                      COLOR_MUTED, 1.0);
    draw_hline(ctx->cr, MARGIN, CONTENT_RIGHT, 40.0, COLOR_BORDER, 0.8);

    char generated[64];
    struct tm tm_value;
    localtime_r(&ctx->generated_at, &tm_value);
    strftime(generated, sizeof(generated), "Generated %Y-%m-%d %H:%M", &tm_value);

    draw_hline(ctx->cr, MARGIN, CONTENT_RIGHT, A4_HEIGHT - 38.0, COLOR_BORDER, 0.8);
    draw_text(ctx->cr, generated, MARGIN, A4_HEIGHT - 24.0, 7.5, false, COLOR_MUTED);

    char page_label[32];
    snprintf(page_label, sizeof(page_label), "Page %d", ctx->page);
    draw_text_aligned(ctx->cr, page_label, CONTENT_RIGHT, A4_HEIGHT - 24.0, 7.5,
                      false, COLOR_MUTED, 1.0);

    ctx->y = CONTENT_TOP;
}

static void ensure_space(report_ctx_t *ctx, double height) {
    if (ctx->y + height > CONTENT_BOTTOM) {
        start_page(ctx);
    }
}

static void section_title(report_ctx_t *ctx, const char *title) {
    ensure_space(ctx, 34.0);
    draw_text(ctx->cr, title, MARGIN, ctx->y + 12.0, 15.0, true, COLOR_TEXT);
    draw_hline(ctx->cr, MARGIN, CONTENT_RIGHT, ctx->y + 20.0, COLOR_BORDER, 0.8);
    ctx->y += 30.0;
}

static int count_wrapped_lines(cairo_t *cr, const char *text, double width,
                               double size, bool bold) {
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", text);

    set_font(cr, size, bold);

    char line[1024] = "";
    int line_count = 0;
    char *save = NULL;
    char *word = strtok_r(copy, " ", &save);

    while (word) {
        char candidate[1024];
        if (line[0] != '\0') {
            snprintf(candidate, sizeof(candidate), "%s %s", line, word);
        } else {
            snprintf(candidate, sizeof(candidate), "%s", word);
        }

        cairo_text_extents_t extents;
        cairo_text_extents(cr, candidate, &extents);

        if (extents.x_advance > width && line[0] != '\0') {
            line_count++;
            snprintf(line, sizeof(line), "%s", word);
        } else {
            snprintf(line, sizeof(line), "%s", candidate);
        }

        word = strtok_r(NULL, " ", &save);
    }

    if (line[0] != '\0') {
        line_count++;
    }

    return line_count > 0 ? line_count : 1;
}

static double draw_wrapped_text(cairo_t *cr, const char *text, double x, double y,
                                double width, double size, bool bold, uint32_t color,
                                double line_height) {
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", text);

    set_font(cr, size, bold);
    set_color(cr, color);

    char line[1024] = "";
    char *save = NULL;
    char *word = strtok_r(copy, " ", &save);

    while (word) {
        char candidate[1024];
        if (line[0] != '\0') {
            snprintf(candidate, sizeof(candidate), "%s %s", line, word);
        } else {
            snprintf(candidate, sizeof(candidate), "%s", word);
        }

        cairo_text_extents_t extents;
        cairo_text_extents(cr, candidate, &extents);

        if (extents.x_advance > width && line[0] != '\0') {
            cairo_move_to(cr, x, y);
            cairo_show_text(cr, line);
            y += line_height;
            snprintf(line, sizeof(line), "%s", word);
        } else {
            snprintf(line, sizeof(line), "%s", candidate);
        }

        word = strtok_r(NULL, " ", &save);
    }

    if (line[0] != '\0') {
        cairo_move_to(cr, x, y);
        cairo_show_text(cr, line);
        y += line_height;
    }

    return y;
}

static void metric_cards(report_ctx_t *ctx, const parser_stats_t *stats,
                         size_t alert_count) {
    double card_height = 72.0;
    double gap = 10.0;
    int card_count = 4;
    double card_width = (CONTENT_WIDTH - gap * (card_count - 1)) / (double)card_count;

    ensure_space(ctx, card_height + 16.0);

    char packets[32];
    char volume[32];
    char duration[32];
    char alerts[32];
    char duration_value[32];

    snprintf(packets, sizeof(packets), "%lu", (unsigned long)stats->total_packets);
    format_bytes(stats->total_bytes, volume, sizeof(volume));
    snprintf(duration_value, sizeof(duration_value), "%.2f s", capture_duration(stats));
    snprintf(duration, sizeof(duration), "%s", duration_value);
    snprintf(alerts, sizeof(alerts), "%zu", alert_count);

    const char *labels[] = {"Total Packets", "Total Volume", "Duration", "Threat Alerts"};
    const char *values[] = {packets, volume, duration, alerts};
    uint32_t colors[] = {COLOR_TEXT, COLOR_TEXT, COLOR_TEXT,
                         alert_count > 0 ? COLOR_RED : COLOR_GREEN};

    for (int i = 0; i < card_count; i++) {
        double x = MARGIN + (double)i * (card_width + gap);

        set_color(ctx->cr, COLOR_PANEL);
        cairo_rectangle(ctx->cr, x, ctx->y, card_width, card_height);
        cairo_fill(ctx->cr);

        set_color(ctx->cr, COLOR_BORDER);
        cairo_set_line_width(ctx->cr, 0.8);
        cairo_rectangle(ctx->cr, x, ctx->y, card_width, card_height);
        cairo_stroke(ctx->cr);

        draw_text(ctx->cr, labels[i], x + 10.0, ctx->y + 20.0, 8.0, false, COLOR_MUTED);
        draw_text(ctx->cr, values[i], x + 10.0, ctx->y + 52.0, 18.0, true, colors[i]);
    }

    ctx->y += card_height + 16.0;
}

static void kv_row(report_ctx_t *ctx, const char *label, const char *value, bool shaded) {
    ensure_space(ctx, 22.0);

    if (shaded) {
        set_color(ctx->cr, COLOR_PANEL);
        cairo_rectangle(ctx->cr, MARGIN, ctx->y, CONTENT_WIDTH, 20.0);
        cairo_fill(ctx->cr);
    }

    draw_text(ctx->cr, label, MARGIN + 8.0, ctx->y + 14.0, 9.2, true, COLOR_MUTED);
    draw_text(ctx->cr, value, MARGIN + 150.0, ctx->y + 14.0, 9.2, false, COLOR_TEXT);
    ctx->y += 20.0;
}

static void draw_capture_metadata(report_ctx_t *ctx, const parser_stats_t *stats) {
    section_title(ctx, "Capture Metadata");

    char start_time[64];
    char end_time[64];
    format_timeval(&stats->start_time, start_time, sizeof(start_time));
    format_timeval(&stats->end_time, end_time, sizeof(end_time));

    char duration[32];
    snprintf(duration, sizeof(duration), "%.3f seconds", capture_duration(stats));

    char volume[64];
    char volume_brief[32];
    format_bytes(stats->total_bytes, volume_brief, sizeof(volume_brief));
    snprintf(volume, sizeof(volume), "%s (%lu bytes)",
             volume_brief, (unsigned long)stats->total_bytes);

    char avg_rate[64];
    double seconds = capture_duration(stats);
    if (seconds > 0.0) {
        snprintf(avg_rate, sizeof(avg_rate), "%.2f packets/s (%.2f KB/s)",
                 (double)stats->total_packets / seconds,
                 ((double)stats->total_bytes / 1024.0) / seconds);
    } else {
        snprintf(avg_rate, sizeof(avg_rate), "n/a");
    }

    char protocols[64];
    snprintf(protocols, sizeof(protocols), "TCP: %lu, UDP: %lu",
             (unsigned long)stats->tcp_packets, (unsigned long)stats->udp_packets);

    char packets[32];
    snprintf(packets, sizeof(packets), "%lu", (unsigned long)stats->total_packets);

    char families[64];
    snprintf(families, sizeof(families), "IPv4: %lu, IPv6: %lu",
             (unsigned long)stats->ipv4_packets, (unsigned long)stats->ipv6_packets);

    char skipped[64];
    snprintf(skipped, sizeof(skipped), "%lu", (unsigned long)stats->dropped_or_corrupt);

    kv_row(ctx, "Capture file", ctx->pcap_name, false);
    kv_row(ctx, "Start time", start_time, true);
    kv_row(ctx, "End time", end_time, false);
    kv_row(ctx, "Duration", duration, true);
    kv_row(ctx, "Total packets", packets, false);
    kv_row(ctx, "Protocol breakdown", protocols, true);
    kv_row(ctx, "Total volume", volume, false);
    kv_row(ctx, "Average rate", avg_rate, true);
    kv_row(ctx, "IP families", families, false);
    kv_row(ctx, "Skipped / malformed", skipped, true);

    ctx->y += 8.0;
}

static void draw_security_summary(report_ctx_t *ctx, const threat_detector_t *detector) {
    section_title(ctx, "Security Summary");

    const threat_alert_t *alerts = NULL;
    size_t alert_count = threat_detector_get_alerts(detector, &alerts);

    if (alert_count == 0) {
        ensure_space(ctx, 44.0);

        set_color(ctx->cr, COLOR_GREEN_BG);
        cairo_rectangle(ctx->cr, MARGIN, ctx->y, CONTENT_WIDTH, 38.0);
        cairo_fill(ctx->cr);

        draw_text(ctx->cr, "No malicious or suspicious activity detected.",
                  MARGIN + 12.0, ctx->y + 24.0, 10.0, true, COLOR_GREEN);
        ctx->y += 48.0;
        return;
    }

    size_t severity_counts[5] = {0};
    for (size_t i = 0; i < alert_count; i++) {
        if (alerts[i].severity < 5) {
            severity_counts[alerts[i].severity]++;
        }
    }

    ensure_space(ctx, 60.0);

    char summary[96];
    snprintf(summary, sizeof(summary), "%zu threat alert%s detected.",
             alert_count, alert_count == 1 ? "" : "s");
    draw_text(ctx->cr, summary, MARGIN, ctx->y + 12.0, 10.0, true, COLOR_TEXT);
    ctx->y += 22.0;

    draw_text(ctx->cr, "Severity breakdown", MARGIN, ctx->y + 10.0, 8.5, true, COLOR_MUTED);
    ctx->y += 18.0;

    double chip_width = CONTENT_WIDTH / 5.0;
    for (int i = 0; i < 5; i++) {
        int severity = 4 - i;
        double x = MARGIN + (double)i * chip_width;

        set_color(ctx->cr, severity_color((threat_severity_t)severity));
        cairo_rectangle(ctx->cr, x, ctx->y + 2.0, 8.0, 8.0);
        cairo_fill(ctx->cr);

        char label[48];
        snprintf(label, sizeof(label), "%s  %zu",
                 threat_severity_to_string((threat_severity_t)severity),
                 severity_counts[severity]);
        draw_text(ctx->cr, label, x + 13.0, ctx->y + 10.0, 8.3, true,
                  severity_color((threat_severity_t)severity));
    }

    ctx->y += 24.0;

    draw_text(ctx->cr, "Detailed findings are listed in the Threat Details section.",
              MARGIN, ctx->y + 8.0, 8.5, false, COLOR_MUTED);
    ctx->y += 18.0;
}

static void draw_chart_image(report_ctx_t *ctx, const char *path, double max_height) {
    ensure_space(ctx, max_height + 10.0);

    cairo_surface_t *image = cairo_image_surface_create_from_png(path);
    if (cairo_surface_status(image) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(image);

        set_color(ctx->cr, COLOR_PANEL);
        cairo_rectangle(ctx->cr, MARGIN, ctx->y, CONTENT_WIDTH, 56.0);
        cairo_fill(ctx->cr);

        draw_text(ctx->cr, "Chart unavailable", MARGIN + 12.0, ctx->y + 32.0,
                  10.0, true, COLOR_MUTED);
        ctx->y += 68.0;
        return;
    }

    double image_width = (double)cairo_image_surface_get_width(image);
    double image_height = (double)cairo_image_surface_get_height(image);
    double scale = CONTENT_WIDTH / image_width;
    if (image_height * scale > max_height) {
        scale = max_height / image_height;
    }

    double draw_width = image_width * scale;
    double draw_height = image_height * scale;
    double x = MARGIN + (CONTENT_WIDTH - draw_width) / 2.0;

    cairo_save(ctx->cr);
    cairo_translate(ctx->cr, x, ctx->y);
    cairo_scale(ctx->cr, scale, scale);
    cairo_set_source_surface(ctx->cr, image, 0.0, 0.0);
    cairo_paint(ctx->cr);
    cairo_restore(ctx->cr);

    cairo_surface_destroy(image);
    ctx->y += draw_height + 12.0;
}

static void draw_alert_block(report_ctx_t *ctx, const threat_alert_t *alert) {
    double description_width = CONTENT_WIDTH - 24.0;
    int lines = count_wrapped_lines(ctx->cr, alert->description, description_width, 9.0, false);
    double block_height = 52.0 + (double)lines * 11.0;

    ensure_space(ctx, block_height + 8.0);

    double top = ctx->y;

    set_color(ctx->cr, COLOR_PANEL);
    cairo_rectangle(ctx->cr, MARGIN, top, CONTENT_WIDTH, block_height);
    cairo_fill(ctx->cr);

    set_color(ctx->cr, severity_color(alert->severity));
    cairo_rectangle(ctx->cr, MARGIN, top, 4.0, block_height);
    cairo_fill(ctx->cr);

    double x = MARGIN + 12.0;
    char severity[32];
    snprintf(severity, sizeof(severity), "%s", threat_severity_to_string(alert->severity));
    draw_text(ctx->cr, severity, x, top + 16.0, 8.5, true,
              severity_color(alert->severity));
    x += text_width(ctx->cr, severity, 8.5, true) + 8.0;

    draw_text(ctx->cr, threat_type_to_string(alert->type), x, top + 16.0, 10.0,
              true, COLOR_TEXT);

    char timestamp[64];
    format_timeval(&alert->timestamp, timestamp, sizeof(timestamp));
    draw_text_aligned(ctx->cr, timestamp, CONTENT_RIGHT - 10.0, top + 16.0, 7.5,
                      false, COLOR_MUTED, 1.0);

    char src[80];
    char dst[96];
    if (alert->src_port > 0) {
        snprintf(src, sizeof(src), "%s:%u", alert->src_ip, alert->src_port);
    } else {
        snprintf(src, sizeof(src), "%s", alert->src_ip);
    }
    if (alert->dst_port > 0 && strchr(alert->dst_ip, ' ') == NULL) {
        snprintf(dst, sizeof(dst), "%s:%u", alert->dst_ip, alert->dst_port);
    } else {
        snprintf(dst, sizeof(dst), "%s", alert->dst_ip);
    }

    char meta[256];
    snprintf(meta, sizeof(meta), "%s -> %s [%s] | %lu packets",
             src, dst,
             alert->protocol == PROTO_TCP ? "TCP" : "UDP",
             (unsigned long)alert->packet_count);
    draw_text(ctx->cr, meta, MARGIN + 12.0, top + 31.0, 8.3, false, COLOR_MUTED);

    draw_wrapped_text(ctx->cr, alert->description, MARGIN + 12.0, top + 46.0,
                      description_width, 9.0, false, COLOR_TEXT, 11.0);

    ctx->y = top + block_height + 8.0;
}

static int compare_alert_severity(const void *a, const void *b) {
    const threat_alert_t *alert_a = (const threat_alert_t *)a;
    const threat_alert_t *alert_b = (const threat_alert_t *)b;
    return (int)alert_b->severity - (int)alert_a->severity;
}

static void draw_alerts_section(report_ctx_t *ctx, const threat_detector_t *detector) {
    const threat_alert_t *alerts = NULL;
    size_t alert_count = threat_detector_get_alerts(detector, &alerts);

    if (alert_count == 0) {
        ensure_space(ctx, 44.0);

        set_color(ctx->cr, COLOR_GREEN_BG);
        cairo_rectangle(ctx->cr, MARGIN, ctx->y, CONTENT_WIDTH, 38.0);
        cairo_fill(ctx->cr);

        draw_text(ctx->cr, "No threat details to report.",
                  MARGIN + 12.0, ctx->y + 24.0, 10.0, true, COLOR_GREEN);
        ctx->y += 48.0;
        return;
    }

    char summary[96];
    snprintf(summary, sizeof(summary), "%zu alert%s, ordered by severity",
             alert_count, alert_count == 1 ? "" : "s");
    draw_text(ctx->cr, summary, MARGIN, ctx->y + 10.0, 8.5, false, COLOR_MUTED);
    ctx->y += 18.0;

    threat_alert_t *sorted = malloc(alert_count * sizeof(threat_alert_t));
    const threat_alert_t *source = alerts;

    if (sorted) {
        memcpy(sorted, alerts, alert_count * sizeof(threat_alert_t));
        qsort(sorted, alert_count, sizeof(threat_alert_t), compare_alert_severity);
        source = sorted;
    }

    for (size_t i = 0; i < alert_count; i++) {
        draw_alert_block(ctx, &source[i]);
    }

    free(sorted);
}

static void draw_title_page(report_ctx_t *ctx, const parser_stats_t *stats,
                            const threat_detector_t *detector) {
    ctx->y += 32.0;

    draw_text(ctx->cr, "Network Traffic Analysis Report", MARGIN, ctx->y,
              25.0, true, COLOR_TEXT);
    ctx->y += 14.0;

    draw_text(ctx->cr, "TCP and UDP traffic, anomaly detection, and threat summary",
              MARGIN, ctx->y, 11.0, false, COLOR_MUTED);
    ctx->y += 38.0;

    const threat_alert_t *alerts = NULL;
    size_t alert_count = threat_detector_get_alerts(detector, &alerts);
    metric_cards(ctx, stats, alert_count);

    draw_capture_metadata(ctx, stats);
    draw_security_summary(ctx, detector);
}

static void draw_charts_pages(report_ctx_t *ctx,
                              const char *throughput_path,
                              const char *histogram_path,
                              const char *talkers_path,
                              const char *ports_path,
                              const char *flags_path,
                              const threat_detector_t *detector) {
    start_page(ctx);
    section_title(ctx, "Traffic Visualizations");
    draw_chart_image(ctx, throughput_path, 306.0);
    draw_chart_image(ctx, histogram_path, 306.0);

    start_page(ctx);
    section_title(ctx, "Top Endpoints and Ports");
    draw_chart_image(ctx, talkers_path, 306.0);
    draw_chart_image(ctx, ports_path, 306.0);

    start_page(ctx);
    section_title(ctx, "TCP Flag Distribution");
    draw_chart_image(ctx, flags_path, 280.0);

    section_title(ctx, "Threat Details");
    draw_alerts_section(ctx, detector);
}

static int generate_report_charts(const char *dir, const traffic_stats_t *stats,
                                  char paths[REPORT_CHART_COUNT][512]) {
    int failures = 0;

    snprintf(paths[0], 512, "%s/throughput_timeline.png", dir);
    snprintf(paths[1], 512, "%s/packet_size_histogram.png", dir);
    snprintf(paths[2], 512, "%s/top_talkers.png", dir);
    snprintf(paths[3], 512, "%s/top_ports.png", dir);
    snprintf(paths[4], 512, "%s/tcp_flags.png", dir);

    if (charts_generate_throughput(stats, paths[0]) != 0) {
        failures++;
    }
    if (charts_generate_packet_size_histogram(stats, paths[1]) != 0) {
        failures++;
    }
    if (charts_generate_top_talkers(stats, paths[2]) != 0) {
        failures++;
    }
    if (charts_generate_top_ports(stats, paths[3]) != 0) {
        failures++;
    }
    if (charts_generate_tcp_flags(stats, paths[4]) != 0) {
        failures++;
    }

    return failures;
}

static void cleanup_report_charts(char paths[REPORT_CHART_COUNT][512], const char *dir) {
    for (int i = 0; i < REPORT_CHART_COUNT; i++) {
        remove(paths[i]);
    }
    rmdir(dir);
}

int report_generate_pdf(const char *pcap_path,
                        const parser_stats_t *parser_stats,
                        const traffic_stats_t *stats,
                        const threat_detector_t *detector,
                        const char *output_path) {
    if (!pcap_path || !parser_stats || !stats || !detector ||
        !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid PDF report arguments\n");
        return -1;
    }

    char temp_template[] = "/tmp/pcap_report_XXXXXX";
    char *temp_dir = mkdtemp(temp_template);
    if (!temp_dir) {
        fprintf(stderr, "Failed to create temporary chart directory\n");
        return -1;
    }

    char chart_paths[REPORT_CHART_COUNT][512];
    int chart_failures = generate_report_charts(temp_dir, stats, chart_paths);
    if (chart_failures > 0) {
        fprintf(stderr, "Warning: %d report chart(s) could not be generated\n",
                chart_failures);
    }

    cairo_surface_t *surface = cairo_pdf_surface_create(output_path, A4_WIDTH, A4_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create PDF surface for '%s': %s\n",
                output_path, cairo_status_to_string(cairo_surface_status(surface)));
        cairo_surface_destroy(surface);
        cleanup_report_charts(chart_paths, temp_dir);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    if (cairo_status(cr) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create PDF drawing context: %s\n",
                cairo_status_to_string(cairo_status(cr)));
        cairo_destroy(cr);
        cairo_surface_destroy(surface);
        cleanup_report_charts(chart_paths, temp_dir);
        return -1;
    }

    report_ctx_t ctx = {
        .cr = cr,
        .page = 0,
        .y = 0.0,
        .pcap_name = path_basename(pcap_path),
        .generated_at = time(NULL)
    };

    start_page(&ctx);
    draw_title_page(&ctx, parser_stats, detector);
    draw_charts_pages(&ctx, chart_paths[0], chart_paths[1], chart_paths[2],
                      chart_paths[3], chart_paths[4], detector);

    cairo_show_page(cr);
    cairo_destroy(cr);
    cairo_surface_finish(surface);

    cairo_status_t status = cairo_surface_status(surface);
    cairo_surface_destroy(surface);

    cleanup_report_charts(chart_paths, temp_dir);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to finalize PDF '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}
