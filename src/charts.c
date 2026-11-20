#include "charts.h"
#include <cairo.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHART_WIDTH  1000
#define CHART_HEIGHT 600

#define PLOT_LEFT   90.0
#define PLOT_RIGHT  40.0
#define PLOT_TOP    80.0
#define PLOT_BOTTOM 70.0

#define COLOR_BG       0xffffff
#define COLOR_PLOT_BG  0xf9fafb
#define COLOR_BORDER   0xd1d5db
#define COLOR_GRID     0xe5e7eb
#define COLOR_TEXT     0x1f2937
#define COLOR_MUTED    0x6b7280
#define COLOR_TCP      0x2563eb
#define COLOR_UDP      0xea580c

static void set_color(cairo_t *cr, uint32_t rgb) {
    cairo_set_source_rgb(cr,
                         ((rgb >> 16) & 0xff) / 255.0,
                         ((rgb >> 8) & 0xff) / 255.0,
                         (rgb & 0xff) / 255.0);
}

static void draw_label(cairo_t *cr, const char *text, double x, double y,
                       double size, bool bold, uint32_t color, double align) {
    cairo_select_font_face(cr, "sans", CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);

    cairo_text_extents_t extents;
    cairo_text_extents(cr, text, &extents);

    set_color(cr, color);
    cairo_move_to(cr, x - extents.x_advance * align, y);
    cairo_show_text(cr, text);
}

static double nice_axis_max(double value) {
    if (value <= 0.0) {
        return 1.0;
    }

    double magnitude = pow(10.0, floor(log10(value)));
    double normalized = value / magnitude;
    double nice;

    if (normalized <= 1.0) {
        nice = 1.0;
    } else if (normalized <= 1.5) {
        nice = 1.5;
    } else if (normalized <= 2.0) {
        nice = 2.0;
    } else if (normalized <= 2.5) {
        nice = 2.5;
    } else if (normalized <= 3.0) {
        nice = 3.0;
    } else if (normalized <= 4.0) {
        nice = 4.0;
    } else if (normalized <= 5.0) {
        nice = 5.0;
    } else if (normalized <= 6.0) {
        nice = 6.0;
    } else if (normalized <= 8.0) {
        nice = 8.0;
    } else {
        nice = 10.0;
    }

    return nice * magnitude;
}

static double point_x(double plot_left, double plot_width, size_t index, size_t count) {
    if (count <= 1) {
        return plot_left + plot_width / 2.0;
    }
    return plot_left + ((double)index * plot_width) / (double)(count - 1);
}

static void draw_series(cairo_t *cr, const time_bucket_t *series, size_t count,
                        bool tcp, double plot_left, double plot_top,
                        double plot_width, double plot_height, double axis_max) {
    set_color(cr, tcp ? COLOR_TCP : COLOR_UDP);
    cairo_set_line_width(cr, 2.5);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);

    for (size_t i = 0; i < count; i++) {
        double bytes = tcp ? (double)series[i].tcp_bytes : (double)series[i].udp_bytes;
        double x = point_x(plot_left, plot_width, i, count);
        double y = plot_top + plot_height - ((bytes / 1024.0) / axis_max) * plot_height;

        if (i == 0) {
            cairo_move_to(cr, x, y);
        } else {
            cairo_line_to(cr, x, y);
        }
    }
    cairo_stroke(cr);

    if (count <= 60) {
        for (size_t i = 0; i < count; i++) {
            double bytes = tcp ? (double)series[i].tcp_bytes : (double)series[i].udp_bytes;
            double x = point_x(plot_left, plot_width, i, count);
            double y = plot_top + plot_height - ((bytes / 1024.0) / axis_max) * plot_height;

            cairo_arc(cr, x, y, 3.2, 0.0, 2.0 * M_PI);
            cairo_fill(cr);
        }
    }
}

static void draw_legend_entry(cairo_t *cr, double x, double y, uint32_t color, const char *label) {
    set_color(cr, color);
    cairo_set_line_width(cr, 3.0);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_move_to(cr, x, y);
    cairo_line_to(cr, x + 26.0, y);
    cairo_stroke(cr);

    draw_label(cr, label, x + 34.0, y + 4.0, 12.0, false, COLOR_TEXT, 0.0);
}

int charts_generate_throughput(const traffic_stats_t *stats, const char *output_path) {
    if (!stats || !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid throughput chart arguments\n");
        return -1;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                          CHART_WIDTH, CHART_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create chart surface\n");
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    set_color(cr, COLOR_BG);
    cairo_paint(cr);

    draw_label(cr, "Throughput Over Time", PLOT_LEFT, 38.0, 24.0, true, COLOR_TEXT, 0.0);
    draw_label(cr, "TCP and UDP bandwidth per second", PLOT_LEFT, 60.0, 12.0,
               false, COLOR_MUTED, 0.0);

    double plot_left = PLOT_LEFT;
    double plot_top = PLOT_TOP;
    double plot_width = CHART_WIDTH - PLOT_LEFT - PLOT_RIGHT;
    double plot_height = CHART_HEIGHT - PLOT_TOP - PLOT_BOTTOM;
    double plot_bottom = plot_top + plot_height;

    size_t count = 0;
    const time_bucket_t *series = traffic_stats_get_time_series(stats, &count);

    set_color(cr, COLOR_PLOT_BG);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_fill(cr);

    if (!series || count == 0) {
        cairo_set_line_width(cr, 1.0);
        set_color(cr, COLOR_BORDER);
        cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
        cairo_stroke(cr);

        draw_label(cr, "No traffic data", plot_left + plot_width / 2.0,
                   plot_top + plot_height / 2.0, 18.0, true, COLOR_MUTED, 0.5);
        cairo_show_page(cr);
        cairo_destroy(cr);
        cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
        cairo_surface_destroy(surface);

        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG '%s': %s\n",
                    output_path, cairo_status_to_string(status));
            return -1;
        }
        return 0;
    }

    double peak_kbps = 0.0;
    for (size_t i = 0; i < count; i++) {
        double tcp_kbps = (double)series[i].tcp_bytes / 1024.0;
        double udp_kbps = (double)series[i].udp_bytes / 1024.0;
        if (tcp_kbps > peak_kbps) peak_kbps = tcp_kbps;
        if (udp_kbps > peak_kbps) peak_kbps = udp_kbps;
    }
    double axis_max = nice_axis_max(peak_kbps > 0.0 ? peak_kbps * 1.1 : 1.0);

    const int y_divisions = 5;
    for (int i = 0; i <= y_divisions; i++) {
        double value = axis_max * (double)i / (double)y_divisions;
        double y = plot_bottom - ((double)i / (double)y_divisions) * plot_height;

        set_color(cr, COLOR_GRID);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, plot_left, y);
        cairo_line_to(cr, plot_left + plot_width, y);
        cairo_stroke(cr);

        char label[32];
        if (axis_max < 10.0) {
            snprintf(label, sizeof(label), "%.1f", value);
        } else {
            snprintf(label, sizeof(label), "%.0f", value);
        }
        draw_label(cr, label, plot_left - 12.0, y + 4.0, 11.0, false, COLOR_MUTED, 1.0);
    }

    draw_label(cr, "KB/s", plot_left - 12.0, plot_top - 12.0, 11.0, true, COLOR_MUTED, 1.0);

    size_t tick_count = count < 8 ? count : 8;
    if (tick_count < 2) {
        tick_count = 1;
    }

    size_t last_tick_index = (size_t)-1;
    for (size_t t = 0; t < tick_count; t++) {
        size_t index;
        if (tick_count == 1) {
            index = 0;
        } else {
            index = (size_t)llround((double)t * (double)(count - 1) / (double)(tick_count - 1));
        }

        if (index == last_tick_index) {
            continue;
        }
        last_tick_index = index;

        double x = point_x(plot_left, plot_width, index, count);
        char label[32];
        snprintf(label, sizeof(label), "%.0f s", (double)index);
        draw_label(cr, label, x, plot_bottom + 24.0, 11.0, false, COLOR_MUTED, 0.5);

        set_color(cr, COLOR_BORDER);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, x, plot_bottom);
        cairo_line_to(cr, x, plot_bottom + 5.0);
        cairo_stroke(cr);
    }

    draw_label(cr, "Elapsed time (seconds)", plot_left + plot_width / 2.0,
               CHART_HEIGHT - 20.0, 12.0, true, COLOR_MUTED, 0.5);

    cairo_save(cr);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_clip(cr);

    draw_series(cr, series, count, true, plot_left, plot_top, plot_width, plot_height, axis_max);
    draw_series(cr, series, count, false, plot_left, plot_top, plot_width, plot_height, axis_max);

    cairo_restore(cr);

    set_color(cr, COLOR_BORDER);
    cairo_set_line_width(cr, 1.5);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    draw_legend_entry(cr, CHART_WIDTH - PLOT_RIGHT - 160.0, PLOT_TOP - 30.0, COLOR_TCP, "TCP");
    draw_legend_entry(cr, CHART_WIDTH - PLOT_RIGHT - 80.0, PLOT_TOP - 30.0, COLOR_UDP, "UDP");

    cairo_show_page(cr);
    cairo_destroy(cr);

    cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
    cairo_surface_destroy(surface);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PNG '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}

int charts_generate_packet_size_histogram(const traffic_stats_t *stats, const char *output_path) {
    if (!stats || !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid packet size histogram arguments\n");
        return -1;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                          CHART_WIDTH, CHART_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create chart surface\n");
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    set_color(cr, COLOR_BG);
    cairo_paint(cr);

    draw_label(cr, "Packet Size Histogram", PLOT_LEFT, 38.0, 24.0, true, COLOR_TEXT, 0.0);

    const uint64_t *histogram = traffic_stats_get_histogram(stats);
    uint64_t total = 0;
    for (int i = 0; i < HISTO_BIN_COUNT; i++) {
        total += histogram ? histogram[i] : 0;
    }

    char subtitle[96];
    snprintf(subtitle, sizeof(subtitle), "Frame size distribution across %lu packets",
             (unsigned long)total);
    draw_label(cr, subtitle, PLOT_LEFT, 60.0, 12.0, false, COLOR_MUTED, 0.0);

    double plot_left = PLOT_LEFT;
    double plot_top = PLOT_TOP;
    double plot_width = CHART_WIDTH - PLOT_LEFT - PLOT_RIGHT;
    double plot_height = CHART_HEIGHT - PLOT_TOP - PLOT_BOTTOM;
    double plot_bottom = plot_top + plot_height;

    set_color(cr, COLOR_PLOT_BG);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_fill(cr);

    cairo_set_line_width(cr, 1.0);
    set_color(cr, COLOR_BORDER);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    if (!histogram || total == 0) {
        draw_label(cr, "No packet data", plot_left + plot_width / 2.0,
                   plot_top + plot_height / 2.0, 18.0, true, COLOR_MUTED, 0.5);
        cairo_show_page(cr);
        cairo_destroy(cr);
        cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
        cairo_surface_destroy(surface);

        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG '%s': %s\n",
                    output_path, cairo_status_to_string(status));
            return -1;
        }
        return 0;
    }

    uint64_t peak = 0;
    for (int i = 0; i < HISTO_BIN_COUNT; i++) {
        if (histogram[i] > peak) {
            peak = histogram[i];
        }
    }

    double axis_max = nice_axis_max(peak > 0 ? (double)peak * 1.1 : 1.0);

    const int y_divisions = 5;
    for (int i = 0; i <= y_divisions; i++) {
        double value = axis_max * (double)i / (double)y_divisions;
        double y = plot_bottom - ((double)i / (double)y_divisions) * plot_height;

        set_color(cr, COLOR_GRID);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, plot_left, y);
        cairo_line_to(cr, plot_left + plot_width, y);
        cairo_stroke(cr);

        char label[32];
        if (axis_max < 10.0) {
            snprintf(label, sizeof(label), "%.1f", value);
        } else {
            snprintf(label, sizeof(label), "%.0f", value);
        }
        draw_label(cr, label, plot_left - 12.0, y + 4.0, 11.0, false, COLOR_MUTED, 1.0);
    }

    draw_label(cr, "Packets", plot_left - 12.0, plot_top - 12.0, 11.0, true, COLOR_MUTED, 1.0);

    double slot_width = plot_width / (double)HISTO_BIN_COUNT;
    double bar_width = slot_width * 0.58;

    for (int i = 0; i < HISTO_BIN_COUNT; i++) {
        double center = plot_left + slot_width * ((double)i + 0.5);
        double count = (double)histogram[i];
        double bar_height = (count / axis_max) * plot_height;
        double bar_top = plot_bottom - bar_height;

        if (bar_height > 0.0) {
            cairo_set_source_rgba(cr, 0x3b / 255.0, 0x82 / 255.0, 0xf6 / 255.0, 0.88);
            cairo_rectangle(cr, center - bar_width / 2.0, bar_top, bar_width, bar_height);
            cairo_fill(cr);

            set_color(cr, COLOR_TCP);
            cairo_set_line_width(cr, 1.0);
            cairo_rectangle(cr, center - bar_width / 2.0, bar_top, bar_width, bar_height);
            cairo_stroke(cr);
        }

        char value_label[48];
        double percentage = total > 0 ? 100.0 * count / (double)total : 0.0;
        if (histogram[i] > 0) {
            snprintf(value_label, sizeof(value_label), "%lu (%.1f%%)",
                     (unsigned long)histogram[i], percentage);
        } else {
            snprintf(value_label, sizeof(value_label), "0");
        }
        draw_label(cr, value_label, center,
                   bar_height > 0.0 ? bar_top - 8.0 : plot_bottom - 8.0,
                   10.0, false, COLOR_TEXT, 0.5);

        draw_label(cr, HISTO_BIN_LABELS[i], center, plot_bottom + 24.0,
                   10.0, false, COLOR_MUTED, 0.5);
    }

    draw_label(cr, "Packet size bin", plot_left + plot_width / 2.0,
               CHART_HEIGHT - 20.0, 12.0, true, COLOR_MUTED, 0.5);

    cairo_show_page(cr);
    cairo_destroy(cr);

    cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
    cairo_surface_destroy(surface);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PNG '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}

static void draw_legend_box(cairo_t *cr, double x, double y, uint32_t color, const char *label) {
    set_color(cr, color);
    cairo_rectangle(cr, x - 6.0, y - 6.0, 12.0, 12.0);
    cairo_fill(cr);
    draw_label(cr, label, x + 12.0, y + 4.0, 12.0, false, COLOR_TEXT, 0.0);
}

static void volume_unit(double max_bytes, double *divisor, const char **unit) {
    if (max_bytes >= 1024.0 * 1024.0 * 1024.0) {
        *divisor = 1024.0 * 1024.0 * 1024.0;
        *unit = "GB";
    } else if (max_bytes >= 1024.0 * 1024.0) {
        *divisor = 1024.0 * 1024.0;
        *unit = "MB";
    } else if (max_bytes >= 1024.0) {
        *divisor = 1024.0;
        *unit = "KB";
    } else {
        *divisor = 1.0;
        *unit = "B";
    }
}

int charts_generate_top_talkers(const traffic_stats_t *stats, const char *output_path) {
    if (!stats || !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid top talkers chart arguments\n");
        return -1;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                          CHART_WIDTH, CHART_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create chart surface\n");
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    set_color(cr, COLOR_BG);
    cairo_paint(cr);

    draw_label(cr, "Top Talkers", PLOT_LEFT, 38.0, 24.0, true, COLOR_TEXT, 0.0);

    ip_talker_stat_t talkers[10];
    size_t count = traffic_stats_get_top_talkers(stats, talkers, 10);

    char subtitle[96];
    snprintf(subtitle, sizeof(subtitle), "Top %zu endpoints by bytes sent and received", count);
    draw_label(cr, subtitle, PLOT_LEFT, 60.0, 12.0, false, COLOR_MUTED, 0.0);

    double plot_left = 270.0;
    double plot_top = PLOT_TOP;
    double plot_width = CHART_WIDTH - plot_left - PLOT_RIGHT;
    double plot_height = CHART_HEIGHT - PLOT_TOP - PLOT_BOTTOM;
    double plot_bottom = plot_top + plot_height;

    set_color(cr, COLOR_PLOT_BG);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_fill(cr);

    cairo_set_line_width(cr, 1.0);
    set_color(cr, COLOR_BORDER);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    if (count == 0) {
        draw_label(cr, "No talker data", plot_left + plot_width / 2.0,
                   plot_top + plot_height / 2.0, 18.0, true, COLOR_MUTED, 0.5);
        cairo_show_page(cr);
        cairo_destroy(cr);
        cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
        cairo_surface_destroy(surface);

        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG '%s': %s\n",
                    output_path, cairo_status_to_string(status));
            return -1;
        }
        return 0;
    }

    uint64_t peak_bytes = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t total_bytes = talkers[i].bytes_sent + talkers[i].bytes_recv;
        if (total_bytes > peak_bytes) {
            peak_bytes = total_bytes;
        }
    }

    double divisor = 1.0;
    const char *unit = "B";
    volume_unit((double)peak_bytes, &divisor, &unit);

    double axis_max = nice_axis_max(peak_bytes > 0 ? ((double)peak_bytes / divisor) * 1.15 : 1.0);

    const int x_divisions = 5;
    for (int i = 0; i <= x_divisions; i++) {
        double value = axis_max * (double)i / (double)x_divisions;
        double x = plot_left + ((double)i / (double)x_divisions) * plot_width;

        set_color(cr, COLOR_GRID);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, x, plot_top);
        cairo_line_to(cr, x, plot_bottom);
        cairo_stroke(cr);

        char label[32];
        if (axis_max < 10.0) {
            snprintf(label, sizeof(label), "%.1f", value);
        } else {
            snprintf(label, sizeof(label), "%.0f", value);
        }
        draw_label(cr, label, x, plot_bottom + 24.0, 11.0, false, COLOR_MUTED, 0.5);
    }

    char axis_title[64];
    snprintf(axis_title, sizeof(axis_title), "Traffic volume (%s)", unit);
    draw_label(cr, axis_title, plot_left + plot_width / 2.0,
               CHART_HEIGHT - 20.0, 12.0, true, COLOR_MUTED, 0.5);

    double slot_height = plot_height / (double)count;
    double bar_height = slot_height * 0.55;
    if (bar_height > 42.0) {
        bar_height = 42.0;
    }

    for (size_t i = 0; i < count; i++) {
        double center_y = plot_top + slot_height * ((double)i + 0.5);
        double bar_y = center_y - bar_height / 2.0;

        double total_units = (double)(talkers[i].bytes_sent + talkers[i].bytes_recv) / divisor;
        double sent_units = (double)talkers[i].bytes_sent / divisor;

        double total_width = (total_units / axis_max) * plot_width;
        double sent_width = (sent_units / axis_max) * plot_width;
        if (sent_width > total_width) {
            sent_width = total_width;
        }
        double recv_width = total_width - sent_width;

        if (sent_width > 0.0) {
            set_color(cr, COLOR_TCP);
            cairo_rectangle(cr, plot_left, bar_y, sent_width, bar_height);
            cairo_fill(cr);
        }
        if (recv_width > 0.0) {
            set_color(cr, COLOR_UDP);
            cairo_rectangle(cr, plot_left + sent_width, bar_y, recv_width, bar_height);
            cairo_fill(cr);
        }

        set_color(cr, COLOR_BORDER);
        cairo_set_line_width(cr, 0.8);
        cairo_rectangle(cr, plot_left, bar_y, total_width, bar_height);
        cairo_stroke(cr);

        draw_label(cr, talkers[i].ip, plot_left - 12.0, center_y + 4.0,
                   10.0, false, COLOR_TEXT, 1.0);

        char value_label[64];
        if (divisor == 1.0) {
            snprintf(value_label, sizeof(value_label), "%.0f %s",
                     (double)talkers[i].total_bytes, unit);
        } else {
            snprintf(value_label, sizeof(value_label), "%.1f %s",
                     (double)talkers[i].total_bytes / divisor, unit);
        }
        draw_label(cr, value_label, plot_left + total_width + 8.0, center_y + 4.0,
                   10.0, false, COLOR_MUTED, 0.0);
    }

    set_color(cr, COLOR_BORDER);
    cairo_set_line_width(cr, 1.5);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 210.0, PLOT_TOP - 30.0, COLOR_TCP, "Sent");
    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 130.0, PLOT_TOP - 30.0, COLOR_UDP, "Received");

    cairo_show_page(cr);
    cairo_destroy(cr);

    cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
    cairo_surface_destroy(surface);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PNG '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}

static const char *port_service_name(uint16_t port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP";
        case 68: return "DHCP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 162: return "SNMP-Trap";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 465: return "SMTPS";
        case 514: return "Syslog";
        case 587: return "SMTP";
        case 636: return "LDAPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        default: return NULL;
    }
}

static void format_volume_brief(char *buffer, size_t size, uint64_t bytes) {
    double divisor = 1.0;
    const char *unit = "B";
    volume_unit((double)bytes, &divisor, &unit);

    if (divisor == 1.0) {
        snprintf(buffer, size, "%.0f %s", (double)bytes, unit);
    } else {
        snprintf(buffer, size, "%.1f %s", (double)bytes / divisor, unit);
    }
}

int charts_generate_top_ports(const traffic_stats_t *stats, const char *output_path) {
    if (!stats || !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid top ports chart arguments\n");
        return -1;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                          CHART_WIDTH, CHART_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create chart surface\n");
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    set_color(cr, COLOR_BG);
    cairo_paint(cr);

    draw_label(cr, "Top Target Ports", PLOT_LEFT, 38.0, 24.0, true, COLOR_TEXT, 0.0);

    port_stat_t ports[10];
    size_t count = traffic_stats_get_top_ports(stats, ports, 10);

    char subtitle[96];
    snprintf(subtitle, sizeof(subtitle), "Top %zu destination ports by packet count", count);
    draw_label(cr, subtitle, PLOT_LEFT, 60.0, 12.0, false, COLOR_MUTED, 0.0);

    double plot_left = 230.0;
    double plot_top = PLOT_TOP;
    double plot_width = CHART_WIDTH - plot_left - PLOT_RIGHT;
    double plot_height = CHART_HEIGHT - PLOT_TOP - PLOT_BOTTOM;
    double plot_bottom = plot_top + plot_height;

    set_color(cr, COLOR_PLOT_BG);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_fill(cr);

    cairo_set_line_width(cr, 1.0);
    set_color(cr, COLOR_BORDER);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    if (count == 0) {
        draw_label(cr, "No port data", plot_left + plot_width / 2.0,
                   plot_top + plot_height / 2.0, 18.0, true, COLOR_MUTED, 0.5);
        cairo_show_page(cr);
        cairo_destroy(cr);
        cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
        cairo_surface_destroy(surface);

        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG '%s': %s\n",
                    output_path, cairo_status_to_string(status));
            return -1;
        }
        return 0;
    }

    uint64_t peak_packets = 0;
    for (size_t i = 0; i < count; i++) {
        if (ports[i].packet_count > peak_packets) {
            peak_packets = ports[i].packet_count;
        }
    }

    double axis_max = nice_axis_max(peak_packets > 0 ? (double)peak_packets * 1.2 : 1.0);

    const int x_divisions = 5;
    for (int i = 0; i <= x_divisions; i++) {
        double value = axis_max * (double)i / (double)x_divisions;
        double x = plot_left + ((double)i / (double)x_divisions) * plot_width;

        set_color(cr, COLOR_GRID);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, x, plot_top);
        cairo_line_to(cr, x, plot_bottom);
        cairo_stroke(cr);

        char label[32];
        if (axis_max < 10.0) {
            snprintf(label, sizeof(label), "%.1f", value);
        } else {
            snprintf(label, sizeof(label), "%.0f", value);
        }
        draw_label(cr, label, x, plot_bottom + 24.0, 11.0, false, COLOR_MUTED, 0.5);
    }

    draw_label(cr, "Packets", plot_left + plot_width / 2.0,
               CHART_HEIGHT - 20.0, 12.0, true, COLOR_MUTED, 0.5);

    double slot_height = plot_height / (double)count;
    double bar_height = slot_height * 0.55;
    if (bar_height > 42.0) {
        bar_height = 42.0;
    }

    for (size_t i = 0; i < count; i++) {
        double center_y = plot_top + slot_height * ((double)i + 0.5);
        double bar_y = center_y - bar_height / 2.0;
        double bar_width = ((double)ports[i].packet_count / axis_max) * plot_width;

        set_color(cr, ports[i].proto == PROTO_TCP ? COLOR_TCP : COLOR_UDP);
        cairo_rectangle(cr, plot_left, bar_y, bar_width, bar_height);
        cairo_fill(cr);

        set_color(cr, COLOR_BORDER);
        cairo_set_line_width(cr, 0.8);
        cairo_rectangle(cr, plot_left, bar_y, bar_width, bar_height);
        cairo_stroke(cr);

        const char *service = port_service_name(ports[i].port);
        const char *proto = ports[i].proto == PROTO_TCP ? "TCP" : "UDP";
        char port_label[64];
        if (service) {
            snprintf(port_label, sizeof(port_label), "%u/%s %s",
                     ports[i].port, proto, service);
        } else {
            snprintf(port_label, sizeof(port_label), "%u/%s", ports[i].port, proto);
        }
        draw_label(cr, port_label, plot_left - 12.0, center_y + 4.0,
                   10.0, false, COLOR_TEXT, 1.0);

        char volume[32];
        format_volume_brief(volume, sizeof(volume), ports[i].byte_count);

        char value_label[96];
        snprintf(value_label, sizeof(value_label), "%lu pkts (%s)",
                 (unsigned long)ports[i].packet_count, volume);
        draw_label(cr, value_label, plot_left + bar_width + 8.0, center_y + 4.0,
                   10.0, false, COLOR_MUTED, 0.0);
    }

    set_color(cr, COLOR_BORDER);
    cairo_set_line_width(cr, 1.5);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 190.0, PLOT_TOP - 30.0, COLOR_TCP, "TCP");
    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 120.0, PLOT_TOP - 30.0, COLOR_UDP, "UDP");

    cairo_show_page(cr);
    cairo_destroy(cr);

    cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
    cairo_surface_destroy(surface);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PNG '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}

int charts_generate_tcp_flags(const traffic_stats_t *stats, const char *output_path) {
    if (!stats || !output_path || output_path[0] == '\0') {
        fprintf(stderr, "Invalid TCP flag chart arguments\n");
        return -1;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                          CHART_WIDTH, CHART_HEIGHT);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to create chart surface\n");
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);
    cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

    set_color(cr, COLOR_BG);
    cairo_paint(cr);

    draw_label(cr, "TCP Flag Distribution", PLOT_LEFT, 38.0, 24.0, true, COLOR_TEXT, 0.0);

    flag_stats_t flags = traffic_stats_get_flag_stats(stats);

    const char *labels[] = {
        "SYN", "SYN-ACK", "ACK", "PSH-ACK", "FIN-ACK",
        "RST", "NULL", "XMAS", "SYN-FIN", "Other"
    };
    uint64_t values[] = {
        flags.syn, flags.syn_ack, flags.ack, flags.psh_ack, flags.fin_ack,
        flags.rst, flags.null_scan, flags.xmas_scan, flags.syn_fin, flags.other
    };
    uint32_t colors[] = {
        COLOR_TCP, COLOR_TCP, COLOR_TCP, COLOR_TCP, COLOR_TCP,
        COLOR_UDP, 0xdc2626, 0xdc2626, 0xdc2626, 0x9ca3af
    };

    const int bin_count = 10;
    uint64_t total = 0;
    for (int i = 0; i < bin_count; i++) {
        total += values[i];
    }

    char subtitle[96];
    snprintf(subtitle, sizeof(subtitle), "TCP flag and scan signature counts across %lu packets",
             (unsigned long)total);
    draw_label(cr, subtitle, PLOT_LEFT, 60.0, 12.0, false, COLOR_MUTED, 0.0);

    double plot_left = PLOT_LEFT;
    double plot_top = PLOT_TOP;
    double plot_width = CHART_WIDTH - PLOT_LEFT - PLOT_RIGHT;
    double plot_height = CHART_HEIGHT - PLOT_TOP - PLOT_BOTTOM;
    double plot_bottom = plot_top + plot_height;

    set_color(cr, COLOR_PLOT_BG);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_fill(cr);

    cairo_set_line_width(cr, 1.0);
    set_color(cr, COLOR_BORDER);
    cairo_rectangle(cr, plot_left, plot_top, plot_width, plot_height);
    cairo_stroke(cr);

    if (total == 0) {
        draw_label(cr, "No TCP packet data", plot_left + plot_width / 2.0,
                   plot_top + plot_height / 2.0, 18.0, true, COLOR_MUTED, 0.5);
        cairo_show_page(cr);
        cairo_destroy(cr);
        cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
        cairo_surface_destroy(surface);

        if (status != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to write PNG '%s': %s\n",
                    output_path, cairo_status_to_string(status));
            return -1;
        }
        return 0;
    }

    uint64_t peak = 0;
    for (int i = 0; i < bin_count; i++) {
        if (values[i] > peak) {
            peak = values[i];
        }
    }

    double axis_max = nice_axis_max(peak > 0 ? (double)peak * 1.1 : 1.0);

    const int y_divisions = 5;
    for (int i = 0; i <= y_divisions; i++) {
        double value = axis_max * (double)i / (double)y_divisions;
        double y = plot_bottom - ((double)i / (double)y_divisions) * plot_height;

        set_color(cr, COLOR_GRID);
        cairo_set_line_width(cr, 1.0);
        cairo_move_to(cr, plot_left, y);
        cairo_line_to(cr, plot_left + plot_width, y);
        cairo_stroke(cr);

        char label[32];
        if (axis_max < 10.0) {
            snprintf(label, sizeof(label), "%.1f", value);
        } else {
            snprintf(label, sizeof(label), "%.0f", value);
        }
        draw_label(cr, label, plot_left - 12.0, y + 4.0, 11.0, false, COLOR_MUTED, 1.0);
    }

    draw_label(cr, "Packets", plot_left - 12.0, plot_top - 12.0, 11.0, true, COLOR_MUTED, 1.0);

    double slot_width = plot_width / (double)bin_count;
    double bar_width = slot_width * 0.58;
    if (bar_width > 58.0) {
        bar_width = 58.0;
    }

    for (int i = 0; i < bin_count; i++) {
        double center = plot_left + slot_width * ((double)i + 0.5);
        double count = (double)values[i];
        double bar_height = (count / axis_max) * plot_height;
        double bar_top = plot_bottom - bar_height;

        if (bar_height > 0.0) {
            set_color(cr, colors[i]);
            cairo_rectangle(cr, center - bar_width / 2.0, bar_top, bar_width, bar_height);
            cairo_fill(cr);

            set_color(cr, COLOR_BORDER);
            cairo_set_line_width(cr, 0.8);
            cairo_rectangle(cr, center - bar_width / 2.0, bar_top, bar_width, bar_height);
            cairo_stroke(cr);
        }

        char value_label[48];
        double percentage = 100.0 * count / (double)total;
        if (values[i] > 0) {
            snprintf(value_label, sizeof(value_label), "%lu (%.1f%%)",
                     (unsigned long)values[i], percentage);
        } else {
            snprintf(value_label, sizeof(value_label), "0");
        }
        draw_label(cr, value_label, center,
                   bar_height > 0.0 ? bar_top - 8.0 : plot_bottom - 8.0,
                   9.5, false, COLOR_TEXT, 0.5);

        draw_label(cr, labels[i], center, plot_bottom + 24.0,
                   10.0, false, COLOR_MUTED, 0.5);
    }

    draw_label(cr, "TCP flag / scan signature", plot_left + plot_width / 2.0,
               CHART_HEIGHT - 20.0, 12.0, true, COLOR_MUTED, 0.5);

    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 390.0, PLOT_TOP - 30.0, COLOR_TCP, "Normal");
    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 300.0, PLOT_TOP - 30.0, COLOR_UDP, "Reset");
    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 210.0, PLOT_TOP - 30.0, 0xdc2626, "Anomalous");
    draw_legend_box(cr, CHART_WIDTH - PLOT_RIGHT - 100.0, PLOT_TOP - 30.0, 0x9ca3af, "Other");

    cairo_show_page(cr);
    cairo_destroy(cr);

    cairo_status_t status = cairo_surface_write_to_png(surface, output_path);
    cairo_surface_destroy(surface);

    if (status != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PNG '%s': %s\n",
                output_path, cairo_status_to_string(status));
        return -1;
    }

    return 0;
}
