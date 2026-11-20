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
