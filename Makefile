CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -std=gnu11 -Iinclude
CAIRO_CFLAGS := $(shell pkg-config --cflags cairo)
CAIRO_LIBS := $(shell pkg-config --libs cairo)
LIBS := -lpcap $(CAIRO_LIBS) -lm

SRCDIR := src
INCDIR := include
BUILDDIR := build
BIN := pcap_analyzer

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRCS))

TEST_GEN_SRC := tests/generate_test_pcap.c
TEST_GEN_BIN := generate_test_pcap

.PHONY: all clean test

all: $(BIN)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(CAIRO_CFLAGS) -c $< -o $@

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

$(TEST_GEN_BIN): $(TEST_GEN_SRC)
	$(CC) $(CFLAGS) $< -lpcap -o $@

test: $(BIN) $(TEST_GEN_BIN)
	@echo "=== Running Step 1 PCAP Ingestion Test ==="
	./$(TEST_GEN_BIN) sample_traffic.pcap
	./$(BIN) sample_traffic.pcap
	@rm -f sample_traffic.pcap

clean:
	rm -rf $(BUILDDIR) $(BIN) $(TEST_GEN_BIN) sample_traffic.pcap
