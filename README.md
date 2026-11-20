# PCAP Traffic Analyzer

A lightweight, high-performance Linux network analysis tool written in C. It analyzes TCP and UDP traffic from `.pcap` files, computes traffic statistics, detects network anomalies and malicious activity via heuristic inspection, and generates both standalone PNG charts and a comprehensive PDF security report using Cairo.

## Features

- **PCAP Ingestion**:
  - Direct processing of `.pcap` files using `libpcap`.
  - Supports Ethernet (with single and QinQ 802.1Q VLAN tags), Linux Cooked Capture (SLL/SLL2), BSD Loopback, and Raw IP datalinks.
  - Full dissection of IPv4 and IPv6 headers with fragmentation validation.
  - Deep inspection of TCP (flags, sequence/ack numbers, window sizes) and UDP payloads.

- **Traffic Metrics & Aggregator**:
  - **Throughput Over Time**: 1-second interval time-series tracking bandwidth and packet rates (total, TCP, UDP).
  - **Packet Size Histogram**: Standard MTU range distribution (`<64`, `64-127`, `128-255`, `256-511`, `512-1023`, `1024-1518`, `>1518` bytes).
  - **Top Talkers**: Hash table tracking transmission and reception volume per endpoint IP.
  - **Top Target Ports**: Protocol and port ranking for destination traffic.
  - **TCP Flag Distribution**: Granular flag state tracking (`SYN`, `SYN-ACK`, `ACK`, `PSH-ACK`, `FIN-ACK`, `RST`) and anomalous combinations.

- **Threat & Malicious Activity Detection** *(In Progress)*:
  - Vertical and horizontal port scan heuristics.
  - Stealth and malformed scans (`NULL`, `XMAS`, `SYN+FIN`).
  - SYN flood and handshake anomaly detection.
  - UDP flood and amplification burst alerts.

- **Visual Reporting & Charts** *(In Progress)*:
  - **5 Cairo PNG Charts**:
    1. Throughput timeline (KB/s and pps over time)
    2. Packet size histogram
    3. Top talkers (transfer volume per IP)
    4. Top target destination ports
    5. TCP flag distribution
  - **Consolidated PDF Report**: Multi-page report containing executive summary, traffic metrics, threat logs, and embedded charts.

## Dependencies

The project relies on standard Linux system libraries and lightweight readily available packages:

- **GCC** (with C11 / GNU11 support)
- **Make**
- **libpcap** (`libpcap-devel`)
- **Cairo** (`cairo-devel`)
- **glibc** and **zlib**

### Installing Dependencies

#### Fedora

```bash
sudo dnf install -y gcc make pkg-config libpcap-devel cairo-devel
```

#### Debian / Ubuntu

```bash
sudo apt-get update && sudo apt-get install -y build-essential pkg-config libpcap-dev libcairo2-dev
```

#### Arch Linux

```bash
sudo pacman -S base-devel libpcap cairo
```

## Building

To build the executable:

```bash
make
```

This compiles the binary `pcap_analyzer` in the project root.

To clean build artifacts:

```bash
make clean
```

## Running & Testing

### Running against a PCAP file

```bash
./pcap_analyzer [OPTIONS] <capture.pcap>
```

#### Options

- `-v`, `--verbose`: Print detailed packet stream during parsing.
- `-h`, `--help`: Display usage information.

### Running Built-in Tests

The project includes a synthetic PCAP generator (`tests/generate_test_pcap.c`) that creates reproducible test captures with HTTP/HTTPS handshakes, DNS queries, and simulated port scans.

To build and run the test suite:

```bash
make test
```
