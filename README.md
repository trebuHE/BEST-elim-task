# PCAP Traffic Analyzer

A lightweight Linux network analysis tool written in C. It analyzes TCP and UDP traffic from `.pcap` files, computes traffic statistics, detects suspicious activity with heuristic checks, and generates publication-ready PNG charts using Cairo. PDF report generation is planned as the next stage.

## Features

- **PCAP Ingestion**
  - Processes `.pcap` files with `libpcap`.
  - Supports Ethernet (with single and QinQ 802.1Q VLAN tags), Linux Cooked Capture (SLL/SLL2), BSD Loopback, and Raw IP datalinks.
  - Dissects IPv4 and IPv6 headers with fragmentation validation.
  - Extracts TCP flags, sequence/acknowledgment numbers, window sizes, and UDP payload lengths.

- **Traffic Metrics**
  - **Throughput Over Time**: 1-second time-series buckets for total, TCP, and UDP bandwidth.
  - **Packet Size Histogram**: Distribution across standard MTU bins (`<64`, `64-127`, `128-255`, `256-511`, `512-1023`, `1024-1518`, `>1518` bytes).
  - **Top Talkers**: Per-endpoint transmission and reception volume.
  - **Top Target Ports**: Destination port ranking by packet count and byte volume.
  - **TCP Flag Distribution**: Standard flags and suspicious scan signatures.

- **Threat Detection**
  - Stealth and malformed TCP scans (`NULL`, `XMAS`, `SYN+FIN`).
  - Vertical port scans.
  - Horizontal network sweeps.
  - SYN flood and incomplete-handshake DoS.
  - UDP flood and high-rate burst anomalies.

- **PNG Charts**
  - Generated directly with Cairo.
  - Fixed 1000x600 resolution.

- **PDF Report** *(planned)*
  - Multi-page report with executive summary, traffic metrics, threat logs, and embedded charts.

## Detection Heuristics

| Threat | Detection Summary | Severity |
| --- | --- | --- |
| Stealth / Malformed Scan | TCP `NULL`, `XMAS`, or `SYN+FIN` flag combinations | MEDIUM / HIGH |
| Vertical Port Scan | Single source probes at least 15 distinct ports on one target | HIGH |
| Horizontal Network Sweep | Single source probes the same port across at least 10 hosts | HIGH |
| SYN Flood | At least 40 SYNs per target with over 80% unacknowledged | CRITICAL |
| UDP Flood / Burst | At least 50 UDP packets in a high-rate burst to one target | HIGH / CRITICAL |

## Charts

Pass `--charts-dir DIR` to write the following files:

| File | Description |
| --- | --- |
| `throughput_timeline.png` | TCP and UDP bandwidth over time |
| `packet_size_histogram.png` | Packet count by frame-size bin |
| `top_talkers.png` | Top endpoints by sent and received bytes |
| `top_ports.png` | Top destination ports by packet count |
| `tcp_flags.png` | TCP flag and scan-signature distribution |

## Dependencies

- **GCC** with C11 / GNU11 support
- **Make**
- **pkg-config**
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

```bash
make
```

This produces the `pcap_analyzer` executable in the project root.

To remove build artifacts:

```bash
make clean
```

## Usage

```bash
./pcap_analyzer [OPTIONS] <capture.pcap>
```

### Options

- `-h`, `--help`: Display usage information.
- `-v`, `--verbose`: Print the packet stream during parsing.
- `-c`, `--charts-dir DIR`: Write PNG charts into `DIR`, creating it if needed.

### Examples

Analyze a capture and generate charts:

```bash
./pcap_analyzer --charts-dir charts capture.pcap
```

Analyze a capture without charts:

```bash
./pcap_analyzer capture.pcap
```

Verbose packet output:

```bash
./pcap_analyzer -v capture.pcap
```

## Test Capture

The repository includes a synthetic PCAP generator under `tests/`. It creates HTTP/HTTPS handshakes, DNS traffic, and multiple simulated attacks.

```bash
make generate_test_pcap
./generate_test_pcap sample_traffic.pcap
./pcap_analyzer --charts-dir charts sample_traffic.pcap
```

Run the existing test target:

```bash
make test
```
