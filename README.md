---
editor_options: 
  markdown: 
    wrap: 72
---

# NIDS — Network Intrusion Detection System

A Network Intrusion Detection System written in Go, built from scratch
on top of [`gopacket`](https://github.com/google/gopacket). It captures
live traffic on a network interface, maintains per-IP behavioral
statistics over sliding time windows, and flags suspicious patterns
associated with common reconnaissance and flooding attacks.

This is the first phase of a two-layer plan: validate the detection
logic in Go, then reimplement the core in C for low-level systems
practice, and eventually add a Python/scikit-learn layer on top of
exported statistics for ML-based detection.

## Status

🚧 **Go prototype phase.** Architecture is in place (capture,
per-protocol state, threshold-based detection are cleanly separated).
Two known issues are still being fixed:

-   ARP spoofing detection currently overwrites its trusted MAC baseline
    with the attacker's MAC after the first detected conflict, which can
    cause it to miss a second spoof attempt from the same source.
-   DNS amplification detection compares `dnsResponse` and `dnsRequests`
    counters that are currently tracked under different IP keys (the
    responding server's IP vs. the local machine's IP), so the
    comparison doesn't reason about the same entity on both sides.

Detection thresholds are implemented but not yet validated against live
attack traffic from the test VMs.

## Detected attack patterns

| Attack type | Mechanism |
|------------------------------------|------------------------------------|
| TCP SYN flood | `SYN` count minus `ACK` count exceeds threshold over two windows |
| Port scan | Number of distinct destination ports touched exceeds threshold |
| TCP FIN scan/flood | Excessive `FIN` flags |
| TCP NULL scan | Packets with no TCP flags set |
| TCP XMAS scan | Packets with `FIN` + `URG` + `PSH` set simultaneously |
| SSH brute-force | Excessive packets to port 22 |
| ICMP flood | Excessive ICMP packet count |
| UDP flood | Excessive UDP packet count *(currently only counts DNS-carrying UDP packets — see Known Issues)* |
| DNS amplification | DNS responses exceed DNS requests by a threshold *(see Known Issues)* |
| ARP spoofing | A new MAC address is seen replying for an IP that was already bound to a different MAC *(see Known Issues)* |

## How it works

1.  **Capture** — packets are pulled live from a network interface via
    `pcap`, filtered at the kernel level with a BPF filter (excluding
    the local machine and whitelisted IPs), and streamed through a
    buffered channel to a separate processing goroutine.
2.  **Per-IP state** — for each source IP, the IDS maintains a struct
    (`ipInfo`) of counters: SYN/ACK/FIN counts, distinct destination
    ports touched, ICMP/UDP/DNS counts, and the MAC address last seen
    replying via ARP for that IP.
3.  **Sliding window** — state resets every `PERIOD` seconds. The
    previous window (`precMemory`) is kept alongside the current one
    (`memory`), so detection can reason across two consecutive windows
    instead of only the most recent few seconds — this avoids missing
    slow-paced attacks that straddle a window boundary.
4.  **Detection** — after each state update, the relevant counters are
    checked against fixed thresholds. Detection logic (`detect.go`) only
    reads `ipInfo`/`IDS` state — it never touches `gopacket`/`layers`
    types directly, keeping it independent from the capture layer.
5.  **Logging** — detections and periodic traffic summaries (packet
    count, packets/sec) are appended to `ids.log` via a buffered writer,
    flushed on each tick and on shutdown (`Ctrl+C` / `SIGTERM`).

## Architecture

```         
main.go                 -> entry point: setup, event loop (ticker / signal / packet channel)
config.go               -> constants, CLI argument parsing, interface/whitelist/BPF setup
process_and_update.go   -> packet parsing: layer extraction and protocol dispatch
update.go               -> per-IP state updates: counters per protocol, log writing
types.go                -> shared types: IDS, ipInfo
detect.go               -> threshold-based attack detection (reads state only)
```

### Key design decisions

-   **Go prototype, C reimplementation later.** Go (with `gopacket`) was
    chosen for fast iteration on detection logic; the validated core
    will later be ported to C.
-   **Whitelist file.** Known/trusted IPs (e.g. the local gateway) are
    excluded from capture entirely via a BPF filter built from
    `whitelist.txt`, rather than filtered out after the fact.
-   **BPF filters.** Capture is filtered at the kernel level to reduce
    unnecessary userspace processing — the local IP and all whitelisted
    IPs are excluded as packet *sources* before any Go code runs.
-   **Two-window memory model.** Keeping both the current and previous
    statistics window lets detection reason about behavior across window
    boundaries (e.g. ports scanned across two consecutive periods)
    without unbounded memory growth.
-   **Capture/processing decoupling.** Packet capture (`getPacket`) and
    packet processing run in separate goroutines connected by a buffered
    channel (`CHANNELSIZE` = 10000), so bursts of traffic don't block
    the capture loop.
-   **ARP cache seeding.** At the start of each window, the system's
    existing ARP cache is read (via `arp.Table()`) to seed known IP→MAC
    bindings before any live traffic is analyzed.
-   **Detection independent of capture types.** `detect.go` never
    imports `gopacket`/`layers` — it only operates on the internal
    `ipInfo` counters, so the detection logic could in principle be
    tested or ported without any packet capture machinery.

## Requirements

-   Go (version per `go.mod`)
-   [`libpcap`](https://www.tcpdump.org/) development headers installed
    on the system (required by `gopacket/pcap`)
-   Root privileges, or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux, to open
    a network interface in promiscuous mode

## Building

``` bash
go build -o ids .
```

## Usage

``` bash
sudo ./ids <interface name>
```

Example:

``` bash
sudo ./ids eth0
```

The IDS expects exactly one argument: the name of the network interface
to listen on. Running it with the wrong number of arguments prints usage
instructions and exits.

On startup, the IDS will: - resolve its own IP address on the given
interface, - load `whitelist.txt` and build a BPF filter excluding the
local IP and all whitelisted IPs as packet sources, - open the interface
in promiscuous mode and begin capturing, - seed known IP→MAC bindings
from the system's existing ARP cache, - write periodic summaries and any
detected attacks to `ids.log`, - print a live spinner to the terminal
while running.

Stop the IDS at any time with `Ctrl+C` (or `SIGTERM`). A final summary
is written to the log and flushed before the process exits.

## Configuration

| Setting | Description | Value |
|------------------------|------------------------|------------------------|
| `PERIOD` | Length of each statistics window, in seconds | `4` |
| `CHANNELSIZE` | Buffer size of the packet channel between capture and processing goroutines | `10000` |
| `TimeLimite` | `pcap` read timeout, in milliseconds | `10` |
| `SNAPLEN` | Maximum number of bytes captured per packet | `1600` |
| `Promiscious` | Whether the interface is opened in promiscuous mode | `true` |
| Whitelist | Path to a file listing IPs excluded from capture | `whitelist.txt` |

### Detection thresholds (per two consecutive windows, i.e. `~2 × PERIOD` seconds)

| Constant               | Value | Triggers on       |
|------------------------|-------|-------------------|
| `MaxSYNMinusAck`       | 5000  | SYN flood         |
| `MaxSSHConnection`     | 20    | SSH brute-force   |
| `MaxNbrPortsDistincts` | 30    | Port scan         |
| `MaxFin`               | 500   | FIN scan/flood    |
| `MaxNull`              | 500   | NULL scan         |
| `MaxXmas`              | 500   | XMAS scan         |
| `MaxICMPS`             | 6000  | ICMP flood        |
| `MaxUDP`               | 5000  | UDP flood         |
| `MaxDNSResMinusReq`    | 4000  | DNS amplification |

These are starting values and have not yet been validated against real
attack traffic — see Known Issues and Roadmap.

## Whitelist format

`whitelist.txt` contains one IP per line. Lines starting with `#` and
empty lines are ignored:

```         
# Local gateway
192.168.1.1
```

## Logging

All output (periodic traffic summaries and attack detections) is
appended to `ids.log` with a timestamp, e.g.:

```         
[Mon Jan 02 15:04:05 2006]  4 seconds summary: 132 packets of 4821  ||  33 packets per second  !!
[Mon Jan 02 15:04:09 2006]  [WARNING] Scan de ports détecté. (35 ports touchés) IP 192.168.1.42
```

The log file is opened in append mode, so restarting the IDS preserves
prior history rather than overwriting it.


## Project layout

```         
.
├── main.go                # Entry point and event loop
├── config.go              # Constants, CLI args, interface/whitelist/BPF setup
├── update.go              # Per-IP state updates, log writing
├── types.go               # Shared types: IDS, ipInfo
├── detect.go              # Threshold-based attack detection
├── go.mod / go.sum        # Go module definition
├── whitelist.txt          # IPs excluded from capture
├── ids.log                # Runtime log output (generated)
```

## Testing setup

Detection logic is being validated using two Ubuntu Server VMs on
VirtualBox: - **IDS-Sniffer** — runs this IDS against a network
interface. - **Traffic-Gen** — generates both normal and attack traffic
(e.g. `hping3` for SYN floods, `nmap -sN`/`-sX` for NULL/XMAS scans, ARP
spoofing tools) to validate detection thresholds.

## Roadmap

-   [ ] Fix ARP spoofing baseline bug (don't let a detected attacker's
    MAC silently become the new trusted baseline)
-   [ ] Fix DNS amplification counter key mismatch
-   [ ] Decide whether the UDP counter should include non-DNS UDP
    traffic, and fix accordingly
-   [ ] Validate all detection thresholds against real attack traffic on
    the test VMs (SYN flood, port scans, ARP spoof, DNS amp, etc.) and
    tune values that false-positive or fail to trigger
-   [ ] Add unit tests, especially for the pure logic in `detect.go` and
    `AddrbyteToString`
-   [ ] Reimplement the validated detection core in C
-   [ ] Export per-IP statistics to CSV for a Python/scikit-learn ML
    detection layer

