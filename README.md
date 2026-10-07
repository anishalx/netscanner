# NetScanner

```bash
                )           (                   )    )     (
             ( /(      *   ))\ )  (    (     ( /( ( /(     )\ )
             )\())(  ` )  /(()/(  )\   )\    )\()))\())(  (()/(
            ((_)\ )\  ( )(_))(_)|((_|(((_)( ((_)\\((_)\ )\  /(_))
             _((_|(_)(_(_()|_)) )\___)\ _ )\ _((_)_((_|(_)(_))
            | \| | __|_   _/ __((/ __(_)_\(_) \| | \| | __| _ \
            | .` | _|  | | \__ \| (__ / _ \ | .` | .` | _||   /
            |_|\_|___| |_| |___/ \___/_/ \_\_|_|\_|_|\_|___|_|_\
        =============================================================
                    Version: 2.0     Twitter: anishalx7
        =============================================================
```

## Overview

**NetScanner** is a fast, cross-platform network discovery and port-scanning tool built with Python and [Scapy](https://scapy.readthedocs.io/). Discover devices on your local network, sweep subnets with ICMP, or scan for open TCP ports — all from a clean command-line interface.

### Why Use NetScanner?

- **User-Friendly**: Designed for both beginners and experienced users.
- **Versatile**: ARP host discovery, ICMP ping sweeps, and TCP port scans in one tool.
- **Fast**: Concurrent probes with tunable thread counts and timeouts.
- **Scriptable**: Table, JSON, or CSV output, with optional file export.

## Features (v2)

- **Five scan methods** (`arp`, `ping`, `tcp`, `udp`, `syn`) plus automatic `all` mode:
  - `arp` — Layer-2 host discovery on your local segment (IP + MAC + vendor)
  - `ping` — ICMP echo sweep
  - `tcp` — privilege-free TCP connect port scan (works without admin/root)
  - `udp` — privilege-free UDP datagram scan (open / open|filtered / closed / filtered, with `--include-closed`); sends protocol probes to well-known service ports (DNS 53, DHCP 67, TFTP 69, NTP 123, NetBIOS 137, SNMP 161, mDNS 5353) so live services report definitively `open`
  - `syn` — half-open TCP SYN scan (needs admin/root; stealthier — the target never sees an established connection); open ports are OS-fingerprinted from the SYN-ACK's TTL + TCP window + TCP options (MSS/WScale/SACK/timestamps; heuristic, disable with `--no-os`)
  - `all` — runs ARP and ICMP, degrading gracefully if either needs privileges; if nothing is found, falls back to a TCP scan of common ports
- **Flexible targets**: single IP, CIDR (`192.168.1.0/24`), hyphen ranges (`192.168.1.1-50`), hostnames, and comma-separated combinations
- **MAC vendor lookup**: the full IEEE OUI database (~40k vendors) is bundled with the tool, layered under friendly curated names, plus custom `--vendor-db` overrides
- **Output formats**: aligned table, JSON, CSV, or JSON Lines (`jsonl`) — the `jsonl` format **streams** port-scan results as they are discovered, so very large scans stay memory-bounded and `-o scan.jsonl` is tailable while it runs
- **Concurrency & tuning**: `--concurrency`, `--timeout`, `--retries`, `--iface`
- **Live progress reporting**: long scans show a rate-limited `done/total (%)` indicator on stderr (auto-hidden for small scans, and a `completed X/Y in Zs` summary always goes to stderr so stdout stays clean for data); `-q/--quiet` silences all of it
- **Hostname resolution** for discovered devices (`--resolve`)
- **Structured error handling**: clear messages for bad targets, missing privileges, and missing drivers — never a raw traceback
- **Fully unit-tested** (155 tests, all network calls mocked), with CI across Python 3.9–3.13

## Installation

### Prerequisites

- **Python 3.8+**
- **Scapy**: `pip install scapy`
- **For `arp`/`ping` on Windows**: [Npcap](https://npcap.com/) (with "WinPcap API-compatible Mode") and an **administrator** shell. On Linux/macOS, `arp`/`ping` need **root** (or CAP_NET_RAW). `tcp` scans work everywhere with no special privileges.

### Install as a package (recommended)

```bash
git clone https://github.com/anishalx/net-scanner.git   # or your fork
cd netscanner
pip install -e .           # installs the `netscanner` command
```

### Or run straight from the repo (v1-style)

```bash
python netscanner.py -t 192.168.1.0/24
```

## Usage

```bash
netscanner -t <target> [options]
```

### Examples

```bash
# Discover devices on the local /24 (auto: ARP + ICMP + TCP fallback)
netscanner -t 192.168.1.0/24

# Classic ARP-only scan of the local segment (needs admin/root)
netscanner -t 192.168.1.0/24 -m arp

# ICMP sweep of a range
netscanner -t 192.168.1.1-192.168.1.50 -m ping

# TCP port scan a single host (no privileges needed)
netscanner -t 192.168.1.5 -m tcp -p 1-1000

# TCP port scan with a custom port list
netscanner -t 192.168.1.5 -m tcp -p 22,80,443,8000-9000

# UDP scan (DNS, SNMP, NTP...); closed ports shown with --include-closed
netscanner -t 192.168.1.5 -m udp -p 53,161,500 --include-closed

# Stealthy half-open SYN scan (needs admin/root; Npcap on Windows);
# open ports include a heuristic OS guess from TTL + TCP window
netscanner -t 192.168.1.5 -m syn -p 1-1000 --include-closed

# Machine-readable output to a file
netscanner -t 192.168.1.0/24 -f json -o scan.json
netscanner -t 192.168.1.0/24 -f csv -o scan.csv

# Streaming JSON Lines: one JSON object per line, written as results arrive.
# Ideal for huge scans (e.g. all 65535 TCP ports) - tail the file while it runs.
netscanner -t 192.168.1.5 -m tcp -p 1-65535 -f jsonl -o scan.jsonl
netscanner -t 192.168.1.5 -m tcp -p 1-65535 -f jsonl | jq -c '.port'

# Resolve hostnames and show MAC vendors
netscanner -t 192.168.1.0/24 -m arp --resolve

# Use a custom OUI vendor database (lines of "OUI,Vendor" or "OUI - Vendor")
netscanner -t 192.168.1.0/24 -m arp --vendor-db oui.csv

# Scan faster/slower by tuning concurrency and timeouts
netscanner -t 10.0.0.0/24 --concurrency 64 --timeout 1
```

### Example Output

```
IP Address    MAC Address       Vendor                  Hostname
-----------   ----------------  ---------------------   --------
192.168.1.1   aa:bb:cc:dd:ee:ff TP-Link
192.168.1.10  b8:27:eb:12:34:56 Raspberry Pi Foundation
192.168.1.20
```

### Options

```
-t, --target TARGET   IP, CIDR range, hyphen range, hostname, or comma list
-m, --method          arp | ping | tcp | udp | syn | all   (default: all)
-p, --ports PORTS     Ports for -m tcp / -m udp / -m syn: '22', '80,443', '1-1000'
    --include-closed  With -m udp / -m syn, also list closed/filtered ports
    --probes FILE     Custom UDP probe file (JSON: port -> hex payload); -m udp
    --no-probes       With -m udp, disable built-in protocol probes
    --no-os           With -m syn, skip OS fingerprinting (faster)
-f, --format          table | json | csv | jsonl   (default: table)
                      jsonl streams port-scan results as they are discovered
-o, --output FILE     Write results to a file
    --iface IFACE     Network interface for ARP scans (e.g. eth0, Wi-Fi)
    --timeout SECS    Timeout per probe          (default: 2.0)
    --retries N       Probe retries              (default: 1)
    --concurrency N   Parallel probes            (default: 32)
    --resolve         Reverse-DNS hostnames (slower)
    --vendor-db FILE  Custom OUI vendor database
    --no-banner       Suppress the ASCII banner-v, --verbose         Debug logging
-q, --quiet           Suppress warnings and progress output
    --version             Show version
```

Run `netscanner -h` for the full help text.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest             # run the test suite
```

All tests mock network access, so they run anywhere — no root or Npcap needed.

## Operating Systems

- **Windows**: Command Prompt or PowerShell (Npcap + admin shell for ARP/ping).
- **macOS / Linux**: Any terminal (root or `CAP_NET_RAW` for ARP/ping).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `ARP scan failed ... winpcap is not installed` | Install [Npcap](https://npcap.com/) and run as administrator |
| `ICMP ping requires administrator/root privileges` | Run as root/admin, or use `-m tcp` |
| `SYN scan failed ... raw sockets unavailable` | SYN scanning needs admin/root (and Npcap on Windows); use `-m tcp` for an unprivileged equivalent |
| `No devices found` | Try `-m ping` or `-m tcp`; the auto `all` mode does this for you |
| UDP shows only `open|filtered` | Expected for ports that don't answer empty datagrams. Known service ports (53 DNS, 67 DHCP, 69 TFTP, 123 NTP, 137 NetBIOS, 161 SNMP, 5353 mDNS) receive protocol probes automatically and report `open` when a live service answers; other ports report `open|filtered` when they stay silent |
| `Invalid target(s)` | Use IPv4, e.g. `192.168.1.0/24`, `192.168.1.1-50`, or a resolvable hostname |
| Unknown MAC vendors | Refresh the bundled database: `python tools/update_oui_db.py`, or supply your own `--vendor-db` CSV |

## Contributing

We welcome contributions! Please:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/YourFeature`).
3. Make your changes and add tests under `tests/`.
4. Run `pytest` and push.
5. Open a pull request.

### Custom UDP probes

Well-known UDP service ports get protocol probes automatically (DNS 53, DHCP 67, TFTP 69, NTP 123, NetBIOS 137, SNMP 161, mDNS 5353). You can extend or override them with a JSON file mapping ports to hex payloads — a commented, ready-to-use example covering DHCP, TFTP, RDP (UDP transport) and mDNS ships at [`examples/probes.json`](examples/probes.json):

```bash
netscanner -t 192.168.1.5 -m udp -p 67,69,5353 --probes examples/probes.json
netscanner -t 192.168.1.5 -m udp -p 53 --no-probes          # disable all probes
```

Keys in the file are port numbers, values are hex payloads; keys starting with `_` are ignored as comments and hex may contain whitespace, so files can be self-documenting:

```json
{
  "_comment": "DHCPDISCOVER for port 67",
  "67": "01010600 12345678 00000000000000000000000000000000 ... 63825363 350101 ff"
}
```

`--no-probes` disables the built-in table; `--probes FILE` entries override the built-ins for the same ports (use both to replace the table entirely).

## Updating the MAC vendor database

The tool ships with the official IEEE MA-L OUI database (`src/netscanner/data/oui.csv.gz`, ~40k vendors), downloaded from [standards-oui.ieee.org](https://standards-oui.ieee.org/oui/oui.csv). To refresh it with the latest assignments:

```bash
python tools/update_oui_db.py
```

Lookups check three layers, in order: your custom `--vendor-db` entries, the curated friendly-name table, then the full IEEE database.

## Disclaimer

NetScanner is intended for **authorized security assessments only** — scanning
networks or systems you do not own or lack permission to test is illegal in
most jurisdictions. The tool prints this notice in its banner; obtain explicit
written permission from the network owner before every scan.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to [Scapy](https://scapy.readthedocs.io/en/latest/) for powering this tool.
- Inspired by various network scanning tools and the open-source community.
