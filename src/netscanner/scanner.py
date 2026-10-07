"""Scanning backends: ARP host discovery, ICMP ping sweep, and TCP/UDP port scans.

All workers run concurrently (ThreadPoolExecutor). Scapy is imported lazily at
module load with a graceful fallback so the CLI can still run TCP/UDP scans and
report clear errors when the library is missing.
"""

from __future__ import annotations

import errno
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# Scapy's own loggers spam stderr (e.g. "No libpcap provider available !")
# during `import scapy.all`, even for scans that never touch raw sockets.
# Silence them BEFORE importing scapy; NetScanner raises its own targeted
# errors when raw sockets are actually needed.
for _scapy_logger in ("scapy", "scapy.runtime", "scapy.loading", "scapy.error"):
    logging.getLogger(_scapy_logger).setLevel(logging.CRITICAL)

try:
    from scapy.all import ARP, Ether, ICMP, IP, TCP, send, sr1, srp  # noqa: F401
    from scapy.error import Scapy_Exception

    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

from . import vendor as vendor_mod
from .osdetect import guess_os, parse_tcp_options
from .utils import LOG, normalize_mac, resolve_hostname

# Used for TCP liveness probing in "all" mode and as the default port set.
COMMON_PORTS = [22, 53, 80, 443, 445, 3389, 8080]

# Protocol-specific UDP probes sent to well-known service ports so a live
# service answers and the port can be reported as definitively "open"
# instead of the ambiguous "open|filtered". Other ports get an empty
# datagram. Payloads follow nmap's well-known probe formats.
# (See examples/probes.json for a commented, extendable copy of this table.)
UDP_PROBES: Dict[int, bytes] = {
    # DNS: version.bind. CHAOS TXT query
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03",
    # NTP: v3 client request (LI=0, VN=3, Mode=3), 48 bytes
    123: b"\x1b" + b"\x00" * 47,
    # NetBIOS: NBSTAT name service query
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    # SNMP: v1 GET for sysDescr.0 (1.3.6.1.2.1.1.1.0), community "public"
    161: b"\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x01\x02\x03\x04"
         b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08"
         b"\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",
    # DHCP: DHCPDISCOVER (op=1 BOOTREQUEST, htype=1 Ethernet, hlen=6,
    # xid=0x12345678, magic cookie, option 53 = DISCOVER)
    67: (b"\x01\x01\x06\x00\x12\x34\x56\x78"
         + b"\x00" * 228  # secs/flags + ciaddr/yiaddr/siaddr/giaddr + chaddr + sname + file
         + b"\x63\x82\x53\x63\x35\x01\x01\xff"),
    # TFTP: RRQ for "test" in octet mode
    69: b"\x00\x01test\x00octet\x00",
    # mDNS: PTR query for _services._dns-sd._udp.local
    5353: (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
           b"\x00\x0c\x00\x01"),
}


def load_probe_db(path: str) -> Dict[int, bytes]:
    """Load custom UDP probes from a JSON file: {"<port>": "<hex payload>"}.

    Example:
        {"53": "1234010000010000000000000776657273696f6e0462696e640000100003"}

    Whitespace inside hex strings is allowed. Keys starting with "_" are
    ignored so files can carry comments (e.g. "_comment"). Raises ValueError
    with a descriptive message on malformed input.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError:
        raise
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid probe file (bad JSON): {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Probe file must be a JSON object mapping port -> hex payload")

    probes: Dict[int, bytes] = {}
    for raw_port, raw_hex in data.items():
        # Keys starting with "_" are treated as comments (e.g. "_comment")
        # so probe files can be self-documenting.
        if isinstance(raw_port, str) and raw_port.startswith("_"):
            continue
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid probe port: '{raw_port}'") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Probe port out of range (1-65535): '{raw_port}'")
        if not isinstance(raw_hex, str) or not raw_hex.strip():
            raise ValueError(f"Probe for port {port} must be a hex string")
        hex_str = "".join(raw_hex.split())
        if len(hex_str) % 2 != 0:
            raise ValueError(f"Probe for port {port} has an odd number of hex digits")
        try:
            probes[port] = bytes.fromhex(hex_str)
        except ValueError as exc:
            raise ValueError(f"Probe for port {port} is not valid hex: {exc}") from exc
    return probes

def _ip_key(ip: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in ip.split("."))


def _dedupe_and_sort(results: List[Dict]) -> List[Dict]:
    """Drop duplicate hosts (overlapping targets can produce repeats) and sort by IP."""
    unique: Dict[str, Dict] = {}
    for entry in results:
        unique.setdefault(entry["ip"], entry)
    return sorted(unique.values(), key=lambda r: _ip_key(r["ip"]))


class ScanError(RuntimeError):
    """Raised when a scan cannot be performed (privileges, missing driver, etc.)."""


ProgressCallback = Callable[[int, int], None]


def _require_scapy() -> None:
    if not HAVE_SCAPY:
        raise ScanError(
            "Scapy is required for this scan method. Install it with: pip install scapy"
        )


def _map_scan(
    worker: Callable[[object], Tuple[List[Dict], Optional[str]]],
    items: List[object],
    concurrency: int,
    progress: Optional[ProgressCallback] = None,
) -> List[Dict]:
    """Run worker(item) concurrently.

    worker returns (results, error_message_or_None). If every item fails, the
    first error is raised as ScanError; if only some fail, a warning is logged
    and the partial results are returned. progress(done, total) is called as
    each item completes.
    """
    results: List[Dict] = []
    errors: List[str] = []
    total = len(items)
    workers = max(1, min(int(concurrency), total or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, item) for item in items]
        for done, future in enumerate(as_completed(futures), start=1):
            batch, error = future.result()
            results.extend(batch)
            if error:
                errors.append(error)
            if progress:
                progress(done, total)
    if errors and not results:
        raise ScanError(errors[0])
    if errors:
        LOG.warning("%d probe(s) failed: %s", len(errors), errors[0])
    return results


def _stream_scan(
    worker: Callable[[object], Tuple[List[Dict], Optional[str]]],
    items: List[object],
    concurrency: int,
    progress: Optional[ProgressCallback] = None,
) -> Iterable[Dict]:
    """Run worker(item) concurrently, yielding each result as it arrives.

    Yields entries in completion order (unordered). Raises ScanError if every
    item failed and nothing was yielded. progress(done, total) is called as
    each item completes.
    """
    errors: List[str] = []
    yielded_any = False
    total = len(items)
    workers = max(1, min(int(concurrency), total or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, item) for item in items]
        for done, future in enumerate(as_completed(futures), start=1):
            batch, error = future.result()
            if batch:
                yielded_any = True
                for entry in batch:
                    yield entry
            if error:
                errors.append(error)
            if progress:
                progress(done, total)
    if errors and not yielded_any:
        raise ScanError(errors[0])
    if errors:
        LOG.warning("%d probe(s) failed: %s", len(errors), errors[0])


def arp_scan(
    targets: Iterable[str],
    timeout: float = 2.0,
    retries: int = 1,
    iface: Optional[str] = None,
    concurrency: int = 32,
    resolve: bool = False,
    vendor_db: Optional[Dict[str, str]] = None,
    progress: Optional[ProgressCallback] = None,
) -> List[Dict]:
    """Discover hosts on the local network segment via ARP requests.

    Each result: {"ip", "mac", "vendor", "hostname"}. Requires raw sockets
    (administrator/root; Npcap on Windows).
    """
    _require_scapy()
    targets = [str(t) for t in targets]

    def worker(ip: str) -> Tuple[List[Dict], Optional[str]]:
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(
                broadcast / arp_request,
                timeout=timeout,
                retry=max(0, retries - 1),
                iface=iface,
                verbose=False,
            )[0]
        except PermissionError:
            return [], "ARP scanning requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], (
                "ARP scan failed (raw sockets unavailable; on Windows install "
                f"Npcap and run as administrator): {exc}"
            )
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"ARP scan failed for {ip}: {exc}"

        entries: List[Dict] = []
        for _, received in answered:
            ip_addr = str(getattr(received, "psrc", ""))
            mac = normalize_mac(str(getattr(received, "hwsrc", "")))
            entries.append(
                {
                    "ip": ip_addr,
                    "mac": mac or None,
                    "vendor": vendor_mod.lookup_vendor(mac, vendor_db) if mac else None,
                    "hostname": resolve_hostname(ip_addr) if resolve else None,
                }
            )
        return entries, None

    results = _map_scan(worker, list(targets), concurrency, progress=progress)
    return _dedupe_and_sort(results)


def icmp_ping(
    targets: Iterable[str],
    timeout: float = 2.0,
    retries: int = 1,
    concurrency: int = 32,
    resolve: bool = False,
    progress: Optional[ProgressCallback] = None,
) -> List[Dict]:
    """Probe hosts with ICMP echo requests.

    Each result: {"ip", "mac": None, "vendor": None, "hostname"}. Requires raw
    sockets on most platforms (administrator/root).
    """
    _require_scapy()
    targets = [str(t) for t in targets]

    def worker(ip: str) -> Tuple[List[Dict], Optional[str]]:
        try:
            reply = sr1(
                IP(dst=ip) / ICMP(),
                timeout=timeout,
                retry=max(0, retries - 1),
                verbose=False,
            )
        except PermissionError:
            return [], "ICMP ping requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], f"ICMP ping failed (raw sockets unavailable): {exc}"
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"ICMP ping failed for {ip}: {exc}"
        if reply is None:
            return [], None
        return (
            [
                {
                    "ip": ip,
                    "mac": None,
                    "vendor": None,
                    "hostname": resolve_hostname(ip) if resolve else None,
                }
            ],
            None,
        )

    results = _map_scan(worker, list(targets), concurrency, progress=progress)
    return _dedupe_and_sort(results)


def _service_name(port: int) -> Optional[str]:
    try:
        return socket.getservbyport(port)
    except OSError:
        return None


def _udp_state_from_error(exc: OSError) -> str:
    """Map the OS error raised by a UDP probe to an nmap-style state.

    Closed ports surface as ICMP port-unreachable, which Python reports as
    ConnectionRefusedError (POSIX ECONNREFUSED) or ConnectionResetError
    (Windows WSAECONNRESET). Host/network unreachable means filtered.
    """
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return "closed"
    if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return "filtered"
    if exc.errno == errno.ETIMEDOUT:
        return "open|filtered"
    return "filtered"


def port_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    resolve: bool = False,
    stream: bool = False,
    progress: Optional[ProgressCallback] = None,
) -> Iterable[Dict]:
    """Scan ports on targets using TCP connect (no privileges required).

    Each result: {"ip", "port", "service", "state": "open"}. With
    stream=True, returns a generator yielding results as they are discovered
    (completion order) instead of a sorted list - useful for very large scans.
    """
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return (
                    [
                        {
                            "ip": ip,
                            "port": port,
                            "service": _service_name(port),
                            "state": "open",
                        }
                    ],
                    None,
                )
            return [], None
        except socket.error:
            return [], None
        finally:
            sock.close()

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency, progress=progress)
    results = _map_scan(worker, jobs, concurrency, progress=progress)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def udp_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    concurrency: int = 64,
    include_closed: bool = False,
    stream: bool = False,
    progress: Optional[ProgressCallback] = None,
    probes: Optional[Dict[int, bytes]] = None,
) -> Iterable[Dict]:
    """Scan ports on targets with a UDP datagram probe (no privileges required).

    UDP has no handshake, so states are inferred from ICMP errors and silence:
      * "open"          - the service replied with data
      * "open|filtered" - no reply and no ICMP error within the timeout
      * "closed"        - ICMP port unreachable
      * "filtered"      - ICMP host/network unreachable or admin-prohibited

    Well-known service ports receive protocol-specific probes so a live
    service answers and the port is reported as definitively "open" (see
    UDP_PROBES: DNS 53, DHCP 67, TFTP 69, NTP 123, NetBIOS 137, SNMP 161,
    mDNS 5353); other ports get an empty datagram and stay "open|filtered"
    when they do not answer.

    Pass probes= to replace the built-in table entirely (e.g. a custom table
    loaded with load_probe_db); ports missing from the table get an empty
    datagram. By default only open and open|filtered ports are reported; pass
    include_closed=True to also list closed/filtered results. With
    stream=True, returns a generator yielding results as discovered.
    """
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # connect() is required so ICMP unreachable errors are delivered
            # to the socket (sendto/recvfrom on an unconnected socket misses them)
            sock.connect((ip, port))
            table = probes if probes is not None else UDP_PROBES
            sock.send(table.get(port, b""))
            try:
                sock.recvfrom(1024)
                state = "open"
            except socket.timeout:
                state = "open|filtered"
            except OSError as exc:
                state = _udp_state_from_error(exc)
        except OSError:
            return [], None  # could not reach the host at all
        finally:
            sock.close()

        if state in ("closed", "filtered") and not include_closed:
            return [], None
        return (
            [{"ip": ip, "port": port, "service": _service_name(port), "state": state}],
            None,
        )

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency, progress=progress)
    results = _map_scan(worker, jobs, concurrency, progress=progress)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def _send_rst(ip: str, port: int) -> None:
    """Best-effort RST to close a half-open TCP connection; never raises."""
    try:
        send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
    except (OSError, RuntimeError, Scapy_Exception):
        pass


def syn_scan(
    targets: Iterable[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    retries: int = 1,
    concurrency: int = 32,
    include_closed: bool = False,
    stream: bool = False,
    progress: Optional[ProgressCallback] = None,
    fingerprint: bool = True,
) -> Iterable[Dict]:
    """Half-open TCP SYN scan (-sS style) using raw sockets (requires admin/root).

    Sends a SYN and infers the state from the reply without completing the
    handshake, so the target application never sees an established connection:
      * "open"     - SYN-ACK received (a RST is sent to close the half-open
                      connection)
      * "closed"   - RST received
      * "filtered" - no reply after retries, or an ICMP error

    Open ports are OS-fingerprinted from the SYN-ACK's IP TTL, TCP window
    size, and TCP options (heuristic, see osdetect.guess_os); the guess plus
    the raw observed TTL/window are included in each result as "os", "ttl",
    and "window". Set fingerprint=False to skip the guess (--no-os).

    By default only open ports are reported; pass include_closed=True to also
    list closed/filtered results. Requires raw sockets (Npcap on Windows).
    With stream=True, returns a generator yielding results as discovered.
    """
    _require_scapy()
    targets = [str(t) for t in targets]
    ports = list(ports)

    def worker(job: Tuple[str, int]) -> Tuple[List[Dict], Optional[str]]:
        ip, port = job
        try:
            # L3 send; scapy routes via the OS routing table (the iface
            # parameter is ignored for sr1, so it is not passed).
            reply = sr1(
                IP(dst=ip) / TCP(dport=port, flags="S"),
                timeout=timeout,
                retry=max(0, retries - 1),
                verbose=False,
            )
        except PermissionError:
            return [], "SYN scanning requires administrator/root privileges."
        except (OSError, RuntimeError, Scapy_Exception) as exc:
            return [], (
                "SYN scan failed (raw sockets unavailable; on Windows install "
                f"Npcap and run as administrator): {exc}"
            )
        except Exception as exc:  # noqa: BLE001 - surface platform quirks cleanly
            return [], f"SYN scan failed for {ip}:{port}: {exc}"

        state = "filtered"
        os_guess = ttl_obs = window_obs = None
        if reply is not None and reply.haslayer(TCP):
            flags = int(reply[TCP].flags)
            # A SYN-ACK has BOTH SYN and ACK set. Testing `flags & 0x12` for
            # truthiness also matched RST+ACK (0x14) -- the reply a *closed*
            # port sends to a SYN (RFC 793) -- so closed ports were reported
            # as open and even got OS-fingerprinted.
            if (flags & 0x12) == 0x12:  # SYN-ACK -> open
                state = "open"
                if reply.haslayer(IP):
                    ttl_obs = int(reply[IP].ttl)
                window_obs = int(reply[TCP].window)
                if fingerprint:
                    mss, wscale, sack, ts = parse_tcp_options(reply[TCP].options)
                    os_guess = guess_os(ttl_obs, window_obs, mss, wscale, sack, ts)
                _send_rst(ip, port)
            elif flags & 0x04:  # RST -> closed
                state = "closed"
        # no reply or ICMP unreachable -> filtered

        entry = {
            "ip": ip,
            "port": port,
            "service": _service_name(port),
            "state": state,
            "os": os_guess,
            "ttl": ttl_obs,
            "window": window_obs,
        }
        if state in ("closed", "filtered") and not include_closed:
            return [], None
        return [entry], None

    jobs = [(ip, port) for ip in targets for port in ports]
    if stream:
        return _stream_scan(worker, jobs, concurrency, progress=progress)
    results = _map_scan(worker, jobs, concurrency, progress=progress)
    results.sort(key=lambda r: (_ip_key(r["ip"]), r["port"]))
    return results


def discover_hosts(
    targets: Iterable[str],
    method: str = "all",
    timeout: float = 2.0,
    retries: int = 1,
    iface: Optional[str] = None,
    concurrency: int = 32,
    resolve: bool = False,
    vendor_db: Optional[Dict[str, str]] = None,
    common_ports: Optional[Iterable[int]] = None,
    progress: Optional[ProgressCallback] = None,
) -> List[Dict]:
    """Discover live hosts, merging results from multiple methods by IP.

    method:
      * "arp"  - ARP only (local segment). Raises ScanError if unavailable.
      * "ping" - ICMP only. Raises ScanError if unavailable.
      * "all"  - ARP then ICMP, degrading gracefully if either fails; if
                 nothing is found, falls back to a TCP connect on common
                 ports (works without privileges).

    Each result: {"ip", "mac", "vendor", "hostname"}.
    """
    _require_scapy()
    targets = [str(t) for t in targets]
    results: Dict[str, Dict] = {}

    def run(method_name: str) -> None:
        if method_name == "arp":
            entries = arp_scan(
                targets,
                timeout=timeout,
                retries=retries,
                iface=iface,
                concurrency=concurrency,
                resolve=resolve,
                vendor_db=vendor_db,
                progress=progress,
            )
        elif method_name == "ping":
            entries = icmp_ping(
                targets,
                timeout=timeout,
                retries=retries,
                concurrency=concurrency,
                resolve=resolve,
                progress=progress,
            )
        else:  # tcp liveness probe
            ports = list(common_ports) if common_ports else COMMON_PORTS
            entries = [
                {
                    "ip": entry["ip"],
                    "mac": None,
                    "vendor": None,
                    "hostname": resolve_hostname(entry["ip"]) if resolve else None,
                }
                for entry in port_scan(
                    targets, ports, timeout=timeout, concurrency=concurrency, progress=progress
                )
            ]
        for entry in entries:
            results.setdefault(entry["ip"], entry)

    if method == "all":
        for name in ("arp", "ping"):
            try:
                run(name)
            except ScanError as exc:
                LOG.warning("Host discovery via %s unavailable: %s", name, exc)
        if not results:
            LOG.info("ARP/ICMP found no hosts; trying TCP connect on common ports...")
            run("tcp")
    elif method == "arp":
        run("arp")
    elif method == "ping":
        run("ping")
    else:
        raise ValueError(f"Unknown discovery method: {method}")

    return sorted(results.values(), key=lambda r: _ip_key(r["ip"]))
