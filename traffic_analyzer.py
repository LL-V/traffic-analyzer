#!/usr/bin/env python3
"""
pcap traffic analyzer for defensive detection.

Parses a libpcap capture file with the Python standard library only (no
scapy / dpkt dependency, which keeps it portable and easy to audit), and
flags two classes of suspicious traffic:

  - C2 beaconing: a destination contacted at near-regular intervals by
    one source. Periodic heartbeats are a hallmark of implant check-in.
  - DNS tunneling: DNS queries with abnormally long labels or high-
    entropy subdomains, which often encode exfiltrated data.

Defensive use: run this on captures from your own network or a lab.
"""

import argparse
import math
import socket
import struct
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# pcap file parsing (libpcap format, little- and big-endian)
# ---------------------------------------------------------------------------

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC_LE = 0x0A0D0D0A  # we do not parse pcapng; detected and refused


@dataclass
class Packet:
    ts_sec: int
    ts_usec: int
    link_type: int
    raw: bytes

    @property
    def ts(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000.0


def read_packets(path: Path):
    """Yield Packet objects from a libpcap file. Raises on pcapng."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError("file too short to be a pcap")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAPNG_MAGIC_LE or magic in (0x0A0D0D0A,):
        raise ValueError("pcapng not supported; convert with editcap or tshark")
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError(f"not a libpcap file (magic {magic:#x})")

    # global header: magic(4) ver_major(2) ver_minor(2) thiszone(4)
    # sigfigs(4) snaplen(4) network(4)  -> 7 fields
    _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", data[:24])
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            break
        raw = data[off:off + incl_len]
        off += incl_len
        yield Packet(ts_sec, ts_usec, network, raw)


# ---------------------------------------------------------------------------
# layer decoders (Ethernet / IPv4 / TCP / UDP / DNS, minimal)
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    src: str = ""
    dst: str = ""
    proto: str = ""
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    payload: bytes = b""


ETHERTYPE_IPV4 = 0x0800


def parse_eth_ip(pkt: Packet) -> Optional[Flow]:
    """Decode Ethernet -> IPv4 -> TCP|UDP. Returns None on skip."""
    if pkt.link_type != 1:  # LINKTYPE_ETHERNET
        return None
    if len(pkt.raw) < 14:
        return None
    ethertype = struct.unpack("!H", pkt.raw[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None
    ip = pkt.raw[14:]
    if len(ip) < 20:
        return None
    ver_ihl = ip[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    total_len = struct.unpack("!H", ip[2:4])[0]
    if total_len < ihl or total_len > len(ip):
        return None
    l4 = ip[ihl:total_len]
    flow = Flow(src=src, dst=dst)
    if proto == 6:                          # TCP
        if len(l4) < 20:
            return None
        sport, dport = struct.unpack("!HH", l4[:4])
        data_off = (l4[12] >> 4) * 4
        if data_off < 20 or data_off > len(l4):
            return None
        flow.proto = "TCP"; flow.sport = sport; flow.dport = dport
        flow.tcp_flags = l4[13]
        flow.payload = l4[data_off:]
    elif proto == 17 and len(l4) >= 8:     # UDP
        sport, dport, _len, _csum = struct.unpack("!HHHH", l4[:8])
        flow.proto = "UDP"; flow.sport = sport; flow.dport = dport
        flow.payload = l4[8:]
    else:
        flow.proto = str(proto)
    return flow


def parse_dns_question(payload: bytes):
    """Return the queried name from a DNS query payload, or None."""
    if len(payload) < 12:
        return None
    # skip 12-byte DNS header, parse QNAME labels
    off = 12
    labels = []
    while off < len(payload):
        ln = payload[off]
        if ln == 0:
            break
        if ln & 0xC0:  # compression pointer — bail
            break
        off += 1
        if off + ln > len(payload):
            break
        labels.append(payload[off:off + ln].decode("latin1", "replace"))
        off += ln
    return ".".join(labels) if labels else None


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class BeaconHit:
    src: str
    dst: str
    dport: int
    count: int
    median_interval: float
    jitter_ratio: float
    note: str


def detect_beacons(flows_with_ts, min_count=10, max_jitter=0.25):
    """A flow group (src,dst,dport) that repeats at near-constant intervals
    looks like a beacon. We measure interval jitter; low jitter + many
    repeats = suspicious."""
    by_pair = defaultdict(list)
    for ts, flow in flows_with_ts:
        # Count connection attempts, not every ACK/data packet in an existing
        # connection. SYN+ACK is a response, so only SYN without ACK is used.
        if (flow.proto == "TCP" and flow.dport
                and flow.tcp_flags & 0x02 and not flow.tcp_flags & 0x10):
            by_pair[(flow.src, flow.dst, flow.dport)].append(ts)
    hits = []
    for (src, dst, dport), times in by_pair.items():
        if len(times) < min_count:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times) - 1)]
        intervals.sort()
        median = intervals[len(intervals) // 2]
        if median <= 0:
            continue
        mean_abs = sum(abs(i - median) for i in intervals) / len(intervals)
        jitter = mean_abs / median
        if jitter <= max_jitter:
            hits.append(BeaconHit(src, dst, dport, len(times), median, jitter,
                                  "near-regular intervals, low jitter"))
    return hits


@dataclass
class DnsTunnelHit:
    query: str
    longest_label: int
    entropy: float
    note: str


def detect_dns_tunneling(queries, min_label=40, min_entropy=3.0,
                         min_label_for_entropy=20):
    """Flag only when length and entropy both look like encoded exfil.

    A long but low-entropy label (padding, repeated words) and a short but
    high-entropy label (random CDN tokens) are negative cases and are not
    reported. Both thresholds must fire, and the label must be long enough
    that entropy is meaningful.
    """
    hits = []
    seen = set()
    for q in queries:
        if not q or q in seen:
            continue
        seen.add(q)
        labels = q.split(".")
        longest = max((len(l) for l in labels), default=0)
        target = max(labels, key=len) if labels else ""
        ent = shannon_entropy(target)
        if (longest >= min_label
                and longest >= min_label_for_entropy
                and ent >= min_entropy):
            hits.append(DnsTunnelHit(q, longest, round(ent, 2),
                                     "long label and high entropy"))
    return hits


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def analyze(path: Path):
    flows_ts = []
    dns_queries = []
    n_pkts = 0
    for pkt in read_packets(path):
        n_pkts += 1
        flow = parse_eth_ip(pkt)
        if flow is None:
            continue
        flows_ts.append((pkt.ts, flow))
        if flow.proto == "UDP" and flow.dport == 53:
            q = parse_dns_question(flow.payload)
            if q:
                dns_queries.append(q)

    beacons = detect_beacons(flows_ts)
    tunnels = detect_dns_tunneling(dns_queries)

    print(f"== {path} ==")
    print(f"packets parsed            : {n_pkts}")
    print(f"flows (eth/ipv4)          : {len(flows_ts)}")
    print(f"DNS queries               : {len(dns_queries)}")
    print()
    print(f"== C2 beacon candidates ({len(beacons)}) ==")
    for h in sorted(beacons, key=lambda x: x.count, reverse=True):
        print(f"  {h.src} -> {h.dst}:{h.dport}  count={h.count}  "
              f"median_int={h.median_interval:.2f}s  jitter={h.jitter_ratio:.2f}")
    if not beacons:
        print("  (none — low regularity, or too few repeats)")
    print()
    print(f"== DNS tunneling candidates ({len(tunnels)}) ==")
    for h in tunnels[:20]:
        print(f"  {h.query}  label={h.longest_label}  entropy={h.entropy}")
    if not tunnels:
        print("  (none — no long/high-entropy query labels)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="libpcap capture to analyze")
    ap.add_argument("--list", action="store_true", help="list detections and exit")
    args = ap.parse_args(argv)
    if args.list:
        print("detections: C2 beacon (periodic TCP), DNS tunneling (long/entropic labels)")
        return 0
    if not args.pcap:
        ap.print_help()
        return 1
    return analyze(Path(args.pcap))


if __name__ == "__main__":
    sys.exit(main())
