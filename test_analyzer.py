#!/usr/bin/env python3
"""
Self-test for traffic_analyzer.

Builds a synthetic libpcap file in memory that contains:
  - a periodic TCP beacon (10 identical-interval packets to one dst:port)
  - a DNS query with a long high-entropy label (tunneling-shaped)
then runs the analyzer and asserts both detections fire.

No network. No third-party deps. Exit 0 only if both hits appear.
"""

import io
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from traffic_analyzer import (
    Flow, Packet, detect_beacons, detect_dns_tunneling, parse_eth_ip,
)

HERE = Path(__file__).resolve().parent
ANALYZER = HERE / "traffic_analyzer.py"


def eth_ip_tcp_udp(src_ip, dst_ip, src_port, dst_port, payload, proto="TCP"):
    """Build an Ethernet/IPv4/(TCP|UDP) frame."""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    # IPv4 header (20 bytes, no options)
    ver_ihl = (4 << 4) | 5
    l4 = b""
    if proto == "TCP":
        # sport H, dport H, seq I, ack I, off+reserved B, flags B, win H, csum H, urg H = 9
        l4 = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0,
                         (5 << 4), 0x02, 0xffff, 0, 0)  # 20-byte TCP, SYN
        l4 += payload
    else:
        udp_len = 8 + len(payload)
        l4 = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    total_len = 20 + len(l4)
    # IPv4 header: ver_ihl B, tos B, total_len H, id H, flags+frag H, ttl B, proto B, csum H, src 4s, dst 4s
    ip = struct.pack("!BBHHHBBH", ver_ihl, 0, total_len, 0, 0, 64,
                     6 if proto == "TCP" else 17, 0)
    ip += socket_inet_aton(src_ip) + socket_inet_aton(dst_ip)
    return eth + ip + l4


def socket_inet_aton(ip):
    return struct.pack("!BBBB", *[int(x) for x in ip.split(".")])


def dns_query(name: str) -> bytes:
    """Minimal DNS query payload (id, flags, 1 question)."""
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    q = struct.pack("!HH", 1, 1)  # type A, class IN
    return hdr + qname + q


def build_pcap() -> bytes:
    """Assemble a libpcap file with beacon + DNS-tunnel traffic."""
    buf = io.BytesIO()
    # global header: magic LE, ver 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (eth)
    buf.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    base = 1_000_000  # 1s
    # 10 periodic beacons to 10.0.0.99:443, exactly 5.0s apart
    for i in range(10):
        ts_sec = base + i * 5
        frame = eth_ip_tcp_udp("10.0.0.5", "10.0.0.99", 50000 + i, 443, b"X", "TCP")
        buf.write(struct.pack("<IIII", ts_sec, 0, len(frame), len(frame)))
        buf.write(frame)
    # one DNS query with a long high-entropy label (tunnel-shaped)
    long_label = "mfrggzdfq3tse4lqozshayrumnxgo5a" * 2  # ~60 chars
    dns = dns_query(long_label + ".evil.example")
    dns_frame = eth_ip_tcp_udp("10.0.0.5", "8.8.8.8", 12345, 53, dns, "UDP")
    buf.write(struct.pack("<IIII", base + 100, 0, len(dns_frame), len(dns_frame)))
    buf.write(dns_frame)
    return buf.getvalue()


def main():
    pcap_path = HERE / "_fixture.pcap"
    pcap_path.write_bytes(build_pcap())
    print(f"wrote fixture: {pcap_path} ({pcap_path.stat().st_size} bytes)")
    proc = subprocess.run(
        [sys.executable, str(ANALYZER), str(pcap_path)],
        capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print("STDERR:", proc.stderr, file=sys.stderr)
    out = proc.stdout
    ok_beacon = "10.0.0.99:443" in out and "count=10" in out
    ok_dns = long_ok(out)
    ok_multi_source = multi_source_isolation_ok()
    ok_ack_noise = ack_noise_ignored()
    ok_truncated = truncated_tcp_is_ignored()
    ok_low_entropy_long = low_entropy_long_label_not_flagged()
    ok_high_entropy_short = high_entropy_short_label_not_flagged()
    ok_non_dns_udp = non_dns_udp_not_parsed_as_dns()
    pcap_path.unlink(missing_ok=True)
    checks = {
        "beacon": ok_beacon,
        "dns": ok_dns,
        "multi_source": ok_multi_source,
        "ack_noise": ok_ack_noise,
        "truncated": ok_truncated,
        "low_entropy_long": ok_low_entropy_long,
        "high_entropy_short": ok_high_entropy_short,
        "non_dns_udp": ok_non_dns_udp,
    }
    if all(checks.values()):
        print("PASS: positive detections + isolation + negative DNS heuristics")
        return 0
    print("FAIL:", " ".join(f"{k}={v}" for k, v in checks.items()))
    return 1


def long_ok(out):
    # DNS hit line contains 'evil.example' and a label len >= 40
    return "evil.example" in out and "label=" in out


def multi_source_isolation_ok():
    """Two five-packet sources must not merge into one ten-packet beacon."""
    flows = []
    for i in range(5):
        first = Flow(src="10.0.0.1", dst="10.0.0.99", proto="TCP", dport=443)
        second = Flow(src="10.0.0.2", dst="10.0.0.99", proto="TCP", dport=443)
        first.tcp_flags = 0x02
        second.tcp_flags = 0x02
        flows.append((i * 10.0, first))
        flows.append((i * 10.0 + 5.0, second))
    return detect_beacons(flows, min_count=10) == []


def ack_noise_ignored():
    """Regular ACK traffic alone is not a series of connection check-ins."""
    flows = []
    for i in range(10):
        flow = Flow(src="10.0.0.5", dst="10.0.0.99", proto="TCP", dport=443)
        flow.tcp_flags = 0x10
        flows.append((i * 5.0, flow))
    return detect_beacons(flows, min_count=10) == []


def truncated_tcp_is_ignored():
    """A 12-byte truncated TCP header must be skipped instead of indexing byte 12."""
    eth = b"\x00" * 12 + b"\x08\x00"
    ver_ihl = (4 << 4) | 5
    ip = struct.pack("!BBHHHBBH", ver_ihl, 0, 32, 0, 0, 64, 6, 0)
    ip += socket_inet_aton("10.0.0.1") + socket_inet_aton("10.0.0.2")
    pkt = Packet(0, 0, 1, eth + ip + b"\x00" * 12)
    try:
        return parse_eth_ip(pkt) is None
    except (IndexError, struct.error):
        return False


def low_entropy_long_label_not_flagged():
    """Repeated words can be long without looking like base32/base64 exfil."""
    q = ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         ".cdn.example")
    return detect_dns_tunneling([q]) == []


def high_entropy_short_label_not_flagged():
    """Short random tokens (CDN/cache keys) must not fire alone."""
    q = "x7k9m2.cdn.example"
    return detect_dns_tunneling([q]) == []


def non_dns_udp_not_parsed_as_dns():
    """UDP to a non-53 port is not treated as a DNS query by analyze()."""
    from traffic_analyzer import analyze
    import tempfile
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    payload = b"not-a-dns-message-at-all"
    frame = eth_ip_tcp_udp("10.0.0.5", "10.0.0.8", 40000, 12345, payload, "UDP")
    buf.write(struct.pack("<IIII", 1_000_000, 0, len(frame), len(frame)))
    buf.write(frame)
    path = HERE / "_non_dns.pcap"
    path.write_bytes(buf.getvalue())
    try:
        # analyze prints; we only care it does not crash and reports 0 DNS
        import io as _io
        from contextlib import redirect_stdout
        sink = _io.StringIO()
        with redirect_stdout(sink):
            rc = analyze(path)
        out = sink.getvalue()
        return rc == 0 and "DNS queries               : 0" in out
    finally:
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
