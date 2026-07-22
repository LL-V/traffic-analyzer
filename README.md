# traffic-analyzer

Parses a libpcap capture and flags two classes of suspicious traffic:

- **C2 beaconing** — a destination a source contacts at near-regular
  intervals. Periodic heartbeats are a hallmark of implant check-in.
- **DNS tunneling** — DNS queries with abnormally long labels or
  high-entropy subdomains, which often encode exfiltrated data.

## Why standard library only

No `scapy` / `dpkt` / `pyshark` dependency. The pcap (libpcap) format
and the Ethernet/IPv4/TCP/UDP/DNS decoders are hand-written with
`struct`, so the tool is portable, easy to audit, and runs anywhere
CPython 3 runs without installing a packet-parsing stack.

## Usage

```bash
python traffic_analyzer.py capture.pcap
python traffic_analyzer.py --list          # print detection classes and exit
```

Output (against a synthetic fixture built by `test_analyzer.py`):

```
== _fixture.pcap ==
packets parsed            : 11
flows (eth/ipv4)          : 11
DNS queries               : 1

== C2 beacon candidates (1) ==
  10.0.0.99:443  count=10  median_int=5.00s  jitter=0.00

== DNS tunneling candidates (1) ==
  mfrggzdfq...go5a.evil.example  label=62  entropy=4.28
```

## Detection logic (honest)

- **Beacon**: groups TCP connection attempts by `(src, dst, dport)`, computes inter-
  arrival intervals, and flags a group as a beacon candidate when it
  has ≥ 10 repeats and the mean absolute deviation of intervals from
  the median is ≤ 25% of the median (low jitter). Only SYN packets without
  ACK are counted, so ACK/data packets from an existing connection do not
  inflate the result. A clean, regular
  heartbeat scores as suspicious; a human browsing the web does not.
- **DNS tunnel**: flags a query only when the longest label is ≥ 40 chars
  **and** its Shannon entropy is ≥ 3.0 bits/char. Length alone or entropy
  alone is not enough (low-entropy padding and short CDN tokens are
  negative cases).

## What it does NOT do

- It only parses **libpcap** format (not pcapng). Convert with
  `editcap -F pcap in.pcapng out.pcap` if needed.
- It only decodes **Ethernet / IPv4 / TCP / UDP**. IPv6, ARP, and
  tunneled encapsulations are skipped, not parsed.
- Beacon detection assumes the beacon is on a **single `(dst, dport)`
  pair**. A beacon that rotates destinations or ports per check-in
  (some modern implants do) will not group into a single bucket and
  will be missed.
- DNS tunnel detection is a **heuristic on the query name**. It does
  not decode the response, does not measure query volume over time,
  and can still false-positive on legitimate long high-entropy labels.
  Treat hits as leads, not verdicts. The self-test includes negative
  cases for low-entropy long labels, high-entropy short labels, and
  non-DNS UDP.
- It does not reassemble TCP streams. Beacon detection works on TCP SYN timing,
  not stream content. Retransmitted SYN packets can still inflate counts because
  this small tool does not maintain a TCP state table.

## Test

`test_analyzer.py` builds a synthetic pcap in memory (one 10-packet
5-second beacon + one long high-entropy DNS query), runs the analyzer,
and asserts both detections fire. It also verifies source isolation,
ignores ACK-only timing, safely skips truncated TCP headers, and checks
DNS negative cases (low-entropy long labels, high-entropy short labels,
non-DNS UDP). No network, no third-party deps.

```bash
python test_analyzer.py    # exit 0 only if both hits appear
```

## Defensive use

Run this on captures from your own network or a lab. The synthetic
fixture is the only capture in this repo; no real traffic is included.

## Related

- Protocol parser fuzzer: [proto-fuzzer](https://github.com/LL-V/proto-fuzzer)
- Protocol CVE disclosures: [proto-cve-disclosures](https://github.com/LL-V/proto-cve-disclosures)
