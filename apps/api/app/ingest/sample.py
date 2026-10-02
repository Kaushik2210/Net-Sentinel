"""Generates a small *synthetic* capture (with Scapy) for demos and tests.

Nothing here is real traffic. The capture is built, written to a real pcap file and then parsed by
the same code path as an upload, so the replay demo exercises the genuine pipeline.

Timeline (attacker 10.0.20.22), ~7 minutes:
  0:00 benign background (DNS + TLS from six workstations)
  0:30 host sweep (SYN to 24 hosts, unanswered)
  1:30 port scan of 10.0.30.12 (40 ports, RST)
  2:30 SSH brute force of 10.0.20.35 (40 short sessions)
  3:30 long SSH session (access), then lateral SSH sessions to two more hosts
  4:30 DNS tunnelling-style lookups
  5:30 exfiltration over TLS to 198.51.100.77 (~4 MB; threshold is scaled in replay, see below)

Real exfiltration volumes cannot be stored in a small sample, so the sample replay lowers
``DataExfiltrationDetector.min_bytes``; this override is recorded in the replay result and shown in the UI.
"""

import contextlib
import os
import random
import string
import tempfile

SAMPLE_OVERRIDES = {"DataExfiltrationDetector": {"min_bytes": 3_000_000}}
T0 = 1_790_000_000.0  # fixed epoch so the sample is reproducible
ATTACKER = "10.0.20.22"
C2 = "198.51.100.77"


def build_sample_pcap(seed: int = 11) -> bytes:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    rng = random.Random(seed)  # noqa: S311 - synthetic data
    pkts = []

    def add(pkt, t):
        pkt.time = t
        pkts.append(pkt)

    def flow(src, dst, sport, dport, t, fwd=0, rev=0, dur=0.5, ack_syn=True, rst_end=False):
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"), t)
        if not ack_syn:
            if rst_end:
                add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="RA"), t + 0.01)
            return
        add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA"), t + 0.01)
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A"), t + 0.02)
        sent = 0
        while sent < fwd:
            n = min(1400, fwd - sent)
            add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"x" * n), t + 0.03 + dur * sent / max(fwd, 1))
            sent += n
        got = 0
        while got < rev:
            n = min(1400, rev - got)
            add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA") / Raw(b"y" * n), t + 0.04 + dur * got / max(rev, 1))
            got += n
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA"), t + dur)

    def dns(src, name, t):
        add(IP(src=src, dst="10.0.10.14") / UDP(sport=rng.randint(30000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=name)), t)

    benign = [f"10.0.20.{n}" for n in (12, 14, 15, 16, 18, 24)]
    for minute in range(7):
        for host in benign:
            for _ in range(rng.randint(2, 4)):
                t = T0 + minute * 60 + rng.uniform(0, 59)
                dns(host, rng.choice(["updates.example.org", "cdn.example.net", "mail.example.com", "api.example.io"]), t)
                flow(host, f"198.51.100.{rng.randint(2, 60)}", rng.randint(30000, 60000), 443, t + 0.1, fwd=rng.randint(300, 2000), rev=rng.randint(1000, 6000))

    for i in range(24):  # 0:30 host sweep
        flow(ATTACKER, f"10.0.{rng.choice([10, 20, 30])}.{40 + i}", 40000 + i, 443, T0 + 30 + i * 1.2, ack_syn=False)
    for i, port in enumerate(rng.sample(range(20, 9000), 40)):  # 1:30 port scan
        flow(ATTACKER, "10.0.30.12", 41000 + i, port, T0 + 90 + i * 0.4, ack_syn=False, rst_end=True)
    for i in range(40):  # 2:30 SSH brute force: short, low-payload sessions
        flow(ATTACKER, "10.0.20.35", 42000 + i, 22, T0 + 150 + i * 0.9, fwd=120, rev=140, dur=0.6)
    flow(ATTACKER, "10.0.20.35", 43000, 22, T0 + 210, fwd=9000, rev=14000, dur=40)  # 3:30 access
    flow(ATTACKER, "10.0.20.12", 43001, 22, T0 + 232, fwd=8000, rev=12000, dur=25)  # lateral
    flow(ATTACKER, "10.0.30.12", 43002, 22, T0 + 240, fwd=8000, rev=12000, dur=25)
    flow(ATTACKER, "10.0.20.14", 43003, 22, T0 + 250, fwd=8000, rev=12000, dur=25)
    for i in range(45):  # 4:30 DNS tunnelling-style lookups
        label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=28))
        dns(ATTACKER, f"{label}.exfil-test.example", T0 + 270 + i * 1.0)
    for i in range(4):  # 5:30 exfiltration ~1 MB per session
        flow(ATTACKER, C2, 44000 + i, 443, T0 + 330 + i * 8, fwd=1_000_000, rev=2000, dur=6)

    pkts.sort(key=lambda p: float(p.time))
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, pkts)
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)
