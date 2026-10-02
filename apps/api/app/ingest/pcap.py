"""PCAP -> normalized events.

Packets are aggregated into flows, and flows are mapped onto the same event vocabulary the
detectors already consume (``conn_attempt``, ``dns_query``, ``tls_session`` ...).

What a PCAP can and cannot tell us (stated honestly in the UI and docs):
* Payloads of SSH/RDP/SMB/TLS are encrypted, so authentication *outcomes* are not observable.
  Admin-protocol flows are therefore classified by shape: a short, low-payload flow that ends in
  FIN/RST is treated as a failed attempt, a long or data-heavy one as an established session.
  Those events carry ``attributes.inferred = true`` so the analyst can see it is a heuristic.
* IPv4 only. Non-TCP/UDP traffic is counted but not modelled.

Safety: the input is untrusted. Size and packet counts are capped, magic bytes are checked before
parsing, the file is parsed from a temporary path that is always removed, and nothing is executed.
Scapy dissectors have had parser vulnerabilities; run replay on an isolated host for hostile captures.
"""

import contextlib
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.detection.base import EventRecord
from app.models.base import new_id

MAX_BYTES = 25 * 1024 * 1024
MAX_PACKETS = 250_000
MAX_EVENTS = 40_000

_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # pcap, microsecond
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # pcap, nanosecond
    b"\x0a\x0d\x0d\x0a",  # pcapng section header
}
ADMIN_PORTS = {22: "ssh", 3389: "rdp", 445: "smb", 5985: "winrm"}
SHORT_FLOW_SECONDS = 3.0
SHORT_FLOW_PAYLOAD = 3000


class PcapError(ValueError):
    """Raised for input we refuse to parse (bad magic, too large, unreadable)."""


@dataclass
class ParseStats:
    packets: int = 0
    ipv4: int = 0
    flows: int = 0
    dns_queries: int = 0
    skipped_non_ip: int = 0
    skipped_other_l4: int = 0
    truncated: bool = False
    first_ts: float | None = None
    last_ts: float | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class _Flow:
    init_ip: str
    init_port: int
    resp_ip: str
    resp_port: int
    first: float
    last: float
    syn: bool = False
    synack: bool = False
    rst: bool = False
    fin: bool = False
    fwd: int = 0
    rev: int = 0
    pkts: int = 0


def validate_upload(data: bytes) -> None:
    if len(data) > MAX_BYTES:
        raise PcapError(f"file exceeds the {MAX_BYTES // (1024 * 1024)} MB limit")
    if len(data) < 24 or data[:4] not in _MAGIC:
        raise PcapError("not a pcap or pcapng file (bad magic bytes)")


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


def _events_from_flow(f: _Flow) -> EventRecord | None:
    base = {
        "id": new_id("evt"), "ts": _utc(f.first), "src_ip": f.init_ip, "dst_ip": f.resp_ip, "dst_port": f.resp_port,
        "bytes_sent": f.fwd, "bytes_received": f.rev, "duration_ms": int((f.last - f.first) * 1000),
    }
    answered = f.synack or (f.rev > 0)
    if f.syn and not answered:
        return EventRecord(protocol="tcp", event_type="conn_attempt", attributes={"state": "unanswered" if not f.rst else "rejected"}, **base)
    if f.syn and f.rst and f.rev == 0 and f.fwd == 0:
        return EventRecord(protocol="tcp", event_type="conn_attempt", attributes={"state": "rejected"}, **base)
    port = f.resp_port
    if port in ADMIN_PORTS:
        short = (f.last - f.first) < SHORT_FLOW_SECONDS and (f.fwd + f.rev) <= SHORT_FLOW_PAYLOAD
        etype = "auth_failure" if short else "auth_success"
        return EventRecord(protocol=ADMIN_PORTS[port], event_type=etype, attributes={"inferred": True, "basis": "flow shape"}, **base)
    if port in (443, 8443):
        return EventRecord(protocol="tls", event_type="tls_session", **base)
    if port == 80:
        return EventRecord(protocol="http", event_type="http_request", **base)
    return EventRecord(protocol="tcp", event_type="tcp_flow", **base)


def parse_pcap(data: bytes) -> tuple[list[EventRecord], ParseStats]:
    """Parse bytes of an untrusted capture into time-ordered events."""
    validate_upload(data)
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import PcapReader

    stats = ParseStats()
    flows: dict[tuple, _Flow] = {}
    events: list[EventRecord] = []

    fd, path = tempfile.mkstemp(suffix=".pcap")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            reader = PcapReader(path)
        except Exception as exc:
            raise PcapError(f"unreadable capture: {exc}") from exc
        with reader:
            for pkt in reader:
                stats.packets += 1
                if stats.packets > MAX_PACKETS:
                    stats.truncated = True
                    stats.notes.append(f"stopped after {MAX_PACKETS} packets")
                    break
                ts = float(pkt.time)
                stats.first_ts = ts if stats.first_ts is None else min(stats.first_ts, ts)
                stats.last_ts = ts if stats.last_ts is None else max(stats.last_ts, ts)
                if IP not in pkt:
                    stats.skipped_non_ip += 1
                    continue
                stats.ipv4 += 1
                ip = pkt[IP]
                if TCP in pkt:
                    tcp = pkt[TCP]
                    a, b = (ip.src, tcp.sport), (ip.dst, tcp.dport)
                    key = (a, b) if a <= b else (b, a)
                    flags = int(tcp.flags)
                    syn, ack = bool(flags & 0x02), bool(flags & 0x10)
                    payload = len(tcp.payload)
                    f = flows.get(key)
                    if f is None:
                        # The side sending the first SYN is the initiator; otherwise first packet's sender.
                        f = flows[key] = _Flow(ip.src, tcp.sport, ip.dst, tcp.dport, ts, ts)
                    if syn and not ack and not f.syn:
                        f.syn = True
                        f.init_ip, f.init_port, f.resp_ip, f.resp_port = ip.src, tcp.sport, ip.dst, tcp.dport
                    f.last = ts
                    f.pkts += 1
                    if syn and ack:
                        f.synack = True
                    f.rst |= bool(flags & 0x04)
                    f.fin |= bool(flags & 0x01)
                    if ip.src == f.init_ip and tcp.sport == f.init_port:
                        f.fwd += payload
                    else:
                        f.rev += payload
                elif UDP in pkt:
                    if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                        stats.dns_queries += 1
                        qname = pkt[DNS].qd.qname
                        domain = (qname.decode("utf-8", "replace") if isinstance(qname, bytes) else str(qname)).rstrip(".")
                        events.append(EventRecord(
                            id=new_id("evt"), ts=_utc(ts), src_ip=ip.src, dst_ip=ip.dst, dst_port=53, protocol="dns",
                            event_type="dns_query", bytes_sent=len(pkt), bytes_received=0, attributes={"domain": domain[:253]},
                        ))
                    else:
                        stats.skipped_other_l4 += 1
                else:
                    stats.skipped_other_l4 += 1
    except PcapError:
        raise
    except Exception as exc:
        raise PcapError(f"failed while parsing capture: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)

    if stats.ipv4 == 0:
        raise PcapError("capture contains no IPv4 packets we can analyse")
    stats.flows = len(flows)
    for f in flows.values():
        ev = _events_from_flow(f)
        if ev:
            events.append(ev)
    events.sort(key=lambda e: e.ts)
    if len(events) > MAX_EVENTS:
        stats.truncated = True
        stats.notes.append(f"kept the first {MAX_EVENTS} of {len(events)} events")
        events = events[:MAX_EVENTS]
    return events, stats
