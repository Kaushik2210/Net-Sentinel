"""Zeek log adapter: ``conn.log`` and ``dns.log`` (tab-separated or JSON-lines) -> normalized events.

This is a *batch* adapter: it reads log files that Zeek (https://zeek.org) has already written. It does not tail a
running sensor; that streaming adapter is future work. Output feeds the same pipeline as PCAP: flows go through
``flow_event`` so detectors and replay see one vocabulary regardless of the source.

Limits of what conn.log can tell us (same honesty rule as PCAP): Zeek's ``conn_state`` tells us whether a TCP
connection was answered or rejected, but not whether a login succeeded. Admin-protocol outcomes are therefore
inferred from flow shape and flagged ``inferred``.
"""

import json
from datetime import UTC, datetime

from app.detection.base import EventRecord
from app.ingest.pcap import MAX_BYTES, MAX_EVENTS, ParseStats, PcapError, flow_event
from app.models.base import new_id

# conn_state values meaning the responder never completed the handshake.
_UNANSWERED = {"S0", "SH", "OTH"}
_REJECTED = {"REJ", "RSTOS0", "RSTRH", "SHR"}


def looks_like_zeek(data: bytes) -> bool:
    head = data[:256].lstrip()
    return head.startswith(b"#separator") or head.startswith(b"#fields") or (head.startswith(b"{") and b'"ts"' in data[:512])


def _num(v, default=0.0) -> float:
    try:
        return default if v in (None, "-", "(empty)", "") else float(v)
    except (TypeError, ValueError):
        return default


def _rows(text: str):
    """Yield (path, dict) rows from TSV (with #fields header) or JSON-lines Zeek output."""
    sep, unset, path, fields = "\t", "-", "conn", None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.startswith("#separator"):
                # Written as "#separator \x09": a space, then an escaped separator.
                val = line.partition(" ")[2].strip()
                sep = val.encode("utf-8").decode("unicode_escape") or "\t"
                continue
            key, _, val = line[1:].partition(sep)
            if key == "unset_field":
                unset = val.strip()
            elif key == "path":
                path = val.strip()
            elif key == "fields":
                fields = val.split(sep)
            continue
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            yield ("dns" if "query" in row else "conn"), row
        elif fields:
            parts = line.split(sep)
            if len(parts) < len(fields):
                continue
            yield path, {k: (None if v == unset else v) for k, v in zip(fields, parts, strict=False)}


def parse_zeek(data: bytes) -> tuple[list[EventRecord], ParseStats]:
    if len(data) > MAX_BYTES:
        raise PcapError(f"file exceeds the {MAX_BYTES // (1024 * 1024)} MB limit")
    if not looks_like_zeek(data):
        raise PcapError("not a Zeek log (expected a #fields TSV header or JSON lines with a 'ts' field)")
    stats = ParseStats()
    events: list[EventRecord] = []
    for path, row in _rows(data.decode("utf-8", "replace")):
        stats.packets += 1  # rows read (field name shared with the PCAP stats)
        ts = _num(row.get("ts"))
        src, dst = row.get("id.orig_h"), row.get("id.resp_h")
        if not ts or not src or not dst or ":" in src or ":" in dst:
            stats.skipped_non_ip += 1  # missing fields or IPv6
            continue
        stats.ipv4 += 1
        stats.first_ts = ts if stats.first_ts is None else min(stats.first_ts, ts)
        stats.last_ts = ts if stats.last_ts is None else max(stats.last_ts, ts)
        if path == "dns" or "query" in row:
            q = (row.get("query") or "").rstrip(".")
            if not q:
                continue
            stats.dns_queries += 1
            events.append(EventRecord(id=new_id("evt"), ts=datetime.fromtimestamp(ts, tz=UTC), src_ip=src, dst_ip=dst, dst_port=int(_num(row.get("id.resp_p"), 53)) or 53,
                                      protocol="dns", event_type="dns_query", bytes_sent=int(_num(row.get("orig_bytes"))), attributes={"domain": q[:253]}))
            continue
        proto = (row.get("proto") or "tcp").lower()
        if proto != "tcp":
            stats.skipped_other_l4 += 1
            continue
        stats.flows += 1
        state = row.get("conn_state") or ""
        events.append(flow_event(src, dst, int(_num(row.get("id.resp_p"))), ts, _num(row.get("duration")), int(_num(row.get("orig_bytes"))), int(_num(row.get("resp_bytes"))),
                                 unanswered=state in _UNANSWERED, rejected=state in _REJECTED))
    if stats.ipv4 == 0:
        raise PcapError("Zeek log contains no usable IPv4 rows")
    events.sort(key=lambda e: e.ts)
    if len(events) > MAX_EVENTS:
        stats.truncated = True
        stats.notes.append(f"kept the first {MAX_EVENTS} of {len(events)} events")
        events = events[:MAX_EVENTS]
    return events, stats
