import asyncio
import hashlib
import logging

from fastapi import APIRouter, HTTPException, Request, UploadFile
from sqlalchemy import select

from app.core.deps import Admin, Analyst, CurrentUser, DbSession, client_ip
from app.ingest.pcap import MAX_BYTES, PcapError, parse_pcap, validate_upload
from app.ingest.sample import SAMPLE_OVERRIDES, build_sample_pcap
from app.ingest.zeek import looks_like_zeek, parse_zeek
from app.models import ReplaySession
from app.replay.engine import build_replay
from app.schemas.common import ORM, UTCDatetime
from app.services import audit

router = APIRouter(prefix="/replay", tags=["replay"])
log = logging.getLogger("netsentinel.ingest")


class ReplaySummary(ORM):
    id: str
    filename: str
    sha256: str
    status: str
    packet_count: int
    duration_s: float
    alert_count: int
    created_at: UTCDatetime
    error: str | None = None


def _summary(s: ReplaySession) -> ReplaySummary:
    r = s.result or {}
    return ReplaySummary(
        id=s.id, filename=s.filename, sha256=s.sha256, status=s.status, packet_count=s.packet_count,
        duration_s=r.get("duration_s", 0), alert_count=len(r.get("alerts", [])), created_at=s.created_at, error=s.error,
    )


def _process(data: bytes, overrides: dict | None) -> tuple[dict, int]:
    events, stats = parse_zeek(data) if looks_like_zeek(data) else parse_pcap(data)
    result = build_replay(events, overrides)
    result["ingest"] = {
        "packets": stats.packets, "ipv4_packets": stats.ipv4, "flows": stats.flows, "events": len(events), "dns_queries": stats.dns_queries,
        "skipped_non_ip": stats.skipped_non_ip, "skipped_other_l4": stats.skipped_other_l4, "truncated": stats.truncated, "notes": stats.notes,
        "source_format": "zeek" if looks_like_zeek(data) else "pcap",
        "heuristics": "Authentication outcomes on SSH/RDP/SMB/WinRM are inferred from flow shape (payloads are encrypted).",
    }
    return result, stats.packets


async def _run(db, filename: str, data: bytes, user, request: Request, overrides: dict | None) -> ReplaySummary:
    sess = ReplaySession(filename=filename[:255], sha256=hashlib.sha256(data).hexdigest(), status="processing", created_by=user.id)
    db.add(sess)
    db.commit()
    try:
        result, packets = await asyncio.to_thread(_process, data, overrides)
        sess.result, sess.packet_count, sess.status = result, packets, "complete"
    except PcapError as exc:
        sess.status, sess.error = "failed", str(exc)[:500]
    except Exception:
        log.exception("replay processing failed for %s", sess.id)
        sess.status, sess.error = "failed", "unexpected processing error"
    db.commit()
    audit.record(db, user.username, "replay.create", sess.id, client_ip(request), status=sess.status, sha256=sess.sha256[:16])
    return _summary(sess)


@router.post("/upload", response_model=ReplaySummary)
async def upload(file: UploadFile, request: Request, user: Analyst, db: DbSession):
    # Read at most MAX_BYTES + 1 so an oversized body is rejected without buffering all of it.
    data = await file.read(MAX_BYTES + 1)
    try:
        if not looks_like_zeek(data):
            validate_upload(data)
        elif len(data) > MAX_BYTES:
            raise PcapError("file exceeds the size limit")
    except PcapError as exc:
        raise HTTPException(422, str(exc)) from exc
    name = (file.filename or "capture.pcap").replace("\\", "/").split("/")[-1]
    return await _run(db, name, data, user, request, None)


@router.post("/sample", response_model=ReplaySummary)
async def sample(request: Request, user: Analyst, db: DbSession):
    """Generate a synthetic capture and replay it through the real pcap pipeline."""
    data = await asyncio.to_thread(build_sample_pcap)
    return await _run(db, "synthetic-attack-sample.pcap", data, user, request, SAMPLE_OVERRIDES)


@router.get("", response_model=list[ReplaySummary])
def list_sessions(_: CurrentUser, db: DbSession):
    rows = db.scalars(select(ReplaySession).order_by(ReplaySession.created_at.desc()).limit(50)).all()
    return [_summary(s) for s in rows]


@router.get("/{session_id}")
def get_session(session_id: str, _: CurrentUser, db: DbSession) -> dict:
    s = db.get(ReplaySession, session_id)
    if s is None:
        raise HTTPException(404, "Replay session not found")
    return {"summary": _summary(s).model_dump(mode="json"), "result": s.result}


@router.delete("/{session_id}", status_code=204)
def delete_session(session_id: str, request: Request, user: Admin, db: DbSession):
    s = db.get(ReplaySession, session_id)
    if s is None:
        raise HTTPException(404, "Replay session not found")
    db.delete(s)
    db.commit()
    audit.record(db, user.username, "replay.delete", session_id, client_ip(request))
