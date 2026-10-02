"""Background ingestion loop: pulls from the active TelemetrySource, persists in batches,
and publishes to the live bus. Batching keeps DB round-trips low as rates grow."""

import asyncio
import contextlib
import logging

from sqlalchemy import delete, func, select

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import Device, NetworkEvent
from app.services.bus import bus
from app.services.simulation import SimulationSource

log = logging.getLogger("netsentinel.ingest")
FLUSH_INTERVAL_S = 1.0
PRUNE_EVERY_S = 60


def _serialize(e: dict) -> dict:
    return {**e, "ts": e["ts"].isoformat()}


def _persist(batch: list[dict]) -> None:
    with SessionLocal() as db:
        db.add_all(NetworkEvent(**e) for e in batch)
        db.commit()


def _prune(keep: int) -> int:
    """Retention: keep the newest ``keep`` events so the demo DB cannot grow unbounded."""
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(NetworkEvent)) or 0
        if total <= keep:
            return 0
        cutoff = db.scalar(select(NetworkEvent.ts).order_by(NetworkEvent.ts.desc()).offset(keep).limit(1))
        res = db.execute(delete(NetworkEvent).where(NetworkEvent.ts <= cutoff))
        db.commit()
        return res.rowcount or 0


def _load_devices() -> list[dict]:
    with SessionLocal() as db:
        return [
            {"id": d.id, "hostname": d.hostname, "ip": d.ip, "device_type": d.device_type}
            for d in db.scalars(select(Device))
        ]


async def run_ingest() -> None:
    s = get_settings()
    if s.telemetry_mode != "simulation":
        log.info("telemetry mode '%s': no source attached", s.telemetry_mode)
        return
    devices = await asyncio.to_thread(_load_devices)
    if not devices:
        log.warning("no devices in database; simulation source not started")
        return
    source = SimulationSource(devices, s.simulation_seed)
    interval = 1.0 / max(s.simulation_events_per_second, 0.1)
    batch: list[dict] = []
    last_flush = last_prune = asyncio.get_running_loop().time()
    log.info("simulation source started (%.1f events/s)", s.simulation_events_per_second)

    while True:
        ev = source.next_event()
        batch.append(ev)
        bus.publish({"type": "event", "data": _serialize(ev)})
        now = asyncio.get_running_loop().time()
        if now - last_flush >= FLUSH_INTERVAL_S:
            to_write, batch, last_flush = batch, [], now
            try:
                await asyncio.to_thread(_persist, to_write)
            except Exception:
                log.exception("failed to persist %d events", len(to_write))
        if now - last_prune >= PRUNE_EVERY_S:
            last_prune = now
            with contextlib.suppress(Exception):
                removed = await asyncio.to_thread(_prune, s.event_retention)
                if removed:
                    log.info("pruned %d old events", removed)
        await asyncio.sleep(interval)
