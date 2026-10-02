import asyncio
import logging

from app.db.session import SessionLocal
from app.services.alerts import run_detection_cycle

log = logging.getLogger("netsentinel.detect")
INTERVAL_S = 10


def _cycle() -> int:
    with SessionLocal() as db:
        return len(run_detection_cycle(db))


async def run_detection_loop() -> None:
    """Periodically run the engine over the recent window. Failures are logged, never fatal."""
    while True:
        await asyncio.sleep(INTERVAL_S)
        try:
            await asyncio.to_thread(_cycle)
        except Exception:
            log.exception("detection cycle failed")
