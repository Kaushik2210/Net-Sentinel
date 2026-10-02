import asyncio
import threading

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.core.deps import Analyst, CurrentUser, DbSession, client_ip
from app.models import Dataset
from app.research.evaluate import run_evaluation
from app.services import audit

router = APIRouter(prefix="/research", tags=["research"])
_run_lock = threading.Lock()
BENCH = "synthetic-benchmark"

# Dataset architecture. Public datasets are NOT bundled or redistributed; see docs/DATASETS.md.
SUPPORTED = [
    {"name": "Synthetic benchmark", "kind": "synthetic", "status": "available", "note": "Generated on demand from the simulator. Used for the results on this page."},
    {"name": "Custom PCAP", "kind": "pcap", "status": "available", "note": "Upload on the Replay page. Unlabelled, so it can be replayed but not scored."},
    {"name": "CICIDS-style flow CSV", "kind": "cicids", "status": "adapter documented, not bundled",
     "note": "Obtain from the publisher under its terms; map columns per docs/DATASETS.md."},
    {"name": "UNSW-NB15-style flow CSV", "kind": "unsw-nb15", "status": "adapter documented, not bundled",
     "note": "Obtain from the publisher under its terms; map columns per docs/DATASETS.md."},
]


@router.get("")
def latest(_: CurrentUser, db: DbSession) -> dict:
    row = db.scalar(select(Dataset).where(Dataset.name == BENCH))
    return {"result": row.meta if row else None, "supported_datasets": SUPPORTED}


@router.post("/run")
async def run(request: Request, user: Analyst, db: DbSession) -> dict:
    """Run the evaluation (about 20 s, CPU-bound, so one at a time) and store the latest result."""
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(409, "An evaluation is already running")
    try:
        result = await asyncio.to_thread(run_evaluation)
    finally:
        _run_lock.release()
    row = db.scalar(select(Dataset).where(Dataset.name == BENCH))
    if row is None:
        row = Dataset(name=BENCH, kind="synthetic", license="generated in-process")
        db.add(row)
    row.records, row.meta = result["trials"], result
    db.commit()
    audit.record(db, user.username, "research.run", BENCH, client_ip(request), trials=result["trials"])
    return {"result": result, "supported_datasets": SUPPORTED}
