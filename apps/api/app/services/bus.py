"""In-process pub/sub for live updates.

Implements the small ``EventBus`` surface the rest of the app depends on. A Redis-backed
implementation can replace this for multi-worker deployments without touching callers.
"""

import asyncio
import contextlib
from collections.abc import AsyncIterator


class EventBus:
    def __init__(self, queue_size: int = 500):
        self._subs: set[asyncio.Queue] = set()
        self._queue_size = queue_size

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue(self._queue_size)
        self._subs.add(q)
        try:
            yield q
        finally:
            self._subs.discard(q)

    def publish(self, message: dict) -> None:
        for q in list(self._subs):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # A slow websocket consumer must never back-pressure ingestion: drop for it.
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
                with contextlib.suppress(asyncio.QueueFull):
                    q.put_nowait(message)

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)


bus = EventBus()
