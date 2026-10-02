"""Per-username failed-login throttle (in addition to the per-IP rate limit).

Keyed by the *submitted* username whether or not it exists, so throttling reveals nothing about which
accounts are real. Trade-off: an attacker can deliberately lock a known username for a few minutes;
that is preferred over unlimited guessing. In-memory and per process: use a shared store (Redis) if
the API is scaled to multiple workers.
"""

import threading
import time
from collections import OrderedDict, deque

MAX_FAILURES = 8
WINDOW_S = 15 * 60
MAX_TRACKED = 10_000

_lock = threading.Lock()
_failures: "OrderedDict[str, deque[float]]" = OrderedDict()


def _recent(key: str, now: float) -> deque[float]:
    q = _failures.setdefault(key, deque())
    while q and now - q[0] > WINDOW_S:
        q.popleft()
    return q


def retry_after(username: str) -> int:
    """Seconds until another attempt is allowed (0 if not locked)."""
    key, now = username.strip().lower(), time.monotonic()
    with _lock:
        q = _recent(key, now)
        if len(q) < MAX_FAILURES:
            return 0
        return max(1, int(WINDOW_S - (now - q[0])))


def record_failure(username: str) -> None:
    key, now = username.strip().lower(), time.monotonic()
    with _lock:
        _recent(key, now).append(now)
        _failures.move_to_end(key)
        while len(_failures) > MAX_TRACKED:
            _failures.popitem(last=False)


def clear(username: str) -> None:
    with _lock:
        _failures.pop(username.strip().lower(), None)


def reset_all() -> None:
    with _lock:
        _failures.clear()
