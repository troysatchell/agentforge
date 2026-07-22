"""PERF1 / TRO-131 — platform resilience primitives.

The platform's OWN operational safety under load: an exponential-backoff-with-
jitter retry for provider 429s, and a bounded, depth-monitored work queue that
aborts with a typed error the Orchestrator can catch rather than growing without
bound. The queue is thread-safe so concurrent attack workers can share it without
exceeding the cap.
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from typing import Any, Callable


class RuntimeAbort(Exception):
    """Base for typed platform aborts the Orchestrator can catch + halt on."""


class RateLimitExhausted(RuntimeAbort):
    """Backoff gave up after ``max_attempts`` retryable failures."""


class QueueOverflow(RuntimeAbort):
    """A bounded work queue rejected an item because it was full."""


def retry_with_backoff(
    fn: Callable[[], Any],
    *,
    is_retryable: Callable[[Exception], bool],
    max_attempts: int = 5,
    base_delay: float = 0.1,
    max_delay: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> Any:
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    if base_delay < 0 or max_delay < 0:
        raise ValueError("base_delay and max_delay must be non-negative")
    if rng is None:
        rng = random.Random()

    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as exc:  # KeyboardInterrupt/SystemExit are BaseException — they propagate
            if not is_retryable(exc):
                raise
            last_exc = exc
            if attempt == max_attempts - 1:
                break
            delay = rng.uniform(0, min(max_delay, base_delay * 2 ** attempt))
            sleep(delay)
    raise RateLimitExhausted(f"retryable call failed after {max_attempts} attempts") from last_exc


class BoundedWorkQueue:
    """A bounded, depth-monitored FIFO queue. Thread-safe (concurrent workers can
    share it without exceeding ``maxsize``); a full ``put`` raises
    :class:`QueueOverflow` — fail-fast admission control, never unbounded growth."""

    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._items: deque[Any] = deque()
        self._lock = threading.Lock()

    @property
    def depth(self) -> int:
        with self._lock:
            return len(self._items)

    def put(self, item: Any) -> None:
        with self._lock:
            if len(self._items) >= self._maxsize:
                raise QueueOverflow(f"queue full at maxsize={self._maxsize}; rejecting item")
            self._items.append(item)

    def get(self) -> Any:
        with self._lock:
            return self._items.popleft()
