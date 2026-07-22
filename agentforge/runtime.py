"""PERF1 / TRO-131 — platform resilience primitives (STUB for the RED phase;
replaced by the PERF1 coding agent).

The platform's OWN operational safety under load: an exponential-backoff-with-
jitter retry for provider 429s, and a bounded, depth-monitored work queue that
aborts with a typed error the Orchestrator can catch rather than growing without
bound.
"""

from __future__ import annotations

import random
import time
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
    is_retryable: Callable[[BaseException], bool],
    max_attempts: int = 5,
    base_delay: float = 0.1,
    max_delay: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> Any:
    if rng is None:
        rng = random.Random()
    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except BaseException as exc:  # noqa: BLE001 — retryability decided by injected predicate
            if not is_retryable(exc):
                raise
            last_exc = exc
            if attempt == max_attempts - 1:
                break
            delay = rng.uniform(0, min(max_delay, base_delay * 2 ** attempt))
            sleep(delay)
    raise RateLimitExhausted(
        f"retryable call failed after {max_attempts} attempts"
    ) from last_exc


class BoundedWorkQueue:
    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._items: list[Any] = []

    @property
    def depth(self) -> int:
        return len(self._items)

    def put(self, item: Any) -> None:
        if self.depth >= self._maxsize:
            raise QueueOverflow(
                f"queue full at maxsize={self._maxsize}; rejecting item"
            )
        self._items.append(item)

    def get(self) -> Any:
        return self._items.pop(0)
