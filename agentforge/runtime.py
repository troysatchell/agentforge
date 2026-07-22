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
    raise NotImplementedError("PERF1: retry_with_backoff not implemented yet")


class BoundedWorkQueue:
    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._items: list[Any] = []

    @property
    def depth(self) -> int:
        return len(self._items)

    def put(self, item: Any) -> None:
        raise NotImplementedError("PERF1: BoundedWorkQueue.put not implemented yet")

    def get(self) -> Any:
        raise NotImplementedError("PERF1: BoundedWorkQueue.get not implemented yet")
