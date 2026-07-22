"""Frozen tests (PERF1 / TRO-131) — platform resilience primitives.

The platform's own operational safety under load: exponential-backoff-with-jitter
retry on provider 429s (bounded, then abort with a typed error), and a bounded,
depth-monitored work queue that rejects overflow rather than growing without
bound. All timing is injected — no real sleeping. Frozen contract for PERF1.
"""

from __future__ import annotations

import random

import pytest

from agentforge.runtime import (
    BoundedWorkQueue,
    QueueOverflow,
    RateLimitExhausted,
    RuntimeAbort,
    retry_with_backoff,
)


class Throttled(Exception):
    """Stand-in for a provider 429."""


def _retryable(exc: BaseException) -> bool:
    return isinstance(exc, Throttled)


def test_retry_succeeds_after_transient_failures():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise Throttled()
        return "ok"

    delays: list[float] = []
    out = retry_with_backoff(
        fn, is_retryable=_retryable, max_attempts=5, base_delay=0.1, max_delay=5.0,
        sleep=delays.append, rng=random.Random(0),
    )
    assert out == "ok"
    assert calls["n"] == 3
    assert len(delays) == 2  # slept before each of the two retries


def test_non_retryable_propagates_immediately():
    def fn():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        retry_with_backoff(fn, is_retryable=_retryable, sleep=lambda d: None, rng=random.Random(0))


def test_raises_rate_limit_exhausted_after_max_attempts():
    def fn():
        raise Throttled()

    with pytest.raises(RateLimitExhausted):
        retry_with_backoff(
            fn, is_retryable=_retryable, max_attempts=3, sleep=lambda d: None, rng=random.Random(0)
        )


def test_backoff_delays_are_full_jitter_bounded():
    def fn():
        raise Throttled()

    delays: list[float] = []
    with pytest.raises(RateLimitExhausted):
        retry_with_backoff(
            fn, is_retryable=_retryable, max_attempts=5, base_delay=0.1, max_delay=1.0,
            sleep=delays.append, rng=random.Random(1),
        )
    # full jitter: 0 <= delay <= min(max_delay, base_delay * 2**attempt); caps non-decreasing
    caps = [min(1.0, 0.1 * (2 ** i)) for i in range(len(delays))]
    assert delays  # at least one backoff happened
    for delay, cap in zip(delays, caps):
        assert 0.0 <= delay <= cap
    assert caps == sorted(caps)


def test_typed_aborts_share_a_base():
    assert issubclass(RateLimitExhausted, RuntimeAbort)
    assert issubclass(QueueOverflow, RuntimeAbort)


def test_bounded_queue_overflow_and_depth():
    q = BoundedWorkQueue(maxsize=2)
    assert q.depth == 0
    q.put("a")
    q.put("b")
    assert q.depth == 2
    with pytest.raises(QueueOverflow):
        q.put("c")


def test_bounded_queue_is_fifo():
    q = BoundedWorkQueue(maxsize=3)
    q.put(1)
    q.put(2)
    assert q.get() == 1
    assert q.get() == 2
    assert q.depth == 0
