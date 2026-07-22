"""PERF2 / TRO-131 — load/baseline profiling harness (STUB for the RED phase;
replaced by the PERF2 coding agent).

Runs a representative attack workload through injected stage callables, timing
each stage, and reports per-stage latency + throughput + the bottleneck — the
baseline the submission measures future performance against.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class StageLatency:
    stage: str
    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float


@dataclass(frozen=True)
class LoadProfile:
    attacks: int
    wall_ms: float
    throughput_per_s: float
    stages: dict  # dict[str, StageLatency]
    bottleneck: str


def default_timer(fn: Callable[[], Any]) -> tuple[Any, float]:
    """Measure ``fn()`` and return ``(result, elapsed_ms)``."""
    start = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - start) * 1000.0


def run_load(
    n: int,
    *,
    generate: Callable[[], Any],
    judge: Callable[[Any], Any],
    persist: Callable[[Any], Any],
    timer: Callable[[Callable[[], Any]], tuple[Any, float]] = default_timer,
) -> LoadProfile:
    raise NotImplementedError("PERF2: run_load not implemented yet")
