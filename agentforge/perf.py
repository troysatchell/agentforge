"""PERF2 / TRO-131 — load/baseline profiling harness (STUB for the RED phase;
replaced by the PERF2 coding agent).

Runs a representative attack workload through injected stage callables, timing
each stage, and reports per-stage latency + throughput + the bottleneck — the
baseline the submission measures future performance against.
"""

from __future__ import annotations

import math
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


def _percentile(samples: list[float], pct: float) -> float:
    """Nearest-rank percentile — returns the constant value for a constant sample."""
    ordered = sorted(samples)
    rank = math.ceil(pct / 100.0 * len(ordered))
    idx = min(max(rank, 1), len(ordered)) - 1
    return ordered[idx]


def _summarize(stage: str, samples: list[float]) -> StageLatency:
    count = len(samples)
    return StageLatency(
        stage=stage,
        count=count,
        mean_ms=sum(samples) / count,
        p50_ms=_percentile(samples, 50.0),
        p95_ms=_percentile(samples, 95.0),
    )


def run_load(
    n: int,
    *,
    generate: Callable[[], Any],
    judge: Callable[[Any], Any],
    persist: Callable[[Any], Any],
    timer: Callable[[Callable[[], Any]], tuple[Any, float]] = default_timer,
) -> LoadProfile:
    """Drive ``n`` generate -> judge -> persist iterations through ``timer``.

    Each stage's result feeds the next; per-stage elapsed_ms is collected across
    all iterations into a :class:`LoadProfile` (latency, throughput, bottleneck).
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    samples: dict[str, list[float]] = {"generate": [], "judge": [], "persist": []}

    for _ in range(n):
        attack, gen_ms = timer(generate)
        verdict, judge_ms = timer(lambda: judge(attack))
        _persisted, persist_ms = timer(lambda: persist(verdict))
        samples["generate"].append(gen_ms)
        samples["judge"].append(judge_ms)
        samples["persist"].append(persist_ms)

    stages = {stage: _summarize(stage, s) for stage, s in samples.items()}
    wall_ms = sum(sum(s) for s in samples.values())
    throughput_per_s = n / (wall_ms / 1000.0) if wall_ms > 0 else float("inf")
    bottleneck = max(stages, key=lambda stage: stages[stage].mean_ms)

    return LoadProfile(
        attacks=n,
        wall_ms=wall_ms,
        throughput_per_s=throughput_per_s,
        stages=stages,
        bottleneck=bottleneck,
    )
