"""OBS-metrics / TRO-128 — the six required questions Q1-Q4 over the exploit
store (STUB for the RED phase; replaced by the OBS-metrics coding agent).

Q1 coverage · Q2 pass/fail x version · Q3 resilience trend · Q4 open findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from agentforge.contracts.common import AttackCategory
from agentforge.store.base import ExploitStore
from agentforge.store.records import ExploitRecord


@dataclass(frozen=True)
class PassFailStat:
    total: int
    success: int
    success_rate: float


@dataclass(frozen=True)
class ResilienceTrend:
    by_version: list  # list[tuple[str | None, float]] ordered by version
    delta: float
    regressing: bool
    answerable: bool


def coverage(store: ExploitStore) -> dict[AttackCategory, int]:
    raise NotImplementedError("OBS-metrics: coverage not implemented yet")


def open_findings(store: ExploitStore) -> dict[AttackCategory, int]:
    raise NotImplementedError("OBS-metrics: open_findings not implemented yet")


def pass_fail_by_version(
    records: Iterable[ExploitRecord],
) -> dict[tuple[AttackCategory, str | None], PassFailStat]:
    raise NotImplementedError("OBS-metrics: pass_fail_by_version not implemented yet")


def resilience_trend(records: Iterable[ExploitRecord]) -> ResilienceTrend:
    raise NotImplementedError("OBS-metrics: resilience_trend not implemented yet")
