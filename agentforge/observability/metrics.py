"""OBS-metrics / TRO-128 — the six required questions Q1-Q4 over the exploit
store (STUB for the RED phase; replaced by the OBS-metrics coding agent).

Q1 coverage · Q2 pass/fail x version · Q3 resilience trend · Q4 open findings.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome
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
    """Q1 — adjudicated attacks per category (the coverage signal)."""
    return store.cases_tested_by_category()


def open_findings(store: ExploitStore) -> dict[AttackCategory, int]:
    """Q4 — confirmed, non-false-positive successes per category."""
    return store.open_findings_by_category()


def pass_fail_by_version(
    records: Iterable[ExploitRecord],
) -> dict[tuple[AttackCategory, str | None], PassFailStat]:
    """Q2 — pass/fail grouped by (attack_category, target_version)."""
    totals: dict[tuple[AttackCategory, str | None], int] = defaultdict(int)
    successes: dict[tuple[AttackCategory, str | None], int] = defaultdict(int)
    for rec in records:
        key = (rec.attack_category, rec.target_version)
        totals[key] += 1
        if rec.outcome is Outcome.SUCCESS:
            successes[key] += 1
    return {
        key: PassFailStat(
            total=total,
            success=successes[key],
            success_rate=successes[key] / total,
        )
        for key, total in totals.items()
    }


_VERSION_CHUNK_RE = re.compile(r"(\d+)")


def _natural_version_key(version: str) -> list[tuple[int, object]]:
    """Natural-order key so 'v2' sorts before 'v10'. Digit runs compare as ints;
    the (rank, value) tuples keep int and str chunks mutually comparable across
    heterogeneous version formats."""
    return [
        (0, int(part)) if part.isdigit() else (1, part)
        for part in _VERSION_CHUNK_RE.split(version)
        if part
    ]


def resilience_trend(records: Iterable[ExploitRecord]) -> ResilienceTrend:
    """Q3 — overall success-rate per target_version, ordered by version.

    A RISING success-rate over versions means the target is REGRESSING (the
    exploit surface is widening). The metric is unanswerable — the sustained-
    null-version alarm — when fewer than two distinct non-null versions have
    been adjudicated; unanswerable implies ``regressing=False``.
    """
    totals: dict[str, int] = defaultdict(int)
    successes: dict[str, int] = defaultdict(int)
    for rec in records:
        version = rec.target_version
        if version is None:
            continue
        totals[version] += 1
        if rec.outcome is Outcome.SUCCESS:
            successes[version] += 1

    # Order by NATURAL version progression (v2 before v10) — release order by
    # construction, independent of adjudication order (backfill-safe).
    ordered = sorted(totals, key=_natural_version_key)
    by_version = [(version, successes[version] / totals[version]) for version in ordered]

    answerable = len(by_version) >= 2
    delta = by_version[-1][1] - by_version[0][1] if answerable else 0.0
    regressing = answerable and delta > 0.05
    return ResilienceTrend(
        by_version=by_version,
        delta=delta,
        regressing=regressing,
        answerable=answerable,
    )
