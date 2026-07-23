"""Frozen tests (OBS-metrics / TRO-128) — the six questions Q1-Q4 over the store.

Q1 coverage (cases per category), Q4 open findings (confirmed successes per
category), Q2 pass/fail grouped by category x target_version, and Q3 the
resilience trend — where a RISING success-rate over versions means the target is
regressing, and the metric is unanswerable on a single version (the sustained-
null-version alarm). Frozen contract for OBS-metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.observability.metrics import (
    PassFailStat,
    ResilienceTrend,
    coverage,
    open_findings,
    pass_fail_by_version,
    resilience_trend,
)
from agentforge.store.records import ExploitRecord
from agentforge.store.sqlite_store import SqliteExploitStore

DX = AttackCategory.DATA_EXFILTRATION
PI = AttackCategory.PROMPT_INJECTION


def _rec(seq, category=DX, outcome=Outcome.SUCCESS, severity=Severity.HIGH, version="v1"):
    return ExploitRecord(
        exploit_id=seq,
        correlation_id="c",
        attack_id="a-" + seq,
        sequence_hash=seq,
        attack_category=category,
        severity=severity,
        outcome=outcome,
        target_version=version,
        adjudicated_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
    )


def _store(records):
    store = SqliteExploitStore()
    for rec in records:
        store.record(rec)
    return store


def test_coverage_counts_cases_per_category():
    cov = coverage(_store([_rec("s1", DX), _rec("s2", DX), _rec("s3", PI)]))
    assert cov[DX] == 2
    assert cov[PI] == 1


def test_open_findings_counts_confirmed_successes():
    store = _store(
        [
            _rec("s1", DX, Outcome.SUCCESS, Severity.HIGH),
            _rec("s2", DX, Outcome.FAIL, Severity.LOW),
            _rec("s3", PI, Outcome.SUCCESS, Severity.HIGH),
        ]
    )
    of = open_findings(store)
    assert of.get(DX) == 1
    assert of.get(PI) == 1


def test_pass_fail_by_version():
    pf = pass_fail_by_version(
        [
            _rec("s1", DX, Outcome.SUCCESS, version="v1"),
            _rec("s2", DX, Outcome.FAIL, version="v1"),
            _rec("s3", DX, Outcome.SUCCESS, version="v2"),
        ]
    )
    v1 = pf[(DX, "v1")]
    assert isinstance(v1, PassFailStat)
    assert (v1.total, v1.success, v1.success_rate) == (2, 1, 0.5)
    v2 = pf[(DX, "v2")]
    assert (v2.total, v2.success, v2.success_rate) == (1, 1, 1.0)


def test_resilience_trend_flags_rising_success_as_regressing():
    # success-rate rises v1(0.0) -> v2(1.0): the target is REGRESSING
    trend = resilience_trend(
        [_rec("s1", DX, Outcome.FAIL, version="v1"), _rec("s2", DX, Outcome.SUCCESS, version="v2")]
    )
    assert isinstance(trend, ResilienceTrend)
    assert trend.answerable is True
    assert trend.delta > 0.05
    assert trend.regressing is True


def test_resilience_trend_stable_is_not_regressing():
    trend = resilience_trend(
        [_rec("s1", DX, Outcome.FAIL, version="v1"), _rec("s2", DX, Outcome.FAIL, version="v2")]
    )
    assert trend.regressing is False


def test_resilience_trend_unanswerable_on_single_version():
    trend = resilience_trend(
        [_rec("s1", DX, Outcome.SUCCESS, version="v1"), _rec("s2", DX, Outcome.FAIL, version="v1")]
    )
    assert trend.answerable is False
