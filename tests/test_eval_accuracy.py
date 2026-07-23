"""Frozen tests (TRO-148) — aggregate Judge accuracy + drift over the labeled corpus.

FROZEN CONTRACT: the coding agent implements `AccuracySummary`,
`summarize_accuracy`, and `accuracy_drift` in `agentforge/evals/runner.py` to make
these pass. It must NOT edit this file, and must not change `run_case`/`run_suite`
behavior (the existing eval-suite gate must stay green).
"""

from __future__ import annotations

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.evals.case import ExpectedVerdict
from agentforge.evals.runner import (
    AccuracySummary,
    EvalResult,
    accuracy_drift,
    summarize_accuracy,
)

A = AttackCategory("prompt_injection")
B = AttackCategory("data_exfiltration")


def _res(case_id: str, category: AttackCategory, passed: bool) -> EvalResult:
    exp = ExpectedVerdict(outcome=Outcome.FAIL, severity=Severity.LOW, fired_oracle_ids=[])
    return EvalResult(
        case_id=case_id,
        attack_category=category,
        passed=passed,
        expected=exp,
        actual_outcome=Outcome.FAIL,
        actual_severity=Severity.LOW,
        actual_fired=[],
    )


def test_summarize_counts_and_overall_accuracy() -> None:
    results = [_res("a", A, True), _res("b", A, False), _res("c", B, True), _res("d", B, True)]
    s = summarize_accuracy(results)
    assert isinstance(s, AccuracySummary)
    assert s.total == 4
    assert s.passed == 3
    assert s.accuracy == 0.75


def test_summarize_per_category_accuracy() -> None:
    results = [_res("a", A, True), _res("b", A, False), _res("c", B, True), _res("d", B, True)]
    s = summarize_accuracy(results)
    assert s.by_category[A] == 0.5
    assert s.by_category[B] == 1.0


def test_summarize_empty_is_zero_not_crash() -> None:
    s = summarize_accuracy([])
    assert s.total == 0
    assert s.passed == 0
    assert s.accuracy == 0.0
    assert dict(s.by_category) == {}


def test_accuracy_drift_is_current_minus_baseline() -> None:
    # current worse than baseline -> negative drift (accuracy regressed)
    assert accuracy_drift(0.90, 0.75) == -0.15
    # improvement -> positive
    assert round(accuracy_drift(0.50, 0.80), 10) == 0.30
    # unchanged
    assert accuracy_drift(0.80, 0.80) == 0.0
