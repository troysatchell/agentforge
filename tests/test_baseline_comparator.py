"""Frozen tests (TRO-150) — BaselineComparator over target_version.

FROZEN CONTRACT: the coding agent implements `compare_to_baseline` +
`BaselineComparison` in `agentforge/observability/metrics.py` to make these pass.
It must NOT edit this file.

Semantics (aligned with `resilience_trend`): a RISING success-rate means the
target got MORE exploitable, i.e. a regression. A category regresses when its
current success-rate exceeds the baseline by strictly MORE than `threshold_pp`
integer percentage points. Independently, a per-category coverage floor breach
(fewer adjudicated attacks than the floor) is also a regression.
"""

from __future__ import annotations

from agentforge.contracts.common import AttackCategory
from agentforge.observability.metrics import BaselineComparison, compare_to_baseline

A = AttackCategory("prompt_injection")
B = AttackCategory("data_exfiltration")


def test_no_change_is_not_a_regression() -> None:
    r = compare_to_baseline(
        baseline={A: 0.20, B: 0.50},
        current={A: 0.20, B: 0.50},
        current_coverage={A: 10, B: 10},
        coverage_floors={A: 5, B: 5},
    )
    assert isinstance(r, BaselineComparison)
    assert r.regressed is False
    assert list(r.regressed_categories) == []
    assert list(r.coverage_breaches) == []
    assert r.overall_delta_pp == 0


def test_success_rate_rising_more_than_5pp_is_a_regression() -> None:
    # prompt_injection got more exploitable: 20% -> 32% (+12pp)
    r = compare_to_baseline(
        baseline={A: 0.20, B: 0.50},
        current={A: 0.32, B: 0.50},
        current_coverage={A: 10, B: 10},
        coverage_floors={A: 5, B: 5},
    )
    assert r.regressed is True
    assert A in r.regressed_categories
    assert B not in r.regressed_categories


def test_boundary_exactly_5pp_is_not_a_regression() -> None:
    # +5pp exactly; the gate is strictly greater-than.
    r = compare_to_baseline(
        baseline={A: 0.20},
        current={A: 0.25},
        current_coverage={A: 10},
        coverage_floors={A: 5},
    )
    assert r.regressed is False
    assert list(r.regressed_categories) == []


def test_coverage_floor_breach_is_a_regression() -> None:
    r = compare_to_baseline(
        baseline={A: 0.20, B: 0.20},
        current={A: 0.20, B: 0.20},
        current_coverage={A: 10, B: 2},  # B below its floor of 5
        coverage_floors={A: 5, B: 5},
    )
    assert r.regressed is True
    assert B in r.coverage_breaches
    assert A not in r.coverage_breaches
    assert list(r.regressed_categories) == []  # no success-rate regression


def test_overall_delta_pp_is_a_signed_integer() -> None:
    r = compare_to_baseline(
        baseline={A: 0.10, B: 0.10},
        current={A: 0.20, B: 0.20},  # +10pp on both -> overall +10pp
        current_coverage={A: 10, B: 10},
        coverage_floors={A: 5, B: 5},
    )
    assert isinstance(r.overall_delta_pp, int)
    assert r.overall_delta_pp == 10


def test_improving_target_has_negative_overall_delta() -> None:
    r = compare_to_baseline(
        baseline={A: 0.40, B: 0.40},
        current={A: 0.20, B: 0.20},  # target hardened -> -20pp
        current_coverage={A: 10, B: 10},
        coverage_floors={A: 5, B: 5},
    )
    assert r.overall_delta_pp == -20
    assert r.regressed is False


def test_threshold_is_configurable() -> None:
    r = compare_to_baseline(
        baseline={A: 0.20},
        current={A: 0.28},  # +8pp
        current_coverage={A: 10},
        coverage_floors={A: 5},
        threshold_pp=10,  # 8 <= 10 -> not a regression
    )
    assert r.regressed is False


def test_coverage_floors_optional_means_no_floor_check() -> None:
    r = compare_to_baseline(
        baseline={A: 0.20},
        current={A: 0.20},
        current_coverage={A: 0},  # zero coverage, but no floors supplied
    )
    assert list(r.coverage_breaches) == []
    assert r.regressed is False
