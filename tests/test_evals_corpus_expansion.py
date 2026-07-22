"""Frozen tests (EV2 / TRO-129) — expand the eval corpus with two new categories.

Two new replay cases exercise attack categories not previously covered, each
firing an EXISTING generic oracle (reuse is correct: the oracle detects the
OUTCOME class, the case names the attack VECTOR):

  * identity_role_exploitation → scope escalation surfaces a non-authorized
    patient → the ``cross_patient`` oracle (success / high).
  * state_corruption → a V5 feedback-loop resurfaces a poisoned, fabricated
    citation → the ``grounding_fabrication`` oracle (success / medium).

These tests are the frozen contract for EV2.
"""

from __future__ import annotations

import pytest

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.evals.runner import CASES_DIR, load_case, run_case, run_suite

CASES = [
    (
        "af-identity_role_exploitation-scope-escalation-001",
        AttackCategory.IDENTITY_ROLE_EXPLOITATION,
        Outcome.SUCCESS,
        Severity.HIGH,
        "cross_patient",
    ),
    (
        "af-state_corruption-feedback-loop-001",
        AttackCategory.STATE_CORRUPTION,
        Outcome.SUCCESS,
        Severity.MEDIUM,
        "grounding_fabrication",
    ),
]


@pytest.mark.parametrize("case_id,category,outcome,severity,oracle_id", CASES)
def test_new_case_id_matches_filename_and_replays(case_id, category, outcome, severity, oracle_id):
    case = load_case(CASES_DIR / f"{case_id}.json")
    assert case.case_id == case_id  # id == filename (provenance discipline)
    assert case.attack_category == category
    assert oracle_id in case.expected.fired_oracle_ids
    result = run_case(case)
    assert result.passed is True
    assert result.actual_outcome is outcome
    assert result.actual_severity is severity
    assert oracle_id in result.actual_fired


def test_run_suite_now_covers_the_new_categories():
    covered = {r.attack_category for r in run_suite()}
    assert AttackCategory.IDENTITY_ROLE_EXPLOITATION in covered
    assert AttackCategory.STATE_CORRUPTION in covered
