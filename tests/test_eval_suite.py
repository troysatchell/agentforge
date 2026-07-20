"""The MVP eval gate: >=3 attack categories, every case reproducibly matches its
expected verdict, and the suite includes a designed false-positive guard."""

from agentforge.contracts.verdict import Outcome
from agentforge.evals import run_suite


def test_suite_covers_at_least_three_attack_categories():
    categories = {r.attack_category for r in run_suite()}
    assert len(categories) >= 3, categories


def test_every_case_matches_its_expected_verdict():
    failed = [r.case_id for r in run_suite() if not r.passed]
    assert not failed, f"cases not matching expected verdict: {failed}"


def test_suite_is_reproducible():
    def snapshot():
        return {
            (r.case_id, r.actual_outcome, r.actual_severity, tuple(sorted(r.actual_fired)))
            for r in run_suite()
        }

    assert snapshot() == snapshot()


def test_suite_includes_a_designed_false_positive_guard():
    # >=1 case whose CORRECT outcome is FAIL — a working-as-designed response the
    # Judge must not file (the FP the triage exercise is built around).
    assert any(r.actual_outcome is Outcome.FAIL for r in run_suite())
