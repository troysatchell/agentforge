"""Deterministic eval replay runner — scores a recorded response through the
Judge oracles. Pure and keyless: same case in, same verdict out.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, ExecutionTelemetry
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.evals.case import EvalCase, ExpectedVerdict, OracleConfig
from agentforge.judge import DeterministicJudge, OracleContext
from agentforge.judge.oracles import (
    CostOverageOracle,
    CrossPatientOracle,
    ForeignFileBytesOracle,
    GroundingFabricationOracle,
    PhiPatternOracle,
    ToolMisuseOracle,
)

CASES_DIR = Path(__file__).resolve().parents[2] / "evals" / "cases"


@dataclass(frozen=True)
class EvalResult:
    case_id: str
    attack_category: AttackCategory
    passed: bool
    expected: ExpectedVerdict
    actual_outcome: Outcome
    actual_severity: Severity
    actual_fired: list[str]


def load_case(path: str | Path) -> EvalCase:
    return EvalCase.model_validate(json.loads(Path(path).read_text()))


def _oracles(cfg: OracleConfig) -> list:
    return [
        PhiPatternOracle(),
        CrossPatientOracle(),
        ForeignFileBytesOracle(),
        GroundingFabricationOracle(legit_source_ids=set(cfg.grounding_legit_source_ids)),
        CostOverageOracle(ceiling_usd=cfg.cost_ceiling_usd),
        ToolMisuseOracle(),
    ]


def run_case(case: EvalCase) -> EvalResult:
    """Replay one case through the deterministic Judge and compare to expected."""
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id=f"eval:{case.case_id}",
        attack_category=case.attack_category,
        owasp_mapping=case.owasp_mapping,
        sequence_hash=case.case_id,
        input_sequence=case.input_sequence,
        target_response=case.recorded_response,
        execution_telemetry=(
            ExecutionTelemetry(cost_usd=case.recorded_cost_usd)
            if case.recorded_cost_usd is not None
            else None
        ),
        executed_at=datetime.now(timezone.utc),
    )
    ctx = OracleContext(
        result=result,
        authorized_scope=AuthorizedScope(authorized_patient_uuid=case.authorized_patient_uuid),
    )
    verdict = DeterministicJudge(_oracles(case.oracle_config)).adjudicate(
        ctx, correlation_id=result.correlation_id
    )
    actual_fired = [o.oracle_id for o in verdict.oracle_results if o.fired]
    # outcome + severity must match exactly; the named oracles must be among those
    # that fired (subset — an incidental extra fire of the same severity is tolerated).
    passed = (
        verdict.outcome == case.expected.outcome
        and verdict.severity == case.expected.severity
        and set(case.expected.fired_oracle_ids) <= set(actual_fired)
    )
    return EvalResult(
        case_id=case.case_id,
        attack_category=case.attack_category,
        passed=passed,
        expected=case.expected,
        actual_outcome=verdict.outcome,
        actual_severity=verdict.severity,
        actual_fired=actual_fired,
    )


def run_suite(cases_dir: str | Path = CASES_DIR) -> list[EvalResult]:
    """Run every case in ``cases_dir`` (sorted by filename) — the reproducible gate."""
    return [run_case(load_case(p)) for p in sorted(Path(cases_dir).glob("*.json"))]


@dataclass(frozen=True)
class AccuracySummary:
    """Aggregate Judge accuracy over a batch of replayed eval cases."""

    total: int
    passed: int
    accuracy: float
    by_category: dict[AttackCategory, float]


def summarize_accuracy(results: list[EvalResult]) -> AccuracySummary:
    """Roll a batch of :class:`EvalResult` up into overall + per-category pass fractions."""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    accuracy = passed / total if total else 0.0

    per_category_total: dict[AttackCategory, int] = {}
    per_category_passed: dict[AttackCategory, int] = {}
    for r in results:
        per_category_total[r.attack_category] = per_category_total.get(r.attack_category, 0) + 1
        per_category_passed[r.attack_category] = per_category_passed.get(
            r.attack_category, 0
        ) + (1 if r.passed else 0)
    by_category = {
        category: per_category_passed[category] / count
        for category, count in per_category_total.items()
    }

    return AccuracySummary(
        total=total,
        passed=passed,
        accuracy=accuracy,
        by_category=by_category,
    )


def accuracy_drift(baseline_accuracy: float, current_accuracy: float) -> float:
    """Signed change in accuracy: ``current - baseline`` (negative == regression).

    Rounded to 10 decimals to shed IEEE-754 subtraction noise so equal accuracies
    report exactly ``0.0`` and small drifts compare cleanly.
    """
    return round(current_accuracy - baseline_accuracy, 10)
