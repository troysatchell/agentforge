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
    GroundingFabricationOracle,
    PhiPatternOracle,
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
        GroundingFabricationOracle(legit_source_ids=set(cfg.grounding_legit_source_ids)),
        CostOverageOracle(ceiling_usd=cfg.cost_ceiling_usd),
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
