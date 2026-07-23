"""EV4 / TRO-129 — promote an executed attack into a replayable EvalCase.

Turns an adjudicated (AttackResult, Verdict) pair into an EvalCase for the
regression corpus — the "Red-Team-generated cases" path. The recorded response
and expected verdict are lifted straight from the executed attack, so the case
round-trips through ``run_case`` to reproduce the finding.
"""

from __future__ import annotations

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict
from agentforge.evals.case import EvalCase, ExpectedVerdict, OracleConfig


def to_eval_case(
    result: AttackResult,
    verdict: Verdict,
    *,
    authorized_patient_uuid: str,
    guards_against: str,
    provenance: str,
    test_design: str = "regression",
    case_id: str | None = None,
    oracle_config: OracleConfig | None = None,
) -> EvalCase:
    """Promote an executed (AttackResult, Verdict) into a replayable EvalCase.

    The recorded response comes from the *result*; the expected verdict mirrors
    the *verdict* using the same ``fired`` derivation the eval runner applies.
    ``case_id`` defaults to a deterministic ``af-<category>-<hash>`` slug so the
    corpus follows the id==filename convention.
    """
    if str(verdict.attack_id) != str(result.attack_id):
        raise ValueError("verdict.attack_id does not match result.attack_id — refusing to combine")
    expected = ExpectedVerdict(
        outcome=verdict.outcome,
        severity=verdict.severity,
        fired_oracle_ids=[o.oracle_id for o in (verdict.oracle_results or []) if o.fired],
    )
    cost_usd = (
        result.execution_telemetry.cost_usd if result.execution_telemetry is not None else None
    )
    resolved_case_id = case_id or f"af-{result.attack_category.value}-{result.sequence_hash[:12]}"

    return EvalCase(
        case_id=resolved_case_id,
        attack_category=result.attack_category,
        attack_subcategory=result.attack_subcategory,
        owasp_mapping=result.owasp_mapping,
        test_design=test_design,
        guards_against=guards_against,
        input_sequence=result.input_sequence,
        authorized_patient_uuid=authorized_patient_uuid,
        recorded_response=result.target_response,
        oracle_config=oracle_config or OracleConfig(),
        recorded_cost_usd=cost_usd,
        expected=expected,
        provenance=provenance,
    )
