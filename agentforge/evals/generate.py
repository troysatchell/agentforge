"""EV4 / TRO-129 — promote an executed attack into a replayable EvalCase (STUB
for the RED phase; replaced by the EV4 coding agent).

Turns an adjudicated (AttackResult, Verdict) pair into an EvalCase for the
regression corpus — the "Red-Team-generated cases" path.
"""

from __future__ import annotations

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict
from agentforge.evals.case import EvalCase, OracleConfig


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
    raise NotImplementedError("EV4: to_eval_case not implemented yet")
