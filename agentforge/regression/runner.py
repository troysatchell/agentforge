"""Regression re-issue runner — STUB (TRO-127).

The exploit store persists only a ``sequence_hash``, not the raw request bytes;
the re-issuable ``input_sequence`` lives on the persisted :class:`EvalCase`. So
``reissue`` sources bytes from an ``EvalCase``, re-fires them through the injected
target client, and hands the LIVE response to the injected Judge for INDEPENDENT
adjudication — the runner never grades anything itself (Red Team / Judge / runner
separation). ``gate_red_proof`` gives a regression test teeth: it can only pass if
the exploit genuinely reproduced.

The coding agent replaces the ``NotImplementedError`` bodies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Outcome, Verdict
from agentforge.evals.case import EvalCase
from agentforge.judge import OracleContext
from agentforge.live_run import JudgeLike, TargetClientLike


class RegressionNotReproduced(Exception):
    """GateRedProof failure: a regression re-issue did not re-fire its predicate."""


@dataclass(frozen=True)
class RegressionOutcome:
    """One re-issue outcome: did the stored exploit reproduce on the live target?"""

    case_id: str
    reproduced: bool
    predicate_fired: bool
    predicate: str | None
    verdict: Verdict
    attack_result: AttackResult


def reissue(
    case: EvalCase,
    *,
    target_client: TargetClientLike,
    judge: JudgeLike,
    access_token: str,
    correlation_id: str,
) -> RegressionOutcome:
    """Re-fire a persisted case's bytes at the live target and let the Judge decide.

    The re-issuable ``input_sequence`` is sourced from ``case`` (the store holds
    only a ``sequence_hash``, no bytes). The LIVE response — never the stale
    ``recorded_response`` — is what the injected Judge adjudicates. The runner
    grades nothing itself: the returned ``verdict`` is exactly the Judge's object.
    """
    response = target_client.execute(access_token=access_token, input_sequence=case.input_sequence)
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id=correlation_id,
        attack_category=case.attack_category,
        attack_subcategory=case.attack_subcategory,
        owasp_mapping=case.owasp_mapping,
        sequence_hash=case.case_id,
        input_sequence=case.input_sequence,
        target_response=response,
        executed_at=datetime.now(timezone.utc),
    )
    ctx = OracleContext(
        result=result,
        authorized_scope=AuthorizedScope(authorized_patient_uuid=case.authorized_patient_uuid),
    )
    verdict = judge.adjudicate(ctx, correlation_id=correlation_id)
    # Reproduction requires PROOF: a success verdict whose success predicate
    # actually re-fired. A bare Outcome.SUCCESS with predicate_fired=None is not
    # proof, so it must not pass gate_red_proof (the GateRedProof contract).
    predicate_fired = bool(verdict.predicate_fired and verdict.predicate_fired.strip())
    return RegressionOutcome(
        case_id=case.case_id,
        reproduced=verdict.outcome == Outcome.SUCCESS and predicate_fired,
        predicate_fired=predicate_fired,
        predicate=verdict.predicate_fired,
        verdict=verdict,
        attack_result=result,
    )


def gate_red_proof(outcome: RegressionOutcome) -> None:
    """Raise :class:`RegressionNotReproduced` unless the exploit reproduced."""
    if not outcome.reproduced:
        raise RegressionNotReproduced(
            f"regression {outcome.case_id!r} did not re-fire its success predicate"
        )
