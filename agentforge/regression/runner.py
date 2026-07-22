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

from dataclasses import dataclass

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict
from agentforge.evals.case import EvalCase
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
    raise NotImplementedError


def gate_red_proof(outcome: RegressionOutcome) -> None:
    """Raise :class:`RegressionNotReproduced` unless the exploit reproduced."""
    raise NotImplementedError
