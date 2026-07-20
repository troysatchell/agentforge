"""``ExploitRecord`` — one adjudicated attack as persisted in the exploit DB.

Pairs the durable facts a regression run needs (``sequence_hash`` — the dedup key
and the bytes to re-issue) with the Judge's verdict fields. Built from the
(AttackResult, Verdict) pair that produced it.
"""

from __future__ import annotations

from datetime import datetime

from agentforge.contracts.common import AttackCategory, StrictModel
from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Outcome, Severity, Verdict


class ExploitRecord(StrictModel):
    """A row in the exploit DB. ``exploit_id`` is unique; ``sequence_hash`` is the
    dedup key (no duplicate attack sequences)."""

    exploit_id: str
    correlation_id: str
    attack_id: str
    sequence_hash: str
    attack_category: AttackCategory
    severity: Severity
    outcome: Outcome
    predicate_fired: str | None = None
    regression_flag: bool = False
    target_version: str | None = None
    reproduction_ref: str | None = None
    adjudicated_at: datetime

    @classmethod
    def from_verdict(
        cls,
        verdict: Verdict,
        result: AttackResult,
        *,
        exploit_id: str | None = None,
    ) -> "ExploitRecord":
        """Build a record from the verdict and the attack it adjudicated.

        ``attack_category`` and ``sequence_hash`` come from the *result* (both
        required there); everything else from the *verdict*. ``exploit_id``
        defaults to the verdict's ``reproduction_ref``, then the ``sequence_hash``.
        """
        return cls(
            exploit_id=exploit_id or verdict.reproduction_ref or result.sequence_hash,
            correlation_id=verdict.correlation_id,
            attack_id=str(verdict.attack_id),
            sequence_hash=result.sequence_hash,
            attack_category=result.attack_category,
            severity=verdict.severity,
            outcome=verdict.outcome,
            predicate_fired=verdict.predicate_fired,
            regression_flag=verdict.regression_flag,
            target_version=verdict.target_version,
            reproduction_ref=verdict.reproduction_ref,
            adjudicated_at=verdict.adjudicated_at,
        )
