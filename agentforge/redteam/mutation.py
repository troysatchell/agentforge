"""RT1 / TRO-123 — mutation of partial-success attacks (STUB for RED phase).

Replaced by the RT1 coding agent. Mutation evolves an already-executed parent
attack toward this target's grounding-bypass and is the ONLY layer where
sampling is live (temperature 0.8-1.0). The mutated child carries
``parent_attack_id`` lineage and stays a verdict-free ``AttackResult``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from agentforge.contracts.result import AttackResult, TargetResponse
from agentforge.redteam.agent import AttackPlan, KimiLike


class Mutator:
    def __init__(self, client: KimiLike, *, target_base_url: str, temperature: float = 0.9) -> None:
        self._client = client
        self._target_base_url = target_base_url
        self._temperature = temperature

    def mutate_plan(self, parent: AttackResult, *, correlation_id: str) -> AttackPlan:
        raise NotImplementedError("RT1: mutate_plan not implemented yet")

    def assemble_child(
        self,
        plan: AttackPlan,
        target_response: TargetResponse,
        parent: AttackResult,
        *,
        correlation_id: str,
        attack_id: uuid.UUID | None = None,
        executed_at: datetime | None = None,
    ) -> AttackResult:
        raise NotImplementedError("RT1: assemble_child not implemented yet")
