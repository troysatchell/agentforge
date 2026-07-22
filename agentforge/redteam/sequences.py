"""RT2 / TRO-123 — multi-turn attack sequences (STUB for RED phase).

Replaced by the RT2 coding agent. Drives an attack turn-by-turn: each target
response is fed back into the next turn's prompt, until the model signals done
or ``max_turns`` is reached, then assembles one verdict-free ``AttackResult``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Callable

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.redteam.agent import KimiLike


class MultiTurnRunner:
    def __init__(self, client: KimiLike, *, target_base_url: str, max_turns: int = 4) -> None:
        self._client = client
        self._target_base_url = target_base_url
        self._max_turns = max_turns

    def run(
        self,
        *,
        category: AttackCategory,
        owasp_mapping: OwaspMapping,
        target: Callable[[InputTurn], TargetResponse],
        correlation_id: str,
        attack_id: uuid.UUID | None = None,
        executed_at: datetime | None = None,
    ) -> AttackResult:
        raise NotImplementedError("RT2: run not implemented yet")
