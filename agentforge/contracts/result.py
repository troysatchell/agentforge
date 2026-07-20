"""``AttackResult`` — mirrors ``redteam_to_judge.schema.json``.

Edge (3): Red Team hands a completed attack to the Judge for INDEPENDENT
adjudication. ``observed_hints`` is advisory only — the Judge recomputes every
verdict signal itself and never trusts the Red Team's own oracle observations
as authoritative.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from typing import Any

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping, StrictModel

# Optional AttackResult fields that are non-nullable in the schema — i.e. the
# key must be ABSENT (not null) when unset. (parent_attack_id/target_version
# are schema-nullable and are left as-is.)
_ABSENT_WHEN_NONE = ("directive_id", "attack_subcategory", "observed_hints", "execution_telemetry")


class InputTurn(StrictModel):
    """One turn of the multi-turn attack as sent to the live target."""

    turn_index: int = Field(ge=0)
    route: str
    payload: dict


class TargetResponse(StrictModel):
    """Raw target response. ``body`` is unconstrained by design — the Judge
    parses it with its own oracles."""

    http_status: int
    body: dict | str


class ExecutionTelemetry(StrictModel):
    """Execution FACTS the Red Team legitimately measures (not verdict
    signals): tokens + cost of generating and executing this attack."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = Field(default=None, ge=0)


class AttackResult(StrictModel):
    """The full multi-turn attack + target response handed to the Judge."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    attack_id: uuid.UUID
    correlation_id: str
    directive_id: uuid.UUID | None = None
    parent_attack_id: str | None = None
    attack_category: AttackCategory
    attack_subcategory: str | None = None
    owasp_mapping: OwaspMapping
    sequence_hash: str
    input_sequence: list[InputTurn] = Field(min_length=1)
    target_response: TargetResponse
    observed_hints: list[OracleResult] | None = None
    execution_telemetry: ExecutionTelemetry | None = None
    target_version: str | None = None
    executed_at: datetime

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)
        for key in _ABSENT_WHEN_NONE:
            if data.get(key) is None:
                data.pop(key, None)
        return data
