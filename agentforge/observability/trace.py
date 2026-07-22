"""OBS-trace / TRO-128 — agent span model + PHI-free label + Langfuse emitter
seam (STUB for the RED phase; replaced by the OBS-trace coding agent).

The ``AgentSpan`` is the per-agent-call unit joined by ``correlation_id`` and
ordered by ``started_at`` (Q6). Emission goes through an injected seam so the
platform is unit-tested without Langfuse/network. Labels are PHI-free.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Protocol, runtime_checkable

from pydantic import Field, field_validator

from agentforge.contracts.common import AttackCategory, OracleResult, StrictModel


class AgentName(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RED_TEAM = "red_team"
    JUDGE = "judge"
    DOCUMENTATION = "documentation"


class AgentSpan(StrictModel):
    """One agent model-call span. StrictModel (extra=forbid) so it can never
    carry raw response bytes — only PHI-free labels/counts/status."""

    agent: AgentName
    correlation_id: str
    started_at: datetime
    model: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0)
    attack_category: AttackCategory | None = None
    label: str | None = None

    @field_validator("started_at")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        # Naive timestamps break started_at ordering (naive vs aware compare
        # raises) and make cross-agent joins ambiguous.
        if value.tzinfo is None:
            raise ValueError("started_at must be timezone-aware")
        return value


def phi_free_label(oracle_results: list[OracleResult]) -> str:
    """Compress oracle results into a PHI-free label carrying only each oracle's
    id and *fired status* — never the raw ``evidence`` bytes.

    ``fired`` maps ``True -> "fired"``, ``False -> "clear"``, ``None -> "n/a"``.
    e.g. ``"cross_patient=fired;phi_pattern=clear;grounding_fabrication=n/a"``.
    """
    parts = []
    for result in oracle_results:
        if result.fired is True:
            status = "fired"
        elif result.fired is False:
            status = "clear"
        else:
            status = "n/a"
        parts.append(f"{result.oracle_id}={status}")
    return ";".join(parts)


@runtime_checkable
class SpanEmitter(Protocol):
    def emit(self, span: AgentSpan) -> None: ...


class NullEmitter:
    """Default no-op emitter."""

    def emit(self, span: AgentSpan) -> None:
        return None


class CollectingEmitter:
    """Records emitted spans in memory (tests / local runs)."""

    def __init__(self) -> None:
        self.spans: list[AgentSpan] = []

    def emit(self, span: AgentSpan) -> None:
        self.spans.append(span)


def to_langfuse_generation(span: AgentSpan) -> dict:
    """Map an :class:`AgentSpan` to a Langfuse *generation* payload.

    Carries only what lives on the span — model, token usage, cost, and start
    time — plus a ``metadata`` block that threads the ``correlation_id`` join key
    and the agent/category/label dimensions. It is structurally PHI-free: an
    AgentSpan has no raw-body field, so raw response content can never leak here.
    """
    metadata: dict[str, Any] = {
        "correlation_id": span.correlation_id,
        "agent": span.agent.value,
        "attack_category": span.attack_category.value if span.attack_category else None,
        "label": span.label,
    }
    end_time = (
        (span.started_at + timedelta(milliseconds=span.latency_ms)).isoformat()
        if span.latency_ms is not None
        else None
    )
    return {
        # traceId = the correlation_id so every agent generation links to the one
        # trace that a verdict/report can be joined back to.
        "traceId": span.correlation_id,
        "name": f"agent:{span.agent.value}",
        "model": span.model,
        "startTime": span.started_at.isoformat(),
        "endTime": end_time,
        "usage": {
            "input": span.input_tokens,
            "output": span.output_tokens,
            "unit": "TOKENS",
            "totalCost": span.cost_usd,
        },
        "metadata": metadata,
    }


class LangfuseEmitter:
    def __init__(
        self,
        transport: Callable[[str, dict, dict], dict],
        *,
        host: str,
        public_key: str | None = None,
        secret_key: str | None = None,
    ) -> None:
        self._transport = transport
        self._host = host
        self._public_key = public_key
        self._secret_key = secret_key

    def emit(self, span: AgentSpan) -> None:
        generation = to_langfuse_generation(span)
        url = f"{self._host.rstrip('/')}/api/public/ingestion"
        headers: dict[str, Any] = {"content-type": "application/json"}
        if self._public_key is not None and self._secret_key is not None:
            token = base64.b64encode(
                f"{self._public_key}:{self._secret_key}".encode()
            ).decode()
            headers["authorization"] = f"Basic {token}"
        body: dict[str, Any] = {
            "batch": [{"type": "generation-create", "body": generation}]
        }
        self._transport(url, headers, body)
