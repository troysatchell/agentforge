"""OBS-trace / TRO-128 — agent span model + PHI-free label + Langfuse emitter
seam (STUB for the RED phase; replaced by the OBS-trace coding agent).

The ``AgentSpan`` is the per-agent-call unit joined by ``correlation_id`` and
ordered by ``started_at`` (Q6). Emission goes through an injected seam so the
platform is unit-tested without Langfuse/network. Labels are PHI-free.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Callable, Protocol, runtime_checkable

from pydantic import Field

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
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = Field(default=None, ge=0)
    latency_ms: float | None = None
    attack_category: AttackCategory | None = None
    label: str | None = None


def phi_free_label(oracle_results: list[OracleResult]) -> str:
    raise NotImplementedError("OBS-trace: phi_free_label not implemented yet")


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
        raise NotImplementedError("OBS-trace: CollectingEmitter.emit not implemented yet")


def to_langfuse_generation(span: AgentSpan) -> dict:
    raise NotImplementedError("OBS-trace: to_langfuse_generation not implemented yet")


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
        raise NotImplementedError("OBS-trace: LangfuseEmitter.emit not implemented yet")
