"""OBS-cost / TRO-128 — per-agent cost attribution (Q5) + per-agent ordering
(Q6) over AgentSpans (STUB for the RED phase; replaced by the OBS-cost agent).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from agentforge.contracts.common import AttackCategory
from agentforge.observability.trace import AgentName, AgentSpan


@dataclass(frozen=True)
class CostReport:
    by_agent: dict[AgentName, float]
    by_category: dict[AttackCategory, float]
    total_usd: float
    cost_per_confirmed_finding: float | None


def attribute_cost(spans: Iterable[AgentSpan], *, confirmed_findings: int) -> CostReport:
    raise NotImplementedError("OBS-cost: attribute_cost not implemented yet")


def agent_order(spans: Iterable[AgentSpan], correlation_id: str) -> list[AgentName]:
    raise NotImplementedError("OBS-cost: agent_order not implemented yet")
