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
    if confirmed_findings < 0:
        raise ValueError("confirmed_findings must be non-negative")
    by_agent: dict[AgentName, float] = {}
    by_category: dict[AttackCategory, float] = {}
    total_usd = 0.0
    for span in spans:
        cost = span.cost_usd or 0.0
        by_agent[span.agent] = by_agent.get(span.agent, 0.0) + cost
        if span.attack_category is not None:
            by_category[span.attack_category] = (
                by_category.get(span.attack_category, 0.0) + cost
            )
        total_usd += cost
    cost_per_confirmed_finding = (
        total_usd / confirmed_findings if confirmed_findings else None
    )
    return CostReport(
        by_agent=by_agent,
        by_category=by_category,
        total_usd=total_usd,
        cost_per_confirmed_finding=cost_per_confirmed_finding,
    )


def agent_order(spans: Iterable[AgentSpan], correlation_id: str) -> list[AgentName]:
    matching = [span for span in spans if span.correlation_id == correlation_id]
    matching.sort(key=lambda span: span.started_at)
    return [span.agent for span in matching]
