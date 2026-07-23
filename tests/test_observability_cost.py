"""Frozen tests (OBS-cost / TRO-128) — per-agent cost attribution (Q5) + order (Q6).

Cost is summed per agent (Red Team vs Judge vs Documentation), per category, and
overall from the AgentSpans, plus cost-per-confirmed-finding; agent_order answers
"what is each agent doing, in what order" via started_at. Frozen contract for OBS-cost.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory
from agentforge.observability.cost import CostReport, agent_order, attribute_cost
from agentforge.observability.trace import AgentName, AgentSpan

DX = AttackCategory.DATA_EXFILTRATION
PI = AttackCategory.PROMPT_INJECTION


def _span(agent, cost, cat=None, sec=0, corr="camp-1"):
    return AgentSpan(
        agent=agent,
        correlation_id=corr,
        started_at=datetime(2026, 7, 22, 12, 0, sec, tzinfo=timezone.utc),
        cost_usd=cost,
        attack_category=cat,
    )


SPANS = [
    _span(AgentName.RED_TEAM, 0.02, DX, 0),
    _span(AgentName.JUDGE, 0.01, DX, 1),
    _span(AgentName.DOCUMENTATION, 0.05, DX, 2),
    _span(AgentName.RED_TEAM, 0.03, PI, 3),
]


def test_attribute_cost_by_agent():
    report = attribute_cost(SPANS, confirmed_findings=2)
    assert isinstance(report, CostReport)
    assert report.by_agent[AgentName.RED_TEAM] == pytest.approx(0.05)
    assert report.by_agent[AgentName.JUDGE] == pytest.approx(0.01)
    assert report.by_agent[AgentName.DOCUMENTATION] == pytest.approx(0.05)


def test_attribute_cost_by_category_and_total():
    report = attribute_cost(SPANS, confirmed_findings=2)
    assert report.by_category[DX] == pytest.approx(0.08)
    assert report.by_category[PI] == pytest.approx(0.03)
    assert report.total_usd == pytest.approx(0.11)


def test_cost_per_confirmed_finding():
    report = attribute_cost(SPANS, confirmed_findings=2)
    assert report.cost_per_confirmed_finding == pytest.approx(0.055)


def test_cost_per_confirmed_finding_none_when_zero_findings():
    report = attribute_cost(SPANS, confirmed_findings=0)
    assert report.cost_per_confirmed_finding is None


def test_none_costs_count_as_zero():
    report = attribute_cost(
        [_span(AgentName.JUDGE, None), _span(AgentName.JUDGE, 0.02)], confirmed_findings=1
    )
    assert report.by_agent[AgentName.JUDGE] == pytest.approx(0.02)
    assert report.total_usd == pytest.approx(0.02)


def test_agent_order_by_started_at():
    order = agent_order(SPANS, "camp-1")
    assert order == [AgentName.RED_TEAM, AgentName.JUDGE, AgentName.DOCUMENTATION, AgentName.RED_TEAM]


def test_agent_order_filters_by_correlation_id():
    other = _span(AgentName.ORCHESTRATOR, 0.0, corr="camp-2")
    order = agent_order([other, *SPANS], "camp-1")
    assert AgentName.ORCHESTRATOR not in order
