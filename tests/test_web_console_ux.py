"""Tests for the console monitoring-UX SSE data (E13 / TRO-138).

The UI (index.html) is verified live; here we freeze the *data* the runner streams:
CON2 orchestrator decision + halt reasons, and CON3 per-agent cost attribution.
Network paths (_run_one) are mocked — no live target.
"""

from __future__ import annotations

import asyncio

from agentforge.web import runner
from agentforge.web.runner import STATE, _cost_by_agent, _next_reason, run_campaign


def test_cost_by_agent_attributes_generation_to_red_team():
    cba = _cost_by_agent({"cost_usd": 0.02})
    assert cba["red_team"] == 0.02
    assert cba["judge"] == 0.0  # deterministic oracles cost nothing
    assert cba["documentation"] == 0.0  # not invoked in the live console path
    assert set(cba) == {"red_team", "judge", "documentation"}


def test_next_reason_names_the_targeted_category():
    assert "tool_misuse" in _next_reason("tool_misuse", {"tool_misuse": 0})


def _canned(verdict="fail", severity="low", cost=0.01):
    def fake(token, spec, seq):
        return {
            "seq": seq, "attack_id": f"a{seq}", "category": spec[0], "subcategory": spec[1],
            "owasp": spec[2], "route": "/r", "http_status": 200, "verdict": verdict,
            "severity": severity, "predicate": None, "cost_usd": cost,
            "agent_path": ["orchestrator", "red_team", "target", "judge"], "ts": "t",
        }
    return fake


def _drive(**kw):
    async def go():
        return [e async for e in run_campaign("tok", **kw)]
    return asyncio.run(go())


def test_emits_a_decision_before_each_attempt_and_per_agent_cost(monkeypatch):
    monkeypatch.setattr(runner, "_run_one", _canned(cost=0.01))
    STATE.stop = False
    events = _drive(categories=["tool_misuse"])
    kinds = [e["event"] for e in events]
    assert kinds[0] == "start"
    decision = next(e for e in events if e["event"] == "decision")
    assert decision["data"]["category"] == "tool_misuse" and decision["data"]["reason"]
    attempt = next(e for e in events if e["event"] == "attempt")
    assert attempt["data"]["cost_by_agent"]["red_team"] == 0.01
    assert kinds[-1] == "done" and events[-1]["data"]["reason"]


def test_halts_on_cost_without_signal(monkeypatch):
    monkeypatch.setattr(runner, "_run_one", _canned(verdict="fail", cost=1.0))
    STATE.stop = False
    events = _drive(budget_usd=0.5)  # first held attempt blows the budget with no breach
    stop = next((e for e in events if e["event"] == "stopped"), None)
    assert stop is not None
    assert "cost" in stop["data"]["reason"].lower()


def test_does_not_halt_when_a_breach_is_found(monkeypatch):
    monkeypatch.setattr(runner, "_run_one", _canned(verdict="success", severity="critical", cost=1.0))
    STATE.stop = False
    events = _drive(categories=["tool_misuse"], budget_usd=0.5)
    assert events[-1]["event"] == "done"  # a breach is signal — no cost-without-signal halt
