"""LangGraph state-graph SKELETON: Orchestrator -> Red Team -> Judge.

Threads a single ``correlation_id`` through typed graph state and produces,
in order, a schema-valid ``AttackDirective`` (edge 1), ``AttackResult``
(edge 3), and ``Verdict`` (edge 5) — see ``agentforge.contracts``.

Red Team (Kimi) and Judge (Sonnet 5) need API keys we do not have yet, so
both nodes here are DETERMINISTIC STUBS: they construct schema-valid
contract instances with NO network / NO API calls. This proves the graph
wiring + typed state + correlation_id threading, not real attacks. Swap the
node bodies for real model calls once keys exist — the graph shape and
``State`` contract stay the same.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import AttackDirective, AuthorizedScope, Budget
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import JudgeType, Outcome, Severity, Verdict


class State(TypedDict, total=False):
    """Graph state threaded across all three nodes.

    ``correlation_id`` is the only field required on the initial invoke;
    ``directive`` / ``result`` / ``verdict`` start unset and are populated
    by the Orchestrator, Red Team, and Judge nodes respectively.
    """

    correlation_id: str
    directive: AttackDirective | None
    result: AttackResult | None
    verdict: Verdict | None


def orchestrator_node(state: State) -> dict[str, AttackDirective]:
    """Deterministic stub: issues one directive for the given correlation_id.

    A real Orchestrator reads coverage state (open findings, cases tested)
    to choose what to attack next; the stub always issues the same fixed,
    schema-valid directive shape so the wiring can be proven without a model.
    """
    correlation_id = state["correlation_id"]
    directive = AttackDirective(
        directive_id=uuid.uuid4(),
        correlation_id=correlation_id,
        attack_category=AttackCategory.PROMPT_INJECTION,
        owasp_mapping=OwaspMapping(web=None, llm="LLM01:2025-prompt-injection"),
        authorized_scope=AuthorizedScope(authorized_patient_uuid=f"stub-patient-{correlation_id}"),
        budget=Budget(max_usd=1.0, max_attempts=1),
        issued_at=datetime.now(timezone.utc),
    )
    return {"directive": directive}


def redteam_node(state: State) -> dict[str, AttackResult]:
    """Deterministic stub standing in for the Kimi-backed Red Team agent.

    No network / no API call — Kimi keys are not provisioned yet. Consumes
    the directive from state and returns a schema-valid ``AttackResult``
    that references it, without actually attacking a live target.
    """
    directive = state["directive"]
    if directive is None:
        raise ValueError("redteam_node requires a directive from the orchestrator node")

    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id=state["correlation_id"],
        directive_id=directive.directive_id,
        attack_category=directive.attack_category,
        owasp_mapping=directive.owasp_mapping,
        sequence_hash="stub-sequence-hash",
        input_sequence=[InputTurn(turn_index=0, route="/stub/route", payload={"stub": True})],
        target_response=TargetResponse(http_status=200, body={"stub": "deterministic-stub-response"}),
        executed_at=datetime.now(timezone.utc),
    )
    return {"result": result}


def judge_node(state: State) -> dict[str, Verdict]:
    """Deterministic stub standing in for the Sonnet-5-backed Judge agent.

    No network / no API call — Sonnet 5 keys are not provisioned yet.
    Consumes the result from state and returns a schema-valid ``Verdict``
    that adjudicates it, always as a deterministic-oracle fail so no
    real judgment is implied by the stub.
    """
    result = state["result"]
    if result is None:
        raise ValueError("judge_node requires a result from the red_team node")

    verdict = Verdict(
        verdict_id=uuid.uuid4(),
        attack_id=result.attack_id,
        correlation_id=state["correlation_id"],
        outcome=Outcome.FAIL,
        predicate_fired=None,
        judge_type=JudgeType.DETERMINISTIC_ORACLE,
        severity=Severity.LOW,
        regression_flag=False,
        adjudicated_at=datetime.now(timezone.utc),
    )
    return {"verdict": verdict}


def build_graph() -> CompiledStateGraph:
    """Compile the Orchestrator -> Red Team -> Judge state graph."""
    graph = StateGraph(State)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("red_team", redteam_node)
    graph.add_node("judge", judge_node)

    graph.add_edge(START, "orchestrator")
    graph.add_edge("orchestrator", "red_team")
    graph.add_edge("red_team", "judge")
    graph.add_edge("judge", END)

    return graph.compile()
