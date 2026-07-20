"""Tests for the LangGraph state-graph SKELETON.

Wiring under test: Orchestrator -> Red Team -> Judge, threading a single
``correlation_id`` through typed graph state and producing, in order, a
schema-valid ``AttackDirective``, ``AttackResult``, and ``Verdict``.

Red Team (Kimi) and Judge (Sonnet 5) need API keys we do not have yet, so
both nodes are DETERMINISTIC STUBS — no network calls. This proves the graph
wiring + typed state + correlation_id threading, not real attacks.
"""

from __future__ import annotations

import uuid

from agentforge.contracts.directive import AttackDirective
from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict
from agentforge.graph import build_graph
from tests._contract_ids import DIRECTIVE, RESULT, VERDICT


def test_build_graph_returns_a_compiled_invokable_graph():
    graph = build_graph()
    assert hasattr(graph, "invoke")


def test_graph_run_produces_directive_result_and_verdict(validate):
    graph = build_graph()
    correlation_id = f"corr-{uuid.uuid4()}"

    final_state = graph.invoke({"correlation_id": correlation_id})

    directive = final_state["directive"]
    result = final_state["result"]
    verdict = final_state["verdict"]

    assert isinstance(directive, AttackDirective)
    assert isinstance(result, AttackResult)
    assert isinstance(verdict, Verdict)

    validate(DIRECTIVE, directive.model_dump(mode="json", exclude={"attack_subcategory", "coverage_context"}))
    validate(RESULT, result.model_dump(mode="json"))
    validate(VERDICT, verdict.model_dump(mode="json"))


def test_graph_threads_correlation_id_end_to_end():
    graph = build_graph()
    correlation_id = f"corr-{uuid.uuid4()}"

    final_state = graph.invoke({"correlation_id": correlation_id})

    assert final_state["correlation_id"] == correlation_id
    assert final_state["directive"].correlation_id == correlation_id
    assert final_state["result"].correlation_id == correlation_id
    assert final_state["verdict"].correlation_id == correlation_id


def test_graph_stub_artifacts_are_referentially_linked():
    # Not real attacks, but the stub chain must still be internally
    # consistent: result references the directive it was "issued from",
    # verdict adjudicates the exact result it was "handed".
    graph = build_graph()
    final_state = graph.invoke({"correlation_id": f"corr-{uuid.uuid4()}"})

    directive = final_state["directive"]
    result = final_state["result"]
    verdict = final_state["verdict"]

    assert result.directive_id == directive.directive_id
    assert verdict.attack_id == result.attack_id


def test_graph_run_is_independent_across_correlation_ids():
    graph = build_graph()

    first = graph.invoke({"correlation_id": "corr-first"})
    second = graph.invoke({"correlation_id": "corr-second"})

    assert first["directive"].correlation_id == "corr-first"
    assert second["directive"].correlation_id == "corr-second"
    assert first["directive"].directive_id != second["directive"].directive_id
    assert first["result"].attack_id != second["result"].attack_id
    assert first["verdict"].verdict_id != second["verdict"].verdict_id
