"""Frozen tests (INT1 / TRO-132) — end-to-end contract trace.

`run_end_to_end` drives directive -> attack -> verdict -> report through the
frozen contract edges, validating each hop against its published schema (via the
conftest `is_valid` fixture) and threading `correlation_id` through every hop.
The success path produces a report; the fail path does not. Frozen contract for INT1.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import AttackDirective, AuthorizedScope, Budget
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.integration import EndToEndTrace, run_end_to_end
from agentforge.judge import DeterministicJudge
from agentforge.judge.oracles import CrossPatientOracle

AUTH = "11111111-1111-1111-1111-111111111111"
OWASP = OwaspMapping(web="A01:2021-broken-access-control", llm="LLM02:2025-sensitive-information-disclosure")


def _directive(corr="camp-e2e"):
    return AttackDirective(
        directive_id=uuid.uuid4(),
        correlation_id=corr,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OWASP,
        authorized_scope=AuthorizedScope(authorized_patient_uuid=AUTH),
        budget=Budget(max_usd=1.0, max_attempts=10),
        issued_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
    )


def _attack_fn(body):
    def make(directive):
        return AttackResult(
            attack_id=uuid.uuid4(),
            correlation_id=directive.correlation_id,
            attack_category=directive.attack_category,
            owasp_mapping=directive.owasp_mapping,
            sequence_hash="e2e-hash",
            input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={"q": "x"})],
            target_response=TargetResponse(http_status=200, body=body),
            executed_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
        )

    return make


def _render(result, verdict):
    return f"# report {verdict.outcome.value} {verdict.severity.value}"


# a body that trips cross_patient -> success
_SUCCESS_BODY = {"answer": "the other patient 22222222-2222-2222-2222-222222222222 has an order"}
_BENIGN_BODY = {"answer": "blood pressure is stable"}


def test_success_path_full_trace(is_valid):
    trace = run_end_to_end(
        directive=_directive(), attack_fn=_attack_fn(_SUCCESS_BODY),
        judge=DeterministicJudge([CrossPatientOracle()]), render_report=_render, is_valid=is_valid,
    )
    assert isinstance(trace, EndToEndTrace)
    assert trace.all_valid is True
    assert trace.report is not None and trace.report.startswith("# report success")
    assert trace.correlation_id == "camp-e2e"


def test_fail_path_produces_no_report(is_valid):
    trace = run_end_to_end(
        directive=_directive(), attack_fn=_attack_fn(_BENIGN_BODY),
        judge=DeterministicJudge([CrossPatientOracle()]), render_report=_render, is_valid=is_valid,
    )
    assert trace.report is None
    assert trace.all_valid is True


def test_every_contract_hop_is_schema_valid(is_valid):
    trace = run_end_to_end(
        directive=_directive(), attack_fn=_attack_fn(_SUCCESS_BODY),
        judge=DeterministicJudge([CrossPatientOracle()]), render_report=_render, is_valid=is_valid,
    )
    for hop in trace.hops:
        assert hop.valid is True
    schemas = " ".join(hop.schema for hop in trace.hops)
    assert "orchestrator_to_redteam" in schemas
    assert "redteam_to_judge" in schemas
    assert "judge_to_documentation" in schemas


def test_correlation_id_threads_through_every_hop(is_valid):
    trace = run_end_to_end(
        directive=_directive("trace-xyz"), attack_fn=_attack_fn(_SUCCESS_BODY),
        judge=DeterministicJudge([CrossPatientOracle()]), render_report=_render, is_valid=is_valid,
    )
    for hop in trace.hops:
        assert hop.payload.get("correlation_id") == "trace-xyz"
