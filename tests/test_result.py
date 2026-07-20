"""Contract tests for AttackResult (redteam_to_judge.schema.json)."""

import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from agentforge.contracts.result import (
    AttackResult,
    ExecutionTelemetry,
    InputTurn,
    TargetResponse,
)
from tests._contract_ids import RESULT


def _minimal_kwargs():
    return dict(
        attack_id=uuid.uuid4(),
        correlation_id="corr-123",
        attack_category=AttackCategory.PROMPT_INJECTION,
        owasp_mapping=OwaspMapping(web=None, llm="LLM01:2025-prompt-injection"),
        sequence_hash="deadbeef",
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={"question": "hi"})],
        target_response=TargetResponse(http_status=200, body={"answer": "hi"}),
        executed_at=datetime.now(timezone.utc),
    )


def test_attack_result_minimal_roundtrips_against_schema(validate):
    result = AttackResult(**_minimal_kwargs())
    validate(RESULT, result.model_dump(mode="json"))


def test_attack_result_full_roundtrips_against_schema(validate):
    kwargs = _minimal_kwargs()
    kwargs.update(
        directive_id=uuid.uuid4(),
        parent_attack_id=str(uuid.uuid4()),
        attack_subcategory="jailbreak-roleplay",
        observed_hints=[OracleResult(oracle_id="phi_pattern", fired=True, evidence="count=1")],
        execution_telemetry=ExecutionTelemetry(input_tokens=10, output_tokens=20, cost_usd=0.001),
        target_version="abc123sha",
    )
    result = AttackResult(**kwargs)
    dumped = result.model_dump(mode="json")
    validate(RESULT, dumped)


def test_attack_result_defaults_schema_version():
    result = AttackResult(**_minimal_kwargs())
    assert result.schema_version == "1.0.0"


def test_attack_result_target_response_accepts_string_body(validate):
    kwargs = _minimal_kwargs()
    kwargs["target_response"] = TargetResponse(http_status=500, body="internal error")
    result = AttackResult(**kwargs)
    validate(RESULT, result.model_dump(mode="json"))


def test_attack_result_forbids_extra_top_level_keys():
    with pytest.raises(Exception):
        AttackResult(**_minimal_kwargs(), sneaky="x")  # type: ignore[call-arg]


def test_attack_result_requires_non_empty_input_sequence():
    kwargs = _minimal_kwargs()
    kwargs["input_sequence"] = []
    with pytest.raises(Exception):
        AttackResult(**kwargs)


def test_input_turn_forbids_extra_keys():
    with pytest.raises(Exception):
        InputTurn(turn_index=0, route="x", payload={}, sneaky="y")  # type: ignore[call-arg]


def test_input_turn_rejects_negative_turn_index():
    with pytest.raises(Exception):
        InputTurn(turn_index=-1, route="x", payload={})


def test_target_response_forbids_extra_keys():
    with pytest.raises(Exception):
        TargetResponse(http_status=200, body={}, sneaky="y")  # type: ignore[call-arg]


def test_execution_telemetry_allows_all_null():
    telemetry = ExecutionTelemetry(input_tokens=None, output_tokens=None, cost_usd=None)
    assert telemetry.input_tokens is None
    assert telemetry.output_tokens is None
    assert telemetry.cost_usd is None


def test_execution_telemetry_fields_are_optional():
    telemetry = ExecutionTelemetry()
    assert telemetry.input_tokens is None
    assert telemetry.output_tokens is None
    assert telemetry.cost_usd is None
