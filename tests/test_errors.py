"""Contract tests for the ``AgentError`` discriminated-union envelope
(mirrors ``errors.schema.json``). One test per ``error_type`` branch proves
the round trip against the schema; the negative tests prove a ``detail``
payload that does not match its ``error_type`` is rejected."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agentforge.contracts.errors import AgentError
from tests._contract_ids import ERRORS

RAISED_AT = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)


def _envelope(error_type, detail, raised_by="orchestrator", correlation_id="corr-1"):
    return {
        "schema_version": "1.0.0",
        "error_type": error_type,
        "correlation_id": correlation_id,
        "raised_by": raised_by,
        "raised_at": RAISED_AT.isoformat(),
        "detail": detail,
    }


def test_target_unreachable_roundtrips(validate):
    payload = _envelope(
        "target_unreachable",
        {"route": "/fhir/Patient", "attempts": 3, "last_http_status": 503, "action": "retry_backoff"},
        raised_by="harness",
    )
    err = AgentError.model_validate(payload)
    validate(ERRORS, err.model_dump(mode="json"))


def test_budget_exceeded_roundtrips(validate):
    payload = _envelope(
        "budget_exceeded",
        {"spent_usd": 12.5, "ceiling_usd": 10.0, "signal_produced": False, "action": "halt_campaign"},
        raised_by="orchestrator",
    )
    err = AgentError.model_validate(payload)
    validate(ERRORS, err.model_dump(mode="json"))


def test_judge_timeout_roundtrips(validate):
    payload = _envelope(
        "judge_timeout",
        {"attack_id": str(uuid.uuid4()), "timeout_ms": 30000, "action": "requeue_once"},
        raised_by="judge",
    )
    err = AgentError.model_validate(payload)
    validate(ERRORS, err.model_dump(mode="json"))


def test_no_findings_roundtrips(validate):
    payload = _envelope(
        "no_findings",
        {"category": "prompt_injection", "attempts_in_window": 40, "action": "redirect_next_gap"},
        raised_by="red_team",
    )
    err = AgentError.model_validate(payload)
    validate(ERRORS, err.model_dump(mode="json"))


def test_regression_detected_roundtrips(validate):
    payload = _envelope(
        "regression_detected",
        {
            "exploit_id": "V1-cross-patient-pdf",
            "reappeared_in_version": "1.4.2",
            "cross_category": "data_exfiltration",
            "action": "trigger_full_regression",
        },
        raised_by="documentation",
    )
    err = AgentError.model_validate(payload)
    validate(ERRORS, err.model_dump(mode="json"))


def test_regression_detected_cross_category_defaults_null(validate):
    payload = _envelope(
        "regression_detected",
        {
            "exploit_id": "V2-tool-misuse",
            "reappeared_in_version": "1.5.0",
            "action": "trigger_full_regression",
        },
        raised_by="documentation",
    )
    err = AgentError.model_validate(payload)
    dumped = err.model_dump(mode="json")
    assert dumped["detail"]["cross_category"] is None
    validate(ERRORS, dumped)


def test_mismatched_detail_is_rejected():
    # error_type says target_unreachable but detail matches budget_exceeded's shape.
    payload = _envelope(
        "target_unreachable",
        {"spent_usd": 12.5, "ceiling_usd": 10.0, "signal_produced": False, "action": "halt_campaign"},
    )
    with pytest.raises(ValidationError):
        AgentError.model_validate(payload)


def test_unknown_error_type_is_rejected():
    payload = _envelope(
        "timeout_exceeded",
        {"route": "/x", "attempts": 1, "last_http_status": None, "action": "retry_backoff"},
    )
    with pytest.raises(ValidationError):
        AgentError.model_validate(payload)


def test_extra_top_level_field_is_rejected():
    payload = _envelope(
        "no_findings",
        {"category": "tool_misuse", "attempts_in_window": 5, "action": "redirect_next_gap"},
    )
    payload["unexpected"] = "nope"
    with pytest.raises(ValidationError):
        AgentError.model_validate(payload)
