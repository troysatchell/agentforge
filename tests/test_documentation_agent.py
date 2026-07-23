"""Frozen tests (T1 / TRO-126) — Documentation Agent.

Contract: confirmed exploits (``outcome=success``) become professional vuln
reports with the six mandatory ``VULN_REPORT_TEMPLATE`` fields, drafted by an
injected Opus client. A data-quality gate refuses to write incomplete/duplicate/
non-success findings BEFORE any model call; critical severity is human-gated.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity, Verdict
from agentforge.documentation import (
    AnthropicClient,
    DocumentationAgent,
)
from agentforge.documentation.anthropic_client import AnthropicError

FIXED_NOW = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)
_OWASP = OwaspMapping(
    web="A01:2021-broken-access-control", llm="LLM06:2025-sensitive-information-disclosure"
)


def _clock() -> datetime:
    return FIXED_NOW


class RecordingDocClient:
    """Fake DocLLMClient — records the prompt and returns a canned report body."""

    def __init__(self, reply: str = "The service reads a caller-supplied path.\nRemediation: reject path mode.") -> None:
        self.reply = reply
        self.calls = 0
        self.system: str | None = None
        self.user: str | None = None

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        self.system = system
        self.user = user
        return self.reply


def _result(sequence_hash: str = "af-data_exfiltration-001") -> AttackResult:
    return AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=_OWASP,
        sequence_hash=sequence_hash,
        input_sequence=[
            InputTurn(turn_index=0, route="POST /api/copilot/document", payload={"file_path": "x.pdf"})
        ],
        target_response=TargetResponse(http_status=200, body={"ok": True}),
        target_version="sha-abc123",
        executed_at=FIXED_NOW,
    )


def _verdict(
    *,
    outcome: Outcome = Outcome.SUCCESS,
    severity: Severity = Severity.HIGH,
    target_version: str | None = "sha-abc123",
    attack_category: AttackCategory | None = AttackCategory.DATA_EXFILTRATION,
    predicate: str = "foreign_file_bytes fired: non-patient server-file bytes disclosed to the VLM",
) -> Verdict:
    return Verdict(
        verdict_id=uuid.uuid4(),
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        outcome=outcome,
        predicate_fired=predicate if outcome == Outcome.SUCCESS else None,
        severity=severity,
        attack_category=attack_category,
        owasp_mapping=_OWASP,
        regression_flag=False,
        target_version=target_version,
        adjudicated_at=FIXED_NOW,
    )


def _agent(client: RecordingDocClient) -> DocumentationAgent:
    return DocumentationAgent(client, clock=_clock)


# --- happy path -----------------------------------------------------------


def test_filed_report_contains_all_mandatory_fields() -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(severity=Severity.HIGH), _result())

    assert out.status == "filed"
    assert out.report_id is not None and out.report_id.startswith("AF-2026-")
    md = out.report_markdown
    assert md is not None
    # 1. unique id + severity
    assert out.report_id in md
    assert "high" in md.lower()
    # 2. category
    assert "data_exfiltration" in md
    # 3. minimal reproduction against a target_version
    assert "/api/copilot/document" in md
    assert "sha-abc123" in md
    # 4. observed (the predicate that fired)
    assert "foreign_file_bytes" in md
    # 5 + 6. remediation + status sections
    assert "remediation" in md.lower()
    assert "status" in md.lower()


def test_uses_injected_client_once_with_finding_context() -> None:
    client = RecordingDocClient()
    _agent(client).document(_verdict(), _result())

    assert client.calls == 1
    assert client.user is not None
    # the finding is handed to the model to draft prose
    assert "foreign_file_bytes" in client.user
    assert "data_exfiltration" in client.user


# --- routing: only success is documented ----------------------------------


@pytest.mark.parametrize("outcome", [Outcome.FAIL, Outcome.PARTIAL])
def test_rejects_non_success_outcomes_without_model_call(outcome: Outcome) -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(outcome=outcome), _result())

    assert out.status == "rejected"
    assert client.calls == 0
    assert "success" in (out.reason or "").lower()


# --- data-quality gate (runs BEFORE any model call) -----------------------


def test_missing_target_version_is_rejected_without_model_call() -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(target_version=None), _result())

    assert out.status == "rejected"
    assert client.calls == 0
    assert "target_version" in (out.reason or "")


def test_missing_category_is_rejected_without_model_call() -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(attack_category=None), _result())

    assert out.status == "rejected"
    assert client.calls == 0


def test_duplicate_sequence_hash_is_rejected() -> None:
    client = RecordingDocClient()
    agent = _agent(client)
    first = agent.document(_verdict(), _result("dup-seq"))
    second = agent.document(_verdict(), _result("dup-seq"))

    assert first.status == "filed"
    assert second.status == "rejected"
    assert "duplicate" in (second.reason or "").lower()
    assert client.calls == 1  # model only invoked for the first, unique finding


def test_empty_model_body_is_rejected() -> None:
    client = RecordingDocClient(reply="   \n  ")
    out = _agent(client).document(_verdict(), _result())

    assert out.status == "rejected"
    # the rejection came from the empty model reply, not an earlier preflight gate
    assert client.calls == 1
    reason = (out.reason or "").lower()
    assert "empty" in reason or "body" in reason


# --- human gate on critical -----------------------------------------------


def test_critical_severity_is_held_for_human() -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(severity=Severity.CRITICAL), _result())

    assert out.status == "held_for_human"
    assert out.report_markdown  # report is still drafted
    assert out.report_id  # and gets an id


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM, Severity.HIGH])
def test_non_critical_severity_auto_files(severity: Severity) -> None:
    client = RecordingDocClient()
    out = _agent(client).document(_verdict(severity=severity), _result(f"seq-{severity.value}"))

    assert out.status == "filed"


# --- unique, sequential ids -----------------------------------------------


def test_report_ids_are_unique_and_sequential() -> None:
    agent = _agent(RecordingDocClient())
    a = agent.document(_verdict(), _result("s1"))
    b = agent.document(_verdict(), _result("s2"))

    assert a.report_id != b.report_id
    assert re.match(r"^AF-2026-\d{3}$", a.report_id or "")
    assert re.match(r"^AF-2026-\d{3}$", b.report_id or "")
    assert a.report_id == "AF-2026-001"
    assert b.report_id == "AF-2026-002"


# --- Anthropic client wire shape ------------------------------------------


def _anthropic_transport(response: dict):
    calls: dict = {}

    def transport(url, headers, body):
        calls["url"] = url
        calls["headers"] = headers
        calls["body"] = body
        return response

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


def test_anthropic_client_builds_body_and_parses_text() -> None:
    resp = {"content": [{"type": "text", "text": "DRAFTED REPORT BODY"}]}
    transport = _anthropic_transport(resp)
    client = AnthropicClient(
        api_key="sk-ant-test",
        base_url="https://api.anthropic.com",
        model="claude-opus-4-8",
        transport=transport,
    )

    out = client.complete(system="SYS", user="USR")

    assert out == "DRAFTED REPORT BODY"
    body = transport.calls["body"]  # type: ignore[attr-defined]
    assert body["model"] == "claude-opus-4-8"
    assert body["system"] == "SYS"
    assert any(m["role"] == "user" and "USR" in str(m["content"]) for m in body["messages"])


def test_anthropic_client_rejects_empty_api_key() -> None:
    with pytest.raises(ValueError):
        AnthropicClient(
            api_key="",
            base_url="https://api.anthropic.com",
            model="claude-opus-4-8",
            transport=lambda u, h, b: {},
        )


def _client(transport) -> AnthropicClient:
    return AnthropicClient(
        api_key="sk-ant-test",
        base_url="https://api.anthropic.com",
        model="claude-opus-4-8",
        transport=transport,
    )


@pytest.mark.parametrize("bad", [None, ["not", "a", "dict"], "raw string", 42])
def test_anthropic_client_rejects_non_object_response(bad) -> None:
    # A transport that returns a non-mapping must degrade to AnthropicError, not a
    # raw TypeError (complete() promises str; DocumentationAgent only handles this).
    with pytest.raises(AnthropicError):
        _client(lambda u, h, b: bad).complete(system="SYS", user="USR")


def test_anthropic_client_rejects_non_string_text() -> None:
    transport = _anthropic_transport({"content": [{"type": "text", "text": None}]})
    with pytest.raises(AnthropicError):
        _client(transport).complete(system="SYS", user="USR")


def test_anthropic_client_wraps_transport_failure() -> None:
    def boom(url, headers, body):
        raise ConnectionError("network down")

    with pytest.raises(AnthropicError):
        _client(boom).complete(system="SYS", user="USR")
