"""Frozen tests (TRO-155) — Documentation agent: prompt-caching + correlation_id.

FROZEN CONTRACT: the coding agent implements the behavior in
`agentforge/documentation/anthropic_client.py` and
`agentforge/documentation/agent.py`. It must NOT edit this file, and must keep
the existing `tests/test_documentation_agent.py` green.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity, Verdict
from agentforge.documentation import AnthropicClient, DocumentationAgent

FIXED_NOW = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)
_OWASP = OwaspMapping(
    web="A01:2021-broken-access-control", llm="LLM06:2025-sensitive-information-disclosure"
)


# --- prompt caching (AnthropicClient builds a cache-marked request body) ------


def _capturing_transport():
    seen: dict = {}

    def transport(url, headers, body):
        seen["body"] = body
        return {"content": [{"type": "text", "text": "DRAFT BODY"}]}

    transport.seen = seen  # type: ignore[attr-defined]
    return transport


def test_request_marks_a_cacheable_prefix() -> None:
    t = _capturing_transport()
    client = AnthropicClient(
        api_key="sk-ant-x",
        base_url="https://api.anthropic.com",
        model="claude-opus-4-8",
        transport=t,
    )
    out = client.complete(system="STABLE SYSTEM PREFIX", user="the variable finding")

    assert out == "DRAFT BODY"
    blob = json.dumps(t.seen["body"])  # type: ignore[attr-defined]
    # the stable prefix is marked for ephemeral prompt-caching somewhere in the body
    assert "cache_control" in blob
    assert "ephemeral" in blob
    # the stable system text is still present in the request
    assert "STABLE SYSTEM PREFIX" in blob


# --- correlation_id threaded into the rendered report -------------------------


class _StubClient:
    def complete(self, *, system: str, user: str) -> str:
        return "The service reads a caller-supplied path.\nRemediation: reject path mode."


def _result(correlation_id: str) -> AttackResult:
    return AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id=correlation_id,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=_OWASP,
        sequence_hash="af-data_exfiltration-corr-001",
        input_sequence=[
            InputTurn(turn_index=0, route="POST /api/copilot/document", payload={"file_path": "x.pdf"})
        ],
        target_response=TargetResponse(http_status=200, body={"ok": True}),
        target_version="sha-abc123",
        executed_at=FIXED_NOW,
    )


def _verdict(correlation_id: str) -> Verdict:
    return Verdict(
        verdict_id=uuid.uuid4(),
        attack_id=uuid.uuid4(),
        correlation_id=correlation_id,
        outcome=Outcome.SUCCESS,
        predicate_fired="foreign_file_bytes fired: server-file bytes disclosed",
        severity=Severity.HIGH,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=_OWASP,
        regression_flag=False,
        target_version="sha-abc123",
        adjudicated_at=FIXED_NOW,
    )


def test_report_carries_the_correlation_id() -> None:
    corr = "corr-7f3a-unique-42"
    agent = DocumentationAgent(_StubClient(), clock=lambda: FIXED_NOW)
    outcome = agent.document(_verdict(corr), _result(corr))

    assert outcome.report_markdown is not None
    assert corr in outcome.report_markdown
