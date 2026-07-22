"""Frozen tests (OBS-trace / TRO-128) — agent spans + PHI-free labels + emitter seam.

An AgentSpan is the per-agent-call unit the Orchestrator/operator read, joined by
correlation_id and ordered by started_at (Q6). Spans are structurally PHI-free
(no raw-body field), labels carry only oracle ids + fired status, and emission
goes through an injected seam so the Langfuse path is unit-tested without a
network. These tests are the frozen contract for OBS-trace.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agentforge.contracts.common import AttackCategory, OracleResult
from agentforge.observability.trace import (
    AgentName,
    AgentSpan,
    CollectingEmitter,
    LangfuseEmitter,
    NullEmitter,
    SpanEmitter,
    phi_free_label,
    to_langfuse_generation,
)

_AT = datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc)


def _span(**kw):
    base = dict(
        agent=AgentName.RED_TEAM,
        correlation_id="camp-1",
        started_at=_AT,
        model="kimi-k2.6",
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.02,
        latency_ms=1200.0,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        label="cross_patient=fired",
    )
    base.update(kw)
    return AgentSpan(**base)


def test_agent_span_is_strict_no_raw_body_field():
    # extra=forbid: raw response bytes can never be smuggled onto a span
    with pytest.raises(ValidationError):
        AgentSpan(
            agent=AgentName.JUDGE,
            correlation_id="c",
            started_at=_AT,
            raw_body="root:x:0:0:root:/root:/bin/bash",
        )


def test_agent_span_rejects_negative_cost():
    with pytest.raises(ValidationError):
        _span(cost_usd=-1.0)


def test_phi_free_label_from_oracle_results():
    label = phi_free_label(
        [
            OracleResult(oracle_id="cross_patient", fired=True, evidence="foreign_pid_count=1"),
            OracleResult(oracle_id="phi_pattern", fired=False, evidence=None),
            OracleResult(oracle_id="grounding_fabrication", fired=None, evidence=None),
        ]
    )
    assert "cross_patient" in label and "phi_pattern" in label
    assert "fired" in label  # carries status, not raw content
    assert "foreign_pid_count=1" not in label  # never the raw evidence bytes


def test_null_emitter_is_noop():
    NullEmitter().emit(_span())  # must not raise


def test_collecting_emitter_records():
    emitter = CollectingEmitter()
    span = _span()
    emitter.emit(span)
    assert emitter.spans == [span]


def test_emitters_satisfy_protocol():
    assert isinstance(NullEmitter(), SpanEmitter)
    assert isinstance(CollectingEmitter(), SpanEmitter)


def test_to_langfuse_generation_is_phi_free_and_carries_join_key():
    gen = to_langfuse_generation(_span())
    assert isinstance(gen, dict) and gen
    blob = str(gen)
    assert "camp-1" in blob  # correlation_id threads the join
    assert "red_team" in blob  # agent dimension
    assert "root:x:0:0" not in blob  # never raw response content


def test_langfuse_emitter_posts_via_injected_transport():
    calls = []

    def transport(url, headers, body):
        calls.append((url, headers, body))
        return {}

    LangfuseEmitter(transport, host="http://localhost:3000", public_key="pk", secret_key="sk").emit(_span())
    assert len(calls) == 1
    url, _headers, body = calls[0]
    assert url.startswith("http://localhost:3000")
    assert "camp-1" in str(body)
    assert "root:x:0:0" not in str(body)
