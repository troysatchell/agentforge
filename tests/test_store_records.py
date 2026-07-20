"""Tests for the shared ExploitRecord — the row the exploit DB stores and the
Orchestrator reads. Pairs an AttackResult (has sequence_hash + category) with the
Verdict that adjudicated it."""

import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity, Verdict
from agentforge.store import ExploitRecord


def _result(**kw) -> AttackResult:
    defaults = dict(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm="LLM02:2025-sensitive-information-disclosure"),
        sequence_hash="hash-abc",
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={})],
        target_response=TargetResponse(http_status=200, body="ok"),
        executed_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return AttackResult(**defaults)


def _verdict(**kw) -> Verdict:
    defaults = dict(
        verdict_id=uuid.uuid4(),
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        outcome=Outcome.SUCCESS,
        predicate_fired="non-patient server-file bytes appeared in the extraction",
        severity=Severity.HIGH,
        regression_flag=False,
        reproduction_ref="hash-abc",
        adjudicated_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return Verdict(**defaults)


def test_from_verdict_pairs_result_and_verdict_fields():
    r = _result()
    v = _verdict(attack_id=r.attack_id)
    rec = ExploitRecord.from_verdict(v, r)
    assert rec.sequence_hash == "hash-abc"            # from the result
    assert rec.attack_category == AttackCategory.DATA_EXFILTRATION  # from the result
    assert rec.severity == Severity.HIGH              # from the verdict
    assert rec.outcome == Outcome.SUCCESS
    assert rec.attack_id == str(r.attack_id)
    assert rec.correlation_id == "camp-1"


def test_exploit_id_defaults_to_reproduction_ref_then_sequence_hash():
    r = _result()
    assert ExploitRecord.from_verdict(_verdict(reproduction_ref="exp-77"), r).exploit_id == "exp-77"
    assert ExploitRecord.from_verdict(_verdict(reproduction_ref=None), r).exploit_id == "hash-abc"


def test_record_rejects_unknown_fields():
    with pytest.raises(Exception):
        ExploitRecord(exploit_id="x", sneaky=1)  # type: ignore[call-arg]
