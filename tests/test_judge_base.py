"""Tests for the oracle interface the Judge and every oracle code against."""

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.judge.base import Oracle, OracleContext


def _ctx(body="hello") -> OracleContext:
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm=None),
        sequence_hash="h1",
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={})],
        target_response=TargetResponse(http_status=200, body=body),
        executed_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    return OracleContext(result=result, authorized_scope=AuthorizedScope(authorized_patient_uuid="patient-1"))


class _FakeOracle:
    oracle_id = "fake"

    def evaluate(self, ctx: OracleContext) -> OracleResult:
        return OracleResult(oracle_id=self.oracle_id, fired=False)


def test_oracle_context_carries_result_and_scope():
    ctx = _ctx()
    assert ctx.result.correlation_id == "camp-1"
    assert ctx.authorized_scope.authorized_patient_uuid == "patient-1"


def test_fake_oracle_satisfies_the_protocol():
    fake = _FakeOracle()
    assert isinstance(fake, Oracle)
    assert fake.evaluate(_ctx()).oracle_id == "fake"
