"""Tests for CostOverageOracle — fires when a single attack's measured
execution cost exceeds the configured ceiling."""

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, ExecutionTelemetry, InputTurn, TargetResponse
from agentforge.judge.base import Oracle, OracleContext
from agentforge.judge.oracles.cost_overage import CostOverageOracle


def _ctx(cost_usd: float | None, telemetry_present: bool = True) -> OracleContext:
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DENIAL_OF_SERVICE,
        owasp_mapping=OwaspMapping(web=None, llm=None),
        sequence_hash="h1",
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={})],
        target_response=TargetResponse(http_status=200, body="ok"),
        execution_telemetry=ExecutionTelemetry(cost_usd=cost_usd) if telemetry_present else None,
        executed_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    return OracleContext(result=result, authorized_scope=AuthorizedScope(authorized_patient_uuid="patient-1"))


def test_cost_overage_oracle_satisfies_protocol():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    assert isinstance(oracle, Oracle)
    assert oracle.oracle_id == "cost_overage"


def test_fires_when_cost_exceeds_ceiling():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    result = oracle.evaluate(_ctx(cost_usd=1.5))
    assert result.oracle_id == "cost_overage"
    assert result.fired is True
    assert result.evidence == "cost_usd=1.5;ceiling=1.0"


def test_does_not_fire_when_cost_under_ceiling():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    result = oracle.evaluate(_ctx(cost_usd=0.5))
    assert result.fired is False
    assert result.evidence == "cost_usd=0.5;ceiling=1.0"


def test_does_not_fire_when_cost_equals_ceiling():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    result = oracle.evaluate(_ctx(cost_usd=1.0))
    assert result.fired is False
    assert result.evidence == "cost_usd=1.0;ceiling=1.0"


def test_fired_is_none_when_telemetry_absent():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    result = oracle.evaluate(_ctx(cost_usd=None, telemetry_present=False))
    assert result.fired is None


def test_fired_is_none_when_cost_usd_is_none():
    oracle = CostOverageOracle(ceiling_usd=1.0)
    result = oracle.evaluate(_ctx(cost_usd=None, telemetry_present=True))
    assert result.fired is None
