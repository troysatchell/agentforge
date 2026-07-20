"""Integration: the independently-built SqliteExploitStore (E7) and Orchestrator
(E5) compose through the ExploitStore Protocol — no shared source, just the
interface. This is what the Protocol boundary buys us."""

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.directive import AttackDirective
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.orchestrator import Orchestrator
from agentforge.store import ExploitRecord, ExploitStore, SqliteExploitStore
from tests._contract_ids import DIRECTIVE

_FIXED_NOW = datetime(2026, 7, 20, tzinfo=timezone.utc)


def _rec(seq: str, category: AttackCategory, *, outcome=Outcome.SUCCESS,
         severity=Severity.HIGH, regression=False, version="sha-1") -> ExploitRecord:
    return ExploitRecord(
        exploit_id=seq,
        correlation_id="camp-1",
        attack_id=str(uuid.uuid4()),
        sequence_hash=seq,
        attack_category=category,
        severity=severity,
        outcome=outcome,
        regression_flag=regression,
        target_version=version,
        adjudicated_at=_FIXED_NOW,
    )


def test_sqlite_store_satisfies_the_protocol():
    assert isinstance(SqliteExploitStore(":memory:"), ExploitStore)


def test_orchestrator_targets_least_covered_category_via_real_store(validate):
    store = SqliteExploitStore(":memory:")
    for i in range(3):
        store.record(_rec(f"pi-{i}", AttackCategory.PROMPT_INJECTION))

    orch = Orchestrator(
        store,
        clock=lambda: _FIXED_NOW,
        id_factory=lambda: uuid.UUID(int=1),
    )
    directive = orch.next_directive(
        correlation_id="camp-1",
        authorized_patient_uuid="patient-1",
        target_base_url="https://target.example",
        max_usd=1.0,
        max_attempts=5,
    )
    assert isinstance(directive, AttackDirective)
    assert directive.attack_category is not AttackCategory.PROMPT_INJECTION  # the covered one
    assert directive.coverage_context.cases_tested_in_category == 0
    validate(DIRECTIVE, directive.model_dump(mode="json"))  # real store -> schema-valid directive


def test_regression_flows_store_to_orchestrator():
    store = SqliteExploitStore(":memory:")
    store.record(_rec("reg-1", AttackCategory.DATA_EXFILTRATION, regression=True, version="sha-9"))
    errors = Orchestrator(store).regression_signals(correlation_id="camp-1")
    assert len(errors) == 1


def test_budget_halt_end_to_end():
    orch = Orchestrator(SqliteExploitStore(":memory:"))
    assert orch.should_halt(spent_usd=2.0, ceiling_usd=1.0, signal_produced=False, correlation_id="c") is not None
    assert orch.should_halt(spent_usd=2.0, ceiling_usd=1.0, signal_produced=True, correlation_id="c") is None
    assert orch.should_halt(spent_usd=0.5, ceiling_usd=1.0, signal_produced=False, correlation_id="c") is None
