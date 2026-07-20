"""TDD tests for the deterministic Orchestrator (E5).

No LLM, never touches the target. Exercises coverage-gap selection
(``next_directive``), the cost-without-signal halt guardrail
(``should_halt``), and regression surfacing (``regression_signals``) against
a small in-memory fake store — never the sqlite store.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.orchestrator import Orchestrator
from agentforge.store import ExploitRecord, ExploitStore
from tests._contract_ids import DIRECTIVE, ERRORS

FIXED_CLOCK_TIME = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
FIXED_DIRECTIVE_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _fixed_clock() -> datetime:
    return FIXED_CLOCK_TIME


def _fixed_id_factory() -> uuid.UUID:
    return FIXED_DIRECTIVE_ID


def _record(category: AttackCategory, n: int, **overrides: object) -> ExploitRecord:
    kwargs: dict[str, object] = dict(
        exploit_id=f"{category.value}-{n}",
        correlation_id="corr-fixture",
        attack_id=str(uuid.uuid4()),
        sequence_hash=f"hash-{category.value}-{n}",
        attack_category=category,
        severity=Severity.LOW,
        outcome=Outcome.FAIL,
        adjudicated_at=FIXED_CLOCK_TIME,
    )
    kwargs.update(overrides)
    return ExploitRecord(**kwargs)  # type: ignore[arg-type]


class _FakeStore:
    """Minimal in-memory ExploitStore over a plain list."""

    def __init__(self, records: list[ExploitRecord] | None = None) -> None:
        self._records: list[ExploitRecord] = list(records or [])

    def record(self, rec: ExploitRecord) -> bool:
        if any(r.sequence_hash == rec.sequence_hash for r in self._records):
            return False
        self._records.append(rec)
        return True

    def all(self) -> list[ExploitRecord]:
        return list(self._records)

    def cases_tested_by_category(self) -> dict[AttackCategory, int]:
        counts: dict[AttackCategory, int] = {}
        for rec in self._records:
            counts[rec.attack_category] = counts.get(rec.attack_category, 0) + 1
        return counts

    def open_findings_by_category(self) -> dict[AttackCategory, int]:
        counts: dict[AttackCategory, int] = {}
        for rec in self._records:
            if rec.outcome == Outcome.SUCCESS and rec.severity != Severity.FALSE_POSITIVE:
                counts[rec.attack_category] = counts.get(rec.attack_category, 0) + 1
        return counts

    def regressions(self) -> list[ExploitRecord]:
        return [r for r in self._records if r.regression_flag]


def test_fake_store_satisfies_exploit_store_protocol() -> None:
    assert isinstance(_FakeStore(), ExploitStore)


def test_next_directive_empty_store_picks_prompt_injection_and_validates_schema(validate) -> None:
    orch = Orchestrator(_FakeStore(), clock=_fixed_clock, id_factory=_fixed_id_factory)

    directive = orch.next_directive(
        correlation_id="corr-1",
        authorized_patient_uuid="patient-abc-123",
        target_base_url="https://target.example.com",
        max_usd=5.0,
        max_attempts=10,
    )

    assert directive.attack_category == AttackCategory.PROMPT_INJECTION
    assert directive.directive_id == FIXED_DIRECTIVE_ID
    assert directive.issued_at == FIXED_CLOCK_TIME
    dumped = directive.model_dump(mode="json", exclude={"attack_subcategory"})
    validate(DIRECTIVE, dumped)


def test_next_directive_picks_least_covered_category_when_store_is_weighted() -> None:
    records: list[ExploitRecord] = []
    for category in (
        AttackCategory.PROMPT_INJECTION,
        AttackCategory.DATA_EXFILTRATION,
        AttackCategory.STATE_CORRUPTION,
        AttackCategory.DENIAL_OF_SERVICE,
        AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    ):
        records.extend(_record(category, i) for i in range(5))
    records.append(_record(AttackCategory.TOOL_MISUSE, 0))
    store = _FakeStore(records)
    orch = Orchestrator(store, clock=_fixed_clock, id_factory=_fixed_id_factory)

    directive = orch.next_directive(
        correlation_id="corr-2",
        authorized_patient_uuid="patient-abc-123",
        target_base_url=None,
        max_usd=5.0,
        max_attempts=10,
    )

    assert directive.attack_category == AttackCategory.TOOL_MISUSE
    assert directive.coverage_context is not None
    assert directive.coverage_context.cases_tested_in_category == 1


def test_next_directive_tie_breaks_by_declaration_order_not_zero_only() -> None:
    # PROMPT_INJECTION and STATE_CORRUPTION tie at 2; PROMPT_INJECTION is
    # declared first so it must win even though it isn't the literal minimum
    # index in the iterable ordering coincidence.
    records = [
        *[_record(AttackCategory.PROMPT_INJECTION, i) for i in range(2)],
        *[_record(AttackCategory.DATA_EXFILTRATION, i) for i in range(9)],
        *[_record(AttackCategory.STATE_CORRUPTION, i) for i in range(2)],
        *[_record(AttackCategory.TOOL_MISUSE, i) for i in range(9)],
        *[_record(AttackCategory.DENIAL_OF_SERVICE, i) for i in range(9)],
        *[_record(AttackCategory.IDENTITY_ROLE_EXPLOITATION, i) for i in range(9)],
    ]
    store = _FakeStore(records)
    orch = Orchestrator(store, clock=_fixed_clock, id_factory=_fixed_id_factory)

    directive = orch.next_directive(
        correlation_id="corr-3",
        authorized_patient_uuid="patient-abc-123",
        target_base_url=None,
        max_usd=5.0,
        max_attempts=10,
    )

    assert directive.attack_category == AttackCategory.PROMPT_INJECTION


def test_should_halt_returns_budget_exceeded_when_over_ceiling_without_signal(validate) -> None:
    orch = Orchestrator(_FakeStore(), clock=_fixed_clock, id_factory=_fixed_id_factory)

    error = orch.should_halt(
        spent_usd=10.0,
        ceiling_usd=10.0,
        signal_produced=False,
        correlation_id="corr-4",
    )

    assert error is not None
    dumped = error.model_dump(mode="json")
    assert dumped["error_type"] == "budget_exceeded"
    assert dumped["raised_by"] == "orchestrator"
    assert dumped["detail"] == {
        "spent_usd": 10.0,
        "ceiling_usd": 10.0,
        "signal_produced": False,
        "action": "halt_campaign",
    }
    validate(ERRORS, dumped)


def test_should_halt_returns_none_when_under_ceiling() -> None:
    orch = Orchestrator(_FakeStore(), clock=_fixed_clock, id_factory=_fixed_id_factory)

    error = orch.should_halt(
        spent_usd=5.0,
        ceiling_usd=10.0,
        signal_produced=False,
        correlation_id="corr-5",
    )

    assert error is None


def test_should_halt_returns_none_when_signal_produced_even_over_ceiling() -> None:
    orch = Orchestrator(_FakeStore(), clock=_fixed_clock, id_factory=_fixed_id_factory)

    error = orch.should_halt(
        spent_usd=15.0,
        ceiling_usd=10.0,
        signal_produced=True,
        correlation_id="corr-6",
    )

    assert error is None


def test_regression_signals_returns_one_error_per_flagged_record(validate) -> None:
    records = [
        _record(
            AttackCategory.PROMPT_INJECTION,
            0,
            exploit_id="V1-cross-patient-pdf",
            regression_flag=True,
            target_version="1.4.2",
        ),
        _record(
            AttackCategory.TOOL_MISUSE,
            0,
            exploit_id="V2-tool-misuse",
            regression_flag=True,
            target_version=None,
        ),
        _record(AttackCategory.DATA_EXFILTRATION, 0, regression_flag=False),
    ]
    store = _FakeStore(records)
    orch = Orchestrator(store, clock=_fixed_clock, id_factory=_fixed_id_factory)

    errors = orch.regression_signals(correlation_id="corr-7")

    assert len(errors) == 2
    dumped = [e.model_dump(mode="json") for e in errors]
    for d in dumped:
        assert d["error_type"] == "regression_detected"
        validate(ERRORS, d)
    assert dumped[0]["detail"]["exploit_id"] == "V1-cross-patient-pdf"
    assert dumped[0]["detail"]["reappeared_in_version"] == "1.4.2"
    assert dumped[1]["detail"]["exploit_id"] == "V2-tool-misuse"
    assert dumped[1]["detail"]["reappeared_in_version"] == "unknown"


def test_regression_signals_returns_empty_list_when_no_regressions() -> None:
    orch = Orchestrator(_FakeStore(), clock=_fixed_clock, id_factory=_fixed_id_factory)

    assert orch.regression_signals(correlation_id="corr-8") == []
