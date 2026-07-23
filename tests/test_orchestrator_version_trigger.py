"""Frozen tests (TRO-156) — Orchestrator target_version-change trigger.

FROZEN CONTRACT: the coding agent implements `Orchestrator.on_target_version` in
`agentforge/orchestrator.py`. It must NOT edit this file, and must not change the
existing `next_directive` / `should_halt` / `regression_signals` behavior (the
existing `tests/test_orchestrator.py` must stay green).

When the target's `current_version` is one the store has NEVER recorded (a target
upgrade), the Orchestrator kicks a regression pass — one `regression_detected`
AgentError per stored exploit, to re-verify it still reproduces on the new
version. A version already present in the store (stable) or an empty store
produces NO trigger (no false positives).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.orchestrator import Orchestrator
from agentforge.store import ExploitRecord

FIXED = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
A = AttackCategory("prompt_injection")
B = AttackCategory("data_exfiltration")


def _record(category: AttackCategory, n: int, **overrides: object) -> ExploitRecord:
    kwargs: dict[str, object] = dict(
        exploit_id=f"{category.value}-{n}",
        correlation_id="corr-fixture",
        attack_id=str(uuid.uuid4()),
        sequence_hash=f"hash-{category.value}-{n}",
        attack_category=category,
        severity=Severity.HIGH,
        outcome=Outcome.SUCCESS,
        adjudicated_at=FIXED,
    )
    kwargs.update(overrides)
    return ExploitRecord(**kwargs)  # type: ignore[arg-type]


class _FakeStore:
    def __init__(self, records: list[ExploitRecord] | None = None) -> None:
        self._records = list(records or [])

    def record(self, rec: ExploitRecord) -> bool:
        if any(r.sequence_hash == rec.sequence_hash for r in self._records):
            return False
        self._records.append(rec)
        return True

    def all(self) -> list[ExploitRecord]:
        return list(self._records)

    def cases_tested_by_category(self) -> dict[AttackCategory, int]:
        c: dict[AttackCategory, int] = {}
        for r in self._records:
            c[r.attack_category] = c.get(r.attack_category, 0) + 1
        return c

    def open_findings_by_category(self) -> dict[AttackCategory, int]:
        c: dict[AttackCategory, int] = {}
        for r in self._records:
            if r.outcome is Outcome.SUCCESS and r.severity is not Severity.FALSE_POSITIVE:
                c[r.attack_category] = c.get(r.attack_category, 0) + 1
        return c

    def regressions(self) -> list[ExploitRecord]:
        return [r for r in self._records if r.regression_flag]


def _orch(store: _FakeStore) -> Orchestrator:
    return Orchestrator(
        store,
        clock=lambda: FIXED,
        id_factory=lambda: uuid.UUID("11111111-1111-1111-1111-111111111111"),
    )


def test_new_version_triggers_regression_pass_over_stored_exploits() -> None:
    store = _FakeStore([_record(A, 1, target_version="v1"), _record(B, 2, target_version="v1")])
    errors = _orch(store).on_target_version(current_version="v2", correlation_id="corr-x")
    assert len(errors) == 2
    assert all(e.error_type == "regression_detected" for e in errors)
    assert all("v2" in str(e.detail) for e in errors)


def test_known_version_does_not_trigger() -> None:
    store = _FakeStore([_record(A, 1, target_version="v2")])
    assert _orch(store).on_target_version(current_version="v2", correlation_id="c") == []


def test_empty_store_does_not_trigger() -> None:
    assert _orch(_FakeStore([])).on_target_version(current_version="v1", correlation_id="c") == []
