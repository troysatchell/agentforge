"""Frozen tests (T3 / TRO-125) — cross_category regression axis, end-to-end.

The basic ``regression_detected`` path already works (see test_orchestrator.py).
This freezes the ONE remaining gap: ``Verdict.cross_category_regression`` must be
plumbed through ``ExploitRecord`` -> ``SqliteExploitStore`` ->
``Orchestrator.regression_signals`` so a cross-category regression surfaces on the
emitted error's ``detail.cross_category``. The existing basic path must be
preserved.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity, Verdict
from agentforge.orchestrator import Orchestrator
from agentforge.store import ExploitRecord, SqliteExploitStore
from tests._contract_ids import ERRORS

FIXED_NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)


def _result(sequence_hash: str = "hash-1") -> AttackResult:
    return AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm=None),
        sequence_hash=sequence_hash,
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={})],
        target_response=TargetResponse(http_status=200, body={"status": "ok"}),
        target_version="sha-9",
        executed_at=FIXED_NOW,
    )


def _verdict(
    *,
    cross_category: str | None = None,
    regression_flag: bool = True,
    target_version: str | None = "sha-9",
) -> Verdict:
    return Verdict(
        verdict_id=uuid.uuid4(),
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        outcome=Outcome.SUCCESS,
        predicate_fired="cross_patient fired: foreign_pid_count=1",
        severity=Severity.HIGH,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm=None),
        regression_flag=regression_flag,
        cross_category_regression=cross_category,
        target_version=target_version,
        adjudicated_at=FIXED_NOW,
    )


# --- record: the field + from_verdict copy --------------------------------


def test_exploit_record_defaults_cross_category_none() -> None:
    rec = ExploitRecord.from_verdict(_verdict(cross_category=None), _result())
    assert rec.cross_category is None


def test_from_verdict_copies_cross_category() -> None:
    rec = ExploitRecord.from_verdict(_verdict(cross_category="tool_misuse"), _result())
    assert rec.cross_category == "tool_misuse"


# --- store: round-trip -----------------------------------------------------


def test_sqlite_roundtrips_cross_category() -> None:
    store = SqliteExploitStore(":memory:")
    store.record(ExploitRecord.from_verdict(_verdict(cross_category="tool_misuse"), _result("hash-x")))
    loaded = store.all()
    assert len(loaded) == 1
    assert loaded[0].cross_category == "tool_misuse"


def test_sqlite_roundtrips_cross_category_none() -> None:
    store = SqliteExploitStore(":memory:")
    store.record(ExploitRecord.from_verdict(_verdict(cross_category=None), _result("hash-y")))
    assert store.all()[0].cross_category is None


def test_sqlite_migrates_a_pre_cross_category_database(tmp_path) -> None:
    """Reopening a DB written before the cross_category column adds it (idempotent
    migration) so inserts/selects over the full column set keep working."""
    path = str(tmp_path / "legacy.db")
    # A legacy table with every column EXCEPT cross_category.
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE exploit_records ("
        "exploit_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, attack_id TEXT NOT NULL, "
        "sequence_hash TEXT NOT NULL, attack_category TEXT NOT NULL, severity TEXT NOT NULL, "
        "outcome TEXT NOT NULL, predicate_fired TEXT, regression_flag INTEGER NOT NULL, "
        "target_version TEXT, reproduction_ref TEXT, adjudicated_at TEXT NOT NULL)"
    )
    legacy.commit()
    legacy.close()

    store = SqliteExploitStore(path)  # must ALTER TABLE ADD COLUMN, not fail
    assert store.record(
        ExploitRecord.from_verdict(_verdict(cross_category="tool_misuse"), _result("hash-mig"))
    )
    assert store.all()[0].cross_category == "tool_misuse"


# --- orchestrator: detail.cross_category ----------------------------------


def test_regression_signals_populates_cross_category(validate) -> None:
    store = SqliteExploitStore(":memory:")
    store.record(
        ExploitRecord.from_verdict(
            _verdict(cross_category="denial_of_service", regression_flag=True), _result("hash-reg")
        )
    )
    errors = Orchestrator(store).regression_signals(correlation_id="camp-1")

    assert len(errors) == 1
    dumped = errors[0].model_dump(mode="json")
    assert dumped["error_type"] == "regression_detected"
    assert dumped["detail"]["cross_category"] == "denial_of_service"
    validate(ERRORS, dumped)


def test_regression_signals_cross_category_null_when_absent(validate) -> None:
    store = SqliteExploitStore(":memory:")
    store.record(
        ExploitRecord.from_verdict(_verdict(cross_category=None, regression_flag=True), _result("hash-n"))
    )
    errors = Orchestrator(store).regression_signals(correlation_id="camp-1")

    assert len(errors) == 1
    dumped = errors[0].model_dump(mode="json")
    assert dumped["detail"]["cross_category"] is None
    validate(ERRORS, dumped)


# --- the basic path stays intact ------------------------------------------


def test_basic_regression_path_preserved(validate) -> None:
    store = SqliteExploitStore(":memory:")
    store.record(
        ExploitRecord.from_verdict(
            _verdict(cross_category=None, regression_flag=True, target_version="1.4.2"), _result("hash-a")
        )
    )
    store.record(
        ExploitRecord.from_verdict(_verdict(cross_category=None, regression_flag=False), _result("hash-b"))
    )
    errors = Orchestrator(store).regression_signals(correlation_id="corr-7")

    assert len(errors) == 1  # only the flagged record surfaces
    detail = errors[0].model_dump(mode="json")["detail"]
    assert detail["exploit_id"] == "hash-a"
    assert detail["reappeared_in_version"] == "1.4.2"
    validate(ERRORS, errors[0].model_dump(mode="json"))
