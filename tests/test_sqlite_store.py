"""Tests for the SQLite exploit store — persistence + coverage-query surface
that satisfies the :class:`agentforge.store.ExploitStore` Protocol.
"""

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.store import ExploitRecord, ExploitStore
from agentforge.store.sqlite_store import SqliteExploitStore


def _record(**kw) -> ExploitRecord:
    defaults = dict(
        exploit_id=str(uuid.uuid4()),
        correlation_id="camp-1",
        attack_id=str(uuid.uuid4()),
        sequence_hash="hash-" + str(uuid.uuid4()),
        attack_category=AttackCategory.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        outcome=Outcome.SUCCESS,
        predicate_fired="non-patient server-file bytes appeared in the extraction",
        regression_flag=False,
        target_version="v1",
        reproduction_ref="repro-1",
        adjudicated_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return ExploitRecord(**defaults)


def test_store_satisfies_exploit_store_protocol():
    store = SqliteExploitStore()
    assert isinstance(store, ExploitStore)


def test_record_round_trips_and_reads_back_equal():
    store = SqliteExploitStore()
    rec = _record()
    assert store.record(rec) is True
    all_records = store.all()
    assert len(all_records) == 1
    assert all_records[0] == rec


def test_record_dedups_on_sequence_hash():
    store = SqliteExploitStore()
    rec1 = _record(sequence_hash="dup-hash", exploit_id="exp-1")
    rec2 = _record(sequence_hash="dup-hash", exploit_id="exp-2")
    assert store.record(rec1) is True
    assert store.record(rec2) is False
    assert len(store.all()) == 1


def test_record_persists_two_distinct_sequence_hashes():
    store = SqliteExploitStore()
    rec1 = _record(sequence_hash="hash-1", exploit_id="exp-1")
    rec2 = _record(sequence_hash="hash-2", exploit_id="exp-2")
    assert store.record(rec1) is True
    assert store.record(rec2) is True
    assert len(store.all()) == 2


def test_cases_tested_by_category_counts():
    store = SqliteExploitStore()
    store.record(_record(exploit_id="exp-1", sequence_hash="h-1", attack_category=AttackCategory.DATA_EXFILTRATION))
    store.record(_record(exploit_id="exp-2", sequence_hash="h-2", attack_category=AttackCategory.DATA_EXFILTRATION))
    store.record(_record(exploit_id="exp-3", sequence_hash="h-3", attack_category=AttackCategory.PROMPT_INJECTION))
    counts = store.cases_tested_by_category()
    assert counts == {
        AttackCategory.DATA_EXFILTRATION: 2,
        AttackCategory.PROMPT_INJECTION: 1,
    }


def test_open_findings_by_category_excludes_fail_and_false_positive():
    store = SqliteExploitStore()
    # success, high severity -> counts
    store.record(
        _record(
            exploit_id="exp-1",
            sequence_hash="h-1",
            attack_category=AttackCategory.TOOL_MISUSE,
            outcome=Outcome.SUCCESS,
            severity=Severity.HIGH,
        )
    )
    # success, but false_positive severity -> excluded
    store.record(
        _record(
            exploit_id="exp-2",
            sequence_hash="h-2",
            attack_category=AttackCategory.TOOL_MISUSE,
            outcome=Outcome.SUCCESS,
            severity=Severity.FALSE_POSITIVE,
        )
    )
    # fail outcome -> excluded
    store.record(
        _record(
            exploit_id="exp-3",
            sequence_hash="h-3",
            attack_category=AttackCategory.TOOL_MISUSE,
            outcome=Outcome.FAIL,
            severity=Severity.CRITICAL,
            predicate_fired=None,
        )
    )
    findings = store.open_findings_by_category()
    assert findings == {AttackCategory.TOOL_MISUSE: 1}


def test_regressions_filters_on_regression_flag():
    store = SqliteExploitStore()
    store.record(_record(exploit_id="exp-1", sequence_hash="h-1", regression_flag=True))
    store.record(_record(exploit_id="exp-2", sequence_hash="h-2", regression_flag=False))
    regressions = store.regressions()
    assert len(regressions) == 1
    assert regressions[0].exploit_id == "exp-1"
    assert regressions[0].regression_flag is True


def test_store_persists_across_reads_with_null_optional_fields():
    store = SqliteExploitStore()
    rec = _record(
        exploit_id="exp-null",
        sequence_hash="h-null",
        predicate_fired=None,
        target_version=None,
        reproduction_ref=None,
    )
    store.record(rec)
    fetched = store.all()[0]
    assert fetched.predicate_fired is None
    assert fetched.target_version is None
    assert fetched.reproduction_ref is None
    assert fetched == rec
