"""SQLite-backed :class:`~agentforge.store.ExploitStore` implementation.

Stdlib ``sqlite3`` only. ``exploit_id`` is the primary key (unique);
``sequence_hash`` has a unique index — that's the dedup gate. Enums persist
as their ``.value``; ``adjudicated_at`` persists as an ISO-8601 string and is
reconstructed into a real ``datetime`` on read.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.store.records import ExploitRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS exploit_records (
    exploit_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    attack_id TEXT NOT NULL,
    sequence_hash TEXT NOT NULL,
    attack_category TEXT NOT NULL,
    severity TEXT NOT NULL,
    outcome TEXT NOT NULL,
    predicate_fired TEXT,
    regression_flag INTEGER NOT NULL,
    cross_category TEXT,
    target_version TEXT,
    reproduction_ref TEXT,
    adjudicated_at TEXT NOT NULL
);
"""

_INDEXES = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_exploit_records_sequence_hash "
    "ON exploit_records (sequence_hash);",
    "CREATE INDEX IF NOT EXISTS ix_exploit_records_severity "
    "ON exploit_records (severity);",
    "CREATE INDEX IF NOT EXISTS ix_exploit_records_attack_category "
    "ON exploit_records (attack_category);",
    "CREATE INDEX IF NOT EXISTS ix_exploit_records_target_version "
    "ON exploit_records (target_version);",
)

_COLUMNS = (
    "exploit_id",
    "correlation_id",
    "attack_id",
    "sequence_hash",
    "attack_category",
    "severity",
    "outcome",
    "predicate_fired",
    "regression_flag",
    "cross_category",
    "target_version",
    "reproduction_ref",
    "adjudicated_at",
)


class SqliteExploitStore:
    """SQLite implementation of the ``ExploitStore`` protocol."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(_SCHEMA)
        for stmt in _INDEXES:
            self._conn.execute(stmt)
        self._conn.commit()

    def record(self, rec: ExploitRecord) -> bool:
        row = (
            rec.exploit_id,
            rec.correlation_id,
            rec.attack_id,
            rec.sequence_hash,
            rec.attack_category.value,
            rec.severity.value,
            rec.outcome.value,
            rec.predicate_fired,
            int(rec.regression_flag),
            rec.cross_category,
            rec.target_version,
            rec.reproduction_ref,
            rec.adjudicated_at.isoformat(),
        )
        placeholders = ", ".join("?" for _ in _COLUMNS)
        sql = f"INSERT INTO exploit_records ({', '.join(_COLUMNS)}) VALUES ({placeholders})"
        try:
            self._conn.execute(sql, row)
        except sqlite3.IntegrityError:
            return False
        self._conn.commit()
        return True

    def all(self) -> list[ExploitRecord]:
        cursor = self._conn.execute(f"SELECT {', '.join(_COLUMNS)} FROM exploit_records")
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def cases_tested_by_category(self) -> dict[AttackCategory, int]:
        cursor = self._conn.execute(
            "SELECT attack_category, COUNT(*) FROM exploit_records GROUP BY attack_category"
        )
        return {AttackCategory(category): count for category, count in cursor.fetchall()}

    def open_findings_by_category(self) -> dict[AttackCategory, int]:
        cursor = self._conn.execute(
            "SELECT attack_category, COUNT(*) FROM exploit_records "
            "WHERE outcome = ? AND severity != ? GROUP BY attack_category",
            (Outcome.SUCCESS.value, Severity.FALSE_POSITIVE.value),
        )
        return {AttackCategory(category): count for category, count in cursor.fetchall()}

    def regressions(self) -> list[ExploitRecord]:
        cursor = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM exploit_records WHERE regression_flag = 1"
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    @staticmethod
    def _row_to_record(row: tuple) -> ExploitRecord:
        (
            exploit_id,
            correlation_id,
            attack_id,
            sequence_hash,
            attack_category,
            severity,
            outcome,
            predicate_fired,
            regression_flag,
            cross_category,
            target_version,
            reproduction_ref,
            adjudicated_at,
        ) = row
        return ExploitRecord(
            exploit_id=exploit_id,
            correlation_id=correlation_id,
            attack_id=attack_id,
            sequence_hash=sequence_hash,
            attack_category=AttackCategory(attack_category),
            severity=Severity(severity),
            outcome=Outcome(outcome),
            predicate_fired=predicate_fired,
            regression_flag=bool(regression_flag),
            cross_category=cross_category,
            target_version=target_version,
            reproduction_ref=reproduction_ref,
            adjudicated_at=datetime.fromisoformat(adjudicated_at),
        )
