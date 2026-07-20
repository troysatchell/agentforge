"""The exploit-store interface the Orchestrator (and future harness) code against.

Defining this as a ``Protocol`` lets the SQLite store and the Orchestrator be
built independently against the same contract — the Orchestrator never depends
on a concrete store implementation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentforge.contracts.common import AttackCategory
from agentforge.store.records import ExploitRecord


@runtime_checkable
class ExploitStore(Protocol):
    """Persistence + coverage-query surface. Implementations MUST dedup on
    ``sequence_hash`` (no duplicate attack sequences) and keep ``exploit_id``
    unique."""

    def record(self, rec: ExploitRecord) -> bool:
        """Persist a record. Returns ``False`` (and inserts nothing) when the
        ``sequence_hash`` is already present."""
        ...

    def all(self) -> list[ExploitRecord]:
        """Every stored record."""
        ...

    def cases_tested_by_category(self) -> dict[AttackCategory, int]:
        """Count of adjudicated attacks per category — the coverage signal."""
        ...

    def open_findings_by_category(self) -> dict[AttackCategory, int]:
        """Count of confirmed, non-false-positive successes per category."""
        ...

    def regressions(self) -> list[ExploitRecord]:
        """Records whose ``regression_flag`` is True (a fixed exploit reappeared)."""
        ...
