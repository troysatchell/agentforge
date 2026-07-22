"""RT3 / TRO-123 — seed-corpus ingestion (STUB for RED phase).

Replaced by the RT3 coding agent. Normalizes external red-team seed records
(Garak reports, PyRIT datasets) into the platform's category-tagged
``SeedAttack`` shape so they can be assembled into schema-valid AttackResults.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.result import InputTurn


class CorpusError(Exception):
    """Raised when a seed record can't be normalized (missing prompt text, or a
    probe/harm label that doesn't map into the closed attack-category set)."""


@dataclass
class SeedAttack:
    attack_category: AttackCategory
    input_sequence: list[InputTurn]
    provenance: str


def from_garak(record: dict, *, route: str) -> SeedAttack:
    raise NotImplementedError("RT3: from_garak not implemented yet")


def from_pyrit(record: dict, *, route: str) -> SeedAttack:
    raise NotImplementedError("RT3: from_pyrit not implemented yet")


def ingest(records: Iterable[dict], *, source: Literal["garak", "pyrit"], route: str) -> list[SeedAttack]:
    raise NotImplementedError("RT3: ingest not implemented yet")
