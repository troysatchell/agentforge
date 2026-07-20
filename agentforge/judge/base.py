"""The oracle interface. Every deterministic oracle and the Judge code against
this — oracles never share context with the Red Team, and the Judge recomputes
every signal from the AttackResult itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agentforge.contracts.common import OracleResult
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult


@dataclass(frozen=True)
class OracleContext:
    """Everything an oracle is allowed to see: the attack + response it must
    judge, and the campaign's authorized scope (the ground truth for
    cross-patient / out-of-scope decisions). Oracle-specific config (cost
    ceilings, legit source ids) lives on the oracle instance, not here."""

    result: AttackResult
    authorized_scope: AuthorizedScope


@runtime_checkable
class Oracle(Protocol):
    """A deterministic oracle. ``oracle_id`` is a stable label; ``evaluate``
    returns a PHI-free :class:`OracleResult` (``fired`` True/False/None)."""

    oracle_id: str

    def evaluate(self, ctx: OracleContext) -> OracleResult: ...
