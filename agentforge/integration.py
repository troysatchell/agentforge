"""INT1 / TRO-132 — end-to-end contract trace (STUB for the RED phase; replaced
by the INT1 coding agent).

Drives a full directive -> attack -> verdict -> report chain through the frozen
``contracts/v1`` edges, validating each hop against its published schema — the
end-to-end correctness proof for the integration packet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from agentforge.contracts.directive import AttackDirective
from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict
from agentforge.judge.base import OracleContext  # noqa: F401  (used by the impl)


@dataclass(frozen=True)
class TraceHop:
    edge: str
    schema: str
    payload: dict
    valid: bool


@dataclass(frozen=True)
class EndToEndTrace:
    correlation_id: str
    hops: list  # list[TraceHop]
    report: str | None
    all_valid: bool


def run_end_to_end(
    *,
    directive: AttackDirective,
    attack_fn: Callable[[AttackDirective], AttackResult],
    judge: Any,
    render_report: Callable[[AttackResult, Verdict], str],
    is_valid: Callable[[str, dict], bool],
) -> EndToEndTrace:
    raise NotImplementedError("INT1: run_end_to_end not implemented yet")
