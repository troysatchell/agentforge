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
from agentforge.contracts.verdict import Outcome, Verdict
from agentforge.judge.base import OracleContext

# The frozen ``contracts/v1`` edges this trace threads through, in order. Each
# ``$id`` is the absolute URI published in the corresponding schema file and
# registered by the conftest ``is_valid`` fixture.
_ORCHESTRATOR_TO_REDTEAM = "https://agentforge/contracts/v1/orchestrator_to_redteam.schema.json"
_REDTEAM_TO_JUDGE = "https://agentforge/contracts/v1/redteam_to_judge.schema.json"
_JUDGE_TO_DOCUMENTATION = "https://agentforge/contracts/v1/judge_to_documentation.schema.json"


@dataclass(frozen=True)
class TraceHop:
    edge: str
    schema: str
    payload: dict
    valid: bool


@dataclass(frozen=True)
class EndToEndTrace:
    correlation_id: str
    hops: tuple  # tuple[TraceHop, ...]
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
    """Drive directive -> attack -> verdict -> report through the frozen edges.

    Each hop's payload is the model's JSON dump validated against its published
    schema; only a ``success`` verdict renders a report."""
    result = attack_fn(directive)
    # Integrity: the attack must belong to this directive's campaign.
    if result.correlation_id != directive.correlation_id:
        raise ValueError("attack result correlation_id does not match the directive")
    ctx = OracleContext(result=result, authorized_scope=directive.authorized_scope)
    verdict = judge.adjudicate(ctx, correlation_id=directive.correlation_id)
    if str(verdict.attack_id) != str(result.attack_id):
        raise ValueError("verdict attack_id does not match the adjudicated result")

    is_success = verdict.outcome is Outcome.SUCCESS
    report = render_report(result, verdict) if is_success else None

    hops = [
        _hop("orchestrator->redteam", _ORCHESTRATOR_TO_REDTEAM, directive, is_valid),
        _hop("redteam->judge", _REDTEAM_TO_JUDGE, result, is_valid),
    ]
    # The judge->documentation edge carries SUCCESS verdicts only — fail/partial
    # verdicts never reach the Documentation agent.
    if is_success:
        hops.append(_hop("judge->documentation", _JUDGE_TO_DOCUMENTATION, verdict, is_valid))

    return EndToEndTrace(
        correlation_id=directive.correlation_id,
        hops=tuple(hops),
        report=report,
        all_valid=all(hop.valid for hop in hops),
    )


def _hop(edge: str, schema: str, model: Any, is_valid: Callable[[str, dict], bool]) -> TraceHop:
    payload = model.model_dump(mode="json")
    return TraceHop(edge=edge, schema=schema, payload=payload, valid=is_valid(schema, payload))
