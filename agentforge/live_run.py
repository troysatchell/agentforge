"""``run_campaign`` — live-run campaign orchestration (T5 / TRO-135).

The MVP live path: Red Team -> TargetClient -> Judge. For each attack
category, the already-built components are tied together in order: the Red
Team plans an attack, the (duck-typed) target client fires it at the live
target, the Red Team assembles the resulting ``AttackResult``, and the
deterministic Judge independently adjudicates a :class:`Verdict` from it.
Nothing here grades anything itself — adjudication is exclusively the
Judge's job, performed on every category's result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Verdict
from agentforge.judge.base import OracleContext
from agentforge.redteam.agent import RedTeam


class TargetClientLike(Protocol):
    """Duck-typed shape the injected target client must satisfy — matches
    ``agentforge.target.client.TargetClient.execute`` without importing it,
    so tests can inject a fake."""

    def execute(self, *, access_token: str, input_sequence: list[InputTurn]) -> TargetResponse: ...


class JudgeLike(Protocol):
    """Duck-typed shape the injected judge must satisfy — matches
    ``agentforge.judge.deterministic.DeterministicJudge.adjudicate`` without
    importing it, so tests can inject a fake or a real judge."""

    def adjudicate(self, ctx: OracleContext, *, correlation_id: str) -> Verdict: ...


@dataclass(frozen=True)
class CampaignResult:
    """One category's fully judged live-run outcome: the executed attack and
    the Judge's independent verdict on it."""

    attack_result: AttackResult
    verdict: Verdict


def run_campaign(
    *,
    redteam: RedTeam,
    target_client: TargetClientLike,
    judge: JudgeLike,
    categories: list[AttackCategory],
    owasp_for: Callable[[AttackCategory], OwaspMapping],
    authorized_scope: AuthorizedScope,
    access_token: str,
    correlation_id: str,
) -> list[CampaignResult]:
    """Run one live attack per category, in order, and judge each result.

    For every category: plan -> execute against the target -> assemble the
    ``AttackResult`` -> adjudicate a ``Verdict``. Returns one
    :class:`CampaignResult` per category, in the same order as ``categories``.
    """
    results: list[CampaignResult] = []
    for category in categories:
        plan = redteam.plan(category=category, owasp_mapping=owasp_for(category))
        response = target_client.execute(access_token=access_token, input_sequence=plan.input_sequence)
        attack_result = redteam.assemble_result(plan, response, correlation_id=correlation_id)
        ctx = OracleContext(result=attack_result, authorized_scope=authorized_scope)
        verdict = judge.adjudicate(ctx, correlation_id=correlation_id)
        results.append(CampaignResult(attack_result=attack_result, verdict=verdict))
    return results
