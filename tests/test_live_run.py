"""Frozen tests (T5 / TRO-135) — live-run campaign orchestration.

``run_campaign`` ties the built components together, per category:
RedTeam plans an attack → TargetClient fires it at the target → RedTeam
assembles the ``AttackResult`` → the deterministic Judge adjudicates it. This is
the MVP live path: one live agent role (the Red Team) firing at the target and
being judged. Everything is INJECTED here (fake Kimi, fake target client, a
controllable oracle) so no network/model is touched. Frozen contract for the ticket.
"""

from __future__ import annotations

import json

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import TargetResponse
from agentforge.contracts.verdict import Outcome, Verdict
from agentforge.judge.deterministic import DeterministicJudge
from agentforge.live_run import CampaignResult, run_campaign
from agentforge.redteam.agent import RedTeam

BASE = "https://openemr-production-4eba.up.railway.app"
OWASP = OwaspMapping(web=None, llm="LLM01:2025-prompt-injection")
REDTEAM_TO_JUDGE = "https://agentforge/contracts/v1/redteam_to_judge.schema.json"
CATS = [
    AttackCategory.PROMPT_INJECTION,
    AttackCategory.DATA_EXFILTRATION,
    AttackCategory.DENIAL_OF_SERVICE,
]
SCOPE = AuthorizedScope(authorized_patient_uuid="patient-1")


def _spec():
    return json.dumps(
        {
            "input_sequence": [
                {"turn_index": 0, "route": "POST /apis/default/api/copilot/turn", "payload": {"message": "probe"}}
            ],
            "observed_hints": [{"oracle_id": "injection_canary", "fired": None, "evidence": "canary"}],
        }
    )


class FakeKimi:
    def __init__(self, content):
        self.content = content

    def complete(self, *, system, user, response_format=None, temperature=None):
        return self.content


class FakeTargetClient:
    """Stands in for TargetClient: records calls, returns a preset TargetResponse."""

    def __init__(self, response):
        self.response = response
        self.calls = []

    def execute(self, *, access_token, input_sequence):
        self.calls.append({"access_token": access_token, "input_sequence": input_sequence})
        return self.response


class _Oracle:
    """Controllable oracle: fires (or not) regardless of input, to drive the verdict."""

    def __init__(self, oracle_id, fired):
        self.oracle_id = oracle_id
        self._fired = fired

    def evaluate(self, ctx):
        return OracleResult(oracle_id=self.oracle_id, fired=self._fired, evidence="e" if self._fired else None)


def _run(judge, target=None, categories=CATS):
    target = target or FakeTargetClient(TargetResponse(http_status=200, body={"reply": "benign"}))
    return run_campaign(
        redteam=RedTeam(FakeKimi(_spec()), target_base_url=BASE),
        target_client=target,
        judge=judge,
        categories=categories,
        owasp_for=lambda c: OWASP,
        authorized_scope=SCOPE,
        access_token="tok-xyz",
        correlation_id="corr-1",
    )


def test_campaign_returns_one_result_per_category_in_order():
    results = _run(DeterministicJudge([_Oracle("noop", False)]))
    assert len(results) == len(CATS)
    assert all(isinstance(r, CampaignResult) for r in results)
    assert [r.attack_result.attack_category for r in results] == CATS


def test_each_result_has_a_real_deterministic_judge_verdict():
    results = _run(DeterministicJudge([_Oracle("noop", False)]))
    for r in results:
        assert isinstance(r.verdict, Verdict)
        assert r.verdict.outcome == Outcome.FAIL  # no oracle fired -> the REAL judge says fail (not a stub)
        assert r.verdict.correlation_id == "corr-1"


def test_firing_oracle_yields_success_verdict_from_real_judge():
    results = _run(DeterministicJudge([_Oracle("phi_pattern", True)]))
    assert all(r.verdict.outcome == Outcome.SUCCESS for r in results)
    assert all(r.verdict.predicate_fired for r in results)


def test_attack_results_are_schema_valid(validate):
    for r in _run(DeterministicJudge([_Oracle("noop", False)])):
        validate(REDTEAM_TO_JUDGE, r.attack_result.model_dump(mode="json"))


def test_target_client_receives_token_and_plan_sequence():
    target = FakeTargetClient(TargetResponse(http_status=200, body={}))
    _run(DeterministicJudge([_Oracle("noop", False)]), target=target, categories=[AttackCategory.PROMPT_INJECTION])
    assert len(target.calls) == 1
    assert target.calls[0]["access_token"] == "tok-xyz"
    assert len(target.calls[0]["input_sequence"]) >= 1


def test_campaign_covers_at_least_three_categories():
    results = _run(DeterministicJudge([_Oracle("noop", False)]))
    assert len({r.attack_result.attack_category for r in results}) >= 3
