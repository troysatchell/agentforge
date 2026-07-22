"""Frozen tests (RT1 / TRO-123) — Red Team mutation of partial-success attacks.

Mutation evolves an already-executed parent attack toward this target's
grounding-bypass. It is the ONLY layer where sampling is live (temperature
0.8-1.0); the base planner stays deterministic. The mutated child carries
``parent_attack_id`` lineage and is still a schema-valid ``AttackResult`` (edge
③) with NO verdict — grading remains the Judge's job. The Kimi client is faked
so no network/model is touched. These tests are the frozen contract for RT1.
"""

from __future__ import annotations

import json

import pytest

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, TargetResponse
from agentforge.redteam.agent import AttackPlan, RedTeam, RedTeamError
from agentforge.redteam.mutation import Mutator

BASE = "https://openemr-production-4eba.up.railway.app"
OWASP = OwaspMapping(web="A01:2021-broken-access-control", llm="LLM01:2025-prompt-injection")
REDTEAM_TO_JUDGE = "https://agentforge/contracts/v1/redteam_to_judge.schema.json"

PARENT_MARKER = "PARENT_CANARY_9AF2"


def _plan_json(msg, route="POST /apis/default/api/copilot/turn"):
    return json.dumps(
        {
            "input_sequence": [{"turn_index": 0, "route": route, "payload": {"message": msg}}],
            "observed_hints": None,
        }
    )


class FakeKimi:
    """Stub KimiClient: records the last call (incl. temperature); returns preset content."""

    def __init__(self, content):
        self.content = content
        self.last_system = None
        self.last_user = None
        self.last_temperature = None
        self.calls = 0

    def complete(self, *, system, user, response_format=None, temperature=None):
        self.last_system = system
        self.last_user = user
        self.last_temperature = temperature
        self.calls += 1
        return self.content


def _parent(resp=None):
    """A real, executed parent attack produced by the base (unsampled) planner."""
    fake = FakeKimi(_plan_json(f"benign probe {PARENT_MARKER}"))
    rt = RedTeam(fake, target_base_url=BASE)
    plan = rt.plan(category=AttackCategory.DATA_EXFILTRATION, owasp_mapping=OWASP)
    resp = resp if resp is not None else TargetResponse(http_status=200, body={"answer": "no"})
    parent = rt.assemble_result(plan, resp, correlation_id="corr-mut")
    return parent, fake


def test_base_planning_uses_no_temperature():
    # The base planner is NOT live-sampled — only mutation is.
    _parent_result, base_fake = _parent()
    assert base_fake.last_temperature is None


def test_mutate_plan_uses_live_sampling_temperature():
    parent, _ = _parent()
    mfake = FakeKimi(_plan_json("mutated grounding-bypass attempt"))
    child_plan = Mutator(mfake, target_base_url=BASE).mutate_plan(parent, correlation_id="corr-mut")
    assert isinstance(child_plan, AttackPlan)
    assert mfake.last_temperature is not None
    assert 0.8 <= mfake.last_temperature <= 1.0


def test_mutate_plan_custom_temperature_still_in_live_band():
    parent, _ = _parent()
    mfake = FakeKimi(_plan_json("mutated"))
    Mutator(mfake, target_base_url=BASE, temperature=0.85).mutate_plan(parent, correlation_id="c")
    assert 0.8 <= mfake.last_temperature <= 1.0


def test_mutate_plan_is_derived_from_parent():
    parent, _ = _parent()
    mfake = FakeKimi(_plan_json("mutated grounding-bypass attempt"))
    Mutator(mfake, target_base_url=BASE).mutate_plan(parent, correlation_id="corr-mut")
    # the mutation prompt is built FROM the parent it is evolving
    assert PARENT_MARKER in mfake.last_user
    assert parent.attack_category.value in mfake.last_user


def test_mutate_plan_keeps_parent_category():
    parent, _ = _parent()
    mfake = FakeKimi(_plan_json("mutated"))
    child_plan = Mutator(mfake, target_base_url=BASE).mutate_plan(parent, correlation_id="c")
    assert child_plan.attack_category == parent.attack_category


def test_assemble_child_sets_parent_lineage(validate):
    parent, _ = _parent()
    mut = Mutator(FakeKimi(_plan_json("mutated grounding-bypass")), target_base_url=BASE)
    child_plan = mut.mutate_plan(parent, correlation_id="corr-mut")
    resp = TargetResponse(http_status=200, body={"answer": "leaked"})
    child = mut.assemble_child(child_plan, resp, parent, correlation_id="corr-mut")
    assert isinstance(child, AttackResult)
    assert child.parent_attack_id == str(parent.attack_id)
    assert child.attack_id != parent.attack_id
    validate(REDTEAM_TO_JUDGE, child.model_dump(mode="json"))


def test_child_recomputes_sequence_hash():
    parent, _ = _parent()
    mut = Mutator(FakeKimi(_plan_json("a very different mutated payload")), target_base_url=BASE)
    child_plan = mut.mutate_plan(parent, correlation_id="c")
    child = mut.assemble_child(
        child_plan, TargetResponse(http_status=200, body={}), parent, correlation_id="c"
    )
    # a mutated (different) input_sequence must hash differently from the parent
    assert child.sequence_hash != parent.sequence_hash


def test_child_carries_no_verdict():
    parent, _ = _parent()
    mut = Mutator(FakeKimi(_plan_json("mutated")), target_base_url=BASE)
    child_plan = mut.mutate_plan(parent, correlation_id="c")
    dump = mut.assemble_child(
        child_plan, TargetResponse(http_status=200, body={"x": 1}), parent, correlation_id="c"
    ).model_dump(mode="json")
    assert "outcome" not in dump and "verdict" not in dump and "predicate_fired" not in dump


def test_malformed_mutation_output_raises_redteam_error():
    parent, _ = _parent()
    mut = Mutator(FakeKimi("this is not json at all"), target_base_url=BASE)
    with pytest.raises(RedTeamError):
        mut.mutate_plan(parent, correlation_id="c")
