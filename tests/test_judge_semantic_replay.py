"""Frozen tests (T4 / TRO-124) — Judge semantic residue layer + replay seam.

Two deliverables:
  1. An OPTIONAL semantic layer on ``DeterministicJudge``, consulted ONLY when no
     deterministic oracle fired. It may promote residue (``judge_type=semantic_llm``)
     but can NEVER be reached — let alone downgrade — a confirmed exploit.
  2. ``InputKeyedReplayTransport`` — deterministic replay keyed by a canonical
     hash of the request body; a miss raises rather than fabricating a response.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import JudgeType, Outcome, Severity
from agentforge.judge.base import OracleContext
from agentforge.judge.deterministic import DeterministicJudge
from agentforge.judge.replay import InputKeyedReplayTransport, ReplayMiss, input_key
from agentforge.judge.semantic import SemanticDecision, SemanticResidueJudge
from tests._contract_ids import VERDICT

FIXED_TIME = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
FIXED_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


class _FakeOracle:
    def __init__(self, oracle_id: str, fired: bool | None, evidence: str | None = None) -> None:
        self.oracle_id = oracle_id
        self._fired = fired
        self._evidence = evidence

    def evaluate(self, ctx: OracleContext) -> OracleResult:
        return OracleResult(oracle_id=self.oracle_id, fired=self._fired, evidence=self._evidence)


class FakeSemanticLayer:
    """Duck-typed semantic layer — records calls, returns a preset decision."""

    def __init__(self, decision: SemanticDecision | None) -> None:
        self.decision = decision
        self.calls = 0

    def assess(self, ctx: OracleContext) -> SemanticDecision | None:
        self.calls += 1
        return self.decision


def _ctx() -> OracleContext:
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="camp-1",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm=None),
        sequence_hash="hash-1",
        input_sequence=[InputTurn(turn_index=0, route="POST /api/copilot/turn", payload={})],
        target_response=TargetResponse(http_status=200, body={"status": "ok"}),
        target_version="v1.2.3",
        executed_at=FIXED_TIME,
    )
    return OracleContext(result=result, authorized_scope=AuthorizedScope(authorized_patient_uuid="patient-1"))


def _judge(oracles: list, *, semantic=None) -> DeterministicJudge:
    return DeterministicJudge(
        oracles, clock=lambda: FIXED_TIME, id_factory=lambda: FIXED_ID, semantic=semantic
    )


# --- semantic layer: promotes residue when oracles are silent -------------


def test_semantic_promotes_residue_when_no_oracle_fires(validate) -> None:
    decision = SemanticDecision(
        outcome=Outcome.SUCCESS,
        severity=Severity.MEDIUM,
        predicate="semantic residue: fabricated citation absent from the pinned chart",
    )
    sem = FakeSemanticLayer(decision)
    judge = _judge([_FakeOracle("phi_pattern", fired=False)], semantic=sem)

    verdict = judge.adjudicate(_ctx(), correlation_id="c")

    assert verdict.outcome == Outcome.SUCCESS
    assert verdict.severity == Severity.MEDIUM
    assert verdict.judge_type == JudgeType.SEMANTIC_LLM
    assert verdict.predicate_fired == decision.predicate
    assert sem.calls == 1
    validate(VERDICT, verdict.model_dump(mode="json"))


def test_no_semantic_layer_preserves_deterministic_fail() -> None:
    judge = _judge([_FakeOracle("phi_pattern", fired=False)])  # semantic defaults to None

    verdict = judge.adjudicate(_ctx(), correlation_id="c")

    assert verdict.outcome == Outcome.FAIL
    assert verdict.severity == Severity.LOW
    assert verdict.predicate_fired is None
    assert verdict.judge_type == JudgeType.DETERMINISTIC_ORACLE


def test_semantic_abstention_yields_deterministic_fail() -> None:
    sem = FakeSemanticLayer(None)  # abstains
    judge = _judge([_FakeOracle("phi_pattern", fired=False)], semantic=sem)

    verdict = judge.adjudicate(_ctx(), correlation_id="c")

    assert verdict.outcome == Outcome.FAIL
    assert verdict.judge_type == JudgeType.DETERMINISTIC_ORACLE
    assert sem.calls == 1


def test_semantic_is_never_consulted_when_an_oracle_fires() -> None:
    """The never-approve-a-confirmed-exploit invariant, enforced structurally."""
    would_downgrade = SemanticDecision(
        outcome=Outcome.FAIL, severity=Severity.LOW, predicate="should never be used"
    )
    sem = FakeSemanticLayer(would_downgrade)
    judge = _judge(
        [_FakeOracle("cross_patient", fired=True, evidence="foreign_pid_count=1")], semantic=sem
    )

    verdict = judge.adjudicate(_ctx(), correlation_id="c")

    assert verdict.outcome == Outcome.SUCCESS
    assert verdict.judge_type == JudgeType.DETERMINISTIC_ORACLE
    assert sem.calls == 0  # the semantic layer is never even reached


# --- SemanticResidueJudge: wraps an injected LLM client --------------------


class FakeSemanticClient:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.calls = 0
        self.user: str | None = None

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        self.user = user
        return self.reply


def test_semantic_residue_judge_parses_a_positive_decision() -> None:
    reply = json.dumps(
        {"outcome": "success", "severity": "medium", "predicate": "fabricated citation"}
    )
    client = FakeSemanticClient(reply)

    decision = SemanticResidueJudge(client).assess(_ctx())

    assert decision is not None
    assert decision.outcome == Outcome.SUCCESS
    assert decision.severity == Severity.MEDIUM
    assert decision.predicate == "fabricated citation"
    assert client.calls == 1
    assert client.user is not None and "data_exfiltration" in client.user


def test_semantic_residue_judge_abstains_on_no_signal() -> None:
    client = FakeSemanticClient(json.dumps({"outcome": "fail"}))
    assert SemanticResidueJudge(client).assess(_ctx()) is None


# --- InputKeyedReplayTransport --------------------------------------------


def test_replay_returns_recorded_response_for_matching_input() -> None:
    body = {"model": "m", "system": "S", "messages": [{"role": "user", "content": "U"}]}
    resp = {"content": [{"type": "text", "text": "R"}]}
    transport = InputKeyedReplayTransport({input_key(body): resp})

    assert transport("https://api", {"h": 1}, body) == resp


def test_input_key_is_order_insensitive() -> None:
    assert input_key({"a": 1, "b": 2}) == input_key({"b": 2, "a": 1})


def test_different_inputs_get_different_keys() -> None:
    assert input_key({"x": 1}) != input_key({"x": 2})


def test_replay_miss_raises_typed_error() -> None:
    transport = InputKeyedReplayTransport({})
    with pytest.raises(ReplayMiss):
        transport("u", {}, {"never": "recorded"})


def test_replay_is_reproducible() -> None:
    body = {"model": "m", "messages": [{"role": "user", "content": "U"}]}
    resp = {"content": [{"type": "text", "text": "R"}]}
    transport = InputKeyedReplayTransport({input_key(body): resp})

    assert transport("u", {}, body) == transport("u", {}, body) == resp
