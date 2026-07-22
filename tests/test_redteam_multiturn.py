"""Frozen tests (RT2 / TRO-123) — Red Team multi-turn attack sequences.

The runner drives an attack turn-by-turn: it asks the (faked) model for the
next single turn, executes it against an injected target callable, and feeds the
target's response back into the next turn's prompt — until the model signals
done or ``max_turns`` is reached. It then assembles ONE schema-valid
``AttackResult`` (edge ③) over the whole ``input_sequence``, carrying no
verdict. No network/model is touched. These tests are the frozen contract for RT2.
"""

from __future__ import annotations

import json

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import TargetResponse
from agentforge.redteam.sequences import MultiTurnRunner

BASE = "https://openemr-production-4eba.up.railway.app"
OWASP = OwaspMapping(web=None, llm="LLM01:2025-prompt-injection")
REDTEAM_TO_JUDGE = "https://agentforge/contracts/v1/redteam_to_judge.schema.json"
PI = AttackCategory.PROMPT_INJECTION

RESP0 = TargetResponse(http_status=200, body={"answer": "step0 RESP0_MARK"})
RESP1 = TargetResponse(http_status=200, body={"answer": "final RESP1_MARK"})


def _turn(route, msg, done):
    return json.dumps({"route": route, "payload": {"message": msg}, "done": done})


class ScriptedKimi:
    """Returns a scripted list of per-turn JSON strings; records each user prompt + temperature."""

    def __init__(self, scripts):
        self._scripts = list(scripts)
        self.prompts = []
        self.temps = []
        self._i = 0

    def complete(self, *, system, user, response_format=None, temperature=None):
        self.prompts.append(user)
        self.temps.append(temperature)
        out = self._scripts[min(self._i, len(self._scripts) - 1)]
        self._i += 1
        return out


class RecordingTarget:
    """Executes turns against scripted responses; records every turn it received."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self._i = 0

    def __call__(self, turn):
        self.calls.append(turn)
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return r


def test_run_drives_turns_until_done():
    client = ScriptedKimi([_turn("/r0", "m0", False), _turn("/r1", "m1", True)])
    target = RecordingTarget([RESP0, RESP1])
    result = MultiTurnRunner(client, target_base_url=BASE).run(
        category=PI, owasp_mapping=OWASP, target=target, correlation_id="c"
    )
    assert [t.turn_index for t in result.input_sequence] == [0, 1]  # ordered
    assert len(target.calls) == 2  # each turn executed exactly once
    assert result.target_response.body == RESP1.body  # final response is retained


def test_response_is_fed_back_into_next_prompt():
    client = ScriptedKimi([_turn("/r0", "m0", False), _turn("/r1", "m1", True)])
    target = RecordingTarget([RESP0, RESP1])
    MultiTurnRunner(client, target_base_url=BASE).run(
        category=PI, owasp_mapping=OWASP, target=target, correlation_id="c"
    )
    # the second turn's prompt contains a marker from the first turn's response
    assert "RESP0_MARK" in client.prompts[1]


def test_run_respects_max_turns_cap():
    client = ScriptedKimi([_turn("/r", "m", False)] * 12)  # model never says done
    target = RecordingTarget([TargetResponse(http_status=200, body={"a": i}) for i in range(12)])
    result = MultiTurnRunner(client, target_base_url=BASE, max_turns=3).run(
        category=PI, owasp_mapping=OWASP, target=target, correlation_id="c"
    )
    assert len(result.input_sequence) == 3
    assert len(target.calls) == 3


def test_result_is_schema_valid_and_verdict_free(validate):
    client = ScriptedKimi([_turn("/r0", "m0", True)])
    target = RecordingTarget([RESP0])
    result = MultiTurnRunner(client, target_base_url=BASE).run(
        category=PI, owasp_mapping=OWASP, target=target, correlation_id="c"
    )
    dump = result.model_dump(mode="json")
    validate(REDTEAM_TO_JUDGE, dump)
    assert "outcome" not in dump and "verdict" not in dump


def test_sequence_hash_stable_for_identical_turns():
    def run_once():
        client = ScriptedKimi([_turn("/r0", "m0", False), _turn("/r1", "m1", True)])
        target = RecordingTarget([RESP0, RESP1])
        return MultiTurnRunner(client, target_base_url=BASE).run(
            category=PI, owasp_mapping=OWASP, target=target, correlation_id="c"
        )

    assert run_once().sequence_hash == run_once().sequence_hash
