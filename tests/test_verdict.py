"""Contract tests for the Verdict model (judge_to_documentation.schema.json).

ROUTING (schema description, review fix #10): only outcome=success flows to
Documentation; all outcomes persist to the exploit DB; outcome=partial also
routes to the Orchestrator as a mutation candidate. ``predicate_fired`` is
what makes a regression test assert SIGNAL, not a generic pass.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from agentforge.contracts.verdict import JudgeType, Outcome, Severity, Verdict
from tests._contract_ids import VERDICT


def _minimal_kwargs() -> dict[str, Any]:
    return dict(
        verdict_id=uuid.uuid4(),
        attack_id=uuid.uuid4(),
        correlation_id="corr-123",
        outcome=Outcome.FAIL,
        predicate_fired=None,
        severity=Severity.LOW,
        regression_flag=False,
        adjudicated_at=datetime.now(timezone.utc),
    )


def test_verdict_minimal_required_fields_roundtrips(validate):
    v = Verdict(**_minimal_kwargs())
    dumped = v.model_dump(mode="json")

    # required-but-nullable key must still be present, as null
    assert dumped["predicate_fired"] is None
    # optional non-nullable keys left unset must be OMITTED, not emitted as null
    assert "reproduction_ref" not in dumped
    assert "ground_truth_ref" not in dumped
    assert "attack_category" not in dumped
    assert "owasp_mapping" not in dumped
    assert "cross_category_regression" not in dumped
    assert "target_version" not in dumped
    assert "oracle_results" not in dumped

    validate(VERDICT, dumped)


def test_verdict_defaults_schema_version_and_judge_type():
    v = Verdict(**_minimal_kwargs())
    assert v.schema_version == "1.0.0"
    assert v.judge_type == JudgeType.DETERMINISTIC_ORACLE


def test_verdict_full_payload_roundtrips(validate):
    kwargs = _minimal_kwargs()
    kwargs.update(
        outcome=Outcome.SUCCESS,
        predicate_fired="non-patient server-file bytes appeared in the VLM extraction",
        judge_type=JudgeType.SEMANTIC_LLM,
        oracle_results=[OracleResult(oracle_id="phi_pattern", fired=True, evidence="count=1")],
        ground_truth_ref="chart-snapshot-42",
        severity=Severity.CRITICAL,
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OwaspMapping(web=None, llm="LLM01:2025-prompt-injection"),
        cross_category_regression="tool_misuse",
        reproduction_ref="seqhash-abc123",
        target_version="v0.4.2",
    )
    v = Verdict(**kwargs)
    dumped = v.model_dump(mode="json")

    validate(VERDICT, dumped)
    assert dumped["oracle_results"][0]["oracle_id"] == "phi_pattern"
    assert dumped["owasp_mapping"] == {"web": None, "llm": "LLM01:2025-prompt-injection"}


def test_verdict_forbids_extra_keys():
    with pytest.raises(Exception):
        Verdict(**_minimal_kwargs(), sneaky="x")  # type: ignore[call-arg]


def test_verdict_requires_regression_flag():
    kwargs = _minimal_kwargs()
    del kwargs["regression_flag"]
    with pytest.raises(Exception):
        Verdict(**kwargs)  # type: ignore[call-arg]


def test_verdict_requires_predicate_fired_key_even_though_nullable():
    kwargs = _minimal_kwargs()
    del kwargs["predicate_fired"]
    with pytest.raises(Exception):
        Verdict(**kwargs)  # type: ignore[call-arg]


def test_verdict_rejects_invalid_outcome():
    with pytest.raises(Exception):
        Verdict(**{**_minimal_kwargs(), "outcome": "bogus"})


def test_verdict_rejects_invalid_severity():
    with pytest.raises(Exception):
        Verdict(**{**_minimal_kwargs(), "severity": "bogus"})
