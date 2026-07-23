"""Frozen tests (RPT1 / TRO-130) — deterministic vuln-report renderer.

`render_vuln_report` emits the six mandatory fields of VULN_REPORT_TEMPLATE from
an adjudicated (AttackResult, Verdict) pair: id+severity, description+impact,
minimal reproduction, observed vs expected, remediation, status+fix-validation.
Frozen contract for RPT1.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import JudgeType, Outcome, Severity, Verdict
from agentforge.documentation.render import render_vuln_report

OWASP = OwaspMapping(web="A05:2021-security-misconfiguration", llm="LLM02:2025-sensitive-information-disclosure")


def _result():
    return AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="c",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OWASP,
        sequence_hash="af-data_exfiltration-local-file-read-001",
        input_sequence=[
            InputTurn(turn_index=0, route="POST /api/copilot/document", payload={"file_path": "../../etc/passwd.pdf"})
        ],
        target_response=TargetResponse(http_status=200, body={"answer": "root:x:0:0"}),
        target_version="deploy-abc123",
        executed_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
    )


def _verdict(result):
    return Verdict(
        verdict_id=uuid.uuid4(),
        attack_id=result.attack_id,
        correlation_id="c",
        outcome=Outcome.SUCCESS,
        predicate_fired="foreign_file_bytes fired: an out-of-scope server file was read",
        judge_type=JudgeType.DETERMINISTIC_ORACLE,
        severity=Severity.CRITICAL,
        attack_category=result.attack_category,
        owasp_mapping=OWASP,
        regression_flag=False,
        reproduction_ref=result.sequence_hash,
        target_version="deploy-abc123",
        adjudicated_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
    )


def _render(**kw):
    result = _result()
    verdict = _verdict(result)
    base = dict(
        af_id="AF-2026-001",
        title="Arbitrary server-file read via /document",
        description="The /document endpoint reads a caller-supplied path.",
        expected="Path mode rejected; no foreign bytes disclosed.",
        remediation="Allowlist the upload dir; normalize realpath.",
        regression_case="evals/cases/af-data_exfiltration-foreign-file-bytes-001.json",
        discovered="2026-07-21",
    )
    base.update(kw)
    return render_vuln_report(result, verdict, **base)


def test_has_all_six_mandatory_sections():
    md = _render()
    assert md.startswith("# AF-2026-001 — Arbitrary server-file read via /document")
    assert "**Severity:** critical" in md
    assert "## Description & clinical impact" in md
    assert "## Reproduction" in md
    assert "## Observed vs expected" in md
    assert "## Recommended remediation" in md
    assert "## Fix validation" in md


def test_derives_fields_from_result_and_verdict():
    md = _render()
    assert "data_exfiltration" in md
    assert "A05:2021-security-misconfiguration" in md
    assert "LLM02:2025-sensitive-information-disclosure" in md
    assert "POST /api/copilot/document" in md  # reproduction from input_sequence
    assert "foreign_file_bytes fired" in md  # observed = predicate_fired
    assert "deploy-abc123" in md  # target_version
    assert "af-data_exfiltration-local-file-read-001" in md  # exploit ref / sequence_hash


def test_bad_af_id_raises():
    with pytest.raises(ValueError):
        _render(af_id="not-an-id")


def test_regression_case_and_status_rendered():
    md = _render(status="open")
    assert "evals/cases/af-data_exfiltration-foreign-file-bytes-001.json" in md
    assert "open" in md
