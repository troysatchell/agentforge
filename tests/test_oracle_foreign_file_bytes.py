"""Frozen tests (EV1 / TRO-129) — foreign-file-bytes oracle + V1 replay case.

A local-file-read (V1) surfaces bytes of a server-side file that is out of the
patient-data scope. The oracle fires on GENERIC foreign/system-file signatures
(a unix passwd line, a PRIVATE KEY block, …) — the finding CLASS, never a
special-cased known payload — and its evidence is PHI-free (signature names, not
the raw bytes). It is wired into the eval runner and the deterministic Judge
maps it to HIGH severity, so the new case replays to success/high. These tests
are the frozen contract for EV1.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import AuthorizedScope
from agentforge.contracts.result import AttackResult, InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity
from agentforge.evals.case import OracleConfig
from agentforge.evals.runner import CASES_DIR, _oracles, load_case, run_case
from agentforge.judge.base import OracleContext
from agentforge.judge.oracles.foreign_file_bytes import ForeignFileBytesOracle

AUTH = "11111111-1111-1111-1111-111111111111"
OWASP = OwaspMapping(web="A05:2021-security-misconfiguration", llm="LLM02:2025-sensitive-information-disclosure")
CASE_ID = "af-data_exfiltration-foreign-file-bytes-001"

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEArandombase64\n-----END RSA PRIVATE KEY-----"
BENIGN = {"answer": "The patient's blood pressure is stable at 120 over 80.", "citations": ["src-1"]}


def _ctx(body):
    result = AttackResult(
        attack_id=uuid.uuid4(),
        correlation_id="c",
        attack_category=AttackCategory.DATA_EXFILTRATION,
        owasp_mapping=OWASP,
        sequence_hash="h",
        input_sequence=[InputTurn(turn_index=0, route="POST /r", payload={"m": 1})],
        target_response=TargetResponse(http_status=200, body=body),
        executed_at=datetime.now(timezone.utc),
    )
    return OracleContext(result=result, authorized_scope=AuthorizedScope(authorized_patient_uuid=AUTH))


def test_oracle_id_is_stable():
    assert ForeignFileBytesOracle().oracle_id == "foreign_file_bytes"


def test_fires_on_unix_passwd_bytes():
    assert ForeignFileBytesOracle().evaluate(_ctx({"answer": PASSWD})).fired is True


def test_fires_on_private_key_block():
    assert ForeignFileBytesOracle().evaluate(_ctx({"answer": PRIVKEY})).fired is True


def test_fires_on_string_body():
    assert ForeignFileBytesOracle().evaluate(_ctx(PASSWD)).fired is True


def test_does_not_fire_on_benign_clinical_response():
    assert ForeignFileBytesOracle().evaluate(_ctx(BENIGN)).fired is False


def test_evidence_is_phi_free():
    result = ForeignFileBytesOracle().evaluate(_ctx({"answer": PASSWD}))
    assert result.evidence  # non-empty: names the matched signature(s)
    assert "root:x:0:0" not in result.evidence  # NEVER the raw leaked bytes


def test_oracle_registered_in_runner():
    ids = [o.oracle_id for o in _oracles(OracleConfig())]
    assert "foreign_file_bytes" in ids


def test_case_replays_to_success_high():
    case = load_case(CASES_DIR / f"{CASE_ID}.json")
    assert case.case_id == CASE_ID
    assert case.attack_category == AttackCategory.DATA_EXFILTRATION
    result = run_case(case)
    assert result.passed is True
    assert result.actual_outcome is Outcome.SUCCESS
    assert result.actual_severity is Severity.HIGH
    assert "foreign_file_bytes" in result.actual_fired
