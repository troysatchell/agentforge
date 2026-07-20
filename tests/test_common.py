"""Contract tests for the shared ``common`` models (common.schema.json $defs)."""

import pytest

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping
from tests._contract_ids import COMMON

CANONICAL_SIX = {
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_role_exploitation",
}


def test_attack_category_is_exactly_the_canonical_six():
    assert {c.value for c in AttackCategory} == CANONICAL_SIX


def test_owasp_mapping_roundtrips_against_schema(validate):
    m = OwaspMapping(web="A01:2021-broken-access-control", llm="LLM01:2025-prompt-injection")
    validate(COMMON + "#/$defs/owaspMapping", m.model_dump(mode="json"))


def test_owasp_mapping_allows_nulls_but_emits_both_required_keys(validate):
    dumped = OwaspMapping(web=None, llm=None).model_dump(mode="json")
    assert set(dumped) == {"web", "llm"}  # schema requires both keys present
    validate(COMMON + "#/$defs/owaspMapping", dumped)


def test_owasp_mapping_forbids_extra_keys():
    with pytest.raises(Exception):
        OwaspMapping(web=None, llm=None, sneaky="x")  # type: ignore[call-arg]


def test_oracle_result_minimal_roundtrips(validate):
    o = OracleResult(oracle_id="phi_pattern", fired=None)
    validate(COMMON + "#/$defs/oracleResult", o.model_dump(mode="json"))


def test_oracle_result_with_evidence_roundtrips(validate):
    o = OracleResult(oracle_id="cross_patient", fired=True, evidence="foreign_pid_count=1")
    validate(COMMON + "#/$defs/oracleResult", o.model_dump(mode="json"))


def test_oracle_result_requires_fired_field():
    with pytest.raises(Exception):
        OracleResult(oracle_id="x")  # type: ignore[call-arg]  # 'fired' is required (nullable, present)
