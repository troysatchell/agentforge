"""Contract tests for AttackDirective (orchestrator_to_redteam.schema.json)."""

import uuid
from datetime import datetime, timezone

import pytest

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import (
    AttackDirective,
    AuthorizedScope,
    Budget,
    CoverageContext,
)
from tests._contract_ids import DIRECTIVE


def _minimal_kwargs():
    return dict(
        directive_id=uuid.uuid4(),
        correlation_id="corr-123",
        attack_category=AttackCategory.PROMPT_INJECTION,
        owasp_mapping=OwaspMapping(web=None, llm="LLM01:2025-prompt-injection"),
        authorized_scope=AuthorizedScope(authorized_patient_uuid="patient-abc-123"),
        budget=Budget(max_usd=5.0, max_attempts=10),
        issued_at=datetime.now(timezone.utc),
    )


def test_attack_directive_minimal_roundtrips_against_schema(validate):
    # attack_subcategory / coverage_context are optional AND non-nullable in
    # the schema — unset, they must be ABSENT, not null, so exclude them by
    # name (NOT a blanket exclude_none=True: that would recurse into
    # owasp_mapping and strip its required-but-nullable 'web' key too).
    directive = AttackDirective(**_minimal_kwargs())
    dumped = directive.model_dump(mode="json", exclude={"attack_subcategory", "coverage_context"})
    validate(DIRECTIVE, dumped)


def test_attack_directive_omits_optional_nonnullable_fields_when_unset(validate):
    # Regression: unset attack_subcategory / coverage_context must be ABSENT from a
    # PLAIN dump (not null), so any consumer (e.g. the Orchestrator) can validate
    # without knowing to exclude them. The model_serializer handles this now.
    directive = AttackDirective(**_minimal_kwargs())
    dumped = directive.model_dump(mode="json")
    assert "attack_subcategory" not in dumped
    assert "coverage_context" not in dumped
    validate(DIRECTIVE, dumped)


def test_attack_directive_full_roundtrips_against_schema(validate):
    kwargs = _minimal_kwargs()
    kwargs.update(
        attack_subcategory="indirect-injection-feedback-loop",
        mutation_axis="delimiter-evasion",
        seed_refs=["seed-001", "exploit-db-42"],
        parent_attack_id=str(uuid.uuid4()),
        coverage_context=CoverageContext(
            open_findings_in_category=2,
            cases_tested_in_category=14,
            last_regression_at=datetime.now(timezone.utc),
        ),
        authorized_scope=AuthorizedScope(
            authorized_patient_uuid="patient-abc-123",
            target_base_url="https://target.example.com",
            ground_truth_snapshot_ref="snapshot-2026-07-20",
        ),
    )
    directive = AttackDirective(**kwargs)
    validate(DIRECTIVE, directive.model_dump(mode="json"))


def test_attack_directive_allows_null_mutation_axis_and_parent_attack_id(validate):
    # mutation_axis / parent_attack_id are nullable — confirm an EXPLICIT null
    # (not just absence) round-trips, distinct from the exclude_none case above.
    kwargs = _minimal_kwargs()
    kwargs.update(
        attack_subcategory="jailbreak-roleplay",
        mutation_axis=None,
        parent_attack_id=None,
        seed_refs=["seed-1"],
        coverage_context=CoverageContext(
            open_findings_in_category=0,
            cases_tested_in_category=0,
            last_regression_at=None,
        ),
    )
    directive = AttackDirective(**kwargs)
    dumped = directive.model_dump(mode="json")
    assert dumped["mutation_axis"] is None
    assert dumped["parent_attack_id"] is None
    validate(DIRECTIVE, dumped)


def test_attack_directive_defaults_schema_version():
    directive = AttackDirective(**_minimal_kwargs())
    assert directive.schema_version == "1.0.0"


def test_attack_directive_defaults_seed_refs_to_empty_list():
    directive = AttackDirective(**_minimal_kwargs())
    assert directive.seed_refs == []


def test_attack_directive_forbids_extra_top_level_keys():
    with pytest.raises(Exception):
        AttackDirective(**_minimal_kwargs(), sneaky="x")  # type: ignore[call-arg]


def test_attack_directive_requires_issued_at():
    kwargs = _minimal_kwargs()
    del kwargs["issued_at"]
    with pytest.raises(Exception):
        AttackDirective(**kwargs)


def test_authorized_scope_roundtrips_with_nulls_against_schema(validate):
    scope = AuthorizedScope(authorized_patient_uuid="patient-xyz")
    dumped = scope.model_dump(mode="json")
    assert set(dumped) == {"authorized_patient_uuid", "target_base_url", "ground_truth_snapshot_ref"}
    validate(DIRECTIVE + "#/properties/authorized_scope", dumped)


def test_authorized_scope_requires_authorized_patient_uuid():
    with pytest.raises(Exception):
        AuthorizedScope()  # type: ignore[call-arg]


def test_authorized_scope_forbids_extra_keys():
    with pytest.raises(Exception):
        AuthorizedScope(authorized_patient_uuid="p1", sneaky="x")  # type: ignore[call-arg]


def test_budget_defaults_max_turns_per_sequence(validate):
    budget = Budget(max_usd=1.5, max_attempts=3)
    assert budget.max_turns_per_sequence == 5
    validate(DIRECTIVE + "#/properties/budget", budget.model_dump(mode="json"))


def test_budget_rejects_negative_max_usd():
    with pytest.raises(Exception):
        Budget(max_usd=-1, max_attempts=1)


def test_budget_rejects_zero_max_attempts():
    with pytest.raises(Exception):
        Budget(max_usd=1, max_attempts=0)


def test_budget_forbids_extra_keys():
    with pytest.raises(Exception):
        Budget(max_usd=1, max_attempts=1, sneaky="x")  # type: ignore[call-arg]


def test_coverage_context_all_optional_roundtrips_empty(validate):
    ctx = CoverageContext()
    validate(DIRECTIVE + "#/properties/coverage_context", ctx.model_dump(mode="json", exclude_none=True))


def test_coverage_context_forbids_extra_keys():
    with pytest.raises(Exception):
        CoverageContext(sneaky="x")  # type: ignore[call-arg]
