"""``AttackDirective`` — mirrors ``orchestrator_to_redteam.schema.json``.

Edge (1): Orchestrator instructs the Red Team what to target next, based on
coverage state. ``authorized_scope`` is the GROUND TRUTH the Judge later
adjudicates against — set by the Orchestrator from campaign config, NEVER
attacker-chosen; the Judge resolves it by ``correlation_id`` from the campaign
store rather than trusting anything the Red Team echoes back.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_serializer

from agentforge.contracts.common import AttackCategory, OwaspMapping, StrictModel

# Optional, NON-nullable schema fields: when unset (None) the key must be ABSENT
# from the JSON dump, never emitted as null (the schema types don't permit null).
# Nullable fields (mutation_axis, parent_attack_id, last_regression_at, the
# AuthorizedScope urls) are left as-is and keep an explicit null.
_DIRECTIVE_ABSENT_WHEN_NONE = ("attack_subcategory", "coverage_context")
_COVERAGE_ABSENT_WHEN_NONE = ("open_findings_in_category", "cases_tested_in_category")


class AuthorizedScope(StrictModel):
    """What this campaign is AUTHORIZED to reach. Only ``authorized_patient_uuid``
    is required; the other two are nullable and optional."""

    authorized_patient_uuid: str
    target_base_url: str | None = None
    ground_truth_snapshot_ref: str | None = None


class Budget(StrictModel):
    """Spend/attempt ceilings for the campaign this directive authorizes."""

    max_usd: float = Field(ge=0)
    max_attempts: int = Field(ge=1)
    max_turns_per_sequence: int = Field(default=5, ge=1)


class CoverageContext(StrictModel):
    """Why the Orchestrator chose this target — the signal it read. All
    fields optional (non-nullable ints; nullable datetime)."""

    open_findings_in_category: int | None = Field(default=None, ge=0)
    cases_tested_in_category: int | None = Field(default=None, ge=0)
    last_regression_at: datetime | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        for key in _COVERAGE_ABSENT_WHEN_NONE:
            if data.get(key) is None:
                data.pop(key, None)
        return data


class AttackDirective(StrictModel):
    """Edge (1) — Orchestrator -> Red Team: what to attack next."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    directive_id: uuid.UUID
    correlation_id: str
    attack_category: AttackCategory
    attack_subcategory: str | None = None
    owasp_mapping: OwaspMapping
    authorized_scope: AuthorizedScope
    mutation_axis: str | None = None
    seed_refs: list[str] = Field(default_factory=list)
    parent_attack_id: str | None = None
    coverage_context: CoverageContext | None = None
    budget: Budget
    issued_at: datetime

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        for key in _DIRECTIVE_ABSENT_WHEN_NONE:
            if data.get(key) is None:
                data.pop(key, None)
        return data
