"""Verdict — mirrors ``judge_to_documentation.schema.json``.

Edge (5) — the Judge's adjudicated verdict. ROUTING (review fix #10): only
``outcome=success`` flows to the Documentation Agent; ALL outcomes persist to
the exploit DB; ``outcome=partial`` also routes to the Orchestrator as a
mutation candidate. ``predicate_fired`` is what makes a regression test assert
SIGNAL, not a generic pass.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import model_serializer

from agentforge.contracts.common import AttackCategory, OracleResult, OwaspMapping, StrictModel

# Fields that are OPTIONAL (not in the schema's "required" list) and are NOT
# themselves nullable in the schema (or whose absence is schema-legal). When
# unset (``None``), these must be OMITTED from the dump entirely, never
# emitted as ``null`` — the schema types don't allow it. This is distinct from
# ``predicate_fired``, which is required *and* nullable: that key must always
# be present, even when its value is null.
_OPTIONAL_FIELDS_OMITTED_WHEN_NONE = frozenset(
    {
        "oracle_results",
        "ground_truth_ref",
        "attack_category",
        "owasp_mapping",
        "cross_category_regression",
        "reproduction_ref",
        "target_version",
    }
)


class Outcome(str, Enum):
    """success = exploit confirmed. Only ``success`` is sent to Documentation;
    ``partial`` routes to the Orchestrator as a mutation candidate; all three
    persist to the exploit DB. Documentation never files a ``partial`` or a
    ``fail``."""

    SUCCESS = "success"
    FAIL = "fail"
    PARTIAL = "partial"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


class JudgeType(str, Enum):
    """Which judge decided. MVP = deterministic_oracle only; semantic_llm is
    governed by labeled ground-truth + the never-approve-a-confirmed-exploit
    invariant."""

    DETERMINISTIC_ORACLE = "deterministic_oracle"
    SEMANTIC_LLM = "semantic_llm"


class Verdict(StrictModel):
    """The Judge's adjudicated verdict on one attack attempt."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    verdict_id: uuid.UUID
    attack_id: uuid.UUID
    """The AttackResult this adjudicates."""
    correlation_id: str
    outcome: Outcome
    predicate_fired: str | None
    """The exact deterministic predicate that decided success, in one
    sentence. Null unless outcome=success."""
    judge_type: JudgeType = JudgeType.DETERMINISTIC_ORACLE
    oracle_results: list[OracleResult] | None = None
    """Which oracles the JUDGE ran (recomputed independently of the Red
    Team's advisory hints) and their outcomes."""
    ground_truth_ref: str | None = None
    severity: Severity
    attack_category: AttackCategory | None = None
    owasp_mapping: OwaspMapping | None = None
    regression_flag: bool
    """True = a previously-fixed exploit reappeared. Blocks any 'resilience
    improving' claim."""
    cross_category_regression: str | None = None
    reproduction_ref: str | None = None
    target_version: str | None = None
    adjudicated_at: datetime

    @model_serializer(mode="wrap")
    def _omit_unset_optional_fields(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        for name in _OPTIONAL_FIELDS_OMITTED_WHEN_NONE:
            if data.get(name) is None:
                data.pop(name, None)
        return data
