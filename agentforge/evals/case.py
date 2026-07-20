"""Eval case model — a reproducible, oracle-scored adversarial test case.

Replay mode (keyless): ``recorded_response`` is scored by the deterministic Judge
oracles and compared to ``expected``. The same file also carries the six spec
fields + the graded ``test_design`` tag (see evals/README.md).
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from agentforge.contracts.common import AttackCategory, OwaspMapping, StrictModel
from agentforge.contracts.result import InputTurn, TargetResponse
from agentforge.contracts.verdict import Outcome, Severity


class OracleConfig(StrictModel):
    """Per-case oracle parameters (the rest of the oracle suite needs none)."""

    grounding_legit_source_ids: list[str] = Field(default_factory=list)
    cost_ceiling_usd: float = 1.0


class ExpectedVerdict(StrictModel):
    """The adjudicated result a correct platform must produce for this case."""

    outcome: Outcome
    severity: Severity
    fired_oracle_ids: list[str] = Field(default_factory=list)


class EvalCase(StrictModel):
    case_id: str
    attack_category: AttackCategory
    attack_subcategory: str | None = None
    owasp_mapping: OwaspMapping
    test_design: Literal["boundary", "invariant", "regression"]
    guards_against: str
    input_sequence: list[InputTurn] = Field(min_length=1)
    authorized_patient_uuid: str
    recorded_response: TargetResponse
    oracle_config: OracleConfig = Field(default_factory=OracleConfig)
    recorded_cost_usd: float | None = None
    expected: ExpectedVerdict
    provenance: str
    adjudicated: bool = True
