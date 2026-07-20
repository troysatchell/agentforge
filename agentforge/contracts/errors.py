"""``AgentError`` contract — mirrors ``errors.schema.json``.

One discriminated union on ``error_type``; every error carries
``correlation_id`` and the raising agent for end-to-end traceability. Each
``error_type`` gets its own closed ``StrictModel`` for ``detail`` (mirroring
the schema's ``allOf`` branches) and its own envelope variant tagged with a
``Literal`` ``error_type``. ``AgentError`` wraps the resulting Pydantic v2
discriminated union (``Field(discriminator="error_type")``), so
``AgentError.model_validate(...)`` dispatches on ``error_type`` and rejects a
``detail`` payload that does not match its branch — it is validated only
against that branch's closed model, never against the others.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import Field, RootModel

from agentforge.contracts.common import AttackCategory, StrictModel


class RaisedBy(str, Enum):
    """Which agent raised the error."""

    ORCHESTRATOR = "orchestrator"
    RED_TEAM = "red_team"
    JUDGE = "judge"
    DOCUMENTATION = "documentation"
    HARNESS = "harness"


# --- detail models: one closed StrictModel per error_type (allOf branches) -


class TargetUnreachableAction(str, Enum):
    RETRY_BACKOFF = "retry_backoff"
    HALT_CAMPAIGN = "halt_campaign"


class TargetUnreachableDetail(StrictModel):
    route: str
    attempts: int = Field(ge=1)
    last_http_status: int | None
    action: TargetUnreachableAction


class BudgetExceededDetail(StrictModel):
    spent_usd: float = Field(ge=0)
    ceiling_usd: float = Field(ge=0)
    signal_produced: bool
    action: Literal["halt_campaign"]


class JudgeTimeoutAction(str, Enum):
    REQUEUE_ONCE = "requeue_once"
    ESCALATE_HUMAN = "escalate_human"


class JudgeTimeoutDetail(StrictModel):
    attack_id: uuid.UUID
    timeout_ms: int = Field(ge=0)
    action: JudgeTimeoutAction


class NoFindingsDetail(StrictModel):
    category: AttackCategory
    attempts_in_window: int = Field(ge=0)
    action: Literal["redirect_next_gap"]


class RegressionDetectedDetail(StrictModel):
    exploit_id: str
    reappeared_in_version: str
    cross_category: str | None = None
    action: Literal["trigger_full_regression"]


# --- envelope variants: one per error_type, tagged for the discriminator ---


class TargetUnreachableError(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_type: Literal["target_unreachable"] = "target_unreachable"
    correlation_id: str
    raised_by: RaisedBy
    raised_at: datetime
    detail: TargetUnreachableDetail


class BudgetExceededError(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_type: Literal["budget_exceeded"] = "budget_exceeded"
    correlation_id: str
    raised_by: RaisedBy
    raised_at: datetime
    detail: BudgetExceededDetail


class JudgeTimeoutError(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_type: Literal["judge_timeout"] = "judge_timeout"
    correlation_id: str
    raised_by: RaisedBy
    raised_at: datetime
    detail: JudgeTimeoutDetail


class NoFindingsError(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_type: Literal["no_findings"] = "no_findings"
    correlation_id: str
    raised_by: RaisedBy
    raised_at: datetime
    detail: NoFindingsDetail


class RegressionDetectedError(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_type: Literal["regression_detected"] = "regression_detected"
    correlation_id: str
    raised_by: RaisedBy
    raised_at: datetime
    detail: RegressionDetectedDetail


_AgentErrorUnion = Annotated[
    Union[
        TargetUnreachableError,
        BudgetExceededError,
        JudgeTimeoutError,
        NoFindingsError,
        RegressionDetectedError,
    ],
    Field(discriminator="error_type"),
]


class AgentError(RootModel[_AgentErrorUnion]):
    """Top-level typed error envelope (mirrors ``errors.schema.json``).

    Construct via ``AgentError.model_validate({...flat envelope dict...})``;
    Pydantic dispatches on ``error_type`` to the matching closed variant, so a
    ``detail`` shaped for a different ``error_type`` is rejected. Dump with
    ``model_dump(mode="json")`` to get back the flat, schema-shaped dict.
    """
