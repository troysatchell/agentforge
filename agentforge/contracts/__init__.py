"""Pydantic models mirroring the versioned JSON Schemas in ``contracts/v1``.

Each contract lives in its own submodule; the public API is re-exported here so
consumers can ``from agentforge.contracts import AttackDirective, Verdict, ...``.
``StrictModel`` (``extra='forbid'``) is the Python analogue of
``additionalProperties: false`` and the base of every contract model.
"""

from .common import AttackCategory, OracleResult, OwaspMapping, StrictModel
from .directive import AttackDirective, AuthorizedScope, Budget, CoverageContext
from .errors import AgentError, RaisedBy
from .result import AttackResult, ExecutionTelemetry, InputTurn, TargetResponse
from .verdict import JudgeType, Outcome, Severity, Verdict

__all__ = [
    # shared
    "StrictModel",
    "AttackCategory",
    "OwaspMapping",
    "OracleResult",
    # edge ① Orchestrator -> Red Team
    "AttackDirective",
    "AuthorizedScope",
    "Budget",
    "CoverageContext",
    # edge ③ Red Team -> Judge
    "AttackResult",
    "InputTurn",
    "TargetResponse",
    "ExecutionTelemetry",
    # edge ⑤ Judge -> Documentation
    "Verdict",
    "Outcome",
    "Severity",
    "JudgeType",
    # typed error envelope
    "AgentError",
    "RaisedBy",
]
