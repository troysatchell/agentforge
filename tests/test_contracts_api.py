"""Integration: the public contract API is importable straight from
``agentforge.contracts`` (not only from the individual submodules)."""

import pydantic

from agentforge.contracts import (
    AgentError,
    AttackCategory,
    AttackDirective,
    AttackResult,
    AuthorizedScope,
    Budget,
    CoverageContext,
    ExecutionTelemetry,
    InputTurn,
    JudgeType,
    OracleResult,
    Outcome,
    OwaspMapping,
    RaisedBy,
    Severity,
    StrictModel,
    TargetResponse,
    Verdict,
)


def test_message_models_are_pydantic_models():
    for model in (AttackDirective, AttackResult, Verdict, AgentError, OwaspMapping, OracleResult):
        assert issubclass(model, pydantic.BaseModel)


def test_attack_category_reexport_is_the_canonical_six():
    assert len(list(AttackCategory)) == 6


def test_enums_are_reexported():
    assert Outcome and Severity and JudgeType and RaisedBy


def test_nested_models_are_reexported():
    for model in (AuthorizedScope, Budget, CoverageContext, InputTurn, TargetResponse, ExecutionTelemetry, StrictModel):
        assert issubclass(model, pydantic.BaseModel)


def test_all_lists_the_public_api():
    import agentforge.contracts as c

    assert {"AttackDirective", "AttackResult", "Verdict", "AgentError"} <= set(c.__all__)
