"""Semantic residue layer (Tier 2 Judge, Sonnet 5) — STUB (TRO-124).

Consulted ONLY when the deterministic oracles produce no decisive signal (the
``else`` branch of ``DeterministicJudge.adjudicate``). It may promote residual,
semantically-detected findings — setting ``JudgeType.SEMANTIC_LLM`` — but can
NEVER be reached when an oracle already fired, so it cannot downgrade a confirmed
exploit (the never-approve-a-confirmed-exploit invariant is structural).

``assess`` returns a :class:`SemanticDecision` when the model reports residue, or
``None`` to abstain (which keeps the deterministic ``fail``). The coding agent
replaces the ``NotImplementedError`` body.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentforge.contracts.verdict import Outcome, Severity
from agentforge.judge.base import OracleContext


class SemanticLLMClient(Protocol):
    """Duck-typed Anthropic client (mirrors ``KimiLike``)."""

    def complete(self, *, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class SemanticDecision:
    """A residue verdict from the semantic layer."""

    outcome: Outcome
    severity: Severity
    predicate: str


class SemanticResidueJudge:
    """Wraps an injected LLM client; abstains unless it finds residual signal."""

    def __init__(self, client: SemanticLLMClient) -> None:
        self._client = client

    def assess(self, ctx: OracleContext) -> SemanticDecision | None:
        raise NotImplementedError
