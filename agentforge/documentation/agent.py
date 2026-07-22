"""DocumentationAgent — STUB (TRO-126).

Consumes a ``success`` :class:`Verdict` + its :class:`AttackResult` and renders a
vuln report matching ``docs/VULN_REPORT_TEMPLATE.md`` (six mandatory fields),
via an injected Opus client. Enforces the data-quality gate before writing and
human-gates critical severity.

The coding agent replaces the ``NotImplementedError`` bodies. It may modify only
the files in this ticket's scope; the frozen tests are the contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal, Protocol

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict


class DocLLMClient(Protocol):
    """Duck-typed model client the agent depends on (mirrors ``KimiLike``)."""

    def complete(self, *, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class DocumentationOutcome:
    """Result of a documentation attempt.

    ``status``:
      - ``filed``          — report auto-filed (low/medium/high severity).
      - ``held_for_human`` — report drafted, awaiting human approval (critical).
      - ``rejected``       — a data-quality / routing gate refused to write.
    """

    status: Literal["filed", "held_for_human", "rejected"]
    report_id: str | None = None
    report_markdown: str | None = None
    reason: str | None = None


class DocumentationAgent:
    """Turns a confirmed exploit into a professional vuln report (no human writer)."""

    def __init__(
        self,
        client: DocLLMClient,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._client = client
        self._clock = clock

    def document(self, verdict: Verdict, result: AttackResult) -> DocumentationOutcome:
        raise NotImplementedError
