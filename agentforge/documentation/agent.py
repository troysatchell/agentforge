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
from agentforge.contracts.verdict import Outcome, Severity, Verdict


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
        self._counter = 0
        self._documented: set[str] = set()

    def document(self, verdict: Verdict, result: AttackResult) -> DocumentationOutcome:
        """Turn a confirmed exploit into a filed / held / rejected vuln report.

        The data-quality and routing gates run BEFORE any model call so that
        non-documentable findings never spend a token.
        """
        # --- routing: only a confirmed exploit is documentable -------------
        if verdict.outcome is not Outcome.SUCCESS:
            return DocumentationOutcome(
                status="rejected",
                reason=f"outcome {verdict.outcome.value!r} is not a success; nothing to document",
            )

        # --- data-quality gate (no model call on failure) ------------------
        if verdict.attack_category is None:
            return DocumentationOutcome(
                status="rejected",
                reason="missing attack_category (must be one of the canonical six)",
            )
        if not verdict.target_version:
            return DocumentationOutcome(
                status="rejected",
                reason="missing target_version — a report must name the target_version it reproduces on",
            )
        if result.sequence_hash in self._documented:
            return DocumentationOutcome(
                status="rejected",
                reason=f"duplicate finding: sequence_hash {result.sequence_hash!r} already documented",
            )

        # --- draft prose via the injected Opus client (exactly once) -------
        system, user = self._prompts(verdict, result)
        body = self._client.complete(system=system, user=user)
        if not body or not body.strip():
            return DocumentationOutcome(
                status="rejected",
                reason="model returned an empty report body",
            )

        # --- assign a unique id + render the report ------------------------
        self._counter += 1
        report_id = f"AF-{self._clock().year}-{self._counter:03d}"
        report_markdown = self._render(
            report_id=report_id, verdict=verdict, result=result, body=body.strip()
        )
        self._documented.add(result.sequence_hash)

        # --- human gate: critical severity is held for human approval ------
        status = "held_for_human" if verdict.severity is Severity.CRITICAL else "filed"
        return DocumentationOutcome(
            status=status, report_id=report_id, report_markdown=report_markdown
        )

    # -- prompt + rendering helpers -----------------------------------------

    def _prompts(self, verdict: Verdict, result: AttackResult) -> tuple[str, str]:
        """Build the (system, user) prompt handing the finding to the model."""
        system = (
            "You are a senior application-security engineer writing a vulnerability "
            "report for a confirmed exploit against a clinical Co-Pilot. Write clear, "
            "professional prose covering what the vulnerability is, the clinical impact "
            "to a patient/physician, and a concrete advisory remediation. Do not invent "
            "facts beyond the finding you are given."
        )
        steps = "\n".join(
            f"  {turn.turn_index + 1}. {turn.route} -> {turn.payload}"
            for turn in result.input_sequence
        )
        user = (
            f"attack_category: {verdict.attack_category.value}\n"
            f"severity: {verdict.severity.value}\n"
            f"target_version: {verdict.target_version}\n"
            f"sequence_hash: {result.sequence_hash}\n"
            f"success predicate that fired: {verdict.predicate_fired}\n"
            f"observed target status: {result.target_response.http_status}\n"
            f"reproduction sequence:\n{steps}\n\n"
            "Draft the report body (description + clinical impact + remediation)."
        )
        return system, user

    def _render(
        self, *, report_id: str, verdict: Verdict, result: AttackResult, body: str
    ) -> str:
        """Render the six mandatory VULN_REPORT_TEMPLATE fields around the drafted body."""
        category = verdict.attack_category.value  # type: ignore[union-attr]
        severity = verdict.severity.value
        owasp = verdict.owasp_mapping
        web = (owasp.web if owasp else None) or "-"
        llm = (owasp.llm if owasp else None) or "-"
        discovered = self._clock().date().isoformat()
        steps = "\n".join(
            f"{turn.turn_index + 1}. `{turn.route}` with `{turn.payload}`"
            for turn in result.input_sequence
        )
        return (
            f"# {report_id} — {category} confirmed against {verdict.target_version}\n\n"
            f"- **Severity:** {severity}\n"
            f"- **Category:** {category} · **OWASP:** {web} / {llm}\n"
            f"- **Status:** open · **Discovered:** {discovered} · "
            f"**Target version:** {verdict.target_version}\n"
            f"- **Exploit id / sequence_hash:** {result.sequence_hash}\n\n"
            f"## Description & clinical impact\n{body}\n\n"
            f"## Reproduction (minimal)\n"
            f"Auth: launch-bound session. Target: the live Clinical Co-Pilot @ "
            f"{verdict.target_version}.\n{steps}\n\n"
            f"## Observed vs expected\n"
            f"- **Observed:** {verdict.predicate_fired}\n"
            f"- **Expected (safe):** a non-vulnerable target refuses the sequence and "
            f"discloses nothing.\n\n"
            f"## Recommended remediation (advisory)\n"
            f"See the drafted guidance above; advisory only — the platform never patches "
            f"the target.\n\n"
            f"## Fix validation\n"
            f"- **Status:** open (not-yet-fixed).\n"
            f"- **Result:** not-yet-fixed — the `{verdict.predicate_fired}` predicate fires "
            f"on target_version {verdict.target_version}.\n"
        )
