"""The deterministic Orchestrator (E5).

No LLM. Never touches the target. Reads coverage/regression signal from an
:class:`ExploitStore` and emits the next :class:`AttackDirective`, the
cost-without-signal halt guardrail, and regression-detected errors. Pure
coverage-gap arithmetic + contract construction — everything else (choosing
*how* to attack) is the Red Team's job downstream of the directive this
class hands it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from agentforge.contracts.common import AttackCategory, OwaspMapping
from agentforge.contracts.directive import (
    AttackDirective,
    AuthorizedScope,
    Budget,
    CoverageContext,
)
from agentforge.contracts.errors import AgentError
from agentforge.store import ExploitStore

# One default OWASP dual-mapping per attack category. Deliberately small and
# static — the Red Team may refine/override per-attempt, but the Orchestrator
# needs *some* valid mapping to construct a directive.
_DEFAULT_OWASP_MAPPING: dict[AttackCategory, OwaspMapping] = {
    AttackCategory.PROMPT_INJECTION: OwaspMapping(web=None, llm="LLM01:2025-prompt-injection"),
    AttackCategory.DATA_EXFILTRATION: OwaspMapping(
        web="A01:2021-broken-access-control",
        llm="LLM02:2025-sensitive-information-disclosure",
    ),
    AttackCategory.STATE_CORRUPTION: OwaspMapping(
        web="A08:2021-software-and-data-integrity-failures",
        llm=None,
    ),
    AttackCategory.TOOL_MISUSE: OwaspMapping(web=None, llm="LLM06:2025-excessive-agency"),
    AttackCategory.DENIAL_OF_SERVICE: OwaspMapping(web=None, llm="LLM10:2025-unbounded-consumption"),
    AttackCategory.IDENTITY_ROLE_EXPLOITATION: OwaspMapping(
        web="A01:2021-broken-access-control",
        llm=None,
    ),
}


class Orchestrator:
    """Deterministic campaign coordinator. No LLM, never touches the target."""

    def __init__(
        self,
        store: ExploitStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        id_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self._store = store
        self._clock = clock
        self._id_factory = id_factory

    def next_directive(
        self,
        *,
        correlation_id: str,
        authorized_patient_uuid: str,
        target_base_url: str | None,
        max_usd: float,
        max_attempts: int,
    ) -> AttackDirective:
        """Pick the least-covered attack category and build a valid directive.

        Considers ALL SIX ``AttackCategory`` members — a category absent from
        the store counts as zero cases tested. Ties break deterministically
        by ``AttackCategory`` declaration order (first-defined wins), which
        falls out of ``min()``'s left-to-right, first-occurrence-wins
        semantics over ``AttackCategory`` iterated in declaration order.
        """
        cases_by_category = self._store.cases_tested_by_category()
        open_findings_by_category = self._store.open_findings_by_category()

        chosen = min(AttackCategory, key=lambda category: cases_by_category.get(category, 0))

        return AttackDirective(
            directive_id=self._id_factory(),
            correlation_id=correlation_id,
            attack_category=chosen,
            owasp_mapping=_DEFAULT_OWASP_MAPPING[chosen],
            authorized_scope=AuthorizedScope(
                authorized_patient_uuid=authorized_patient_uuid,
                target_base_url=target_base_url,
            ),
            budget=Budget(max_usd=max_usd, max_attempts=max_attempts),
            coverage_context=CoverageContext(
                open_findings_in_category=open_findings_by_category.get(chosen, 0),
                cases_tested_in_category=cases_by_category.get(chosen, 0),
            ),
            issued_at=self._clock(),
        )

    def should_halt(
        self,
        *,
        spent_usd: float,
        ceiling_usd: float,
        signal_produced: bool,
        correlation_id: str,
    ) -> AgentError | None:
        """Halt guardrail: cost has accrued past ceiling with no signal produced."""
        if spent_usd < ceiling_usd or signal_produced:
            return None

        return AgentError.model_validate(
            {
                "schema_version": "1.0.0",
                "error_type": "budget_exceeded",
                "correlation_id": correlation_id,
                "raised_by": "orchestrator",
                "raised_at": self._clock(),
                "detail": {
                    "spent_usd": spent_usd,
                    "ceiling_usd": ceiling_usd,
                    "signal_produced": False,
                    "action": "halt_campaign",
                },
            }
        )

    def regression_signals(self, *, correlation_id: str) -> list[AgentError]:
        """One ``regression_detected`` error per flagged record in the store."""
        return [
            AgentError.model_validate(
                {
                    "schema_version": "1.0.0",
                    "error_type": "regression_detected",
                    "correlation_id": correlation_id,
                    "raised_by": "orchestrator",
                    "raised_at": self._clock(),
                    "detail": {
                        "exploit_id": rec.exploit_id,
                        "reappeared_in_version": rec.target_version or "unknown",
                        "cross_category": rec.cross_category,
                        "action": "trigger_full_regression",
                    },
                }
            )
            for rec in self._store.regressions()
        ]

    def on_target_version(
        self, *, current_version: str, correlation_id: str
    ) -> list[AgentError]:
        """Kick a full regression pass when the target reports a new version.

        A ``current_version`` the store has never recorded — while the store is
        non-empty — means the black-box target was upgraded underneath us. Every
        stored exploit must be re-verified against the new build, so emit one
        ``regression_detected`` error per stored record. A version already seen
        in the store (stable) or an empty store yields no trigger, so a steady
        campaign never produces false regression signals.
        """
        records = self._store.all()
        known_versions = {rec.target_version for rec in records}
        if not records or current_version in known_versions:
            return []

        return [
            AgentError.model_validate(
                {
                    "schema_version": "1.0.0",
                    "error_type": "regression_detected",
                    "correlation_id": correlation_id,
                    "raised_by": "orchestrator",
                    "raised_at": self._clock(),
                    "detail": {
                        "exploit_id": rec.exploit_id,
                        "reappeared_in_version": current_version,
                        "cross_category": rec.cross_category,
                        "action": "trigger_full_regression",
                    },
                }
            )
            for rec in records
        ]
