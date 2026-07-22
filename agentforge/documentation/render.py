"""RPT1 / TRO-130 — deterministic vuln-report renderer (STUB for the RED phase;
replaced by the RPT1 coding agent).

Emits the six mandatory fields of ``docs/VULN_REPORT_TEMPLATE.md`` from an
adjudicated (AttackResult, Verdict) pair — the Documentation Agent's structured
skeleton, keyless and reproducible, for the submission's vuln reports.
"""

from __future__ import annotations

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict


def render_vuln_report(
    result: AttackResult,
    verdict: Verdict,
    *,
    af_id: str,
    title: str,
    description: str,
    expected: str,
    remediation: str,
    regression_case: str,
    discovered: str,
    status: str = "open",
    fix_result: str = "not-yet-fixed (predicate fires on current target_version)",
) -> str:
    raise NotImplementedError("RPT1: render_vuln_report not implemented yet")
