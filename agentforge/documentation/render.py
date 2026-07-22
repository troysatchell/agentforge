"""RPT1 / TRO-130 — deterministic vuln-report renderer.

Emits the six mandatory fields of ``docs/VULN_REPORT_TEMPLATE.md`` from an
adjudicated (AttackResult, Verdict) pair — the Documentation Agent's structured
skeleton, keyless and reproducible, for the submission's vuln reports. A report
is only rendered for a confirmed finding: a ``success`` verdict with a fired
predicate on a consistent (matching-``attack_id``) pair — the same data-quality
gate the agent enforces before writing.
"""

from __future__ import annotations

import json
import re

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Outcome, Verdict

_AF_ID_RE = re.compile(r"AF-\d{4}-\d{3}")


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
    """Render a confirmed exploit into the mandatory six-field vuln report.

    Deterministic and keyless: every field is derived from the adjudicated
    ``(result, verdict)`` pair plus the human-authored prose args, following
    ``docs/VULN_REPORT_TEMPLATE.md`` exactly.
    """
    if not _AF_ID_RE.fullmatch(af_id):
        raise ValueError(f"af_id must match AF-YYYY-NNN, got {af_id!r}")
    if verdict.outcome is not Outcome.SUCCESS:
        raise ValueError("a vuln report is only rendered for a confirmed (success) verdict")
    if str(verdict.attack_id) != str(result.attack_id):
        raise ValueError("verdict/result attack_id mismatch — refusing to render")
    if verdict.predicate_fired is None:
        raise ValueError("a confirmed finding must carry a success predicate")

    owasp = result.owasp_mapping
    target_version = result.target_version or verdict.target_version

    # Reproduction: a numbered list of each attack turn's route + payload
    # (deterministic key order so the report is stable across runs).
    steps = []
    for turn in result.input_sequence:
        payload = json.dumps(turn.payload, sort_keys=True, separators=(",", ":"))
        steps.append(f"{turn.turn_index + 1}. `{turn.route}` with `{payload}`")
    reproduction = "\n".join(steps)

    return (
        f"# {af_id} — {title}\n"
        "\n"
        f"- **Severity:** {verdict.severity.value}\n"
        f"- **Category:** {result.attack_category.value} · "
        f"**OWASP:** {owasp.web} / {owasp.llm}\n"
        f"- **Status:** {status} · **Discovered:** {discovered} · "
        f"**Target version:** {target_version}\n"
        f"- **Exploit id / sequence_hash:** {result.sequence_hash}\n"
        "\n"
        "## Description & clinical impact\n\n"
        f"{description}\n"
        "\n"
        "## Reproduction (minimal)\n\n"
        f"{reproduction}\n"
        "\n"
        "## Observed vs expected\n\n"
        f"- **Observed:** {verdict.predicate_fired}\n"
        f"- **Expected (safe):** {expected}\n"
        "\n"
        "## Recommended remediation (advisory)\n\n"
        f"{remediation}\n"
        "\n"
        "## Fix validation\n\n"
        f"- **Regression case:** `{regression_case}`\n"
        f"- **Result:** {fix_result}\n"
    )
