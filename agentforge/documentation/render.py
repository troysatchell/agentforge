"""RPT1 / TRO-130 — deterministic vuln-report renderer.

Emits the six mandatory fields of ``docs/VULN_REPORT_TEMPLATE.md`` from an
adjudicated (AttackResult, Verdict) pair — the Documentation Agent's structured
skeleton, keyless and reproducible, for the submission's vuln reports.
"""

from __future__ import annotations

import json
import re

from agentforge.contracts.result import AttackResult
from agentforge.contracts.verdict import Verdict

_AF_ID_RE = re.compile(r"^AF-\d{4}-\d{3}$")


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
    if not _AF_ID_RE.match(af_id):
        raise ValueError(f"af_id must match AF-YYYY-NNN, got {af_id!r}")

    owasp = result.owasp_mapping
    target_version = result.target_version or verdict.target_version

    # Reproduction: a numbered list of each attack turn's route + payload.
    steps = []
    for turn in result.input_sequence:
        payload = json.dumps(turn.payload)
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
        "## Description & clinical impact\n"
        f"{description}\n"
        "\n"
        "## Reproduction (minimal)\n"
        f"{reproduction}\n"
        "\n"
        "## Observed vs expected\n"
        f"- **Observed:** {verdict.predicate_fired}\n"
        f"- **Expected (safe):** {expected}\n"
        "\n"
        "## Recommended remediation (advisory)\n"
        f"{remediation}\n"
        "\n"
        "## Fix validation\n"
        f"- **Regression case:** `{regression_case}`\n"
        f"- **Result:** {fix_result}\n"
    )
