# USERS — Who AgentForge serves, and why automation is the right solution

> Scope note: these are the users of **the adversarial platform**, not the physicians who use the
> Clinical Co-Pilot (those are the *target's* users). The platform's job is to earn a security
> team's trust in continuously stress-testing an AI feature clinicians depend on.

## Personas

### 1. Application-security / product-security engineer (primary)
Owns the *continuous* security posture of the co-pilot's AI features — not a one-off pentest.
- **Goals:** find real, reproducible vulnerabilities before attackers do; know which attack surfaces
  are covered vs untested; prove a fix actually fixed the vuln and didn't regress another category.
- **Pains today:** attack techniques mutate faster than a human writes payloads; findings are hard to
  reproduce; a fix validated once is never re-run; there is no coverage/trend visibility.
- **What they do with AgentForge:** launch and read campaigns; triage new findings each morning;
  trigger a regression run after a fix ships; consume vuln reports and coverage dashboards.

### 2. CISO / security lead (approver)
The "defend it to a hospital CISO" standard. Reads trend reports; signs off on ship/no-ship.
- **Goals:** a defensible answer to "is this AI feature getting more or less resilient over time?";
  assurance that the platform itself won't cause harm (won't attack the wrong system, won't file noise).
- **What they do with AgentForge:** review the ATO-style evidence packet; approve critical-severity
  findings before publish; audit what each agent did during an autonomous run.

### 3. Product / co-pilot engineer (consumer of findings)
Receives a vuln report and must reproduce + fix it **without having been present** when it was found.
- **Goals:** a minimal reproduction, observed-vs-expected behavior, and a remediation direction they
  can act on.
- **What they do with AgentForge:** open a report from `docs/VULN_REPORT_TEMPLATE.md`, reproduce it,
  fix the target, redeploy, and let the regression harness confirm the fix held.

## Core workflows

1. **Overnight campaign → morning triage.** The platform runs autonomously; the engineer reviews new
   findings, dispositioning each (validate / remediate / defer / document — see the triage exercise).
2. **"We shipped a fix — did it hold, and did it break anything?"** The Orchestrator triggers a
   regression run on a new `target_version`; the Judge re-adjudicates stored exploits; the harness
   flags reappearance or a cross-category regression.
3. **"What's under-tested?"** A coverage view (cases per category, pass/fail over versions) tells the
   engineer — and the Orchestrator — where to point the Red Team next.
4. **"Is the system improving?"** A resilience trend over `target_version` answers the CISO's question.

## Why automation is the right solution (the justification the spec asks for)

- **Attacks mutate; static lists rot.** Determining whether a *category* of exploit is addressed —
  not just one payload — requires generating and mutating variants continuously. That is generative,
  high-volume work a human cannot sustain; it is exactly what an autonomous Red Team is for.
- **Reproduction and regression are bookkeeping at scale.** Converting a confirmed exploit into a
  deterministic, versioned, re-runnable case — and re-running the whole suite on every deploy — is
  tedious, error-prone, and never-skipped-safely. Automation does it identically every time.
- **Coverage and trend visibility need a data substrate, not a memory.** "Which surfaces are tested,
  which are regressing" is only answerable if every run is logged, costed, and queryable — the
  observability layer the Orchestrator also reads.
- **But judgment stays human where it's irreversible.** Automation proposes; a human disposes on the
  calls that matter: **critical-severity publication**, **remediation approval** (the platform never
  pushes a fix), and **ship/no-ship**. Findings that implicate an auth danger-zone are reports, not
  fixes. This division — automate the discovery/reproduction/regression treadmill, gate the
  irreversible decisions — is the design, and it is what makes a CISO able to trust the platform with
  continuous testing of a system physicians depend on.
