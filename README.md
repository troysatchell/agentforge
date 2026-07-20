# AgentForge — Adversarial Evaluation Platform

*A multi-agent red-team platform that continuously discovers, evaluates, escalates, and documents
vulnerabilities in the OpenEMR **Clinical Co-Pilot** — an AI feature the platform attacks as a live,
deployed HTTP target.*

> **Independent repo, by design.** AgentForge lives outside the OpenEMR fork. It never edits the
> target or imports its code at runtime; it attacks over the target's guarded HTTP surface only. The
> co-pilot is one *target instance* — the agents *discover* findings; specific vulnerabilities are
> seed/ground-truth, not wired-in constants.

## Status (this pass)

**Docs-first.** The non-code deliverables are being assembled before code. Platform language /
framework / per-role models (decisions **D1/D2/D3**) are not yet locked, so code scaffolding and the
D1-dependent sections of `ARCHITECTURE.md` (framework, cost-at-scale) are deferred.

| Deliverable | State |
|---|---|
| `THREAT_MODEL.md` | ✅ assembled (hard gate) |
| `USERS.md` | ✅ assembled |
| `contracts/` (v1 message schemas) | ✅ frozen + validated |
| `docs/DECISION_RECORD.md` (build-vs-configure) | ✅ (Architecture-Defense deliverable) |
| `docs/AGENT_INTERACTION.md` (evidence packet + diagram) | ✅ (feeds `ARCHITECTURE.md`) |
| `docs/VULN_REPORT_TEMPLATE.md` | ✅ (Documentation-Agent output format) |
| `docs/OBSERVABILITY.md` (the 6 questions → metrics) | ✅ |
| `evals/` (case template + schema) | ✅ template; ⏳ cases need the live runner |
| `ARCHITECTURE.md` | ⏳ pending D1/D2/D3 (material ready in `docs/`) |
| code (agents, target_client, harness, oracles) | ⏳ pending D1 |

## The target (Stage 1 — stand-up)

- **Deployed target URL:** `https://openemr-production-4eba.up.railway.app`
  (Railway: OpenEMR + MariaDB; **demo data only — no real PHI**). Submit this URL with every checkpoint.
- **Reaching the co-pilot:** log in → open a patient → chart left-menu **Co-Pilot** → a real SMART
  EHR-launch (OAuth2 + PKCE, confidential client) mints a **patient-scoped, launch-bound token**;
  the panel renders at
  `.../interface/modules/custom_modules/oe-module-copilot/public/panel.html`.
- **Surface:** REST routes under `/apis/default/api/copilot/*` (`turn`, `snapshot`, `document`,
  `source`, `ping/health/ready`) + the session AJAX path
  (`.../public/ajax.php`, `index.php`). See `THREAT_MODEL.md`.

### Changes made to bring the target into a testable state (Stage-1 record)

*The co-pilot required **no source changes** to serve as a target — it is attacked over HTTP as an
external client. The following operational setup makes it testable:*

- **Deployed** to Railway (OpenEMR + MariaDB volumes) with `ANTHROPIC_API_KEY` and `COHERE_API_KEY`
  set as service env vars (without them the co-pilot degrades honestly, so both must be present for
  a representative attack surface).
- **Demo data only** — seeded synthetic patients (e.g. Alma Reyes); no real PHI. This is what makes
  running an adversarial suite against a live deployment acceptable.
- **Auth:** clinical routes reject hand-minted tokens (TRO-52) and require a launch-bound token, so
  the platform's `target_client` must drive the SMART launch chain to obtain one (planned; the Week-2
  demo already scripts this in the target repo's `demo/copilot-demo.sh`).
- **State isolation (planned):** a **dedicated test patient + teardown** on the Railway deploy for
  the submission gate, and a **disposable local/worktree stack** for destructive / high-volume runs —
  because some attacks persist state (document attach; derived-observation writes have no dedup).

## Repo map

```
agentforge/
  README.md              # this file
  THREAT_MODEL.md        # HARD GATE — full attack-surface map (6 categories)
  USERS.md               # who the platform serves + why automation
  ARCHITECTURE.md        # pending D1/D2/D3 (material in docs/AGENT_INTERACTION.md + DECISION_RECORD.md)
  contracts/             # versioned inter-agent JSON Schemas (v1) + README
  evals/                 # adversarial test-case template + schema (cases pending the live runner)
  docs/
    DECISION_RECORD.md       # build-vs-configure (Garak/PyRIT/ZAP/Semgrep/...)
    AGENT_INTERACTION.md     # the four agents, diagram, trust boundaries, failure modes, AI-use
    VULN_REPORT_TEMPLATE.md  # Documentation-Agent report format (the 6 required fields)
    OBSERVABILITY.md         # the 6 observability questions → exact metrics
    REVIEW_FIXES_APPLIED.md  # ADR trail of the pre-v1 contract corrections
```

## Deliverables the platform must eventually produce (spec recap)

Threat model (this repo) · multi-agent `ARCHITECTURE.md` · `./evals/` (≥3 categories, live) ·
≥3 vuln reports · AI cost analysis (100/1K/10K/100K) · demo video · deployed target URL every checkpoint.
