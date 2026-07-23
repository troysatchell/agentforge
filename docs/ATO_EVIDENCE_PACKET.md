# ATO-style Evidence Packet — AgentForge

*An Authority-to-Operate–style dossier for **AgentForge, the attacker platform**
(not the target). It assembles the accreditation boundary, architecture,
data-flow, auth model, dependency inventory, a control self-scan, evaluation
evidence, and a worked postmortem into one reviewable artifact. Cross-references:
`ARCHITECTURE.md`, `THREAT_MODEL.md`, `AGENT_INTERACTION.md`, `OBSERVABILITY.md`,
`TRIAGE.md`, `AI_COST_ANALYSIS.md`.*

Evidence current as of branch `docs/e10-deliverables`; test suite **302 tests /
41 modules green**.

---

## 1. Accreditation boundary

**System:** AgentForge — a four-agent platform that continuously discovers,
adjudicates, escalates, and documents vulnerabilities in the OpenEMR Clinical
Co-Pilot, treated as a **live, mostly-black-box HTTP target**.

**In boundary:** the Orchestrator, Red Team, Judge, and Documentation agents; the
typed `contracts/v1` message edges; the exploit store + regression harness; the
eval suite; the observability layer.

**Out of boundary (explicit):** the target (OpenEMR / `oe-module-copilot`). The
platform holds **zero target source** — attested: `git ls-files | grep -i
openemr` returns nothing. The target requires no source change to be a target;
AgentForge reaches it only over its guarded HTTP surface.

**Operating premise:** authorized, sanctioned penetration testing against a
single sanctioned target, hard-scoped by an allow-list and a launch-bound token.

---

## 2. System architecture

```
                         ┌──────────────────────────────────────────────┐
                         │  AgentForge (attacker)  —  LangGraph state graph │
                         │                                                │
   coverage/findings/    │   ┌───────────────┐   ① AttackDirective        │
   budget (store) ─────▶ │   │ Orchestrator  │ ───────────────┐          │
                         │   │ (deterministic│                ▼          │
                         │   │   code, no LLM)│         ┌───────────────┐ │
                         │   └───────▲───────┘         │   Red Team     │ │
                         │           │ budget_exceeded  │  (Kimi K2.6,   │ │
                         │           │ / regression     │   Moonshot)    │ │
                         │           │                  └───────┬───────┘ │
                         │           │                          │ HTTP    │
   ══ trust boundary ════╪═══════════╪══════════════════════════╪═════════╪══
                         │           │                          ▼         │
                         │   ┌───────┴───────┐   ③ AttackResult ┌────────┐│   guarded
                         │   │    Judge      │ ◀───────────────│ Target ││──▶ HTTP
                         │   │ oracles (code)│                  │ client ││    surface
                         │   │ + Sonnet 5    │   ⑤ Verdict      │(launch- ││   (co-pilot)
                         │   │  (residue)    │ ──────┐          │ bound)  ││
                         │   └───────────────┘       ▼          └────────┘│
                         │        │ persist    ┌───────────────┐          │
                         │        ▼            │ Documentation │          │
                         │   ┌──────────┐      │  (Opus 4.8)   │──▶ vuln   │
                         │   │ Exploit  │      └───────────────┘   report  │
                         │   │ DB + reg │                                  │
                         │   └──────────┘   every span → Langfuse (PHI-free)│
                         └──────────────────────────────────────────────┘
```

- **Framework:** LangGraph (D2) — a checkpointable typed state graph whose edges
  are the `contracts/v1` schemas; checkpointing doubles as the regression
  replay/resume substrate.
- **Trust boundary** (double line) runs between the platform and the target: the
  only crossing is the launch-bound, allow-list-scoped Target client.
- **Provider independence:** Red Team runs on Moonshot; Judge/Documentation on
  Anthropic — different processes, different providers, no shared context.

---

## 3. Data-flow & data classification

| Edge | Producer → Consumer | Schema | Payload |
|---|---|---|---|
| ① | Orchestrator → Red Team | `orchestrator_to_redteam.schema.json` | `AttackDirective` (category, authorized_scope, budget) |
| ③ | Red Team → Judge | `redteam_to_judge.schema.json` | `AttackResult` (input_sequence, target_response, advisory hints) |
| ⑤ | Judge → Documentation | `judge_to_documentation.schema.json` | `Verdict` (outcome, severity, predicate_fired) |
| — | any agent → harness | `errors.schema.json` | 5 typed `AgentError` modes |
| — | shared `$defs` | `common.schema.json` | AttackCategory, OwaspMapping, OracleResult |

**Data classification & PHI handling.** Target responses may echo **demo-patient**
data. The platform's discipline:
- The Judge parses raw response bytes **in-process only** (oracles are pure
  functions); raw bytes are never persisted to the trace.
- Observability stores **PHI-free labels only** — oracle ids, fired status,
  counts (`AgentSpan` is a StrictModel with **no raw-body field** — structurally
  incapable of carrying response content; `phi_free_label` emits `oracle_id=status`).
- Everything is correlated by `correlation_id` (threaded to Langfuse as
  `traceId`) so a finding is traceable Orchestrator→Red Team→Judge→Documentation
  without storing content.

---

## 4. Authentication & authorization model

| Control | Mechanism | Evidence |
|---|---|---|
| **Reach the target only as the delegated physician** | SMART launch chain (login → chart-menu launch → confidential code exchange) → **launch-bound token** | `target/client.py`; TRO-134 (driver done) |
| **Hand-minted tokens are refused** | Clinical routes 403 anything not launch-bound (target-side TRO-52); launch-bound is the *only* path | THREAT_MODEL §D8 |
| **Attack only the sanctioned host** | SSRF-safe target allow-list; off-target routes → `OutOfScopeError`; fails closed on malformed URLs | `target/allowlist.py` (14 tests) |
| **Red Team ⟂ Judge** | Different providers (Moonshot vs Anthropic), different processes, no shared state; Judge treats Red Team hints as advisory and recomputes every signal | invariant #2; `judge/deterministic.py` |
| **Secrets management** | All keys in `.env` (**gitignored** — attested via `git check-ignore .env`); `.env.example` is the placeholder template | `config.py`, `.env.example` |

---

## 5. Dependency inventory (SBOM-lite)

**Runtime:** Python **3.11.4** (`requires-python >=3.11`). Build backend: hatchling.

| Package | Resolved | Declared | Role |
|---|---|---|---|
| pydantic | 2.13.4 | `>=2.6` | contract/message models (v2, `extra=forbid`) |
| pydantic-core | (pinned by pydantic) | — | — |
| langgraph | 1.2.9 | `>=0.2` | typed state graph |
| langchain-core | 1.4.9 | (via langgraph) | graph primitives |
| jsonschema | 4.26.0 | `>=4.20` (`[format-nongpl]`) | schema validation |
| referencing | 0.37.0 | (via jsonschema) | `$ref` registry |
| python-dotenv | 1.2.2 | `>=1.0` | `.env` loading |
| pytest | 9.1.1 | `>=8.0` (dev) | test gate |
| httpx | 0.28.1 | `>=0.27` (dev) | test client |
| fastapi | 0.139.2 | `>=0.110` (web) | operator console |
| starlette / uvicorn / anyio | 1.3.1 / 0.51.0 / 4.14.2 | (web) | ASGI stack |

**Supply-chain posture:** **no vendor LLM SDK is a dependency** — model calls use
the stdlib `urllib.request` against OpenAI-compatible endpoints via an *injected
transport*. Consequences: (a) minimal third-party attack surface; (b) every model
client is unit-tested without network or keys; (c) no SDK auto-update pulls
untrusted code into the model path. Deps are intentionally minimal and pinned by
range in `pyproject.toml`.

---

## 6. Control self-scan (the six non-negotiable invariants as controls)

Each platform invariant is a control with a shape-enforced mechanism and test
evidence — not a policy statement.

| # | Control | Enforcement mechanism | Evidence |
|---|---|---|---|
| C1 | **Never touch the target** | No target source in repo; HTTP-only via allow-listed launch-bound client | `git ls-files` clean; `target/*` |
| C2 | **Red Team ⟂ Judge** | Separate providers/processes; Judge recomputes every signal, hints advisory | `judge/deterministic.py`; `test_deterministic_judge.py` |
| C3 | **Deterministic-first at the eval boundary** | Structured output + input-keyed replay + reasoning effort — **never temperature** (rejected on both Anthropic models); oracles decide most verdicts | `judge/replay.py`; `test_judge_semantic_replay.py` |
| C4 | **Findings discovered, not hardcoded** | Seed vulns are runtime inputs/regression seeds, never wired-in constants; oracles detect finding *classes* | `evals/cases/*`; reviewer-verified generic oracles |
| C5 | **`contracts/v1` frozen** | v1 schemas immutable; a change is a new version | `test_contracts_api.py`, `_contract_ids.py` |
| C6 | **Secrets in `.env`** | gitignored; `.env.example` placeholder kept in sync | `git check-ignore .env` |

**Regression / self-integrity evidence:** **302 tests across 41 modules, green**;
5 frozen contract schemas; a `never-approve-a-confirmed-exploit` invariant that
holds *structurally* (the semantic layer is only reachable in the no-oracle-fired
branch and can never downgrade a `fired=True` verdict).

**Economic self-governance:** the Orchestrator halts a campaign on
cost-without-signal (`budget_exceeded` → `halt_campaign`); per-agent cost is
attributable (`observability/cost.py`). See `AI_COST_ANALYSIS.md`.

---

## 7. Evaluation evidence

| Metric | Value | Source |
|---|---|---|
| Attack categories covered | **6 / 6** (closed set) | `contracts/common.py` |
| Reproducible replay cases | **8** (`evals/cases/*.json`) | id==filename enforced |
| Deterministic oracles | **6** (`cross_patient`, `phi_pattern`, `foreign_file_bytes`, `tool_misuse` = HIGH; `grounding_fabrication`, `cost_overage` = MEDIUM) | `judge/oracles/*` |
| Designed false-positive | **1**, correctly declined (no oracle fires) | `af-prompt_injection-rejected-echo-negative-001` |
| Reproducibility | same case in → same verdict out (keyless replay) | `test_eval_runner.py::test_replay_is_reproducible` |
| Findings register | 11 confirmed (1 crit / 4 high / 4 med / 2 low) + 1 FP | `TRIAGE.md` |

Every eval case carries OWASP dual-Top-10 mapping (web + LLM), a `test_design`
tag (boundary / invariant / regression), and `guards_against` provenance. The
regression harness re-issues **stored attack bytes** and asserts `predicate_fired`
— a fix is *validated*, never assumed.

---

## 8. Sample incident postmortem

**INC-2026-07-21 — Live integration run against the deployed target**

*Summary.* During the first live integration run against
`https://openemr-production-…railway.app`, the platform exercised its Target
client end-to-end. Two guardrails fired as designed; one blocker was surfaced.
Classified **no-harm / controls-effective**.

*Timeline.*
- **T0** — Red Team generates an attack; Target client issues `POST
  /apis/default/api/copilot/turn`.
- **T0+** — Target returns **401** (unauthenticated). *Detection:* the auth
  boundary held — a hand-minted/absent token cannot reach clinical routes
  (TRO-52). Recorded as a legitimate **"defense held"** result, not a platform
  error.
- **T1** — A generated attack referenced an **off-target route/host**. *Response:*
  the allow-list rejected it with `OutOfScopeError` **before any request left the
  process** — the trust-&-safety control prevented an out-of-scope request.
- **T2** — Blocker identified: driving the SMART launch past the 401 needs a
  **logged-in physician session** whose credentials are not in `.env`.

*What worked (controls-effective).* (1) The allow-list fails closed and blocked an
off-target request. (2) The target's auth boundary held against non-launch-bound
access, and the platform recorded it correctly rather than mis-filing a finding.
(3) No PHI was written to the trace at any point.

*Root cause of the blocker.* By design — the platform refuses to hand-mint tokens;
the only sanctioned path is a launch-bound token, which requires a physician
login the operator must supply.

*Corrective action.* Provide the physician login (or the Week-2 demo launch path)
to complete end-to-end firing; the launch-chain driver (TRO-134) is already
coded. No code change required — the block is an intentional safety property.

*Regression guard.* The off-target-block and the 401-handling paths are covered
by `target/allowlist.py` (14 tests) and the Target-client tests; a change that
weakened either would fail the suite.

---

## 9. Residual risk & conditions for full ATO

| Residual item | Risk | Condition to close |
|---|---|---|
| Live-target firing not yet exercised past 401 | Medium — eval evidence is replay-based, not yet live-confirmed end-to-end | Operator supplies the physician login (unblocks TRO-135 / E9 live runner / E2 disposable patient) |
| Self-hosted Langfuse not deployed | Low — the emission *mapping* is built + tested behind a seam; the deploy is infra | Stand up the self-hosted instance; wire live agent calls (E8) |
| Novelty (embedding-distance) view absent | Low — dedup + resilience-trend shipped; novelty is an enhancement | Add the embedding-distance signal (E8) |
| Performance/load baselines not captured | Low-Medium | E11 — baselines, 100-case load test, backoff-under-429 |
| Anthropic model rates modeled, not measured | Low — cost analysis is directional | Replace with measured Langfuse aggregates once live |

**Recommendation:** conditional ATO — the platform's **safety and containment**
controls (allow-list, launch-bound auth, PHI-free observability, provider
independence, frozen contracts, deterministic-first adjudication) are shape-enforced
and test-evidenced. The open items are live-run confirmation and
observability/performance infrastructure, none of which affect the containment
posture.
