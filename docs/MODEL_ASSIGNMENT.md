# Model Assignment — one model per layer, with per-layer instructions

*AgentForge · Week 3 · resolves orientation **D3** (per-role models) + **D6** (observability
backend). Drop into ARCHITECTURE.md §Model Choice + the AI-use disclosure section.*

> **The graded question this answers:** "where AI vs deterministic tooling, and *why that model*
> for each AI role." Every layer states its model, why that model beats the alternatives *for its
> job*, and the **specific config that makes it best-quality** — because the levers differ by layer
> (an offensive model wants diversity; a judge wants reproducibility; a writer wants prose quality).

---

## Summary

| Layer | Model | Provider | AI? | Why this one | Primary quality/determinism lever |
|---|---|---|---|---|---|
| **Orchestrator** | — (deterministic) | — | No | Reproducible control flow, auditable to a CISO, zero token cost, cannot drift | Pure code over the observability substrate |
| **Red Team** | **Kimi K2.6** (Moonshot; confirm API string) | Moonshot | Yes | Top open-weights agentic/eval performance; tractable under authorized-pentest framing where frontier RLHF models refuse; cheapest tier at the highest call volume; **provider-independent from the Judge** | Higher `temperature` for mutation diversity (the *only* layer where sampling params are live) |
| **Judge — oracles** | — (deterministic) | — | No | Reused Week 1/2 PHP detectors; auditable; cannot drift | Decide most verdicts before any model is called |
| **Judge — semantic** | **`claude-sonnet-5`** | Anthropic | Yes (last resort) | Near-Opus judgment at lower cost; scales with attack volume; structured output; different provider from Red Team | Determinism via **structured schema + input-keyed replay**, *not* temperature (see below) |
| **Documentation** | **`claude-opus-4-8`** | Anthropic | Yes | Best long-form technical write quality — the explicit ask; reports must be reproduce-and-fix ready | Strict template + prompt-cached context + `effort: high` |
| **Observability** | **Langfuse** (self-hosted) | — | n/a | Per-generation model+cost tracking natively answers Obs Q5/Q6; open, self-hostable (holds the PHI-processor line) | One span/generation per agent call, keyed by `correlation_id` |

**Independence at the model level:** Red Team (Kimi / Moonshot) and Judge (Sonnet 5 / Anthropic) are
**different providers** — a model-level reinforcement of the contract-level Red Team ⟂ Judge boundary
(`observed_hints` advisory; Judge recomputes signals; owns ground truth by `correlation_id`). An
attacker model cannot influence a verdict it never talks to and cannot even share weights with.

---

## Orchestrator — deterministic (no model)

Reads coverage gaps, open findings, regressions, novelty, and budget from the observability substrate;
emits `AttackDirective`s, regression triggers, and halt signals. **No LLM.**

- **Why deterministic is the *right* choice, not a shortcut:** same state → same directive (reproducible
  campaigns), every autonomous step is auditable code (the CISO-defensibility bar), zero marginal token
  cost on the busiest control loop, and it cannot drift. This is precisely the assignment's
  "where deterministic tooling is correct" answer — state it as a deliberate design position.
- **Cheap-model tie-break: deferred, not adopted.** If prioritization ever needs a genuinely fuzzy
  tie-break, the escape hatch is `claude-haiku-4-5` at `effort: low` with a single-choice structured
  output — but v1 stays fully deterministic so the Orchestrator remains 100% auditable.

## Red Team — Kimi K2 (Moonshot)

Generates novel attacks, mutates partial successes toward *this* target's grounding-bypass, drives
multi-turn sequences. Speaks the `AttackResult` (③) contract; `observed_hints` are **advisory only**.

**Why Kimi, not a frontier Anthropic model:**
1. **Offensive tractability.** Frontier RLHF models are trained to refuse offensive-security workflows;
   Kimi is more workable under an explicit authorized-pentest system prompt. (This is the D3
   "offensive-refusal problem" the orientation names.)
2. **Eval performance.** Strong open-weights agentic/tool-use scores — "eval best" for the generative
   attack role.
3. **Cost at volume.** Attack generation dominates platform token spend (D11); the cheapest capable
   tier belongs on the highest-volume layer.
4. **Independence.** A different provider from the Judge hardens the Red Team ⟂ Judge boundary.

**Model id / endpoint — version pinned, confirm the literal string.** Version = **Kimi K2.6** (founder,
2026-07-20). Confirm the exact API-string form against the live catalog before first run — e.g.
`moonshotai/kimi-k2.6` (OpenRouter) or the `kimi-k2.6*` id via Moonshot's native OpenAI-compatible
endpoint (`/chat/completions`) — and pin it (+ any dated snapshot) so regression runs reproduce. Literal
string **UNVERIFIED vs live catalog**, same discipline the orientation applies to the Cohere model ids.

**Specific instructions:**
- **System prompt:** explicit *authorized security research / delegated pentest* framing; hard-scope
  to `authorized_scope.target_base_url` (the target-URL allowlist); state founder authorization.
- **Structured attack-spec output** matching `redteam_to_judge.schema.json` — use Kimi's JSON mode /
  tool-calling (OpenAI-compatible) to emit the attack sequence + advisory hints.
- **Sampling is a live lever here (unlike the Anthropic layers):** raise `temperature` on mutation
  passes for diversity (~0.8–1.0), lower it for targeted reproduction of a near-miss. This is the one
  layer where temperature does real work.
- **Never self-evaluates** — enforced by contract shape; the Red Team is never handed the Judge's
  oracles or ground-truth snapshot.
- **Stochastic generation ≠ non-reproducible regression.** The exploit DB stores the *realized* attack
  bytes; regression **re-issues the stored sequence** (asserting `predicate_fired`), it does not
  re-generate. A stochastic attacker is therefore compatible with a deterministic regression gate.

## Judge — deterministic oracles first, `claude-sonnet-5` for the semantic residue

**Tier 1 — deterministic oracles (decide most verdicts, no model called):** reuse the Week 1/2 PHP
substrate — `PhiPatternDetector` (PHI-leak), grounding/citation-verification (was a fabricated clinical
claim presented as grounded?), HTTP status, cross-patient vs `authorized_scope`, cost overage. Auditable,
zero-cost, cannot drift.

**Tier 2 — Sonnet 5, only for genuinely semantic verdicts** the oracles cannot settle (e.g. "did the
response *semantically comply* with an injected instruction in a way no regex catches?").

**Why Sonnet 5, not Opus:** near-Opus judgment on the semantic call, cheaper, and Judge calls scale with
attack count (D11) — the volume-sensitive AI layer takes the Sonnet tier. Different provider from Kimi.

**Determinism WITHOUT temperature — the load-bearing instruction.** On Sonnet 5, `temperature` /
`top_p` / `top_k` are **rejected (400)** and `budget_tokens` is removed, so the classic "pin
temperature=0 for a deterministic judge" is impossible. Reproducibility comes from three things instead
(exactly the orientation's D.4 "replay + json_schema, not temp/seed" precedent):
- **Structured verdict** via `output_config.format` json_schema (or `messages.parse()`),
  `additionalProperties: false`, closed enum `verdict ∈ {success|fail|partial}` + `reason` + confidence.
  A validated, parseable verdict every time.
- **`InputKeyedReplayTransport`** wrapping the Judge's own model call — sha256-canonicalized
  record/replay; an **unseen input throws** (input corruption → red gate, never a canned answer). This
  is the reproducibility guarantee that replaces temperature pinning.
- **`thinking: {type: "adaptive"}` + `output_config: {effort: "high"}`** for rigorous reasoning about
  exploit success; leave `display: "omitted"` (default) — the verdict is the schema, not the prose.
- **Invariant (model-agnostic):** *the Judge must never approve a confirmed exploit* — an integration
  test, not a prompt.

**Drift control:** the semantic layer is scored against a **labeled judge-eval ground-truth set**
(measures accuracy, detects drift); the oracles can't drift but are validated for accuracy on the same
set. Judge runs in a **separate process/context** from the Red Team.

## Documentation — `claude-opus-4-8`

Turns confirmed `success` verdicts into professional vuln reports (the `VULN_REPORT_TEMPLATE` shape),
with **no human writing them**. This is the layer where write quality is the whole point → top model.

**Why Opus 4.8:** best long-form technical prose; the bar is "a senior engineer not present can
reproduce, validate, and fix from the report alone." Documentation runs at the **lowest volume** (only
confirmed successes), so the premium tier is affordable here.

**Specific instructions:**
- **Strict template** (the six mandatory fields) as scaffolding; structured front-matter (severity,
  OWASP mapping, `correlation_id`, `target_version`) via structured output; prose body free-form.
- **`thinking: {type: "adaptive"}` + `effort: "high"`** (`xhigh` for critical). **Stream** with a
  generous `max_tokens` (16k–32k; streaming is required above ~16k to avoid HTTP timeouts).
- **4.8 behavioral tuning (from the migration guide):** 4.8 narrates more and can over-elaborate —
  add *"lead with severity and outcome; be selective, not verbose; every claim traceable to a tool
  result."* Its warmer default voice is fine for a report but keep it clinical/professional.
- **Prompt caching = the Documentation cost lever (D11):** the report template + threat-model context
  are a stable prefix → put `cache_control: {type: "ephemeral"}` on the last stable block; only the
  per-finding data varies after it. Large token saving across a report batch.
- **Human gate on critical (D9):** low/medium auto-file; **critical requires human approval before
  publish.** Documentation files `success` only; remediation is advisory, never auto-pushed.

## Observability — Langfuse (resolves D6)

Backend = **Langfuse, self-hosted** (open, self-hostable). Wrap every layer's model call so each emits
a Langfuse generation carrying `model`, tokens, `cost_usd`, latency, and `correlation_id`. Langfuse
tracks per-generation model+cost natively → directly answers **Obs Q5** (per-agent cost, the AI Cost
Analysis input) and **Obs Q6** (what each agent did, in order), joined by `correlation_id` — the
agent-dimension extension of the Week 1/2 JSONL trace + `TraceDashboard`.

- **PHI caveat (state it, don't hide it):** target responses may echo demo-patient data, which would
  make a trace sink a data processor (the reason the *product* refused a vendor sink, C4). Mitigations:
  (a) **self-hosted** Langfuse, not SaaS, so no third party sees it; (b) store **PHI-free labels only**
  (oracle ids, counts, status), never raw response bytes — same discipline as `OBSERVABILITY.md`.
  Demo-data-only target makes this acceptable; the doc says so explicitly.
- **Langfuse ≠ Garak (clearing the conflation):** Langfuse fills the **observability** slot (D6). Garak
  is a red-team **probe seed corpus** in a *different* slot (D7, currently "configure" in
  `DECISION_RECORD.md`). Choosing Langfuse for observability does not by itself decide Garak's fate as a
  seed corpus — see the open question at the bottom.

---

## Model → cost tier (feeds the AI Cost Analysis / D11)

| Layer | Tier | Volume | Net cost driver |
|---|---|---|---|
| Orchestrator + Judge oracles | **$0** (deterministic) | highest | free — the point of deterministic-first |
| Red Team (Kimi K2) | cheapest LLM tier | **highest LLM volume** (attack-gen dominates) | dominates platform spend; cap via Orchestrator budget-halt |
| Judge semantic (Sonnet 5) | mid | scales with attacks | minimized by deterministic-first — escalate to the model only when oracles can't decide |
| Documentation (Opus 4.8) | premium | **lowest** (confirmed successes only) | bounded by low volume + prompt-cached template |

The Orchestrator's "halt when cost accrues without signal" is the runtime guardrail; the per-layer model
mix (free control loop, cheap attacker, mid judge, premium-but-rare writer) is the structural one.

---

## Concrete call shapes (Anthropic layers)

**Judge — semantic verdict (`claude-sonnet-5`):**
```
messages.parse(          # or output_config.format json_schema
  model="claude-sonnet-5",
  thinking={"type": "adaptive"},          # NO temperature/top_p/budget_tokens — all 400 on Sonnet 5
  output_config={"effort": "high", "format": VERDICT_SCHEMA},  # closed enum success|fail|partial
  max_tokens=4096,
)
# wrapped by InputKeyedReplayTransport → reproducible; unseen input throws
```

**Documentation — vuln report (`claude-opus-4-8`):**
```
messages.stream(         # stream: max_tokens > ~16k
  model="claude-opus-4-8",
  thinking={"type": "adaptive"},          # NO temperature/budget_tokens on 4.8
  output_config={"effort": "high"},       # "xhigh" for critical
  system=[{... TEMPLATE + THREAT_MODEL ..., "cache_control": {"type": "ephemeral"}}],  # cached prefix
  max_tokens=32000,
)
```

**Red Team (Kimi K2, OpenAI-compatible):** `/chat/completions` with `response_format` json / tool-calling
for the attack spec; `temperature` ~0.8–1.0 on mutation passes. Pin the exact model id first.

---

## Resolved: Langfuse and Garak are different slots

**"Langfuse not Garak" = observability = Langfuse (D6); Garak unchanged (founder, 2026-07-20).** Garak
stays **configure: generic-injection seed corpus** feeding the Red Team (D7, `DECISION_RECORD.md`). The
two never competed — Langfuse fills the observability slot, Garak the seed-corpus slot. No `DECISION_RECORD`
change; the pre-defense Garak empirical-gap run stands.
