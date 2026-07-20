# Build-vs-Configure Decision Record

*AgentForge — Adversarial Evaluation Platform · Week 3 · Architecture Defense deliverable*

---

## Defense-ready summary (read this first)

The honest answer is **hybrid, not build-everything**. Off-the-shelf security tooling
covers the *commodity* layer well — generic LLM injection payloads (Garak/PyRIT),
OWASP-web and access-control fuzzing (ZAP), and static code scanning (Semgrep, already
in the target repo). None of it covers the layer this assignment actually grades:
**clinical-context-aware attack generation, mutation of partially-successful attacks toward
this target's specific grounding-bypass, coverage-driven prioritization that reads the
target's own threat model, and healthcare-grade judging** (did a *fabricated clinical claim*
get presented as grounded? did PHI leak? did a cross-patient boundary break?).

So we **configure** the commodity tools as seed corpora and deterministic oracles, and we
**build** the four agents where the value is domain awareness and autonomy. A decisive
second reason to build: only a custom platform can reuse the mature Week 1/2 PHP
substrate — `PhiPatternDetector`, the four deterministic clinical detectors,
`BaselineComparator`, `GateRedProof` — as **Judge oracles**. No COTS tool can call those.

---

## Decision table

| Tool | What it covers | Where it falls short *for this target* | Decision |
|---|---|---|---|
| **Garak** | Broad LLM probe library: known jailbreaks, generic prompt-injection corpus, toxicity | Not EMR-aware; blind to the chart-grounding/citation-verification defense; can't mutate toward *this* target's grounding-bypass; no multi-turn clinical sequences; no coverage prioritization; can't drive SMART-launch auth | **Configure** — seed corpus for the generic injection category; feeds the Red Team, doesn't replace it |
| **PyRIT** | LLM red-team orchestration: attack converters/mutators, some multi-turn, scoring | General-purpose; its orchestrator isn't coverage-aware of this threat model; scoring isn't clinical (can't judge grounded-fabrication or PHI leak); adopting its orchestration wholesale fights the LangGraph state model | **Borrow, don't adopt** — reuse its converters/mutators as a mutation library; keep our own Orchestrator + Judge |
| **OWASP ZAP** | Web-app scanning/proxy: broken-access-control probing, injection, SSRF, protocol fuzzing, request replay | No LLM semantics; can't judge whether a fabricated *clinical* claim was grounded; can't mutate a prompt-injection payload; "success" is HTTP-level, not clinical-meaning-level | **Configure** — baseline scan for the OWASP-web / access-control category (V1/V2 authz probes) + protocol fuzzing; acts as a deterministic oracle feeding the Judge |
| **Burp Suite** | Same web-scanning class as ZAP, commercial | Same LLM-blindness as ZAP; licensing overhead with no marginal benefit over ZAP for this scope | **Out** — ZAP covers the need, open-source, scriptable |
| **Semgrep** | SAST — static code vulnerability detection | Static-only; cannot test the *live deployed* target; no runtime prompt injection; blind to the extracted-value feedback loop (V5) | **Reuse as-is** — already in target repo; used for the ATO evidence-packet dependency/code scan; out of scope for the runtime attack loop |
| **Commercial red-team platforms** (Lakera, Robust Intelligence, HiddenLayer, etc.) | Managed LLM red-teaming as a service | Cost; black-box (can't defend "every autonomous step" to a CISO); not clinical-context tunable; can't integrate the Week 1/2 PHP oracles | **Out** — fails the defensibility bar and the reuse requirement |

---

## Per-tool reasoning

**Garak — configure as seed corpus.** Garak's value is breadth: a large, maintained
library of known jailbreak and injection patterns. That's exactly what a Red Team should
*start* from and then *mutate beyond*. What it cannot do is understand that this target's
core defense is fresh-minted citation verification against the live chart — so it can't
steer toward the grounding-bypass that would actually matter here. We ingest its injection
probes as seed cases; the Red Team's job begins where Garak's ends.

**PyRIT — borrow the mutators, not the orchestration.** PyRIT ships useful prompt
converters and multi-turn scaffolding. We treat those as a library the Red Team can call.
We do *not* adopt PyRIT's orchestrator, because our Orchestrator's whole job is to read
*this target's* coverage state and threat model — a domain-specific decision that a generic
orchestrator can't make, and that would collide with our LangGraph state graph.

**ZAP — configure as the web-layer oracle.** The OWASP-web items (broken access control,
injection, SSRF) are genuinely ZAP's home turf, and V1/V2 are web authz bugs. ZAP runs
the deterministic web probes better than an LLM would. But ZAP's verdict is HTTP-level;
it can't tell whether a returned document constitutes a *cross-patient PHI disclosure* in
clinical terms. So ZAP is an oracle that *feeds* the Judge, not the Judge itself.

**Semgrep — reuse, already present.** It's already in the target repo. It contributes the
static dependency/code scan for the ATO evidence packet. It has no role in the live
runtime attack loop, because static analysis can't exercise a deployed target or a
runtime feedback loop.

**Commercial platforms — out.** Two disqualifiers: they're black boxes (a CISO deciding
whether to trust continuous testing of physician-facing systems cannot audit an opaque
autonomous step), and they cannot call the existing PHP oracles that make our Judge
credible. Cost is a third, minor reason.

---

## Why custom agents are justified

Every capability the assignment grades sits in the gap the commodity tools leave open:

- **Clinical-context-aware generation** — attacks that target chart-grounding, the
  extracted-value feedback loop (V5), and cross-patient boundaries, not generic jailbreaks.
- **Mutation of partial successes** — taking a payload that *almost* bypassed grounding and
  autonomously generating variants toward the bypass. No configured tool does target-specific
  mutation with a coverage objective.
- **Coverage-driven prioritization** — an Orchestrator that reads *this* threat model's open
  findings and untested surfaces and decides what to probe next. This is domain logic, not
  a library feature.
- **Healthcare-grade judging** — the success predicate is clinical: *was a fabricated claim
  presented as grounded? did a PHI pattern leak? did a cross-patient read succeed?* These are
  answered by our Week 1/2 deterministic oracles, which only a custom platform can invoke.
- **Professional vuln documentation** — reports a senior security engineer can reproduce and
  fix, generated without a human writing them.

## What we reuse from Weeks 1–2 (the reuse that COTS can't touch)

| Existing asset | Role in the platform |
|---|---|
| `PhiPatternDetector` | Judge oracle — deterministic PHI-leak verdict |
| Four clinical detectors (panic labs, drug-drug, drug-allergy, follow-ups) | Judge oracles — clinical-signal verdicts |
| `BaselineComparator` (>5pp integer + per-category floors) | Regression-trend math over the exploit DB |
| `GateRedProof` + `synthetic-regression.patch` pattern | Proof that each regression test catches its own exploit |
| `InputKeyedReplayTransport` | Determinism seam for any LLM call, incl. a future Judge |
| JSONL trace + `TraceDashboard` + `alert-check` | Observability precedent extended to inter-agent + per-agent cost |

This reuse is itself a build-vs-configure argument: the substrate is already healthcare-grade
and PHI-disciplined. Rebuilding it inside a COTS tool would be worse and slower.

---

## One-line defense position

> We configure the commodity layer (Garak/PyRIT seeds, ZAP web-fuzzing, Semgrep SAST)
> and build the four agents where the graded value lives — clinical-context awareness,
> partial-success mutation, coverage-driven prioritization, and healthcare-grade
> judging/documentation — reusing the Week 1/2 PHP oracles no external tool can call.

---

## Evidence to bring to the defense (pre-work)

Run Garak's injection probes against the live target **once** before the defense. Record:
(a) what it caught, (b) the clinical-context gap it missed (grounding-bypass, feedback loop,
cross-patient). That empirical gap *is* the justification for building custom agents —
state it as observed fact, not abstract reasoning.

> **Scope note (review #11):** Garak against *this* target is not a 30-minute drop-in — it
> needs a **custom REST generator** that mints a launch-bound token via the SMART chain and
> wraps the `{patient_uuid, question}` turn body (ties to orientation §D8 auth). Budget for that
> generator, or the empirical-gap evidence won't be ready.

---

## Pending review additions (#11–#13 — not yet folded; out of the #1–#10 schema pass)

These three review items extend this record and should be added before the Architecture Defense:

- **#11 — Garak auth cost.** Now captured in the scope note above; keep it prominent.
- **#12 — Semgrep target vs self-scan.** The ATO evidence packet wants a scan of **the platform's
  own** code, not only the target's. Split the Semgrep use into (a) *self-scan* of the AgentForge
  repo (the ATO artifact) and (b) optional white-box supplement of the target repo. Also state the
  platform is **grey-box** (it holds the target's threat model + repo) rather than pure black-box —
  discovery is grey-box-informed, which is legitimate but should be named, not hidden.
- **#13 — Missing rows: the eval/judge harness and observability.** This record only covers *attack*
  tooling. The assignment also grades the **regression harness** and the **observability layer**. Add
  build-vs-configure rows for: promptfoo / DeepEval / Inspect (configure-vs-build the eval/Judge
  layer — decision: build, because the Judge oracles are the Week 1/2 PHP deterministic detectors,
  which those tools can't call) and Langfuse / LangSmith / Braintrust (observability).
  **Observability RESOLVED (founder, 2026-07-20): configure Langfuse (self-hosted)** — cross-ref
  orientation D6 and [`MODEL_ASSIGNMENT.md`](./MODEL_ASSIGNMENT.md); self-hosted holds the
  demo-PHI-in-target-responses processor line, PHI-free labels only. Note this is a *different slot*
  from Garak: **Langfuse = observability (D6); Garak = generic-injection seed corpus (D7, "configure"
  above)** — the two do not compete, and "Langfuse not Garak" does not by itself retire Garak as a
  seed corpus (open question flagged in `MODEL_ASSIGNMENT.md`).
