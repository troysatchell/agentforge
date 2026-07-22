# AI Cost Analysis — platform-side spend

*What it costs to **run AgentForge** (the attacker), attributed per agent and
extrapolated across attack volume. This is the platform's own cost, not the
target's. The per-agent split is exactly what `observability/cost.py`
(`attribute_cost → by_agent`) computes from the `cost_usd` stamped on every
agent span; the numbers below apply a rate card to a modeled workload.*

## The one architectural fact that sets the cost curve

**Cost is spent only where a model runs.** Three of the four agents (and the
whole regression path) are **deterministic — $0 in tokens**:

| Layer | Model | Billed? |
|---|---|---|
| Orchestrator | pure code | **$0** |
| Judge — Tier-1 oracles | regex/parse code | **$0** (decides *most* verdicts) |
| Regression replay | `InputKeyedReplayTransport` (re-issues stored bytes) | **$0** |
| Red Team | Kimi K2.6 (Moonshot) | Kimi rate |
| Judge — Tier-2 semantic | Claude Sonnet 5 | Sonnet rate *(escalation only)* |
| Documentation | Claude Opus 4.8 | Opus rate *(distinct findings only)* |

The deterministic-first design is the primary cost control: the layers that run
on **every** attack cost nothing, and the expensive models run **rarely** — the
Sonnet judge only when no oracle can decide, the Opus writer only on a *new*
confirmed finding (deduped on `sequence_hash`).

## Rate card

| Model | Role | $/1M input | $/1M output | Source |
|---|---|---|---|---|
| Kimi K2.6 | Red Team | **$0.60** | **$2.50** | **repo-grounded** — `web/runner.py:38` (`_IN_RATE`, `_OUT_RATE`) |
| Claude Sonnet 5 | Judge (semantic) | $3.00 | $15.00 | modeled (Anthropic list-price tier) |
| Claude Opus 4.8 | Documentation | $15.00 | $75.00 | modeled (Anthropic list-price tier) |

*Only the Kimi rate is committed in code; the two Anthropic rates are list-price
estimates and are the main sensitivity knob (see below).*

## Workload model (per attack)

| Agent | When it runs | Tokens/call (in → out) | Assumption |
|---|---|---|---|
| Red Team | every attack (+ mutation on partial successes) | 1,200 → 400 | ×1.3 calls/attack (30% get one live-sampled mutation pass) |
| Judge semantic | **only when no oracle fires** | 2,000 → 800 | **10% escalation** (oracles decide ~90%) |
| Documentation | **only a distinct confirmed success** | ~1,500 → 6,000 | template/threat-model prefix is prompt-cached; deduped on `sequence_hash` |

Derived per-unit costs:

- **Red Team:** `(1,200·0.60 + 400·2.50)/1e6 × 1.3 = $0.00224` per attack.
- **Judge semantic:** `(2,000·3 + 800·15)/1e6 × 0.10 = $0.0018` per attack.
- **Documentation:** `(1,500·15 + 6,000·75)/1e6 = $0.47` per **distinct finding**
  (not per attack).

The Documentation term is keyed to *distinct findings*, which **saturate** — the
set of exploitable vulns is small and the easy ones are found first. Modeled
distinct-finding counts: 100→8, 1K→20, 10K→40, 100K→55 (sub-linear).

## Cost by attack volume (100 / 1K / 10K / 100K)

| Attacks | Red Team | Judge semantic | Documentation | Orch + oracles + replay | **Total** | Distinct findings | **$/confirmed finding** |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | $0.22 | $0.18 | $3.78 | $0.00 | **$4.18** | 8 | $0.52 |
| 1,000 | $2.24 | $1.80 | $9.45 | $0.00 | **$13.49** | 20 | $0.67 |
| 10,000 | $22.36 | $18.00 | $18.90 | $0.00 | **$59.26** | 40 | $1.48 |
| 100,000 | $223.60 | $180.00 | $25.99 | $0.00 | **$429.59** | 55 | $7.81 |

## What the curve says

1. **Total spend scales ~linearly and stays cheap** — a **100,000-attack**
   campaign that surfaces 55 distinct findings costs **~$430**. The deterministic
   layers absorb the entire highest-volume workload for free.
2. **The premium model de-scales.** Documentation (Opus) is **90% of cost at 100
   attacks but 6% at 100K** — because it is bounded by *distinct findings*
   (dedup), not attack count. Spending the most-expensive model only on novel
   confirmed exploits is what keeps the premium tier from dominating at scale.
3. **At scale, Red Team generation dominates** (52% of spend at 100K), with the
   Sonnet judge second (42%) — matching the design intent
   (`MODEL_ASSIGNMENT.md`: "attack-gen dominates platform spend"). If the Judge
   graded *every* attack with a model instead of escalating only ~10%, Tier-2
   cost alone would be **~$1,800 at 100K** (10× higher) — the oracle-first split
   is a 4× reduction in total platform cost.
4. **Cost-per-confirmed-finding rises with volume** ($0.52 → $7.81): diminishing
   returns as the target's easy surface is exhausted. This is the exact economic
   signal the **budget guard** acts on.

## The economic control loop

The Orchestrator halts a campaign when money is burning without producing
signal — `should_halt(spent_usd, ceiling_usd, signal_produced)` emits a
`budget_exceeded` `AgentError` (`action: halt_campaign`) once
`spent_usd ≥ ceiling AND not signal_produced` (`orchestrator.py`). Combined with
per-agent attribution on every span, an operator sees **which agent** is
spending and **whether that spend is buying findings** — and the platform stops
itself before cost-per-finding runs away.

## Sensitivity

| Lever | Effect |
|---|---|
| Anthropic rates (modeled) | Documentation is the exposure; a 2× Opus rate raises the 100-attack total ~90%, the 100K total only ~6%. |
| Escalation rate (oracles' decisiveness) | Linear on Judge cost. Every finding class moved from the Sonnet layer into a deterministic oracle removes it from the bill entirely — the ongoing reason to grow the oracle set. |
| Prompt caching on the Documentation prefix | The template + threat-model prefix is static; caching it keeps the Opus input term flat as reports accumulate. |
| Mutation rate | Linear on Red Team cost; the 30% assumption is the tunable exploration/exploitation knob. |

## Method + limitations

- Per-agent attribution is real (`observability/cost.py`); the token counts and
  escalation/success/dedup rates are **modeled assumptions**, stated inline so
  they can be replaced with measured Langfuse aggregates once a live campaign
  runs (`cost_usd` per span → `attribute_cost`).
- Target-side inference cost (the OpenEMR copilot's own Opus/Cohere calls) is
  **not** billed to AgentForge and is excluded; the DoS finding's `$5.00` is the
  *target's* amplified cost, which the platform *measures* (via `cost_overage`)
  but does not pay.
