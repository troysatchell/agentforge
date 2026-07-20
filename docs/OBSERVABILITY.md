# Observability — the data substrate the Orchestrator reads

Not just for humans: this is the substrate the **Orchestrator** reads to prioritize, and the trail a
human operator uses to understand behavior at any time. It extends the Week-1/2 precedent (a PHI-free
JSONL span trace with an explicit `correlation_id`, `TraceDashboard` aggregator, `alert-check`) with
an **agent dimension** and **per-agent cost**.

**Backend (D6, resolved 2026-07-20): Langfuse, self-hosted.** Each agent's model call emits a Langfuse
generation carrying `model` · tokens · `cost_usd` · latency · `correlation_id`; Langfuse's native
per-generation model+cost tracking answers Q5/Q6 directly. Self-hosted (not SaaS) + PHI-free labels
only holds the demo-PHI-in-responses processor line. Per-layer model config: [`MODEL_ASSIGNMENT.md`](./MODEL_ASSIGNMENT.md).

## The six required questions → the exact metric that answers each

| # | Question | Metric / derivation | Source |
|---|---|---|---|
| 1 | Which attack categories tested, and how many cases per category? | `count(cases) group by attack_category` (+ `count(attacks) group by category`) | exploit DB / eval store |
| 2 | Current pass/fail rate across categories and versions? | `outcome` rate grouped by `attack_category × target_version` | Verdicts |
| 3 | Is the target becoming more or less resilient over time? | success-rate **trend over `target_version`** (BaselineComparator-style >5pp + per-category floors); a rising success-rate = regressing target | Verdicts × target_version |
| 4 | Which vulnerabilities are open / in-progress / resolved? | `status` field on each exploit-DB record | exploit DB |
| 5 | How much did this run cost, and at what rate is cost scaling? | `sum(execution_telemetry.cost_usd)` per run + per category + **per agent**; `cost_per_confirmed_finding`; run-over-run slope | agent traces |
| 6 | What is each agent doing, and in what order? | per-agent trace spans joined by `correlation_id`, ordered by `started_at` (the JSONL span pattern + an `agent` field) | agent traces |

## What the Orchestrator specifically reads (its inputs)

- **Coverage gaps** — categories with the fewest cases / lowest recent attempts (Q1).
- **Open high-severity findings** — unresolved criticals/highs (Q4).
- **Recent regressions** — a previously-fixed exploit that reappeared (Q3, `regression_flag`).
- **Novelty signal** — embedding distance of recent attacks vs the seed corpus (are we exploring or
  repeating? — *not* `sequence_hash`, which is only a dedup key).
- **Budget** — spend vs ceiling for the current campaign (halt when cost accrues without signal, Q5).

## Design notes

- **Per-agent cost, not just platform cost.** Every agent's LLM call stamps `cost_usd` on its span,
  so cost is attributable to Red Team vs Judge vs Documentation — the input to the AI Cost Analysis.
- **`target_version` is the resilience axis.** Q3 is only answerable if every Verdict carries the
  build it was adjudicated against. The target exposes no build-id, so the platform manufactures one;
  **observability alarms on a sustained-null `target_version`** rather than letting Q3 silently become
  unanswerable.
- **Trace → verdict join.** `correlation_id` threads a finding back through every agent that produced
  it (Orchestrator directive → Red Team attack → Judge verdict → Documentation report), so any report
  is fully traceable — the equivalent of the Week-1/2 disclosure-log ↔ trace join, applied to agents.
- **PHI caveat.** Target responses may echo demo-patient data; the trace stores PHI-free labels
  (oracle ids, counts, status), never raw response content — same discipline as the target's own trace.
