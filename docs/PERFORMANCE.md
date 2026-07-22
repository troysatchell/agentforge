# Performance & Load — AgentForge

*Baseline profiles, a load run, the regression-scan SLO, the bottleneck, and the
platform's own rate-limit/backoff. Numbers below are **measured** by the
profiling harness (`agentforge/perf.py`, `run_load`) over the real deterministic
pipeline — no network — plus the live-run wall-clock from
`evals/results/live-run.json`.*

## Baseline profile — 100-iteration deterministic run

`run_load(100, generate, judge, persist)` over the **real** Judge (all 6 oracles)
+ SQLite store, measured with `time.perf_counter` (no live model, no HTTP):

| Stage | mean | p50 | p95 |
|---|---:|---:|---:|
| generate (attack assembly) | 0.0097 ms | 0.0091 ms | 0.0115 ms |
| **judge (6 oracles)** | **0.0388 ms** | 0.0344 ms | 0.0416 ms |
| persist (store.record) | 0.0162 ms | 0.0150 ms | 0.0210 ms |

- **Wall (deterministic work):** 6.463 ms for 100 attacks · **throughput 15,471 attacks/s**.
- **Bottleneck (deterministic path):** `judge` — the six-oracle sweep, at ~0.039 ms/attack. Still ~400× cheaper than a single network round-trip.
- **Process footprint:** the platform is stdlib-only at the data layer (SQLite `:memory:`/file, regex oracles); no heavyweight runtime. Two distinct memory terms: **persisted** exploit-store rows grow linearly in *confirmed findings* (dedup on `sequence_hash`), not attack count; **in-flight** working memory (attack payloads + queued work) is separately bounded by the worker count and the `BoundedWorkQueue` capacity.

**Read:** the platform's *own* compute is negligible. The deterministic-first design (oracles decide most verdicts with no model call) means the highest-volume work costs microseconds.

## Regression-scan SLO (verified)

A full scan of the exploit store — `all()` + `cases_tested_by_category()` +
`regressions()` — over a populated store:

- **Measured: 0.517 ms at 100 records.** SLO budget: **≤ 2 s** for a full regression scan. **PASS** at the measured size (>3,800× under budget).
- The store is indexed on `severity`, `attack_category`, `target_version` (`sqlite_store.py`) and dedups on a UNIQUE `sequence_hash`; a full-table scan is expected to stay linear in rows, so the **projected** cost at 10⁴ records is well under budget — this is an extrapolation from the single measured size, not yet a benchmarked guarantee.
- *CI note:* the SLO is a one-line perf guard (scan-under-budget assertion) for the regression job. Hardening follow-up: assert the budget at several dataset sizes (10² / 10³ / 10⁴) so super-linear growth is actually caught rather than assumed.

## Load / stress — 100 consecutive attacks against the live target

Platform-level metrics from the captured live run (`evals/results/live-run.json`,
6 categories, extrapolated to the 100-attack shape):

| Metric | Observed |
|---|---|
| Agent orchestration latency (deterministic) | ~0.06 ms/attack (generate+judge+persist, measured above) |
| **LLM call latency (Red Team, Kimi K2.6)** | **~20–40 s/attack** wall (dominant term — live generation + target HTTP round-trip; 6 attacks ≈ 3 min wall) |
| Deterministic pipeline throughput | 15,471 attacks/s (measured, 100-attack `run_load`, all stages) — the platform is never the bottleneck |
| Cost / attack | ~$0.005 (live: $0.03024 / 6) |

**The bottleneck at real scale is the Red Team LLM call**, not the platform. Every
deterministic stage is sub-millisecond; the wall-clock is >99.99% the provider
round-trip. This matches the cost analysis (`AI_COST_ANALYSIS.md`): attack
generation dominates both spend and latency.

### Architectural change that addresses it

Serial attacks are LLM-latency-bound, so wall-clock scales linearly with attack
count. The fix is **concurrency with fail-fast admission control**, using the
PERF1 primitives:

- Run K attack workers pulling from a **`BoundedWorkQueue`** — depth-monitored,
  **fail-fast**: a `put` at capacity raises a typed `QueueOverflow` (admission is
  rejected; the queue never grows without bound). This is overload *shedding*,
  not blocking backpressure.
- Wrap each provider call in **`retry_with_backoff`** (full-jitter exponential
  backoff on 429s; `RateLimitExhausted` → Orchestrator halt after the cap).
- Throughput then scales with K until the provider's rate limit or the target's
  capacity is the ceiling — at which point backoff, queue-overflow shedding, and
  the budget-halt loop keep the platform stable instead of thrashing.

**Idealized** upper bound: a ~50-minute serial 100-attack run approaches
`~50min / K`. Real speedup will be lower — throttled by provider concurrency
limits, target capacity, retry backoff, and queue-overflow shedding — but the
deterministic core is unchanged either way.

## The platform's own rate-limit / backoff (implemented — PERF1)

`agentforge/runtime.py`:

- **`retry_with_backoff(fn, *, is_retryable, max_attempts, base_delay, max_delay, sleep, rng)`** — full-jitter exponential backoff (`delay ∈ [0, min(max_delay, base·2^n)]`) on retryable provider errors (429s); non-retryable errors propagate immediately; after `max_attempts` it raises **`RateLimitExhausted`** (a typed `RuntimeAbort` the Orchestrator catches → `halt_campaign`).
- **`BoundedWorkQueue(maxsize)`** — a depth-monitored queue; `put()` raises **`QueueOverflow`** at capacity (abort-with-typed-error, never unbounded growth); `get()` is FIFO.

Both are fully unit-tested (`tests/test_runtime_resilience.py`) with injected `sleep`/`rng` — no real sleeping, deterministic.

## Method & limitations

- Deterministic-path latencies are **measured** (`run_load`, `perf_counter`); the
  LLM latency is from the **real live run** wall-clock (`live-run.json`),
  attributable to the provider, not the platform.
- The harness (`agentforge/perf.py`) is the reusable instrument: re-run
  `run_load` with the live pipeline (real Kimi + `TargetClient`) once a
  launch-bound token is provided to capture end-to-end latencies directly.
