# evals/ — Adversarial test-case suite

The seed cases the Red Team learns from and extends, and the regression cases confirmed exploits
become. **Not static payloads** — each case is a structured, reproducible, extensible unit that runs
against the **live** target and is judged deterministically.

> Status: the case **schema + a seed template** are defined here. Actual cases + pass/fail results
> require the live runner + `target_client` (pending D1). Each seed maps to a threat-model finding.

## Case schema (the six spec fields + design tag)

Every case is one JSON file (`cases/<case_id>.json`) with these fields — the Stage-3 required six,
plus the graded test-design tag:

| Field | Spec requirement | Notes |
|---|---|---|
| `attack_category` + `attack_subcategory` | *Attack category and subcategory* | `attack_category` = the six canonical values (`contracts/v1/common.schema.json`) |
| `owasp_mapping` | *(engineering req)* | `{web, llm}` OWASP ids |
| `input_sequence` | *The specific prompt or input sequence* | list of `{turn_index, route, payload}` — multi-turn supported; the exact requests sent to the live target |
| `expected_safe_behavior` | *The expected safe behavior* | what a non-vulnerable target does |
| `observed` | *Observed behavior (pass/fail/partial)* | `{status, target_version, verdict_ref, run_at}` — null until executed; filled per run |
| `expected_severity` + `exploitability` | *Severity rating and exploitability assessment* | severity enum + Low/Med/High difficulty |
| `add_to_regression` | *Whether to add to the regression suite* | true once confirmed |
| `test_design` | *(graded req)* | `boundary` \| `invariant` \| `regression` — **every case must exercise one** |
| `success_predicate` + `oracle_ids` | — | the deterministic reason "success" fires; the Judge oracles that decide it (never trusts Red Team hints) |
| `_provenance` + `_seed` | — | where the case came from; whether it is a seed the Red Team extends |

## Test-design rule (graded — static payload lists do not satisfy this)

Each case must exercise exactly one of:
- **boundary** — a limit (max prompt length, min token budget, an edge-case multi-turn sequence);
- **invariant** — a property that must always hold, e.g. *the Judge must never mark a confirmed
  successful exploit as safe*, or *a fabricated citation is never presented as grounded*;
- **regression** — a previously-fixed vulnerability that must not reappear.

## How a case runs (reproducibility)

1. `target_client` mints a launch-bound token via the SMART chain and stamps the current
   `target_version` (git SHA / deploy metadata / `/ready` hash).
2. The `input_sequence` is replayed against the **live** deployed target.
3. The **Judge** recomputes the `oracle_ids` from the raw response (+ its own ground-truth snapshot,
   resolved by `correlation_id`) → `observed.status` and a `verdict_ref`.
4. `BaselineComparator`-style math over `observed` across `target_version`s answers "more/less
   resilient over time"; the `GateRedProof` pattern proves each regression case actually catches its
   exploit (a case that can't go red on the vulnerable build is worthless).

Determinism note: the *target* answer model is not seeded, so a case's pass/fail is judged on a
**deterministic predicate** (foreign bytes present / cross-patient row returned / cost over ceiling /
fabricated-citation grounded), never on model prose equivalence.

## Seed categories for the MVP (≥3, threat-model-prioritized)

`data_exfiltration` (V1/V2/V6) · `denial_of_service` (V3) · `state_corruption` (V4/V5) —
with `prompt_injection` as the standing grounding-bypass probe. See `case.template.json` for the
reference shape (a V1 local-file-read seed).
