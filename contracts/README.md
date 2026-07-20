# /contracts — Inter-Agent Message Contracts

Versioned JSON Schema (draft 2020-12) for every inter-agent boundary. All communication
uses these shapes. Both the producing and consuming agent are contract-tested against them.

## Schemas (v1)

| File | Edge | Producer → Consumer |
|---|---|---|
| `v1/common.schema.json` | — | Shared `$defs` (`attackCategory`, `owaspMapping`, `oracleResult`). **Must be registered** for the others to resolve their `$ref`s. |
| `v1/orchestrator_to_redteam.schema.json` | ① AttackDirective | Orchestrator → Red Team |
| `v1/redteam_to_judge.schema.json` | ③ AttackResult | Red Team → Judge |
| `v1/judge_to_documentation.schema.json` | ⑤ Verdict | Judge → Documentation (+ exploit DB) |
| `v1/errors.schema.json` | — | Any agent (5 typed failure modes) |

Edge numbers match the diagram in `../docs/AGENT_INTERACTION.md`. Edges ② (Red Team → target,
plain HTTP) and ④ (Judge → exploit DB, internal persistence) are not inter-agent messages, so they
have no schema. The Verdict (⑤) is the single record written to both Documentation and the DB.

## One canonical taxonomy

`attack_category` is defined **once** in `common.schema.json#/$defs/attackCategory` and `$ref`'d
by every contract — so the same six-value set (`prompt_injection`, `data_exfiltration`,
`state_corruption`, **`tool_misuse`**, `denial_of_service`, `identity_role_exploitation`) is
enforced end-to-end. These are the spec's six Stage-2 categories. The OWASP dual-Top-10 mapping
lives in a separate `owasp_mapping` object — the two taxonomies never collide in one field.

## Error types (all in `errors.schema.json`)

`target_unreachable` · `budget_exceeded` · `judge_timeout` · `no_findings` · `regression_detected`

Discriminated union on `error_type`; each branch is closed (`additionalProperties:false`) so a
wrong-type payload cannot masquerade as another error. Each carries `correlation_id` + `raised_by`.

## Versioning policy

- Every schema declares `schema_version` (semver) and pins it via a `const` on that field.
  There is deliberately **no** top-level non-standard `version` keyword — the `const` is the single
  source of truth.
- **Breaking change** (remove/rename a required field, tighten a type) → bump major, new `v2/`
  directory, migration note. Old version stays until all agents migrate.
- **Additive change** (new optional field) → bump minor, no new directory.
- Contract tests run both sides on every change; a breaking change with no version bump fails CI.

## Migration notes

*v1 is the initial released version.* Pre-release review corrections (Judge-independence,
generic oracle results, taxonomy, etc.) are logged in `../docs/REVIEW_FIXES_APPLIED.md`; they
predate v1 and require no data migration.

When a breaking change lands, record here: what changed, why, which agents were affected, and the
migration step for existing exploit-DB records.

## Design notes worth defending

- **Judge independence is enforced by the *shape*, not just by policy.** The Red Team's
  observations travel as `observed_hints` — explicitly **advisory, non-authoritative**. The Judge
  **recomputes** every verdict signal from `input_sequence` + `target_response` with its own
  oracles. An agent that both generates and evaluates is compromised by design; a hint field the
  Judge is contractually told to distrust keeps the boundary real even under a drifting Red Team.
- **The Judge owns its ground truth.** Authorization context (`authorized_scope`) and the grounding
  baseline (`ground_truth_snapshot_ref`) are resolved by the Judge from the campaign store **by
  `correlation_id`** — never accepted from the Red Team. This makes a "cross-patient leak" or
  "fabricated claim" verdict falsifiable rather than a matter of the attacker's say-so.
- **Signals are generic, not finding-specific.** `oracle_results` / `observed_hints` are lists of
  `{oracle_id, fired, evidence}`. A new attack class adds a new `oracle_id` string — the contract
  does not gain a field and does not version-bump. This keeps the contract target-agnostic: it is
  not wired to specific findings; the agents discover and the oracles grow independently.
- **`sequence_hash` is a dedup key and a novelty *lower bound*, not a novelty measure.** It is
  sha256 of the canonicalized `input_sequence`; a new hash is necessary but not sufficient for true
  novelty. The real "generates-not-replays" number is **embedding distance vs the seed corpus**,
  computed by the Orchestrator — reported alongside, never conflated with, the hash.
- **`predicate_fired`** is the one-sentence deterministic reason a verdict is `success` — what makes
  a regression test assert the *signal*, not a generic pass (the spec's "a test that passes because
  behavior changed is worse than no test").
- **`parent_attack_id`** threads lineage through mutation, so a partial success and its variants form
  an auditable chain.
- **`target_version` closes the Week-1/2 build-attribution gap — but the platform must fill it.** The
  target exposes no build-id natively; the platform manufactures one (target-repo SHA at deploy /
  deploy metadata / hash of `/ready`) and stamps it here. If null, regression-to-deploy attribution
  silently degrades, so observability alarms on a sustained-null `target_version`.
- **Routing of `partial`.** Only `outcome=success` reaches the Documentation Agent; a `partial`
  routes to the Orchestrator as a mutation candidate; all outcomes persist to the exploit DB.
