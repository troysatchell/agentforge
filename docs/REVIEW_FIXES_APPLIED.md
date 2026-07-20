# Review Fixes Applied — pre-v1 contract & evidence-packet corrections

*AgentForge · Week 3 · records the corrections made to the drafted `/contracts` schemas,
`AGENT_INTERACTION.md`, and `DECISION_RECORD.md` before v1 was frozen. Doubles as the ADR trail
the spec asks for (interface arbitration + contract corrections).*

These predate the v1 release, so **no data migration is required** — they shaped the initial
schema. Fixes #1–#10 are applied here; #11–#13 (build-vs-configure additions) are flagged as
pending in `DECISION_RECORD.md`.

| # | Concern | Change made | Files |
|---|---|---|---|
| **1** | **Judge-independence leak** — the Red Team computed the very signals the Judge scored (`captured_signals` booleans), collapsing the spec's most-emphasized boundary. | Renamed to **`observed_hints`** and marked **advisory / non-authoritative**; the Judge now **recomputes** every verdict signal from `input_sequence` + `target_response`. Boundary text hardened in the evidence packet. | `redteam_to_judge`, `AGENT_INTERACTION`, `contracts/README` |
| **2** | **Judge had no independent ground truth** — couldn't falsifiably rule "fabricated claim" / "cross-patient" without knowing the authorized baseline. | Added **`authorized_scope`** to the directive (set by the Orchestrator, never attacker-chosen) and **`ground_truth_ref`** to the Verdict; the Judge resolves both **by `correlation_id`** and reads its own snapshot (new dashed edge in the diagram). | `orchestrator_to_redteam`, `judge_to_documentation`, `AGENT_INTERACTION` |
| **3** | **`tool_misuse` missing** from the category enum — contradicted the spec's six + the §C.0 cover-with-evidence finding. | Added `tool_misuse` to the canonical enum. | `common` |
| **4** | **Taxonomy inconsistent** — `attack_category` was a 7-value enum in one schema, free-form string in two others, and blended spec-names with OWASP-names. | Defined **one** canonical `attackCategory` (the spec's six) in `common.schema.json`, `$ref`'d by all contracts; OWASP kept separate in `owaspMapping`. | `common` + all three |
| **5** | **`target_version` unfillable** — the target exposes no build-id, so it would silently be null and kill regression-to-deploy attribution. | Documented that the **platform manufactures** it (target-repo SHA / deploy metadata / `/ready` hash) and that observability **alarms on sustained null** rather than failing silent. | `redteam_to_judge`, `contracts/README` |
| **6** | **Signals over-fit to specific findings** — `foreign_file_bytes_present` (V1) etc. hardcoded, forcing a contract bump per new finding class (against the "agents discover, don't wire-in findings" principle). | Replaced fixed booleans with a generic **`oracleResult` list** `{oracle_id, fired, evidence}`. New finding = new `oracle_id`, no contract change. | `common`, `redteam_to_judge`, `judge_to_documentation` |
| **7** | **Novelty overstated** — README claimed the `sequence_hash` measured "generates-not-replays." | Reframed the hash as a **dedup key + syntactic-novelty lower bound**; true novelty = **embedding distance vs seed corpus** (Orchestrator-computed). | `redteam_to_judge`, `contracts/README` |
| **8** | **Non-standard top-level `version` keyword** — ignored by validators, could disagree with the real pin. | Removed; `schema_version` `const` is the single source of truth. | all schemas |
| **9** | **Loose nested objects** — `additionalProperties` unset on nested objects and error branches, so a wrong-type `detail` could masquerade as another error. | Added `additionalProperties:false` to nested objects and closed every `errors` if/then branch. | all schemas |
| **10** | **`partial` verdicts routed to Documentation** — filing a partial as a report is premature. | Documentation consumes **`success` only**; `partial` → Orchestrator (mutation); all outcomes persist to the DB. Encoded in the `outcome` description + README routing. | `judge_to_documentation`, `AGENT_INTERACTION`, `contracts/README` |

## Verification

- All five schemas parse as JSON; all nine cross-file `$ref`s resolve against
  `common.schema.json#/$defs` (attackCategory, owaspMapping, oracleResult).
- Contract tests (to be written in the platform repo) must register `common.schema.json` so the
  `$ref`s resolve, and must assert **both** producer and consumer sides of each edge.

## Residual (deliberately not changed here)

- **`target_response.body`** stays unconstrained (`object|string`) — raw target output is the
  Judge's evidence and must not be pre-shaped.
- **`input_sequence[].payload`** stays an open object — request bodies vary by route by design.
- **#11–#13** (Garak-auth cost, Semgrep self-scan vs target, missing harness/observability rows)
  are documentation additions to `DECISION_RECORD.md`, not schema changes — pending, flagged there.
