# Integration Packet — AgentForge

*The inter-agent contract boundary as a submission artifact: the published
interfaces, contract-test evidence, a cross-agent dependency map, migration
policy, and an end-to-end trace proving correctness through the frozen edges.
Cross-references: `contracts/`, `docs/DECISION_RECORD.md`, `docs/AGENT_INTERACTION.md`.*

## Published interfaces (`contracts/v1/`)

All inter-agent communication uses **versioned JSON Schema** (Draft 2020-12),
published in `/contracts` — a stranger could implement an agent against these
alone (explicit enums, worked examples, no field whose meaning requires reading
our code):

| Schema (`$id` under `https://agentforge/contracts/v1/`) | Edge | Producer → Consumer |
|---|---|---|
| `orchestrator_to_redteam.schema.json` | ① | Orchestrator → Red Team (`AttackDirective`) |
| `redteam_to_judge.schema.json` | ③ | Red Team → Judge (`AttackResult`) |
| `judge_to_documentation.schema.json` | ⑤ | Judge → Documentation (`Verdict`) |
| `errors.schema.json` | — | any agent → harness (5 typed `AgentError` modes) |
| `common.schema.json` | `$defs` | shared (`AttackCategory`, `OwaspMapping`, `OracleResult`) |

Every message carries `schema_version` (const `"1.0.0"`) and
`additionalProperties: false`. Enums are explicit (the closed six-category set,
the OWASP mappings); optional-vs-nullable fields are distinguished by shape.

## Contract-test evidence (both sides conform)

- **`tests/test_contracts_api.py` + `tests/_contract_ids.py`** verify that the
  Pydantic models (the producers/consumers) round-trip against the published
  JSON Schemas — both the producing side (model → JSON validates) and the
  consuming side (schema-valid JSON → model parses).
- The full suite is **322 tests green**; the contract layer is frozen (a v1
  schema change is a breaking change → new version, never a mutation of v1).

## End-to-end correctness trace (`agentforge/integration.py`, `run_end_to_end`)

A single directive driven through every edge, each hop validated against its
published schema (real `Draft202012Validator`, `format-nongpl` on):

```json
{
  "correlation_id": "e2e-demo",
  "all_valid": true,
  "report_present": true,
  "hops": [
    { "edge": "orchestrator->redteam", "schema": "orchestrator_to_redteam.schema.json", "valid": true },
    { "edge": "redteam->judge",        "schema": "redteam_to_judge.schema.json",        "valid": true },
    { "edge": "judge->documentation",  "schema": "judge_to_documentation.schema.json",  "valid": true }
  ]
}
```

**Proof:** the directive → attack → verdict → report chain is schema-valid at
every hop, `correlation_id` threads unchanged through all three (the trace↔verdict
join key), and a report is produced only on a `success` verdict. Covered by
`tests/test_integration_e2e.py` (success + fail paths).

## Cross-agent dependency map

```
Orchestrator ──①AttackDirective──▶ Red Team ──③AttackResult──▶ Judge ──⑤Verdict──▶ Documentation
     ▲                                                            │
     └──────────────── exploit store / observability ◀───────────┘   (Orchestrator reads coverage/
                                                                      findings/regressions/budget)
```

- **Orchestrator** depends on: the store (coverage/findings/regressions/budget) — nothing upstream.
- **Red Team** depends on: `AttackDirective` (① schema) only. No shared state with the Judge.
- **Judge** depends on: `AttackResult` (③) + the campaign's `authorized_scope` (resolved by `correlation_id`, never trusting Red Team-asserted authorization).
- **Documentation** depends on: `Verdict` (⑤), success verdicts only.
- **Trust boundaries:** Red Team ⟂ Judge (different providers/processes); Documentation is human-gated on critical severity.

## ADRs / decision record

Architectural decisions are recorded in **`docs/DECISION_RECORD.md`** (D1 Python,
D2 LangGraph, D3 model assignment, D6 Langfuse, the deterministic-first eval
boundary, the build-vs-configure record vs Burp/ZAP/Semgrep/Garak). Any contract
correction would be recorded there and paired with a schema version bump.

## Migration policy

- `contracts/v1` is **frozen**. A field addition/removal to a message schema is a
  **breaking change**: add `contracts/v2/...`, a migration note, and updated
  contract tests — never mutate v1 (guarded by `test_contracts_api.py`).
- The exploit store migrates additively (`sqlite_store.py::_migrate` idempotently
  `ALTER`s new columns, e.g. `cross_category`), so existing records survive a
  schema-version bump without data loss.

## Integration-week note (build-one / inherit-another)

The chosen stranger-implementable seam is **Red Team → Judge** (`redteam_to_judge`)
— the cleanest boundary with no hidden coupling (the Judge recomputes every
signal from the `AttackResult` and treats Red Team `observed_hints` as advisory
only). A peer could implement a Red Team against this contract and hand results to
our Judge, or vice-versa, using the published schema + worked examples alone. The
live integration with an independently-built peer agent is the one open item here
— it requires a second team; the contract, its tests, and the end-to-end trace
above are the platform-side half, ready.
