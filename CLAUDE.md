# CLAUDE.md

Guidance for Claude Code (and other agents) working in this repo.

## What this is

**AgentForge** — a multi-agent platform that continuously **discovers, evaluates, escalates, and
documents** vulnerabilities in the OpenEMR **Clinical Co-Pilot** (`oe-module-copilot`), treated as a
live, mostly-black-box **HTTP target**. This repo is the *attacker*, deliberately independent of the
target's codebase.

Read `README.md`, `ARCHITECTURE.md`, and `THREAT_MODEL.md` first — they are the source of truth.
`docs/` holds the design record (`AGENT_INTERACTION.md`, `DECISION_RECORD.md`, `OBSERVABILITY.md`,
`MODEL_ASSIGNMENT.md`, `VULN_REPORT_TEMPLATE.md`).

## Non-negotiable invariants

These are enforced by shape, not politeness — violating one breaks the platform's premise:

1. **Never touch the target.** AgentForge attacks the co-pilot over its guarded HTTP surface only.
   No editing the OpenEMR fork, no importing its code at runtime, no service accounts, no
   `$ignoreAuth`. The target requires *no* source changes to be a target.
2. **Red Team ⟂ Judge.** Different processes, different providers (Moonshot vs Anthropic), no shared
   context. The attacker gets no channel to influence a verdict; the Judge treats Red Team
   `observed_hints` as advisory only and recomputes every signal independently. Never wire these
   together or let one import the other's state.
3. **Deterministic-first at the eval boundary.** Determinism comes from structured output +
   input-keyed replay + reasoning effort — **not temperature** (rejected on both Anthropic models).
   The Orchestrator is pure code (no model). The Judge decides most verdicts with reused oracles
   (PHI regex, citation-grounding, cross-patient, cost); the semantic LLM layer handles only residue.
4. **Findings are discovered, not hardcoded.** Seed vulns (V1 local-file-read, V2 cross-patient, V5
   feedback loop) exist only as ground truth / regression seeds. They are runtime inputs, never
   wired-in constants. Don't "shortcut" a detector by special-casing a known finding.
5. **`/contracts` schemas are versioned and frozen.** The inter-agent JSON Schemas in `contracts/v1/`
   are the graph's edges. Changing a v1 schema is a breaking change — add a new version, don't mutate
   v1. `tests/test_contracts_api.py` and `tests/_contract_ids.py` guard this.
6. **Secrets stay in `.env`** (gitignored, never committed). `.env.example` is the placeholder
   template — keep it in sync when you add a config key. See `agentforge/config.py`.

## The four agents (see `ARCHITECTURE.md` / `docs/AGENT_INTERACTION.md`)

| Agent | Model | Role |
|---|---|---|
| Orchestrator | deterministic code | reads coverage/findings/budget, decides next target, halts on cost-without-signal |
| Red Team | Kimi K2.6 (Moonshot) | generates + mutates novel attacks; never grades its own work |
| Judge | oracles + Claude Sonnet 5 | deterministic-first verdicts; owns ground truth by `correlation_id` |
| Documentation | Claude Opus 4.8 | confirmed exploits → vuln reports; human-gated on critical severity |

Framework is **LangGraph** (D2): a checkpointable typed state graph; checkpointing doubles as the
regression replay/resume substrate.

## Commands

```bash
# Setup (Python >= 3.11)
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'          # installs pydantic, langgraph, jsonschema, python-dotenv + pytest

# Test — the primary gate. pytest config lives in pyproject.toml (testpaths=tests, -q)
pytest                            # full suite (23 test modules)
pytest tests/test_deterministic_judge.py   # one module
pytest -k contracts               # by keyword
```

TDD is the norm here — tests exist for config, contracts, judge, orchestrator, eval runner, replay.
Add/extend a test with any behavior change; keep the suite green before committing.

**Executing a plan test-first:** use the **`/tdd-loop`** skill. It's the intended way to build out a
PRD/spec/plan-mode output here — it decomposes the plan into tickets, freezes tests from each
ticket's acceptance criteria, dispatches coding sub-agents to make those frozen tests pass (agents
never edit the tests), and loops until green. Trigger it explicitly (`/tdd-loop`) or by intent
("loop sub-agents through these tickets", "build this out test-first"). It manages a ticket board at
`.tdd-loop/board.json`.

## Code layout

```
agentforge/
  config.py            # env-driven config (models, target URL, keys) — mirrors .env.example
  graph.py             # LangGraph state graph wiring
  orchestrator.py      # deterministic Orchestrator (no model)
  contracts/           # pydantic models for the v1 message schemas (common/directive/result/verdict/errors)
  judge/               # base + deterministic-first judge + oracles
  store/               # SQLite exploit store (base/records/sqlite_store)
  evals/               # eval case model + runner (replay suite)
contracts/v1/          # the frozen JSON Schemas themselves (source of truth for edges)
evals/                 # adversarial case template + cases
tests/                 # pytest suite — mirrors the package
```

## Conventions

- Python 3.11+, pydantic v2 for all contract/message types, `jsonschema` for schema validation.
- Everything keyed by `correlation_id` for trace/verdict/report correlation (Langfuse observability).
- Commit style: Conventional Commits (`feat:`, `chore:`, …), often with a `TRO-###` Linear ref.
- Match surrounding code; don't introduce new deps without reason (deps are intentionally minimal).

## Git remotes — pushes go to two places

`git push` mirrors to **both** GitHub and the GauntletAI GitLab in one command:

- `origin` — fetches from GitHub, **pushes to both** GitHub + `labs.gauntletai.com`
- `gitlab` — separate handle for `labs.gauntletai.com` only

So a plain `git push` fans out. If you need one target only: `git push gitlab main` (GitLab only).
Because it's a two-target push, read the output — if one remote rejects, the other may still succeed.
