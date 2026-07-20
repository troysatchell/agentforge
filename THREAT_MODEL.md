# THREAT MODEL — OpenEMR Clinical Co-Pilot

*The attack-surface map AgentForge continuously exercises. A **living document**: the platform's
Judge feeds confirmed findings back as new rows, and every fix is re-validated against it.*

Target: the deployed Clinical Co-Pilot (`https://openemr-production-4eba.up.railway.app`, demo data
only). Evidence is `file:line`-grounded to the target repo; three findings are **confirmed live**.

---

## Executive summary (~500 words)

The Clinical Co-Pilot is an AI feature inside OpenEMR exposed as **seven OAuth2-guarded HTTP routes**
(`/api/copilot/*`) plus a **session AJAX path**. Its LLM calls — Anthropic `claude-opus-4-8` for the
answer turn and for document (VLM) extraction, Cohere embed/rerank for guideline retrieval — sit
**outside the trust boundary**: the model receives minimum-necessary fields and its output is
untrusted until grounded. The primary structural defense is **citation-grounding**: every answer
claim must resolve against a freshly-minted reference index over the **live** chart, and any claim
whose citation does not verify is stripped to text-only. This makes "inject a fabricated *clinical
fact*" genuinely hard — but it does nothing against exfiltration, cost, or authorization attacks,
which is where the real risk concentrates.

**Key findings — three confirmed live against the deployed target:**

- **V1 (HIGH) — authenticated arbitrary-file-read → VLM exfiltration.** `POST /document` accepts a
  caller-supplied server `file_path`, validated by *extension only* (no path-traversal guard, no
  allowlisted directory), then `file_get_contents` reads it, streams it to the VLM, and attaches it
  to a patient chart. Any readable file ending in `.pdf/.png/.jpg/.jpeg` is disclosed.
- **V2 (HIGH) — cross-patient via the un-launch-bound session path.** `ajax.php` is not
  launch-bound, so an authenticated physician session can drive turns/uploads against **any**
  `patient_uuid` (the known TRO-51 gap). Confirmed deployed and executing.
- **V5 (MEDIUM) — indirect context poisoning.** A VLM-extracted numeric value persists as a derived
  lab and **re-enters later turn prompts with no provenance flag** — the model cannot distinguish an
  attacker-planted value from a lab-verified result.

**Highest-risk categories:** **Data exfiltration** (V1 is arbitrary server-file read — the single
strongest finding) and **Identity/role exploitation** (V2 cross-patient). **Denial-of-service** is
*systemically* open: no inbound rate limit, no per-user/session cost budget anywhere, and turn input
is uncapped — cost is *recorded* but never *enforced*. **State corruption** (V5 + client-supplied
`prior_turns`) is the subtlest, most AI-specific class. **Direct prompt injection** is the
best-defended (grounding), but remains a priority to *probe* because grounding is the linchpin —
if it breaks, fabricated clinical guidance reaches a physician.

**How the platform prioritizes coverage.** Each category is ranked by
`(confirmed > hypothesis) × severity × exploitation-ease × defense-absence`. That ordering puts
**data-exfiltration** and **broken-access/identity** first (confirmed, severe, easy, under-defended),
**DoS/cost** second (systemic, trivial, undefended), **state-corruption / indirect injection** third
(subtle, partially defended, confirmed loop), and **direct prompt injection** last for *volume* but
retained as a standing probe of the grounding defense. The Orchestrator reads live coverage counts
and open findings from the observability store and directs the Red Team at the highest-value
under-tested category each cycle; a confirmed exploit becomes a regression case pinned by its
`predicate_fired`, so a later "fix" only passes if the exploit's *signal* is actually gone — not
merely because model behavior drifted. The threat model is exercised, not filed: it is the coverage
map the Orchestrator prioritizes against and the Judge validates fixes against.

---

## 1. Target overview & trust boundary

**Routes (all `/apis/default/api/copilot/*`; OAuth2 Bearer + module default-deny ACL):**

| Route | ACL / scope | Input | LLM? | Relevance |
|---|---|---|---|---|
| `GET ping/health/ready` | `patients/demo` | — | no | `/ready` = dependency probes |
| `POST /turn` | `patients/med` | `patient_uuid`, **`question`**, **`prior_turns[]` (client-supplied)**, `ask_evidence` | yes (Anthropic) | primary injection + cost surface; launch-bound |
| `POST /snapshot` | `patients/med` | `patient_uuid` | no | launch-bound (TRO-52) |
| `POST /document` | `patients/med` | `patient_uuid`, `doc_type`, content-b64 **or** `file_path` | yes (VLM) | indirect-injection + the two writes; **V1** |
| `POST /source` | `patients/med` | `token`, `patient_uuid` | no | citation resolution; returns full doc bytes |

Second surface: **session AJAX** (`public/index.php` → `ajax.php`, CSRF + `SessionGate`) — **not
launch-bound** → free-form `patient_uuid` (**V2**).

**Trust boundary.** The OpenEMR instance is the boundary; the **LLM is outside it** (no credentials,
no DB, minimum-necessary fields only). Governing rules the model operates under:
- **Chart content & uploaded documents are untrusted free text** — "data, never instructions."
- **The model's own prior output is not a source** — every turn re-grounds against the live chart.
- **LLM/VLM output is a draft** — untrusted until grounded/parsed into typed fields.
- **The deterministic critical subset bypasses the model entirely** (panic labs, drug-drug,
  drug-allergy, open follow-ups are code, not model salience).

**Structural defenses in place:** citation-grounding (fabricated cited facts stripped to text-only),
minimum-necessary field allowlist, pre-call PHI **disclosure logging**, `/source` anti-enumeration
(identical error for cross-patient vs unknown), launch-patient binding on REST clinical routes,
PDF.js `isEvalSupported:false`.

---

## 2. Attack surface by category (the six)

Rubric for the two judged dimensions is in the Appendix. Each category lists: **Surface · Impact ·
Exploitation difficulty · Existing-defense coverage · Findings · OWASP · Status.**

### 2.1 Prompt injection — direct / indirect / multi-turn
- **Surface:** direct = free-form `question`; indirect = uploaded document text → VLM extraction;
  multi-turn = client-supplied `prior_turns[]`.
- **Impact:** fabricated clinical guidance shown to a physician (high clinical impact) — *if* it can
  be made to appear grounded.
- **Exploitation difficulty:** **High** to produce a *grounded* fabrication (must defeat fresh
  reference-index verification against the live chart); **Low** to get instruction text *accepted as
  data* (trivial, but inert on its own).
- **Existing-defense coverage:** **Strong** — "data not instructions" system prompt + citation
  grounding + rejected-claims-are-text-only. *Partial gap:* injected text can still pollute a
  free-text value that persists (→ 2.3 / V5).
- **Findings:** V4 (`prior_turns` channel); the two committed golden cases
  (`injection-vlm-embedded-instructions-inert`, `injection-extracted-field-steering-rejected`).
- **OWASP:** LLM01 prompt injection. **Status:** best-defended; probed continuously as a grounding-bypass hunt.

### 2.2 Data exfiltration — PHI leak / cross-patient / authorization bypass
- **Surface:** `/document` **`file_path`** (V1); `/source` returns **full document bytes** (V6);
  cross-patient via the session path (V2); `question` text to Cohere as a second processor (V8).
- **Impact:** **arbitrary server-file disclosure** to the LLM vendor *and* into a patient chart (V1);
  cross-patient PHI exposure (V2). Highest-impact class.
- **Exploitation difficulty:** **Low** — V1 is a single authenticated POST with an allowed-extension
  path; V2 is an authenticated session + a free-form uuid.
- **Existing-defense coverage:** **Partial/None** — launch-binding covers the REST clinical routes but
  **not `ajax.php`**; `/source` has anti-enumeration; disclosure logging *records* but does not
  *prevent*. **No path-traversal guard, no allowlisted upload dir.**
- **Findings:** V1 (confirmed), V2 (confirmed present), V6, V8.
- **OWASP:** Web A01 broken access control; LLM06 sensitive-information disclosure. **Status:
  HIGHEST RISK.**

### 2.3 State corruption — conversation-history manipulation / context poisoning
- **Surface:** client-supplied `prior_turns[]` (history manipulation, V4); a persisted VLM-extracted
  value re-entering later turn prompts (context poisoning, V5).
- **Impact:** an attacker plants a numeric "lab value" via an uploaded document; it resurfaces in
  future turns as an ordinary lab **with no provenance/preliminary flag**, so the model — and the
  physician reading a grounded answer — cannot tell it from a verified result.
- **Exploitation difficulty:** **Medium** (V5 needs a crafted upload with a numeric analyte; the loop
  is confirmed live); **Low** but low-impact for V4.
- **Existing-defense coverage:** **Partial** — grounding re-runs each turn (so a poisoned value must
  become a real chart row, which V5's persistence achieves); "prior turns are never a source of
  fact." *Gap:* no provenance flag reaches the model; derived writes have **no dedup** (V7).
- **Findings:** V5 (confirmed live), V4, V7.
- **OWASP:** LLM01 (indirect injection); insecure design. **Status:** subtle, AI-specific, partial defense.

### 2.4 Tool misuse — unintended invocation / parameter tampering / recursive calls
- **Cover-with-evidence:** *model-invoked* tool misuse is **foreclosed by design** — the co-pilot's
  LLM has **no function-calling**; it returns a constrained JSON-schema completion and cannot invoke
  reads, writes, or tools. Orchestration is deterministic server-side (hard-fixed supervisor state);
  the two writes fire only from the explicit `/document` route. The real surface is therefore
  **client-controlled request parameters**, not model-chosen tool args.
- **Surface:** `file_path` (V1), `ask_evidence` (V3 — toggles embed+rerank: tool/cost amplification),
  `prior_turns` (V4).
- **Exploitation difficulty:** N/A for model-invoked (foreclosed); see V1/V3 otherwise.
- **Existing-defense coverage:** **Strong (structural)** — no agency is granted to the model.
- **OWASP:** LLM07 excessive agency (foreclosed). **Status:** foreclosed at the model; client-param surface real.

### 2.5 Denial of service — token exhaustion / infinite loops / cost amplification
- **Surface:** **uncapped `question` + `prior_turns` length** (confirmed no length cap in
  `TurnEndpoint`); `ask_evidence:true` → embed+rerank each turn; `/document` accepts up to 10 MiB
  (path-mode size self-declared, unverified).
- **Impact:** an authenticated caller drives **unbounded LLM/embed/rerank spend**; slow, expensive turns.
- **Exploitation difficulty:** **Low** — long payloads / repeated calls by a single authenticated caller.
- **Existing-defense coverage:** **None at the enforcement layer** — cost is *recorded* in the trace
  but never *capped*; output is capped at 2048 tokens but **input is uncapped**; the circuit breaker
  is per-process (no cross-request state); **no inbound rate limit** on any route. No server-side
  autonomous loop, so "infinite loop" is client-driven.
- **Findings:** V3 (confirmed uncapped input); the substrate gaps generally.
- **OWASP:** LLM10/LLM04 unbounded consumption; Web insecure design. **Status:** systemically open, easy, undefended.

### 2.6 Identity & role exploitation — privilege escalation / persona hijacking / trust-boundary
- **Surface:** patient-scope (V2 / TRO-51 — the client holds physician-wide `user/*` scopes and the
  target patient is a free-form `patient_uuid`); persona-hijack attempts via `question`/`prior_turns`;
  trust-boundary probing (does injected text ever cause a boundary crossing?).
- **Impact:** cross-patient access (V2, high); persona hijack (low — grounding resists).
- **Exploitation difficulty:** **Low** for V2 (via the un-bound session path); **Med-High** for
  persona hijack (grounding + "prior turns not a source" resist it).
- **Existing-defense coverage:** **Partial** — launch-binding on REST routes (not `ajax.php`); ACL
  `patients/med`. Privilege escalation *within* the OpenEMR ACL is a **core danger-zone → report, not fix**.
- **Findings:** V2. **OWASP:** Web A01; LLM. **Status:** high (cross-patient); report-only for core priv-esc.

---

## 3. Findings register

`file:line` evidence and live-confirmation detail are maintained in the target-repo orientation
(`WEEK3_REDTEAM_ORIENTATION.md` §C/§C.live). Summary:

| # | Finding | Category | OWASP (web / llm) | Severity | Exploit difficulty | Defense coverage | Status |
|---|---|---|---|---|---|---|---|
| **V1** | `/document` path-mode arbitrary-file-read → VLM + chart | data_exfiltration | A01 / LLM06 | High | Low | None (no traversal guard) | **Confirmed live** |
| **V2** | `ajax.php` cross-patient (not launch-bound) | identity_role_exploitation | A01 / — | High | Low | Partial (REST bound, session not) | **Confirmed present** |
| **V3** | Uncapped input + no cost/rate enforcement | denial_of_service | Insecure design / LLM10 | Med-High | Low | None | **Confirmed (no cap)** |
| **V4** | Client-controlled `prior_turns` injection | state_corruption / prompt_injection | — / LLM01 | Low-Med | Low | Strong (grounding) | Hypothesis |
| **V5** | Extracted-value → chart → later-prompt poisoning | state_corruption | Insecure design / LLM01 | Med | Med | Partial (no provenance flag) | **Confirmed live (numeric)** |
| **V6** | `/source` returns full document bytes | data_exfiltration | Insecure design / LLM06 | Low-Med | Low | Partial (ownership-checked) | Hypothesis |
| **V7** | Derived-observation write has no dedup | state_corruption | Insecure design / — | Low-Med | Low | None | Confirmed (design) |
| **V8** | `question` text to Cohere (2nd processor) | data_exfiltration | — / LLM06 (supply-chain) | Low | n/a | By-design (disclosed) | Confirmed (design) |

Each confirmed exploit becomes a regression case (`evals/`) pinned by a deterministic
`predicate_fired`, so a fix passes only when the *signal* is gone.

---

## 4. Coverage prioritization

Ranking function: `priority = confirmed_weight × severity × exploitation_ease × defense_absence`.

1. **Data exfiltration** (V1) — confirmed, high, easy, undefended → **first**.
2. **Identity/role — cross-patient** (V2) — confirmed, high, easy, partial → **first**.
3. **Denial of service / cost** (V3) — systemic, easy, undefended → **second**.
4. **State corruption / indirect injection** (V5) — confirmed loop, medium, partial → **third**.
5. **Prompt injection (direct/multi-turn)** — well-defended by grounding → **standing probe**
   (lower volume, but never dropped: grounding is the linchpin defense, so a bypass is high-value).
6. **Tool misuse** — model path foreclosed → covered-with-evidence; client-param surface folds into V1/V3.

The **Orchestrator** reads live per-category coverage counts + open findings + recent regressions
from the observability store and issues the next `AttackDirective` at the highest-value under-tested
category; it halts a campaign when cost accrues without signal (`budget_exceeded`).

---

## 5. Living-document loop

1. Red Team generates/mutates against the live target → 2. Judge adjudicates (recomputing signals
independently) → 3. a confirmed exploit is stored (versioned, queryable) and **added here** as a
finding row + as a regression case → 4. a fix ships to the target (new `target_version`) → 5. the
Orchestrator triggers a regression run; the Judge re-adjudicates; reappearance or a cross-category
regression is flagged, and this document's Status column is updated. The threat model never goes stale
because the platform is what keeps exercising it.

---

## Appendix — rating rubric

**Exploitation difficulty**
- **Low** — a single authenticated request or a trivially-authored input; no defense to defeat.
- **Medium** — requires a crafted multi-step sequence or a specific precondition (e.g. a persisted
  upload), but no novel technique.
- **High** — must defeat an active structural defense (e.g. citation grounding) or chain conditions.

**Existing-defense coverage**
- **None** — no control addresses this surface (enforcement absent).
- **Partial** — a control exists but has a gap (covers one surface/route, not another; records but
  doesn't prevent).
- **Strong** — a structural control materially blocks the class (e.g. grounding vs fabricated facts;
  no model function-calling vs excessive agency).

*All findings require an authenticated `patients/med` principal (a valid launch-bound token, or an
authenticated session for the `ajax.php` path). The platform obtains one by driving the SMART launch
chain — it never bypasses auth, never uses a service account, never touches core.*
