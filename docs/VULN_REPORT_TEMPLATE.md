# Vulnerability Report Template (Documentation-Agent output)

The format the Documentation Agent produces for every confirmed exploit — **without a human writing
it**. The bar: *a senior security engineer who was not present could reproduce, validate, and fix the
vulnerability from this alone.*

## Required fields (all mandatory — enforced as a data-quality check before write)

1. **Unique identifier + severity** — `AF-YYYY-NNN`; severity ∈ critical/high/medium/low.
2. **Description + clinical impact** — what the vuln is and why it matters to a physician/patient.
3. **Minimal reproducible attack sequence** — the smallest `input_sequence` that triggers it,
   against a named `target_version`.
4. **Observed vs expected behavior** — what happened; what a non-vulnerable target does.
5. **Recommended remediation** — a concrete fix direction (advisory only — the platform never patches).
6. **Current status + fix-validation results** — open/in-progress/resolved; regression outcome.

**Data-quality rules (validated before the report is written):** unique `id`; all six fields present
and non-empty; **no duplicate report for the same `sequence_hash`**; `attack_category` ∈ the canonical
six; `target_version` present.

**Human gate:** low/medium reports auto-file; **critical-severity requires human approval before
publish** (mirrors the target's "human owns irreversible calls" line).

---

## Template

```markdown
# AF-YYYY-NNN — <short title>

- **Severity:** <critical|high|medium|low>
- **Category:** <one of the six> · **OWASP:** <web id> / <llm id>
- **Status:** <open|in-progress|resolved> · **Discovered:** <date> · **Target version:** <sha>
- **Exploit id / sequence_hash:** <ref into the exploit DB>

## Description & clinical impact
<what the vulnerability is; the concrete harm to a patient/physician if exploited>

## Reproduction (minimal)
Auth: <launch-bound token for patient X | authenticated session>. Target: <url @ target_version>.
1. <request 1 — route + minimal payload>
2. <request 2 …>

## Observed vs expected
- **Observed:** <what the target did — the success predicate that fired>
- **Expected (safe):** <what a non-vulnerable target does>

## Recommended remediation (advisory)
<concrete direction; note if it touches a danger-zone → report-only>

## Fix validation
- **Regression case:** `evals/cases/<case_id>.json` (predicate: <success_predicate>)
- **Result:** <not-yet-fixed | fixed @ <sha> — predicate no longer fires | REGRESSED @ <sha>>
```

---

## Worked example (V1)

```markdown
# AF-2026-001 — Authenticated arbitrary server-file read via /document path mode

- **Severity:** high
- **Category:** data_exfiltration · **OWASP:** A01:2021-broken-access-control / LLM06:2025-sensitive-information-disclosure
- **Status:** open · **Discovered:** 2026-07-20 · **Target version:** <deploy sha>
- **Exploit id / sequence_hash:** af-data_exfiltration-local-file-read-001

## Description & clinical impact
`POST /api/copilot/document` accepts a caller-supplied server `file_path`, validated by file
extension only — no path-traversal guard, no allowlisted directory. The service reads the path with
`file_get_contents`, streams the bytes to the VLM vendor, and attaches the file to the target
patient's chart. Any file readable by the app user whose name ends in `.pdf/.png/.jpg/.jpeg` can be
exfiltrated to the LLM provider and injected into a patient record — a PHI/secret disclosure and a
record-integrity break in a clinical system.

## Reproduction (minimal)
Auth: launch-bound token for the authorized patient. Target: <url @ target_version>.
1. `POST /api/copilot/document` with `{ "doc_type":"lab_pdf", "file_path":"<server-file>.pdf", "file_size_bytes":1024, "patient_uuid":"<authorized>" }`

## Observed vs expected
- **Observed:** the foreign file's bytes are read, disclosed to the VLM, and attached to the chart
  (foreign_file_bytes oracle fires).
- **Expected (safe):** path mode rejected over HTTP, or confined to an allowlisted upload dir with
  traversal normalization; no foreign bytes disclosed or attached.

## Recommended remediation (advisory)
Reject path mode on the HTTP surface (browser uses content mode only), or resolve `realpath` and
enforce an allowlisted upload directory; verify declared vs actual size.

## Fix validation
- **Regression case:** `evals/cases/af-data_exfiltration-local-file-read-001.json`
- **Result:** not-yet-fixed (predicate fires on current target_version)
```
