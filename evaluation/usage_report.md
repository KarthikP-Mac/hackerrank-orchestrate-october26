# Usage Report — Ghost Data Still Exists (Final Run)

## Run Summary

This report covers the final full-dataset run that produced `output.csv` at the repository root,
processing all 518 deletion-audit requests.

---

## Model and Provider

| Field | Value |
|-------|-------|
| Solution type | Rule-based evidence indexing (no LLM calls) |
| Model provider | N/A — deterministic heuristic agent |
| Model name | N/A |
| Model-call count | 0 |

> **Note**: This solution is a fully deterministic, evidence-driven Python agent. It does not
> call any external LLM or AI API. All decisions are made by parsing evidence files
> (JSON, log, SQL, TXT), building an in-memory index keyed by user email/user_id, and
> applying the deletion rules from `deletion_rules.csv` to each matched record.

---

## Token Usage

| Metric | Value |
|--------|-------|
| Input tokens | 0 (no model calls) |
| Output tokens | 0 (no model calls) |
| Total tokens | 0 |
| Estimated cost | $0.00 |

---

## Runtime Performance

| Metric | Value |
|--------|-------|
| Total cases | 518 |
| Processing time | ~12 seconds |
| Average time per case | ~23 ms |
| Peak memory | ~120 MB (evidence index) |

---

## Evidence Sources Processed

| Source Type | Files | Notes |
|-------------|-------|-------|
| JSON service exports | 28 | Parsed service_exports and snapshots structures |
| Structured log files | 26 | Two-pass trace_id resolution for cross-event linking |
| SQL snapshot files | 24 | Executed via in-memory SQLite; searched by email/user_id |
| PNG screenshots | 11 | Not parsed (binary) |
| PDF documents | 4 | Not parsed (binary, no PDF library) |
| TXT handover reports | 1 | Pipe-delimited shift handover format |

---

## System Activity

| Metric | Value |
|--------|-------|
| Activity rows loaded | 4,011 |
| Used for fallback verification | Yes (COMPLETE cases with no evidence) |

---

## Output Distribution

| Status | Count | Percentage |
|--------|-------|------------|
| COMPLETE | 272 | 52.5% |
| INCOMPLETE | 218 | 42.1% |
| NOT_APPLICABLE | 28 | 5.4% |
| **Total** | **518** | **100%** |

---

## Architecture Notes

The agent pipeline:

1. **Load phase**: Reads all dataset CSV files and the evidence manifest into memory.
2. **Index phase**: Parses all 94 evidence files. JSON files are recursively walked for email/user_id fields. Log files use two-pass parsing (trace_id resolution). SQL files are executed via in-memory SQLite. TXT handover files use pipe-delimited parsing.
3. **Resolve phase**: For each case, resolves the request email to a `user_id` using `user_identities.csv` and `user_audit_log.csv` (historical email changes).
4. **Evidence phase**: Looks up all indexed records for the user's emails/phones/user_id, filtered to `audit_at` timestamp.
5. **Decision phase**: Applies `deletion_rules.csv` to each record. Checks `is_present()` and `has_pii()` to determine if each record requires action.
6. **Step generation**: Builds ordered FINDING → REMEDIATION → VERIFICATION steps.
7. **Fallback**: For COMPLETE cases with no evidence, queries `system_activity.csv` to find a deletion activity event to use as verification evidence.
