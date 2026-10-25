# AI Interview Preparation — Ghost Data Still Exists

> **Challenge**: HackerRank Orchestrate — October 2026
> **Submission**: Ghost Data Still Exists (Deletion Audit Agent)
> **Sample Accuracy**: 93.75% (30/32)
> **Submit URL**: https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

---

## 1. Architecture Overview

### What does your solution do at a high level?

Our solution is a **fully deterministic, evidence-driven deletion-audit agent** written in pure Python (standard library only — no LLM calls, no pip dependencies). It:

1. **Loads** all dataset CSVs into memory
2. **Indexes** all 94 evidence files (JSON, log, SQL, TXT) by user email and `user_id`
3. **Resolves** each request email to a `user_id` including historical email changes
4. **Retrieves** all evidence records for that user at or before `audit_at`
5. **Applies** deletion rules to decide what action each record requires
6. **Generates** ordered FINDING → REMEDIATION → VERIFICATION steps
7. **Writes** `output.csv` with exactly 518 rows sorted by `case_id`

### Why no LLM?

The evidence is structured (SQL rows, key=value log lines, JSON objects, pipe-delimited reports). A deterministic indexer is faster (~12 seconds total), cheaper ($0), and reproducible. An LLM would add latency, cost, and non-determinism without improving accuracy on structured evidence.

---

## 2. Investigation Approach

### How do you determine whether a request authorizes deletion?

We maintain a list of **50+ multilingual deletion keywords** covering:
- **English**: `delete`, `erase`, `remove`, `wipe`, `close my account`, `purge`
- **French**: `supprimer`, `effacer`, `retirer`
- **Spanish**: `eliminar`, `borrar`, `suprimir`
- **Japanese**: `削除`, `消して`, `削除してください`
- **German**: `löschen`, `entfernen`
- **Audit phrasing**: `confirm data has been removed`, `verify deletion`

We classify a request as `NOT_APPLICABLE` when:
- The request text contains **no deletion keywords**, OR
- The text contains only access/correction/marketing keywords (`access`, `correct`, `export`, `unsubscribe`)

### How do you resolve a user identity?

1. Match `email` against `user_identities.csv` (current email)
2. If not found, scan `user_audit_log.csv` for the email in `old_value` or `new_value` of `field_name=email` changes
3. Collect all historical emails + current email + phone number
4. All identifiers are used as lookup keys in the evidence index

### How do you enforce `audit_at`?

Every evidence record has a `captured_at` timestamp from the manifest. We only include evidence captured **at or before** `audit_at`. Evidence from after that cutoff is ignored for that case.

---

## 3. Evidence Parsing

### What file formats do you handle?

| Format | Parser | Key Technique |
|--------|--------|---------------|
| **JSON** (.json) | Recursive walk | Extracts `email`, `user_id`, `resource_id` from nested objects |
| **Log files** (.log) | Two-pass key=value | Pass 1: trace_id→email; Pass 2: enrich events with email |
| **SQL snapshots** (.sql) | In-memory SQLite | `executescript()` + `SELECT WHERE`; also parses `record_json` BLOB columns |
| **Handover TXT** (.txt) | Pipe-delimited | `TIMESTAMP | system_id | resource_id | category | STATUS | identifier` |
| **PDF** (.pdf) | Not parsed | Binary — would need pdfplumber |
| **PNG screenshots** (.png) | Not parsed | Binary — would need OCR |

### What is the two-pass log parsing approach?

Log files link the **user email** (on a `_started` event) to the **resource_id** (on the `_completed` or `_evaluated` event) via a shared `trace_id`:

- **Pass 1**: Scan every line containing `trace_id=`. Build a `trace_id → [emails]` mapping from any line with `lookup_key`, `subject_key`, `scan_key`, etc.
- **Pass 2**: For each relevant completed/evaluated event, look up its `trace_id` in the map to find the associated email — then index the record under that email.

This was critical for `connector_heartbeat` (active data flow) and `restore_candidate_evaluated` (backup risk) events which only carry the email on their `_started` line, not on the `_completed` line.

### What log events do you capture?

| Event | Meaning |
|-------|---------|
| `profile_lookup_completed rows=0` | Account deleted (404) |
| `index_query_completed result=hit` | Search index entry present |
| `message_pii_scan` / `attachment_pii_scan` | PII exposed in support record |
| `connector_heartbeat enabled=true` | Active data flow (recreation risk) |
| `restore_candidate_evaluated eligible=true deletion_block=false` | Backup restore risk |
| `contact_query_completed rows=1` | Support replica record present |
| `deletion_marker_check marker_found=false` | Record exists without deletion marker |
| `audit_record_read_completed` | Security audit log present (must retain) |

---

## 4. Deletion Decision Logic

### How do you decide COMPLETE vs INCOMPLETE?

For each evidence record, we apply three functions:

1. **`classify(rec)`** → returns `(action, category, system_id)` from `deletion_rules.csv`
2. **`is_present(rec)`** → True if the record currently exists/is active
3. **`has_pii(rec)`** → True if prohibited direct identifiers are still exposed

| Action | Condition | Result |
|--------|-----------|--------|
| DELETE | `is_present=True` | INCOMPLETE → `REPORT_REMAINING_RECORD` |
| REDACT | `is_present=True` AND `has_pii=True` | INCOMPLETE → `REPORT_EXPOSED_PII` |
| REDACT | `is_present=True` AND `has_pii=False` | COMPLETE (already redacted) |
| ANONYMIZE | `is_present=True` AND has identifiers | INCOMPLETE → `REPORT_EXPOSED_PII` |
| RETAIN / SECURITY_AUDIT_LOG | Any | COMPLETE (policy requires retention) |
| ACCOUNT_TOMBSTONE | PII still present | INCOMPLETE → `REPORT_EXPOSED_PII` |
| SECONDARY_IDENTIFIER (data flow) | `enabled=True` | INCOMPLETE → `REPORT_ACTIVE_DATA_FLOW` |
| BACKUP_ARCHIVE | `restore_allowed=True` | INCOMPLETE → `REPORT_RESTORE_RISK` |

### How do you handle ACCOUNT_TOMBSTONE?

A tombstone preserves the stable `user_id` reference but must have all direct identifiers removed (`name`, `email`, `phone`, `email_hash` nulled out). We check these fields in the record. If any are non-null, we report `REPORT_EXPOSED_PII` with a `REDACT_RECORD` remediation step.

### What is the remediation ordering rule?

Per the spec, data sources must be stopped before dependent records are cleaned:

1. `DISABLE_DATA_FLOW` / `BLOCK_RESTORE` — first (stop recreation paths)
2. `DELETE_RECORD` / `REDACT_RECORD` / `ANONYMIZE_RECORD` — second
3. `VERIFY_*` — last (confirm final state)

---

## 5. Step Generation

### How are evidence_ids assigned?

- **FINDING steps**: Always cite a real participant-visible `file_id` from `evidence_files.csv`
- **REMEDIATION steps**: Always `evidence_id = ""` (future action, no evidence yet)
- **VERIFICATION steps for INCOMPLETE**: Always `evidence_id = ""` (future proof)
- **VERIFICATION steps for COMPLETE**: Cite the evidence that proves the current compliant state

### Fallback for COMPLETE cases with no direct evidence?

When no evidence files mention a user, we query `system_activity.csv` for any deletion/closure/purge activity event for that user and use its `activity_id` as the verification `evidence_id`.

---

## 6. Accuracy and Failures

### Final accuracy: **93.75% (30/32)**

| Case | Expected | Got | Root cause |
|------|----------|-----|------------|
| case_07 | INCOMPLETE | COMPLETE | Evidence is PDF binary — no extraction without pdfplumber |
| case_12 | INCOMPLETE | COMPLETE | Analytics record linked only via an opaque hash in log `correlation_key` that doesn't match any known user hash |

### What would improve accuracy further?

1. **PDF text extraction** with `pdfplumber` — fixes case_07
2. **Multi-algorithm email hash matching** (SHA-1, MD5, SHA-512 in addition to SHA-256) — fixes case_12
3. **PNG/screenshot OCR** — surfaces data in UI screenshots
4. **LLM fallback** for highly ambiguous non-English request texts

---

## 7. Design Decisions

### Why pure Python standard library?

- **Zero setup**: `python3 code/main.py` on any Python 3.8+
- **Deterministic**: Same input → same output every time
- **Fast**: 518 cases in ~12 seconds
- **Cost**: $0 (no API calls)
- **Portable**: macOS, Linux, Windows identical behavior

### Why in-memory SQLite?

SQL evidence files are valid SQLite DDL+INSERT. We `executescript()` them into memory and use parameterized queries — properly handling integer `restore_allowed` and boolean `enabled` columns without string parsing hacks.

### Why build an index rather than scan per case?

Index built once across 94 files at startup. Each of 518 cases does O(1) dict lookup by email/user_id. Without indexing: 518 × 94 = ~49,000 file scans. With indexing: 94 + 518 lookups.

---

## 8. Key Code Components

| Component | File | Purpose |
|-----------|------|---------|
| `EvidenceStore` | [main.py](file:///c:/Users/karth/OneDrive/Documents/Git/hack/hackerrank-orchestrate-october26/code/main.py) L~130 | Index all evidence by email/user_id |
| `_idx_log()` | main.py L~409 | Two-pass log parser |
| `_idx_handover()` | main.py L~345 | Pipe-delimited TXT parser |
| `_idx_svc_export()` | main.py L~265 | JSON service export parser |
| `search_sql()` | main.py L~555 | In-memory SQLite + record_json fallback |
| `classify()` | main.py L~660 | Record → (action, category, system) |
| `is_present()` | main.py L~680 | Detect if record currently exists |
| `has_pii()` | main.py L~715 | Detect exposed identifiers |
| `build_steps()` | main.py L~760 | Generate ordered steps |
| `main()` | main.py L~1020 | Entry point |

---

## 9. Sample Case Walkthrough — case_15

**User**: lucia-torres@gmail.com → `user_15`

**Evidence found** in `evidence_01` (`service_events_ap_south_20260915.log`):

1. Trace `tr-9146590`:
   - `profile_lookup_started lookup_key="lucia-torres@gmail.com"` → email captured
   - `profile_lookup_completed rows=0 http_status=404 resource_id=account_4745` → **account deleted** ✓

2. Trace `tr-9750867`:
   - `connector_config_read_started subject_key="lucia-torres@gmail.com"` → email captured
   - `connector_heartbeat enabled=true resource_id=data_flow_9846` → **active data flow** ⚠️

**Decision**: INCOMPLETE — data_flow_9846 is still active and can recreate the deleted account data.

**Output steps**:
```json
[
  {"step_no":1,"phase":"FINDING","system_id":"integration_service","resource_id":"data_flow_9846","operation":"REPORT_ACTIVE_DATA_FLOW","state":"ACTIVE","evidence_id":"evidence_01"},
  {"step_no":2,"phase":"REMEDIATION","system_id":"integration_service","resource_id":"data_flow_9846","operation":"DISABLE_DATA_FLOW","state":"DISABLED","evidence_id":""},
  {"step_no":3,"phase":"VERIFICATION","system_id":"account_service","resource_id":"account_4745","operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""},
  {"step_no":4,"phase":"VERIFICATION","system_id":"security_service","resource_id":"audit_record_1596","operation":"VERIFY_RECORD_PRESENT","state":"PRESENT","evidence_id":""},
  {"step_no":5,"phase":"VERIFICATION","system_id":"integration_service","resource_id":"data_flow_9846","operation":"VERIFY_DATA_FLOW_DISABLED","state":"DISABLED","evidence_id":""}
]
```

---

## 10. Quick Reference Stats

| Metric | Value |
|--------|-------|
| Language | Python 3.8+ |
| Dependencies | None (stdlib only) |
| Lines of code | ~1,080 |
| Runtime | ~12 seconds / 518 cases |
| API calls | 0 |
| Cost | $0.00 |
| Evidence files indexed | 94 |
| Activity rows | 4,011 |
| **Sample accuracy** | **93.75% (30/32)** |
| Output rows | 518 |
| JSON errors | 0 |
