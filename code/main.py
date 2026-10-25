#!/usr/bin/env python3
"""
Ghost Data Still Exists - HackerRank Orchestrate October 2026
Improved AI-powered deletion audit agent v2.
"""

import csv
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DATASET = REPO_ROOT / "dataset"
OUTPUT_CSV = REPO_ROOT / "output.csv"

# Expanded deletion keyword detection
DELETION_KEYWORDS = [
    # English direct
    "delete", "deletion", "erase", "erasure", "erased", "erasing",
    "remove my", "remove the profile", "remove records", "remove any",
    "remove all", "remove personal", "removal", "removing",
    "close my account", "close the account", "closed my account",
    "account closure", "account deleted", "account deletion",
    "wipe", "purge", "right to be forgotten", "right to erasure",
    "gdpr", "permanently", "permanent deletion", "permanent account",
    "data deletion", "account-deletion", "data removed", "data wiped",
    "deleted my account", "deleting my account", "deleting the account",
    "personal data", "personal information", "personal details",
    "my profile", "my account", "clean my personal",
    "clean out", "left behind",
    "removed", "account and", "gone", "no traces",
    "whether the account", "already been removed", "already removed",
    "confirm that the profile", "confirm the profile",
    "profile is gone", "account is gone", "account was deleted",
    "verify that my account", "verify that the account",
    "inspect the actual systems", "inspect the systems",
    "check the actual", "check the latest state",
    "cannot identify me", "no longer identify",
    "audit the deletion", "confirm deletion",
    "traces in search", "traces in support",
    # French
    "supprimez", "supprimer", "suppression", "supprimé", "effacer",
    "suppr", "résiliation",
    # Spanish
    "eliminar", "borrar", "eliminación", "eliminando", "borrado",
    # Japanese
    "削除", "抹消",
    # Other
    "löschen", "verwijderen",
    "verwijdering", "удалить", "حذف",
    "no longer need this account",
    "disconnect", "disconnected",
    "fully removed", "truly gone", "actually deleted",
    "switch off", "can no longer",
    "stop sending my data",
]

NON_DELETION_KEYWORDS_ONLY = [
    "access my data",
    "download my data",
    "export my data",
    "opt out of marketing only",
    "marketing emails only",
    "unsubscribe only",
    "billing question only",
]

SYSTEM_CATEGORY_MAP = {
    "account_service": "USER_PROFILE",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "support_attachment": "SUPPORT_ATTACHMENT",
    "analytics_platform": "ANALYTICS_PROFILE",
    "marketing_platform": "MARKETING_PROFILE",
    "export_service": "USER_EXPORT",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "security_service": "SECURITY_AUDIT_LOG",
    "archive_service": "SECURITY_AUDIT_LOG",
    "backup_service": "BACKUP_ARCHIVE",
    "integration_service": "SECONDARY_IDENTIFIER",
    "profile_service": "USER_PROFILE",
    "notification_service": "EMAIL_DELIVERY_LOG",
    "object_storage": "USER_EXPORT",
    "cache_service": "CACHE_ENTRY",
}

FINDING_OP_ORDER = [
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
]
REMEDIATION_OP_ORDER = [
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
    "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
]
VERIFICATION_OP_ORDER = [
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def parse_iso(ts):
    if not ts:
        return None
    try:
        ts = ts.strip().rstrip("Z")
        if "." in ts:
            ts = ts.split(".")[0]
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def is_deletion_request(request_text):
    """Determine if request_text is a deletion request."""
    text_lower = request_text.strip().lower()
    # Check deletion keywords
    for kw in DELETION_KEYWORDS:
        if kw in text_lower:
            return True
    return False


def resolve_user(email, identities, audit_log):
    """Resolve user_id and all known email/phone identifiers."""
    email_norm = email.strip().lower()
    user_id = None
    for uid, row in identities.items():
        if row.get("email", "").strip().lower() == email_norm:
            user_id = uid
            break
    if user_id is None:
        for entry in audit_log:
            if entry.get("field_name") == "email":
                old_val = (entry.get("old_value") or "").strip().lower()
                new_val = (entry.get("new_value") or "").strip().lower()
                if old_val == email_norm or new_val == email_norm:
                    user_id = entry["user_id"]
                    break
    if user_id is None:
        return None, {email_norm}, set()
    current = identities.get(user_id, {})
    all_emails = set()
    all_phones = set()
    curr_email = (current.get("email") or "").strip().lower()
    curr_phone = (current.get("phone") or "").strip().lower()
    if curr_email:
        all_emails.add(curr_email)
    if curr_phone:
        all_phones.add(curr_phone)
    for entry in audit_log:
        if entry["user_id"] != user_id:
            continue
        field = entry.get("field_name", "")
        old_v = (entry.get("old_value") or "").strip().lower()
        new_v = (entry.get("new_value") or "").strip().lower()
        if field == "email":
            if old_v:
                all_emails.add(old_v)
            if new_v:
                all_emails.add(new_v)
        elif field == "phone":
            if old_v:
                all_phones.add(old_v)
            if new_v:
                all_phones.add(new_v)
    return user_id, all_emails, all_phones


class EvidenceStore:
    """Indexes all non-SQL evidence files for fast lookup by email or user_ref."""

    def __init__(self, manifest):
        self.manifest = manifest
        self._cache = {}
        self._email_index = {}
        self._user_ref_index = {}
        self._built = False

    def _get_content(self, file_id, file_path):
        if file_id in self._cache:
            return self._cache[file_id]
        full = DATASET / file_path
        if not full.exists():
            self._cache[file_id] = None
            return None
        suffix = full.suffix.lower()
        try:
            if suffix == ".json":
                with open(full, encoding="utf-8") as f:
                    c = json.load(f)
            elif suffix in (".log", ".txt"):
                with open(full, encoding="utf-8") as f:
                    c = f.read()
            else:
                c = None
        except Exception:
            c = None
        self._cache[file_id] = c
        return c

    def build_index(self):
        if self._built:
            return
        self._built = True
        skip_ext = {".sql", ".pdf", ".png"}
        for entry in self.manifest:
            fid = entry["file_id"]
            fp = entry["file_path"]
            cat = entry["captured_at"]
            if any(fp.endswith(e) for e in skip_ext):
                continue
            c = self._get_content(fid, fp)
            if c is None:
                continue
            if isinstance(c, dict) and "service_exports" in c:
                self._idx_svc_export(fid, cat, c)
            elif isinstance(c, dict) and "snapshots" in c:
                self._idx_snapshots(fid, cat, c)
            elif isinstance(c, dict):
                self._idx_json_node(fid, cat, c, "root")
            elif isinstance(c, str):
                # Check if it's a pipe-delimited handover report
                if "| account_service |" in c or "| search_service |" in c or "SHIFT HANDOVER" in c:
                    self._idx_handover(fid, cat, c)
                else:
                    self._idx_log(fid, cat, c)

    def _add(self, emails, refs, rec):
        for e in emails:
            if e:
                self._email_index.setdefault(e.strip().lower(), []).append(rec)
        for r in refs:
            if r:
                self._user_ref_index.setdefault(r.strip(), []).append(rec)

    def _idx_svc_export(self, fid, cat, c):
        sx = c.get("service_exports", {})
        for lk in sx.get("account_service", {}).get("profile_lookups", []):
            p = lk.get("profile") or {}
            self._add([e for e in [p.get("email")] if e and "@" in e],
                      [r for r in [p.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "account_service",
                       "resource_id": lk.get("resource_id"), "type": "account_profile",
                       "status_code": lk.get("status_code"), "profile": p, "raw": lk})
        for p in sx.get("analytics_platform", {}).get("profiles", []):
            self._add([e for e in [p.get("email")] if e and "@" in e],
                      [r for r in [p.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "analytics_platform",
                       "resource_id": p.get("resource_id"), "type": "analytics_profile",
                       "profile": p, "raw": p})
        for r in sx.get("backup_service", {}).get("restore_entries", []):
            self._add([e for e in [r.get("customer_email")] if e and "@" in e],
                      [ref for ref in [r.get("customer_reference")] if ref],
                      {"file_id": fid, "captured_at": cat, "system": "backup_service",
                       "resource_id": r.get("resource_id"), "type": "backup_restore",
                       "restore_allowed": r.get("restore_allowed"), "raw": r})
        for e in sx.get("export_service", {}).get("exports", []):
            self._add([em for em in [e.get("owner_email")] if em and "@" in em],
                      [r for r in [e.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "export_service",
                       "resource_id": e.get("resource_id"), "type": "export", "raw": e})
        for conn in sx.get("integration_service", {}).get("connectors", []):
            self._add([e for e in [conn.get("customer_email")] if e and "@" in e],
                      [r for r in [conn.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "integration_service",
                       "resource_id": conn.get("resource_id"), "type": "data_flow",
                       "enabled": conn.get("enabled"), "connector_name": conn.get("connector_name"),
                       "raw": conn})
        for q in sx.get("search_service", {}).get("index_queries", []):
            for d in q.get("hits", {}).get("documents", []):
                self._add([e for e in [d.get("email")] if e and "@" in e],
                          [r for r in [d.get("customer_reference")] if r],
                          {"file_id": fid, "captured_at": cat, "system": "search_service",
                           "resource_id": d.get("resource_id") or q.get("resource_id"),
                           "type": "search_index",
                           "total_hits": q.get("hits", {}).get("total", 0), "raw": d})
        for a in sx.get("security_service", {}).get("audit_records", []):
            self._add([], [r for r in [a.get("subject_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "security_service",
                       "resource_id": a.get("resource_id"), "type": "audit_record",
                       "retention_until": a.get("retention_until"),
                       "event_code": a.get("event_code"), "raw": a})
        for t in sx.get("support_platform", {}).get("tickets", []):
            self._add([e for e in [t.get("requester_email")] if e and "@" in e],
                      [r for r in [t.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "support_platform",
                       "resource_id": t.get("resource_id"), "type": "support_ticket", "raw": t})
        for p in sx.get("marketing_platform", {}).get("profiles", []):
            self._add([e for e in [p.get("email")] if e and "@" in e],
                      [r for r in [p.get("customer_reference")] if r],
                      {"file_id": fid, "captured_at": cat, "system": "marketing_platform",
                       "resource_id": p.get("resource_id"), "type": "marketing_profile", "raw": p})

    def _idx_snapshots(self, fid, cat, c):
        for snap in c.get("snapshots", []):
            ds = snap.get("data_store", "")
            col = snap.get("collection", "")
            col_l = col.lower()
            for rd in snap.get("records", []):
                emails = [v.strip().lower() for k, v in rd.items()
                          if k in ("email", "owner_email", "requester_email") and v and "@" in v]
                refs = [v.strip() for k, v in rd.items()
                        if k in ("subject_reference", "customer_reference", "user_id") and v]
                rtype = ("tombstone" if ("tombstone" in col_l or "deleted_customer" in col_l)
                         else "audit_record" if "audit" in col_l else "snapshot_record")
                self._add(emails, refs,
                          {"file_id": fid, "captured_at": cat, "system": ds,
                           "resource_id": rd.get("resource_id"), "type": rtype,
                           "collection": col, "raw": rd})

    def _idx_json_node(self, fid, cat, node, path, depth=0):
        if depth > 6:
            return
        if isinstance(node, list):
            for i, item in enumerate(node):
                self._idx_json_node(fid, cat, item, f"{path}[{i}]", depth + 1)
        elif isinstance(node, dict):
            emails = []
            refs = []
            rid = node.get("resource_id") or node.get("id")
            for k, v in node.items():
                if v and isinstance(v, str):
                    if k in ("email", "owner_email", "requester_email", "customer_email") and "@" in v:
                        emails.append(v.strip().lower())
                    elif k in ("user_id", "subject_reference", "customer_reference"):
                        refs.append(v.strip())
                    elif k == "resource_id":
                        rid = v
            if emails or refs:
                sys_name = next((s for s in SYSTEM_CATEGORY_MAP if s in path.lower()), "unknown")
                self._add(emails, refs, {"file_id": fid, "captured_at": cat, "system": sys_name,
                                         "resource_id": rid, "type": "generic", "raw": node})
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    self._idx_json_node(fid, cat, v, f"{path}.{k}", depth + 1)

    def _idx_handover(self, fid, cat, content):
        """Parse pipe-delimited handover/shift-report txt files.
        Format: - TIMESTAMP | system_id | resource_id | category | STATUS | identifier
        STATUS: NOT_FOUND, FOUND, IDENTIFIABLE, ACTIVE, DISABLED, BLOCKED, ANONYMIZED, REDACTED
        """
        for line in content.split("\n"):
            line = line.strip()
            if not line.startswith("-"):
                continue
            parts = [p.strip() for p in line.lstrip("- ").split("|")]
            if len(parts) < 6:
                continue
            ts, system_id, resource_id, category, status, identifier = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            if not resource_id or not identifier:
                continue

            emails = []
            refs = []
            if "@" in identifier:
                emails.append(identifier.strip().lower())
            elif identifier.strip().startswith("user_"):
                refs.append(identifier.strip())

            # Determine presence/state from status
            status_upper = status.upper()
            rec_type = "handover_record"
            extra = {}

            if category.upper() in ("DATA_FLOW", "SECONDARY_IDENTIFIER"):
                rec_type = "data_flow"
                extra["enabled"] = status_upper == "ACTIVE"
            elif category.upper() == "BACKUP_ARCHIVE":
                rec_type = "backup_restore"
                extra["restore_allowed"] = status_upper == "ACTIVE"
            elif category.upper() == "SECURITY_AUDIT_LOG":
                rec_type = "audit_record"
            elif category.upper() == "ACCOUNT_TOMBSTONE":
                rec_type = "tombstone"
                # IDENTIFIABLE = PII exposed, REDACTED = cleaned
                if status_upper == "IDENTIFIABLE":
                    extra["name"] = "present"  # signal PII
            else:
                rec_type = "handover_record"

            # Build presence/PII signals
            extra["handover_status"] = status_upper
            # For analytics/support, IDENTIFIABLE = PII exposed
            if status_upper == "IDENTIFIABLE":
                extra["pii_exposed"] = True
            elif status_upper in ("FOUND",):
                extra["pii_exposed"] = False  # found but check further

            rec = {
                "file_id": fid, "captured_at": cat,
                "system": system_id, "resource_id": resource_id,
                "type": rec_type, "category": category, "raw": {
                    "handover_status": status_upper,
                    "identifier": identifier,
                    "category": category,
                }, **extra,
            }
            self._add(emails, refs, rec)

    def _idx_log(self, fid, cat, content):
        """Parse structured key=value log files using two-pass trace_id resolution."""
        ev_names = [
            "event=profile_lookup_completed", "event=index_query_completed",
            "event=analytics_profile_read_completed", "event=connector_config_read_completed",
            "event=restore_policy_read_completed", "event=support_ticket_read_completed",
            "event=audit_record_read_completed",
            "event=message_pii_scan", "event=attachment_pii_scan",
            "event=attachment_scan",
            "event=connector_heartbeat",            # active data flow
            "event=restore_candidate_evaluated",    # backup restore risk
            "event=export_download_check_completed",
            "event=contact_lookup_completed",
            "event=contact_query_completed",        # support_replica variant
            "event=deletion_marker_check",          # record exists without deletion marker
            "event=analytics_identity_scan",
        ]
        # First pass: build trace_id → (emails, refs) from "_started" events
        trace_context = {}
        for line in content.split("\n"):
            if "trace_id=" not in line:
                continue
            tf = {m.group(1): m.group(2) for m in re.finditer(r"(\w+)=([^\s]+)", line)}
            tq = {m.group(1): m.group(2) for m in re.finditer(r'(\w+)="([^"]+)"', line)}
            tf.update(tq)
            tid = tf.get("trace_id", "")
            if not tid:
                continue
            t_emails = []
            t_refs = []
            for k in ("lookup_key", "subject_key", "scan_key", "match_key",
                      "customer_email", "requester_email", "correlation_key", "matched_value"):
                v = tf.get(k, "")
                if v and "@" in v:
                    t_emails.append(v.strip().lower().strip('"'))
            for k in ("subject_ref", "customer_reference"):
                v = tf.get(k, "")
                if v and v.startswith("user_"):
                    t_refs.append(v.strip())
            if t_emails or t_refs:
                if tid not in trace_context:
                    trace_context[tid] = ([], [])
                trace_context[tid][0].extend(t_emails)
                trace_context[tid][1].extend(t_refs)

        # Second pass: parse completed/evaluated events
        for line in content.split("\n"):
            if not any(ev in line for ev in ev_names):
                continue
            quoted = {}
            for m in re.finditer(r'(\w+)="([^"]+)"', line):
                quoted[m.group(1)] = m.group(2)
            fields = {m.group(1): m.group(2) for m in re.finditer(r"(\w+)=([^\s]+)", line)}
            fields.update(quoted)

            emails = []
            for k in ("lookup_key", "customer_email", "requester_email",
                      "correlation_key", "match_key", "subject_key",
                      "scan_key", "matched_value"):
                v = fields.get(k, "null")
                if v and v != "null" and "@" in v:
                    emails.append(v.strip().lower().strip('"'))
            refs = []
            for k in ("customer_reference", "subject_ref"):
                v = fields.get(k, "null")
                if v and v != "null" and v.startswith("user_"):
                    refs.append(v.strip())

            # Use trace_id to find emails from matching started events
            tid = fields.get("trace_id", "")
            if tid and tid in trace_context:
                tc_emails, tc_refs = trace_context[tid]
                for e in tc_emails:
                    if e not in emails:
                        emails.append(e)
                for r in tc_refs:
                    if r not in refs:
                        refs.append(r)

            rid = fields.get("resource_id", "")
            svc = fields.get("service", "unknown")
            extra = {}
            if "enabled" in fields:
                extra["enabled"] = fields["enabled"] == "true"
            if "restore_allowed" in fields:
                extra["restore_allowed"] = fields.get("restore_allowed") == "true"
            if "http_status" in fields:
                try:
                    extra["status_code"] = int(fields["http_status"])
                except Exception:
                    pass
            if "rows" in fields:
                try:
                    extra["rows"] = int(fields["rows"])
                except Exception:
                    pass
            if "result" in fields:
                extra["result"] = fields["result"]
            if "retention_until" in fields:
                extra["retention_until"] = fields["retention_until"]
            if "event_code" in fields:
                extra["event_code"] = fields["event_code"]

            ev = fields.get("event", "")
            rtype = "log_record"
            if "pii_scan" in ev or "pii_found" in ev or "identity_scan" in ev:
                rtype = "log_pii_scan"
                extra["pii_exposed"] = True
            elif ev == "connector_heartbeat":
                rtype = "data_flow"
                en = fields.get("enabled", "false")
                extra["enabled"] = en.lower() == "true"
            elif ev == "restore_candidate_evaluated":
                rtype = "backup_restore"
                eligible = fields.get("eligible", "false")
                deletion_block = fields.get("deletion_block", "true")
                extra["restore_allowed"] = (eligible.lower() == "true" and
                                            deletion_block.lower() == "false")
            elif ev == "deletion_marker_check":
                # marker_found=false means the record exists but deletion is NOT marked
                marker_found = fields.get("marker_found", "true")
                if marker_found.lower() == "false":
                    extra["rows"] = 1  # record present, not cleaned

            if emails or refs:
                self._add(emails, refs,
                          {"file_id": fid, "captured_at": cat, "system": svc,
                           "resource_id": rid, "type": rtype, "raw": fields, **extra})

    def find_for_user(self, user_id, all_emails, all_phones, audit_at):
        """Return all evidence records for this user at or before audit_at."""
        self.build_index()
        audit_ts = parse_iso(audit_at)
        seen = set()
        results = []

        def add(rec):
            key = (rec["file_id"], rec["system"], rec["resource_id"])
            if key not in seen:
                cap_ts = parse_iso(rec.get("captured_at", ""))
                if cap_ts and audit_ts and cap_ts <= audit_ts:
                    seen.add(key)
                    results.append(rec)

        for email in all_emails:
            for rec in self._email_index.get(email, []):
                add(rec)
        if user_id:
            for rec in self._user_ref_index.get(user_id, []):
                add(rec)
        return results


def search_sql(manifest, all_emails, all_phones, user_id, audit_at):
    """Search SQL evidence files for user records."""
    audit_ts = parse_iso(audit_at)
    results = []
    for entry in manifest:
        fid = entry["file_id"]
        fp = entry["file_path"]
        cat = entry["captured_at"]
        if not fp.endswith(".sql"):
            continue
        cap_ts = parse_iso(cat)
        if cap_ts and audit_ts and cap_ts > audit_ts:
            continue
        full = DATASET / fp
        if not full.exists():
            continue
        try:
            sql = full.read_text(encoding="utf-8")
        except Exception:
            continue
        try:
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.executescript(sql)
            conn.commit()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for table in tables:
                try:
                    cur.execute(f'PRAGMA table_info("{table}")')
                    cols = [c[1] for c in cur.fetchall()]
                    col_lower_set = {c.lower() for c in cols}

                    # Build WHERE clause from direct identifier columns
                    conds = []
                    params = []
                    for col in cols:
                        cl = col.lower()
                        if cl in ("email", "owner_email", "customer_email", "requester_email"):
                            for em in all_emails:
                                conds.append(f'lower("{col}") = ?')
                                params.append(em.lower())
                        elif cl in ("phone", "customer_phone"):
                            for ph in all_phones:
                                conds.append(f'"{col}" = ?')
                                params.append(ph)
                        elif cl in ("user_id", "customer_reference", "subject_reference"):
                            if user_id:
                                conds.append(f'"{col}" = ?')
                                params.append(user_id)

                    if not conds:
                        # Fallback: search record_json column for embedded identifiers
                        if "record_json" not in col_lower_set:
                            continue
                        conds_json = []
                        params_json = []
                        for em in all_emails:
                            conds_json.append("record_json LIKE ?")
                            params_json.append(f'%"email":"{em}"%')
                        if user_id:
                            conds_json.append("record_json LIKE ?")
                            params_json.append(f'%"{user_id}"%')
                        if not conds_json:
                            continue
                        where_json = " OR ".join(conds_json)
                        try:
                            cur.execute(f'SELECT * FROM "{table}" WHERE {where_json}', params_json)
                            for row in cur.fetchall():
                                rd = dict(row)
                                rj = rd.get("record_json", "")
                                try:
                                    inner = json.loads(rj) if rj else {}
                                except Exception:
                                    inner = {}
                                rid = rd.get("resource_id") or inner.get("resource_id") or f"{table}_row"
                                origin_sys = rd.get("origin_system", "")
                                col_name = rd.get("collection_name", "")
                                sys_name = _infer_sys(origin_sys or col_name or table)
                                merged = {**inner, **{k: v for k, v in rd.items() if k != "record_json"}}
                                results.append({"file_id": fid, "captured_at": cat,
                                                "system": sys_name, "resource_id": str(rid),
                                                "type": "sql_record", "table": col_name or table,
                                                "raw": merged})
                        except sqlite3.Error:
                            pass

                    where_clause = " OR ".join(conds)

                    cur.execute(f'SELECT * FROM "{table}" WHERE {where_clause}', params)
                    for row in cur.fetchall():
                        rd = dict(row)
                        rid = (rd.get("resource_id") or rd.get("id") or
                               rd.get("record_id") or f"{table}_row")
                        sys_name = _infer_sys(table)
                        # Special: backup tables - set type based on restore_allowed
                        rec_type = "sql_record"
                        extra = {}
                        table_l = table.lower()
                        if "backup" in table_l or "restore" in table_l:
                            rec_type = "backup_restore"
                            ra = rd.get("restore_allowed")
                            extra["restore_allowed"] = bool(ra) if ra is not None else False
                        elif "connector" in table_l or "subscription" in table_l:
                            rec_type = "data_flow"
                            en = rd.get("enabled")
                            extra["enabled"] = bool(en) if en is not None else False
                        results.append({"file_id": fid, "captured_at": cat, "system": sys_name,
                                        "resource_id": str(rid), "type": rec_type,
                                        "table": table, "raw": rd, **extra})
                except sqlite3.Error:
                    continue
            conn.close()
        except sqlite3.Error:
            continue
    return results


def _infer_sys(t):
    t = t.lower()
    if "account" in t:
        return "account_service"
    if "search" in t or "index" in t:
        return "search_service"
    if "support" in t or "ticket" in t:
        return "support_platform"
    if "analytic" in t:
        return "analytics_platform"
    if "marketing" in t:
        return "marketing_platform"
    if "export" in t:
        return "export_service"
    if "backup" in t or "archive" in t:
        return "backup_service"
    if "audit" in t or "security" in t:
        return "security_service"
    if "integration" in t or "connector" in t or "data_flow" in t:
        return "integration_service"
    if "tombstone" in t or "deleted" in t or "identity" in t:
        return "identity_service"
    if "email" in t or "delivery" in t or "notification" in t:
        return "email_delivery_service"
    return "unknown"


def classify(rec, rules):
    """Classify a record: returns (action, category, system_id)."""
    sys = rec.get("system", "unknown")
    rtype = rec.get("type", "")
    if rtype in ("tombstone", "snapshot_record") and rec.get("collection"):
        col = rec.get("collection", "").lower()
        if "tombstone" in col or "deleted_customer" in col:
            sys = "identity_service"
    if rtype == "data_flow":
        cat = "SECONDARY_IDENTIFIER"
        return rules.get(cat, "DELETE"), cat, "integration_service"
    if rtype == "backup_restore":
        cat = "BACKUP_ARCHIVE"
        return rules.get(cat, "RETAIN"), cat, "backup_service"
    if rtype == "audit_record":
        cat = "SECURITY_AUDIT_LOG"
        return rules.get(cat, "RETAIN"), cat, "security_service"
    if rtype == "handover_record":
        # Use category from handover file if available
        hcat = rec.get("category", "")
        if hcat:
            cat = hcat.upper()
            # Map handover categories to rule categories
            cat_map = {
                "USER_PROFILE": "USER_PROFILE", "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
                "ANALYTICS_PROFILE": "ANALYTICS_PROFILE", "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
                "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT", "MARKETING_PROFILE": "MARKETING_PROFILE",
                "USER_EXPORT": "USER_EXPORT", "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
                "DATA_FLOW": "SECONDARY_IDENTIFIER", "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
                "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
                "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
            }
            mapped = cat_map.get(cat, cat)
            return rules.get(mapped, "DELETE"), mapped, sys
        cat = SYSTEM_CATEGORY_MAP.get(sys, "USER_PROFILE")
        return rules.get(cat, "DELETE"), cat, sys
    if rtype == "log_pii_scan":
        # Use the system to determine category
        cat = SYSTEM_CATEGORY_MAP.get(sys, "SUPPORT_MESSAGE")
        return rules.get(cat, "REDACT"), cat, sys
    cat = SYSTEM_CATEGORY_MAP.get(sys, "USER_PROFILE")
    return rules.get(cat, "DELETE"), cat, sys



def is_present(rec):
    """Determine if this record represents present/active data."""
    t = rec.get("type", "")
    if t == "account_profile":
        return rec.get("status_code") == 200 and rec.get("profile") is not None
    if t == "search_index":
        return rec.get("total_hits", 0) > 0
    if t == "analytics_profile":
        p = rec.get("profile") or rec.get("raw") or {}
        return p.get("email") is not None or p.get("customer_reference") is not None
    if t == "data_flow":
        return rec.get("enabled", False)
    if t == "backup_restore":
        return rec.get("restore_allowed", False)
    if t == "audit_record":
        return True
    if t == "tombstone":
        r = rec.get("raw", {})
        return any(r.get(f) is not None for f in ["name", "email", "phone", "email_hash"])
    if t == "log_record":
        if rec.get("status_code") == 404 or rec.get("rows") == 0:
            return False
        return rec.get("result") == "hit" or rec.get("rows", 1) > 0
    if t == "log_pii_scan":
        return True  # PII scan found something
    if t == "handover_record":
        status = rec.get("handover_status", "FOUND")
        # Present if found/identifiable/active
        return status in ("FOUND", "IDENTIFIABLE", "ACTIVE")
    if t == "sql_record":
        return True
    if t == "snapshot_record":
        r = rec.get("raw", {})
        col = rec.get("collection", "").lower()
        if "tombstone" in col or "deleted" in col:
            return any(r.get(f) is not None for f in ["name", "email", "phone", "email_hash"])
        return True
    return True


def has_pii(rec, all_emails=None):
    """Check if record still exposes PII that should be removed."""
    t = rec.get("type", "")
    raw = rec.get("raw") or {}
    profile = rec.get("profile") or {}
    # PII scan events directly signal exposed PII
    if t == "log_pii_scan" or rec.get("pii_exposed"):
        return True
    if t == "analytics_profile":
        return (raw.get("email") is not None or
                profile.get("email") is not None or
                raw.get("customer_reference") is not None)
    if t == "support_ticket":
        return (raw.get("requester_email") is not None or
                raw.get("requester_name") is not None or
                raw.get("requester_phone") is not None)
    if t == "tombstone":
        return any(raw.get(f) is not None for f in ["name", "email", "phone", "email_hash"])
    if t == "handover_record":
        # IDENTIFIABLE status means PII is exposed
        return rec.get("handover_status", "") == "IDENTIFIABLE"
    if t == "snapshot_record":
        col = rec.get("collection", "").lower()
        if "tombstone" in col or "deleted" in col:
            return any(raw.get(f) is not None for f in ["name", "email", "phone", "email_hash"])
        if "analytic" in col:
            return raw.get("email") is not None or raw.get("customer_reference") is not None
        if "support" in col:
            return (raw.get("requester_email") is not None or
                    raw.get("requester_name") is not None)
    if t == "log_record":
        v = raw.get("customer_email", "null")
        return bool(v and v not in ("null", ""))
    if t == "sql_record":
        for k, v in raw.items():
            if v is not None and k.lower() in ("email", "name", "phone", "email_hash"):
                return True
    return False


def mk(no, phase, sys, res, op, state, ev):
    return {"step_no": no, "phase": phase, "system_id": sys, "resource_id": res,
            "operation": op, "state": state, "evidence_id": ev}


def build_steps(records, rules, is_complete, all_emails=None):
    """Build ordered FINDING + REMEDIATION + VERIFICATION steps."""
    findings, remeds, verifs = [], [], []
    handled = set()

    for rec in records:
        action, cat, sys_id = classify(rec, rules)
        rid = rec.get("resource_id", "")
        fid = rec.get("file_id", "")
        if not rid:
            continue
        key = (sys_id, rid)
        if key in handled:
            continue
        handled.add(key)
        pres = is_present(rec)
        pii = has_pii(rec, all_emails)
        rtype = rec.get("type", "")

        # Data flows
        if rtype == "data_flow":
            if rec.get("enabled"):
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "DISABLE_DATA_FLOW", "DISABLED", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", fid))
            continue

        # Backup/restore risk
        if rtype == "backup_restore":
            if rec.get("restore_allowed"):
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_RESTORE_RISK", "ACTIVE", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "BLOCK_RESTORE", "BLOCKED", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", fid))
            continue

        # Security audit (always RETAIN)
        if rtype == "audit_record" or cat == "SECURITY_AUDIT_LOG":
            verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_PRESENT", "PRESENT",
                             fid if is_complete else ""))
            continue

        # Account tombstones (REDACT, keep user_id, remove PII)
        if rtype == "tombstone" or (cat == "ACCOUNT_TOMBSTONE" and sys_id == "identity_service"):
            if pii:
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_EXPOSED_PII", "PRESENT", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "REDACT_RECORD", "REDACTED", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", fid))
            continue

        # Regular records based on deletion rule
        if action == "DELETE":
            if pres:
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_REMAINING_RECORD", "PRESENT", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "DELETE_RECORD", "ABSENT", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ABSENT", "ABSENT", fid))
        elif action == "REDACT":
            if pii:
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_EXPOSED_PII", "PRESENT", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "REDACT_RECORD", "REDACTED", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
            elif pres:
                # Present but no PII exposed - already properly redacted
                if is_complete:
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", fid))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", fid))
        elif action == "ANONYMIZE":
            if pii:
                if not is_complete:
                    findings.append(mk(0, "FINDING", sys_id, rid, "REPORT_EXPOSED_PII", "PRESENT", fid))
                    remeds.append(mk(0, "REMEDIATION", sys_id, rid, "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
            elif pres:
                # Present but no PII - already properly anonymized
                if is_complete:
                    verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", fid))
            elif is_complete:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", fid))
        elif action == "RETAIN":
            if pres:
                verifs.append(mk(0, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_PRESENT", "PRESENT",
                                 fid if is_complete else ""))

    fi = {op: i for i, op in enumerate(FINDING_OP_ORDER)}
    ri = {op: i for i, op in enumerate(REMEDIATION_OP_ORDER)}
    vi = {op: i for i, op in enumerate(VERIFICATION_OP_ORDER)}

    def dedup(steps):
        seen, out = set(), []
        for s in steps:
            k = (s["system_id"], s["resource_id"], s["operation"])
            if k not in seen:
                seen.add(k)
                out.append(s)
        return out

    findings = sorted(dedup(findings), key=lambda s: (fi.get(s["operation"], 99), s["system_id"], s["resource_id"]))
    remeds = sorted(dedup(remeds), key=lambda s: (ri.get(s["operation"], 99), s["system_id"], s["resource_id"]))
    verifs = sorted(dedup(verifs), key=lambda s: (vi.get(s["operation"], 99), s["system_id"], s["resource_id"]))
    all_steps = findings + remeds + verifs
    for i, s in enumerate(all_steps, 1):
        s["step_no"] = i
    return all_steps


def get_status(records, rules):
    """Determine deletion status from evidence records."""
    for rec in records:
        action, cat, sys_id = classify(rec, rules)
        rtype = rec.get("type", "")
        if rtype == "data_flow" and rec.get("enabled"):
            return "INCOMPLETE"
        if rtype == "backup_restore" and rec.get("restore_allowed"):
            return "INCOMPLETE"
        if rtype == "audit_record" or cat == "SECURITY_AUDIT_LOG":
            continue
        # Tombstones: incomplete only if PII still exposed
        if rtype == "tombstone":
            if has_pii(rec):
                return "INCOMPLETE"
            continue  # tombstone with no PII is correctly handled
        if action == "DELETE" and is_present(rec):
            return "INCOMPLETE"
        # For REDACT/ANONYMIZE: incomplete only when PII is still exposed
        # If record is present but has no PII, it's already been properly treated
        if action in ("REDACT", "ANONYMIZE") and has_pii(rec):
            return "INCOMPLETE"
    return "COMPLETE"


def find_account_resource_from_activity(activity_rows, user_id, all_emails, audit_at):
    """Find an account resource_id from system_activity.csv."""
    audit_ts = parse_iso(audit_at)
    # Look for DELETE_RECORD events on account_service targeting this user
    candidates = []
    for row in activity_rows:
        ev_ts = parse_iso(row.get("event_time", ""))
        if ev_ts and audit_ts and ev_ts > audit_ts:
            continue
        details = (row.get("details") or "").lower()
        resource_id = row.get("resource_id", "")
        event_type = row.get("event_type", "")
        target_sys = row.get("target_system", "") or row.get("source_system", "")
        matched = False
        for email in all_emails:
            if email and email.lower() in details:
                matched = True
                break
        if not matched and user_id:
            if user_id.lower() in details:
                matched = True
        if matched and resource_id:
            candidates.append((target_sys or "account_service", resource_id, row.get("activity_id", "")))
    # Prefer account_service resources
    for sys, rid, aid in candidates:
        if "account" in sys.lower() and "account_" in rid.lower():
            return sys, rid, aid
    # Return first match if found
    return candidates[0] if candidates else None


def process_case(case, identities, audit_log, store, sql_manifest, rules, activity_rows=None):
    """Process a single deletion request case."""
    cid = case["case_id"]
    email = case["email"]
    text = case.get("request_text", "")
    audit_at = case["audit_at"]
    reported_status = case.get("reported_status", "COMPLETE")

    if not is_deletion_request(text):
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    uid, emails, phones = resolve_user(email, identities, audit_log)
    recs = store.find_for_user(uid, emails, phones, audit_at)
    recs += search_sql(sql_manifest, emails, phones, uid, audit_at)

    status = get_status(recs, rules)
    is_comp = status == "COMPLETE"
    steps = build_steps(recs, rules, is_comp, all_emails=emails)

    # When COMPLETE but no steps found, use system_activity to find evidence
    if is_comp and not steps and activity_rows:
        acct = find_account_resource_from_activity(activity_rows, uid, emails, audit_at)
        if acct:
            sys_id, rid, aid = acct
            steps = [mk(1, "VERIFICATION", sys_id, rid, "VERIFY_RECORD_ABSENT", "ABSENT", aid)]

    return {"case_id": cid, "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))}


def main():
    print("Loading data...")
    rules = {r["data_category"]: r["required_action"]
             for r in load_csv(DATASET / "deletion_rules.csv")}
    identities = {r["user_id"]: r for r in load_csv(DATASET / "user_identities.csv")}
    audit_log = load_csv(DATASET / "user_audit_log.csv")
    manifest = load_csv(DATASET / "evidence_files.csv")
    activity_rows = load_csv(DATASET / "system_activity.csv")
    sql_manifest = [e for e in manifest if e["file_path"].endswith(".sql")]
    print(f"Identities: {len(identities)}, Audit: {len(audit_log)}, Evidence: {len(manifest)}, Activity: {len(activity_rows)}")
    print("Building index...")
    store = EvidenceStore(manifest)
    store.build_index()
    print("Index built.")
    requests = load_csv(DATASET / "deletion_requests.csv")
    print(f"Processing {len(requests)} cases...")
    results = []
    for i, case in enumerate(requests, 1):
        if i % 100 == 0:
            print(f"  {i}/{len(requests)}...")
        results.append(process_case(case, identities, audit_log, store, sql_manifest, rules, activity_rows))
    results.sort(key=lambda r: r["case_id"])
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            w.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])
    print(f"Done! {OUTPUT_CSV}")
    stats = {}
    for r in results:
        stats[r["deletion_status"]] = stats.get(r["deletion_status"], 0) + 1
    print(f"Summary: {stats}")


if __name__ == "__main__":
    main()
