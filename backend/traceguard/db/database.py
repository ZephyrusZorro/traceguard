"""SQLite WAL Persistence Layer with Explicit Schema Migrations and Atomic Repositories."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from traceguard.config import settings
from traceguard.schemas import CounterfactualResult, DiagnosisResult, TraceIngestRequest


MIGRATIONS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS traces (
        id TEXT PRIMARY KEY,
        external_trace_id TEXT NOT NULL,
        idempotency_key TEXT UNIQUE,
        scenario_name TEXT NOT NULL,
        framework TEXT NOT NULL,
        status TEXT NOT NULL,
        root_goal TEXT NOT NULL,
        total_tokens INTEGER NOT NULL DEFAULT 0,
        total_latency_ms REAL NOT NULL DEFAULT 0.0,
        ground_truth_agent TEXT,
        ground_truth_step INTEGER,
        ground_truth_mode TEXT,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_traces_created ON traces(created_at DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS spans (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        step_index INTEGER NOT NULL,
        parent_span_id TEXT,
        agent_name TEXT NOT NULL,
        operation_name TEXT NOT NULL,
        tool_name TEXT,
        input_text TEXT NOT NULL,
        output_text TEXT NOT NULL,
        provenance TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        tokens_in INTEGER NOT NULL,
        tokens_out INTEGER NOT NULL,
        status TEXT NOT NULL,
        attributes_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id, step_index);
    """,
    """
    CREATE TABLE IF NOT EXISTS diagnoses (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        council_run_id TEXT NOT NULL,
        attributed_agent TEXT NOT NULL,
        attributed_step_index INTEGER NOT NULL,
        mast_pillar TEXT NOT NULL,
        mast_mode TEXT NOT NULL,
        confidence REAL NOT NULL,
        causal_verification_score REAL NOT NULL,
        contradiction_detected INTEGER NOT NULL,
        contradiction_note TEXT,
        security_verdict TEXT NOT NULL,
        summary TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_diag_trace ON diagnoses(trace_id, created_at DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS counterfactual_replays (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        intervention_step_index INTEGER NOT NULL,
        intervention_type TEXT NOT NULL,
        patched_content TEXT NOT NULL,
        original_outcome TEXT NOT NULL,
        counterfactual_outcome TEXT NOT NULL,
        causal_flip INTEGER NOT NULL,
        delta_score REAL NOT NULL,
        downstream_recovered_steps INTEGER NOT NULL,
        replayed_spans_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS capability_policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        rule_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_by TEXT NOT NULL,
        approved_by TEXT,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS webhook_endpoints (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        events_json TEXT NOT NULL,
        min_severity TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT,
        event_type TEXT NOT NULL,
        target_url TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        hmac_signature TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        http_status INTEGER,
        last_error TEXT,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TraceGuardDB:
    """Thread-safe SQLite WAL repository."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(MIGRATIONS[0])
            cur = conn.execute("SELECT MAX(version) as v FROM schema_migrations").fetchone()
            current_v = int(cur["v"]) if cur and cur["v"] is not None else 0
            for idx, sql in enumerate(MIGRATIONS[1:], start=1):
                if idx > current_v:
                    conn.executescript(sql)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                        (idx, _now()),
                    )
            # Seed default ACTIVE capability policy if table is empty
            cnt = conn.execute("SELECT COUNT(*) as c FROM capability_policies").fetchone()["c"]
            if cnt == 0:
                default_rule = {
                    "blocked_tools_when_tainted": ["send_email", "http_post", "webhook_send", "transfer_funds", "shell_exec", "delete_records"],
                    "forbid_secret_to_external": True,
                    "max_injection_threshold": 0.62,
                }
                conn.execute(
                    """INSERT INTO capability_policies (id, name, description, rule_json, status, created_by, approved_by, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "pol-default-camel",
                        "CaMeL Baseline Taint-to-Sink Guard",
                        "Prevents untrusted tool outputs flagged as indirect prompt injections from invoking external exfiltration sinks or mixing with SECRET_DATA.",
                        json.dumps(default_rule),
                        "ACTIVE",
                        "system",
                        "system",
                        _now(),
                    ),
                )

    def log_audit(self, actor: str, action: str, resource_type: str, resource_id: str, details: dict[str, Any] | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO audit_logs (id, actor, action, resource_type, resource_id, details_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (f"aud-{uuid.uuid4().hex[:12]}", actor, action, resource_type, resource_id, json.dumps(details or {}), _now()),
            )

    def insert_trace(self, req: TraceIngestRequest) -> tuple[str, bool]:
        """Idempotently persist a trace and its spans. Returns (trace_id, created_new)."""
        with self._lock, self._connect() as conn:
            if req.idempotency_key:
                existing = conn.execute(
                    "SELECT id FROM traces WHERE idempotency_key = ?", (req.idempotency_key,)
                ).fetchone()
                if existing:
                    return str(existing["id"]), False

            trace_id = f"tr-{uuid.uuid4().hex[:12]}"
            tot_tokens = sum(s.tokens_in + s.tokens_out for s in req.spans)
            tot_lat = round(sum(s.latency_ms for s in req.spans), 2)
            conn.execute(
                """INSERT INTO traces (
                    id, external_trace_id, idempotency_key, scenario_name, framework, status,
                    root_goal, total_tokens, total_latency_ms, ground_truth_agent, ground_truth_step,
                    ground_truth_mode, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    trace_id,
                    req.external_trace_id,
                    req.idempotency_key,
                    req.scenario_name,
                    req.framework,
                    req.status.value,
                    req.root_goal,
                    tot_tokens,
                    tot_lat,
                    req.ground_truth_agent,
                    req.ground_truth_step,
                    req.ground_truth_mode.value if req.ground_truth_mode else None,
                    _now(),
                ),
            )
            for s in sorted(req.spans, key=lambda x: x.step_index):
                conn.execute(
                    """INSERT INTO spans (
                        id, trace_id, step_index, parent_span_id, agent_name, operation_name, tool_name,
                        input_text, output_text, provenance, latency_ms, tokens_in, tokens_out, status, attributes_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f"{trace_id}:{s.span_id}",
                        trace_id,
                        s.step_index,
                        s.parent_span_id,
                        s.agent_name,
                        s.operation_name,
                        s.tool_name,
                        s.input_text,
                        s.output_text,
                        s.provenance.value,
                        s.latency_ms,
                        s.tokens_in,
                        s.tokens_out,
                        s.status,
                        json.dumps(s.attributes),
                    ),
                )
            return trace_id, True

    def list_traces(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT t.*,
                       (SELECT COUNT(*) FROM spans s WHERE s.trace_id = t.id) AS span_count,
                       d.attributed_agent, d.attributed_step_index, d.mast_mode,
                       d.confidence, d.causal_verification_score, d.security_verdict,
                       d.contradiction_detected
                FROM traces t
                LEFT JOIN diagnoses d ON d.id = (
                    SELECT id FROM diagnoses d2 WHERE d2.trace_id = t.id ORDER BY d2.created_at DESC LIMIT 1
                )
                ORDER BY t.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_trace_detail(self, trace_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            t = conn.execute("SELECT * FROM traces WHERE id = ?", (trace_id,)).fetchone()
            if not t:
                return None
            spans = conn.execute(
                "SELECT * FROM spans WHERE trace_id = ? ORDER BY step_index ASC", (trace_id,)
            ).fetchall()
            diag = conn.execute(
                "SELECT payload_json FROM diagnoses WHERE trace_id = ? ORDER BY created_at DESC LIMIT 1",
                (trace_id,),
            ).fetchone()
            replays = conn.execute(
                "SELECT * FROM counterfactual_replays WHERE trace_id = ? ORDER BY created_at DESC LIMIT 10",
                (trace_id,),
            ).fetchall()

            parsed_spans = []
            for sp in spans:
                d = dict(sp)
                d["span_id"] = d["id"].split(":", 1)[-1]
                d["attributes"] = json.loads(d.pop("attributes_json"))
                parsed_spans.append(d)

            parsed_replays = []
            for rp in replays:
                rd = dict(rp)
                rd["causal_flip"] = bool(rd["causal_flip"])
                rd["replayed_spans"] = json.loads(rd.pop("replayed_spans_json"))
                parsed_replays.append(rd)

            return {
                "trace": dict(t),
                "spans": parsed_spans,
                "latest_diagnosis": json.loads(diag["payload_json"]) if diag else None,
                "replays": parsed_replays,
            }

    def save_diagnosis(self, diag: DiagnosisResult) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO diagnoses (
                    id, trace_id, council_run_id, attributed_agent, attributed_step_index,
                    mast_pillar, mast_mode, confidence, causal_verification_score,
                    contradiction_detected, contradiction_note, security_verdict, summary,
                    payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    diag.id,
                    diag.trace_id,
                    diag.council_run_id,
                    diag.attributed_agent,
                    diag.attributed_step_index,
                    diag.mast_pillar,
                    diag.mast_mode,
                    diag.confidence,
                    diag.causal_verification_score,
                    1 if diag.contradiction_detected else 0,
                    diag.contradiction_note,
                    diag.security_verdict,
                    diag.summary,
                    diag.model_dump_json(),
                    diag.created_at,
                ),
            )

    def save_counterfactual(self, cf: CounterfactualResult) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO counterfactual_replays (
                    id, trace_id, intervention_step_index, intervention_type, patched_content,
                    original_outcome, counterfactual_outcome, causal_flip, delta_score,
                    downstream_recovered_steps, replayed_spans_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cf.id,
                    cf.trace_id,
                    cf.intervention_step_index,
                    cf.intervention_type,
                    cf.patched_content,
                    cf.original_outcome,
                    cf.counterfactual_outcome,
                    1 if cf.causal_flip else 0,
                    cf.delta_score,
                    cf.downstream_recovered_steps,
                    json.dumps(cf.replayed_spans),
                    cf.created_at,
                ),
            )

    # --- Policies (Human Approval Gate) ---

    def list_policies(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM capability_policies ORDER BY created_at DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["rule"] = json.loads(d.pop("rule_json"))
                out.append(d)
            return out

    def create_policy(self, name: str, description: str, rule: dict[str, Any], created_by: str, status: str = "PENDING_APPROVAL") -> dict[str, Any]:
        pid = f"pol-{uuid.uuid4().hex[:10]}"
        ts = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO capability_policies (id, name, description, rule_json, status, created_by, approved_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (pid, name, description, json.dumps(rule), status, created_by, None, ts),
            )
        return {"id": pid, "name": name, "description": description, "rule": rule, "status": status, "created_by": created_by, "approved_by": None, "created_at": ts}

    def update_policy_status(self, policy_id: str, status: str, approved_by: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE capability_policies SET status = ?, approved_by = ? WHERE id = ?",
                (status, approved_by, policy_id),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM capability_policies WHERE id = ?", (policy_id,)).fetchone()
            d = dict(row)
            d["rule"] = json.loads(d.pop("rule_json"))
            return d

    # --- Webhooks & Audits ---

    def register_webhook(self, target_url: str, events: list[str], min_severity: str) -> dict[str, Any]:
        wid = f"wh-{uuid.uuid4().hex[:10]}"
        ts = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO webhook_endpoints (id, target_url, events_json, min_severity, active, created_at)
                   VALUES (?, ?, ?, ?, 1, ?)""",
                (wid, target_url, json.dumps(events), min_severity, ts),
            )
        return {"id": wid, "target_url": target_url, "events": events, "min_severity": min_severity, "active": True, "created_at": ts}

    def list_webhooks(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM webhook_endpoints ORDER BY created_at DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["events"] = json.loads(d.pop("events_json"))
                d["active"] = bool(d["active"])
                out.append(d)
            return out

    def record_webhook_delivery(
        self,
        endpoint_id: str | None,
        event_type: str,
        target_url: str,
        payload: dict[str, Any],
        hmac_sig: str,
        status: str,
        attempts: int,
        http_status: int | None,
        last_error: str | None,
    ) -> dict[str, Any]:
        did = f"whd-{uuid.uuid4().hex[:10]}"
        ts = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO webhook_deliveries (
                    id, endpoint_id, event_type, target_url, payload_json, hmac_signature,
                    status, attempts, http_status, last_error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (did, endpoint_id, event_type, target_url, json.dumps(payload), hmac_sig, status, attempts, http_status, last_error, ts),
            )
        return {"id": did, "event_type": event_type, "target_url": target_url, "status": status, "attempts": attempts, "http_status": http_status, "last_error": last_error, "created_at": ts}

    def list_webhook_deliveries(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhook_deliveries ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d.pop("payload_json"))
                out.append(d)
            return out

    def list_audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["details"] = json.loads(d.pop("details_json"))
                out.append(d)
            return out

    def get_system_stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            traces_total = conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]
            compromised = conn.execute("SELECT COUNT(*) FROM traces WHERE status = 'COMPROMISED'").fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM traces WHERE status = 'FAILED'").fetchone()[0]
            replays = conn.execute("SELECT COUNT(*) FROM counterfactual_replays").fetchone()[0]
            flips = conn.execute("SELECT COUNT(*) FROM counterfactual_replays WHERE causal_flip = 1").fetchone()[0]
            pending_pol = conn.execute("SELECT COUNT(*) FROM capability_policies WHERE status = 'PENDING_APPROVAL'").fetchone()[0]
            active_pol = conn.execute("SELECT COUNT(*) FROM capability_policies WHERE status = 'ACTIVE'").fetchone()[0]
            return {
                "total_traces": traces_total,
                "failed_traces": failed,
                "compromised_traces": compromised,
                "counterfactual_replays": replays,
                "causal_recoveries": flips,
                "active_policies": active_pol,
                "pending_policies": pending_pol,
            }
