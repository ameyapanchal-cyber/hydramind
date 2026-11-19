"""SQLite store — logs every scan, finding, scope decision, AI decision and
human approval for reproducible, auditable reports."""
from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "pipeline.db"


def _conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL, tool TEXT NOT NULL, started_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            host TEXT, port INTEGER, protocol TEXT,
            service TEXT, product TEXT, version TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            action_id INTEGER, tool TEXT NOT NULL, risk TEXT NOT NULL,
            description TEXT, approved INTEGER NOT NULL DEFAULT 0,
            executed INTEGER NOT NULL DEFAULT 0, result TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS scope_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL, tool TEXT NOT NULL,
            allowed INTEGER NOT NULL, reason TEXT, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS triage_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            rank INTEGER, severity TEXT, source TEXT, description TEXT,
            why TEXT, next_step TEXT, created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS reasoner_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            hypothesis TEXT, proposed_command TEXT,
            confidence REAL, risk_level TEXT,
            human_decision TEXT NOT NULL, rejection_reason TEXT,
            executed INTEGER NOT NULL DEFAULT 0, result TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES triage_findings(id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            finding_id INTEGER, tool TEXT, title TEXT,
            verdict TEXT, severity TEXT, confidence REAL,
            rationale TEXT, remediation TEXT,
            provider TEXT, model TEXT, same_family INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id),
            FOREIGN KEY(finding_id) REFERENCES triage_findings(id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS model_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
            role TEXT NOT NULL, profile TEXT, provider TEXT, model TEXT,
            prompt_hash TEXT, latency_ms INTEGER,
            tokens_in INTEGER, tokens_out INTEGER,
            response TEXT, error TEXT, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            summary TEXT NOT NULL, provider TEXT, model TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id))""")
        # Migration: older DBs lack the columns for gobuster/nikto findings
        cols = {r["name"] for r in c.execute("PRAGMA table_info(findings)")}
        for col, typ in (("tool", "TEXT"), ("path", "TEXT"),
                         ("status", "INTEGER"), ("size", "INTEGER"), ("detail", "TEXT")):
            if col not in cols:
                c.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")


def new_scan(target: str, tool: str) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (target, tool, started_at) VALUES (?, ?, ?)",
            (target, tool, _now()))
        return cur.lastrowid


def save_findings(scan_id: int, tool: str, findings: list):
    """Save findings from any tool. nmap rows keep port/service fields,
    gobuster rows use path/status/size, nikto rows use detail."""
    with _conn() as c:
        c.executemany(
            """INSERT INTO findings
               (scan_id, tool, host, port, protocol, service, product, version,
                path, status, size, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(scan_id, tool, f.get("host"), f.get("port"), f.get("protocol"),
              f.get("service"), f.get("product"), f.get("version"),
              f.get("path"), f.get("status"), f.get("size"),
              f.get("detail") or f.get("finding")) for f in findings])


def save_triage_findings(scan_id: int, ranked: list) -> list[int]:
    """Persist each AI-ranked triage finding; returns row ids (rank order)
    so reasoner_decisions can FK to them."""
    with _conn() as c:
        ids = []
        for item in ranked:
            cur = c.execute(
                """INSERT INTO triage_findings
                   (scan_id, rank, severity, source, description, why, next_step, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, item.get("rank"), item.get("severity"),
                 item.get("source"), item.get("finding"), item.get("why"),
                 item.get("next_step"), _now()))
            ids.append(cur.lastrowid)
        return ids


def log_reasoner_decision(finding_id: int, hypothesis: str, proposed_command: str,
                          confidence: float, risk_level: str, human_decision: str,
                          rejection_reason: str = "", executed: bool = False,
                          result: str = "") -> int:
    """Audit trail for every Reasoner proposal + human y/n decision."""
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO reasoner_decisions
               (finding_id, hypothesis, proposed_command, confidence, risk_level,
                human_decision, rejection_reason, executed, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, hypothesis, proposed_command, confidence, risk_level,
             human_decision, rejection_reason, int(executed), result, _now()))
        return cur.lastrowid


def log_action(scan_id: int, action_id: int, tool: str, risk: str,
               description: str, approved: bool, executed: bool, result: str = "") -> int:
    """Audit trail for executed/queued actions."""
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO actions
               (scan_id, action_id, tool, risk, description, approved, executed, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, action_id, tool, risk, description,
             int(approved), int(executed), result, _now()))
        return cur.lastrowid


def save_validation(scan_id: int, finding_id: int | None, tool: str, title: str,
                    verdict: str, severity: str, confidence: float,
                    rationale: str = "", remediation: str = "",
                    provider: str = "", model: str = "",
                    same_family: bool = False) -> int:
    """Persist one second-model validation verdict for the report."""
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO validations
               (scan_id, finding_id, tool, title, verdict, severity, confidence,
                rationale, remediation, provider, model, same_family, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, finding_id, tool, title, verdict, severity, confidence,
             rationale, remediation, provider, model, int(same_family), _now()))
        return cur.lastrowid


def scan_row(scan_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def findings_for_scan(scan_id: int) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def triage_for_scan(scan_id: int) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM triage_findings WHERE scan_id = ? ORDER BY rank, id",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def decisions_for_scan(scan_id: int) -> list[dict]:
    """Reasoner decisions joined with the triage finding they belong to."""
    with _conn() as c:
        rows = c.execute(
            """SELECT rd.*, tf.rank, tf.severity AS triage_severity,
                      tf.source, tf.description AS triage_description,
                      tf.why, tf.next_step
               FROM reasoner_decisions rd
               JOIN triage_findings tf ON rd.finding_id = tf.id
               WHERE tf.scan_id = ? ORDER BY tf.rank, rd.id""",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def validations_for_scan(scan_id: int) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM validations WHERE scan_id = ? ORDER BY id",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def clear_validations(scan_id: int) -> None:
    """Make re-validation idempotent (one verdict set per scan)."""
    with _conn() as c:
        c.execute("DELETE FROM validations WHERE scan_id = ?", (scan_id,))


def actions_for_scan(scan_id: int) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM actions WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def scope_events_for_target(target: str, limit: int = 20) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            """SELECT * FROM scope_events WHERE target = ?
               ORDER BY id DESC LIMIT ?""",
            (target, limit)).fetchall()
        return [dict(r) for r in rows]


def log_scope_event(target: str, tool: str, allowed: bool, reason: str = "") -> int:
    """Every scope-firewall decision (allow AND deny) is logged."""
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scope_events (target, tool, allowed, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (target, tool, int(allowed), reason, _now()))
        return cur.lastrowid


def log_model_call(scan_id: int | None, role: str, profile: str, provider: str,
                   model: str, prompt_hash: str, latency_ms: int,
                   tokens_in: int | None, tokens_out: int | None,
                   response: str = "", error: str = "") -> int:
    """One row per model invocation — the reproducibility audit trail."""
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO model_calls (scan_id, role, profile, provider, model,
                                        prompt_hash, latency_ms, tokens_in,
                                        tokens_out, response, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, role, profile, provider, model, prompt_hash,
             int(latency_ms), tokens_in, tokens_out, response, error, _now()))
        return cur.lastrowid


def model_calls_for_scan(scan_id: int) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM model_calls WHERE scan_id = ? ORDER BY id",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def save_summary(scan_id: int, summary: str, provider: str, model: str) -> int:
    with _conn() as c:
        c.execute("DELETE FROM scan_summaries WHERE scan_id = ?", (scan_id,))
        cur = c.execute(
            """INSERT INTO scan_summaries (scan_id, summary, provider, model,
                                           created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, summary, provider, model, _now()))
        return cur.lastrowid


def summary_for_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM scan_summaries WHERE scan_id = ? ORDER BY id DESC"
            " LIMIT 1", (scan_id,)).fetchone()
        return dict(row) if row else None


def action_history(target: str, limit: int = 10) -> list[dict]:
    """Recent approved/executed actions for a target (across all scans) —
    feeds the Reasoner's context so chained attacks build on what already
    succeeded/failed."""
    with _conn() as c:
        rows = c.execute(
            """SELECT a.tool, a.risk, a.description, a.result, a.approved, a.executed
               FROM actions a JOIN scans s ON a.scan_id = s.id
               WHERE s.target = ? AND a.approved = 1
               ORDER BY a.id DESC LIMIT ?""",
            (target, limit)).fetchall()
        return [dict(r) for r in rows]
