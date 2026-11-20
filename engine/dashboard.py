"""Read-only dashboard data layer.

All functions are safe to call while a scan is writing: queries are short and
SQLite runs in WAL mode with a busy timeout. Nothing here mutates the database.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from engine import db

ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "reports"
REPORT_RE = re.compile(r"^report_\d+\.(md|html)$")
VERDICTS = ("confirmed", "likely", "needs_review", "false_positive")


def _rows(c, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in c.execute(sql, params).fetchall()]


def _empty(error: str = "database not initialized") -> dict:
    return {"ok": False, "error": error, "scans": [], "totals": {},
            "recent_calls": [], "scope_events": []}


def overview(limit: int = 25) -> dict:
    try:
        with db._conn() as c:
            scans = _rows(c, "SELECT id, target, tool, started_at FROM scans"
                             " ORDER BY id DESC LIMIT ?", (int(limit),))
            findings = {r["scan_id"]: r["n"] for r in _rows(
                c, "SELECT scan_id, COUNT(*) AS n FROM findings GROUP BY scan_id")}
            triage = {r["scan_id"]: r["n"] for r in _rows(
                c, "SELECT scan_id, COUNT(*) AS n FROM triage_findings GROUP BY scan_id")}
            executed = {r["scan_id"]: r["n"] for r in _rows(
                c, "SELECT tf.scan_id, COUNT(*) AS n FROM reasoner_decisions rd"
                   " JOIN triage_findings tf ON rd.finding_id = tf.id"
                   " WHERE rd.executed = 1 GROUP BY tf.scan_id")}
            verdicts: dict[int, dict] = {}
            for r in _rows(c, "SELECT scan_id, verdict, COUNT(*) AS n"
                              " FROM validations GROUP BY scan_id, verdict"):
                verdicts.setdefault(r["scan_id"], {})[r["verdict"]] = r["n"]
            profiles = {r["scan_id"]: r["profile"] for r in _rows(
                c, "SELECT scan_id, profile FROM model_calls WHERE id IN"
                   " (SELECT MAX(id) FROM model_calls WHERE scan_id IS NOT NULL"
                   "  GROUP BY scan_id)")}
            for scan in scans:
                sid = scan["id"]
                v = verdicts.get(sid, {})
                scan.update({
                    "raw_findings": findings.get(sid, 0),
                    "triage_findings": triage.get(sid, 0),
                    "executed_actions": executed.get(sid, 0),
                    "confirmed": v.get("confirmed", 0),
                    "false_positive": v.get("false_positive", 0),
                    "needs_review": v.get("needs_review", 0),
                    "profile": profiles.get(sid, ""),
                    "report_md": (REPORTS_DIR / f"report_{sid}.md").exists(),
                    "report_html": (REPORTS_DIR / f"report_{sid}.html").exists(),
                })
            totals = {
                "scans": len(scans),
                "raw_findings": sum(findings.values()),
                "executed_actions": sum(executed.values()),
                "confirmed": sum(v.get("confirmed", 0) for v in verdicts.values()),
                "false_positive": sum(v.get("false_positive", 0) for v in verdicts.values()),
                "model_calls": c.execute(
                    "SELECT COUNT(*) FROM model_calls").fetchone()[0],
            }
            recent_calls = _rows(
                c, "SELECT scan_id, role, profile, provider, model, latency_ms,"
                   " tokens_in, tokens_out, error, created_at FROM model_calls"
                   " ORDER BY id DESC LIMIT 12")
            scope_events = _rows(
                c, "SELECT target, tool, allowed, reason, created_at FROM"
                   " scope_events ORDER BY id DESC LIMIT 10")
            return {"ok": True, "scans": scans, "totals": totals,
                    "recent_calls": recent_calls, "scope_events": scope_events}
    except sqlite3.OperationalError as e:
        return _empty(str(e))


def scan_detail(scan_id: int) -> dict:
    try:
        with db._conn() as c:
            scan = c.execute("SELECT id, target, tool, started_at FROM scans"
                             " WHERE id = ?", (int(scan_id),)).fetchone()
            if not scan:
                return {"ok": False, "error": f"scan {scan_id} not found"}
            return {
                "ok": True,
                "scan": dict(scan),
                "findings": db.findings_for_scan(scan_id),
                "triage": db.triage_for_scan(scan_id),
                "decisions": db.decisions_for_scan(scan_id),
                "validations": db.validations_for_scan(scan_id),
                "model_calls": db.model_calls_for_scan(scan_id),
                "summary": db.summary_for_scan(scan_id),
                "report_md": (REPORTS_DIR / f"report_{scan_id}.md").exists(),
                "report_html": (REPORTS_DIR / f"report_{scan_id}.html").exists(),
            }
    except sqlite3.OperationalError as e:
        return {"ok": False, "error": str(e)}


def safe_report(name: str) -> Path | None:
    """Only report_<id>.md|.html directly inside reports/ may be served."""
    if not REPORT_RE.fullmatch(name or ""):
        return None
    path = (REPORTS_DIR / name).resolve()
    if path.parent != REPORTS_DIR.resolve() or not path.is_file():
        return None
    return path


def health() -> dict:
    try:
        with db._conn() as c:
            scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        return {"ok": True, "db": str(db.DB_PATH), "scans": scans}
    except sqlite3.OperationalError as e:
        return {"ok": False, "error": str(e), "db": str(db.DB_PATH)}
