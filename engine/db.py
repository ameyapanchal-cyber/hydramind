"""SQLite store — logs every scan, finding and approved action for reproducible reports."""
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
            (target, tool, datetime.now(timezone.utc).isoformat()))
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


def log_action(scan_id: int, action_id: int, tool: str, risk: str,
               description: str, approved: bool, executed: bool, result: str = "") -> int:
    """Audit trail for the approval gate — every proposed action is logged,
    approved or not."""
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO actions
               (scan_id, action_id, tool, risk, description, approved, executed, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, action_id, tool, risk, description,
             int(approved), int(executed), result,
             datetime.now(timezone.utc).isoformat()))
        return cur.lastrowid
