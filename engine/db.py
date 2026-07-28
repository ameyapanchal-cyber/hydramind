"""SQLite store — logs every scan and finding for reproducible reports."""
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


def new_scan(target: str, tool: str) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (target, tool, started_at) VALUES (?, ?, ?)",
            (target, tool, datetime.now(timezone.utc).isoformat()))
        return cur.lastrowid


def save_findings(scan_id: int, findings: list):
    with _conn() as c:
        c.executemany(
            """INSERT INTO findings
               (scan_id, host, port, protocol, service, product, version)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(scan_id, f.get("host"), f.get("port"), f.get("protocol"),
              f.get("service"), f.get("product"), f.get("version")) for f in findings])
