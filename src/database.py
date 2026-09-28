"""SQLite storage for analyzed reports."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_reports.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    threat_type TEXT,
    severity TEXT,
    summary TEXT,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(_SCHEMA)
    return conn


def save_report(filename: str, threat_type: str, severity: str,
                summary: str, result: dict) -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO reports (filename, threat_type, severity, summary, result_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (filename, threat_type, severity, summary, json.dumps(result),
         datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_reports(limit: int = 50) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, filename, threat_type, severity, created_at FROM reports"
        " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(zip(["id", "filename", "threat_type", "severity", "created_at"], r))
            for r in rows]


def get_report(report_id: int) -> dict | None:
    conn = _connect()
    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    if not row:
        return None
    keys = ["id", "filename", "threat_type", "severity", "summary",
            "result_json", "created_at"]
    rec = dict(zip(keys, row))
    rec["result"] = json.loads(rec.pop("result_json"))
    return rec


def delete_report(report_id: int) -> None:
    conn = _connect()
    conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()
