"""Tiny sqlite layer for scan history. No ORM — keeps the dependency surface
small and the schema obvious."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock

DB_PATH = Path(__file__).parent / "phishguard.db"
_lock = Lock()


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT NOT NULL,
                url         TEXT NOT NULL,
                hostname    TEXT,
                verdict     TEXT NOT NULL,
                risk_score  REAL NOT NULL,
                reasons     TEXT,
                intel       TEXT,
                latency_ms  REAL
            )
            """
        )


def insert_scan(row: dict) -> int:
    with _lock, _conn() as c:
        cur = c.execute(
            """INSERT INTO scans (ts, url, hostname, verdict, risk_score, reasons, intel, latency_ms)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                row["ts"], row["url"], row.get("hostname"), row["verdict"],
                row["risk_score"], json.dumps(row.get("reasons", [])),
                json.dumps(row.get("intel", {})), row.get("latency_ms"),
            ),
        )
        return cur.lastrowid


def recent_scans(limit: int = 100) -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        d["intel"] = json.loads(d["intel"] or "{}")
        out.append(d)
    return out


def get_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["reasons"] = json.loads(d["reasons"] or "[]")
    d["intel"] = json.loads(d["intel"] or "{}")
    return d


def stats() -> dict:
    with _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phish = c.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict='phishing'"
        ).fetchone()[0]
        susp = c.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict='suspicious'"
        ).fetchone()[0]
    return {
        "total": total,
        "phishing": phish,
        "suspicious": susp,
        "legitimate": total - phish - susp,
    }
