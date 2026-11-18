"""SQLite storage for scans and findings. Cookie values are never stored."""
import sqlite3
from datetime import datetime

import config
from scanner.severity import SEVERITY_ORDER, risk_summary

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT NOT NULL, started_at TEXT NOT NULL,
    completed_at TEXT, status TEXT NOT NULL, total_findings INTEGER DEFAULT 0,
    risk_summary TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_name TEXT, title TEXT, category TEXT, status TEXT, severity TEXT,
    evidence TEXT, explanation TEXT, recommendation TEXT, rule_reason TEXT);
"""
_ORDER_SQL = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITY_ORDER)) + " END"


def conn():
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_scan(target):
    with conn() as c:
        return c.execute("INSERT INTO scans (target_url, started_at, status) VALUES (?,?,?)",
                         (target, _now(), "Running")).lastrowid


def finish_scan(scan_id, status, findings, error=None):
    total = sum(1 for f in findings if f["status"] != "Pass")
    with conn() as c:
        for f in findings:
            c.execute("""INSERT INTO findings (scan_id, check_name, title, category, status, severity,
                         evidence, explanation, recommendation, rule_reason) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                      (scan_id, f["check_name"], f["title"], f["category"], f["status"], f["severity"],
                       f["evidence"], f["explanation"], f["recommendation"], f["rule_reason"]))
        c.execute("UPDATE scans SET completed_at=?, status=?, total_findings=?, risk_summary=?, error=? WHERE id=?",
                  (_now(), status, total, risk_summary(findings), error, scan_id))


def get_scan(scan_id):
    with conn() as c:
        return c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()


def get_findings(scan_id):
    with conn() as c:
        return c.execute(f"SELECT * FROM findings WHERE scan_id=? ORDER BY {_ORDER_SQL}, "
                         f"CASE status WHEN 'Fail' THEN 0 WHEN 'Info' THEN 1 ELSE 2 END, id", (scan_id,)).fetchall()


def get_finding(scan_id, finding_id):
    with conn() as c:
        return c.execute("SELECT * FROM findings WHERE id=? AND scan_id=?", (finding_id, scan_id)).fetchone()


def list_scans(limit=None):
    sql = "SELECT * FROM scans ORDER BY id DESC" + (f" LIMIT {int(limit)}" if limit else "")
    with conn() as c:
        return c.execute(sql).fetchall()


def severity_counts(scan_id=None):
    sql, args = "SELECT severity, COUNT(*) n FROM findings WHERE status != 'Pass'", ()
    if scan_id:
        sql, args = sql + " AND scan_id=?", (scan_id,)
    with conn() as c:
        rows = {r["severity"]: r["n"] for r in c.execute(sql + " GROUP BY severity", args)}
    return {s: rows.get(s, 0) for s in SEVERITY_ORDER}


def dashboard_stats():
    return {"total_scans": len(list_scans()), "recent": list_scans(5), "counts": severity_counts()}
