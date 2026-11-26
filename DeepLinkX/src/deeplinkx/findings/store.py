"""Local scan history and finding status tracking (SQLite)."""
from __future__ import annotations

import json
import sqlite3
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from ..config import home_dir
from ..errors import DeeplinkXError
from ..models import Finding, Status

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created TEXT NOT NULL,
  package TEXT NOT NULL,
  version TEXT,
  apk_name TEXT,
  sha256 TEXT,
  profile TEXT,
  risk INTEGER,
  level TEXT,
  counts TEXT,
  duration REAL,
  data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_pkg ON scans(package, id);
CREATE TABLE IF NOT EXISTS scan_findings (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  rule_id TEXT, severity TEXT, component TEXT, title TEXT,
  PRIMARY KEY (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS statuses (
  package TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT DEFAULT '',
  updated TEXT NOT NULL,
  PRIMARY KEY (package, fingerprint)
);
"""


class HistoryError(DeeplinkXError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else home_dir() / "history.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- scans
    def save_scan(self, report: dict) -> int:
        apk = report["apk"]
        summary = report["summary"]
        blob = zlib.compress(json.dumps(report, separators=(",", ":")).encode("utf-8"), 6)
        with self._db() as db:
            cur = db.execute(
                "INSERT INTO scans(created, package, version, apk_name, sha256, profile, risk, level, counts, "
                "duration, data) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (report["meta"]["created"], apk["package"], apk.get("version_name") or "", apk["file_name"],
                 apk["hashes"]["sha256"], report["meta"]["profile"], summary["risk_score"], summary["risk_level"],
                 json.dumps(summary["by_severity"]), report["meta"].get("duration", 0.0), blob))
            scan_id = cur.lastrowid
            db.executemany(
                "INSERT OR IGNORE INTO scan_findings VALUES (?,?,?,?,?,?)",
                [(scan_id, f["fingerprint"], f["rule_id"], f["severity"], f.get("component"), f["title"])
                 for f in report["findings"]])
        return int(scan_id)

    def list_scans(self, limit: int = 50, package: Optional[str] = None) -> list[dict]:
        sql = ("SELECT id, created, package, version, apk_name, sha256, profile, risk, level, counts, duration "
               "FROM scans")
        args: list = []
        if package:
            sql += " WHERE package = ?"
            args.append(package)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._db() as db:
            rows = db.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["counts"] = json.loads(d["counts"] or "{}")
            out.append(d)
        return out

    def get_scan(self, scan_id: int) -> dict:
        with self._db() as db:
            row = db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise HistoryError(f"scan {scan_id} not found")
        report = json.loads(zlib.decompress(row["data"]).decode("utf-8"))
        report["meta"]["scan_id"] = scan_id
        return report

    def latest(self, package: str, before: Optional[int] = None) -> Optional[dict]:
        sql = "SELECT id FROM scans WHERE package = ?"
        args: list = [package]
        if before is not None:
            sql += " AND id < ?"
            args.append(before)
        sql += " ORDER BY id DESC LIMIT 1"
        with self._db() as db:
            row = db.execute(sql, args).fetchone()
        return self.get_scan(row["id"]) if row else None

    def delete_scan(self, scan_id: int) -> bool:
        with self._db() as db:
            return db.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0

    def prune(self, keep: int = 50) -> int:
        with self._db() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM scans ORDER BY id DESC LIMIT -1 OFFSET ?", (keep,))]
            for i in ids:
                db.execute("DELETE FROM scans WHERE id = ?", (i,))
        return len(ids)

    # ---- status tracking
    def statuses(self, package: str) -> dict[str, dict]:
        with self._db() as db:
            rows = db.execute("SELECT fingerprint, status, note, updated FROM statuses WHERE package = ?",
                              (package,)).fetchall()
        return {r["fingerprint"]: dict(r) for r in rows}

    def apply_statuses(self, package: str, findings: list[Finding]) -> None:
        known = self.statuses(package)
        for f in findings:
            st = known.get(f.fingerprint)
            if st:
                f.status = Status.parse(st["status"])

    def set_status(self, package: str, fingerprint_prefix: str, status: str | Status, note: str = "") -> list[str]:
        st = Status.parse(status)
        report = self.latest(package)
        if report is None:
            raise HistoryError(f"no scan for package {package}")
        fps = {f["fingerprint"] for f in report["findings"]}
        for f in report["findings"]:
            if f["id"].lower() == fingerprint_prefix.lower():
                fps = {f["fingerprint"]}
                break
        else:
            fps = {fp for fp in fps if fp.startswith(fingerprint_prefix)}
        if not fps:
            raise HistoryError(f"no finding matches '{fingerprint_prefix}'")
        if len(fps) > 1:
            raise HistoryError(f"'{fingerprint_prefix}' is ambiguous ({len(fps)} findings)")
        with self._db() as db:
            for fp in fps:
                db.execute(
                    "INSERT INTO statuses(package, fingerprint, status, note, updated) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(package, fingerprint) DO UPDATE SET status=excluded.status, note=excluded.note, "
                    "updated=excluded.updated", (package, fp, st.value, note, _now()))
        return sorted(fps)

    # ---- comparison
    def diff(self, older: dict, newer: dict) -> dict:
        a = {f["fingerprint"]: f for f in older["findings"]}
        b = {f["fingerprint"]: f for f in newer["findings"]}
        return {
            "new": [b[k] for k in b if k not in a],
            "resolved": [a[k] for k in a if k not in b],
            "persisting": [b[k] for k in b if k in a],
            "risk_before": older["summary"]["risk_score"],
            "risk_after": newer["summary"]["risk_score"],
        }
