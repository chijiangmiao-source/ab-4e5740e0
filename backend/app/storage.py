"""Persistent frozen audit conclusions (SQLite, stdlib only)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id          TEXT PRIMARY KEY,
    fingerprint       TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        REAL NOT NULL,
    conclusion_json   TEXT NOT NULL
);
"""


class AuditExists(Exception):
    def __init__(self, audit_id: str, fingerprint_existing: str,
                 fingerprint_incoming: str):
        super().__init__(f"audit_id {audit_id!r} is already frozen with different inputs")
        self.audit_id = audit_id
        self.fingerprint_existing = fingerprint_existing
        self.fingerprint_incoming = fingerprint_incoming


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def freeze(self, audit_id: str, fingerprint: str, conclusion: dict) -> dict:
        """Freeze a conclusion.

        Same audit_id + same input fingerprint returns the previously frozen
        conclusion (idempotent reopen/resubmit); a different fingerprint is a
        conflict -- frozen conclusions never silently mutate.
        """
        payload = json.dumps(conclusion, ensure_ascii=False, sort_keys=True)
        with self._lock:
            cur = self._conn.execute(
                "SELECT fingerprint, conclusion_json FROM audits WHERE audit_id = ?",
                (audit_id,),
            )
            row = cur.fetchone()
            if row is not None:
                existing_fp, existing_json = row
                if existing_fp != fingerprint:
                    raise AuditExists(audit_id, existing_fp, fingerprint)
                return json.loads(existing_json) | {"reopened": True}
            now = time.time()
            self._conn.execute(
                "INSERT INTO audits (audit_id, fingerprint, status, created_at, "
                "conclusion_json) VALUES (?, ?, ?, ?, ?)",
                (audit_id, fingerprint, conclusion.get("status"), now, payload),
            )
            self._conn.commit()
            stored = json.loads(payload)
            stored["frozen_at"] = now
            return stored

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT conclusion_json, created_at FROM audits WHERE audit_id = ?",
                (audit_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        data = json.loads(row[0])
        data["frozen_at"] = row[1]
        data["reopened"] = True
        return data

    def list_ids(self) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT audit_id, status, fingerprint, created_at FROM audits "
                "ORDER BY created_at DESC"
            )
            rows = cur.fetchall()
        return [
            {"audit_id": a, "status": s, "fingerprint": f, "frozen_at": t}
            for a, s, f, t in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
