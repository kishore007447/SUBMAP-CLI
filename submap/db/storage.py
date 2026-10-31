"""SQLite persistence layer for scan results and history."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from submap.core.models import ScanResult
from submap.utils.logger import get_logger

log = get_logger(__name__)

DB_PATH = Path.home() / ".config" / "submap" / "scans.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    status TEXT DEFAULT 'running',
    config_json TEXT,
    result_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    asset TEXT NOT NULL,
    evidence TEXT,
    detected_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
"""


class ScanDatabase:
    """SQLite-backed scan storage."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def save_scan_start(self, scan_id: str, domain: str, config: dict) -> None:
        """Record scan start."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (id, domain, started_at, status, config_json) "
                "VALUES (?, ?, ?, 'running', ?)",
                (scan_id, domain, datetime.utcnow().isoformat(), json.dumps(config)),
            )
            conn.commit()

    def save_scan_result(self, result: ScanResult) -> None:
        """Persist a completed scan result."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE scans SET finished_at=?, status='done', result_json=? WHERE id=?",
                (
                    datetime.utcnow().isoformat(),
                    result.model_dump_json(),
                    result.scan_id,
                ),
            )
            for finding in result.findings:
                conn.execute(
                    "INSERT OR REPLACE INTO findings "
                    "(id, scan_id, domain, severity, finding_type, asset, evidence, detected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding.finding_id,
                        result.scan_id,
                        result.domain,
                        finding.severity.value,
                        finding.finding_type,
                        finding.asset,
                        finding.evidence,
                        finding.detected_at.isoformat(),
                    ),
                )
            conn.commit()

    def get_scan(self, scan_id: str) -> ScanResult | None:
        """Load a scan result by ID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            if row and row[0]:
                return ScanResult.model_validate_json(row[0])
        return None

    def get_last_scan(self, domain: str) -> ScanResult | None:
        """Load the most recent scan for a domain."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE domain=? AND status='done' "
                "ORDER BY finished_at DESC LIMIT 1",
                (domain,),
            ).fetchone()
            if row and row[0]:
                return ScanResult.model_validate_json(row[0])
        return None

    def list_scans(self, domain: Optional[str] = None, limit: int = 20) -> list[dict]:
        """List recent scans."""
        with sqlite3.connect(self.db_path) as conn:
            if domain:
                rows = conn.execute(
                    "SELECT id, domain, started_at, finished_at, status "
                    "FROM scans WHERE domain=? ORDER BY started_at DESC LIMIT ?",
                    (domain, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, domain, started_at, finished_at, status "
                    "FROM scans ORDER BY started_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()

            return [
                {
                    "id": r[0],
                    "domain": r[1],
                    "started_at": r[2],
                    "finished_at": r[3],
                    "status": r[4],
                }
                for r in rows
            ]

    def mark_interrupted(self, scan_id: str) -> None:
        """Mark a scan as interrupted (for resume support)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE scans SET status='interrupted' WHERE id=?", (scan_id,)
            )
            conn.commit()

    def get_interrupted_scan(self, domain: str) -> Optional[str]:
        """Return scan_id of most recent interrupted scan for this domain."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM scans WHERE domain=? AND status='interrupted' "
                "ORDER BY started_at DESC LIMIT 1",
                (domain,),
            ).fetchone()
        return row[0] if row else None
