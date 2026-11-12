"""SQLite persistence for scan metadata and sanitized analysis results."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class ScanRepository:
    """Store completed scan summaries and evidence without response bodies."""

    def __init__(self, database_path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    risk_json TEXT NOT NULL,
                    request_stats_json TEXT NOT NULL,
                    report_paths_json TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _sanitize_config(config):
        """Remove secret-like fields and redact URL query strings before storage."""
        secret_markers = (
            "authorization",
            "cookie",
            "password",
            "secret",
            "token",
            "credential",
            "api-key",
            "api_key",
        )

        def clean(value, key=""):
            normalized_key = key.lower()
            if any(marker in normalized_key for marker in secret_markers):
                return "[REDACTED]"
            if isinstance(value, dict):
                return {
                    item_key: clean(item, item_key)
                    for item_key, item in value.items()
                }
            if isinstance(value, list):
                return [clean(item) for item in value]
            return value

        sanitized = clean(config)
        target = sanitized.get("target", {}) if isinstance(sanitized, dict) else {}
        if isinstance(target, dict) and isinstance(target.get("url"), str):
            parsed = urlsplit(target["url"])
            hostname = parsed.hostname or ""
            if ":" in hostname:
                hostname = f"[{hostname}]"
            if parsed.port is not None:
                hostname = f"{hostname}:{parsed.port}"
            target["url"] = urlunsplit(
                (parsed.scheme, hostname, parsed.path, "", "")
            )
        if isinstance(sanitized, dict):
            sanitized.pop("_config_path", None)
        return sanitized

    def save_scan(
        self,
        scan_id,
        target,
        started_at,
        completed_at,
        config,
        analysis_results,
        risk_report,
        request_stats,
        report_paths,
    ):
        """Persist a scan atomically using bound SQL parameters."""
        parsed_target = urlsplit(target)
        hostname = parsed_target.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if parsed_target.port is not None:
            hostname = f"{hostname}:{parsed_target.port}"
        safe_target = urlunsplit(
            (
                parsed_target.scheme,
                hostname,
                parsed_target.path,
                "",
                "",
            )
        )
        serialized = (
            scan_id,
            safe_target,
            started_at,
            completed_at,
            json.dumps(self._sanitize_config(config), ensure_ascii=False),
            json.dumps(analysis_results, ensure_ascii=False),
            json.dumps(risk_report, ensure_ascii=False),
            json.dumps(request_stats, ensure_ascii=False),
            json.dumps(report_paths, ensure_ascii=False),
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, target, started_at, completed_at, config_json,
                    analysis_json, risk_json, request_stats_json, report_paths_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                serialized,
            )

    def list_scans(self, limit=50):
        """Return recent scan summaries, newest first."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("Scan list limit must be a positive integer.")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scan_id, target, started_at, completed_at, request_stats_json
                FROM scans ORDER BY completed_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "scan_id": row["scan_id"],
                "target": row["target"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "request_stats": json.loads(row["request_stats_json"]),
            }
            for row in rows
        ]

    def get_scan(self, scan_id):
        """Retrieve one stored scan, or raise KeyError when it does not exist."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"Scan not found: {scan_id}")
        return {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "config": json.loads(row["config_json"]),
            "analysis_results": json.loads(row["analysis_json"]),
            "risk_report": json.loads(row["risk_json"]),
            "request_stats": json.loads(row["request_stats_json"]),
            "report_paths": json.loads(row["report_paths_json"]),
        }

    def latest_scan(self):
        """Return the most recently completed scan, or None if no scans exist."""
        scans = self.list_scans(limit=1)
        return self.get_scan(scans[0]["scan_id"]) if scans else None
