import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Generator

import config
from analyzer import AnalysisResult



_CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    subject         TEXT    NOT NULL,
    sender          TEXT    NOT NULL,
    content         TEXT    NOT NULL,
    threat_level    TEXT    NOT NULL,
    threat_score    INTEGER NOT NULL,
    keywords        TEXT    NOT NULL,   -- JSON array
    urgent_keywords TEXT    NOT NULL,   -- JSON array
    urls            TEXT    NOT NULL,   -- JSON array
    suspicious_urls TEXT    NOT NULL,   -- JSON array
    red_flags       TEXT    NOT NULL,   -- JSON array
    explanation     TEXT    NOT NULL,
    recommendations TEXT    NOT NULL    -- JSON array
);
"""

_CREATE_IDX_TIMESTAMP = """
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);
"""

_CREATE_IDX_THREAT = """
CREATE INDEX IF NOT EXISTS idx_scans_threat ON scans (threat_level);
"""



class DatabaseManager:
    """
    Thin wrapper around the SQLite database that stores scan results.

    Usage
    -----
    db = DatabaseManager()
    db.save_scan(result)
    rows = db.get_recent_scans(20)
    stats = db.get_statistics()
    """

    def __init__(self, db_path: str = config.DB_PATH):
        self._path = db_path
        self._initialise()



    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield an auto-committing connection; roll back on error."""
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row          # access columns by name
        conn.execute("PRAGMA journal_mode=WAL") # safe for concurrent reads
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialise(self) -> None:
        """Create tables and indexes if they do not yet exist."""
        with self._connect() as conn:
            conn.execute(_CREATE_SCANS_TABLE)
            conn.execute(_CREATE_IDX_TIMESTAMP)
            conn.execute(_CREATE_IDX_THREAT)


    def save_scan(self, result: AnalysisResult) -> int:
        """
        Persist a completed AnalysisResult to the database.
        Returns the newly inserted row id.
        """
        sql = """
        INSERT INTO scans (
            timestamp, subject, sender, content,
            threat_level, threat_score,
            keywords, urgent_keywords, urls, suspicious_urls,
            red_flags, explanation, recommendations
        ) VALUES (
            :timestamp, :subject, :sender, :content,
            :threat_level, :threat_score,
            :keywords, :urgent_keywords, :urls, :suspicious_urls,
            :red_flags, :explanation, :recommendations
        )
        """
        params = {
            "timestamp":       result.timestamp,
            "subject":         result.subject,
            "sender":          result.sender,
            "content":         result.content,
            "threat_level":    result.threat_level,
            "threat_score":    result.threat_score,
            "keywords":        json.dumps(result.matched_keywords),
            "urgent_keywords": json.dumps(result.matched_urgent_keywords),
            "urls":            json.dumps(result.detected_urls),
            "suspicious_urls": json.dumps(result.suspicious_urls),
            "red_flags":       json.dumps(result.red_flags),
            "explanation":     result.explanation,
            "recommendations": json.dumps(result.recommendations),
        }
        with self._connect() as conn:
            cursor = conn.execute(sql, params)
            return cursor.lastrowid

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a single scan record by id. Returns True if a row was deleted."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def clear_all_scans(self) -> int:
        """Delete every scan record. Returns the number of rows deleted."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans")
            return cursor.rowcount

  

    def get_recent_scans(self, limit: int = config.MAX_HISTORY_DISPLAY) -> list[dict[str, Any]]:
        """
        Return the most recent `limit` scans, newest first.
        JSON columns are automatically decoded back to Python objects.
        """
        sql = """
        SELECT id, timestamp, subject, sender, threat_level, threat_score,
               keywords, urgent_keywords, urls, suspicious_urls,
               red_flags, explanation, recommendations, content
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """
        with self._connect() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [self._deserialise_row(row) for row in rows]

    def get_scan_by_id(self, scan_id: int) -> dict[str, Any] | None:
        """Return a single scan record by primary key, or None if not found."""
        sql = "SELECT * FROM scans WHERE id = ?"
        with self._connect() as conn:
            row = conn.execute(sql, (scan_id,)).fetchone()
        return self._deserialise_row(row) if row else None

    def get_statistics(self) -> dict[str, int]:
        """
        Return aggregate counts used by the dashboard statistics panel.

        Keys
        ----
        total       – all scans ever stored
        safe        – scans classified as Safe
        suspicious  – scans classified as Suspicious
        malicious   – scans classified as Malicious
        """
        sql = """
        SELECT
            COUNT(*)                                            AS total,
            SUM(CASE WHEN threat_level = :safe     THEN 1 ELSE 0 END) AS safe,
            SUM(CASE WHEN threat_level = :susp     THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN threat_level = :mal      THEN 1 ELSE 0 END) AS malicious
        FROM scans
        """
        params = {
            "safe": config.THREAT_SAFE,
            "susp": config.THREAT_SUSPICIOUS,
            "mal":  config.THREAT_MALICIOUS,
        }
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()

        if row is None:
            return {"total": 0, "safe": 0, "suspicious": 0, "malicious": 0}

        return {
            "total":      row["total"]      or 0,
            "safe":       row["safe"]       or 0,
            "suspicious": row["suspicious"] or 0,
            "malicious":  row["malicious"]  or 0,
        }

    def search_scans(
        self,
        keyword: str = "",
        threat_level: str = "",
        limit: int = config.MAX_HISTORY_DISPLAY,
    ) -> list[dict[str, Any]]:
        """
        Filter scans by free-text keyword (matches subject/sender/content)
        and/or threat level.  Returns newest-first up to `limit` rows.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if keyword.strip():
            conditions.append(
                "(subject LIKE ? OR sender LIKE ? OR content LIKE ?)"
            )
            like = f"%{keyword.strip()}%"
            params.extend([like, like, like])

        if threat_level.strip():
            conditions.append("threat_level = ?")
            params.append(threat_level.strip())

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
        SELECT id, timestamp, subject, sender, threat_level, threat_score,
               keywords, urgent_keywords, urls, suspicious_urls,
               red_flags, explanation, recommendations, content
        FROM scans
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
        """
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialise_row(row) for row in rows]

    def get_total_count(self) -> int:
        """Return the total number of stored scans."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
        return row["n"] if row else 0



    @staticmethod
    def _deserialise_row(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a sqlite3.Row to a plain dict, decoding JSON columns."""
        d = dict(row)
        json_columns = (
            "keywords", "urgent_keywords", "urls",
            "suspicious_urls", "red_flags", "recommendations",
        )
        for col in json_columns:
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    d[col] = []
        return d
