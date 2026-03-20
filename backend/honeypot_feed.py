"""
honeypot_feed.py – Cyber Shield Honeypot integration for Threat Intelligence API

Provides read-only access to the Cyber Shield SQLite database to check if an IP
has been observed by the honeypot sensor network.

Functions:
    is_ip_in_honeypot(ip) -> bool
    get_honeypot_details(ip) -> dict
    get_all_honeypot_ips(limit) -> list[dict]
"""
import os
import sqlite3
import logging
import functools
from datetime import datetime

logger = logging.getLogger("ThreatAPI.HoneypotFeed")

# ─── Configuration ────────────────────────────────────────────────────────────

def _get_db_path() -> str:
    """Resolve the shared SQLite database path (same as Cyber Shield uses)."""
    return os.environ.get("DATABASE_URL", "data/cyber_shield.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


# ─── In-process LRU cache (avoids hammering DB during Bulk CSV jobs) ──────────

@functools.lru_cache(maxsize=4096)
def is_ip_in_honeypot(ip: str) -> bool:
    """
    Returns True if the given IP has at least one record in the honeypot database.

    Data source: 'anomalies' table, column 'src_ip'.
    Caches each result for the lifetime of the process (LRU, max 4096 unique IPs).
    """
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM anomalies WHERE src_ip = ? LIMIT 1",
                (ip,)
            )
            result = cursor.fetchone()
            found = result is not None
            logger.debug(f"[HoneypotFeed] is_ip_in_honeypot({ip}) -> {found}")
            return found
    except Exception as e:
        logger.error(f"[HoneypotFeed] DB error for {ip}: {e}")
        return False


def get_honeypot_details(ip: str) -> dict:
    """
    Returns detailed honeypot stats for a given IP:
      - hit_count: total number of records
      - first_seen: earliest timestamp
      - last_seen: most recent timestamp
      - types: list of distinct threat types recorded
    Returns empty dict if IP not found or on error.
    """
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    COUNT(*)       AS hit_count,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen,
                    GROUP_CONCAT(DISTINCT type) AS types
                FROM anomalies
                WHERE src_ip = ?
                """,
                (ip,)
            )
            row = cursor.fetchone()
            if not row or row["hit_count"] == 0:
                return {}
            return {
                "hit_count":  row["hit_count"],
                "first_seen": row["first_seen"],
                "last_seen":  row["last_seen"],
                "types":      row["types"].split(",") if row["types"] else [],
            }
    except Exception as e:
        logger.error(f"[HoneypotFeed] get_honeypot_details error for {ip}: {e}")
        return {}


def get_all_honeypot_ips(limit: int = 500) -> list:
    """
    Returns a list of all unique IPs observed by the honeypot, with stats.
    Used by GET /api/honeypot-feed endpoint.
    """
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    src_ip,
                    COUNT(*)       AS hit_count,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen
                FROM anomalies
                WHERE src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY hit_count DESC
                LIMIT ?
                """,
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"[HoneypotFeed] get_all_honeypot_ips error: {e}")
        return []


def invalidate_cache() -> None:
    """Clear the LRU cache (call after DB is updated during tests or seeding)."""
    is_ip_in_honeypot.cache_clear()
    logger.info("[HoneypotFeed] LRU cache cleared.")
