"""
SecOps AI Assistant — Database Layer

Async SQLite database for alert history, investigation results, and enrichment cache.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from app.config import get_settings

_db: Optional[aiosqlite.Connection] = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    normalized_json TEXT,
    source_format TEXT,
    created_at REAL NOT NULL,
    status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    enrichment_json TEXT,
    analysis_json TEXT,
    llm_provider TEXT,
    llm_model TEXT,
    latency_ms REAL,
    token_count INTEGER,
    estimated_cost REAL,
    created_at REAL NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    cache_key TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at REAL NOT NULL,
    ttl_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_investigations_alert ON investigations(alert_id);
CREATE INDEX IF NOT EXISTS idx_cache_key ON enrichment_cache(cache_key);
"""


async def get_db() -> aiosqlite.Connection:
    """Get or create database connection."""
    global _db
    if _db is None:
        settings = get_settings()
        db_path = settings.db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _db = await aiosqlite.connect(str(db_path))
        _db.row_factory = aiosqlite.Row
        await _db.executescript(SCHEMA_SQL)
        await _db.commit()
    return _db


async def close_db():
    """Close database connection."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None


# --- Alert CRUD ---

async def save_alert(
    alert_id: str,
    raw_json: dict,
    normalized_json: dict | None = None,
    source_format: str = "unknown",
) -> None:
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO alerts (id, raw_json, normalized_json, source_format, created_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            alert_id,
            json.dumps(raw_json),
            json.dumps(normalized_json) if normalized_json else None,
            source_format,
            time.time(),
            "pending",
        ),
    )
    await db.commit()


async def update_alert_status(alert_id: str, status: str) -> None:
    db = await get_db()
    await db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    await db.commit()


async def get_alert(alert_id: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


async def list_alerts(limit: int = 50, offset: int = 0) -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = await cursor.fetchall()
    return [_row_to_dict(row) for row in rows]


async def count_alerts() -> int:
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) as cnt FROM alerts")
    row = await cursor.fetchone()
    return row[0] if row else 0


# --- Investigation CRUD ---

async def save_investigation(
    investigation_id: str,
    alert_id: str,
    enrichment_json: dict | None = None,
    analysis_json: dict | None = None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    latency_ms: float | None = None,
    token_count: int | None = None,
    estimated_cost: float | None = None,
) -> None:
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO investigations "
        "(id, alert_id, enrichment_json, analysis_json, llm_provider, llm_model, "
        "latency_ms, token_count, estimated_cost, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            investigation_id,
            alert_id,
            json.dumps(enrichment_json) if enrichment_json else None,
            json.dumps(analysis_json) if analysis_json else None,
            llm_provider,
            llm_model,
            latency_ms,
            token_count,
            estimated_cost,
            time.time(),
        ),
    )
    await db.commit()


async def get_investigation(alert_id: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM investigations WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
        (alert_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


async def get_investigation_stats() -> dict:
    db = await get_db()

    # Severity breakdown
    cursor = await db.execute(
        "SELECT analysis_json FROM investigations WHERE analysis_json IS NOT NULL"
    )
    rows = await cursor.fetchall()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    total_latency = 0.0
    total_cost = 0.0
    count = 0

    for row in rows:
        try:
            analysis = json.loads(row[0])
            severity = analysis.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        except (json.JSONDecodeError, AttributeError):
            pass

    cursor = await db.execute(
        "SELECT AVG(latency_ms), SUM(estimated_cost), COUNT(*) FROM investigations"
    )
    stats_row = await cursor.fetchone()

    return {
        "severity_breakdown": severity_counts,
        "avg_latency_ms": round(stats_row[0] or 0, 2),
        "total_cost": round(stats_row[1] or 0, 4),
        "total_investigations": stats_row[2] or 0,
    }


# --- Enrichment Cache ---

async def get_cached_enrichment(cache_key: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute(
        "SELECT data_json, created_at, ttl_seconds FROM enrichment_cache WHERE cache_key = ?",
        (cache_key,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    # Check TTL
    created_at = row[1]
    ttl = row[2]
    if time.time() - created_at > ttl:
        await db.execute("DELETE FROM enrichment_cache WHERE cache_key = ?", (cache_key,))
        await db.commit()
        return None

    return json.loads(row[0])


async def set_cached_enrichment(
    cache_key: str, data: dict, provider: str, ttl_seconds: int = 3600
) -> None:
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO enrichment_cache (cache_key, data_json, provider, created_at, ttl_seconds) "
        "VALUES (?, ?, ?, ?, ?)",
        (cache_key, json.dumps(data), provider, time.time(), ttl_seconds),
    )
    await db.commit()


# --- Helpers ---

def _row_to_dict(row: aiosqlite.Row) -> dict:
    """Convert a database row to a dictionary, parsing JSON fields."""
    d = dict(row)
    for key in ("raw_json", "normalized_json", "enrichment_json", "analysis_json", "data_json"):
        if key in d and d[key] is not None:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


async def find_related_alerts(
    ip: str | None = None,
    user: str | None = None,
    hostname: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Find historical alerts matching given indicators."""
    db = await get_db()
    conditions = []
    params = []

    if ip:
        conditions.append("(normalized_json LIKE ?)")
        params.append(f'%"{ip}"%')
    if user:
        conditions.append("(normalized_json LIKE ?)")
        params.append(f'%"{user}"%')
    if hostname:
        conditions.append("(normalized_json LIKE ?)")
        params.append(f'%"{hostname}"%')

    if not conditions:
        return []

    where_clause = " OR ".join(conditions)
    query = f"SELECT * FROM alerts WHERE {where_clause} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [_row_to_dict(row) for row in rows]
