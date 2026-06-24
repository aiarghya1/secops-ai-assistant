"""
SecOps AI Assistant — Investigation Routes

API endpoints for retrieving investigation results and statistics.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.database import get_investigation, get_investigation_stats

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/investigations", tags=["Investigations"])


@router.get("/stats")
async def get_stats():
    """Get aggregate statistics for all investigations."""
    try:
        return await get_investigation_stats()
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")


@router.get("/{alert_id}")
async def get_investigation_by_alert(alert_id: str):
    """Get the investigation result for a specific alert."""
    investigation = await get_investigation(alert_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found for this alert")
    
    # Restructure for frontend consumption
    return {
        "alert_id": alert_id,
        "investigation": investigation.get("analysis_json"),
        "enrichment": investigation.get("enrichment_json"),
        "metadata": {
            "llm_provider": investigation.get("llm_provider"),
            "llm_model": investigation.get("llm_model"),
            "latency_ms": investigation.get("latency_ms"),
            "token_count": investigation.get("token_count"),
            "estimated_cost": investigation.get("estimated_cost"),
            "created_at": investigation.get("created_at"),
        }
    }
