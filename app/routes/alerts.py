"""
SecOps AI Assistant — Alert Routes

API endpoints for ingesting and managing security alerts.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from app.adapters.adapter_registry import normalize_alert
from app.ai.analyzer import AlertAnalyzer
from app.config import get_settings
from app.database import get_alert, list_alerts, save_alert, save_investigation, update_alert_status
from app.models.investigation import AnalysisRequest, AnalysisResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


async def background_analyze_alert(alert_id: str, alert_data: dict, source_format: str | None = None):
    """Background task to analyze an alert without blocking the ingestion API."""
    try:
        # Update status
        await update_alert_status(alert_id, "analyzing")
        
        # Normalize
        normalized = normalize_alert(alert_data, source_format)
        await save_alert(
            alert_id=alert_id,
            raw_json=alert_data,
            normalized_json=normalized.model_dump(),
            source_format=normalized.source_format,
        )
        
        # Analyze
        analyzer = AlertAnalyzer()
        investigation, enrichment = await analyzer.analyze(normalized)
        
        # Save results
        await save_investigation(
            investigation_id=investigation.investigation_id,
            alert_id=alert_id,
            enrichment_json=enrichment.model_dump(),
            analysis_json=investigation.model_dump(),
            llm_provider=investigation.llm_provider,
            llm_model=investigation.llm_model,
            latency_ms=investigation.analysis_latency_ms,
            token_count=investigation.token_count,
            estimated_cost=investigation.estimated_cost,
        )
        
        await update_alert_status(alert_id, "completed")
        logger.info(f"Background analysis completed for {alert_id}")
        
        # In a real system, you would broadcast via WebSocket here
        # (This is handled in the frontend for this prototype)
        
    except Exception as e:
        logger.error(f"Background analysis failed for {alert_id}: {e}")
        await update_alert_status(alert_id, "failed")


@router.post("/ingest")
async def ingest_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    source: str | None = None,
):
    """
    Ingest a raw security alert.
    
    Accepts any JSON payload. Source format is auto-detected if not provided.
    Analysis runs in the background.
    """
    try:
        alert_data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not isinstance(alert_data, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object")

    try:
        # Quickly normalize to get an ID and validate
        normalized = normalize_alert(alert_data, source)
        
        # Save initial state
        await save_alert(
            alert_id=normalized.id,
            raw_json=alert_data,
            normalized_json=normalized.model_dump(),
            source_format=normalized.source_format,
        )
        
        # Kick off background analysis
        background_tasks.add_task(
            background_analyze_alert,
            normalized.id,
            alert_data,
            normalized.source_format,
        )
        
        return {
            "success": True,
            "message": "Alert ingested and queued for analysis",
            "alert_id": normalized.id,
            "source_format": normalized.source_format,
        }
        
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Ingest error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during ingestion")


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_alert_sync(request: AnalysisRequest):
    """
    Ingest and analyze an alert synchronously.
    
    Useful for testing or UI actions that need an immediate response.
    """
    try:
        normalized = normalize_alert(request.alert_data, request.source_format)
        
        # Save
        await save_alert(
            alert_id=normalized.id,
            raw_json=request.alert_data,
            normalized_json=normalized.model_dump(),
            source_format=normalized.source_format,
        )
        await update_alert_status(normalized.id, "analyzing")
        
        # Analyze
        analyzer = AlertAnalyzer()
        investigation, enrichment = await analyzer.analyze(
            normalized, 
            force_reanalyze=request.force_reanalyze
        )
        
        # Save results
        await save_investigation(
            investigation_id=investigation.investigation_id,
            alert_id=normalized.id,
            enrichment_json=enrichment.model_dump(),
            analysis_json=investigation.model_dump(),
            llm_provider=investigation.llm_provider,
            llm_model=investigation.llm_model,
            latency_ms=investigation.analysis_latency_ms,
            token_count=investigation.token_count,
            estimated_cost=investigation.estimated_cost,
        )
        
        await update_alert_status(normalized.id, "completed")
        
        return AnalysisResponse(
            success=True,
            alert_id=normalized.id,
            source_format=normalized.source_format,
            investigation=investigation,
            demo_mode=get_settings().is_demo_mode,
        )
        
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Sync analysis error: {e}")
        return AnalysisResponse(
            success=False,
            alert_id="unknown",
            source_format="unknown",
            error=str(e),
        )


@router.get("")
async def get_alerts(limit: int = 50, offset: int = 0):
    """List ingested alerts."""
    return await list_alerts(limit, offset)


@router.get("/{alert_id}")
async def get_alert_by_id(alert_id: str):
    """Get details for a specific alert."""
    alert = await get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
