"""
SecOps AI Assistant — Sample Routes

API endpoints for serving sample alert JSON files to the dashboard.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/samples", tags=["Samples"])

_SAMPLES_DIR = get_settings().project_root / "samples"


@router.get("")
async def list_samples():
    """List available sample alerts."""
    if not _SAMPLES_DIR.exists():
        return []
    
    samples = []
    for file_path in _SAMPLES_DIR.glob("*.json"):
        # Format name for display (e.g., splunk_brute_force -> Splunk Brute Force)
        display_name = file_path.stem.replace("_", " ").title()
        samples.append({
            "id": file_path.stem,
            "name": display_name,
            "filename": file_path.name
        })
    
    return sorted(samples, key=lambda x: x["name"])


@router.get("/{sample_id}")
async def get_sample(sample_id: str):
    """Get the raw JSON for a specific sample."""
    file_path = _SAMPLES_DIR / f"{sample_id}.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample not found")
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid JSON in sample file")
    except Exception as e:
        logger.error(f"Error reading sample {sample_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to read sample file")
