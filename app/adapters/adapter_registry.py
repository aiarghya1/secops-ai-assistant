"""
SecOps AI Assistant — Adapter Registry

Auto-detects alert source format and routes to the correct adapter.
Falls back to the generic adapter for unrecognized formats.
"""

from __future__ import annotations

import logging
from typing import Any

from app.adapters.crowdstrike import adapt_crowdstrike_alert, is_crowdstrike_format
from app.adapters.generic import adapt_generic_alert
from app.adapters.splunk import adapt_splunk_alert, is_splunk_format
from app.adapters.suricata import adapt_suricata_alert, is_suricata_format
from app.models.alert import NormalizedAlert

logger = logging.getLogger(__name__)

# Ordered by specificity — most specific first
_ADAPTERS = [
    ("suricata", is_suricata_format, adapt_suricata_alert),
    ("crowdstrike", is_crowdstrike_format, adapt_crowdstrike_alert),
    ("splunk", is_splunk_format, adapt_splunk_alert),
]


def detect_format(data: dict[str, Any]) -> str:
    """
    Auto-detect the alert format from the JSON structure.

    Returns: 'splunk', 'crowdstrike', 'suricata', or 'generic'
    """
    for name, detector, _ in _ADAPTERS:
        try:
            if detector(data):
                logger.info(f"Detected alert format: {name}")
                return name
        except Exception as e:
            logger.warning(f"Format detection error for {name}: {e}")
            continue

    logger.info("No specific format detected, using generic adapter")
    return "generic"


def normalize_alert(
    data: dict[str, Any],
    source_format: str | None = None,
) -> NormalizedAlert:
    """
    Normalize a raw alert JSON into the internal NormalizedAlert schema.

    Args:
        data: Raw alert JSON data
        source_format: Optional format hint ('splunk', 'crowdstrike', 'suricata', 'generic').
                       If None, auto-detects the format.

    Returns:
        NormalizedAlert with consistent field structure.

    Raises:
        ValueError: If the alert data cannot be parsed.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Alert data must be a JSON object (dict), got {type(data).__name__}")

    if not data:
        raise ValueError("Alert data cannot be empty")

    # Auto-detect if no format specified
    if source_format is None:
        source_format = detect_format(data)

    # Route to adapter
    adapter_map = {
        "suricata": adapt_suricata_alert,
        "crowdstrike": adapt_crowdstrike_alert,
        "splunk": adapt_splunk_alert,
        "generic": adapt_generic_alert,
    }

    adapter_fn = adapter_map.get(source_format.lower(), adapt_generic_alert)

    try:
        normalized = adapter_fn(data)
        logger.info(
            f"Normalized alert: id={normalized.id}, "
            f"format={normalized.source_format}, "
            f"severity={normalized.severity.value}, "
            f"title={normalized.title[:80]}"
        )
        return normalized
    except Exception as e:
        logger.error(f"Adapter error for format '{source_format}': {e}")
        # Fall back to generic on any adapter error
        try:
            return adapt_generic_alert(data)
        except Exception as fallback_error:
            raise ValueError(
                f"Failed to parse alert with both '{source_format}' and generic adapters: "
                f"{e} / {fallback_error}"
            ) from fallback_error
