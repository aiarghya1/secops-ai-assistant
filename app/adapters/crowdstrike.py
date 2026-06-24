"""
SecOps AI Assistant — CrowdStrike Falcon Adapter

Converts CrowdStrike Falcon detection event JSON into the normalized NormalizedAlert schema.
Handles the nested event/metadata structure from the Falcon Streaming API.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.alert import (
    AlertCategory,
    AlertSeverity,
    EndpointInfo,
    NetworkInfo,
    NormalizedAlert,
    ProcessInfo,
    UserInfo,
)

_CS_SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "informational": AlertSeverity.INFORMATIONAL,
    "info": AlertSeverity.INFORMATIONAL,
    # Numeric severities (CrowdStrike uses 1-5)
    "5": AlertSeverity.CRITICAL,
    "4": AlertSeverity.HIGH,
    "3": AlertSeverity.MEDIUM,
    "2": AlertSeverity.LOW,
    "1": AlertSeverity.INFORMATIONAL,
}

_CS_CATEGORY_MAP = {
    "malware": AlertCategory.MALWARE,
    "ransomware": AlertCategory.MALWARE,
    "detection": AlertCategory.SUSPICIOUS_ACTIVITY,
    "prevention": AlertCategory.SUSPICIOUS_ACTIVITY,
    "credential theft": AlertCategory.BRUTE_FORCE,
    "privilege escalation": AlertCategory.PRIVILEGE_ESCALATION,
    "lateral movement": AlertCategory.NETWORK_INTRUSION,
    "command and control": AlertCategory.C2_COMMUNICATION,
    "exfiltration": AlertCategory.DATA_EXFILTRATION,
    "reconnaissance": AlertCategory.RECONNAISSANCE,
}


def is_crowdstrike_format(data: dict[str, Any]) -> bool:
    """Detect if the data looks like a CrowdStrike detection event."""
    # Check for CrowdStrike event structure
    if "event" in data and isinstance(data["event"], dict):
        event = data["event"]
        cs_fields = ["SeverityName", "EndpointIp", "EndpointName", "IncidentType",
                      "DetectName", "ComputerName", "Severity"]
        matches = sum(1 for f in cs_fields if f in event)
        if matches >= 2:
            return True

    # Check for flattened CrowdStrike fields
    cs_flat_fields = ["SeverityName", "DetectName", "FalconHostLink",
                       "ComputerName", "DetectDescription"]
    matches = sum(1 for f in cs_flat_fields if f in data)
    return matches >= 2


def adapt_crowdstrike_alert(data: dict[str, Any]) -> NormalizedAlert:
    """Convert a CrowdStrike Falcon detection event into NormalizedAlert."""
    # Handle nested vs flattened structure
    event = data.get("event", data)
    metadata = data.get("metadata", {})

    # Alert ID
    alert_id = (
        metadata.get("id")
        or event.get("DetectId")
        or event.get("IncidentId")
        or f"cs-{uuid.uuid4().hex[:12]}"
    )

    # Timestamp
    timestamp = (
        metadata.get("updated_at")
        or event.get("ProcessStartTime")
        or event.get("CreatedTimestamp")
        or event.get("Timestamp")
        or datetime.now(timezone.utc).isoformat()
    )

    # Title
    title = (
        event.get("DetectName")
        or event.get("IncidentDescription")
        or event.get("DetectDescription")
        or event.get("Tactic")
        or "CrowdStrike Detection"
    )

    # Description
    description = (
        event.get("DetectDescription")
        or event.get("IncidentDescription")
        or event.get("Objective")
    )

    # Severity
    severity_raw = str(
        event.get("SeverityName", "")
        or event.get("Severity", "")
        or event.get("MaxSeverity", "")
    ).lower().strip()
    severity = _CS_SEVERITY_MAP.get(severity_raw, AlertSeverity.UNKNOWN)

    # Category
    incident_type = str(event.get("IncidentType", "") or event.get("Tactic", "")).lower()
    category = _CS_CATEGORY_MAP.get(incident_type, AlertCategory.UNKNOWN)
    if category == AlertCategory.UNKNOWN:
        # Try to detect from description
        text = f"{title} {description or ''}".lower()
        for key, cat in _CS_CATEGORY_MAP.items():
            if key in text:
                category = cat
                break

    # Network info
    network = NetworkInfo(
        src_ip=event.get("EndpointIp") or event.get("LocalIP"),
        dest_ip=event.get("RemoteAddress") or event.get("ExternalIP"),
        dest_port=_safe_int(event.get("RemotePort")),
        protocol=event.get("Protocol"),
    )

    # Endpoint info
    endpoint = EndpointInfo(
        hostname=(
            event.get("EndpointName")
            or event.get("ComputerName")
            or event.get("MachineDomain")
        ),
        ip_address=event.get("EndpointIp") or event.get("LocalIP"),
        os=event.get("Platform") or event.get("OS"),
        agent_version=event.get("AgentVersion"),
    )

    # User info
    user = UserInfo(
        username=event.get("UserName") or event.get("UserPrincipal"),
        domain=event.get("MachineDomain") or event.get("UserDomain"),
    )

    # Process info
    process = ProcessInfo(
        name=event.get("FileName") or event.get("ProcessName"),
        pid=_safe_int(event.get("ProcessId")),
        command_line=event.get("CommandLine") or event.get("CmdLine"),
        parent_name=event.get("ParentImageFileName") or event.get("ParentProcessName"),
        parent_pid=_safe_int(event.get("ParentProcessId")),
        file_path=event.get("FilePath") or event.get("ImageFileName"),
        file_hash=event.get("SHA256") or event.get("MD5") or event.get("SHA1"),
    )

    # MITRE mappings
    mitre_tactics = []
    mitre_techniques = []
    if event.get("Tactic"):
        mitre_tactics.append(event["Tactic"])
    if event.get("Technique"):
        mitre_techniques.append(event["Technique"])

    # Extract indicators
    indicators = _extract_cs_indicators(event)

    return NormalizedAlert(
        id=alert_id,
        timestamp=timestamp,
        source_format="crowdstrike",
        title=title,
        description=description,
        severity=severity,
        category=category,
        network=network,
        endpoint=endpoint,
        user=user,
        process=process,
        rule_id=event.get("DetectId"),
        rule_name=event.get("DetectName"),
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_indicators=indicators,
        raw_data=data,
    )


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _extract_cs_indicators(event: dict) -> list[str]:
    """Extract IOCs from CrowdStrike event data."""
    indicators = set()
    ip_fields = ["EndpointIp", "LocalIP", "RemoteAddress", "ExternalIP"]
    hash_fields = ["SHA256", "MD5", "SHA1"]
    domain_fields = ["DomainName", "RemoteHost"]

    for field in ip_fields + hash_fields + domain_fields:
        val = event.get(field)
        if val and isinstance(val, str) and val.strip():
            indicators.add(val.strip())

    # CrowdStrike IOCs array
    iocs = event.get("IOCs", [])
    if isinstance(iocs, list):
        for ioc in iocs:
            if isinstance(ioc, str):
                indicators.add(ioc)
            elif isinstance(ioc, dict) and "value" in ioc:
                indicators.add(str(ioc["value"]))

    return list(indicators)
