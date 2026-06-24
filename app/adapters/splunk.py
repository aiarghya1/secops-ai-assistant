"""
SecOps AI Assistant — Splunk Alert Adapter

Converts Splunk webhook/alert JSON into the normalized NormalizedAlert schema.
Handles Splunk's nested `result` object and various field naming conventions.
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


# Splunk severity mapping
_SPLUNK_SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "informational": AlertSeverity.INFORMATIONAL,
    "info": AlertSeverity.INFORMATIONAL,
    "1": AlertSeverity.INFORMATIONAL,
    "2": AlertSeverity.LOW,
    "3": AlertSeverity.MEDIUM,
    "4": AlertSeverity.HIGH,
    "5": AlertSeverity.CRITICAL,
}

# Keywords to category mapping
_CATEGORY_KEYWORDS = {
    AlertCategory.BRUTE_FORCE: ["brute", "force", "login", "failed", "auth", "password"],
    AlertCategory.MALWARE: ["malware", "virus", "trojan", "ransomware", "worm"],
    AlertCategory.PHISHING: ["phishing", "spear", "social engineering"],
    AlertCategory.DATA_EXFILTRATION: ["exfil", "data loss", "dlp", "transfer"],
    AlertCategory.C2_COMMUNICATION: ["c2", "command and control", "beacon", "callback"],
    AlertCategory.PRIVILEGE_ESCALATION: ["privilege", "escalation", "elevation", "sudo"],
    AlertCategory.NETWORK_INTRUSION: ["intrusion", "exploit", "vulnerability", "cve"],
    AlertCategory.INSIDER_THREAT: ["insider", "unauthorized", "policy violation"],
    AlertCategory.RECONNAISSANCE: ["scan", "recon", "enumeration", "probe"],
}


def is_splunk_format(data: dict[str, Any]) -> bool:
    """Detect if the data looks like a Splunk alert."""
    splunk_indicators = ["sid", "search_name", "results_link", "result", "app"]
    matches = sum(1 for key in splunk_indicators if key in data)
    return matches >= 2


def adapt_splunk_alert(data: dict[str, Any]) -> NormalizedAlert:
    """Convert a Splunk alert JSON into NormalizedAlert."""
    # Extract the result object (where most useful data lives)
    result = data.get("result", {})
    if isinstance(result, list) and len(result) > 0:
        result = result[0]
    elif not isinstance(result, dict):
        result = {}

    # Merge top-level and result fields for searching
    all_fields = {**data, **result}

    # Alert ID
    alert_id = str(
        data.get("sid", "")
        or result.get("_cd", "")
        or f"splunk-{uuid.uuid4().hex[:12]}"
    )

    # Timestamp
    timestamp = (
        result.get("_time")
        or result.get("timestamp")
        or data.get("trigger_time")
        or datetime.now(timezone.utc).isoformat()
    )

    # Title
    title = (
        data.get("search_name")
        or data.get("name")
        or result.get("alert_name")
        or "Splunk Alert"
    )

    # Description
    description = (
        result.get("description")
        or result.get("message")
        or data.get("description")
    )

    # Severity
    severity_raw = str(
        result.get("severity", "")
        or result.get("urgency", "")
        or result.get("priority", "")
        or data.get("severity", "")
    ).lower().strip()
    severity = _SPLUNK_SEVERITY_MAP.get(severity_raw, AlertSeverity.UNKNOWN)

    # Category detection from title/description
    category = _detect_category(title, description or "")

    # Network info
    network = NetworkInfo(
        src_ip=_find_field(all_fields, ["src_ip", "src", "source_ip", "src_addr", "srcip"]),
        src_port=_safe_int(_find_field(all_fields, ["src_port", "srcport", "source_port"])),
        dest_ip=_find_field(all_fields, ["dest_ip", "dest", "destination_ip", "dst", "dst_ip", "dstip"]),
        dest_port=_safe_int(_find_field(all_fields, ["dest_port", "dstport", "destination_port"])),
        protocol=_find_field(all_fields, ["protocol", "proto", "transport"]),
    )

    # Endpoint info
    endpoint = EndpointInfo(
        hostname=_find_field(all_fields, ["host", "hostname", "dvc", "endpoint_name", "computer_name"]),
        ip_address=_find_field(all_fields, ["host_ip", "endpoint_ip"]),
        os=_find_field(all_fields, ["os", "operating_system"]),
    )

    # User info
    user = UserInfo(
        username=_find_field(all_fields, ["user", "username", "src_user", "account_name", "user_name"]),
        domain=_find_field(all_fields, ["user_domain", "domain", "nt_domain"]),
        email=_find_field(all_fields, ["email", "user_email", "mail"]),
    )

    # Process info
    process = ProcessInfo(
        name=_find_field(all_fields, ["process", "process_name", "proc"]),
        command_line=_find_field(all_fields, ["process_command", "command_line", "cmdline", "cmd"]),
        parent_name=_find_field(all_fields, ["parent_process", "parent_process_name"]),
        file_path=_find_field(all_fields, ["file_path", "filepath", "path"]),
        file_hash=_find_field(all_fields, ["file_hash", "hash", "md5", "sha256", "sha1"]),
    )

    # Extract raw indicators
    indicators = _extract_indicators(all_fields)

    # Rule info
    rule_id = _find_field(all_fields, ["rule_id", "signature_id", "sid"])
    rule_name = _find_field(all_fields, ["rule_name", "signature", "search_name"])

    return NormalizedAlert(
        id=alert_id,
        timestamp=timestamp,
        source_format="splunk",
        title=title,
        description=description,
        severity=severity,
        category=category,
        network=network,
        endpoint=endpoint,
        user=user,
        process=process,
        rule_id=rule_id,
        rule_name=rule_name,
        raw_indicators=indicators,
        raw_data=data,
    )


def _find_field(data: dict, field_names: list[str]) -> str | None:
    """Search for a field value across multiple possible field names."""
    for name in field_names:
        val = data.get(name)
        if val is not None and str(val).strip():
            return str(val).strip()
    return None


def _safe_int(value: str | None) -> int | None:
    """Safely convert to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _detect_category(title: str, description: str) -> AlertCategory:
    """Detect alert category from title and description text."""
    text = f"{title} {description}".lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return AlertCategory.UNKNOWN


def _extract_indicators(data: dict) -> list[str]:
    """Extract potential IOCs from all string fields."""
    indicators = set()
    ip_fields = ["src_ip", "dest_ip", "source_ip", "destination_ip", "host_ip",
                 "src", "dst", "srcip", "dstip", "endpoint_ip"]
    hash_fields = ["file_hash", "hash", "md5", "sha256", "sha1"]
    domain_fields = ["domain", "url", "dest_domain", "dns_query"]

    for field in ip_fields + hash_fields + domain_fields:
        val = data.get(field)
        if val and isinstance(val, str) and val.strip():
            indicators.add(val.strip())

    return list(indicators)
