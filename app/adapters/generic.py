"""
SecOps AI Assistant — Generic Alert Adapter

Best-effort adapter for unknown/generic JSON alert formats.
Uses heuristic field matching to extract common security alert fields
from unrecognized JSON structures.
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

# Field name synonyms for heuristic matching
_IP_FIELD_NAMES = [
    "src_ip", "source_ip", "srcip", "src_addr", "source_address",
    "srcAddr", "sourceIP", "sourceIp", "client_ip", "attacker_ip",
    "remote_ip", "ip_address", "ip", "ipAddress",
]

_DEST_IP_FIELD_NAMES = [
    "dest_ip", "destination_ip", "dstip", "dst_addr", "destination_address",
    "dstAddr", "destIP", "destinationIp", "target_ip", "server_ip",
]

_PORT_SRC_NAMES = ["src_port", "source_port", "srcport", "srcPort"]
_PORT_DST_NAMES = ["dest_port", "destination_port", "dstport", "dstPort", "port"]

_USER_FIELD_NAMES = [
    "user", "username", "user_name", "userName", "account_name",
    "accountName", "actor", "subject", "principal", "src_user",
    "source_user", "login_name",
]

_HOST_FIELD_NAMES = [
    "host", "hostname", "host_name", "hostName", "computer_name",
    "computerName", "endpoint", "endpoint_name", "machine", "device",
    "device_name", "asset_name", "server", "workstation",
]

_TITLE_FIELD_NAMES = [
    "title", "name", "alert_name", "alertName", "rule_name", "ruleName",
    "detection_name", "event_name", "eventName", "summary", "subject",
    "message", "alert_title",
]

_DESC_FIELD_NAMES = [
    "description", "details", "detail", "message", "msg", "reason",
    "explanation", "body", "content", "narrative", "notes",
]

_SEVERITY_FIELD_NAMES = [
    "severity", "priority", "urgency", "risk", "risk_level", "riskLevel",
    "threat_level", "threatLevel", "criticality", "importance", "level",
    "alert_severity", "sev",
]

_TIMESTAMP_FIELD_NAMES = [
    "timestamp", "time", "created_at", "createdAt", "event_time",
    "eventTime", "date", "datetime", "occurred_at", "detected_at",
    "alert_time", "start_time", "ts", "@timestamp",
]

_HASH_FIELD_NAMES = [
    "hash", "file_hash", "md5", "sha1", "sha256", "sha512",
    "fileHash", "checksum",
]

_SEVERITY_WORD_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "crit": AlertSeverity.CRITICAL,
    "emergency": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "major": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "moderate": AlertSeverity.MEDIUM,
    "warning": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "minor": AlertSeverity.LOW,
    "informational": AlertSeverity.INFORMATIONAL,
    "info": AlertSeverity.INFORMATIONAL,
    "notice": AlertSeverity.INFORMATIONAL,
}

_CATEGORY_KEYWORDS = {
    AlertCategory.BRUTE_FORCE: ["brute", "force", "login", "failed auth", "password", "credential"],
    AlertCategory.MALWARE: ["malware", "virus", "trojan", "ransomware", "worm", "backdoor"],
    AlertCategory.PHISHING: ["phishing", "spear", "social engineering", "suspicious email"],
    AlertCategory.DATA_EXFILTRATION: ["exfil", "data loss", "dlp", "data transfer", "data leak"],
    AlertCategory.C2_COMMUNICATION: ["c2", "command and control", "beacon", "callback", "c&c"],
    AlertCategory.PRIVILEGE_ESCALATION: ["privilege", "escalation", "elevation", "sudo", "admin"],
    AlertCategory.NETWORK_INTRUSION: ["intrusion", "exploit", "vulnerability", "cve", "injection"],
    AlertCategory.INSIDER_THREAT: ["insider", "unauthorized access", "policy violation", "suspicious user"],
    AlertCategory.RECONNAISSANCE: ["scan", "recon", "enumeration", "probe", "discovery"],
}


def adapt_generic_alert(data: dict[str, Any]) -> NormalizedAlert:
    """
    Best-effort conversion of any JSON alert into NormalizedAlert.
    Uses heuristic field name matching across common naming conventions.
    """
    # Flatten nested structures for searching
    flat = _flatten_dict(data)

    # Alert ID
    alert_id = str(
        _search_field(flat, ["id", "alert_id", "alertId", "event_id", "eventId", "uuid", "incident_id"])
        or f"generic-{uuid.uuid4().hex[:12]}"
    )

    # Timestamp
    timestamp = _search_field(flat, _TIMESTAMP_FIELD_NAMES) or datetime.now(timezone.utc).isoformat()

    # Title
    title = _search_field(flat, _TITLE_FIELD_NAMES) or "Security Alert"

    # Description
    description = _search_field(flat, _DESC_FIELD_NAMES)

    # Severity
    severity_raw = str(_search_field(flat, _SEVERITY_FIELD_NAMES) or "").lower().strip()
    severity = _SEVERITY_WORD_MAP.get(severity_raw, AlertSeverity.UNKNOWN)
    if severity == AlertSeverity.UNKNOWN and severity_raw:
        # Try numeric
        try:
            num = int(severity_raw)
            if num >= 9:
                severity = AlertSeverity.CRITICAL
            elif num >= 7:
                severity = AlertSeverity.HIGH
            elif num >= 4:
                severity = AlertSeverity.MEDIUM
            elif num >= 1:
                severity = AlertSeverity.LOW
        except ValueError:
            pass

    # Category
    category = _detect_category(title, description or "")

    # Network
    network = NetworkInfo(
        src_ip=_search_field(flat, _IP_FIELD_NAMES),
        src_port=_safe_int(_search_field(flat, _PORT_SRC_NAMES)),
        dest_ip=_search_field(flat, _DEST_IP_FIELD_NAMES),
        dest_port=_safe_int(_search_field(flat, _PORT_DST_NAMES)),
        protocol=_search_field(flat, ["protocol", "proto", "transport", "ip_protocol"]),
    )

    # Endpoint
    endpoint = EndpointInfo(
        hostname=_search_field(flat, _HOST_FIELD_NAMES),
        ip_address=_search_field(flat, ["endpoint_ip", "host_ip", "local_ip"]),
        os=_search_field(flat, ["os", "operating_system", "platform", "os_name"]),
    )

    # User
    user = UserInfo(
        username=_search_field(flat, _USER_FIELD_NAMES),
        email=_search_field(flat, ["email", "user_email", "mail", "emailAddress"]),
        domain=_search_field(flat, ["domain", "user_domain", "ad_domain"]),
        department=_search_field(flat, ["department", "dept", "business_unit"]),
        role=_search_field(flat, ["role", "user_role", "job_title"]),
    )

    # Process
    process = ProcessInfo(
        name=_search_field(flat, ["process", "process_name", "proc", "processName"]),
        command_line=_search_field(flat, ["command_line", "cmdline", "cmd", "commandLine"]),
        file_path=_search_field(flat, ["file_path", "filepath", "path", "filePath"]),
        file_hash=_search_field(flat, _HASH_FIELD_NAMES),
    )

    # Extract indicators from all values
    indicators = _extract_indicators_generic(flat)

    return NormalizedAlert(
        id=alert_id,
        timestamp=timestamp,
        source_format="generic",
        title=title,
        description=description,
        severity=severity,
        category=category,
        network=network,
        endpoint=endpoint,
        user=user,
        process=process,
        raw_indicators=indicators,
        raw_data=data,
    )


def _flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten a nested dictionary, keeping both leaf values and the original keys."""
    items: dict[str, Any] = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        # Store with original key name (last part) for matching
        if isinstance(v, dict):
            items.update(_flatten_dict(v, new_key, sep))
        elif isinstance(v, list):
            items[k] = str(v)  # Store list as string for searching
            items[new_key] = str(v)
        else:
            items[k] = v
            if new_key != k:
                items[new_key] = v
    return items


def _search_field(flat: dict, field_names: list[str]) -> str | None:
    """Search flattened dict for any matching field name."""
    for name in field_names:
        # Exact match
        if name in flat and flat[name] is not None:
            val = str(flat[name]).strip()
            if val:
                return val
        # Case-insensitive search
        for key, val in flat.items():
            if key.lower() == name.lower() and val is not None:
                return str(val).strip() if str(val).strip() else None
    return None


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _detect_category(title: str, description: str) -> AlertCategory:
    text = f"{title} {description}".lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return AlertCategory.UNKNOWN


def _extract_indicators_generic(flat: dict) -> list[str]:
    """Extract potential IOCs from all string values in flattened dict."""
    indicators = set()
    ip_like_fields = set(_IP_FIELD_NAMES + _DEST_IP_FIELD_NAMES +
                          ["src_ip", "dest_ip", "ip", "remote_ip", "local_ip"])
    hash_like_fields = set(_HASH_FIELD_NAMES)

    for key, val in flat.items():
        if val is None or not isinstance(val, str):
            continue
        val = val.strip()
        if not val:
            continue

        key_lower = key.lower().split(".")[-1]  # Get leaf key name

        if key_lower in ip_like_fields or "ip" in key_lower:
            # Validate as IP
            parts = val.split(".")
            if len(parts) == 4 and all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                indicators.add(val)

        if key_lower in hash_like_fields or "hash" in key_lower:
            if len(val) in (32, 40, 64) and all(
                c in "0123456789abcdefABCDEF" for c in val
            ):
                indicators.add(val)

        if "domain" in key_lower or "host" in key_lower:
            if "." in val and not val.startswith("http") and not all(
                p.isdigit() for p in val.split(".")
            ):
                indicators.add(val)

    return list(indicators)
