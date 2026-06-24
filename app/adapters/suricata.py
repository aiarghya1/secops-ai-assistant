"""
SecOps AI Assistant — Suricata EVE JSON Adapter

Converts Suricata EVE (Extensible Event Format) JSON into the normalized NormalizedAlert schema.
Handles the standardized EVE alert format with nested alert object.
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

# Suricata severity is 1 (highest) to 4 (lowest)
_SURICATA_SEVERITY_MAP = {
    1: AlertSeverity.CRITICAL,
    2: AlertSeverity.HIGH,
    3: AlertSeverity.MEDIUM,
    4: AlertSeverity.LOW,
}

# Suricata category keywords
_SURICATA_CATEGORY_MAP = {
    "a network trojan was detected": AlertCategory.MALWARE,
    "malware": AlertCategory.MALWARE,
    "potentially bad traffic": AlertCategory.SUSPICIOUS_ACTIVITY,
    "attempted information leak": AlertCategory.DATA_EXFILTRATION,
    "attempted denial of service": AlertCategory.NETWORK_INTRUSION,
    "web application attack": AlertCategory.NETWORK_INTRUSION,
    "attempted admin": AlertCategory.PRIVILEGE_ESCALATION,
    "attempted user": AlertCategory.BRUTE_FORCE,
    "misc attack": AlertCategory.SUSPICIOUS_ACTIVITY,
    "suspicious user-agent": AlertCategory.C2_COMMUNICATION,
    "trojan activity": AlertCategory.MALWARE,
    "exploit kit": AlertCategory.NETWORK_INTRUSION,
    "command and control": AlertCategory.C2_COMMUNICATION,
    "c2": AlertCategory.C2_COMMUNICATION,
    "exfiltration": AlertCategory.DATA_EXFILTRATION,
    "phishing": AlertCategory.PHISHING,
    "policy violation": AlertCategory.POLICY_VIOLATION,
}


def is_suricata_format(data: dict[str, Any]) -> bool:
    """Detect if the data looks like a Suricata EVE alert."""
    # Standard EVE format
    if data.get("event_type") == "alert" and "alert" in data:
        return True

    # Check for Suricata-specific fields
    suricata_fields = ["event_type", "flow_id", "alert", "src_ip", "dest_ip"]
    matches = sum(1 for f in suricata_fields if f in data)
    if matches >= 3:
        return True

    # Check nested alert structure
    alert_obj = data.get("alert", {})
    if isinstance(alert_obj, dict):
        alert_fields = ["signature_id", "signature", "category", "severity"]
        matches = sum(1 for f in alert_fields if f in alert_obj)
        if matches >= 2:
            return True

    return False


def adapt_suricata_alert(data: dict[str, Any]) -> NormalizedAlert:
    """Convert a Suricata EVE alert into NormalizedAlert."""
    alert_obj = data.get("alert", {})
    if not isinstance(alert_obj, dict):
        alert_obj = {}

    flow = data.get("flow", {})
    if not isinstance(flow, dict):
        flow = {}

    http = data.get("http", {})
    if not isinstance(http, dict):
        http = {}

    dns = data.get("dns", {})
    if not isinstance(dns, dict):
        dns = {}

    tls = data.get("tls", {})
    if not isinstance(tls, dict):
        tls = {}

    # Alert ID
    alert_id = (
        str(alert_obj.get("signature_id", ""))
        + "-"
        + str(data.get("flow_id", uuid.uuid4().hex[:8]))
    )
    if alert_id.startswith("-"):
        alert_id = f"suricata-{uuid.uuid4().hex[:12]}"

    # Timestamp
    timestamp = data.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Title
    title = (
        alert_obj.get("signature")
        or alert_obj.get("rule")
        or "Suricata Alert"
    )

    # Description
    description = alert_obj.get("category", "")
    if http.get("url"):
        description += f" | URL: {http['url']}"
    if http.get("hostname"):
        description += f" | Host: {http['hostname']}"

    # Severity (Suricata uses 1=highest, 4=lowest)
    severity_num = alert_obj.get("severity")
    if isinstance(severity_num, int):
        severity = _SURICATA_SEVERITY_MAP.get(severity_num, AlertSeverity.UNKNOWN)
    else:
        severity = AlertSeverity.UNKNOWN

    # Category from Suricata's own categorization
    suricata_category = str(alert_obj.get("category", "")).lower()
    category = AlertCategory.UNKNOWN
    for key, cat in _SURICATA_CATEGORY_MAP.items():
        if key in suricata_category or key in title.lower():
            category = cat
            break

    # Network info (Suricata always has this)
    network = NetworkInfo(
        src_ip=data.get("src_ip"),
        src_port=_safe_int(data.get("src_port")),
        dest_ip=data.get("dest_ip"),
        dest_port=_safe_int(data.get("dest_port")),
        protocol=data.get("proto"),
        bytes_sent=_safe_int(flow.get("bytes_toserver")),
        bytes_received=_safe_int(flow.get("bytes_toclient")),
    )

    # Determine direction
    src_ip = data.get("src_ip", "")
    if src_ip.startswith(("10.", "172.16.", "192.168.")):
        network.direction = "outbound"
    else:
        network.direction = "inbound"

    # Endpoint (derive from IPs)
    endpoint = EndpointInfo()
    if network.direction == "outbound" and src_ip:
        endpoint.ip_address = src_ip
    elif network.dest_ip and network.dest_ip.startswith(("10.", "172.16.", "192.168.")):
        endpoint.ip_address = network.dest_ip

    # User info (rarely in Suricata, but check)
    user = UserInfo()

    # Extract indicators
    indicators = _extract_suricata_indicators(data, alert_obj, http, dns, tls)

    # Rule info
    rule_id = str(alert_obj.get("signature_id", "")) or None
    rule_name = alert_obj.get("signature")

    # MITRE from metadata if available
    mitre_tactics = []
    mitre_techniques = []
    alert_metadata = alert_obj.get("metadata", {})
    if isinstance(alert_metadata, dict):
        if "mitre_tactic_id" in alert_metadata:
            mitre_tactics = alert_metadata["mitre_tactic_id"] if isinstance(
                alert_metadata["mitre_tactic_id"], list
            ) else [alert_metadata["mitre_tactic_id"]]
        if "mitre_technique_id" in alert_metadata:
            mitre_techniques = alert_metadata["mitre_technique_id"] if isinstance(
                alert_metadata["mitre_technique_id"], list
            ) else [alert_metadata["mitre_technique_id"]]

    return NormalizedAlert(
        id=alert_id,
        timestamp=timestamp,
        source_format="suricata",
        title=title,
        description=description if description else None,
        severity=severity,
        category=category,
        network=network,
        endpoint=endpoint,
        user=user,
        rule_id=rule_id,
        rule_name=rule_name,
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


def _extract_suricata_indicators(
    data: dict, alert_obj: dict, http: dict, dns: dict, tls: dict
) -> list[str]:
    """Extract IOCs from Suricata EVE data."""
    indicators = set()

    # IPs
    for field in ["src_ip", "dest_ip"]:
        val = data.get(field)
        if val:
            indicators.add(str(val))

    # HTTP indicators
    if http.get("hostname"):
        indicators.add(http["hostname"])
    if http.get("url"):
        indicators.add(http["url"])
    if http.get("http_user_agent"):
        indicators.add(http["http_user_agent"])

    # DNS indicators
    if dns.get("rrname"):
        indicators.add(dns["rrname"])
    dns_answers = dns.get("answers", [])
    if isinstance(dns_answers, list):
        for answer in dns_answers:
            if isinstance(answer, dict) and answer.get("rdata"):
                indicators.add(str(answer["rdata"]))

    # TLS indicators
    if tls.get("sni"):
        indicators.add(tls["sni"])
    if tls.get("fingerprint"):
        indicators.add(tls["fingerprint"])
    if tls.get("ja3", {}).get("hash"):
        indicators.add(tls["ja3"]["hash"])

    # File hashes if present
    fileinfo = data.get("fileinfo", {})
    if isinstance(fileinfo, dict):
        for hash_type in ["md5", "sha1", "sha256"]:
            if fileinfo.get(hash_type):
                indicators.add(fileinfo[hash_type])

    return list(indicators)
