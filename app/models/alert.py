"""
SecOps AI Assistant — Alert Models

Normalized alert schema (OCSF-lite) that all adapters convert into.
Provides a consistent internal representation regardless of source SIEM format.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class AlertCategory(str, Enum):
    MALWARE = "malware"
    NETWORK_INTRUSION = "network_intrusion"
    BRUTE_FORCE = "brute_force"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    C2_COMMUNICATION = "c2_communication"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


class NetworkInfo(BaseModel):
    """Network-related fields from the alert."""
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None  # inbound, outbound, lateral
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None


class EndpointInfo(BaseModel):
    """Endpoint/host information from the alert."""
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    mac_address: Optional[str] = None
    agent_version: Optional[str] = None


class UserInfo(BaseModel):
    """User account information from the alert."""
    username: Optional[str] = None
    domain: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None


class ProcessInfo(BaseModel):
    """Process execution details if available."""
    name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    parent_name: Optional[str] = None
    parent_pid: Optional[int] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None


class NormalizedAlert(BaseModel):
    """
    Internal normalized alert schema (OCSF-lite).

    All SIEM-specific adapters convert their raw format into this schema,
    ensuring consistent processing through the enrichment and analysis pipeline.
    """
    id: str = Field(description="Unique alert identifier")
    timestamp: str = Field(description="Alert timestamp in ISO 8601 format")
    source_format: str = Field(description="Original format: splunk, crowdstrike, suricata, generic")

    # Core fields
    title: str = Field(description="Human-readable alert title/name")
    description: Optional[str] = Field(default=None, description="Alert description/details")
    severity: AlertSeverity = Field(default=AlertSeverity.UNKNOWN, description="Alert severity level")
    category: AlertCategory = Field(default=AlertCategory.UNKNOWN, description="Alert category")

    # Structured sub-objects
    network: Optional[NetworkInfo] = None
    endpoint: Optional[EndpointInfo] = None
    user: Optional[UserInfo] = None
    process: Optional[ProcessInfo] = None

    # Detection metadata
    rule_id: Optional[str] = Field(default=None, description="Detection rule/signature ID")
    rule_name: Optional[str] = Field(default=None, description="Detection rule/signature name")
    mitre_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")

    # Raw data
    raw_indicators: list[str] = Field(
        default_factory=list,
        description="Extracted IOCs: IPs, domains, hashes, URLs"
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Original raw alert data for reference"
    )

    def get_all_ips(self) -> list[str]:
        """Extract all IP addresses from the alert."""
        ips = set()
        if self.network:
            if self.network.src_ip:
                ips.add(self.network.src_ip)
            if self.network.dest_ip:
                ips.add(self.network.dest_ip)
        if self.endpoint and self.endpoint.ip_address:
            ips.add(self.endpoint.ip_address)
        # Also check raw indicators
        for indicator in self.raw_indicators:
            # Simple IP pattern check
            parts = indicator.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ips.add(indicator)
        return list(ips)

    def get_all_domains(self) -> list[str]:
        """Extract domain-like indicators."""
        domains = []
        for indicator in self.raw_indicators:
            if "." in indicator and not all(
                p.isdigit() for p in indicator.split(".")
            ):
                # Likely a domain, not an IP
                if not indicator.startswith("http"):
                    domains.append(indicator)
        return domains

    def get_all_hashes(self) -> list[str]:
        """Extract file hash indicators."""
        hashes = []
        for indicator in self.raw_indicators:
            # MD5 (32), SHA1 (40), SHA256 (64) hex strings
            if len(indicator) in (32, 40, 64) and all(
                c in "0123456789abcdefABCDEF" for c in indicator
            ):
                hashes.append(indicator)
        if self.process and self.process.file_hash:
            hashes.append(self.process.file_hash)
        return list(set(hashes))

    def summary_line(self) -> str:
        """One-line summary for the alert."""
        parts = [f"[{self.severity.value.upper()}]", self.title]
        if self.network and self.network.src_ip:
            parts.append(f"from {self.network.src_ip}")
        if self.endpoint and self.endpoint.hostname:
            parts.append(f"on {self.endpoint.hostname}")
        if self.user and self.user.username:
            parts.append(f"user={self.user.username}")
        return " ".join(parts)
