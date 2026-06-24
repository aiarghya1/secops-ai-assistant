"""
SecOps AI Assistant — Investigation Models

Structured output models for AI analysis results, enrichment data,
and the final investigation report.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Enrichment Data Models ---

class IPReputationData(BaseModel):
    """IP reputation lookup results."""
    ip: str
    is_malicious: bool = False
    malicious_score: float = Field(default=0.0, ge=0.0, le=100.0, description="0-100 risk score")
    detection_engines: int = 0
    total_engines: int = 0
    abuse_reports: int = 0
    last_seen: Optional[str] = None
    categories: list[str] = Field(default_factory=list)
    country: Optional[str] = None
    isp: Optional[str] = None
    source: str = "mock"


class DomainIntelData(BaseModel):
    """Domain intelligence results."""
    domain: str
    is_malicious: bool = False
    reputation_score: float = Field(default=0.0, ge=0.0, le=100.0)
    registration_date: Optional[str] = None
    registrar: Optional[str] = None
    category: Optional[str] = None
    whois_info: dict[str, Any] = Field(default_factory=dict)
    source: str = "mock"


class GeoIPData(BaseModel):
    """GeoIP lookup results."""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    source: str = "mock"


class HistoricalMatch(BaseModel):
    """A historical alert that matches current indicators."""
    alert_id: str
    timestamp: str
    title: str
    severity: str
    matching_indicator: str


class AssetContextData(BaseModel):
    """Asset/CMDB context for involved hosts."""
    identifier: str  # IP or hostname
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None  # server, workstation, network_device, cloud_instance
    criticality: Optional[str] = None  # critical, high, medium, low
    owner: Optional[str] = None
    department: Optional[str] = None
    os: Optional[str] = None
    environment: Optional[str] = None  # production, staging, development
    last_patched: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    source: str = "mock"


class EnrichmentData(BaseModel):
    """Aggregated enrichment results from all providers."""
    ip_reputation: list[IPReputationData] = Field(default_factory=list)
    domain_intel: list[DomainIntelData] = Field(default_factory=list)
    geo_ip: list[GeoIPData] = Field(default_factory=list)
    historical_matches: list[HistoricalMatch] = Field(default_factory=list)
    asset_context: list[AssetContextData] = Field(default_factory=list)
    enrichment_errors: list[str] = Field(
        default_factory=list,
        description="Errors from failed enrichment providers"
    )
    enrichment_time_ms: float = 0.0


# --- AI Analysis Models ---

class EvidenceItem(BaseModel):
    """A piece of evidence supporting the analysis."""
    description: str
    source: str  # e.g., "ip_reputation", "historical_data", "alert_content"
    confidence: str = "medium"  # high, medium, low
    data: Optional[dict[str, Any]] = None


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping for the alert."""
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    description: Optional[str] = None


class RecommendedAction(BaseModel):
    """A recommended response action for the analyst."""
    action: str
    priority: str  # immediate, short_term, long_term
    description: str
    automated: bool = False  # Can this be automated?


class TimelineEvent(BaseModel):
    """An event in the reconstructed timeline."""
    timestamp: str
    event: str
    source: str
    significance: str = "normal"  # critical, important, normal


class InvestigationResult(BaseModel):
    """
    Complete AI analysis result for a security alert.

    This is the primary output structure that analysts interact with.
    """
    alert_id: str
    investigation_id: str

    # Core Assessment
    severity: str = Field(description="Assessed severity: critical, high, medium, low, informational")
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Confidence in the assessment (0.0 - 1.0)"
    )
    verdict: str = Field(description="true_positive, false_positive, suspicious, benign, inconclusive")
    classification: str = Field(description="Brief classification of the alert type")

    # Analysis
    executive_summary: str = Field(description="2-3 sentence summary for the analyst")
    root_cause_analysis: str = Field(description="Detailed root cause analysis")
    attack_narrative: Optional[str] = Field(
        default=None,
        description="Narrative reconstruction of the attack chain"
    )

    # Supporting Evidence
    evidence: list[EvidenceItem] = Field(default_factory=list)
    mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Actions
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    iocs_extracted: list[str] = Field(
        default_factory=list,
        description="Indicators of Compromise extracted"
    )

    # Metadata
    analysis_reasoning: Optional[str] = Field(
        default=None,
        description="Chain-of-thought reasoning trace (for audit/explainability)"
    )
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    analysis_latency_ms: float = 0.0
    token_count: int = 0
    estimated_cost: float = 0.0

    # Enrichment summary
    enrichment_summary: Optional[str] = Field(
        default=None,
        description="Summary of enrichment findings"
    )


class AnalysisRequest(BaseModel):
    """Request to analyze an alert."""
    alert_data: dict[str, Any] = Field(description="Raw alert JSON data")
    source_format: Optional[str] = Field(
        default=None,
        description="Optional hint: 'splunk', 'crowdstrike', 'suricata', or auto-detect"
    )
    force_reanalyze: bool = Field(
        default=False,
        description="Force re-analysis even if cached result exists"
    )


class AnalysisResponse(BaseModel):
    """Response wrapping the investigation result."""
    success: bool
    alert_id: str
    source_format: str
    investigation: Optional[InvestigationResult] = None
    error: Optional[str] = None
    demo_mode: bool = False
