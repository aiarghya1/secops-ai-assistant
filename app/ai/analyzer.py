"""
SecOps AI Assistant — Alert Analyzer

Main analysis orchestrator that coordinates enrichment, LLM analysis,
and post-processing of results. Includes hallucination guards and
confidence calibration.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

from app.ai.llm_client import LLMClient
from app.ai.prompts import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
    format_alert_for_llm,
    format_enrichment_for_llm,
)
from app.config import get_settings
from app.enrichment.orchestrator import EnrichmentOrchestrator
from app.models.alert import NormalizedAlert
from app.models.investigation import (
    EnrichmentData,
    EvidenceItem,
    InvestigationResult,
    MitreMapping,
    RecommendedAction,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


# Pre-computed demo results for when no API keys are configured
_DEMO_RESULTS = {
    "brute_force": InvestigationResult(
        alert_id="demo",
        investigation_id="demo-inv-001",
        severity="high",
        confidence=0.88,
        verdict="true_positive",
        classification="Brute Force Login Attack",
        executive_summary="A sustained brute force attack was detected targeting the admin_user account from IP 185.220.101.34, a known Tor exit node with 47/70 detection engine flags. The source IP has 2 previous alerts in our system, establishing a pattern of credential-based attacks.",
        root_cause_analysis="The attacker is using a Tor exit node (185.220.101.34, Nuremberg, Germany) to mask their origin while conducting credential-stuffing attacks against the admin_user account. The IP has a malicious reputation score of 92/100 with 1,243 abuse reports. This is a classic brute-force pattern where automated tooling cycles through credential lists against exposed authentication endpoints. The target is a finance department workstation (WS-FINANCE-042) with PCI-scope classification, making this a high-severity event.",
        attack_narrative="1. Attacker establishes connection via Tor network to anonymize their source.\n2. Automated tooling initiates rapid authentication attempts against the admin_user account.\n3. 8 failed login events detected within the alerting window.\n4. The attack targets a PCI-scope workstation in the Finance department.\n5. If successful, the attacker could gain access to sensitive financial data.",
        evidence=[
            EvidenceItem(description="Source IP 185.220.101.34 is a known Tor exit node with malicious score 92/100", source="ip_reputation", confidence="high", data={"score": 92.0, "engines": "47/70"}),
            EvidenceItem(description="IP has 1,243 abuse reports on AbuseIPDB", source="ip_reputation", confidence="high", data={"abuse_reports": 1243}),
            EvidenceItem(description="2 previous high-severity alerts from this IP in past 7 days", source="historical_data", confidence="high"),
            EvidenceItem(description="Target host WS-FINANCE-042 is PCI-scope, Finance department", source="asset_context", confidence="high", data={"criticality": "high", "tags": ["pci-scope"]}),
            EvidenceItem(description="8 failed login attempts indicate automated credential stuffing", source="alert_content", confidence="medium"),
        ],
        mitre_mapping=[
            MitreMapping(tactic="Credential Access", tactic_id="TA0006", technique="Brute Force", technique_id="T1110", description="Multiple failed login attempts from single source"),
            MitreMapping(tactic="Initial Access", tactic_id="TA0001", technique="Valid Accounts", technique_id="T1078", description="Targeting admin account for initial foothold"),
        ],
        timeline=[
            TimelineEvent(timestamp="T-7d", event="First alert from 185.220.101.34 (Tor brute force)", source="historical", significance="important"),
            TimelineEvent(timestamp="T-4d", event="Second alert from same IP (SSH failed logins)", source="historical", significance="important"),
            TimelineEvent(timestamp="T-0", event="Current alert: 8 failed logins targeting admin_user on WS-FINANCE-042", source="alert", significance="critical"),
        ],
        recommended_actions=[
            RecommendedAction(action="Block IP", priority="immediate", description="Block 185.220.101.34 at the perimeter firewall. Consider blocking the /24 subnet.", automated=True),
            RecommendedAction(action="Lock Account", priority="immediate", description="Temporarily lock the admin_user account and force password reset. Verify no successful logins occurred.", automated=True),
            RecommendedAction(action="Review Auth Logs", priority="short_term", description="Review authentication logs for admin_user across all systems for the past 7 days to check for any successful logins from this or other suspicious IPs.", automated=False),
            RecommendedAction(action="Implement MFA", priority="long_term", description="Ensure MFA is enforced on all admin accounts, especially those with access to PCI-scope systems.", automated=False),
            RecommendedAction(action="Tor Exit Block", priority="short_term", description="Consider implementing a Tor exit node blocklist at the firewall level to prevent future anonymous attacks.", automated=True),
        ],
        iocs_extracted=["185.220.101.34"],
        analysis_reasoning="Step 1: The alert indicates 8 failed logins from a single IP. Step 2: Enrichment shows this IP is a known Tor exit node with extremely high malicious score (92/100). Step 3: Historical data shows 2 previous incidents from this IP. Step 4: The target is a PCI-scope financial workstation, elevating severity. Step 5: This is consistent with automated credential stuffing via anonymized infrastructure. Verdict: TRUE POSITIVE with high confidence.",
        enrichment_summary="IP 185.220.101.34: Tor exit node, malicious score 92/100, 47/70 engines, Germany. Target asset: WS-FINANCE-042, PCI-scope, Finance dept. 2 prior alerts from same IP.",
    ),
    "malware": InvestigationResult(
        alert_id="demo",
        investigation_id="demo-inv-002",
        severity="critical",
        confidence=0.92,
        verdict="true_positive",
        classification="Malware Execution — Potential Ransomware Precursor",
        executive_summary="CrowdStrike detected execution of a suspicious process on WIN-SERVER-01 (Domain Controller, Tier-0 asset) by service account svc_admin. The process has characteristics consistent with ransomware precursor activity. This is a CRITICAL event given the asset is a domain controller.",
        root_cause_analysis="A potentially malicious process was executed on WIN-SERVER-01, which is a critical Tier-0 domain controller. The process was spawned by the svc_admin service account, which has previous alerts for unusual activity. The combination of a service account executing suspicious processes on a domain controller strongly suggests either a compromised service account or an insider threat. The endpoint's criticality as a domain controller means any compromise could affect the entire Active Directory environment.",
        attack_narrative="1. The svc_admin service account was used to execute a suspicious process on the domain controller.\n2. This service account had a prior alert for use from an unusual location.\n3. The process execution pattern is consistent with ransomware precursor tools (reconnaissance/staging phase).\n4. If the DC is compromised, the attacker could gain full domain control.\n5. This represents a potential 'golden ticket' attack scenario.",
        evidence=[
            EvidenceItem(description="Process executed on Tier-0 domain controller WIN-SERVER-01", source="asset_context", confidence="high", data={"criticality": "critical", "tags": ["domain-controller", "tier-0"]}),
            EvidenceItem(description="svc_admin has 1 previous high-severity alert for unusual location usage", source="historical_data", confidence="high"),
            EvidenceItem(description="CrowdStrike detection engine flagged as MEDIUM+ severity", source="alert_content", confidence="high"),
        ],
        mitre_mapping=[
            MitreMapping(tactic="Execution", tactic_id="TA0002", technique="Command and Scripting Interpreter", technique_id="T1059", description="Suspicious process execution via service account"),
            MitreMapping(tactic="Privilege Escalation", tactic_id="TA0004", technique="Valid Accounts: Domain Accounts", technique_id="T1078.002", description="Service account used for lateral movement"),
            MitreMapping(tactic="Defense Evasion", tactic_id="TA0005", technique="Masquerading", technique_id="T1036", description="Potential process name disguising"),
        ],
        timeline=[
            TimelineEvent(timestamp="T-2d", event="svc_admin used from unusual location (prior alert)", source="historical", significance="important"),
            TimelineEvent(timestamp="T-0", event="Suspicious process execution on DC by svc_admin", source="crowdstrike", significance="critical"),
        ],
        recommended_actions=[
            RecommendedAction(action="Isolate Endpoint", priority="immediate", description="Network-isolate WIN-SERVER-01 if possible (coordinate with AD team first — this is a DC). Use CrowdStrike network containment as alternative.", automated=True),
            RecommendedAction(action="Disable Service Account", priority="immediate", description="Disable svc_admin immediately and rotate all associated credentials. Audit all systems using this account.", automated=True),
            RecommendedAction(action="Forensic Triage", priority="immediate", description="Collect memory dump and disk image from WIN-SERVER-01 before any remediation. Preserve evidence chain.", automated=False),
            RecommendedAction(action="AD Assessment", priority="short_term", description="Run an AD security assessment to check for golden ticket indicators, rogue accounts, and GPO changes.", automated=False),
            RecommendedAction(action="Incident Response", priority="immediate", description="Escalate to IR team. This may be an active compromise of a Tier-0 asset requiring full incident response.", automated=False),
        ],
        iocs_extracted=["10.0.0.5", "svc_admin"],
        analysis_reasoning="Step 1: Alert is on a domain controller (Tier-0, most critical asset class). Step 2: Executed by a service account with prior suspicious activity. Step 3: CrowdStrike detection indicates malicious process execution. Step 4: Domain controller compromise = entire domain compromise risk. Step 5: Verdict is TRUE POSITIVE with CRITICAL severity due to asset criticality.",
        enrichment_summary="Endpoint: WIN-SERVER-01, Tier-0 domain controller, production. User: svc_admin, 1 prior high-severity alert. Asset criticality: CRITICAL.",
    ),
    "c2_beacon": InvestigationResult(
        alert_id="demo",
        investigation_id="demo-inv-003",
        severity="critical",
        confidence=0.90,
        verdict="true_positive",
        classification="Command & Control Beacon Activity",
        executive_summary="Suricata detected outbound C2 beacon communication from internal host 192.168.1.50 to known malicious IP 198.51.100.23 (Russia, bulletproof hosting). The destination has 3 prior critical/high alerts and a malicious score of 95/100. This indicates an active compromise with established C2 channel.",
        root_cause_analysis="An internal workstation (192.168.1.50, WS-DEV-017, Engineering department) is communicating with a known C2 server at 198.51.100.23. The Suricata IDS detected a suspicious User-Agent string characteristic of malware beaconing. The destination IP is hosted on Russian bulletproof hosting infrastructure with a 95/100 malicious score and 2,891 abuse reports. Three previous alerts from this IP confirm it's an established C2 endpoint. The developer workstation likely became compromised via a phishing email, supply chain attack, or drive-by download.",
        attack_narrative="1. Initial compromise of developer workstation (likely via phishing or malicious download).\n2. Malware establishes persistence on WS-DEV-017.\n3. Outbound beacon to C2 server 198.51.100.23 on port 80 (using HTTP to blend with normal traffic).\n4. C2 server responds with commands (data staging, reconnaissance, etc.).\n5. Developer workstation has code access, creating data exfiltration risk.\n6. Attacker could use developer credentials for supply chain attack.",
        evidence=[
            EvidenceItem(description="Destination IP 198.51.100.23 has malicious score 95/100 with 2,891 abuse reports", source="ip_reputation", confidence="high", data={"score": 95.0, "categories": ["c2", "malware-distribution"]}),
            EvidenceItem(description="3 previous critical/high alerts involving 198.51.100.23", source="historical_data", confidence="high"),
            EvidenceItem(description="Destination hosted on Russian bulletproof hosting (PIN Data Center)", source="geo_ip", confidence="high"),
            EvidenceItem(description="VPN-flagged IP indicating effort to hide true infrastructure", source="geo_ip", confidence="medium"),
            EvidenceItem(description="Suricata signature for suspicious User-Agent (C2 indicator)", source="alert_content", confidence="high"),
            EvidenceItem(description="Source is developer workstation with code access", source="asset_context", confidence="high", data={"tags": ["developer", "code-access"]}),
        ],
        mitre_mapping=[
            MitreMapping(tactic="Command and Control", tactic_id="TA0011", technique="Application Layer Protocol: Web Protocols", technique_id="T1071.001", description="C2 over HTTP/80 to blend with normal web traffic"),
            MitreMapping(tactic="Command and Control", tactic_id="TA0011", technique="Non-Standard Port", technique_id="T1571", description="Beacon communication pattern"),
            MitreMapping(tactic="Exfiltration", tactic_id="TA0010", technique="Exfiltration Over C2 Channel", technique_id="T1041", description="Potential data exfiltration risk via established C2"),
        ],
        timeline=[
            TimelineEvent(timestamp="T-7d", event="First C2 beacon alert to 198.51.100.23", source="historical", significance="critical"),
            TimelineEvent(timestamp="T-5d", event="Suspicious outbound connection to same IP", source="historical", significance="important"),
            TimelineEvent(timestamp="T-3d", event="Malware download from 198.51.100.23 detected", source="historical", significance="critical"),
            TimelineEvent(timestamp="T-0", event="Active C2 beacon: 192.168.1.50 → 198.51.100.23:80", source="suricata", significance="critical"),
        ],
        recommended_actions=[
            RecommendedAction(action="Isolate Host", priority="immediate", description="Immediately network-isolate WS-DEV-017 (192.168.1.50). Do NOT power off — preserve memory for forensics.", automated=True),
            RecommendedAction(action="Block C2 IP", priority="immediate", description="Block 198.51.100.23 and the entire 198.51.100.0/24 at perimeter firewall. Add to threat intelligence blocklist.", automated=True),
            RecommendedAction(action="Revoke Credentials", priority="immediate", description="Revoke all credentials for the user of WS-DEV-017. Rotate any code signing keys or API tokens accessible from this machine.", automated=False),
            RecommendedAction(action="Code Repository Audit", priority="short_term", description="Audit all code commits from this developer in the past 30 days for signs of supply chain injection.", automated=False),
            RecommendedAction(action="Network Sweep", priority="short_term", description="Search network logs for any other internal hosts communicating with 198.51.100.23 or the /24 subnet.", automated=True),
            RecommendedAction(action="Malware Analysis", priority="short_term", description="Perform full disk forensics and malware analysis on the isolated workstation.", automated=False),
        ],
        iocs_extracted=["198.51.100.23", "192.168.1.50"],
        analysis_reasoning="Step 1: Outbound connection from internal host to external IP. Step 2: External IP is known C2 server with 95/100 malicious score on bulletproof hosting. Step 3: Three prior alerts confirm this is an established threat. Step 4: Suricata signature specifically identifies C2 beacon pattern. Step 5: Source workstation belongs to a developer with code access, significantly elevating the risk. Verdict: TRUE POSITIVE, CRITICAL severity.",
        enrichment_summary="Source: WS-DEV-017, developer workstation, Engineering. Dest: 198.51.100.23, Russia, bulletproof hosting, malicious score 95/100. 3 prior critical alerts. VPN-flagged.",
    ),
}


class AlertAnalyzer:
    """
    Main analysis engine that orchestrates enrichment and LLM analysis.

    Pipeline:
    1. Enrich normalized alert with contextual data
    2. Format context for LLM consumption
    3. Call LLM for structured analysis
    4. Validate and post-process response
    5. Apply confidence calibration
    """

    def __init__(self):
        self.enrichment = EnrichmentOrchestrator()
        self.llm_client = LLMClient()
        self.settings = get_settings()

    async def analyze(
        self,
        alert: NormalizedAlert,
        force_reanalyze: bool = False,
    ) -> tuple[InvestigationResult, EnrichmentData]:
        """
        Analyze a normalized alert end-to-end.

        Returns:
            Tuple of (InvestigationResult, EnrichmentData)
        """
        investigation_id = f"inv-{uuid.uuid4().hex[:12]}"
        start_time = time.time()

        # Step 1: Enrich
        logger.info(f"Starting enrichment for alert {alert.id}")
        enrichment = await self.enrichment.enrich(alert)

        # Step 2: Check if we're in demo mode
        if self.settings.is_demo_mode:
            logger.info("Running in demo mode — returning pre-computed results")
            result = self._get_demo_result(alert, investigation_id, enrichment)
            return result, enrichment

        # Step 3: Build LLM prompts
        alert_summary = format_alert_for_llm(alert.model_dump())
        enrichment_summary = format_enrichment_for_llm(enrichment.model_dump())
        user_prompt = build_analysis_prompt(alert_summary, enrichment_summary)

        # Step 4: Call LLM
        logger.info(f"Calling LLM for analysis of alert {alert.id}")
        try:
            llm_response = await self.llm_client.complete(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                response_format="json",
                temperature=0.1,
                max_tokens=4096,
            )
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            # Return a degraded result with enrichment only
            return self._build_degraded_result(
                alert, investigation_id, enrichment, str(e)
            ), enrichment

        # Step 5: Parse and validate LLM response
        try:
            analysis_data = llm_response.parse_json()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            logger.debug(f"Raw response: {llm_response.content[:500]}")
            return self._build_degraded_result(
                alert, investigation_id, enrichment,
                f"LLM returned invalid JSON: {e}"
            ), enrichment

        # Step 6: Build InvestigationResult
        total_latency = (time.time() - start_time) * 1000
        result = self._build_result(
            alert_id=alert.id,
            investigation_id=investigation_id,
            analysis_data=analysis_data,
            llm_response=llm_response,
            enrichment=enrichment,
            total_latency_ms=total_latency,
        )

        # Step 7: Post-process and validate
        result = self._post_process(result, alert, enrichment)

        return result, enrichment

    def _build_result(
        self,
        alert_id: str,
        investigation_id: str,
        analysis_data: dict,
        llm_response: Any,
        enrichment: EnrichmentData,
        total_latency_ms: float,
    ) -> InvestigationResult:
        """Build InvestigationResult from LLM analysis output."""
        # Parse evidence
        evidence = []
        for ev in analysis_data.get("evidence", []):
            try:
                evidence.append(EvidenceItem(**ev))
            except Exception:
                evidence.append(EvidenceItem(
                    description=str(ev.get("description", ev)),
                    source=str(ev.get("source", "llm")),
                    confidence=str(ev.get("confidence", "medium")),
                ))

        # Parse MITRE mappings
        mitre = []
        for m in analysis_data.get("mitre_mapping", []):
            try:
                mitre.append(MitreMapping(**m))
            except Exception:
                pass

        # Parse timeline
        timeline = []
        for t in analysis_data.get("timeline", []):
            try:
                timeline.append(TimelineEvent(**t))
            except Exception:
                pass

        # Parse recommended actions
        actions = []
        for a in analysis_data.get("recommended_actions", []):
            try:
                actions.append(RecommendedAction(**a))
            except Exception:
                pass

        return InvestigationResult(
            alert_id=alert_id,
            investigation_id=investigation_id,
            severity=analysis_data.get("severity", "unknown"),
            confidence=min(max(float(analysis_data.get("confidence", 0.5)), 0.0), 1.0),
            verdict=analysis_data.get("verdict", "inconclusive"),
            classification=analysis_data.get("classification", "Unknown"),
            executive_summary=analysis_data.get("executive_summary", "Analysis completed."),
            root_cause_analysis=analysis_data.get("root_cause_analysis", ""),
            attack_narrative=analysis_data.get("attack_narrative"),
            evidence=evidence,
            mitre_mapping=mitre,
            timeline=timeline,
            recommended_actions=actions,
            iocs_extracted=analysis_data.get("iocs_extracted", []),
            analysis_reasoning=analysis_data.get("analysis_reasoning"),
            llm_provider=llm_response.provider,
            llm_model=llm_response.model,
            analysis_latency_ms=round(total_latency_ms, 2),
            token_count=llm_response.total_tokens,
            estimated_cost=llm_response.estimated_cost,
        )

    def _post_process(
        self,
        result: InvestigationResult,
        alert: NormalizedAlert,
        enrichment: EnrichmentData,
    ) -> InvestigationResult:
        """
        Post-process the LLM result with hallucination guards and confidence calibration.
        """
        # Confidence calibration based on enrichment completeness
        enrichment_completeness = self._calc_enrichment_completeness(enrichment)
        if enrichment_completeness < 0.5:
            # Reduce confidence if enrichment was sparse
            result.confidence = min(result.confidence, 0.6)
            if not result.enrichment_summary:
                result.enrichment_summary = "⚠️ Limited enrichment data available. Confidence reduced."

        # Validate IOCs against actual alert data
        valid_iocs = []
        alert_text = json.dumps(alert.model_dump()).lower()
        for ioc in result.iocs_extracted:
            if ioc.lower() in alert_text or ioc in [
                ip for ip in alert.get_all_ips()
            ]:
                valid_iocs.append(ioc)
            else:
                # IOC not found in alert data — possible hallucination
                logger.warning(f"IOC '{ioc}' not found in alert data — possible hallucination")
        result.iocs_extracted = valid_iocs if valid_iocs else result.iocs_extracted

        # Add enrichment summary if not present
        if not result.enrichment_summary:
            result.enrichment_summary = self._build_enrichment_summary(enrichment)

        return result

    def _calc_enrichment_completeness(self, enrichment: EnrichmentData) -> float:
        """Calculate how complete the enrichment data is (0.0 - 1.0)."""
        scores = []
        if enrichment.ip_reputation:
            scores.append(1.0)
        if enrichment.geo_ip:
            scores.append(1.0)
        if enrichment.asset_context:
            scores.append(1.0)
        if enrichment.domain_intel:
            scores.append(1.0)

        # Penalize errors
        error_penalty = min(len(enrichment.enrichment_errors) * 0.1, 0.5)

        return (sum(scores) / max(len(scores), 1)) - error_penalty if scores else 0.0

    def _build_enrichment_summary(self, enrichment: EnrichmentData) -> str:
        """Build a concise enrichment summary string."""
        parts = []
        for rep in enrichment.ip_reputation:
            status = "malicious" if rep.is_malicious else "clean"
            parts.append(f"IP {rep.ip}: {status} ({rep.malicious_score}/100)")
        for asset in enrichment.asset_context:
            if asset.asset_name:
                parts.append(f"Asset {asset.asset_name}: {asset.criticality or 'unknown'} criticality")
        if enrichment.historical_matches:
            parts.append(f"{len(enrichment.historical_matches)} historical matches")
        return ". ".join(parts) if parts else "No enrichment data."

    def _get_demo_result(
        self,
        alert: NormalizedAlert,
        investigation_id: str,
        enrichment: EnrichmentData,
    ) -> InvestigationResult:
        """Return a pre-computed demo result based on alert characteristics."""
        # Try to match based on category/title
        title_lower = alert.title.lower()

        if any(k in title_lower for k in ["brute", "force", "login", "auth", "password"]):
            result = _DEMO_RESULTS["brute_force"].model_copy()
        elif any(k in title_lower for k in ["malware", "virus", "trojan", "ransomware", "malicious process"]):
            result = _DEMO_RESULTS["malware"].model_copy()
        elif any(k in title_lower for k in ["c2", "beacon", "command and control", "suspicious user-agent"]):
            result = _DEMO_RESULTS["c2_beacon"].model_copy()
        else:
            # Default to brute force demo
            result = _DEMO_RESULTS["brute_force"].model_copy()

        result.alert_id = alert.id
        result.investigation_id = investigation_id
        result.llm_provider = "demo"
        result.llm_model = "pre-computed"
        result.estimated_cost = 0.0
        result.enrichment_summary = self._build_enrichment_summary(enrichment)

        return result

    def _build_degraded_result(
        self,
        alert: NormalizedAlert,
        investigation_id: str,
        enrichment: EnrichmentData,
        error: str,
    ) -> InvestigationResult:
        """Build a degraded result when LLM analysis fails."""
        # Determine severity from enrichment data
        max_score = 0.0
        for rep in enrichment.ip_reputation:
            max_score = max(max_score, rep.malicious_score)

        if max_score >= 80:
            severity = "high"
        elif max_score >= 50:
            severity = "medium"
        else:
            severity = str(alert.severity.value)

        return InvestigationResult(
            alert_id=alert.id,
            investigation_id=investigation_id,
            severity=severity,
            confidence=0.3,
            verdict="inconclusive",
            classification=alert.title,
            executive_summary=f"AI analysis unavailable ({error}). Enrichment data provided below for manual review.",
            root_cause_analysis="Automated analysis could not be completed. Please review the enrichment data and raw alert manually.",
            evidence=[
                EvidenceItem(
                    description=f"LLM analysis failed: {error}",
                    source="system",
                    confidence="low",
                ),
            ],
            recommended_actions=[
                RecommendedAction(
                    action="Manual Review",
                    priority="immediate",
                    description="Review the enrichment data and raw alert manually. AI analysis was unavailable.",
                    automated=False,
                ),
            ],
            enrichment_summary=self._build_enrichment_summary(enrichment),
            analysis_reasoning=f"Degraded mode: {error}",
        )
