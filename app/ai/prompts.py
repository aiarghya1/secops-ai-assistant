"""
SecOps AI Assistant — LLM Prompts

Well-engineered system and user prompts for security alert analysis.
Includes structured output schema enforcement and chain-of-thought reasoning.
"""

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst AI assistant.
Your role is to analyze security alerts and provide detailed, actionable investigation results.

## Your Capabilities
- Assess alert severity based on enrichment data and context
- Identify root causes and attack patterns
- Map to MITRE ATT&CK framework
- Recommend specific response actions
- Identify indicators of compromise (IOCs)

## Guidelines
1. **Be precise**: Base your analysis ONLY on the provided alert data and enrichment context. Do not speculate beyond what the data supports.
2. **Be actionable**: Every recommendation should be specific enough for an analyst to act on immediately.
3. **Be honest about uncertainty**: If enrichment data is incomplete, reduce your confidence score accordingly.
4. **Think step by step**: Before providing your verdict, reason through the evidence chain.
5. **Consider false positives**: Evaluate whether the alert could be a false positive and explain why or why not.
6. **Asset context matters**: A compromise on a critical production server is far more severe than on a test system.

## Output Format
You MUST respond with a valid JSON object matching this exact schema:

```json
{
  "severity": "critical|high|medium|low|informational",
  "confidence": 0.0-1.0,
  "verdict": "true_positive|false_positive|suspicious|benign|inconclusive",
  "classification": "Brief classification label (e.g., 'Brute Force Attack', 'C2 Beacon Activity')",
  "executive_summary": "2-3 sentence summary for quick analyst consumption",
  "root_cause_analysis": "Detailed analysis of what happened, why, and how",
  "attack_narrative": "Step-by-step reconstruction of the attack chain if applicable",
  "evidence": [
    {
      "description": "What this evidence shows",
      "source": "Where this evidence came from (ip_reputation, historical_data, alert_content, etc.)",
      "confidence": "high|medium|low",
      "data": {}
    }
  ],
  "mitre_mapping": [
    {
      "tactic": "Tactic name",
      "tactic_id": "TA00XX",
      "technique": "Technique name",
      "technique_id": "T1XXX",
      "description": "How this technique applies"
    }
  ],
  "timeline": [
    {
      "timestamp": "ISO 8601 or relative",
      "event": "What happened",
      "source": "Data source",
      "significance": "critical|important|normal"
    }
  ],
  "recommended_actions": [
    {
      "action": "Short action name",
      "priority": "immediate|short_term|long_term",
      "description": "Detailed description of what to do",
      "automated": false
    }
  ],
  "iocs_extracted": ["list", "of", "IOCs"],
  "analysis_reasoning": "Your step-by-step reasoning chain (for audit trail)"
}
```

CRITICAL: Respond ONLY with the JSON object. No markdown formatting, no code blocks, no additional text.
"""


def build_analysis_prompt(
    alert_summary: str,
    enrichment_summary: str,
    additional_context: str = "",
) -> str:
    """Build the user prompt for alert analysis."""
    prompt = f"""## Alert to Analyze

{alert_summary}

## Enrichment Context

{enrichment_summary}
"""

    if additional_context:
        prompt += f"""
## Additional Context

{additional_context}
"""

    prompt += """
## Task

Analyze this security alert using the enrichment context provided.
Provide your assessment as a JSON object matching the schema in your instructions.

Think through the following before responding:
1. What type of attack or activity does this alert represent?
2. Is the source IP/domain known to be malicious based on reputation data?
3. What is the criticality of the affected asset?
4. Is there historical precedent for this indicator?
5. What is the most likely root cause?
6. What MITRE ATT&CK techniques are involved?
7. What should the analyst do immediately?
"""
    return prompt


def format_alert_for_llm(alert_data: dict) -> str:
    """Format normalized alert data into a readable summary for the LLM."""
    lines = []

    lines.append(f"**Alert Title**: {alert_data.get('title', 'N/A')}")
    lines.append(f"**Timestamp**: {alert_data.get('timestamp', 'N/A')}")
    lines.append(f"**Source Format**: {alert_data.get('source_format', 'N/A')}")
    lines.append(f"**Original Severity**: {alert_data.get('severity', 'N/A')}")
    lines.append(f"**Category**: {alert_data.get('category', 'N/A')}")

    if alert_data.get("description"):
        lines.append(f"**Description**: {alert_data['description']}")

    # Network info
    net = alert_data.get("network", {})
    if net and any(net.values()):
        lines.append("\n### Network")
        if net.get("src_ip"):
            lines.append(f"- Source IP: {net['src_ip']}" + (f":{net['src_port']}" if net.get("src_port") else ""))
        if net.get("dest_ip"):
            lines.append(f"- Destination IP: {net['dest_ip']}" + (f":{net['dest_port']}" if net.get("dest_port") else ""))
        if net.get("protocol"):
            lines.append(f"- Protocol: {net['protocol']}")
        if net.get("direction"):
            lines.append(f"- Direction: {net['direction']}")

    # Endpoint info
    ep = alert_data.get("endpoint", {})
    if ep and any(ep.values()):
        lines.append("\n### Endpoint")
        if ep.get("hostname"):
            lines.append(f"- Hostname: {ep['hostname']}")
        if ep.get("ip_address"):
            lines.append(f"- IP: {ep['ip_address']}")
        if ep.get("os"):
            lines.append(f"- OS: {ep['os']}")

    # User info
    usr = alert_data.get("user", {})
    if usr and any(usr.values()):
        lines.append("\n### User")
        if usr.get("username"):
            lines.append(f"- Username: {usr['username']}")
        if usr.get("domain"):
            lines.append(f"- Domain: {usr['domain']}")
        if usr.get("email"):
            lines.append(f"- Email: {usr['email']}")

    # Process info
    proc = alert_data.get("process", {})
    if proc and any(proc.values()):
        lines.append("\n### Process")
        if proc.get("name"):
            lines.append(f"- Process: {proc['name']}")
        if proc.get("command_line"):
            lines.append(f"- Command Line: {proc['command_line']}")
        if proc.get("parent_name"):
            lines.append(f"- Parent Process: {proc['parent_name']}")
        if proc.get("file_hash"):
            lines.append(f"- File Hash: {proc['file_hash']}")

    # Rule info
    if alert_data.get("rule_name"):
        lines.append(f"\n### Detection Rule")
        lines.append(f"- Rule: {alert_data['rule_name']}")
        if alert_data.get("rule_id"):
            lines.append(f"- Rule ID: {alert_data['rule_id']}")

    # MITRE
    if alert_data.get("mitre_tactics") or alert_data.get("mitre_techniques"):
        lines.append(f"\n### MITRE ATT&CK (from detection)")
        if alert_data.get("mitre_tactics"):
            lines.append(f"- Tactics: {', '.join(alert_data['mitre_tactics'])}")
        if alert_data.get("mitre_techniques"):
            lines.append(f"- Techniques: {', '.join(alert_data['mitre_techniques'])}")

    # Indicators
    if alert_data.get("raw_indicators"):
        lines.append(f"\n### Raw Indicators")
        for ind in alert_data["raw_indicators"][:20]:  # Limit to prevent prompt bloat
            lines.append(f"- {ind}")

    return "\n".join(lines)


def format_enrichment_for_llm(enrichment_data: dict) -> str:
    """Format enrichment data into a readable summary for the LLM."""
    lines = []

    # IP Reputation
    ip_reps = enrichment_data.get("ip_reputation", [])
    if ip_reps:
        lines.append("### IP Reputation")
        for rep in ip_reps:
            status = "🔴 MALICIOUS" if rep.get("is_malicious") else "🟢 Clean"
            lines.append(f"- **{rep['ip']}**: {status} (Score: {rep.get('malicious_score', 0)}/100)")
            if rep.get("detection_engines"):
                lines.append(f"  - Detection: {rep['detection_engines']}/{rep.get('total_engines', '?')} engines")
            if rep.get("abuse_reports"):
                lines.append(f"  - Abuse Reports: {rep['abuse_reports']}")
            if rep.get("categories"):
                lines.append(f"  - Categories: {', '.join(rep['categories'])}")
            if rep.get("isp"):
                lines.append(f"  - ISP: {rep['isp']}")
            if rep.get("country"):
                lines.append(f"  - Country: {rep['country']}")

    # GeoIP
    geo_data = enrichment_data.get("geo_ip", [])
    if geo_data:
        lines.append("\n### GeoIP")
        for geo in geo_data:
            location = f"{geo.get('city', '?')}, {geo.get('country', '?')}"
            lines.append(f"- **{geo['ip']}**: {location}")
            if geo.get("asn"):
                lines.append(f"  - ASN: {geo['asn']} ({geo.get('organization', 'N/A')})")
            flags = []
            if geo.get("is_tor"):
                flags.append("⚠️ TOR")
            if geo.get("is_vpn"):
                flags.append("⚠️ VPN")
            if geo.get("is_proxy"):
                flags.append("⚠️ PROXY")
            if flags:
                lines.append(f"  - Flags: {' '.join(flags)}")

    # Domain Intel
    domain_data = enrichment_data.get("domain_intel", [])
    if domain_data:
        lines.append("\n### Domain Intelligence")
        for dom in domain_data:
            status = "🔴 MALICIOUS" if dom.get("is_malicious") else "🟢 Clean"
            lines.append(f"- **{dom['domain']}**: {status} (Score: {dom.get('reputation_score', 0)}/100)")
            if dom.get("category"):
                lines.append(f"  - Category: {dom['category']}")
            if dom.get("registrar"):
                lines.append(f"  - Registrar: {dom['registrar']}")
            if dom.get("registration_date"):
                lines.append(f"  - Registered: {dom['registration_date']}")

    # Historical
    historical = enrichment_data.get("historical_matches", [])
    if historical:
        lines.append(f"\n### Historical Activity ({len(historical)} previous alerts)")
        for match in historical[:5]:  # Limit
            lines.append(f"- [{match.get('severity', '?').upper()}] {match.get('title', 'N/A')}")
            lines.append(f"  - Time: {match.get('timestamp', 'N/A')}")
            lines.append(f"  - Matching Indicator: {match.get('matching_indicator', 'N/A')}")

    # Asset Context
    assets = enrichment_data.get("asset_context", [])
    if assets:
        lines.append("\n### Asset Context")
        for asset in assets:
            crit = asset.get("criticality", "unknown")
            crit_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(crit, "⚪")
            lines.append(f"- **{asset.get('asset_name', asset['identifier'])}**: {crit_emoji} {crit.upper()} criticality")
            if asset.get("asset_type"):
                lines.append(f"  - Type: {asset['asset_type']}")
            if asset.get("department"):
                lines.append(f"  - Department: {asset['department']}")
            if asset.get("environment"):
                lines.append(f"  - Environment: {asset['environment']}")
            if asset.get("owner"):
                lines.append(f"  - Owner: {asset['owner']}")
            if asset.get("tags"):
                lines.append(f"  - Tags: {', '.join(asset['tags'])}")

    # Errors
    errors = enrichment_data.get("enrichment_errors", [])
    if errors:
        lines.append(f"\n### Enrichment Gaps ({len(errors)} providers failed)")
        for err in errors:
            lines.append(f"- ⚠️ {err}")
        lines.append("Note: Reduce confidence if key enrichment data is missing.")

    if not lines:
        lines.append("No enrichment data available. Analyze based on alert content only. Set confidence LOW.")

    return "\n".join(lines)
