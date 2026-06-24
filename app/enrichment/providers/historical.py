"""
SecOps AI Assistant — Historical Behavior Provider

Queries local database for past alerts involving the same IP/user/host
to detect patterns and repeat offenders.
"""

from __future__ import annotations

from typing import Any

from app.enrichment.providers.base import BaseEnrichmentProvider
from app.models.investigation import HistoricalMatch


# Mock historical data for sample scenarios
_MOCK_HISTORY = {
    "185.220.101.34": [
        HistoricalMatch(
            alert_id="hist-001",
            timestamp="2026-06-20T14:30:00Z",
            title="Tor Exit Node Brute Force Attempt",
            severity="high",
            matching_indicator="185.220.101.34",
        ),
        HistoricalMatch(
            alert_id="hist-002",
            timestamp="2026-06-18T09:15:00Z",
            title="Multiple Failed SSH Logins from Tor",
            severity="medium",
            matching_indicator="185.220.101.34",
        ),
    ],
    "45.33.32.156": [
        HistoricalMatch(
            alert_id="hist-003",
            timestamp="2026-06-22T11:00:00Z",
            title="Port Scan Detected from 45.33.32.156",
            severity="low",
            matching_indicator="45.33.32.156",
        ),
    ],
    "198.51.100.23": [
        HistoricalMatch(
            alert_id="hist-004",
            timestamp="2026-06-21T03:45:00Z",
            title="C2 Beacon Activity to Known Malicious IP",
            severity="critical",
            matching_indicator="198.51.100.23",
        ),
        HistoricalMatch(
            alert_id="hist-005",
            timestamp="2026-06-19T16:20:00Z",
            title="Suspicious Outbound Connection to 198.51.100.23",
            severity="high",
            matching_indicator="198.51.100.23",
        ),
        HistoricalMatch(
            alert_id="hist-006",
            timestamp="2026-06-17T08:00:00Z",
            title="Malware Download from 198.51.100.23",
            severity="critical",
            matching_indicator="198.51.100.23",
        ),
    ],
    "admin_user": [
        HistoricalMatch(
            alert_id="hist-007",
            timestamp="2026-06-23T02:30:00Z",
            title="Off-Hours Admin Login Detected",
            severity="medium",
            matching_indicator="admin_user",
        ),
    ],
    "svc_admin": [
        HistoricalMatch(
            alert_id="hist-008",
            timestamp="2026-06-22T05:00:00Z",
            title="Service Account Used from Unusual Location",
            severity="high",
            matching_indicator="svc_admin",
        ),
    ],
    "jsmith": [
        HistoricalMatch(
            alert_id="hist-009",
            timestamp="2026-06-21T14:00:00Z",
            title="Excessive Data Download by User jsmith",
            severity="medium",
            matching_indicator="jsmith",
        ),
        HistoricalMatch(
            alert_id="hist-010",
            timestamp="2026-06-15T10:30:00Z",
            title="jsmith Accessed Restricted Files",
            severity="high",
            matching_indicator="jsmith",
        ),
    ],
    "203.0.113.50": [
        HistoricalMatch(
            alert_id="hist-011",
            timestamp="2026-06-23T07:00:00Z",
            title="Large Data Transfer to Chinese IP",
            severity="high",
            matching_indicator="203.0.113.50",
        ),
    ],
}


class HistoricalProvider(BaseEnrichmentProvider):
    """Historical alert behavior lookup provider."""

    name = "historical"
    timeout_seconds = 3.0

    def is_available(self) -> bool:
        return True

    async def enrich(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        """Look up historical alerts for an indicator."""
        matches = _MOCK_HISTORY.get(indicator, [])

        # Also try to query the real database
        try:
            from app.database import find_related_alerts
            if indicator_type == "ip":
                db_matches = await find_related_alerts(ip=indicator)
            elif indicator_type == "user":
                db_matches = await find_related_alerts(user=indicator)
            elif indicator_type == "hostname":
                db_matches = await find_related_alerts(hostname=indicator)
            else:
                db_matches = []

            for match in db_matches:
                normalized = match.get("normalized_json", {})
                if isinstance(normalized, dict):
                    matches.append(HistoricalMatch(
                        alert_id=match.get("id", "unknown"),
                        timestamp=str(match.get("created_at", "")),
                        title=normalized.get("title", "Unknown Alert"),
                        severity=normalized.get("severity", "unknown"),
                        matching_indicator=indicator,
                    ))
        except Exception:
            pass  # DB might not be initialized yet

        return {
            "indicator": indicator,
            "match_count": len(matches),
            "matches": [m.model_dump() for m in matches],
            "is_repeat_offender": len(matches) >= 3,
            "pattern_summary": self._summarize_pattern(matches),
        }

    def _summarize_pattern(self, matches: list[HistoricalMatch]) -> str:
        if not matches:
            return "No historical activity found."
        if len(matches) == 1:
            return f"1 previous alert: {matches[0].title}"
        severities = [m.severity for m in matches]
        crit_high = sum(1 for s in severities if s in ("critical", "high"))
        return (
            f"{len(matches)} previous alerts found. "
            f"{crit_high} were critical/high severity. "
            f"Latest: {matches[0].title} ({matches[0].timestamp})"
        )
