"""
SecOps AI Assistant — IP Reputation Provider

Mock IP reputation data (VirusTotal/AbuseIPDB style) with realistic responses.
Pluggable architecture for real API integration.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from app.enrichment.providers.base import BaseEnrichmentProvider
from app.models.investigation import IPReputationData

# Realistic mock database of known-malicious IPs and their profiles
_KNOWN_MALICIOUS_IPS = {
    "185.220.101.34": {
        "is_malicious": True,
        "malicious_score": 92.0,
        "detection_engines": 47,
        "total_engines": 70,
        "abuse_reports": 1243,
        "last_seen": "2026-06-24T10:30:00Z",
        "categories": ["malware", "botnet", "spam"],
        "country": "Germany",
        "isp": "Tor Exit Node (Zwiebelfreunde e.V.)",
    },
    "45.33.32.156": {
        "is_malicious": True,
        "malicious_score": 78.0,
        "detection_engines": 38,
        "total_engines": 70,
        "abuse_reports": 567,
        "last_seen": "2026-06-23T15:45:00Z",
        "categories": ["scanner", "brute-force"],
        "country": "United States",
        "isp": "Linode LLC",
    },
    "198.51.100.23": {
        "is_malicious": True,
        "malicious_score": 95.0,
        "detection_engines": 52,
        "total_engines": 70,
        "abuse_reports": 2891,
        "last_seen": "2026-06-24T08:15:00Z",
        "categories": ["c2", "malware-distribution"],
        "country": "Russia",
        "isp": "Bulletproof Hosting Inc.",
    },
    "104.21.55.2": {
        "is_malicious": True,
        "malicious_score": 65.0,
        "detection_engines": 28,
        "total_engines": 70,
        "abuse_reports": 312,
        "last_seen": "2026-06-22T22:00:00Z",
        "categories": ["phishing", "suspicious"],
        "country": "United States",
        "isp": "Cloudflare Inc.",
    },
    "203.0.113.50": {
        "is_malicious": True,
        "malicious_score": 88.0,
        "detection_engines": 45,
        "total_engines": 70,
        "abuse_reports": 1567,
        "last_seen": "2026-06-24T12:00:00Z",
        "categories": ["c2", "data-exfiltration"],
        "country": "China",
        "isp": "China Telecom",
    },
    "91.219.236.222": {
        "is_malicious": True,
        "malicious_score": 71.0,
        "detection_engines": 32,
        "total_engines": 70,
        "abuse_reports": 445,
        "last_seen": "2026-06-23T18:30:00Z",
        "categories": ["ransomware", "exploit-kit"],
        "country": "Netherlands",
        "isp": "Ecatel LTD",
    },
}

# Known benign IPs for realistic responses
_KNOWN_BENIGN_IPS = {
    "8.8.8.8": {"country": "United States", "isp": "Google LLC"},
    "1.1.1.1": {"country": "United States", "isp": "Cloudflare Inc."},
    "208.67.222.222": {"country": "United States", "isp": "OpenDNS"},
}

# Private IP ranges
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.", "0.")


class IPReputationProvider(BaseEnrichmentProvider):
    """IP reputation lookup provider with mock data."""

    name = "ip_reputation"
    timeout_seconds = 5.0

    def is_available(self) -> bool:
        return True  # Mock is always available

    async def enrich(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        """Look up IP reputation."""
        if indicator_type != "ip":
            return {}

        result = self._mock_lookup(indicator)
        return result.model_dump()

    def _mock_lookup(self, ip: str) -> IPReputationData:
        """Generate realistic mock IP reputation data."""
        # Check known malicious
        if ip in _KNOWN_MALICIOUS_IPS:
            data = _KNOWN_MALICIOUS_IPS[ip]
            return IPReputationData(ip=ip, source="mock_virustotal", **data)

        # Check known benign
        if ip in _KNOWN_BENIGN_IPS:
            info = _KNOWN_BENIGN_IPS[ip]
            return IPReputationData(
                ip=ip,
                is_malicious=False,
                malicious_score=0.0,
                detection_engines=0,
                total_engines=70,
                abuse_reports=0,
                country=info["country"],
                isp=info["isp"],
                source="mock_virustotal",
            )

        # Private IPs — always clean
        if ip.startswith(_PRIVATE_PREFIXES):
            return IPReputationData(
                ip=ip,
                is_malicious=False,
                malicious_score=0.0,
                detection_engines=0,
                total_engines=70,
                categories=["internal"],
                country="Internal Network",
                isp="Private Range",
                source="mock_virustotal",
            )

        # Generate deterministic but realistic data based on IP hash
        seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)

        is_suspicious = rng.random() < 0.3  # 30% chance of being suspicious
        score = rng.uniform(40, 85) if is_suspicious else rng.uniform(0, 15)
        engines = int(score / 100 * 70)

        countries = ["United States", "Germany", "Netherlands", "France",
                      "United Kingdom", "Japan", "Brazil", "India", "Canada"]
        isps = ["Amazon Web Services", "DigitalOcean", "OVH SAS",
                 "Hetzner Online GmbH", "Google Cloud", "Microsoft Azure"]

        return IPReputationData(
            ip=ip,
            is_malicious=is_suspicious,
            malicious_score=round(score, 1),
            detection_engines=engines,
            total_engines=70,
            abuse_reports=rng.randint(0, 50) if is_suspicious else 0,
            last_seen="2026-06-24T06:00:00Z" if is_suspicious else None,
            categories=["suspicious"] if is_suspicious else [],
            country=rng.choice(countries),
            isp=rng.choice(isps),
            source="mock_virustotal",
        )
