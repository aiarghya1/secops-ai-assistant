"""
SecOps AI Assistant — Domain Intelligence Provider

Mock domain reputation and WHOIS-like data with realistic responses.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from app.enrichment.providers.base import BaseEnrichmentProvider
from app.models.investigation import DomainIntelData

_KNOWN_MALICIOUS_DOMAINS = {
    "evil-payload.ru": {
        "is_malicious": True,
        "reputation_score": 95.0,
        "registration_date": "2026-05-01",
        "registrar": "RegRU",
        "category": "malware-distribution",
        "whois_info": {
            "registrant": "REDACTED FOR PRIVACY",
            "name_servers": ["ns1.bulletproof-dns.net", "ns2.bulletproof-dns.net"],
            "status": "clientTransferProhibited",
        },
    },
    "suspicious-login.com": {
        "is_malicious": True,
        "reputation_score": 88.0,
        "registration_date": "2026-06-10",
        "registrar": "NameCheap Inc.",
        "category": "phishing",
        "whois_info": {
            "registrant": "WhoisGuard Protected",
            "name_servers": ["ns1.registrar-servers.com"],
            "status": "clientTransferProhibited",
            "age_days": 14,
        },
    },
    "c2-beacon.xyz": {
        "is_malicious": True,
        "reputation_score": 97.0,
        "registration_date": "2026-06-15",
        "registrar": "Njalla",
        "category": "c2",
        "whois_info": {
            "registrant": "1337 Services LLC",
            "name_servers": ["ns1.njal.la", "ns2.njal.la"],
            "status": "ok",
            "age_days": 9,
        },
    },
    "data-drop.io": {
        "is_malicious": True,
        "reputation_score": 82.0,
        "registration_date": "2026-04-20",
        "registrar": "Porkbun LLC",
        "category": "data-exfiltration",
        "whois_info": {
            "registrant": "REDACTED",
            "name_servers": ["ns1.porkbun.com"],
            "age_days": 65,
        },
    },
}

_KNOWN_BENIGN_DOMAINS = {
    "google.com": {"reputation_score": 0.0, "category": "search-engine", "registrar": "MarkMonitor Inc."},
    "microsoft.com": {"reputation_score": 0.0, "category": "technology", "registrar": "MarkMonitor Inc."},
    "github.com": {"reputation_score": 0.0, "category": "development", "registrar": "MarkMonitor Inc."},
    "cloudflare.com": {"reputation_score": 0.0, "category": "cdn-security", "registrar": "MarkMonitor Inc."},
}


class DomainIntelProvider(BaseEnrichmentProvider):
    """Domain intelligence lookup provider with mock data."""

    name = "domain_intel"
    timeout_seconds = 5.0

    def is_available(self) -> bool:
        return True

    async def enrich(self, indicator: str, indicator_type: str = "domain") -> dict[str, Any]:
        if indicator_type != "domain":
            return {}
        result = self._mock_lookup(indicator)
        return result.model_dump()

    def _mock_lookup(self, domain: str) -> DomainIntelData:
        # Clean domain
        domain = domain.lower().strip().rstrip(".")

        if domain in _KNOWN_MALICIOUS_DOMAINS:
            data = _KNOWN_MALICIOUS_DOMAINS[domain]
            return DomainIntelData(domain=domain, source="mock_whois", **data)

        if domain in _KNOWN_BENIGN_DOMAINS:
            info = _KNOWN_BENIGN_DOMAINS[domain]
            return DomainIntelData(
                domain=domain,
                is_malicious=False,
                reputation_score=info["reputation_score"],
                category=info["category"],
                registrar=info["registrar"],
                registration_date="1997-09-15",
                source="mock_whois",
            )

        # Generate deterministic mock data
        seed = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)

        # Suspicious TLDs
        suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".ru", ".cn", ".top"]
        is_suspicious = any(domain.endswith(tld) for tld in suspicious_tlds) or rng.random() < 0.2

        registrars = ["GoDaddy LLC", "NameCheap Inc.", "Cloudflare Inc.",
                       "Google Domains", "Tucows Domains", "OVH SAS"]

        score = rng.uniform(50, 80) if is_suspicious else rng.uniform(0, 20)

        return DomainIntelData(
            domain=domain,
            is_malicious=is_suspicious,
            reputation_score=round(score, 1),
            registration_date=f"20{rng.randint(15, 26):02d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            registrar=rng.choice(registrars),
            category="suspicious" if is_suspicious else "uncategorized",
            source="mock_whois",
        )
