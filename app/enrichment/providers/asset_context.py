"""
SecOps AI Assistant — Asset Context Provider

Mock CMDB/asset inventory for mapping IPs and hostnames to asset metadata.
Crucial for severity scoring: attack on a payment server ≠ attack on a dev box.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from app.enrichment.providers.base import BaseEnrichmentProvider
from app.models.investigation import AssetContextData

_KNOWN_ASSETS = {
    "10.0.0.5": AssetContextData(
        identifier="10.0.0.5",
        asset_name="WIN-SERVER-01",
        asset_type="server",
        criticality="critical",
        owner="IT Operations",
        department="Infrastructure",
        os="Windows Server 2022",
        environment="production",
        last_patched="2026-06-10",
        tags=["active-directory", "domain-controller", "tier-0"],
    ),
    "WIN-SERVER-01": AssetContextData(
        identifier="WIN-SERVER-01",
        asset_name="WIN-SERVER-01",
        asset_type="server",
        criticality="critical",
        owner="IT Operations",
        department="Infrastructure",
        os="Windows Server 2022",
        environment="production",
        last_patched="2026-06-10",
        tags=["active-directory", "domain-controller", "tier-0"],
    ),
    "192.168.1.105": AssetContextData(
        identifier="192.168.1.105",
        asset_name="WS-FINANCE-042",
        asset_type="workstation",
        criticality="high",
        owner="Jane Smith",
        department="Finance",
        os="Windows 11 Enterprise",
        environment="production",
        last_patched="2026-06-15",
        tags=["finance", "pci-scope", "sensitive-data"],
    ),
    "192.168.1.50": AssetContextData(
        identifier="192.168.1.50",
        asset_name="WS-DEV-017",
        asset_type="workstation",
        criticality="medium",
        owner="John Developer",
        department="Engineering",
        os="Ubuntu 24.04 LTS",
        environment="development",
        last_patched="2026-06-20",
        tags=["developer", "code-access", "vpn-user"],
    ),
    "192.168.1.200": AssetContextData(
        identifier="192.168.1.200",
        asset_name="SRV-DB-PROD-01",
        asset_type="server",
        criticality="critical",
        owner="Database Team",
        department="Infrastructure",
        os="Red Hat Enterprise Linux 9",
        environment="production",
        last_patched="2026-06-05",
        tags=["database", "pci-scope", "customer-data", "tier-1"],
    ),
    "10.0.1.15": AssetContextData(
        identifier="10.0.1.15",
        asset_name="SRV-WEB-PROD-03",
        asset_type="server",
        criticality="high",
        owner="Web Platform Team",
        department="Engineering",
        os="Ubuntu 22.04 LTS",
        environment="production",
        last_patched="2026-06-18",
        tags=["web-server", "internet-facing", "customer-portal"],
    ),
    "10.0.2.50": AssetContextData(
        identifier="10.0.2.50",
        asset_name="SRV-STAGING-01",
        asset_type="server",
        criticality="low",
        owner="QA Team",
        department="Engineering",
        os="Ubuntu 22.04 LTS",
        environment="staging",
        last_patched="2026-06-01",
        tags=["staging", "non-production", "test-data"],
    ),
}


class AssetContextProvider(BaseEnrichmentProvider):
    """Asset context/CMDB lookup provider with mock data."""

    name = "asset_context"
    timeout_seconds = 2.0

    def is_available(self) -> bool:
        return True

    async def enrich(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        if indicator_type not in ("ip", "hostname"):
            return {}
        result = self._mock_lookup(indicator)
        return result.model_dump()

    def _mock_lookup(self, identifier: str) -> AssetContextData:
        # Check known assets
        if identifier in _KNOWN_ASSETS:
            return _KNOWN_ASSETS[identifier]

        # Private IPs get a generated asset
        private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                             "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                             "172.30.", "172.31.", "192.168.")
        if identifier.startswith(private_prefixes):
            return self._generate_asset(identifier)

        # External IPs / unknown hosts
        return AssetContextData(
            identifier=identifier,
            asset_name=None,
            asset_type="external",
            criticality=None,
            source="mock_cmdb",
        )

    def _generate_asset(self, identifier: str) -> AssetContextData:
        """Generate a realistic mock asset for internal IPs."""
        seed = int(hashlib.md5(identifier.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)

        asset_types = ["workstation", "server", "network_device", "printer", "cloud_instance"]
        criticalities = ["critical", "high", "medium", "low"]
        environments = ["production", "staging", "development", "test"]
        departments = ["Engineering", "Finance", "HR", "Sales", "Marketing",
                         "IT Operations", "Security", "Legal", "Executive"]
        os_options = ["Windows 11 Enterprise", "Windows 10 Enterprise",
                       "macOS Sonoma", "Ubuntu 22.04 LTS", "Red Hat Enterprise Linux 9"]

        asset_type = rng.choice(asset_types)
        prefix = {"workstation": "WS", "server": "SRV", "network_device": "NET",
                   "printer": "PRN", "cloud_instance": "CLD"}
        name = f"{prefix.get(asset_type, 'ASSET')}-{rng.randint(100, 999)}"

        return AssetContextData(
            identifier=identifier,
            asset_name=name,
            asset_type=asset_type,
            criticality=rng.choice(criticalities),
            owner=f"Team-{rng.randint(1, 20)}",
            department=rng.choice(departments),
            os=rng.choice(os_options),
            environment=rng.choice(environments),
            last_patched=f"2026-06-{rng.randint(1, 24):02d}",
            tags=[asset_type],
            source="mock_cmdb",
        )
