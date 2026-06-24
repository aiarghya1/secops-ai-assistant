"""
SecOps AI Assistant — GeoIP Provider

Mock GeoIP lookup with realistic country/city/ASN data.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from app.enrichment.providers.base import BaseEnrichmentProvider
from app.models.investigation import GeoIPData

_KNOWN_GEO = {
    "185.220.101.34": {
        "country": "Germany", "country_code": "DE", "city": "Nuremberg",
        "region": "Bavaria", "latitude": 49.4521, "longitude": 11.0767,
        "asn": "AS205100", "organization": "Zwiebelfreunde e.V.",
        "is_tor": True, "is_vpn": False, "is_proxy": False,
    },
    "45.33.32.156": {
        "country": "United States", "country_code": "US", "city": "Fremont",
        "region": "California", "latitude": 37.5485, "longitude": -121.9886,
        "asn": "AS63949", "organization": "Akamai Connected Cloud (Linode)",
        "is_tor": False, "is_vpn": False, "is_proxy": False,
    },
    "198.51.100.23": {
        "country": "Russia", "country_code": "RU", "city": "Moscow",
        "region": "Moscow Oblast", "latitude": 55.7558, "longitude": 37.6173,
        "asn": "AS44050", "organization": "PIN Data Center",
        "is_tor": False, "is_vpn": True, "is_proxy": False,
    },
    "104.21.55.2": {
        "country": "United States", "country_code": "US", "city": "San Francisco",
        "region": "California", "latitude": 37.7749, "longitude": -122.4194,
        "asn": "AS13335", "organization": "Cloudflare Inc.",
        "is_tor": False, "is_vpn": False, "is_proxy": True,
    },
    "203.0.113.50": {
        "country": "China", "country_code": "CN", "city": "Beijing",
        "region": "Beijing", "latitude": 39.9042, "longitude": 116.4074,
        "asn": "AS4134", "organization": "China Telecom",
        "is_tor": False, "is_vpn": False, "is_proxy": False,
    },
    "91.219.236.222": {
        "country": "Netherlands", "country_code": "NL", "city": "Amsterdam",
        "region": "North Holland", "latitude": 52.3676, "longitude": 4.9041,
        "asn": "AS29073", "organization": "Ecatel LTD",
        "is_tor": False, "is_vpn": True, "is_proxy": False,
    },
    "8.8.8.8": {
        "country": "United States", "country_code": "US", "city": "Mountain View",
        "region": "California", "latitude": 37.386, "longitude": -122.0838,
        "asn": "AS15169", "organization": "Google LLC",
    },
}

_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.", "0.")

# Cities by country for realistic generation
_GEO_DATABASE = [
    {"country": "United States", "code": "US", "city": "Ashburn", "region": "Virginia", "lat": 39.0438, "lon": -77.4874, "asn": "AS14618", "org": "Amazon.com Inc."},
    {"country": "Germany", "code": "DE", "city": "Frankfurt", "region": "Hessen", "lat": 50.1109, "lon": 8.6821, "asn": "AS24940", "org": "Hetzner Online GmbH"},
    {"country": "Netherlands", "code": "NL", "city": "Amsterdam", "region": "North Holland", "lat": 52.3676, "lon": 4.9041, "asn": "AS60781", "org": "LeaseWeb B.V."},
    {"country": "United Kingdom", "code": "GB", "city": "London", "region": "England", "lat": 51.5074, "lon": -0.1278, "asn": "AS5089", "org": "Virgin Media"},
    {"country": "Japan", "code": "JP", "city": "Tokyo", "region": "Tokyo", "lat": 35.6762, "lon": 139.6503, "asn": "AS2516", "org": "KDDI Corporation"},
    {"country": "Singapore", "code": "SG", "city": "Singapore", "region": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS16509", "org": "Amazon.com Inc."},
    {"country": "Brazil", "code": "BR", "city": "São Paulo", "region": "São Paulo", "lat": -23.5505, "lon": -46.6333, "asn": "AS28573", "org": "Claro S.A."},
    {"country": "India", "code": "IN", "city": "Mumbai", "region": "Maharashtra", "lat": 19.0760, "lon": 72.8777, "asn": "AS9829", "org": "National Internet Backbone"},
    {"country": "Canada", "code": "CA", "city": "Toronto", "region": "Ontario", "lat": 43.6532, "lon": -79.3832, "asn": "AS577", "org": "Bell Canada"},
    {"country": "France", "code": "FR", "city": "Paris", "region": "Île-de-France", "lat": 48.8566, "lon": 2.3522, "asn": "AS16276", "org": "OVH SAS"},
]


class GeoIPProvider(BaseEnrichmentProvider):
    """GeoIP lookup provider with mock data."""

    name = "geo_ip"
    timeout_seconds = 3.0

    def is_available(self) -> bool:
        return True

    async def enrich(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        if indicator_type != "ip":
            return {}
        result = self._mock_lookup(indicator)
        return result.model_dump()

    def _mock_lookup(self, ip: str) -> GeoIPData:
        # Private IP
        if ip.startswith(_PRIVATE_PREFIXES):
            return GeoIPData(
                ip=ip,
                country="Internal Network",
                country_code="--",
                city="Internal",
                asn="Private",
                organization="Internal Network",
                source="mock_geoip",
            )

        # Known IPs
        if ip in _KNOWN_GEO:
            data = _KNOWN_GEO[ip]
            return GeoIPData(ip=ip, source="mock_geoip", **data)

        # Generate deterministic geo data
        seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)
        geo = rng.choice(_GEO_DATABASE)

        return GeoIPData(
            ip=ip,
            country=geo["country"],
            country_code=geo["code"],
            city=geo["city"],
            region=geo["region"],
            latitude=geo["lat"],
            longitude=geo["lon"],
            asn=geo["asn"],
            organization=geo["org"],
            is_vpn=rng.random() < 0.1,
            is_tor=rng.random() < 0.05,
            is_proxy=rng.random() < 0.08,
            source="mock_geoip",
        )
