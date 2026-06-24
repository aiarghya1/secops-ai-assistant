"""
SecOps AI Assistant — Enrichment Orchestrator

Runs all enrichment providers in parallel, respecting timeouts.
Partial enrichment is acceptable — analysis proceeds with whatever data is available.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from app.config import get_settings
from app.enrichment.providers.asset_context import AssetContextProvider
from app.enrichment.providers.domain_intel import DomainIntelProvider
from app.enrichment.providers.geo_ip import GeoIPProvider
from app.enrichment.providers.historical import HistoricalProvider
from app.enrichment.providers.ip_reputation import IPReputationProvider
from app.models.alert import NormalizedAlert
from app.models.investigation import (
    AssetContextData,
    DomainIntelData,
    EnrichmentData,
    GeoIPData,
    HistoricalMatch,
    IPReputationData,
)

logger = logging.getLogger(__name__)


class EnrichmentOrchestrator:
    """Orchestrates parallel enrichment queries for alert indicators."""

    def __init__(self):
        self.ip_reputation = IPReputationProvider()
        self.domain_intel = DomainIntelProvider()
        self.geo_ip = GeoIPProvider()
        self.historical = HistoricalProvider()
        self.asset_context = AssetContextProvider()

    async def enrich(self, alert: NormalizedAlert) -> EnrichmentData:
        """
        Enrich a normalized alert with data from all providers.

        Runs all enrichment in parallel with per-provider timeouts.
        Partial results are acceptable — the analyzer will note reduced confidence.
        """
        start_time = time.time()
        settings = get_settings()
        global_timeout = settings.enrichment_timeout_seconds * 3  # 3x single provider

        enrichment = EnrichmentData()
        errors: list[str] = []

        # Collect all indicators to look up
        ips = alert.get_all_ips()
        domains = alert.get_all_domains()
        hashes = alert.get_all_hashes()

        # Build task list
        tasks = []
        task_names = []

        # IP-based enrichment
        for ip in ips:
            tasks.append(self._safe_enrich(self.ip_reputation, ip, "ip"))
            task_names.append(f"ip_reputation:{ip}")
            tasks.append(self._safe_enrich(self.geo_ip, ip, "ip"))
            task_names.append(f"geo_ip:{ip}")
            tasks.append(self._safe_enrich(self.historical, ip, "ip"))
            task_names.append(f"historical:ip:{ip}")
            tasks.append(self._safe_enrich(self.asset_context, ip, "ip"))
            task_names.append(f"asset_context:{ip}")

        # Domain-based enrichment
        for domain in domains:
            tasks.append(self._safe_enrich(self.domain_intel, domain, "domain"))
            task_names.append(f"domain_intel:{domain}")

        # User-based historical lookup
        if alert.user and alert.user.username:
            tasks.append(self._safe_enrich(self.historical, alert.user.username, "user"))
            task_names.append(f"historical:user:{alert.user.username}")

        # Host-based lookups
        if alert.endpoint and alert.endpoint.hostname:
            tasks.append(self._safe_enrich(
                self.asset_context, alert.endpoint.hostname, "hostname"
            ))
            task_names.append(f"asset_context:host:{alert.endpoint.hostname}")
            tasks.append(self._safe_enrich(
                self.historical, alert.endpoint.hostname, "hostname"
            ))
            task_names.append(f"historical:host:{alert.endpoint.hostname}")

        if not tasks:
            logger.warning("No indicators to enrich")
            enrichment.enrichment_time_ms = (time.time() - start_time) * 1000
            return enrichment

        # Run all enrichment tasks in parallel with global timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=global_timeout,
            )
        except asyncio.TimeoutError:
            logger.error(f"Global enrichment timeout ({global_timeout}s)")
            results = [None] * len(tasks)
            errors.append(f"Global enrichment timeout after {global_timeout}s")

        # Process results
        for i, (name, result) in enumerate(zip(task_names, results)):
            if isinstance(result, Exception):
                error_msg = f"{name}: {type(result).__name__}: {result}"
                logger.warning(f"Enrichment error: {error_msg}")
                errors.append(error_msg)
                continue

            if result is None:
                continue

            try:
                self._process_result(name, result, enrichment)
            except Exception as e:
                errors.append(f"{name}: processing error: {e}")

        enrichment.enrichment_errors = errors
        enrichment.enrichment_time_ms = round((time.time() - start_time) * 1000, 2)

        logger.info(
            f"Enrichment complete: {len(enrichment.ip_reputation)} IP reps, "
            f"{len(enrichment.geo_ip)} geo, {len(enrichment.domain_intel)} domains, "
            f"{len(enrichment.historical_matches)} historical, "
            f"{len(enrichment.asset_context)} assets, "
            f"{len(errors)} errors, "
            f"{enrichment.enrichment_time_ms:.0f}ms"
        )

        return enrichment

    async def _safe_enrich(self, provider, indicator: str, indicator_type: str) -> dict | None:
        """Run a single enrichment with timeout and error handling."""
        try:
            return await asyncio.wait_for(
                provider.enrich(indicator, indicator_type),
                timeout=provider.timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"{provider.name} timeout after {provider.timeout_seconds}s")
        except Exception as e:
            raise RuntimeError(f"{provider.name} error: {e}") from e

    def _process_result(self, task_name: str, result: dict, enrichment: EnrichmentData) -> None:
        """Process a single enrichment result into the EnrichmentData structure."""
        if not result:
            return

        prefix = task_name.split(":")[0]

        if prefix == "ip_reputation":
            enrichment.ip_reputation.append(IPReputationData(**result))
        elif prefix == "geo_ip":
            enrichment.geo_ip.append(GeoIPData(**result))
        elif prefix == "domain_intel":
            enrichment.domain_intel.append(DomainIntelData(**result))
        elif prefix == "historical":
            matches = result.get("matches", [])
            for match_data in matches:
                enrichment.historical_matches.append(HistoricalMatch(**match_data))
        elif prefix == "asset_context":
            enrichment.asset_context.append(AssetContextData(**result))
