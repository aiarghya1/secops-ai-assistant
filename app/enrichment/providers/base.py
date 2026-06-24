"""
SecOps AI Assistant — Enrichment Provider Base

Abstract base class for all enrichment providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseEnrichmentProvider(ABC):
    """Base class for enrichment data providers."""

    name: str = "base"
    timeout_seconds: float = 5.0

    @abstractmethod
    async def enrich(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        """
        Enrich a single indicator.

        Args:
            indicator: The value to look up (IP, domain, hash, etc.)
            indicator_type: Type of indicator: 'ip', 'domain', 'hash', 'url'

        Returns:
            Dictionary of enrichment data.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured and available."""
        ...
