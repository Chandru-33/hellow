"""Base scanner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from devsecops.core.models import Finding, ScanContext


class BaseScanner(ABC):
    """Abstract base for all scanners."""

    name: str = "base"

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Run scan and return findings."""

    def is_enabled(self, context: ScanContext) -> bool:
        scanners = context.config.get("scanners", {})
        key = self.config_key
        return scanners.get(key, True)

    @property
    def config_key(self) -> str:
        return self.name
