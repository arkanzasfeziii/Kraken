"""Custom exception hierarchy for Kraken."""

from __future__ import annotations


class KrakenError(Exception):
    """Base exception for all Kraken errors."""


class ModuleError(KrakenError):
    """Raised when a module encounters a runtime error."""


class ClusterConnectionError(KrakenError):
    """Raised when connection to K8s API fails."""


class DependencyError(KrakenError):
    """Raised when a required dependency is missing."""

    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
        self.package = package
