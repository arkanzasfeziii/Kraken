"""Constants and configuration for Kraken."""

from __future__ import annotations

from kraken import __author__, __version__

TOOL_NAME = "Kraken Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "kraken"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║        ⚠   KRAKEN — AUTHORIZED RED TEAM USE ONLY   ⚠                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL Kubernetes attacks: RBAC enumeration,         ║
║  secret extraction, container escape, service account abuse, IMDS           ║
║  credential harvest, and etcd direct access.                                ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the cluster owner                           ║
║    ✓ Defined scope (clusters / namespaces / registries)                     ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
