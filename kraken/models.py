"""Data models used across all Kraken modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    target: str = ""
    data: Any = None
    severity: str = "INFO"
    notes: str = ""


@dataclass
class Credential:
    type: str
    value: dict[str, str]
    source: str
    notes: str = ""


@dataclass
class EngagementContext:
    api_host: str = ""
    api_port: int = 6443
    token: str = ""
    kubeconfig: str = ""
    namespace: str = "default"
    results: list[AttackResult] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    loot: dict[str, Any] = field(default_factory=dict)
    k8s_core: Any = None
    k8s_rbac: Any = None
    k8s_apps: Any = None
    k8s_batch: Any = None
    delay: float = 0.2
