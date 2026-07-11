"""Kubernetes and cloud native attack modules."""

from kraken.modules.cloudbridge import CloudBridgeModule
from kraken.modules.enum import EnumModule
from kraken.modules.escape import EscapeModule
from kraken.modules.etcd import EtcdModule
from kraken.modules.saabuse import SAAbuseModule
from kraken.modules.secretdump import SecretDumpModule

__all__ = [
    "EnumModule",
    "SecretDumpModule",
    "EscapeModule",
    "SAAbuseModule",
    "CloudBridgeModule",
    "EtcdModule",
]
