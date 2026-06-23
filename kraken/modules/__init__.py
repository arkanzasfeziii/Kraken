"""Kubernetes and cloud native attack modules."""

from kraken.modules.enum import EnumModule
from kraken.modules.secretdump import SecretDumpModule
from kraken.modules.escape import EscapeModule
from kraken.modules.saabuse import SAAbuseModule
from kraken.modules.cloudbridge import CloudBridgeModule
from kraken.modules.etcd import EtcdModule

__all__ = [
    "EnumModule", "SecretDumpModule", "EscapeModule",
    "SAAbuseModule", "CloudBridgeModule", "EtcdModule",
]
