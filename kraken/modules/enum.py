"""Enumerate namespaces, pods, services, RBAC, and identify attack surface."""

from __future__ import annotations

from typing import Any, Dict, List

from kraken.models import AttackResult, EngagementContext
from kraken.logger import log
from kraken.modules.base import BaseModule
from kraken.utils.helpers import k8s_connect

try:
    from kubernetes import client as k8s_client
    from kubernetes.client.rest import ApiException
except ImportError:
    k8s_client = None  # type: ignore[assignment,misc]
    ApiException = Exception  # type: ignore[assignment,misc]

# Privilege escalation RBAC paths checked against current identity
RBAC_PRIVESC_PATHS = [
    ("pods/exec",      "exec",        "Exec into any pod — lateral movement / code execution"),
    ("pods",           "create",      "Create pods with privileged specs or hostPath mounts"),
    ("secrets",        "get",         "Read all secrets including service account tokens"),
    ("clusterroles",   "bind",        "Bind ClusterRoleBinding → escalate to cluster-admin"),
    ("serviceaccounts","impersonate", "Impersonate any SA → assume its RBAC permissions"),
    ("nodes",          "create",      "Create node objects → join fake node, get secrets"),
    ("pods",           "patch",       "Patch running pod to add volume mounts or env vars"),
]


class EnumModule(BaseModule):
    """Enumerate namespaces, pods, services, RBAC, and identify attack surface."""

    name = "enum"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        if not k8s_connect(ctx):
            return [AttackResult("enum", "connect", "FAILED",
                                 notes="Cannot connect. Check --token, --kubeconfig, or in-cluster")]
        results: List[AttackResult] = []
        results.extend(self._enum_cluster_info(ctx))
        results.extend(self._enum_namespaces(ctx))
        results.extend(self._enum_pods(ctx))
        results.extend(self._enum_services(ctx))
        results.extend(self._enum_rbac(ctx))
        results.extend(self._find_privileged_pods(ctx))
        results.extend(self._enum_service_accounts(ctx))
        return results

    # ── cluster info ──────────────────────────────────────────────────────────

    def _enum_cluster_info(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            version_api = k8s_client.VersionApi()
            ver = version_api.get_code()
            info = {"version": ver.git_version, "platform": ver.platform}
            ctx.loot["cluster_version"] = info
            log(f"[Enum] Cluster version: {ver.git_version} | Platform: {ver.platform}", "INFO")
            return [AttackResult("enum", "cluster_info", "INFO", data=info,
                                 notes=f"K8s {ver.git_version} on {ver.platform}")]
        except Exception as exc:
            return [AttackResult("enum", "cluster_info", "FAILED", notes=str(exc))]

    # ── namespaces ────────────────────────────────────────────────────────────

    def _enum_namespaces(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            ns_list = ctx.k8s_core.list_namespace()
            namespaces = [ns.metadata.name for ns in ns_list.items]
            ctx.loot["namespaces"] = namespaces
            log(f"[Enum] Namespaces: {namespaces}", "INFO")
            sensitive = [n for n in namespaces if any(
                kw in n.lower() for kw in ["prod", "production", "payment", "finance", "secret", "cred"])]
            if sensitive:
                log(f"[Enum] Sensitive namespaces: {sensitive}", "WARN")
            return [AttackResult("enum", "namespaces", "INFO",
                                 data={"count": len(namespaces), "namespaces": namespaces,
                                       "sensitive": sensitive},
                                 severity="HIGH" if sensitive else "INFO",
                                 notes=f"{len(namespaces)} namespaces. Sensitive: {sensitive}")]
        except ApiException as exc:
            return [AttackResult("enum", "namespaces", "FAILED", notes=str(exc))]

    # ── pods ──────────────────────────────────────────────────────────────────

    def _enum_pods(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            pods_all = ctx.k8s_core.list_pod_for_all_namespaces()
            pods: List[Dict[str, Any]] = []
            for pod in pods_all.items:
                pod_info: Dict[str, Any] = {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "node": pod.spec.node_name,
                    "status": pod.status.phase,
                    "containers": [c.name for c in (pod.spec.containers or [])],
                    "images": [c.image for c in (pod.spec.containers or [])],
                    "host_pid": pod.spec.host_pid or False,
                    "host_network": pod.spec.host_network or False,
                    "service_account": pod.spec.service_account_name,
                }
                pods.append(pod_info)
            ctx.loot["pods"] = pods
            log(f"[Enum] {len(pods)} pods across all namespaces", "INFO")
            return [AttackResult("enum", "pods", "INFO",
                                 data={"count": len(pods), "pods": pods[:20]},
                                 notes=f"{len(pods)} pods enumerated")]
        except ApiException as exc:
            return [AttackResult("enum", "pods", "FAILED", notes=str(exc))]

    # ── services ──────────────────────────────────────────────────────────────

    def _enum_services(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            svc_all = ctx.k8s_core.list_service_for_all_namespaces()
            services: List[Dict[str, Any]] = []
            exposed: List[Dict[str, Any]] = []
            for svc in svc_all.items:
                svc_info: Dict[str, Any] = {
                    "name": svc.metadata.name,
                    "namespace": svc.metadata.namespace,
                    "type": svc.spec.type,
                    "cluster_ip": svc.spec.cluster_ip,
                    "ports": [(p.port, p.protocol) for p in (svc.spec.ports or [])],
                    "external_ip": [str(i.ip) for i in (svc.status.load_balancer.ingress or [])]
                    if svc.status.load_balancer and svc.status.load_balancer.ingress else [],
                }
                services.append(svc_info)
                if svc.spec.type in ("LoadBalancer", "NodePort"):
                    exposed.append(svc_info)
            ctx.loot["services"] = services
            if exposed:
                log(f"[Enum] Externally exposed services: {[s['name'] for s in exposed]}", "WARN")
            return [AttackResult("enum", "services", "INFO",
                                 data={"count": len(services), "exposed": exposed},
                                 severity="MEDIUM" if exposed else "INFO",
                                 notes=f"{len(services)} services, {len(exposed)} externally exposed")]
        except ApiException as exc:
            return [AttackResult("enum", "services", "FAILED", notes=str(exc))]

    # ── RBAC ──────────────────────────────────────────────────────────────────

    def _enum_rbac(self, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        priv_bindings: List[Dict[str, Any]] = []
        wildcard_roles: List[Dict[str, Any]] = []
        try:
            crbs = ctx.k8s_rbac.list_cluster_role_binding()
            for crb in crbs.items:
                role_name = crb.role_ref.name
                subjects = crb.subjects or []
                for subj in subjects:
                    if subj.kind in ("ServiceAccount", "User", "Group"):
                        # Check if cluster-admin or wildcard
                        if role_name == "cluster-admin":
                            priv_bindings.append({
                                "binding": crb.metadata.name,
                                "role": role_name,
                                "subject": f"{subj.kind}/{subj.name}",
                                "namespace": getattr(subj, "namespace", ""),
                            })
                            log(f"[Enum/RBAC] cluster-admin: {subj.kind}/{subj.name}", "CRIT")
            # Check cluster roles for wildcards
            crs = ctx.k8s_rbac.list_cluster_role()
            for cr in crs.items:
                for rule in (cr.rules or []):
                    verbs = set(rule.verbs or [])
                    resources = set(rule.resources or [])
                    if "*" in verbs and "*" in resources:
                        wildcard_roles.append({"role": cr.metadata.name,
                                               "verbs": list(verbs),
                                               "resources": list(resources)})

            ctx.loot["rbac"] = {"cluster_admin_bindings": priv_bindings,
                                 "wildcard_roles": wildcard_roles}
            results.append(AttackResult(
                "enum", "rbac", "SUCCESS" if priv_bindings else "INFO",
                severity="CRITICAL" if priv_bindings else "INFO",
                data={"cluster_admin_subjects": len(priv_bindings),
                      "wildcard_roles": len(wildcard_roles)},
                notes=f"{len(priv_bindings)} cluster-admin bindings, {len(wildcard_roles)} wildcard roles",
            ))

            # Check dangerous permissions for current SA
            results.extend(self._check_own_perms(ctx))
        except ApiException as exc:
            results.append(AttackResult("enum", "rbac", "FAILED", notes=str(exc)))
        return results

    def _check_own_perms(self, ctx: EngagementContext) -> List[AttackResult]:
        """Check if current SA/user has dangerous permissions."""
        dangerous: List[Dict[str, str]] = []
        auth_api = k8s_client.AuthorizationV1Api()
        for resource, verb, desc in RBAC_PRIVESC_PATHS:
            try:
                body = k8s_client.V1SelfSubjectAccessReview(
                    spec=k8s_client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=k8s_client.V1ResourceAttributes(
                            verb=verb, resource=resource, namespace="default"
                        )
                    )
                )
                resp = auth_api.create_self_subject_access_review(body)
                if resp.status.allowed:
                    dangerous.append({"resource": resource, "verb": verb, "desc": desc})
                    log(f"[Enum/RBAC] CAN {verb} {resource}: {desc}", "CRIT")
            except Exception:
                pass
        if dangerous:
            ctx.loot["own_dangerous_perms"] = dangerous
            return [AttackResult("enum", "own_permissions", "SUCCESS",
                                 severity="CRITICAL",
                                 data=dangerous,
                                 notes=f"Current identity has {len(dangerous)} dangerous permissions!")]
        return [AttackResult("enum", "own_permissions", "INFO",
                             notes="No obvious dangerous RBAC permissions for current identity")]

    # ── privileged pods ───────────────────────────────────────────────────────

    def _find_privileged_pods(self, ctx: EngagementContext) -> List[AttackResult]:
        privileged_pods: List[Dict[str, Any]] = []
        for pod_info in ctx.loot.get("pods", []):
            if pod_info.get("host_pid") or pod_info.get("host_network"):
                privileged_pods.append(pod_info)
                log(f"[Enum] Privileged pod: {pod_info['name']} in {pod_info['namespace']}", "WARN")
        # Also check spec for security context
        try:
            pods_all = ctx.k8s_core.list_pod_for_all_namespaces()
            for pod in pods_all.items:
                for c in (pod.spec.containers or []):
                    sc = c.security_context
                    if sc and (sc.privileged or sc.run_as_user == 0 or sc.allow_privilege_escalation):
                        privileged_pods.append({
                            "name": pod.metadata.name,
                            "namespace": pod.metadata.namespace,
                            "container": c.name,
                            "privileged": sc.privileged,
                            "run_as_root": sc.run_as_user == 0,
                        })
                        log(f"[Enum] Privileged container: {pod.metadata.namespace}/{pod.metadata.name}/{c.name}", "CRIT")
        except Exception:
            pass
        ctx.loot["privileged_pods"] = privileged_pods
        return [AttackResult("enum", "privileged_pods",
                             "SUCCESS" if privileged_pods else "INFO",
                             severity="CRITICAL" if privileged_pods else "INFO",
                             data=privileged_pods,
                             notes=f"{len(privileged_pods)} privileged pods/containers — escape candidates")]

    # ── service accounts ──────────────────────────────────────────────────────

    def _enum_service_accounts(self, ctx: EngagementContext) -> List[AttackResult]:
        sa_tokens: List[Dict[str, Any]] = []
        try:
            for ns in ctx.loot.get("namespaces", ["default"]):
                sas = ctx.k8s_core.list_namespaced_service_account(namespace=ns)
                for sa in sas.items:
                    sa_tokens.append({
                        "name": sa.metadata.name,
                        "namespace": ns,
                        "secrets": [s.name for s in (sa.secrets or [])],
                    })
        except Exception:
            pass
        ctx.loot["service_accounts"] = sa_tokens
        return [AttackResult("enum", "service_accounts", "INFO",
                             data={"count": len(sa_tokens)},
                             notes=f"{len(sa_tokens)} service accounts enumerated")]
