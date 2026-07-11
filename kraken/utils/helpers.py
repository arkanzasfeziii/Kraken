"""Shared helper functions for Kubernetes operations."""

from __future__ import annotations

import base64
import re
from typing import Any

from kraken.logger import log
from kraken.models import EngagementContext

try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config

    K8S_SDK = True
except ImportError:
    K8S_SDK = False

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
    (r"(?i)aws.{0,20}secret.{0,10}['\"][0-9a-zA-Z/+]{40}", "AWS_SECRET"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_API_KEY"),
    (r"ghp_[0-9a-zA-Z]{36}", "GITHUB_PAT"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{8,}", "PASSWORD"),
    (r"(?i)(secret|token|api_key)\s*[=:]\s*['\"][^\s'\"]{16,}", "SECRET"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "PRIVATE_KEY"),
    (r"(?i)connection_?string\s*[=:]\s*['\"][^\s'\"]{20,}", "CONNECTION_STRING"),
]


def b64d(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return s


def scan_for_secrets(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, text, re.MULTILINE):
            val = m.group(0) if not m.groups() else m.group(1)
            found.append({"type": label, "value": val[:200]})
    return found


def k8s_connect(ctx: EngagementContext) -> bool:
    if not K8S_SDK:
        log("Install kubernetes: pip install kubernetes", "ERR")
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
            try:
                k8s_config.load_incluster_config()
                log("[K8s] Using in-cluster config (running inside pod)", "INFO")
            except Exception:
                k8s_config.load_kube_config()

        ctx.k8s_core = k8s_client.CoreV1Api()
        ctx.k8s_rbac = k8s_client.RbacAuthorizationV1Api()
        ctx.k8s_apps = k8s_client.AppsV1Api()
        ctx.k8s_batch = k8s_client.BatchV1Api()
        ctx.k8s_core.list_namespace()
        log("Connected to Kubernetes cluster", "OK")
        return True
    except Exception as exc:
        log(f"K8s connect failed: {exc}", "ERR")
        return False


def k8s_api_raw(ctx: EngagementContext, path: str, method: str = "GET", body: Any = None) -> dict | None:
    if not HAS_REQUESTS:
        return None
    url = f"https://{ctx.api_host}:{ctx.api_port}{path}"
    hdrs = {"Authorization": f"Bearer {ctx.token}", "Content-Type": "application/json"}
    try:
        resp = requests.request(method, url, headers=hdrs, json=body, verify=False, timeout=10)
        return resp.json() if resp.text else {}
    except Exception:
        return None
