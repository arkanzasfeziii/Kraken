# Kraken — Kubernetes & Cloud Native Offensive Suite

> **Map every RBAC misconfiguration, drain every secret, escape the container, and bridge to the cloud metadata service — from a single compromised pod.**

---

## Threat Model

Kubernetes security failures are architectural, not incidental. The same features that make containers powerful — shared kernel access, mounted service account tokens, broad RBAC permissions — become the attack surface when misconfigured at scale.

Kraken models the attacker who starts inside a compromised workload and escalates to cluster-admin, then to cloud:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **Initial Recon** | No network policy between namespaces; API server accessible from workloads | Query Kubernetes API from inside pod; enumerate all namespaces, pods, services |
| **RBAC Misconfig** | Service account has `get/list` on secrets cluster-wide, or `create` on pods | Identify wildcard permissions; map privilege escalation paths to cluster-admin |
| **Secret Extraction** | Secrets stored as base64 in etcd without envelope encryption | Dump all secrets across namespaces, decode in-memory, scan for credential patterns |
| **Container Escape** | Pod runs as privileged, or mounts Docker socket, or has `CAP_SYS_ADMIN` | Escape to host via nsenter, Docker socket chroot, or cgroup release_agent |
| **Service Account Abuse** | Default service accounts with auto-mounted tokens and excessive RBAC permissions | Read mounted token from `/var/run/secrets/kubernetes.io/serviceaccount/token`, use against API |
| **Cloud Bridge** | EKS/AKS/GKE IMDS endpoints accessible from pod network | Query AWS, Azure, or GCP metadata service from within cluster — extract cloud IAM credentials |
| **Etcd Access** | Etcd exposed on port 2379 without TLS client authentication | Dump entire cluster state via v2 HTTP API or etcdctl — all secrets, configs, cluster state |

**Scope:** Authorized red team engagements against Kubernetes environments where the goal is to understand the blast radius of a single compromised container.

---

## Why This Exists

A compromised container is not an endpoint compromise. It is, potentially, a compromised Kubernetes cluster — which is potentially a compromised cloud account.

The gap between "attacker has code execution inside a pod" and "attacker has cluster-admin and AWS administrator credentials" is narrower than most organizations realize:

- Default service accounts auto-mount tokens with permissions scoped to cluster-wide secret access
- Privileged pods are deployed for "operational convenience" without understanding the host access they grant
- RBAC roles accumulate wildcard permissions as teams add capabilities without reviewing existing grants
- etcd runs on port 2379 on control-plane nodes — accessible if network policies don't explicitly block it
- IMDSv1 on EKS nodes responds to HTTP requests from any pod that can reach the node IP

Kraken chains these misconfigurations. It doesn't report that a privileged pod exists — it demonstrates what an attacker does with it.

---

## Capabilities

### Cluster Enumeration
- **Cluster version** fingerprinting via `/version` API — flags known vulnerable releases
- **Namespace enumeration** — flags sensitive namespace names: `prod`, `payment`, `finance`, `database`
- **Pod enumeration** — detects `hostPID`, `hostNetwork`, privileged security contexts, and pods running as root across all namespaces
- **Service exposure** — lists all `LoadBalancer` and `NodePort` services with external IP bindings
- **RBAC analysis** — enumerates all ClusterRoleBindings; flags `cluster-admin` assignments; detects wildcard roles (`*` on verbs or resources); checks 7 known privilege escalation paths via `RBAC_PRIVESC_PATHS`
- **Self-permission check** — evaluates the compromised service account's own permissions against dangerous verb/resource combinations
- **Service account enumeration** — lists all service accounts and their RBAC bindings per namespace

### Secret Extraction
- **Kubernetes Secrets dump** — lists all secrets across all namespaces; base64-decodes values in-memory; scans decoded content for credential patterns (AWS keys, tokens, API keys, passwords, connection strings)
- **Service account token identification** — flags `kubernetes.io/service-account-token` type secrets
- **ConfigMap scanning** — searches ConfigMaps for keys/values matching credential patterns (passwords, endpoints, tokens)

### Container Escape Techniques

Kraken evaluates five escape paths against the current pod's configuration:

| Technique | Condition | Method |
|---|---|---|
| **Privileged Container** | `securityContext.privileged: true` | `nsenter --mount=/proc/1/ns/mnt -- chroot /host` |
| **Docker Socket Mount** | `/var/run/docker.sock` mounted | `docker run --rm -v /:/host alpine chroot /host` |
| **HostPath Root Mount** | `/` or `/host` mounted from node | `chroot /host` — full host filesystem access |
| **HostPID Namespace** | `hostPID: true` | `nsenter -t 1 -m -u -i -n -p` — enter PID 1 namespace |
| **cgroup v1 Release Agent** | Writable `/sys/fs/cgroup/*/release_agent` | Write payload to release_agent — CVE-2022-0492 variant |

Also checks capabilities: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN` — each enabling different escape or pivot paths.

### Service Account Token Abuse
- **Mounted token extraction** — reads `/var/run/secrets/kubernetes.io/serviceaccount/token` from current pod
- **Cross-namespace token theft** — enumerates and extracts service account tokens from all accessible namespaces
- **Admin binding check** — tests each harvested token against RBAC to identify tokens with `cluster-admin` or privileged bindings
- **TokenRequest API** — requests short-lived tokens for additional service accounts via the TokenRequest API

### Cloud Bridge — IMDS Lateral Movement

From inside the cluster pod network, probe managed Kubernetes cloud metadata services:

| Cloud | Endpoint | What's Extracted |
|---|---|---|
| **AWS EKS** | `169.254.169.254/latest/meta-data/iam/security-credentials/` | IAM role name → `AccessKeyId`, `SecretAccessKey`, `Token` |
| **Azure AKS** | `169.254.169.254/metadata/identity/oauth2/token` | Managed identity OAuth2 access token |
| **GCP GKE** | `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | GCP service account bearer token |
| **GCP GKE** | `metadata.google.internal/computeMetadata/v1/project/project-id` | GCP project identifier |

### Etcd Direct Access
- **Port check** — detects etcd on port 2379 on the API server host
- **Unauthenticated v2 HTTP API** — dumps all keys via `/v2/keys/?recursive=true` — returns full cluster state without credentials if TLS client auth is disabled
- **etcdctl v3** — executes `etcdctl get --prefix="" --keys-only` and full key dump with optional cert directory

---

## Architecture

```
Target (kubeconfig · API host · in-cluster token)
                    │
                    ▼
         EngagementContext
  ┌──────────────────────────────────────┐
  │  api_host · api_port · token         │
  │  kubeconfig · namespace              │
  │  K8s Core / RBAC / Apps / Batch API  │
  └──────────────────────────────────────┘
                    │
      ┌─────────────┼──────────────┐
      ▼             ▼              ▼
  EnumModule   SecretDump     EscapeModule
  RBAC+pods    K8s Secrets    5 escape paths
  namespaces   ConfigMaps     capability check
      │
      ├─────────────────────────┐
      ▼                         ▼
  SAAbuseModule          CloudBridgeModule
  token theft            AWS/Azure/GCP IMDS
  cross-ns abuse         credential harvest
                              │
                              ▼
                        EtcdModule
                    direct etcd dump
                              │
                              ▼
                       JSON Report
              (namespace · finding · severity)
```

---

## Attack Flow

1. **API discovery** — connect to Kubernetes API using provided kubeconfig, bearer token, or auto-detected in-cluster token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. **Cluster enumeration** — fingerprint the cluster version; enumerate all namespaces (flag sensitive names); list pods with security context analysis; identify exposed services and RBAC misconfigurations
3. **RBAC privilege escalation mapping** — evaluate current service account permissions against `RBAC_PRIVESC_PATHS`; flag any account with paths to cluster-admin escalation
4. **Secret extraction** — dump all secrets across all namespaces; base64-decode values in-memory; run credential pattern scanning across all decoded content
5. **Escape evaluation** — check pod's security context for privileged flag, `hostPID`, mounted Docker socket, HostPath mounts, and writable cgroup release_agent; report which escapes are feasible and provide the exact command to execute them
6. **Token harvesting** — extract all accessible service account tokens across namespaces; test each against RBAC to identify tokens with admin-level permissions
7. **Cloud bridge** — probe AWS, Azure, and GCP IMDS endpoints from inside the cluster network; extract cloud credentials if IMDS is reachable
8. **Etcd sweep** — attempt unauthenticated access to etcd port 2379; dump cluster state if accessible
9. **Report** — `--output report.json` with full finding list, severity, and recommended remediation per namespace

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Enumerate cluster from external kubeconfig
python kraken.py --kubeconfig ~/.kube/config --modules enum

# Dump and decode all Kubernetes secrets
python kraken.py --kubeconfig ~/.kube/config --modules secrets

# Check container escape paths (run from inside a pod)
python kraken.py --modules escape

# Enumerate and abuse service account tokens
python kraken.py --kubeconfig ~/.kube/config --modules sa

# Probe IMDS endpoints (from inside cluster network)
python kraken.py --modules cloud

# Direct etcd access check
python kraken.py --api-host 10.96.0.1 --modules etcd

# Full engagement chain
python kraken.py --kubeconfig ~/.kube/config --modules all --output kraken-findings.json

# Non-interactive mode
python kraken.py --kubeconfig ~/.kube/config --modules all --yes --output results.json
```

---

## Output

```
15:11:04 [INFO]  [Enum] Kubernetes v1.27.3 | API: https://10.96.0.1:6443
15:11:05 [WARN]  [Enum] Sensitive namespace detected: prod, payment, database
15:11:05 [CRIT]  [Enum/Pods] Privileged pod: api-gateway (namespace: prod)
15:11:05 [CRIT]  [Enum/Pods] hostPID=true: log-collector (namespace: monitoring)
15:11:06 [CRIT]  [Enum/RBAC] cluster-admin binding: system:serviceaccount:default:api-sa
15:11:06 [CRIT]  [Enum/RBAC] Wildcard role: ci-runner (verbs: * resources: *)
15:11:06 [CRIT]  [Enum/RBAC] PrivEsc path: create pods → pod exec → cluster-admin

15:11:07 [CRIT]  [Secrets] 84 secrets decoded across 6 namespaces
15:11:07 [CRIT]  [Secrets] AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE (namespace: prod)
15:11:07 [CRIT]  [Secrets] DB_PASSWORD: supersecret123 (namespace: database)
15:11:07 [CRIT]  [Secrets] SA token: system:serviceaccount:kube-system:default

15:11:08 [CRIT]  [Escape] Privileged container confirmed — escape feasible
15:11:08 [INFO]  [Escape] Command: nsenter --mount=/proc/1/ns/mnt -- chroot /host /bin/bash
15:11:08 [CRIT]  [Escape] CAP_SYS_ADMIN capability present — additional escape paths available

15:11:09 [CRIT]  [Cloud/AWS] IMDS reachable — role: eks-node-role
15:11:09 [CRIT]  [Cloud/AWS] Credentials extracted: AccessKeyId=ASIA..., Expiration=+1h

15:11:10 [CRIT]  [Etcd] Port 2379 open — attempting unauthenticated dump
15:11:10 [CRIT]  [Etcd] Unauthenticated access — full cluster state exposed (3,847 keys)

[✓] Cluster audit complete — 11 critical findings | report: kraken-findings.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module |
|---|---|---|
| Container and Resource Discovery | T1613 | EnumModule |
| Unsecured Credentials: Container API | T1552.007 | SecretDumpModule, SAAbuseModule |
| Escape to Host | T1611 | EscapeModule |
| Valid Accounts: Cloud Accounts | T1078.004 | CloudBridgeModule |
| Exploit Public-Facing Application | T1190 | EtcdModule |
| Steal Application Access Token | T1528 | SAAbuseModule |
| Account Discovery | T1087 | EnumModule / RBAC |

**Tactics:** TA0007 Discovery · TA0006 Credential Access · TA0004 Privilege Escalation · TA0008 Lateral Movement

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-732 | Incorrect Permission Assignment for Critical Resource | RBAC wildcard roles, cluster-admin bindings |
| CWE-200 | Exposure of Sensitive Information | etcd unauthenticated access, IMDS without enforcement |
| CWE-250 | Execution with Unnecessary Privileges | Privileged pod, CAP_SYS_ADMIN grants |
| CWE-306 | Missing Authentication for Critical Function | etcd v2 HTTP API, IMDS endpoints |
| CWE-522 | Insufficiently Protected Credentials | Kubernetes Secrets base64 encoding only |
| CWE-269 | Improper Privilege Management | RBAC privilege escalation paths |

---

## Legal Notice

Kraken is designed exclusively for authorized penetration testing and security assessment activities where explicit written permission has been obtained from the asset owner. Unauthorized testing of Kubernetes clusters or cloud environments is illegal and may expose confidential infrastructure data. The author assumes no liability for misuse.
