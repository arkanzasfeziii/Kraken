# Architecture

## Package Structure

```
kraken/
├── cli.py               # Argument parsing, module dispatch
├── config.py            # Tool metadata, legal warning
├── models.py            # AttackResult, Credential, EngagementContext
├── logger.py            # Colored terminal logging
├── output.py            # Banner, results, JSON export
├── exceptions.py        # Typed exceptions
│
├── modules/
│   ├── base.py          # BaseModule ABC
│   ├── enum.py          # K8s RBAC, namespace, pod, service enumeration
│   ├── secretdump.py    # Secret extraction and decoding
│   ├── escape.py        # Container escape techniques
│   ├── saabuse.py       # Service account token abuse
│   ├── cloudbridge.py   # IMDS credential harvest (EKS/AKS/GKE)
│   └── etcd.py          # Direct etcd access and secret extraction
│
├── utils/
│   └── helpers.py       # K8s connect, API raw, base64, secret scanner
│
└── data/
```

## Key Design

**K8s SDK + raw API fallback**: Modules use the kubernetes Python SDK when
available, with raw REST fallback via `k8s_api_raw()` for environments
where the SDK isn't installed.

**BaseModule ABC**: All modules implement `run(ctx, **kwargs) -> List[AttackResult]`.
Adding a new attack technique is one file + registration in MODULE_REGISTRY.
