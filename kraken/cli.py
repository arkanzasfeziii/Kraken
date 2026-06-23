"""Command-line interface for Kraken."""

from __future__ import annotations

import argparse
import textwrap

from kraken.config import COMMAND, TOOL_NAME, VERSION
from kraken.logger import log
from kraken.models import EngagementContext
from kraken.modules import (
    CloudBridgeModule, EnumModule, EscapeModule,
    EtcdModule, SAAbuseModule, SecretDumpModule,
)
from kraken.output import dump_results, print_banner, print_legal

MODULE_REGISTRY = {
    "enum": (EnumModule, lambda a: {}),
    "secret-dump": (SecretDumpModule, lambda a: {}),
    "escape": (EscapeModule, lambda a: {}),
    "sa-abuse": (SAAbuseModule, lambda a: {"target_sa": a.target_sa}),
    "cloud-bridge": (CloudBridgeModule, lambda a: {}),
    "etcd": (EtcdModule, lambda a: {"etcd_host": a.etcd_host, "cert_dir": a.cert_dir}),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --modules enum
              {COMMAND} --kubeconfig ~/.kube/config --modules enum
              {COMMAND} --api-host 10.0.0.1 --token TOKEN --modules secret-dump
              {COMMAND} --modules escape
              {COMMAND} --modules sa-abuse --target-sa default
              {COMMAND} --modules cloud-bridge
              {COMMAND} --etcd-host 10.0.0.1 --modules etcd
              {COMMAND} --modules all --output loot.json
        """),
    )
    p.add_argument("--api-host", default="")
    p.add_argument("--api-port", type=int, default=6443)
    p.add_argument("--token", default="")
    p.add_argument("--kubeconfig", default="")
    p.add_argument("--namespace", default="default")
    p.add_argument("--etcd-host", default="")
    p.add_argument("--cert-dir", default="")
    p.add_argument("--target-sa", default="")
    p.add_argument("--modules", nargs="+",
                   choices=["enum", "secret-dump", "escape", "sa-abuse", "cloud-bridge", "etcd", "all"],
                   default=["enum"])
    p.add_argument("--output", "-o", help="Save results to JSON")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    if not print_legal(args.yes):
        return 1

    ctx = EngagementContext(
        api_host=args.api_host, api_port=args.api_port,
        token=args.token, kubeconfig=args.kubeconfig,
        namespace=args.namespace,
    )

    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        entry = MODULE_REGISTRY.get(mod_name)
        if not entry:
            continue
        mod_cls, kwargs_fn = entry
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            results = mod.run(ctx, **kwargs_fn(args))
            ctx.results.extend(results)
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0
