"""Colored logging for terminal output."""

from __future__ import annotations

from datetime import datetime, timezone

_COLORS = {
    "INFO": "\033[36m",
    "OK": "\033[32m",
    "WARN": "\033[33m",
    "ERR": "\033[31m",
    "CRIT": "\033[35m",
}
_RESET = "\033[0m"


def log(msg: str, level: str = "INFO") -> None:
    color = _COLORS.get(level, "")
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{color}{ts} [{level}] {msg}{_RESET}")
