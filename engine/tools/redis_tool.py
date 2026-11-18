"""redis-cli module — unauthenticated Redis checks/exploitation (lab-only).

Destructive commands are refused: they would wipe the lab target or the
evidence mid-engagement, which is the opposite of getting results.
"""
from __future__ import annotations
from engine.runner import run_tool

BLOCKED_COMMANDS = {"FLUSHALL", "FLUSHDB", "SHUTDOWN", "DEBUG", "SLAVEOF",
                    "REPLICAOF"}


def run_redis(args: list[str], timeout: int = 30):
    return run_tool(["redis-cli"] + list(args), timeout=timeout)


def parse_redis(result) -> list[dict]:
    out = (result.stdout or "").strip()
    findings = []
    if out.upper() == "PONG":
        findings.append({
            "title": "Redis unauthenticated (PONG)",
            "detail": "redis-cli PING answered without credentials",
            "evidence": out[:200],
        })
    if "redis_version" in out:
        version = ""
        for line in out.splitlines():
            if line.startswith("redis_version:"):
                version = line.split(":", 1)[1].strip()
        findings.append({
            "title": f"Redis {version} INFO exposed unauthenticated".strip(),
            "detail": "full INFO output readable without authentication",
            "evidence": out[:500],
        })
    return findings
