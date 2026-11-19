"""hydra module — credential brute-force (lab-only, human-approved).

hydra stays interactive-free; the pipeline never supplies wordlists itself,
the Reasoner must reference one under /usr/share/wordlists (Kali paths are
allowed by validate_action).
"""
from __future__ import annotations
import re
from engine.runner import run_tool

# file output / module-file flags: not useful for a probe, easily abused
BLOCKED_FLAGS = {"-o", "-M", "-I"}

CRED_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<proto>[\w-]+)\]\s+host:\s*(?P<host>\S+)\s+"
    r"login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)")


def run_hydra(args: list[str], timeout: int = 300):
    return run_tool(["hydra"] + list(args), timeout=timeout)


def parse_hydra(result) -> list[dict]:
    out = result.stdout or ""
    findings = []
    for m in CRED_RE.finditer(out):
        findings.append({
            "title": f"Valid credentials: {m['login']}:{m['password']} "
                     f"({m['proto']}/{m['port']})",
            "detail": f"{m['proto']} on {m['host']}:{m['port']} accepted "
                      f"{m['login']}:{m['password']}",
            "evidence": m.group(0)[:300],
        })
    return findings
