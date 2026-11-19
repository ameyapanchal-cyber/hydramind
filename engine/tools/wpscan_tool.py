"""wpscan module — WordPress enumeration/vulnerability scanning (lab-only)."""
from __future__ import annotations
from engine.runner import run_tool

BLOCKED_FLAGS = {"-o", "--output"}


def run_wpscan(url: str, extra: list[str] | None = None, timeout: int = 600):
    cmd = ["wpscan", "--url", url, "--no-banner", "--no-color"]
    if extra:
        cmd += [a for a in extra if a not in cmd]
    return run_tool(cmd, timeout=timeout)


def parse_wpscan(result) -> list[dict]:
    out = result.stdout or ""
    findings = []
    for line in out.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if "vulnerab" in low or low.startswith("[!]"):
            findings.append({
                "title": stripped[:120],
                "detail": stripped,
                "evidence": stripped[:400],
            })
        elif "wordpress version" in low:
            findings.append({
                "title": stripped[:120],
                "detail": "WordPress version identified",
                "evidence": stripped[:400],
            })
    return findings
