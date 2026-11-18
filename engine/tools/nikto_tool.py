"""nikto module — web server misconfiguration and vuln scanner."""
from __future__ import annotations
from engine.runner import run_tool, ToolResult


def run_nikto(target: str, timeout: int = 180):
    if not target.startswith("http"):
        target = f"http://{target}"
    # no -Format: plain text goes to stdout; -Format would make nikto write
    # nikto_*.txt files into the working directory as a side effect
    cmd = ["nikto", "-h", target, "-nointeractive"]
    return run_tool(cmd, timeout=timeout)


def parse_nikto(result: ToolResult) -> list[dict]:
    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Nikto findings start with "+ ". Skip OSVDB refs and failure/error
        # notices (e.g. "+ [FAIL] Unable to connect to host:port") — those
        # are not findings.
        if not line.startswith("+ ") or line == "+" or "OSVDB" in line:
            continue
        if line[2:].startswith(("[FAIL]", "[ERROR]")):
            continue
        findings.append({"finding": line[2:]})
    return findings
