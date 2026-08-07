"""nikto module — web server misconfiguration and vuln scanner."""
from __future__ import annotations
from engine.runner import run_tool, ToolResult


def run_nikto(target: str, timeout: int = 180):
    if not target.startswith("http"):
        target = f"http://{target}"
    cmd = ["nikto", "-h", target, "-nointeractive", "-Format", "txt"]
    return run_tool(cmd, timeout=timeout)


def parse_nikto(result: ToolResult) -> list[dict]:
    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Nikto findings start with "+ "
        if line.startswith("+ ") and "OSVDB" not in line and line != "+":
            findings.append({"finding": line[2:]})
    return findings
