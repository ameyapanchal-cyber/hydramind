"""gobuster module — brute-force directories/files on a web server."""
from __future__ import annotations
import re
from engine.runner import run_tool, ToolResult

# Default wordlist on Kali — exists at this path
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def run_gobuster(target: str, wordlist: str = DEFAULT_WORDLIST, timeout: int = 120):
    # Ensure target has http/https scheme
    if not target.startswith("http"):
        target = f"http://{target}"
    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", "20",          # 20 threads
        "-q",                # quiet — only results, no banner
        "--no-error",
    ]
    return run_tool(cmd, timeout=timeout)


def parse_gobuster(result: ToolResult) -> list[dict]:
    findings = []
    # Current gobuster: "docs    (Status: 301) [Size: 312] [--> http://.../docs/]"
    # Older versions include the leading slash — accept both.
    pattern = re.compile(
        r"^/?(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\]")
    for line in result.stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            path = m.group("path")
            if not path.startswith("/"):
                path = "/" + path
            findings.append({
                "path": path,
                "status": int(m.group("status")),
                "size": int(m.group("size")),
            })
    return findings
