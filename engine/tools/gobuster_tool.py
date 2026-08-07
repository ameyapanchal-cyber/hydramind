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
    # Lines look like: /admin                (Status: 200) [Size: 1234]
    pattern = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]")
    for line in result.stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            findings.append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)),
            })
    return findings
