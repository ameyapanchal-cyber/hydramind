"""gobuster module — brute-force directories/files on a web server."""
from __future__ import annotations
import random
import re
import string
import urllib.request
from engine.runner import run_tool, ToolResult

# Default wordlist on Kali — exists at this path
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def _wildcard_length(target: str) -> int | None:
    """SPA catch-alls (e.g. Juice Shop) answer 200 for every path, which makes
    gobuster abort. Probe a random path; if it is 200, return its body length
    so gobuster can exclude it."""
    probe = target.rstrip("/") + "/" + "".join(
        random.choices(string.ascii_lowercase, k=16))
    try:
        with urllib.request.urlopen(probe, timeout=5) as resp:
            if resp.status != 200:
                return None
            length = resp.headers.get("Content-Length")
            return int(length) if length is not None else len(resp.read())
    except Exception:
        return None


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
    wildcard = _wildcard_length(target)
    if wildcard is not None:
        cmd += ["--exclude-length", str(wildcard)]
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
