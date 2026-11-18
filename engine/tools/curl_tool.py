"""curl module — fetch URLs/files and deliver HTTP requests (in-scope only).

Covers the actions the Reasoner needs that nikto cannot do: reading an exposed
file (php.ini, robots.txt, /etc/passwd via CVE-2021-41773 traversal) and
POSTing payloads (Apache cgi RCE).
"""
from __future__ import annotations
import re
from engine.runner import run_tool

# file write/upload/config-read flags — never useful for a probe, easily abused
BLOCKED_FLAGS = {"-o", "-O", "--output", "-T", "--upload-file", "-K",
                 "--config", "-F"}


def run_curl(args: list[str], timeout: int = 60):
    args = list(args)
    if "-s" not in args and "--silent" not in args:
        args = ["-s"] + args
    return run_tool(["curl"] + args, timeout=timeout)


def parse_curl(result) -> list[dict]:
    """Turn a response into findings when it proves traversal or RCE."""
    body = result.stdout or ""
    if "root:x:0:0:" in body:
        return [{
            "title": "Path traversal: /etc/passwd exposed",
            "detail": "curl response contains the local /etc/passwd file",
            "evidence": body[:300],
        }]
    if re.search(r"uid=\d+\(", body) and re.search(r"gid=\d+\(", body):
        return [{
            "title": "Command execution confirmed (id output)",
            "detail": "curl response contains `id` output of the web server user",
            "evidence": body[:300],
        }]
    return []
