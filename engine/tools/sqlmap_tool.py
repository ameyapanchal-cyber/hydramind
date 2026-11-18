"""sqlmap module — SQL injection testing (lab-only, human-approved).

Always runs in --batch mode so the pipeline can never hang on an interactive
question; the human approval already happened at the gate.
"""
from __future__ import annotations
import re
from engine.runner import run_tool

# interactive shells / file writes — would hang the pipeline or alter the host
BLOCKED_FLAGS = {"--os-shell", "--os-pwn", "--sql-shell", "--file-write",
                 "--file-dest"}


def run_sqlmap(url: str, extra: list[str] | None = None, timeout: int = 600):
    cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
           "--threads", "2", "--disable-coloring"]
    if extra:
        cmd += [a for a in extra if a not in cmd]
    return run_tool(cmd, timeout=timeout)


def parse_sqlmap(result) -> list[dict]:
    out = result.stdout or ""
    if "is vulnerable" not in out.lower() and not re.search(
            r"Parameter: .+\((GET|POST|COOKIE)\)", out):
        return []
    param = re.search(r"Parameter: (.+)", out)
    evidence = [line for line in out.splitlines()
                if "vulnerable" in line.lower() or "Parameter:" in line
                or line.strip().startswith("Type:")]
    return [{
        "title": f"SQL injection confirmed: {param.group(1).strip() if param else '?'}",
        "detail": "\n".join(evidence)[:500],
        "evidence": "\n".join(evidence)[:500],
    }]
