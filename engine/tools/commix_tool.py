"""commix module — OS command injection testing (lab-only, human-approved).

Runs in --batch mode so the pipeline never hangs on an interactive prompt.
"""
from __future__ import annotations
import re
from engine.runner import run_tool

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def run_commix(args: list[str], timeout: int = 600):
    args = list(args)
    if "--batch" not in args:
        args.append("--batch")
    # commix v4.x ignores -u and reads targets from stdin whenever stdin is
    # not a TTY (true for every pipeline subprocess) — this flag disables that
    if "--ignore-stdin" not in args:
        args.append("--ignore-stdin")
    # deterministic scans: never trust a previously stored commix session
    if "--ignore-session" not in args and "--flush-session" not in args:
        args.append("--ignore-session")
    # after confirming injection commix would spawn a pseudo-terminal shell;
    # in batch mode it answers "Y" and then loops forever on EOF — decline it
    if not any(a == "--answers" or a.startswith("--answers=") for a in args):
        args.append("--answers=pseudo-terminal shell=N")
    return run_tool(["commix"] + args, timeout=timeout)


def parse_commix(result) -> list[dict]:
    out = ANSI_RE.sub("", result.stdout or "")
    findings = []
    for line in out.splitlines():
        stripped = line.strip()
        if "Do you want to" in stripped:
            stripped = stripped.split("Do you want to")[0].strip()
        low = stripped.lower()
        if "vulnerable" in low or "is injectable" in low:
            findings.append({
                "title": stripped[:120],
                "detail": "commix confirmed command injection",
                "evidence": stripped[:400],
            })
        elif low.startswith("payload:"):
            findings.append({
                "title": stripped[:120],
                "detail": "working injection payload",
                "evidence": stripped[:400],
            })
    return findings
