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


# Tools the executor can actually run today vs. ones queued for Phase 3
KNOWN_TOOLS = {"nmap", "gobuster", "nikto"}
PHASE3_TOOLS = {"sqlmap", "hydra", "wpscan", "commix", "metasploit"}

# args that write/read files or otherwise escape the intended scan
BLOCKED_NMAP_ARGS = {"-oN", "-oX", "-oG", "-oA", "-oS", "-iL", "--datadir",
                     "--excludefile", "--append-output", "--stylesheet"}
MAX_ARGS = 12

# one CLI token: no shell metacharacters, no spaces, no quotes
SAFE_ARG = re.compile(r"^[A-Za-z0-9_.,:/@=+\-*]{1,64}$")

RISK_LEVELS = ("passive", "active", "exploit")

SYSTEM_PROMPT = """You are the Reasoner — the strategic core of HydraMind, an
AUTHORIZED penetration testing pipeline. You receive ONE finding from the
triage phase, plus context: sibling findings for the same target, and the
history of already-approved/executed actions and their outcomes for that
target.

Decide the single best next action. Chains are good — build on what history
shows succeeded or failed — but propose exactly ONE command.

risk_level classification:
- "passive": enumeration of the kind the recon phase already does
  (deeper nmap version/port scans, bigger gobuster wordlists, nikto).
- "active": probing beyond passive recon that is not yet exploitation.
- "exploit": exploitation-class tools (sqlmap/hydra/wpscan/commix) or any
  payload delivery. These are gated behind environment: lab.

Respond ONLY with valid JSON:
{
  "attack_hypothesis": "<what weakness you hypothesize and why>",
  "exact_tool_and_command": "<ONE exact command, e.g. 'nmap -p 80,443 10.0.0.5'>",
  "expected_outcome": "<what result confirms or refutes the hypothesis>",
  "confidence": 0.7,
  "risk_level": "passive|active|exploit"
}

Hard rules for exact_tool_and_command:
- binary must be one of: nmap, gobuster, nikto, sqlmap, hydra, wpscan, commix
- write the target literally as given in the input — never a placeholder
- no shell chaining: no ; | && || backticks sudo
- no file input/output arguments
- do not repeat an action that history already shows ran
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
    Safety boundary for ONE proposed command. Fail-closed: any bad token
    rejects the whole action. Returns {"tool", "args", "command"} or None.
    """
    try:
        tokens = shlex.split(command or "")
    except ValueError:
        return None
    if not tokens:
        return None
    tool = Path(tokens[0]).name.lower()
    if tool not in KNOWN_TOOLS | PHASE3_TOOLS:
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
    # the command must actually aim at the scoped target
    if not any(target.lower() in a.lower() for a in args):
        return None
    return {"tool": tool, "args": args, "command": command.strip()}
