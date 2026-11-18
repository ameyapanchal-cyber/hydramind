"""
AI Reasoner — the strategic core (a strong model: GPT-4o by default, override
with HYDRAMIND_REASONER_MODEL). Takes the target + raw findings + triage report
and produces an attack plan: assessment, attack paths and concrete next actions.

Every action is labeled "passive" (safe recon) or "active" (needs the human
approval gate). validate_plan() is the safety boundary between the AI and the
tool executor: nothing runs unless it survives it.
"""
from __future__ import annotations
import json
import os
import re
from openai import OpenAI

_client = None


def _get_client() -> OpenAI:
    """Lazy init so a missing OPENAI_API_KEY doesn't crash at import time."""
    global _client
    if _client is None:
        _client = OpenAI()  # reads OPENAI_API_KEY from environment
    return _client

# Tools the executor can actually run today vs. ones queued for Phase 3
KNOWN_TOOLS = {"nmap", "gobuster", "nikto"}
PHASE3_TOOLS = {"sqlmap", "hydra", "wpscan"}

# args that write/read files or otherwise escape the intended scan
BLOCKED_NMAP_ARGS = {"-oN", "-oX", "-oG", "-oA", "-oS", "-iL", "--datadir",
                     "--excludefile", "--append-output", "--stylesheet"}
MAX_ACTIONS = 5
MAX_ARGS = 12

SAFE_ARG = re.compile(r"^[A-Za-z0-9_.,:/@=+\-*]{1,64}$")

SYSTEM_PROMPT = """You are the Reasoner — the strategic core of HydraMind, an
AUTHORIZED penetration testing pipeline. You receive recon findings
(nmap, gobuster, nikto) and a triage report from a cheaper junior model,
and you decide what to do next.

Your job:
1. Assess the target's overall attack surface.
2. Propose concrete attack paths worth pursuing.
3. Propose up to 5 concrete next actions.

Classify every action's risk honestly:
- "passive": safe enumeration of the kind the recon phase already did
  (deeper nmap version/port scans, bigger gobuster wordlists, nikto).
- "active": ANYTHING beyond that — credential brute force, injection
  testing (sqlmap), exploitation, attack payloads. When unsure, say "active".

Respond ONLY with valid JSON in this exact format:
{
  "assessment": "<2-3 sentence strategic read of the target>",
  "attack_paths": [
    {"title": "<short name>", "steps": ["<step 1>", "<step 2>", "..."]}
  ],
  "actions": [
    {
      "id": 1,
      "tool": "nmap|gobuster|nikto|sqlmap|hydra|wpscan",
      "risk": "passive|active",
      "target": "<must be EXACTLY the target given in the input>",
      "args": ["<CLI arguments, one per list item, no target>"],
      "description": "<one line: what this action does>",
      "rationale": "<why now, and what we learn either way>"
    }
  ],
  "priority": 1
}

Rules:
- Max 5 actions, ordered most-valuable-first. "priority" is the id of the
  single best next action.
- args must NOT contain credentials, passwords or attack payloads.
- Do not propose anything against targets other than the one given.
- Every action must teach us something, even if it fails."""


def reason(target: str, findings: dict, triage_report: dict) -> dict:
    """Ask the strong model for an attack plan. Returns raw parsed JSON."""
    user_msg = json.dumps({
        "target": target,
        "findings": findings,
        "triage": triage_report,
    }, indent=2)
    model = os.environ.get("HYDRAMIND_REASONER_MODEL", "gpt-4o")
    response = _get_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.3,
    )
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


def _clean_text(value, limit=300) -> str:
    return str(value or "").strip()[:limit]


def _check_args(tool: str, args) -> tuple[list | None, list]:
    """Validate CLI args fail-closed: one bad token rejects the whole action
    (a half-sanitized list can leave dangling flag values that tools would
    misread — e.g. a blocked '-oN' followed by its file path, which nmap
    would then treat as a target). Returns (args, problems) or (None, problems)."""
    problems = []
    if not isinstance(args, list):
        return None, ["args is not a list"]
    if len(args) > MAX_ARGS:
        return None, [f"too many args ({len(args)})"]
    for a in args:
        a = str(a).strip()
        if not a or not SAFE_ARG.match(a):
            return None, [f"unsafe arg: {a!r}"]
        if tool == "nmap" and (a in BLOCKED_NMAP_ARGS
                               or a.startswith("--datadir")
                               or a.startswith("--excludefile")):
            return None, [f"blocked arg: {a!r}"]
    return [str(a).strip() for a in args], problems


def validate_plan(plan: dict, target: str) -> dict:
    """
    Safety boundary: normalize the model's plan and reject anything that
    doesn't survive it. Only this validated structure reaches the executor.
    """
    if not isinstance(plan, dict):
        return {"assessment": "", "attack_paths": [], "actions": [],
                "priority": None, "rejected": ["plan is not a JSON object"]}

    rejected: list[str] = []
    assessment = _clean_text(plan.get("assessment"), 600)

    attack_paths = []
    for p in (plan.get("attack_paths") or [])[:5]:
        if isinstance(p, dict) and p.get("title"):
            steps = [_clean_text(s, 200) for s in (p.get("steps") or [])[:8] if s]
            attack_paths.append({"title": _clean_text(p.get("title"), 120),
                                 "steps": steps})

    actions = []
    next_id = 1
    raw_actions = plan.get("actions") or []
    if not isinstance(raw_actions, list):
        raw_actions = []
    if len(raw_actions) > MAX_ACTIONS:
        rejected.append(f"plan had {len(raw_actions)} actions — kept first {MAX_ACTIONS}")
    for a in raw_actions[:MAX_ACTIONS]:
        if not isinstance(a, dict):
            rejected.append("dropped non-object action")
            continue
        tool = str(a.get("tool") or "").strip().lower()
        if tool not in KNOWN_TOOLS | PHASE3_TOOLS:
            rejected.append(f"action {next_id}: unknown tool '{tool}' → manual")
            tool = "manual"
        risk = str(a.get("risk") or "").strip().lower()
        if risk not in ("passive", "active"):
            rejected.append(f"action {next_id}: bad risk '{risk}' → treated as active")
            risk = "active"  # fail-safe: unknown risk = needs approval
        a_target = str(a.get("target") or "").strip().lower()
        if a_target != target:
            rejected.append(f"action {next_id}: target '{a_target}' != scoped "
                            f"target '{target}' → DROPPED")
            continue
        args, problems = _check_args(tool, a.get("args"))
        if args is None:
            rejected.extend(f"action {next_id}: {p}" for p in problems)
            rejected.append(f"action {next_id}: DROPPED (bad args)")
            continue
        actions.append({
            "id": next_id,
            "tool": tool,
            "risk": risk,
            "target": target,
            "args": args,
            "description": _clean_text(a.get("description"), 200),
            "rationale": _clean_text(a.get("rationale"), 300),
        })
        next_id += 1

    priority = plan.get("priority")
    if not isinstance(priority, int) or not any(x["id"] == priority for x in actions):
        priority = actions[0]["id"] if actions else None

    return {"assessment": assessment, "attack_paths": attack_paths,
            "actions": actions, "priority": priority, "rejected": rejected}
