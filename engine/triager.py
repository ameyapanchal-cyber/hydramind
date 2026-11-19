"""
AI Triager — the first Hydra head.
Takes all raw findings (nmap + gobuster + nikto) and asks the triager role
(config/models.yaml: Ollama / GPT-4o-mini / any provider) to rank them by risk
so you don't read raw tool output yourself.
"""
from __future__ import annotations
import json

from engine import models

SYSTEM_PROMPT = """You are a penetration testing AI assistant.
You will receive a JSON list of findings from recon tools (nmap, gobuster,
nikto) and possibly user-supplied endpoints (source "user").
Your job is to rank them by risk and explain each one clearly.

Respond ONLY with valid JSON in this exact format:
{
  "ranked_findings": [
    {
      "rank": 1,
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "source": "nmap|gobuster|nikto|user",
      "finding": "<brief description>",
      "why": "<why this matters for a pentester>",
      "next_step": "<the single most useful next action>"
    }
  ],
  "summary": "<2-3 sentence overall assessment>"
}
Only include findings worth investigating. Filter out pure noise.
User-supplied endpoints are explicit priorities — always include them, and copy
their exact URL (scheme, host, port, path and query string) into the finding
text and next_step. Never shorten or invent a URL."""


def triage(all_findings: dict, scan_id: int | None = None) -> dict:
    """
    all_findings: {
        "nmap": [...],
        "gobuster": [...],
        "nikto": [...]
    }
    Returns the parsed JSON from the triager role.
    """
    user_msg = json.dumps(all_findings, indent=2)
    reply = models.chat("triager", SYSTEM_PROMPT, user_msg,
                        temperature=0.2, json_mode=True, scan_id=scan_id)
    raw = reply.text.strip()
    # Strip markdown code fences if GPT wraps in ```json
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)
