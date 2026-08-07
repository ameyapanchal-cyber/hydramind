"""
AI Triager — the first Hydra head.
Takes all raw findings (nmap + gobuster + nikto) and asks GPT-4o-mini
to rank them by risk so you don't read raw tool output yourself.
"""
from __future__ import annotations
import json
import os
from openai import OpenAI

client = OpenAI()  # reads OPENAI_API_KEY from environment

SYSTEM_PROMPT = """You are a penetration testing AI assistant.
You will receive a JSON list of findings from recon tools (nmap, gobuster, nikto).
Your job is to rank them by risk and explain each one clearly.

Respond ONLY with valid JSON in this exact format:
{
  "ranked_findings": [
    {
      "rank": 1,
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "source": "nmap|gobuster|nikto",
      "finding": "<brief description>",
      "why": "<why this matters for a pentester>",
      "next_step": "<the single most useful next action>"
    }
  ],
  "summary": "<2-3 sentence overall assessment>"
}
Only include findings worth investigating. Filter out pure noise."""


def triage(all_findings: dict) -> dict:
    """
    all_findings: {
        "nmap": [...],
        "gobuster": [...],
        "nikto": [...]
    }
    Returns the parsed JSON from GPT.
    """
    user_msg = json.dumps(all_findings, indent=2)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.2,
    )
    raw = response.choices[0].message.content.strip()
    # Strip markdown code fences if GPT wraps in ```json
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)
