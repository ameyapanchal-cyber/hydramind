"""Optional LLM Writer — grounded executive summary for the report.

The writer role is OFF by default (`writer: none`): reports are deterministic
templates from SQLite. When enabled in config/models.yaml, the writer receives
ONLY the validated findings (with stable [F1]..[Fn] IDs) and must produce a
short executive summary that cites those IDs. A citation check rejects any
summary that invents finding IDs; on rejection the report keeps the
deterministic summary and the error is logged in `model_calls`.

The LLM never sees raw tool output here — only the validator's verdicts — so it
cannot add new "facts" that the audit trail does not contain.
"""
from __future__ import annotations

import json
import re

from engine import db, models

CITATION_RE = re.compile(r"\[F(\d+)\]")

SYSTEM_PROMPT = """You are the Writer for an AUTHORIZED penetration-test
report. You receive ONLY validated findings, each with a stable ID like [F1],
its verdict, severity, confidence and the validator's rationale.

Write a 3-5 sentence executive summary for a technical reader.

Rules:
- Cite findings by their exact bracketed IDs, e.g. [F1] or [F2].
- Only state findings whose verdict is "confirmed" or "likely"; do not present
  false positives or needs-review items as vulnerabilities.
- Do not invent hosts, URLs, CVEs, numbers or attack paths. Use only the
  supplied text.
- If nothing is confirmed/likely, say the scan produced no validated
  vulnerabilities and mention that lower-confidence items need review.
- Plain text only, no markdown headings, no lists, no code fences."""


def _validate_citations(text: str, count: int) -> bool:
    """Every [Fn] must exist; a confirmed/likely summary must cite at least one."""
    ids = {int(m) for m in CITATION_RE.findall(text or "")}
    if any(i < 1 or i > count for i in ids):
        return False
    return True


def generate_summary(scan_id: int) -> dict | None:
    """Generate + persist a grounded summary. Returns None when disabled or
    when there is nothing to summarize. Raises ValueError on a failed citation
    check (caller keeps the deterministic report)."""
    cfg = models.resolve_role("writer")
    if cfg["provider"] == "none":
        return None
    scan = db.scan_row(scan_id)
    validations = db.validations_for_scan(scan_id)
    if not scan or not validations:
        return None

    findings = []
    actionable = 0
    for index, v in enumerate(validations, 1):
        if v.get("verdict") in ("confirmed", "likely"):
            actionable += 1
        findings.append({
            "id": f"F{index}",
            "title": v.get("title") or "",
            "verdict": v.get("verdict") or "",
            "severity": v.get("severity") or "",
            "confidence": round(float(v.get("confidence") or 0), 2),
            "rationale": (v.get("rationale") or "")[:300],
            "remediation": (v.get("remediation") or "")[:200],
        })
    payload = {
        "target": scan["target"],
        "validated_findings": findings,
        "counts": {"validated": len(findings), "confirmed_or_likely": actionable},
    }
    reply = models.chat("writer", SYSTEM_PROMPT,
                        json.dumps(payload, indent=2, default=str),
                        temperature=0.2, scan_id=scan_id)
    text = (reply.text or "").strip()
    if not _validate_citations(text, len(findings)):
        raise ValueError("writer summary failed the [Fn] citation check")
    if actionable and not CITATION_RE.search(text):
        raise ValueError("writer summary cites no findings")
    db.save_summary(scan_id, text, reply.provider, reply.model)
    return {"summary": text, "provider": reply.provider, "model": reply.model}
