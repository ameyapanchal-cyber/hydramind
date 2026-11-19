"""Validator — independent second-model cross-check before the report.

The Reasoner proposes actions; this module asks a *different model family*
(validator role in config/models.yaml) to judge whether each finding is
actually supported by the evidence that the executor recorded.

Independence is computed against the active reasoner role, not hardcoded:
same-family verdicts are flagged in the DB/report, and
HYDRAMIND_REQUIRE_SECOND_FAMILY=1 refuses to validate when families match.

Override with HYDRAMIND_VALIDATOR_PROVIDER / HYDRAMIND_VALIDATOR_MODEL or a
profile. No available model -> validation is skipped (reports still work).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict

from engine import db, models
from engine.models import DEFAULT_MODELS, GOOGLE_FALLBACK_MODELS  # re-exported
from engine.models import redact as _redact
VERDICTS = ("confirmed", "likely", "false_positive", "needs_review")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class ValidationResult:
    verdict: str
    severity: str
    confidence: float
    rationale: str
    remediation: str
    provider: str
    model: str
    same_family: bool

    def to_dict(self) -> dict:
        return asdict(self)


SYSTEM_PROMPT = """You are the Validator — an independent second-model reviewer
in an AUTHORIZED penetration-testing pipeline. Another model proposed actions,
a human approved them, and the executor recorded the evidence below.

Judge ONE finding against its evidence and decide whether the final report may
state it as a real vulnerability.

Verdicts:
- "confirmed": evidence directly proves it (e.g. sqlmap reports a vulnerable
  parameter, /etc/passwd content was returned, RCE output shows command
  execution, credentials were accepted, unauthenticated Redis INFO/CONFIG
  output was returned).
- "likely": strong indirect signal but not definitive.
- "false_positive": evidence contradicts the claim, is a generic banner, a
  403/401 that correctly blocks access, or the action failed.
- "needs_review": evidence is missing or ambiguous.

Evidence rules:
- If "executed" is false, the finding rests on triage text only: mark it
  "needs_review" unless the supplied text itself proves the claim. Never
  mark "confirmed"/"likely" from a generic triage summary.
- The executor summary "0 finding(s)" only means the parser produced no
  structured finding — the raw command output is still evidence; judge it.
- "exit_code": 0 means the command ran successfully against the target; its
  "output" is the real target response.
- A service banner/version alone is not a vulnerability. Mark "likely" only
  when the finding text explicitly ties the version to a known CVE;
  otherwise "needs_review".
- A 403/401 response that blocks access is NOT a vulnerability.
- sqlmap listing an injectable parameter/type = "confirmed" SQL injection.
- Returned /etc/passwd content or command output = "confirmed" RCE/traversal.
- redis-cli INFO/CONFIG GET/KEYS returning any data without authentication
  (even an empty KEYS list or a path like /data) = "confirmed" unauthenticated
  Redis access.

Adjust severity from the evidence (CRITICAL/HIGH/MEDIUM/LOW/INFO) and give one
actionable remediation sentence. Never invent evidence that is not supplied.

Respond ONLY with valid JSON:
{"verdict": "confirmed|likely|false_positive|needs_review",
 "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
 "confidence": 0.0,
 "rationale": "<=300 chars, cite the supplied evidence",
 "remediation": "<=200 chars, one actionable fix"}
"""

def provider_config() -> dict:
    """Resolve the validator role + independence against the reasoner."""
    cfg = models.resolve_validator()
    return {
        "provider": cfg["provider"],
        "model": cfg["model"],
        "same_family": cfg["same_family"],
        "family": cfg["family"],
        "reasoner_family": cfg.get("reasoner_family", ""),
        "profile": cfg["profile"],
        "fallback_from": cfg.get("fallback_from", ""),
    }


def _clean(value, limit: int = 600) -> str:
    return str(value or "").strip()[:limit]


def parse_validation_response(raw: str, provider: str, model: str,
                              same_family: bool,
                              fallback_severity: str = "INFO") -> ValidationResult:
    """Parse the model JSON defensively — bad output becomes needs_review,
    never a silent confirmation."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, IndexError):
        match = re.search(r"\{.*\}", text, re.S)
        data = json.loads(match.group(0)) if match else {}
    if not isinstance(data, dict):
        data = {}

    verdict = str(data.get("verdict") or "").strip().lower()
    verdict = verdict.replace("-", "_").replace(" ", "_")
    if verdict in ("true_positive", "truepositive", "valid"):
        verdict = "confirmed"
    if verdict in ("falsepositive", "false"):
        verdict = "false_positive"
    if verdict not in VERDICTS:
        verdict = "needs_review"

    severity = str(data.get("severity") or "").strip().upper()
    if severity not in SEVERITIES:
        severity = fallback_severity if fallback_severity in SEVERITIES else "INFO"

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = min(max(confidence, 0.0), 1.0)

    return ValidationResult(
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        rationale=_clean(data.get("rationale"), 400) or "(no rationale returned)",
        remediation=_clean(data.get("remediation"), 300),
        provider=provider,
        model=model,
        same_family=same_family,
    )


def validate_finding(target: str, tool: str, title: str, description: str,
                     triage_why: str = "", triage_next: str = "",
                     executed: bool = False, command: str = "",
                     result: str = "", tool_findings: str = "",
                     fallback_severity: str = "INFO",
                     scan_id: int | None = None) -> ValidationResult:
    """Ask the validator model about one finding. Raises on transport errors."""
    cfg = models.resolve_validator()
    if cfg["provider"] == "none":
        raise RuntimeError("no validator model available")

    code_match = re.search(r"\brc=(-?\d+)", result or "")
    exit_code = int(code_match.group(1)) if code_match else (0 if executed else None)
    payload = {
        "target": target,
        "finding": {
            "tool": tool,
            "title": _clean(title, 300),
            "description": _clean(description, 800),
            "triage_why": _clean(triage_why, 400),
            "triage_next_step": _clean(triage_next, 400),
            "evidence_source": "execution" if executed else "recon",
        },
        "execution": {
            "executed": executed,
            "exit_code": exit_code,
            "approved_command": _clean(command, 500),
            "output": _clean(result, 1200),
            "tool_evidence": _clean(tool_findings, 2500),
        },
    }
    reply = models.chat(
        "validator", SYSTEM_PROMPT,
        json.dumps(payload, indent=2, default=str),
        temperature=0.1, json_mode=True, scan_id=scan_id, role_cfg=cfg,
    )
    return parse_validation_response(reply.text, reply.provider, reply.model,
                                     cfg["same_family"], fallback_severity)


def validate_scan(scan_id: int, top_n: int | None = None) -> list[dict]:
    """Validate a scan's triage findings against logged evidence and persist
    the verdicts. Returns one summary dict per finding (rank order)."""
    cfg = models.resolve_validator()
    if cfg["provider"] == "none":
        return []
    if cfg["same_family"]:
        if os.environ.get("HYDRAMIND_REQUIRE_SECOND_FAMILY", "").lower() in (
                "1", "true", "yes"):
            print(f"[validator] REFUSED — {cfg['provider']}/{cfg['model']} is the "
                  f"same family as the reasoner ({cfg['reasoner_family']}); "
                  f"set a different validator provider/model.")
            return []
        print(f"[validator] WARNING: {cfg['provider']}/{cfg['model']} is the same "
              f"family as the reasoner ({cfg['reasoner_family']}) — independence "
              f"is flagged in the report.")

    scan = db.scan_row(scan_id)
    if not scan:
        return []
    target = scan["target"]
    triage = db.triage_for_scan(scan_id)
    decisions = {}
    for d in db.decisions_for_scan(scan_id):
        decisions.setdefault(d["finding_id"], d)
    findings = db.findings_for_scan(scan_id)
    db.clear_validations(scan_id)  # re-validation replaces prior verdicts

    results = []
    for tf in triage[:top_n] if top_n else triage:
        d = decisions.get(tf["id"]) or {}
        executed = bool(d.get("executed"))
        command = (d.get("proposed_command") or "").strip()
        cmd_tool = command.split()[0].strip("'\"") if command else ""
        tool = cmd_tool or tf.get("source") or "triage"
        evidence = ""
        if executed:
            related = [f for f in findings if f.get("tool") == tool]
            evidence = "\n".join(
                f"- {(f.get('detail') or f.get('title') or '')}".strip()
                for f in related)[:2500]
        try:
            vr = validate_finding(
                target=target,
                tool=tool,
                title=tf.get("description") or "",
                description=tf.get("description") or "",
                triage_why=tf.get("why") or "",
                triage_next=tf.get("next_step") or "",
                executed=executed,
                command=command,
                result=d.get("result") or "",
                tool_findings=evidence,
                fallback_severity=tf.get("severity") or "INFO",
                scan_id=scan_id,
            )
            error = ""
        except Exception as e:  # transport/API failure must not kill the scan
            e = RuntimeError(_redact(e))
            vr = ValidationResult(
                verdict="needs_review",
                severity=tf.get("severity") if tf.get("severity") in SEVERITIES else "INFO",
                confidence=0.0,
                rationale=f"validator error: {_clean(e, 300)}",
                remediation="",
                provider=cfg["provider"],
                model=cfg["model"],
                same_family=cfg["same_family"],
            )
            error = str(e)

        db.save_validation(
            scan_id, tf["id"], tool, tf.get("description") or "",
            vr.verdict, vr.severity, vr.confidence, vr.rationale,
            vr.remediation, vr.provider, vr.model, vr.same_family,
        )
        note = f"  (error: {error[:80]})" if error else ""
        print(f"  #{tf.get('rank')} [{vr.verdict}] {vr.severity} "
              f"({vr.confidence:.0%}) {tf.get('description', '')[:60]}"
              f"{note}", flush=True)
        results.append({
            "rank": tf.get("rank"), "title": tf.get("description") or "",
            "verdict": vr.verdict, "severity": vr.severity,
            "confidence": vr.confidence, "rationale": vr.rationale,
            "provider": vr.provider, "model": vr.model,
            "same_family": vr.same_family, "error": error,
        })
    return results
