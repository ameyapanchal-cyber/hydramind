"""Validator — independent second-model cross-check before the report.

The Reasoner (OpenAI) proposes actions; this module asks a *different model
family* to judge whether each finding is actually supported by the evidence
that the executor recorded. Providers are auto-selected:

    ANTHROPIC_API_KEY  -> anthropic (claude)
    GOOGLE_API_KEY / GEMINI_API_KEY -> google (gemini)
    OPENAI_API_KEY     -> openai fallback (same family as the Reasoner,
                          flagged honestly in the DB/report)

Override with HYDRAMIND_VALIDATOR_PROVIDER / HYDRAMIND_VALIDATOR_MODEL.
No key at all -> validation is skipped (reports still work).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict

from engine import db

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "google": "gemini-flash-latest",
    "openai": "gpt-4o",
}
GOOGLE_FALLBACK_MODELS = ("gemini-3-flash-preview", "gemini-3.1-flash-lite")
VERDICTS = ("confirmed", "likely", "false_positive", "needs_review")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

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

_client = None


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


def provider_config() -> dict:
    """Resolve the validator provider/model. 'none' when no API key exists."""
    provider = os.environ.get("HYDRAMIND_VALIDATOR_PROVIDER", "").strip().lower()
    if provider not in ("anthropic", "google", "openai", "none"):
        provider = ""
    if not provider:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
            provider = "google"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            provider = "none"
    model = os.environ.get("HYDRAMIND_VALIDATOR_MODEL", "").strip()
    if not model:
        model = DEFAULT_MODELS.get(provider, "")
    return {
        "provider": provider,
        "model": model,
        "same_family": provider == "openai",
    }


def _openai_client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(timeout=60.0)
    return _client


def _redact(text: str) -> str:
    """Strip API keys/query secrets from error text before it is stored."""
    text = re.sub(r"(key=)[^&\s\"']+", r"\1REDACTED", str(text or ""))
    text = re.sub(r"(api[_-]?key[\"']?\s*[:=]\s*)[^\s\"',}]+", r"\1REDACTED",
                  text, flags=re.I)
    return text


def _call_model(provider: str, model: str, system: str, user: str) -> tuple[str, str]:
    """One chat completion via the provider's REST API (OpenAI uses the SDK).
    Returns (text, model_actually_used)."""
    if provider == "openai":
        response = _openai_client().chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content or "", model

    import requests

    if provider == "anthropic":
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 700,
                "temperature": 0.1,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=60,
        )
        response.raise_for_status()
        blocks = response.json().get("content") or []
        return ("".join(b.get("text", "") for b in blocks
                        if b.get("type") == "text"), model)

    if provider == "google":
        key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        candidates = [model] + [m for m in GOOGLE_FALLBACK_MODELS if m != model]
        last_error = None
        for name in candidates:
            try:
                response = requests.post(
                    "https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{name}:generateContent",
                    params={"key": key},
                    json={
                        "systemInstruction": {"parts": [{"text": system}]},
                        "contents": [{"role": "user", "parts": [{"text": user}]}],
                        "generationConfig": {
                            "temperature": 0.1,
                            "responseMimeType": "application/json",
                        },
                    },
                    timeout=45,
                )
                response.raise_for_status()
                cands = response.json().get("candidates") or []
                parts = (cands[0].get("content", {}).get("parts") or []) if cands else []
                text = "".join(p.get("text", "") for p in parts)
                if text.strip():
                    return text, name
                last_error = RuntimeError(f"{name}: empty response")
            except Exception as e:  # try the next Gemini model on 404/429/503
                last_error = e
        raise RuntimeError(_redact(last_error))

    raise RuntimeError(f"unsupported validator provider: {provider}")


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
                     fallback_severity: str = "INFO") -> ValidationResult:
    """Ask the validator model about one finding. Raises on transport errors."""
    cfg = provider_config()
    if cfg["provider"] == "none":
        raise RuntimeError("no validator API key configured")

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
    raw, model_used = _call_model(cfg["provider"], cfg["model"], SYSTEM_PROMPT,
                                  json.dumps(payload, indent=2, default=str))
    return parse_validation_response(raw, cfg["provider"], model_used,
                                     cfg["same_family"], fallback_severity)


def validate_scan(scan_id: int, top_n: int | None = None) -> list[dict]:
    """Validate a scan's triage findings against logged evidence and persist
    the verdicts. Returns one summary dict per finding (rank order)."""
    cfg = provider_config()
    if cfg["provider"] == "none":
        return []

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
