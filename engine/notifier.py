"""n8n webhook notifier — best-effort, redacted, never blocks a scan.

Enable with `--webhook https://n8n.example/webhook/hydramind` or
`HYDRAMIND_N8N_WEBHOOK`. Events: scan_started, scan_refused, scan_failed,
scan_finished, validation_finished, agent_plan. Payloads contain only audit-trail metadata
(no cookies, API keys or raw tool output); secrets are redacted before sending.
A failed webhook logs one line and the scan continues.
"""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone

from engine import db, models

_webhook: str | None = None
_enabled = True

_SECRET_KEYS = ("key", "token", "secret", "cookie", "password", "authorization")


def configure(webhook: str | None = None, enabled: bool = True) -> None:
    global _webhook, _enabled
    _webhook = webhook.strip() if webhook else None
    _enabled = enabled


def webhook_url() -> str:
    return (_webhook or os.environ.get("HYDRAMIND_N8N_WEBHOOK", "")).strip()


def _sanitize(value):
    if isinstance(value, dict):
        clean = {}
        for k, v in value.items():
            if any(s in str(k).lower() for s in _SECRET_KEYS):
                clean[k] = "[redacted]"
            else:
                clean[k] = _sanitize(v)
        return clean
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    if isinstance(value, str):
        return models.redact(value)
    return value


def emit(event: str, data: dict | None = None, timeout: float = 5.0) -> bool:
    """POST one event to the configured n8n webhook. Returns True on 2xx."""
    if not _enabled:
        return False
    url = webhook_url()
    if not url:
        return False
    payload = {
        "source": "hydramind",
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": _sanitize(data or {}),
    }
    request = urllib.request.Request(
        url, data=json.dumps(payload, default=str).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "HydraMind/1.0"},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            ok = 200 <= response.status < 300
    except Exception as e:
        print(f"[notify] {event} failed: {models.redact(e)[:160]}")
        return False
    if ok:
        print(f"[notify] {event} → n8n")
    return ok


def counts(scan_id: int) -> dict:
    triage = db.triage_for_scan(scan_id)
    decisions = db.decisions_for_scan(scan_id)
    validations = db.validations_for_scan(scan_id)
    verdicts: dict[str, int] = {}
    for v in validations:
        verdicts[v.get("verdict") or "unknown"] = verdicts.get(v.get("verdict") or "unknown", 0) + 1
    return {
        "raw_findings": len(db.findings_for_scan(scan_id)),
        "triage_findings": len(triage),
        "executed_actions": sum(1 for d in decisions if d.get("executed")),
        "validations": len(validations),
        "verdicts": verdicts,
    }


def scan_started(scan_id: int, target: str, profile: str, dry_run: bool) -> bool:
    return emit("scan_started", {"scan_id": scan_id, "target": target,
                                 "profile": profile, "dry_run": dry_run})


def scan_refused(target: str, reason: str, profile: str) -> bool:
    return emit("scan_refused", {"target": target, "reason": reason,
                                 "profile": profile})


def scan_failed(scan_id: int, target: str, profile: str, stage: str,
                error: str) -> bool:
    return emit("scan_failed", {"scan_id": scan_id, "target": target,
                                "profile": profile, "stage": stage,
                                "error": str(error)[:500]})


def scan_finished(scan_id: int, target: str, profile: str, dry_run: bool,
                  reports: dict | None = None) -> bool:
    data = {"scan_id": scan_id, "target": target, "profile": profile,
            "dry_run": dry_run, **counts(scan_id)}
    if reports:
        data["reports"] = {k: str(v) for k, v in reports.items()}
    return emit("scan_finished", data)


def validation_finished(scan_id: int, target: str, profile: str,
                        reports: dict | None = None) -> bool:
    data = {"scan_id": scan_id, "target": target, "profile": profile,
            **counts(scan_id)}
    if reports:
        data["reports"] = {k: str(v) for k, v in reports.items()}
    return emit("validation_finished", data)
