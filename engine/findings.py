"""Finding — the structured unit every tool and AI head works with.
Shape per architecture spec: {tool, target, severity, title, description,
raw_evidence, timestamp}."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    tool: str
    target: str
    severity: str = "INFO"
    title: str = ""
    description: str = ""
    raw_evidence: str = ""
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool, "target": self.target, "severity": self.severity,
            "title": self.title, "description": self.description,
            "raw_evidence": self.raw_evidence, "timestamp": self.timestamp,
        }


def finding_from_tool(tool: str, target: str, d: dict) -> Finding:
    """Normalize a raw tool finding dict (nmap/gobuster/nikto shapes)."""
    if tool == "nmap":
        svc = d.get("product") or d.get("service") or "unknown"
        title = f"{svc} on port {d.get('port')}/{d.get('protocol', 'tcp')}"
        desc = f"{svc} {d.get('version') or ''} listening on port {d.get('port')}".strip()
    elif tool == "gobuster":
        title = f"Path {d.get('path')} (HTTP {d.get('status')})"
        desc = f"Discovered path {d.get('path')} — status {d.get('status')}, {d.get('size')} bytes"
    elif tool == "nikto":
        title = (d.get("finding") or "nikto finding")[:120]
        desc = d.get("finding") or ""
    elif tool in ("curl", "sqlmap", "redis-cli"):
        title = (d.get("title") or f"{tool} finding")[:120]
        desc = d.get("detail") or d.get("evidence") or json.dumps(d)
    else:
        title, desc = json.dumps(d)[:120], json.dumps(d)
    return Finding(tool=tool, target=target, title=title, description=desc,
                   raw_evidence=json.dumps(d))


def finding_from_triage(item: dict, target: str) -> Finding:
    """Normalize an AI triage item (ranked finding) into a Finding."""
    return Finding(
        tool=item.get("source") or "triage",
        target=target,
        severity=item.get("severity") or "INFO",
        title=(item.get("finding") or "")[:200],
        description=f"{item.get('finding', '')} — {item.get('why', '')}".strip(" -—"),
        raw_evidence=json.dumps(item),
    )
