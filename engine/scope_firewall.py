"""Scope Firewall — the ethical core. No target runs unless it's authorized here,
and no tool runs against a target whose policy doesn't allow that tool.

Two-stage authorization:
  1. check(target)   — is this host/CIDR authorized at all?
  2. check_tool(target, tool) — is this specific tool allowed for this target?

Every decision (allow and deny) is logged to SQLite via db.log_scope_event().
"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Tools that must never run outside an environment: lab target
EXPLOIT_CLASS_TOOLS = {"sqlmap", "hydra", "wpscan", "commix", "metasploit"}

VALID_ENVIRONMENTS = {"lab", "live_authorized"}


class ScopeError(Exception):
    """Raised when a target/tool is out of scope. The pipeline must stop."""


@dataclass
class TargetPolicy:
    host: str
    authorized: bool = True
    environment: str | None = None            # lab | live_authorized
    allowed_tools: set[str] = field(default_factory=set)
    forbidden_tools: set[str] = field(default_factory=set)
    program_rules_url: str | None = None
    rate_limit: str | None = None

    @classmethod
    def from_dict(cls, d: dict, index: int) -> "TargetPolicy":
        if not isinstance(d, dict) or "host" not in d:
            raise ValueError(f"scope targets[{index}] must be a dict with 'host'")
        env = d.get("environment")
        if env is not None and env not in VALID_ENVIRONMENTS:
            raise ValueError(f"targets[{index}]: environment must be one of {sorted(VALID_ENVIRONMENTS)}")
        return cls(
            host=str(d["host"]).strip().lower(),
            authorized=bool(d.get("authorized", True)),
            environment=env,
            allowed_tools={str(t).strip().lower() for t in (d.get("allowed_tools") or [])},
            forbidden_tools={str(t).strip().lower() for t in (d.get("forbidden_tools") or [])},
            program_rules_url=d.get("program_rules_url"),
            rate_limit=d.get("rate_limit"),
        )


class ScopeFirewall:
    def __init__(self, scope_file):
        self.scope_file = Path(scope_file)
        data = yaml.safe_load(self.scope_file.read_text()) or {}
        self.allowed = [h.strip().lower() for h in (data.get("allowed_hosts") or [])]
        self.denied = [h.strip().lower() for h in (data.get("denied_hosts") or [])]
        self.targets: list[TargetPolicy] = []
        for i, t in enumerate(data.get("targets") or []):
            self.targets.append(TargetPolicy.from_dict(t, i))

    # ---------- stage 1: is this host authorized at all? ----------
    def _match_policy(self, target: str) -> TargetPolicy | None:
        t = target.strip().lower()
        for p in self.targets:
            if p.host == t:
                return p
            if "/" in p.host:
                try:
                    if ipaddress.ip_address(t) in ipaddress.ip_network(p.host, strict=False):
                        return p
                except ValueError:
                    continue
        return None

    def check(self, target: str) -> str:
        t = target.strip().lower()
        if t in self.denied:
            raise ScopeError(f"BLOCKED: '{target}' is on the deny list.")
        policy = self._match_policy(t)
        if policy is not None:
            if not policy.authorized:
                raise ScopeError(f"BLOCKED: '{target}' is listed but marked authorized: false.")
            return t
        if t in self.allowed:
            return t
        for entry in self.allowed:
            if "/" in entry:
                try:
                    if ipaddress.ip_address(t) in ipaddress.ip_network(entry, strict=False):
                        return t
                except ValueError:
                    continue
        raise ScopeError(
            f"BLOCKED: '{target}' is NOT in scope.yaml. "
            f"Add it only if you are authorized to test it."
        )

    # ---------- stage 2: is this tool allowed for this target? ----------
    def check_tool(self, target: str, tool: str) -> None:
        """Hard-refuse when the target's policy doesn't allow this tool.
        Same severity as an unauthorized target."""
        t = target.strip().lower()
        self.check(t)  # stage 1 always first
        tool = tool.strip().lower()
        policy = self._match_policy(t)
        if policy is not None:
            if tool in policy.forbidden_tools:
                raise ScopeError(
                    f"BLOCKED: tool '{tool}' is in forbidden_tools for '{target}'.")
            if policy.allowed_tools and tool not in policy.allowed_tools:
                raise ScopeError(
                    f"BLOCKED: tool '{tool}' is not in allowed_tools for '{target}' "
                    f"(allowed: {sorted(policy.allowed_tools)}).")
            if tool in EXPLOIT_CLASS_TOOLS and policy.environment != "lab":
                raise ScopeError(
                    f"BLOCKED: exploitation-class tool '{tool}' requires "
                    f"environment: lab — '{target}' is "
                    f"'{policy.environment or 'unclassified'}'.")
        else:
            # legacy allowed_hosts entry: recon only, no exploitation class
            if tool in EXPLOIT_CLASS_TOOLS:
                raise ScopeError(
                    f"BLOCKED: exploitation-class tool '{tool}' requires a rich "
                    f"targets entry with environment: lab — '{target}' is a "
                    f"legacy allowed_hosts entry.")


if __name__ == "__main__":
    from engine import db
    fw = ScopeFirewall(Path(__file__).resolve().parents[1] / "config" / "scope.yaml")
    db.init_db()
    for t in ["scanme.nmap.org", "google.com", "127.0.0.1"]:
        try:
            print(f"[ALLOW] {fw.check(t)}")
            db.log_scope_event(t, "recon", True, "")
        except ScopeError as e:
            print(f"[DENY ] {e}")
            db.log_scope_event(t, "recon", False, str(e))
