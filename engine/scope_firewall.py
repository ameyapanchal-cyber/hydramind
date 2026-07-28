"""Scope Firewall — the ethical core. No target runs unless it's authorized here."""
from __future__ import annotations
import ipaddress
import yaml
from pathlib import Path


class ScopeError(Exception):
    """Raised when a target is out of scope. The pipeline must stop."""


class ScopeFirewall:
    def __init__(self, scope_file):
        self.scope_file = Path(scope_file)
        data = yaml.safe_load(self.scope_file.read_text()) or {}
        self.allowed = [h.strip().lower() for h in (data.get("allowed_hosts") or [])]
        self.denied = [h.strip().lower() for h in (data.get("denied_hosts") or [])]

    def check(self, target: str) -> str:
        t = target.strip().lower()
        if t in self.denied:
            raise ScopeError(f"BLOCKED: '{target}' is on the deny list.")
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


if __name__ == "__main__":
    fw = ScopeFirewall(Path(__file__).resolve().parents[1] / "config" / "scope.yaml")
    for t in ["scanme.nmap.org", "google.com", "127.0.0.1"]:
        try:
            print(f"[ALLOW] {fw.check(t)}")
        except ScopeError as e:
            print(f"[DENY ] {e}")
