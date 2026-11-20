"""Context-aware model routing policies.

Rules live in ``config/routing.yaml`` (override with
``HYDRAMIND_ROUTING_FILE``). Routing is opt-in: enable it with
``HYDRAMIND_ROUTING=1`` (or ``--routing`` on main.py/agent.py), otherwise the
active profile's per-role model always wins.

A rule matches a role plus optional context predicates (severity, source,
risk level, minimum finding count, minimum RAG score) and selects a symbolic
tier from the profile (``deep``/``cheap`` in ``config/models.yaml``) or an
explicit provider/model. The validator is deliberately never routed: its
independence is computed against the reasoner and must stay explicit.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from engine import models

ROOT = Path(__file__).resolve().parents[1]
ROUTING_PATH = ROOT / "config" / "routing.yaml"
ROUTABLE_ROLES = ("triager", "reasoner")
_cache: dict | None = None
_cache_key: tuple = ()


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _path() -> Path:
    return Path(os.environ.get("HYDRAMIND_ROUTING_FILE", ROUTING_PATH)).expanduser()


def _load(force: bool = False) -> dict:
    global _cache, _cache_key
    path = _path()
    env = os.environ.get("HYDRAMIND_ROUTING", "").strip().lower()
    key = (str(path), path.stat().st_mtime if path.exists() else 0, env)
    if _cache is not None and not force and key == _cache_key:
        return _cache
    data: dict = {}
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except Exception as e:
            print(f"[routing] warning: could not read {path}: {e}")
    enabled = bool(data.get("enabled", False))
    if env in ("0", "false", "no", "off"):
        enabled = False
    elif _truthy(env):
        enabled = True
    _cache = {
        "enabled": enabled,
        "rules": [r for r in (data.get("rules") or []) if isinstance(r, dict)],
        "source": str(path),
    }
    _cache_key = key
    return _cache


def reload() -> None:
    _load(force=True)


def enabled() -> bool:
    return bool(_load()["enabled"])


def _normalize(value) -> str:
    return str(value or "").strip().lower()


def _match(when: dict, context: dict) -> bool:
    if "severity" in when:
        allowed = {_normalize(v) for v in (when.get("severity") or [])}
        if _normalize(context.get("severity")) not in allowed:
            return False
    if "source" in when:
        allowed = {_normalize(v) for v in (when.get("source") or [])}
        if _normalize(context.get("source")) not in allowed:
            return False
    if "risk_level" in when:
        allowed = {_normalize(v) for v in (when.get("risk_level") or [])}
        if _normalize(context.get("risk_level")) not in allowed:
            return False
    if "rag_score_gte" in when:
        try:
            if float(context.get("rag_score") or 0) < float(when["rag_score_gte"]):
                return False
        except (TypeError, ValueError):
            return False
    if "finding_count_gte" in when:
        try:
            if int(context.get("finding_count") or 0) < int(when["finding_count_gte"]):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _family_safe(role: str, cfg: dict, profile: str | None) -> bool:
    """Never let a routed reasoner collapse into the validator's family."""
    if role != "reasoner" or cfg.get("provider") in (None, "", "none"):
        return True
    validator = models.resolve_role("validator", profile)
    if validator.get("provider") in (None, "", "none"):
        return True
    return cfg.get("family") != validator.get("family")


def resolve(role: str, context: dict | None = None,
            profile: str | None = None) -> tuple[dict, dict]:
    """Return (role config, routing decision) for one model call."""
    base = models.resolve_role(role, profile)
    decision = {"role": role, "policy": "profile", "tier": None,
                "reason": "profile default"}
    conf = _load()
    if not conf["enabled"] or role not in ROUTABLE_ROLES:
        return base, decision
    ctx = context or {}
    for rule in conf["rules"]:
        if _normalize(rule.get("role")) != role:
            continue
        if not _match(rule.get("when") or {}, ctx):
            continue
        use = rule.get("use") or {}
        name = str(rule.get("name") or "rule")
        tier_name = str(use.get("tier") or "").strip()
        if tier_name:
            tier = models.resolve_tier(tier_name, profile)
            if not tier:
                continue
            cfg = {**base, "provider": tier["provider"], "model": tier["model"],
                   "family": tier["family"], "tier": tier_name}
            if not _family_safe(role, cfg, profile):
                print(f"[routing] skipped {name}: routed reasoner family "
                      f"would match the validator family")
                continue
            return cfg, {"role": role, "policy": name, "tier": tier_name,
                         "reason": f"tier {tier_name} ({tier['provider']}/{tier['model']})"}
        if use.get("provider"):
            provider = _normalize(use["provider"])
            model = str(use.get("model") or models.DEFAULT_MODELS.get(provider, ""))
            cfg = {**base, "provider": provider, "model": model,
                   "family": models.model_family(provider, model)}
            if not _family_safe(role, cfg, profile):
                print(f"[routing] skipped {name}: routed reasoner family "
                      f"would match the validator family")
                continue
            return cfg, {"role": role, "policy": name, "tier": None,
                         "reason": f"explicit {provider}/{model}"}
    return base, decision


def describe(role: str, context: dict | None = None,
             profile: str | None = None) -> str:
    cfg, decision = resolve(role, context, profile)
    if decision["policy"] == "profile":
        return f"{role}={cfg['provider']}/{cfg['model']} (profile)"
    return (f"{role}={cfg['provider']}/{cfg['model']} "
            f"(routing: {decision['policy']})")
