"""Role-based model registry — one place to switch models per pipeline role.

Roles: triager, reasoner, validator, writer.

Profiles live in ``config/models.yaml`` (override the path with
``HYDRAMIND_MODELS_FILE``). Resolution precedence for each role:

    env HYDRAMIND_<ROLE>_PROVIDER / HYDRAMIND_<ROLE>_MODEL
    -> profile entry in config/models.yaml
    -> built-in default

The active profile comes from ``--profile`` (CLI), then ``HYDRAMIND_PROFILE``,
then ``default_profile`` in the config file.

Providers: openai, anthropic, google, openrouter, ollama (local), none.
Ollama and OpenRouter speak the OpenAI-compatible API, so one adapter covers
them; Anthropic and Google use their native REST endpoints.

Every call is timed and logged to SQLite (``model_calls``) with role, profile,
provider, model, prompt hash, latency, token counts and the (redacted) response
or error — the reproducibility trail a thesis needs.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "models.yaml"

ROLES = ("triager", "reasoner", "validator", "writer")
PROVIDERS = ("openai", "anthropic", "google", "openrouter", "ollama", "none")

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "google": "gemini-flash-latest",
    "openai": "gpt-4o",
    "openrouter": "qwen/qwen3-8b:free",
    "ollama": "llama3.1:8b",
}
GOOGLE_FALLBACK_MODELS = ("gemini-3-flash-preview", "gemini-3.1-flash-lite")

BUILTIN_PROFILES = {
    "hybrid": {
        "triager": {"provider": "openai", "model": "gpt-4o-mini"},
        "reasoner": {"provider": "openai", "model": "gpt-4o"},
        "validator": {"provider": "google", "model": "gemini-flash-latest"},
        "writer": {"provider": "none", "model": ""},
    },
    "free": {
        "triager": {"provider": "ollama", "model": "llama3.1:8b"},
        "reasoner": {"provider": "google", "model": "gemini-flash-latest"},
        "validator": {"provider": "ollama", "model": "mistral:7b"},
        "writer": {"provider": "none", "model": ""},
    },
    "quality": {
        "triager": {"provider": "ollama", "model": "llama3.1:8b"},
        "reasoner": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
        "validator": {"provider": "google", "model": "gemini-flash-latest"},
        "writer": {"provider": "none", "model": ""},
    },
    "local": {
        "triager": {"provider": "ollama", "model": "llama3.1:8b"},
        "reasoner": {"provider": "ollama", "model": "qwen2.5:7b"},
        "validator": {"provider": "ollama", "model": "mistral:7b"},
        "writer": {"provider": "none", "model": ""},
    },
}

_config: dict | None = None
_active_profile: str | None = None
_ollama_ok: bool | None = None
_clients: dict = {}


@dataclass
class ModelReply:
    text: str
    role: str
    profile: str
    provider: str
    model: str
    latency_ms: int
    tokens_in: int | None = None
    tokens_out: int | None = None


def redact(text) -> str:
    """Strip API keys/query secrets from error text before it is stored."""
    text = re.sub(r"(key=)[^&\s\"']+", r"\1REDACTED", str(text or ""))
    text = re.sub(r"(api[_-]?key[\"']?\s*[:=]\s*)[^\s\"',}]+", r"\1REDACTED",
                  text, flags=re.I)
    text = re.sub(r"(sk-)[A-Za-z0-9_\-]{8,}", r"\1REDACTED", text)
    return text


def _load() -> dict:
    global _config
    if _config is not None:
        return _config
    data: dict = {}
    path = Path(os.environ.get("HYDRAMIND_MODELS_FILE", CONFIG_PATH))
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except Exception as e:  # bad config must not take the pipeline down
            print(f"[models] warning: could not read {path}: {e}")
    profiles = {name: dict(roles or {}) for name, roles in BUILTIN_PROFILES.items()}
    for name, roles in (data.get("profiles") or {}).items():
        profiles.setdefault(name, {}).update(roles or {})
    _config = {
        "default_profile": str(data.get("default_profile") or "hybrid"),
        "profiles": profiles,
    }
    return _config


def configure(profile: str | None = None) -> None:
    """Set the active profile (CLI wins; env HYDRAMIND_PROFILE otherwise)."""
    global _active_profile
    _active_profile = (profile or os.environ.get("HYDRAMIND_PROFILE") or "").strip() or None


def active_profile() -> str:
    cfg = _load()
    name = _active_profile or cfg["default_profile"]
    if name not in cfg["profiles"]:
        name = cfg["default_profile"]
    return name


def model_family(provider: str, model: str) -> str:
    """Coarse family used for the validator-independence rule.

    Cloud providers are their own family; local/OpenRouter models are grouped
    by weight lineage (llama, qwen, mistral, gemma, deepseek, ...)."""
    provider = (provider or "none").strip().lower()
    if provider in ("openai", "anthropic", "google"):
        return provider
    if provider in ("ollama", "openrouter"):
        name = (model or "").lower()
        for fam in ("llama", "codellama", "qwen", "mistral", "mixtral", "gemma",
                    "deepseek", "phi", "gemini", "claude", "gpt"):
            if fam in name:
                return {"mixtral": "mistral", "codellama": "llama"}.get(fam, fam)
        base = name.split(":")[0].split("/")[0] or provider
        return f"{provider}:{base}"
    return provider


def _ollama_base() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")


def _ollama_up() -> bool:
    global _ollama_ok
    if _ollama_ok is not None:
        return _ollama_ok
    root = _ollama_base()
    if root.endswith("/v1"):
        root = root[:-3]
    try:
        with urllib.request.urlopen(root + "/api/tags", timeout=1.5):
            _ollama_ok = True
    except Exception:
        _ollama_ok = False
    return _ollama_ok


def available(provider: str) -> bool:
    provider = (provider or "none").strip().lower()
    if provider == "none":
        return True
    if provider == "openai":
        return bool(os.environ.get("OPENAI_API_KEY"))
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if provider == "google":
        return bool(os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"))
    if provider == "openrouter":
        return bool(os.environ.get("OPENROUTER_API_KEY"))
    if provider == "ollama":
        return _ollama_up()
    return False


def resolve_role(role: str, profile: str | None = None) -> dict:
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")
    cfg = _load()
    pname = profile or active_profile()
    base = dict((cfg["profiles"].get(pname) or {}).get(role)
                or (BUILTIN_PROFILES["hybrid"].get(role) or {}))
    env = f"HYDRAMIND_{role.upper()}_"
    provider = (os.environ.get(env + "PROVIDER", "").strip().lower()
                or str(base.get("provider") or "none").lower())
    model = (os.environ.get(env + "MODEL", "").strip()
             or str(base.get("model") or "").strip())
    if role == "validator":
        provider = (os.environ.get("HYDRAMIND_VALIDATOR_PROVIDER", "").strip().lower()
                    or provider)
        model = os.environ.get("HYDRAMIND_VALIDATOR_MODEL", "").strip() or model
    if role == "reasoner":
        model = os.environ.get("HYDRAMIND_REASONER_MODEL", "").strip() or model
    if not model and provider in DEFAULT_MODELS:
        model = DEFAULT_MODELS[provider]
    return {"role": role, "profile": pname, "provider": provider,
            "model": model, "family": model_family(provider, model)}


def _ensure_available(cfg: dict, prefer_diff_family: str | None = None) -> dict:
    """Fallback to another *available* provider; prefer a different family."""
    if cfg["provider"] == "none" or available(cfg["provider"]):
        return cfg
    alts = [p for p in ("anthropic", "google", "openai", "openrouter", "ollama")
            if available(p)]
    alts.sort(key=lambda p: model_family(p, DEFAULT_MODELS.get(p, ""))
              == prefer_diff_family)
    if not alts:
        return {**cfg, "provider": "none", "model": "", "family": "none"}
    provider = alts[0]
    model = DEFAULT_MODELS.get(provider, "")
    return {**cfg, "provider": provider, "model": model,
            "family": model_family(provider, model),
            "fallback_from": cfg["provider"]}


def resolve_validator(profile: str | None = None) -> dict:
    """Validator config + computed independence against the active reasoner."""
    reasoner = resolve_role("reasoner", profile)
    cfg = _ensure_available(resolve_role("validator", profile), reasoner["family"])
    cfg["same_family"] = (cfg["provider"] != "none"
                          and cfg["family"] == reasoner["family"])
    cfg["reasoner_family"] = reasoner["family"]
    return cfg


def role_summary(profile: str | None = None) -> str:
    parts = []
    for role in ROLES:
        cfg = (resolve_validator(profile) if role == "validator"
               else resolve_role(role, profile))
        if cfg["provider"] == "none":
            parts.append(f"{role}=off")
        elif not available(cfg["provider"]):
            parts.append(f"{role}={cfg['provider']}/{cfg['model']} (unavailable)")
        else:
            parts.append(f"{role}={cfg['provider']}/{cfg['model']}")
    return f"[models] profile {profile or active_profile()} · " + " · ".join(parts)


def _client(provider: str):
    from openai import OpenAI
    if provider in _clients:
        return _clients[provider]
    if provider == "openai":
        client = OpenAI(timeout=90.0)
    elif provider == "openrouter":
        client = OpenAI(base_url="https://openrouter.ai/api/v1",
                        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
                        timeout=90.0,
                        default_headers={"X-Title": "HydraMind"})
    elif provider == "ollama":
        client = OpenAI(base_url=_ollama_base(), api_key="ollama", timeout=180.0)
    else:
        raise RuntimeError(f"no OpenAI-compatible client for {provider}")
    _clients[provider] = client
    return client


def _openai_compatible(cfg: dict, system: str, user: str, temperature: float,
                       json_mode: bool, max_tokens: int | None):
    kwargs = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": temperature,
    }
    if max_tokens:
        kwargs["max_tokens"] = max_tokens
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    try:
        response = _client(cfg["provider"]).chat.completions.create(**kwargs)
    except Exception:
        if not (json_mode and cfg["provider"] == "ollama"):
            raise
        kwargs.pop("response_format", None)  # older Ollama: prompt handles JSON
        response = _client(cfg["provider"]).chat.completions.create(**kwargs)
    text = response.choices[0].message.content or ""
    usage = getattr(response, "usage", None)
    return (text, cfg["model"],
            getattr(usage, "prompt_tokens", None),
            getattr(usage, "completion_tokens", None))


def _anthropic(cfg: dict, system: str, user: str, temperature: float,
               max_tokens: int | None):
    import requests
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": cfg["model"], "max_tokens": max_tokens or 1024,
              "temperature": temperature, "system": system,
              "messages": [{"role": "user", "content": user}]},
        timeout=90,
    )
    response.raise_for_status()
    data = response.json()
    blocks = data.get("content") or []
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    usage = data.get("usage") or {}
    return text, cfg["model"], usage.get("input_tokens"), usage.get("output_tokens")


def _google(cfg: dict, system: str, user: str, temperature: float,
            json_mode: bool, max_tokens: int | None):
    import requests
    key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    models = [cfg["model"]] + [m for m in GOOGLE_FALLBACK_MODELS
                               if m != cfg["model"]]
    last_error: Exception | None = None
    for name in models:
        try:
            generation = {"temperature": temperature}
            if json_mode:
                generation["responseMimeType"] = "application/json"
            if max_tokens:
                generation["maxOutputTokens"] = max_tokens
            response = requests.post(
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{name}:generateContent",
                params={"key": key},
                json={"systemInstruction": {"parts": [{"text": system}]},
                      "contents": [{"role": "user", "parts": [{"text": user}]}],
                      "generationConfig": generation},
                timeout=90,
            )
            response.raise_for_status()
            data = response.json()
            cands = data.get("candidates") or []
            parts = (cands[0].get("content", {}).get("parts") or []) if cands else []
            text = "".join(p.get("text", "") for p in parts)
            if text.strip():
                usage = data.get("usageMetadata") or {}
                return (text, name, usage.get("promptTokenCount"),
                        usage.get("candidatesTokenCount"))
            last_error = RuntimeError(f"{name}: empty response")
        except Exception as e:
            last_error = e
    raise RuntimeError(redact(last_error))


_TRANSIENT = ("429", "500", "502", "503", "504", "timed out", "timeout",
              "connection", "temporarily")


def _dispatch(cfg: dict, system: str, user: str, temperature: float,
              json_mode: bool, max_tokens: int | None):
    provider = cfg["provider"]
    if provider in ("openai", "openrouter", "ollama"):
        return _openai_compatible(cfg, system, user, temperature, json_mode, max_tokens)
    if provider == "anthropic":
        return _anthropic(cfg, system, user, temperature, max_tokens)
    if provider == "google":
        return _google(cfg, system, user, temperature, json_mode, max_tokens)
    raise RuntimeError(f"unsupported provider: {provider}")


def chat(role: str, system: str, user: str, *, temperature: float = 0.2,
         json_mode: bool = False, scan_id: int | None = None,
         max_tokens: int | None = None, role_cfg: dict | None = None) -> ModelReply:
    cfg = role_cfg or resolve_role(role)
    if cfg["provider"] == "none":
        raise RuntimeError(f"no model configured for role '{role}' "
                           f"(profile {cfg['profile']})")
    if not available(cfg["provider"]):
        raise RuntimeError(f"{cfg['provider']} is not available for role "
                           f"'{role}' (missing key or unreachable)")
    prompt_hash = hashlib.sha256(
        (system + "\n" + user).encode("utf-8", "replace")).hexdigest()[:16]
    started = time.monotonic()
    try:
        try:
            text, used_model, tin, tout = _dispatch(
                cfg, system, user, temperature, json_mode, max_tokens)
        except Exception as e:
            if not any(t in str(e).lower() for t in _TRANSIENT):
                raise
            time.sleep(2)
            text, used_model, tin, tout = _dispatch(
                cfg, system, user, temperature, json_mode, max_tokens)
    except Exception as e:
        latency = int((time.monotonic() - started) * 1000)
        _log(scan_id, role, cfg, cfg["model"], prompt_hash, latency,
             None, None, "", e)
        raise
    latency = int((time.monotonic() - started) * 1000)
    _log(scan_id, role, cfg, used_model, prompt_hash, latency,
         tin, tout, text, None)
    return ModelReply(text=text, role=role, profile=cfg["profile"],
                      provider=cfg["provider"], model=used_model,
                      latency_ms=latency, tokens_in=tin, tokens_out=tout)


def _log(scan_id, role, cfg, used_model, prompt_hash, latency,
         tin, tout, text, error) -> None:
    try:
        from engine import db
        db.log_model_call(scan_id, role, cfg["profile"], cfg["provider"],
                          used_model, prompt_hash, latency, tin, tout,
                          redact(text)[:4000], redact(error) if error else "")
    except Exception as e:  # logging must never break a scan
        print(f"[models] warning: could not log {role} call: {e}")
