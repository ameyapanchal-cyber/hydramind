#!/usr/bin/env python3
"""Phase 4 tests — validator parsing/provider selection, report rendering,
eval scoring, and DB round-trips. Plain asserts, no test framework:

    python tests/test_phase4.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import db, reporter, validator  # noqa: E402

PASS = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS
    if not condition:
        print(f"FAIL {name} {detail}")
        raise SystemExit(1)
    PASS += 1
    print(f"ok   {name}")


def test_validator_parsing() -> None:
    ok = validator.parse_validation_response(
        '```json\n{"verdict":"confirmed","severity":"high","confidence":1.7,'
        '"rationale":"sqlmap listed id","remediation":"parameterize"}\n```',
        "anthropic", "claude-test", False)
    check("validator: fenced JSON parsed", ok.verdict == "confirmed")
    check("validator: severity uppercased", ok.severity == "HIGH")
    check("validator: confidence clamped", ok.confidence == 1.0)
    check("validator: same_family flag", ok.same_family is False)

    syn = validator.parse_validation_response(
        '{"verdict":"false-positive","severity":"nonsense","confidence":"x"}',
        "openai", "gpt-test", True, fallback_severity="MEDIUM")
    check("validator: verdict synonym", syn.verdict == "false_positive")
    check("validator: severity fallback", syn.severity == "MEDIUM")
    check("validator: confidence fallback", syn.confidence == 0.0)

    bad = validator.parse_validation_response("not json at all", "google", "gem", False)
    check("validator: unparseable -> needs_review", bad.verdict == "needs_review")

    partial = validator.parse_validation_response(
        'some text {"verdict": "likely", "severity": "LOW"} trailing',
        "google", "gem", False)
    check("validator: JSON extracted from prose", partial.verdict == "likely")

    leaked = validator._redact(
        "404 for https://api.example/v1?key=AQ.SECRET123&x=1 api_key=SECRET456")
    check("validator: API key redacted from errors",
          "SECRET123" not in leaked and "SECRET456" not in leaked
          and "REDACTED" in leaked)
    check("validator: gemini fallback chain present",
          len(validator.GOOGLE_FALLBACK_MODELS) >= 2
          and validator.DEFAULT_MODELS["google"] not in validator.GOOGLE_FALLBACK_MODELS)


def test_provider_selection() -> None:
    saved = {k: os.environ.pop(k, None)
             for k in ("ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
                       "OPENAI_API_KEY", "HYDRAMIND_VALIDATOR_PROVIDER",
                       "HYDRAMIND_VALIDATOR_MODEL")}
    try:
        cfg = validator.provider_config()
        check("provider: none without keys", cfg["provider"] == "none")

        os.environ["OPENAI_API_KEY"] = "x"
        cfg = validator.provider_config()
        check("provider: openai fallback", cfg["provider"] == "openai")
        check("provider: openai flagged same-family", cfg["same_family"] is True)

        os.environ["ANTHROPIC_API_KEY"] = "x"
        cfg = validator.provider_config()
        check("provider: anthropic wins", cfg["provider"] == "anthropic")
        check("provider: anthropic not same-family", cfg["same_family"] is False)

        os.environ["HYDRAMIND_VALIDATOR_PROVIDER"] = "google"
        os.environ["GOOGLE_API_KEY"] = "x"
        cfg = validator.provider_config()
        check("provider: explicit override", cfg["provider"] == "google")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _seed_temp_db(path: Path) -> int:
    old = db.DB_PATH
    db.DB_PATH = path
    db.init_db()
    scan_id = db.new_scan("127.0.0.1", "phase4-test")
    db.save_findings(scan_id, "sqlmap", [
        {"detail": "Parameter: id (GET) Type: boolean-based blind"}])
    triage_ids = db.save_triage_findings(scan_id, [
        {"rank": 1, "severity": "HIGH", "source": "user",
         "finding": "Potential SQL injection <script>alert(1)</script>",
         "why": "id is injectable", "next_step": "run sqlmap"},
        {"rank": 2, "severity": "LOW", "source": "nikto",
         "finding": "403 restricted", "why": "blocked", "next_step": "none"},
    ])
    db.log_reasoner_decision(
        triage_ids[0], "id is injectable", "sqlmap -u 'http://127.0.0.1/x' --batch",
        0.9, "exploit", "approved", executed=True, result="rc=0, 1 finding(s)")
    db.log_reasoner_decision(
        triage_ids[1], "restricted", "curl -s http://127.0.0.1/x/.htpasswd",
        0.4, "active", "rejected", rejection_reason="403 already blocked")
    db.log_action(scan_id, 1, "sqlmap", "exploit", "test", True, True, "rc=0")
    db.save_validation(scan_id, triage_ids[0], "sqlmap", "Potential SQL injection",
                       "confirmed", "HIGH", 0.95, "sqlmap evidence", "parameterize",
                       "openai", "gpt-4o", True)
    db.log_scope_event("127.0.0.1", "recon", True, "")
    db.DB_PATH = old
    return scan_id


def test_reporter() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        old = db.DB_PATH
        scan_id = _seed_temp_db(tmp_path / "test.db")
        try:
            db.DB_PATH = tmp_path / "test.db"
            data = reporter.build_report_data(scan_id)
            check("report: scan loaded", data["scan"]["target"] == "127.0.0.1")
            check("report: triage loaded", len(data["triage"]) == 2)
            check("report: executed counted", data["executed_count"] == 1)
            check("report: verdict counted", data["verdict_counts"]["confirmed"] == 1)

            md = reporter.render_markdown(data)
            check("report: markdown title", "# HydraMind" in md)
            check("report: markdown evidence", "sqlmap" in md and "confirmed" in md)
            check("report: markdown scope events", "scope firewall" in md.lower())

            html = reporter.render_html(data)
            check("report: html doctype", html.startswith("<!doctype html>"))
            check("report: html escapes script", "&lt;script&gt;" in html
                  and "<script>alert(1)</script>" not in html)
            check("report: html verdict", "confirmed" in html)

            paths = reporter.write_reports(scan_id, out_dir=tmp_path / "reports")
            check("report: files written",
                  Path(paths["markdown"]).exists() and Path(paths["html"]).exists())
        finally:
            db.DB_PATH = old


def test_clear_validations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        old = db.DB_PATH
        scan_id = _seed_temp_db(tmp_path / "test.db")
        try:
            db.DB_PATH = tmp_path / "test.db"
            check("db: validation saved", len(db.validations_for_scan(scan_id)) == 1)
            db.clear_validations(scan_id)
            check("db: validations cleared", db.validations_for_scan(scan_id) == [])
        finally:
            db.DB_PATH = old


def test_eval_scoring() -> None:
    spec = importlib.util.spec_from_file_location(
        "run_eval", ROOT / "eval" / "run_eval.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    lab = {"expect": {"tools": ["sqlmap"], "keywords": ["injection"]}}
    full = mod._score(lab, [{"exact_tool_and_command": "sqlmap -u x",
                             "attack_hypothesis": "SQL injection",
                             "expected_outcome": "id injectable"}])
    check("eval: full score", full["score"] == 1.0)
    tool_only = mod._score(lab, [{"exact_tool_and_command": "sqlmap -u x",
                                  "attack_hypothesis": "maybe db",
                                  "expected_outcome": "test"}])
    check("eval: tool-only score", tool_only["score"] == 0.5)
    miss = mod._score(lab, [{"exact_tool_and_command": "curl -s x",
                             "attack_hypothesis": "fetch", "expected_outcome": "body"}])
    check("eval: miss score", miss["score"] == 0.0)


def main() -> int:
    test_validator_parsing()
    test_provider_selection()
    test_reporter()
    test_clear_validations()
    test_eval_scoring()
    print(f"\n{PASS} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
