#!/usr/bin/env python3
"""Phase 6 tests — CVE/ExploitDB RAG, routing policies, prompt grounding and
the LangGraph review agent. Plain asserts, no test framework:

    python tests/test_phase6.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import agent, db, models, rag, routing  # noqa: E402
from engine.findings import Finding  # noqa: E402
from engine.reasoner import ReasonerOutput  # noqa: E402
from engine import reasoner, triager  # noqa: E402

PASS = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS
    if not condition:
        print(f"FAIL {name} {detail}")
        raise SystemExit(1)
    PASS += 1
    print(f"ok   {name}")


def test_rag() -> None:
    stats = rag.stats()
    check("rag: corpus loaded", stats["documents"] >= 25, str(stats))
    apache = rag.retrieve("Apache httpd 2.4.49 path traversal", k=3)
    ids = [d["id"] for d in apache]
    check("rag: Apache CVE ranked", "CVE-2021-41773" in ids
          or "EDB-50383" in ids, str(ids))
    check("rag: version boost applied", apache[0]["score"] > 10)
    redis = rag.retrieve("redis-cli 127.0.0.1:6379 unauthenticated INFO", k=3)
    check("rag: Redis advisory top", redis and redis[0]["id"] == "ADV-REDIS-UNAUTH")
    check("rag: relative cutoff drops noise",
          all(d["id"] != "ADV-JENKINS-SCRIPT" for d in redis))
    check("rag: unrelated query empty",
          rag.retrieve("zzzz qqqq xxxx", k=3) == [])
    block = rag.context_block(apache)
    check("rag: context cites R1", "[R1]" in block and "never invent" in block.lower())
    check("rag: finding lookup", rag.retrieve_for_finding(
        {"title": "Apache 2.4.49 on port 8080", "detail": "CVE-2021-41773"}, k=1))

    old = os.environ.get("HYDRAMIND_RAG")
    os.environ["HYDRAMIND_RAG"] = "0"
    try:
        check("rag: disabled by env", rag.retrieve("Apache 2.4.49") == [])
    finally:
        if old is None:
            os.environ.pop("HYDRAMIND_RAG", None)
        else:
            os.environ["HYDRAMIND_RAG"] = old

    with tempfile.TemporaryDirectory() as td:
        extra = Path(td) / "extra.jsonl"
        extra.write_text(json.dumps({
            "id": "TEST-9000", "title": "Unique zxqmarker service bug",
            "products": ["zxqmarker"], "versions": ["1.2.3"],
            "severity": "high", "description": "zxqmarker RCE proof",
            "tags": ["rce"], "references": []}) + "\n")
        old = os.environ.get("HYDRAMIND_RAG_EXTRA")
        os.environ["HYDRAMIND_RAG_EXTRA"] = str(extra)
        rag.reload()
        try:
            hits = rag.retrieve("zxqmarker 1.2.3", k=2)
            check("rag: extra corpus loaded", hits and hits[0]["id"] == "TEST-9000")
        finally:
            if old is None:
                os.environ.pop("HYDRAMIND_RAG_EXTRA", None)
            else:
                os.environ["HYDRAMIND_RAG_EXTRA"] = old
            rag.reload()


def test_routing() -> None:
    os.environ.pop("HYDRAMIND_ROUTING", None)
    routing.reload()
    base, decision = routing.resolve("reasoner", {"severity": "CRITICAL"})
    check("routing: disabled uses profile", decision["policy"] == "profile"
          and base["model"] == "gpt-4o")
    check("routing: validator never routed",
          routing.resolve("validator", {"severity": "HIGH"})[1]["policy"] == "profile")

    os.environ["HYDRAMIND_ROUTING"] = "1"
    routing.reload()
    deep, d1 = routing.resolve("reasoner", {"severity": "HIGH"})
    cheap, d2 = routing.resolve("reasoner", {"severity": "LOW"})
    ragdeep, d3 = routing.resolve("reasoner", {"severity": "MEDIUM", "rag_score": 9})
    bulk, d4 = routing.resolve("triager", {"finding_count": 50})
    normal, d5 = routing.resolve("triager", {"finding_count": 5})
    check("routing: high severity -> deep tier", d1["policy"] == "deep-critical-high"
          and deep["model"] == "gpt-4o")
    check("routing: low severity -> cheap tier", d2["policy"] == "cheap-low-severity"
          and cheap["model"] == "gpt-4o-mini")
    check("routing: RAG score -> deep tier", d3["policy"] == "deep-exploit-context")
    check("routing: bulk triage -> cheap tier", d4["policy"] == "cheap-bulk-triage"
          and bulk["model"] == "gpt-4o-mini")
    check("routing: normal triage stays profile", d5["policy"] == "profile"
          and normal["model"] == "gpt-4o-mini")
    check("routing: config tiers exist", models.resolve_tier("deep") is not None
          and models.resolve_tier("missing") is None)

    with tempfile.TemporaryDirectory() as td:
        custom = Path(td) / "routing.yaml"
        custom.write_text("""
enabled: true
rules:
  - name: explicit-custom
    role: reasoner
    when: {severity: [critical]}
    use: {provider: ollama, model: mistral:7b}
""")
        old = os.environ.get("HYDRAMIND_ROUTING_FILE")
        os.environ["HYDRAMIND_ROUTING_FILE"] = str(custom)
        routing.reload()
        try:
            cfg, dec = routing.resolve("reasoner", {"severity": "CRITICAL"})
            check("routing: explicit provider/model override",
                  dec["policy"] == "explicit-custom"
                  and cfg["provider"] == "ollama" and cfg["model"] == "mistral:7b")
        finally:
            if old is None:
                os.environ.pop("HYDRAMIND_ROUTING_FILE", None)
            else:
                os.environ["HYDRAMIND_ROUTING_FILE"] = old
            routing.reload()

    with tempfile.TemporaryDirectory() as td:
        unsafe = Path(td) / "routing.yaml"
        unsafe.write_text("""
enabled: true
rules:
  - name: collides-with-validator
    role: reasoner
    when: {severity: [critical]}
    use: {provider: google, model: gemini-flash-latest}
""")
        old = os.environ.get("HYDRAMIND_ROUTING_FILE")
        os.environ["HYDRAMIND_ROUTING_FILE"] = str(unsafe)
        routing.reload()
        try:
            cfg, dec = routing.resolve("reasoner", {"severity": "CRITICAL"})
            check("routing: validator-family collision skipped",
                  dec["policy"] == "profile" and cfg["provider"] == "openai")
        finally:
            if old is None:
                os.environ.pop("HYDRAMIND_ROUTING_FILE", None)
            else:
                os.environ["HYDRAMIND_ROUTING_FILE"] = old
            routing.reload()
    os.environ.pop("HYDRAMIND_ROUTING", None)
    routing.reload()


def test_prompts() -> None:
    captured = {}
    real_chat = models.chat

    def fake_chat(role, system, user, **kwargs):
        captured.update({"role": role, "system": system, "user": user, **kwargs})
        if role == "triager":
            text = json.dumps({"ranked_findings": [], "summary": "fake"})
        else:
            text = json.dumps({
                "attack_hypothesis": "uses [R1]", "exact_tool_and_command":
                "curl -s --path-as-is 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/etc/passwd'",
                "expected_outcome": "passwd content", "confidence": 0.8,
                "risk_level": "active"})
        return SimpleNamespace(text=text)

    models.chat = fake_chat
    try:
        triager.triage({"nmap": [{"port": 8080, "service": "http",
                                  "product": "Apache httpd", "version": "2.4.49",
                                  "detail": "Apache httpd 2.4.49"}]})
        user = captured["user"]
        check("triager: reference block injected", "[R1]" in user)
        check("triager: Apache CVE grounded", "CVE-2021-41773" in user)
        check("triager: routing config passed", captured.get("role_cfg")
              and captured["role_cfg"]["provider"] == "openai")

        out = reasoner.reason_about_finding(
            Finding(tool="nmap", target="127.0.0.1", severity="HIGH",
                    title="Apache 2.4.49", description="Apache httpd 2.4.49"),
            {"target": "127.0.0.1", "sibling_findings": [], "action_history": []})
        user = captured["user"]
        check("reasoner: reference block injected", "[R1]" in user)
        check("reasoner: CVE grounded", "CVE-2021-41773" in user)
        check("reasoner: role_cfg supplied", captured.get("role_cfg") is not None)
        check("reasoner: output parsed", out.risk_level == "active")
    finally:
        models.chat = real_chat
        os.environ.pop("HYDRAMIND_ROUTING", None)
        routing.reload()


def seed_scan() -> int:
    scan_id = db.new_scan("127.0.0.1", "phase6")
    db.save_findings(scan_id, "nmap", [
        {"host": "127.0.0.1", "port": 8080, "protocol": "tcp",
         "service": "http", "product": "Apache httpd", "version": "2.4.49"}])
    db.save_triage_findings(scan_id, [
        {"rank": 1, "severity": "HIGH", "source": "nmap",
         "finding": "Apache httpd 2.4.49 on port 8080/tcp",
         "why": "CVE-2021-41773 path traversal", "next_step": "test traversal"},
        {"rank": 2, "severity": "LOW", "source": "gobuster",
         "finding": "/robots.txt", "why": "minor info", "next_step": "fetch"},
    ])
    return scan_id


def test_agent(tmp: Path) -> None:
    scan_id = seed_scan()
    before = len(db.validations_for_scan(scan_id))
    real = agent.reason_about_finding
    real_can = agent._can_reason
    agent._can_reason = lambda cfg: True
    agent.reason_about_finding = lambda finding, context, scan_id=None, role_cfg=None: (
        ReasonerOutput(
            attack_hypothesis="grounded by [R1]",
            exact_tool_and_command="curl -s --path-as-is "
            "'http://127.0.0.1:8080/icons/.%2e/%2e%2e/etc/passwd'",
            expected_outcome="passwd", confidence=0.8, risk_level="active"))
    try:
        out = tmp / "plan.json"
        state = agent.run(scan_id, max_findings=5, max_deep=2, output=str(out))
        result = state.get("result") or {}
        check("agent: graph produced result", bool(result) and out.exists())
        check("agent: one deep review for HIGH finding",
              result["counts"]["deep_reviews"] == 1)
        check("agent: quick review for LOW finding",
              result["counts"]["quick"] == 1)
        check("agent: proposal safety-checked",
              result["findings"][0]["command_safe"] is True)
        check("agent: RAG refs attached",
              any(r["id"] == "CVE-2021-41773" or r["id"] == "EDB-50383"
                  for r in result["findings"][0]["references"]))
        check("agent: DB unchanged",
              len(db.validations_for_scan(scan_id)) == before)
        saved = json.loads(out.read_text())
        check("agent: plan JSON written", saved["counts"]["deep_reviews"] == 1
              and saved["executes"] is False)
        check("agent: notes never executed", "not executed" in saved["note"].lower())

        agent.reason_about_finding = lambda *a, **k: ReasonerOutput(
            attack_hypothesis="bad", exact_tool_and_command=
            "curl -o /tmp/stolen http://127.0.0.1:8080/",
            expected_outcome="x", confidence=0.4, risk_level="active")
        unsafe = agent.run(scan_id, max_findings=1, max_deep=1,
                           output=str(tmp / "unsafe.json"))
        check("agent: unsafe command rejected",
              unsafe["result"]["counts"]["unsafe_commands"] == 1)

        capped = agent.run(scan_id, max_findings=5, max_deep=0,
                           output=str(tmp / "capped.json"))
        check("agent: deep cap enforced",
              capped["result"]["counts"]["deep_reviews"] == 0)

        missing = agent.run(99999)
        check("agent: missing scan errors", missing.get("error")
              and missing.get("result", {}).get("error"))
    finally:
        agent.reason_about_finding = real
        agent._can_reason = real_can


def main() -> int:
    old_db = db.DB_PATH
    os.environ.pop("HYDRAMIND_N8N_WEBHOOK", None)
    with tempfile.TemporaryDirectory() as td:
        db.DB_PATH = Path(td) / "test.db"
        db.init_db()
        test_rag()
        test_routing()
        test_prompts()
        test_agent(Path(td))
        db.DB_PATH = old_db
    print(f"\n{PASS} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
