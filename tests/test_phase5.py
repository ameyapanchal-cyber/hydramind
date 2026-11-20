#!/usr/bin/env python3
"""Phase 5 tests — n8n notifier, dashboard data layer, HTTP server, workflow
template. Plain asserts, no test framework:

    python tests/test_phase5.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard as web  # noqa: E402
from engine import dashboard as dash  # noqa: E402
from engine import db, notifier  # noqa: E402

PASS = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS
    if not condition:
        print(f"FAIL {name} {detail}")
        raise SystemExit(1)
    PASS += 1
    print(f"ok   {name}")


def seed() -> tuple[int, int]:
    scan_id = db.new_scan("10.0.0.5", "phase4")
    db.save_findings(scan_id, "nmap", [
        {"host": "10.0.0.5", "port": 80, "protocol": "tcp",
         "service": "http", "product": "Apache", "version": "2.4.49"}])
    db.save_findings(scan_id, "gobuster", [
        {"path": "/admin", "status": 200, "size": 1234, "detail": "http://10.0.0.5/admin"}])
    finding_ids = db.save_triage_findings(scan_id, [
        {"rank": 1, "severity": "HIGH", "source": "nmap",
         "finding": "Apache 2.4.49 path traversal (CVE-2021-41773)",
         "why": "known CVE", "next_step": "curl traversal"}])
    db.log_reasoner_decision(finding_ids[0], "traversal works", "curl http://10.0.0.5/",
                             0.9, "LOW", "approved", executed=True,
                             result="root:x:0:0")
    db.save_validation(scan_id, finding_ids[0], "nmap",
                       "Apache 2.4.49 path traversal", "confirmed", "HIGH",
                       0.92, "curl output matches CVE", "upgrade", "google",
                       "gemini-test", same_family=False)
    db.log_model_call(scan_id, "triager", "hybrid", "openai", "gpt-4o-mini",
                      "abc123", 1200, 500, 120, response="{}")
    return scan_id, finding_ids[0]


def test_sanitize() -> None:
    clean = notifier._sanitize({
        "target": "http://10.0.0.5",
        "cookie": "PHPSESSID=secret123",
        "api_key": "sk-ABCDEFGH12345678",
        "nested": [{"token": "tok", "note": "failed https://x/v1?key=AQ.SECRET"}],
        "count": 3,
    })
    check("notifier: cookie key redacted", clean["cookie"] == "[redacted]")
    check("notifier: api_key key redacted", clean["api_key"] == "[redacted]")
    check("notifier: nested token redacted", clean["nested"][0]["token"] == "[redacted]")
    check("notifier: key= stripped from strings",
          "AQ.SECRET" not in clean["nested"][0]["note"])
    check("notifier: harmless fields kept", clean["target"] == "http://10.0.0.5"
          and clean["count"] == 3)


class _Capture(BaseHTTPRequestHandler):
    received: list[dict] = []

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.__class__.received.append(json.loads(body))
        self.send_response(204)
        self.end_headers()


def test_emit() -> None:
    old_env = os.environ.pop("HYDRAMIND_N8N_WEBHOOK", None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/webhook/hydramind"
    try:
        notifier.configure(webhook=url)
        ok = notifier.emit("scan_started", {
            "scan_id": 7, "target": "10.0.0.5", "cookie": "PHPSESSID=abc"})
        check("notifier: POST returns True", ok is True)
        check("notifier: event delivered", len(_Capture.received) == 1)
        payload = _Capture.received[0]
        check("notifier: envelope fields",
              payload["source"] == "hydramind"
              and payload["event"] == "scan_started"
              and payload["data"]["scan_id"] == 7
              and bool(payload["timestamp"]))
        check("notifier: cookie redacted in payload",
              payload["data"]["cookie"] == "[redacted]")

        notifier.configure(webhook="http://127.0.0.1:1/none", enabled=True)
        check("notifier: unreachable webhook is non-fatal",
              notifier.emit("scan_finished", {"scan_id": 7}) is False)
        notifier.configure(enabled=False)
        check("notifier: --no-notify disables sending",
              notifier.emit("scan_finished", {"scan_id": 7}) is False)
    finally:
        notifier.configure(webhook=None, enabled=True)
        server.shutdown()
        server.server_close()
        if old_env is not None:
            os.environ["HYDRAMIND_N8N_WEBHOOK"] = old_env


def test_counts_and_dashboard(scan_id: int) -> None:
    counts = notifier.counts(scan_id)
    check("notifier: raw finding count", counts["raw_findings"] == 2)
    check("notifier: triage count", counts["triage_findings"] == 1)
    check("notifier: executed action count", counts["executed_actions"] == 1)
    check("notifier: validation count", counts["validations"] == 1)
    check("notifier: verdict breakdown", counts["verdicts"] == {"confirmed": 1})

    data = dash.overview()
    check("dashboard: overview ok", data["ok"] is True)
    scan = next(s for s in data["scans"] if s["id"] == scan_id)
    check("dashboard: scan row counts",
          scan["raw_findings"] == 2 and scan["triage_findings"] == 1
          and scan["executed_actions"] == 1 and scan["confirmed"] == 1)
    check("dashboard: profile from model calls", scan["profile"] == "hybrid")
    check("dashboard: totals", data["totals"]["confirmed"] == 1
          and data["totals"]["model_calls"] == 1)
    check("dashboard: recent model call", data["recent_calls"][0]["role"] == "triager")
    check("dashboard: scope event logged", len(data["scope_events"]) == 0)

    detail = dash.scan_detail(scan_id)
    check("dashboard: detail ok", detail["ok"] is True)
    check("dashboard: validations present", len(detail["validations"]) == 1)
    check("dashboard: decisions present", len(detail["decisions"]) == 1)
    check("dashboard: missing scan 404", dash.scan_detail(99999)["ok"] is False)
    check("dashboard: health", dash.health()["ok"] is True)


def test_safe_report(tmp: Path) -> None:
    reports = tmp / "reports"
    reports.mkdir()
    (reports / "report_1.md").write_text("# report\n")
    (reports / "report_1.html").write_text("<h1>report</h1>")
    (reports / "notes.txt").write_text("private")
    old = dash.REPORTS_DIR
    dash.REPORTS_DIR = reports
    try:
        check("dashboard: markdown report resolved",
              dash.safe_report("report_1.md") is not None)
        check("dashboard: traversal rejected",
              dash.safe_report("../../etc/passwd") is None)
        check("dashboard: arbitrary name rejected",
              dash.safe_report("notes.txt") is None)
        check("dashboard: missing report rejected",
              dash.safe_report("report_2.md") is None)
    finally:
        dash.REPORTS_DIR = old


def _get(url: str) -> tuple[int, bytes, str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "")


def test_http(scan_id: int, tmp: Path) -> None:
    old = dash.REPORTS_DIR
    dash.REPORTS_DIR = tmp / "reports"
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    server.verbose = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, body, ctype = _get(base + "/")
        check("http: index served", status == 200 and b"HydraMind" in body
              and "text/html" in ctype)
        status, body, _ = _get(base + "/api/health")
        check("http: health API", status == 200 and json.loads(body)["ok"] is True)
        status, body, _ = _get(base + "/api/overview")
        overview = json.loads(body)
        check("http: overview API", status == 200 and overview["ok"] is True
              and len(overview["scans"]) == 1)
        status, body, _ = _get(base + f"/api/scan/{scan_id}")
        check("http: scan detail API", status == 200
              and json.loads(body)["scan"]["id"] == scan_id)
        status, body, ctype = _get(base + "/reports/report_1.md")
        check("http: report served", status == 200 and b"# report" in body
              and "text/markdown" in ctype)
        status, _, _ = _get(base + "/reports/..%2F..%2Fetc%2Fpasswd")
        check("http: report traversal blocked", status == 404)
        status, _, _ = _get(base + "/api/scan/nope")
        check("http: bad scan id -> 400", status == 400)
        status, _, _ = _get(base + "/nope")
        check("http: unknown path -> 404", status == 404)
    finally:
        server.shutdown()
        server.server_close()
        dash.REPORTS_DIR = old


def test_workflow() -> None:
    path = ROOT / "integrations" / "n8n" / "hydramind_notify.json"
    workflow = json.loads(path.read_text())
    names = {n["name"] for n in workflow["nodes"]}
    check("n8n: workflow imports as JSON", workflow["name"] == "HydraMind notify")
    check("n8n: webhook + code + sink nodes",
          {"HydraMind webhook", "Format message",
           "Send notification (replace me)"} <= names)
    webhook = next(n for n in workflow["nodes"]
                   if n["name"] == "HydraMind webhook")
    check("n8n: POST /hydramind", webhook["parameters"]["path"] == "hydramind"
          and webhook["parameters"]["httpMethod"] == "POST")
    check("n8n: nodes connected", len(workflow["connections"]) == 2)


def main() -> int:
    old_db = db.DB_PATH
    old_reports = dash.REPORTS_DIR
    with tempfile.TemporaryDirectory() as td:
        db.DB_PATH = Path(td) / "test.db"
        db.init_db()
        scan_id, _ = seed()
        test_sanitize()
        test_emit()
        test_counts_and_dashboard(scan_id)
        test_safe_report(Path(td))
        test_http(scan_id, Path(td))
        test_workflow()
        db.DB_PATH = old_db
        dash.REPORTS_DIR = old_reports
    print(f"\n{PASS} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
