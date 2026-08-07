#!/usr/bin/env python3
"""HydraMind — Phase 1. Usage: python3 main.py --target scanme.nmap.org"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from engine.scope_firewall import ScopeFirewall, ScopeError
from engine.tools.nmap_tool import run_nmap, parse_nmap
from engine.tools.gobuster_tool import run_gobuster, parse_gobuster
from engine.tools.nikto_tool import run_nikto, parse_nikto
from engine.triager import triage
from engine import db

SCOPE_FILE = Path(__file__).resolve().parent / "config" / "scope.yaml"


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind (Phase 1)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--skip-nikto", action="store_true", help="skip nikto (slow)")
    args = ap.parse_args()

    # 1. Scope gate
    fw = ScopeFirewall(SCOPE_FILE)
    try:
        target = fw.check(args.target)
    except ScopeError as e:
        print(f"\n{e}\n"); return 1
    print(f"[scope] '{target}' authorized.\n")

    db.init_db()
    scan_id = db.new_scan(target, tool="phase1")
    all_findings = {}

    # 2. nmap
    print("[nmap] scanning ports + services...")
    result, xml_path = run_nmap(target)
    nmap_findings = parse_nmap(xml_path)
    all_findings["nmap"] = nmap_findings
    db.save_findings(scan_id, nmap_findings)
    print(f"       {len(nmap_findings)} open port(s) found.")

    # 3. gobuster (only if port 80/443 is open)
    web_ports = [f["port"] for f in nmap_findings if f["port"] in (80, 443, 8080, 8443)]
    if web_ports:
        print(f"[gobuster] web port(s) found — brute-forcing directories...")
        gb_result = run_gobuster(target)
        gb_findings = parse_gobuster(gb_result)
        all_findings["gobuster"] = gb_findings
        print(f"           {len(gb_findings)} path(s) found.")
    else:
        print("[gobuster] no web ports — skipping.")
        all_findings["gobuster"] = []

    # 4. nikto
    if web_ports and not args.skip_nikto:
        print("[nikto] scanning for web misconfigs (this can take 2-3 min)...")
        nk_result = run_nikto(target)
        nk_findings = parse_nikto(nk_result)
        all_findings["nikto"] = nk_findings
        print(f"        {len(nk_findings)} finding(s).")
    else:
        all_findings["nikto"] = []

    # 5. AI Triage
    total = sum(len(v) for v in all_findings.values())
    if total == 0:
        print("\n[triager] No findings to triage. Clean result."); return 0

    print(f"\n[triager] sending {total} finding(s) to GPT-4o-mini for analysis...")
    try:
        report = triage(all_findings)
    except Exception as e:
        print(f"[triager] AI call failed: {e}"); return 1

    # 6. Print ranked report
    print("\n" + "="*60)
    print("  HYDRAMIND — TRIAGE REPORT")
    print("="*60)
    print(f"\n{report.get('summary', '')}\n")
    for item in report.get("ranked_findings", []):
        sev = item.get("severity", "?")
        print(f"[{sev}] #{item['rank']} — {item['finding']}")
        print(f"       Why: {item['why']}")
        print(f"       Next: {item['next_step']}\n")

    # Save full report as JSON
    report_path = Path("data") / f"report_{scan_id}.json"
    report_path.write_text(json.dumps({"target": target, "raw": all_findings, "triage": report}, indent=2))
    print(f"[db] full report saved → {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
