#!/usr/bin/env python3
"""AI Pentest Pipeline — Phase 0. Usage: python3 main.py --target scanme.nmap.org"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from engine.scope_firewall import ScopeFirewall, ScopeError
from engine.tools.nmap_tool import run_nmap, parse_nmap
from engine import db

SCOPE_FILE = Path(__file__).resolve().parent / "config" / "scope.yaml"


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Pentest Pipeline (Phase 0)")
    ap.add_argument("--target", required=True, help="host/IP to scan (must be in scope.yaml)")
    args = ap.parse_args()

    fw = ScopeFirewall(SCOPE_FILE)
    try:
        target = fw.check(args.target)
    except ScopeError as e:
        print(f"\n{e}\n")
        return 1
    print(f"[scope] '{target}' is authorized. Proceeding.\n")

    db.init_db()
    scan_id = db.new_scan(target, tool="nmap")
    print("[nmap] scanning (this can take a minute)...")
    result, xml_path = run_nmap(target)
    if result.timed_out:
        print("[nmap] scan timed out.")
        return 1
    if result.returncode != 0:
        print(f"[nmap] failed:\n{result.stderr}")
        return 1

    findings = parse_nmap(xml_path)
    db.save_findings(scan_id, findings)

    if not findings:
        print("[report] No open ports found. (A clean result is still a valid finding.)")
        return 0

    print(f"[report] {len(findings)} open port(s) found:\n")
    for f in findings:
        banner = " ".join(x for x in (f["product"], f["version"]) if x)
        print(f"  {f['port']}/{f['protocol']:<4} {f['service']:<12} {banner}")
    print(f"\n[db] saved to {db.DB_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
