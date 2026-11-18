#!/usr/bin/env python3
"""HydraMind — Phase 2. Usage: python3 main.py --target scanme.nmap.org

Pipeline: recon (nmap/gobuster/nikto) → AI triage → AI reasoner →
HUMAN APPROVAL GATE → execute approved actions (labs only) → report."""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from engine.scope_firewall import ScopeFirewall, ScopeError
from engine.tools.nmap_tool import run_nmap, parse_nmap
from engine.tools.gobuster_tool import run_gobuster, parse_gobuster, DEFAULT_WORDLIST
from engine.tools.nikto_tool import run_nikto, parse_nikto
from engine.triager import triage
from engine.reasoner import reason, validate_plan, KNOWN_TOOLS, PHASE3_TOOLS
from engine import db

SCOPE_FILE = Path(__file__).resolve().parent / "config" / "scope.yaml"
GOBUSTER_WORDLIST_ROOT = Path("/usr/share/wordlists")
REASONER_MODEL = os.environ.get("HYDRAMIND_REASONER_MODEL", "gpt-4o")


def _ask(msg: str, default_yes: bool) -> bool:
    """Approval prompt. Passive actions default to yes, active to NO —
    the human must type 'y' for anything risky."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        ans = input(f"  {msg} {suffix} ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes") if ans else default_yes


def _wordlist_from_args(args: list[str]) -> str:
    """Pull -w <path> out of a gobuster action; only allow Kali wordlists.
    (Both sides are resolved: /usr/share/wordlists/* are often symlinks.)"""
    for i, a in enumerate(args):
        if a == "-w" and i + 1 < len(args):
            root = GOBUSTER_WORDLIST_ROOT.resolve()
            resolved = Path(args[i + 1]).resolve()
            if resolved.is_file() and resolved.is_relative_to(root):
                return str(resolved)
            print(f"  [gate] wordlist '{args[i + 1]}' rejected — using default.")
            return DEFAULT_WORDLIST
    return DEFAULT_WORDLIST


def _execute_action(action: dict, target: str) -> tuple[list[dict], str]:
    """Run an approved action through runner.py. Returns (findings, summary)."""
    tool, args = action["tool"], action["args"]

    if tool == "nmap":
        result, xml_path = run_nmap(target, extra_args=args or None)
        findings = [] if result.timed_out else parse_nmap(xml_path)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    if tool == "gobuster":
        wordlist = _wordlist_from_args(args)
        result = run_gobuster(target, wordlist=wordlist)
        findings = parse_gobuster(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} path(s), wl={wordlist}"

    if tool == "nikto":
        result = run_nikto(target)
        findings = parse_nikto(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    return [], "not executed"


def _ai_fail_hint(e: Exception) -> str:
    msg = str(e).lower()
    if "api key" in msg or "credentials" in msg or "api_key" in msg:
        return "  (hint: export OPENAI_API_KEY=sk-...)"
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind (Phase 2)")
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
    scan_id = db.new_scan(target, tool="phase2")
    all_findings = {}

    # 2. nmap
    print("[nmap] scanning ports + services...")
    result, xml_path = run_nmap(target)
    nmap_findings = parse_nmap(xml_path)
    all_findings["nmap"] = nmap_findings
    db.save_findings(scan_id, "nmap", nmap_findings)
    print(f"       {len(nmap_findings)} open port(s) found.")

    # 3. gobuster (only if a web port is open)
    web_ports = [f["port"] for f in nmap_findings if f["port"] in (80, 443, 8080, 8443)]
    if web_ports:
        print(f"[gobuster] web port(s) found — brute-forcing directories...")
        gb_result = run_gobuster(target)
        gb_findings = parse_gobuster(gb_result)
        all_findings["gobuster"] = gb_findings
        db.save_findings(scan_id, "gobuster", gb_findings)
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
        db.save_findings(scan_id, "nikto", nk_findings)
        print(f"        {len(nk_findings)} finding(s).")
    else:
        all_findings["nikto"] = []

    # 5. AI Triage
    total = sum(len(v) for v in all_findings.values())
    if total == 0:
        print("\n[triager] No findings to triage. Clean result."); return 0

    print(f"\n[triager] sending {total} finding(s) to GPT-4o-mini for analysis...")
    try:
        triage_report = triage(all_findings)
    except Exception as e:
        print(f"[triager] AI call failed: {e}{_ai_fail_hint(e)}"); return 1

    print("\n" + "="*60)
    print("  HYDRAMIND — TRIAGE REPORT")
    print("="*60)
    print(f"\n{triage_report.get('summary', '')}\n")
    for item in triage_report.get("ranked_findings", []):
        sev = item.get("severity", "?")
        print(f"[{sev}] #{item['rank']} — {item['finding']}")
        print(f"       Why: {item['why']}")
        print(f"       Next: {item['next_step']}\n")

    # 6. AI Reasoner (strong model) — attack plan
    print(f"[reasoner] asking {REASONER_MODEL} for an attack plan...")
    try:
        plan = validate_plan(reason(target, all_findings, triage_report), target)
    except Exception as e:
        print(f"[reasoner] AI call failed: {e}{_ai_fail_hint(e)}"); return 1
    for note in plan["rejected"]:
        print(f"  [plan-guard] {note}")

    print("\n" + "="*60)
    print("  HYDRAMIND — ATTACK PLAN (Reasoner)")
    print("="*60)
    print(f"\n{plan['assessment']}\n")
    for path in plan["attack_paths"]:
        print(f"  Path: {path['title']}")
        for i, step in enumerate(path["steps"], 1):
            print(f"     {i}. {step}")
    if not plan["actions"]:
        print("\n[reasoner] No safe next actions proposed. Pipeline done.")
        _save_report(scan_id, target, all_findings, triage_report, plan, [])
        return 0
    print(f"\n  Proposed actions (priority: #{plan['priority']}):")
    for a in plan["actions"]:
        risk = "ACTIVE" if a["risk"] == "active" else "passive"
        cmd = f"{a['tool']} {' '.join(a['args'])}".strip()
        print(f"\n  #{a['id']} [{risk}] {a['description']}")
        print(f"       cmd: {cmd} {a['target']}")
        print(f"       why: {a['rationale']}")

    # 7. HUMAN APPROVAL GATE — nothing risky runs without an explicit 'y'
    print("\n" + "="*60)
    print("  APPROVAL GATE — you are the human in the loop")
    print("="*60)
    action_results = []
    for a in plan["actions"]:
        is_active = a["risk"] == "active"
        approved, executed, result, status = False, False, "", ""
        print(f"\n  Action #{a['id']} [{a['risk']}] {a['tool']}: {a['description']}")

        if not _ask(f"  Approve action #{a['id']}?", default_yes=not is_active):
            status = "rejected"
            print(f"       → skipped (not approved).")
        elif a["tool"] not in KNOWN_TOOLS:
            approved = True
            status = "queued-phase3"
            print(f"       → [phase3] {a['tool']} approved + queued "
                  f"(not implemented yet).")
        else:
            approved = True
            # defense in depth: re-check scope right before every execution
            try:
                fw.check(a["target"])
            except ScopeError as e:
                result = f"scope-blocked: {e}"
                status = "blocked"
                print(f"       → BLOCKED: {e}")
            else:
                print(f"       → running...")
                findings, result = _execute_action(a, target)
                executed = True
                status = "executed"
                db.save_findings(scan_id, a["tool"], findings)
                print(f"       → done: {result}")
                action_results.append({**a, "status": status,
                                       "summary": result, "new_findings": findings})

        db.log_action(scan_id, a["id"], a["tool"], a["risk"], a["description"],
                      approved=approved, executed=executed, result=result)
        if status != "executed":
            action_results.append({**a, "status": status})

    # 8. Save full report
    _save_report(scan_id, target, all_findings, triage_report, plan, action_results)
    return 0


def _save_report(scan_id, target, all_findings, triage_report, plan, action_results):
    report_path = Path("data") / f"report_{scan_id}.json"
    report_path.write_text(json.dumps({
        "target": target,
        "raw": all_findings,
        "triage": triage_report,
        "reasoner": plan,
        "actions": action_results,
    }, indent=2))
    print(f"\n[db] full report saved → {report_path}")


if __name__ == "__main__":
    sys.exit(main())
