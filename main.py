#!/usr/bin/env python3
"""HydraMind — Phase 2. Usage: python3 main.py --target scanme.nmap.org

Pipeline: scope check -> recon (nmap/gobuster/nikto, all logged) -> AI triage
-> per-finding AI Reasoner (GPT-4o) -> HUMAN APPROVAL GATE -> approved passive
actions execute; exploitation-class tools are logged and queued for Phase 3
(labs only) -> report."""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from engine.scope_firewall import ScopeFirewall, ScopeError
from engine.tools.nmap_tool import run_nmap, parse_nmap
from engine.tools.gobuster_tool import run_gobuster, parse_gobuster, DEFAULT_WORDLIST
from engine.tools.nikto_tool import run_nikto, parse_nikto
from engine.triager import triage
from engine.reasoner import (reason_about_finding, validate_action,
                             KNOWN_TOOLS)
from engine.findings import finding_from_tool, finding_from_triage
from engine import db

SCOPE_FILE = Path(__file__).resolve().parent / "config" / "scope.yaml"
GOBUSTER_WORDLIST_ROOT = Path("/usr/share/wordlists")
REASONER_MODEL = os.environ.get("HYDRAMIND_REASONER_MODEL", "gpt-4o")


def _ask(msg: str, default_yes: bool) -> bool:
    """Approval prompt. Passive findings default to yes, everything else to
    NO — the human must type 'y' for anything risky. EOF/no input = never."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        ans = input(f"  {msg} {suffix} ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes") if ans else default_yes


def _rejection_reason() -> str:
    try:
        reason = input("  rejection reason (one line): ").strip()
    except EOFError:
        reason = ""
    return reason or "(no reason given)"


def _wordlist_from_args(args: list[str]) -> str:
    """Pull -w <path> out of a gobuster command; only allow Kali wordlists.
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


def _web_url(target: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{target}:{port}"


def _url_from_args(args: list[str], target: str) -> str | None:
    """Extract a validated -u/-h URL from a proposed command; must reference
    the scoped target (a non-standard web port then survives into execution)."""
    for flag in ("-u", "-h"):
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args) and target.lower() in args[i + 1].lower():
                return args[i + 1]
    return None


def _execute_action(tool: str, args: list[str], target: str,
                    default_url: str | None = None) -> tuple[list[dict], str]:
    """Run an approved, validated action through runner.py.
    Returns (findings, summary)."""
    if tool == "nmap":
        extra = [a for a in args if target.lower() not in a.lower()]
        result, xml_path = run_nmap(target, extra_args=extra or None)
        findings = [] if result.timed_out else parse_nmap(xml_path)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    url = _url_from_args(args, target) or default_url or target

    if tool == "gobuster":
        result = run_gobuster(url, wordlist=_wordlist_from_args(args))
        findings = [] if result.timed_out else parse_gobuster(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} path(s) @ {url}"

    if tool == "nikto":
        result = run_nikto(url)
        findings = [] if result.timed_out else parse_nikto(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s) @ {url}"

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

    # 1. Scope gate (stage 1: host authorization)
    fw = ScopeFirewall(SCOPE_FILE)
    try:
        target = fw.check(args.target)
    except ScopeError as e:
        db.init_db()
        db.log_scope_event(args.target, "recon", False, str(e))
        print(f"\n{e}\n"); return 1
    db.init_db()
    db.log_scope_event(target, "recon", True, "")
    print(f"[scope] '{target}' authorized.\n")

    scan_id = db.new_scan(target, tool="phase2")
    all_findings = {}

    # 2. nmap
    print("[nmap] scanning ports + services...")
    result, xml_path = run_nmap(target)
    nmap_findings = parse_nmap(xml_path)
    all_findings["nmap"] = nmap_findings
    db.save_findings(scan_id, "nmap", nmap_findings)
    print(f"       {len(nmap_findings)} open port(s) found.")

    # 3. gobuster (one pass per discovered web port)
    web_ports = [f["port"] for f in nmap_findings if f["port"] in (80, 443, 8080, 8443, 8081)]
    web_urls = [_web_url(target, p) for p in web_ports]
    gb_findings = []
    if web_urls:
        for wu in web_urls:
            print(f"[gobuster] brute-forcing {wu}...")
            gb_result = run_gobuster(wu)
            found = [] if gb_result.timed_out else parse_gobuster(gb_result)
            for d in found:
                d["url"] = wu
                d["detail"] = f"{wu}{d['path']}"
            gb_findings.extend(found)
            print(f"           {len(found)} path(s) found.")
        all_findings["gobuster"] = gb_findings
        db.save_findings(scan_id, "gobuster", gb_findings)
    else:
        print("[gobuster] no web ports — skipping.")
        all_findings["gobuster"] = []

    # 4. nikto
    nk_findings = []
    if web_urls and not args.skip_nikto:
        for wu in web_urls:
            print(f"[nikto] scanning {wu} for web misconfigs (this can take 2-3 min)...")
            nk_result = run_nikto(wu)
            found = [] if nk_result.timed_out else parse_nikto(nk_result)
            for d in found:
                d["url"] = wu
                d["detail"] = f"[{wu}] {d['finding']}"
            nk_findings.extend(found)
            print(f"        {len(found)} finding(s).")
        all_findings["nikto"] = nk_findings
        db.save_findings(scan_id, "nikto", nk_findings)
    else:
        all_findings["nikto"] = []

    web_url = web_urls[0] if web_urls else None

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
    ranked = triage_report.get("ranked_findings", [])
    for item in ranked:
        sev = item.get("severity", "?")
        print(f"[{sev}] #{item['rank']} — {item['finding']}")
        print(f"       Why: {item['why']}")
        print(f"       Next: {item['next_step']}\n")

    # Persist triage items so reasoner_decisions can FK to them
    triage_ids = db.save_triage_findings(scan_id, ranked)

    # 6. Per-finding Reasoner + HUMAN APPROVAL GATE
    print("="*60)
    print(f"  REASONER ({REASONER_MODEL}) + APPROVAL GATE — one finding at a time")
    print("="*60)
    decisions = []
    for item, finding_id in zip(ranked, triage_ids):
        finding = finding_from_triage(item, target)
        siblings = [finding_from_tool(t, target, d).to_dict()
                    for t, lst in all_findings.items() for d in lst
                    if t != finding.tool][:10]
        context = {
            "target": target,
            "sibling_findings": siblings,
            "action_history": db.action_history(target),
        }

        print(f"\n--- Finding #{item['rank']} [{item.get('severity', '?')}] "
              f"{item['finding']}")
        try:
            out = reason_about_finding(finding, context)
        except Exception as e:
            print(f"[reasoner] AI call failed: {e}{_ai_fail_hint(e)}"); return 1

        action = validate_action(out.exact_tool_and_command, target)
        guard = "" if action else "  [guard] proposed command failed safety validation — will NOT run"
        print(f"  hypothesis : {out.attack_hypothesis}")
        print(f"  command    : {out.exact_tool_and_command}")
        print(f"  expected   : {out.expected_outcome}")
        print(f"  confidence : {out.confidence:.0%}   risk: {out.risk_level}")
        if guard:
            print(guard)

        approved = _ask(f"  Approve action for finding #{item['rank']}?",
                        default_yes=(out.risk_level == "passive"))
        if not approved:
            reason = _rejection_reason()
            db.log_reasoner_decision(finding_id, out.attack_hypothesis,
                                     out.exact_tool_and_command, out.confidence,
                                     out.risk_level, "rejected",
                                     rejection_reason=reason)
            decisions.append({**out.to_dict(), "rank": item["rank"],
                              "human_decision": "rejected",
                              "rejection_reason": reason})
            continue

        executed, result_text, status = False, "", "approved"
        if action is None:
            result_text = "not executed: proposed command failed safety validation"
            status = "guard-rejected"
        elif action["tool"] not in KNOWN_TOOLS:
            # exploitation-class / phase-3 tool: approve + log + queue, NEVER run here
            try:
                fw.check_tool(target, action["tool"])
                print(f"  → [phase3] {action['tool']} approved + queued "
                      f"(not implemented yet) — stopping pipeline.")
                db.log_action(scan_id, item["rank"], action["tool"],
                              out.risk_level, out.attack_hypothesis,
                              approved=True, executed=False)
                status = "queued-phase3"
            except ScopeError as e:
                result_text = str(e)
                status = "scope-blocked"
                print(f"  → BLOCKED: {e}")
            if status == "queued-phase3":
                db.log_reasoner_decision(finding_id, out.attack_hypothesis,
                                         out.exact_tool_and_command, out.confidence,
                                         out.risk_level, "approved",
                                         result="queued for Phase 3")
                decisions.append({**out.to_dict(), "rank": item["rank"],
                                  "human_decision": "approved",
                                  "status": status})
                break  # nothing executes past this point until Phase 3
        else:
            # stage 2: per-tool authorization + stage-1 re-check
            try:
                fw.check(target)
                fw.check_tool(target, action["tool"])
            except ScopeError as e:
                result_text = str(e)
                status = "scope-blocked"
                print(f"  → BLOCKED: {e}")
            else:
                print(f"  → running...")
                new_findings, result_text = _execute_action(
                    action["tool"], action["args"], target, default_url=web_url)
                executed = True
                db.save_findings(scan_id, action["tool"], new_findings)
                db.log_action(scan_id, item["rank"], action["tool"],
                              out.risk_level, out.attack_hypothesis,
                              approved=True, executed=True, result=result_text)
                print(f"  → done: {result_text}")
                for f in new_findings[:5]:
                    nf = finding_from_tool(action["tool"], target, f)
                    print(f"     + {nf.title}")

        db.log_reasoner_decision(finding_id, out.attack_hypothesis,
                                 out.exact_tool_and_command, out.confidence,
                                 out.risk_level, "approved",
                                 executed=executed, result=result_text)
        decisions.append({**out.to_dict(), "rank": item["rank"],
                          "human_decision": "approved", "status": status,
                          "executed": executed, "result": result_text})

    # 7. Save full report
    report_path = Path("data") / f"report_{scan_id}.json"
    report_path.write_text(json.dumps({
        "target": target,
        "raw": all_findings,
        "triage": triage_report,
        "decisions": decisions,
    }, indent=2))
    print(f"\n[db] full report saved → {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
