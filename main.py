#!/usr/bin/env python3
"""HydraMind — Phase 4. Usage: python3 main.py --target 127.0.0.1

Pipeline: scope check -> recon (nmap/gobuster/nikto, all logged) -> AI triage
-> per-finding AI Reasoner (GPT-4o) -> HUMAN APPROVAL GATE -> approved actions
execute -> second-model validator -> Markdown/HTML report.

Extra modes: --dry-run (proposals only, no gate/execution), --report <scan_id>,
--validate-scan <scan_id>.
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from engine.scope_firewall import ScopeFirewall, ScopeError
from engine.tools.nmap_tool import run_nmap, parse_nmap
from engine.tools.gobuster_tool import run_gobuster, parse_gobuster, DEFAULT_WORDLIST
from engine.tools.nikto_tool import run_nikto, parse_nikto
from engine.tools.curl_tool import run_curl, parse_curl
from engine.tools.sqlmap_tool import run_sqlmap, parse_sqlmap
from engine.tools.redis_tool import run_redis, parse_redis
from engine.tools.hydra_tool import run_hydra, parse_hydra
from engine.tools.wpscan_tool import run_wpscan, parse_wpscan
from engine.tools.commix_tool import run_commix, parse_commix
from engine.triager import triage
from engine.reasoner import reason_about_finding, validate_action
from engine.validator import validate_scan, provider_config
from engine.findings import finding_from_tool, finding_from_triage
from engine import db, models, reporter

SCOPE_FILE = Path(__file__).resolve().parent / "config" / "scope.yaml"
GOBUSTER_WORDLIST_ROOT = Path("/usr/share/wordlists")
WEB_PORTS = (80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000)


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
    for flag in ("-u", "-h", "--url"):
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args) and target.lower() in args[i + 1].lower():
                return args[i + 1]
    return None


def _execute_action(tool: str, args: list[str], target: str,
                    default_url: str | None = None,
                    cookie: str | None = None) -> tuple[list[dict], str]:
    """Run an approved, validated action through runner.py.
    The session cookie (--cookie) is injected here, never by the AI.
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

    if tool == "curl":
        run_args = list(args)
        if cookie and "-b" not in run_args and "--cookie" not in run_args:
            run_args = ["-b", cookie] + run_args
        result = run_curl(run_args)
        findings = [] if result.timed_out else parse_curl(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        body = (result.stdout or result.stderr or "").strip().replace("\n", " ")[:220]
        return findings, f"{status}, {len(findings)} finding(s) — {body}"

    if tool == "sqlmap":
        url = _url_from_args(args, target)
        if not url:
            return [], "no -u/--url referencing the target — not executed"
        extra, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-u", "--url"):
                skip = True
                continue
            extra.append(a)
        if cookie and "--cookie" not in extra:
            extra += ["--cookie", cookie]
        result = run_sqlmap(url, extra=extra)
        findings = [] if result.timed_out else parse_sqlmap(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    if tool == "redis-cli":
        result = run_redis(args)
        findings = [] if result.timed_out else parse_redis(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        out = (result.stdout or result.stderr or "").strip().replace("\n", " ")[:220]
        return findings, f"{status}, {len(findings)} finding(s) — {out}"

    if tool == "hydra":
        result = run_hydra(args)
        findings = [] if result.timed_out else parse_hydra(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        out = (result.stdout or result.stderr or "").strip().replace("\n", " ")[-220:]
        return findings, f"{status}, {len(findings)} finding(s) — {out}"

    if tool == "wpscan":
        url = _url_from_args(args, target)
        if not url:
            return [], "no --url referencing the target — not executed"
        extra, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a == "--url":
                skip = True
                continue
            extra.append(a)
        result = run_wpscan(url, extra=extra)
        findings = [] if result.timed_out else parse_wpscan(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    if tool == "commix":
        run_args = list(args)
        if cookie and "--cookie" not in run_args:
            run_args += ["--cookie", cookie]
        result = run_commix(run_args)
        findings = [] if result.timed_out else parse_commix(result)
        status = "timed out" if result.timed_out else f"rc={result.returncode}"
        return findings, f"{status}, {len(findings)} finding(s)"

    return [], "not executed"


def _ai_fail_hint(e: Exception) -> str:
    msg = str(e).lower()
    if any(k in msg for k in ("api key", "credentials", "api_key", "not available")):
        return ("  (hint: check config/models.yaml profile keys — OPENAI_API_KEY, "
                "ANTHROPIC_API_KEY, GOOGLE_API_KEY, OPENROUTER_API_KEY, or "
                "start Ollama on OLLAMA_BASE_URL)")
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind (Phase 4)")
    ap.add_argument("--target", help="host to test (required unless --report/--validate-scan)")
    ap.add_argument("--skip-nikto", action="store_true", help="skip nikto (slow)")
    ap.add_argument("--ports", help="nmap port spec (e.g. 1-10000, 6379,8080)")
    ap.add_argument("--seed-url", help="user-supplied endpoint to analyze (must be in scope)")
    ap.add_argument("--cookie", help="session cookie injected into sqlmap/curl/commix (never logged)")
    ap.add_argument("--dry-run", action="store_true",
                    help="recon + triage + reasoner only — no approval, no execution")
    ap.add_argument("--report", type=int, metavar="SCAN_ID",
                    help="render Markdown + HTML for an existing scan and exit")
    ap.add_argument("--validate-scan", type=int, metavar="SCAN_ID",
                    help="run the second-model validator over an existing scan, then exit")
    ap.add_argument("--json-report", help="path for the raw JSON report (default data/report_<id>.json)")
    ap.add_argument("--no-validate", action="store_true", help="skip the second-model validator")
    ap.add_argument("--no-report", action="store_true", help="skip Markdown/HTML report generation")
    ap.add_argument("--profile", help="model profile from config/models.yaml "
                                      "(hybrid/free/quality/local); env HYDRAMIND_PROFILE")
    args = ap.parse_args()
    models.configure(args.profile)

    if args.report is not None:
        db.init_db()
        try:
            paths = reporter.write_reports(args.report)
        except ValueError as e:
            print(f"[report] {e}")
            return 1
        print(f"[report] markdown → {paths['markdown']}")
        print(f"[report] html     → {paths['html']}")
        return 0

    if args.validate_scan is not None:
        db.init_db()
        if not db.scan_row(args.validate_scan):
            print(f"[validator] scan {args.validate_scan} not found")
            return 1
        cfg = provider_config()
        if cfg["provider"] == "none":
            print("[validator] no API key — set ANTHROPIC_API_KEY, "
                  "GOOGLE_API_KEY/GEMINI_API_KEY or OPENAI_API_KEY")
            return 1
        if cfg.get("fallback_from"):
            print(f"[validator] {cfg['fallback_from']} unavailable — using "
                  f"{cfg['provider']}/{cfg['model']}")
        print(f"[validator] {cfg['provider']}/{cfg['model']} over scan "
              f"{args.validate_scan}...")
        validate_scan(args.validate_scan)
        try:
            from engine.writer import generate_summary
            written = generate_summary(args.validate_scan)
            if written:
                print(f"[writer] summary via {written['provider']}/{written['model']}")
        except Exception as e:
            print(f"[writer] skipped: {e}")
        paths = reporter.write_reports(args.validate_scan)
        print(f"[report] markdown → {paths['markdown']}")
        print(f"[report] html     → {paths['html']}")
        return 0

    if not args.target:
        ap.error("--target is required (or use --report/--validate-scan)")

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
    print(models.role_summary())

    scan_id = db.new_scan(target, tool="phase4")
    all_findings = {}

    # 2. nmap
    print("[nmap] scanning ports + services...")
    result, xml_path = run_nmap(target, extra_args=["-p", args.ports] if args.ports else None)
    nmap_findings = parse_nmap(xml_path)
    all_findings["nmap"] = nmap_findings
    db.save_findings(scan_id, "nmap", nmap_findings)
    print(f"       {len(nmap_findings)} open port(s) found.")

    # 3. gobuster (one pass per discovered web port)
    seen = set()
    web_ports = [f["port"] for f in nmap_findings
                 if (f["port"] in WEB_PORTS
                     or str(f.get("service") or "").startswith("http"))
                 and not (f["port"] in seen or seen.add(f["port"]))]
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

    # 4b. user-supplied endpoint (explicit priority, still must be in scope)
    if args.seed_url:
        if target not in args.seed_url.lower():
            print(f"[seed] ignored: '{args.seed_url}' does not reference target "
                  f"'{target}'.")
            return 1
        all_findings["user"] = [{"url": args.seed_url,
                                 "detail": args.seed_url,
                                 "path": args.seed_url}]
        db.save_findings(scan_id, "user", all_findings["user"])
        print(f"[seed] user endpoint queued for triage: {args.seed_url}")

    # 5. AI Triage
    total = sum(len(v) for v in all_findings.values())
    if total == 0:
        print("\n[triager] No findings to triage. Clean result."); return 0

    tcfg = models.resolve_role("triager")
    print(f"\n[triager] sending {total} finding(s) to "
          f"{tcfg['provider']}/{tcfg['model']} for analysis...")
    try:
        triage_report = triage(all_findings, scan_id=scan_id)
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
    rcfg = models.resolve_role("reasoner")
    print("="*60)
    mode = ("DRY RUN — proposals only, nothing executes" if args.dry_run
            else "APPROVAL GATE — one finding at a time")
    print(f"  REASONER ({rcfg['provider']}/{rcfg['model']}) + {mode}")
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
            out = reason_about_finding(finding, context, scan_id=scan_id)
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

        if args.dry_run:
            db.log_reasoner_decision(finding_id, out.attack_hypothesis,
                                     out.exact_tool_and_command, out.confidence,
                                     out.risk_level, "dry_run",
                                     executed=False, result="dry-run: not executed")
            decisions.append({**out.to_dict(), "rank": item["rank"],
                              "human_decision": "dry_run", "status": "dry-run",
                              "executed": False, "result": "dry-run: not executed"})
            print("  [dry-run] proposal recorded — not executed")
            continue

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
                    action["tool"], action["args"], target, default_url=web_url,
                    cookie=args.cookie)
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

    # 7. Second-model validation (skipped in dry-run / with --no-validate)
    validation_results = []
    if not args.dry_run and not args.no_validate:
        cfg = provider_config()
        if cfg["provider"] == "none":
            print("\n[validator] skipped — no ANTHROPIC/GOOGLE/OPENAI key.")
        else:
            same = " (SAME FAMILY as reasoner — independence flagged)" if cfg["same_family"] else ""
            if cfg.get("fallback_from"):
                print(f"\n[validator] {cfg['fallback_from']} unavailable — "
                      f"using {cfg['provider']}/{cfg['model']}")
            print(f"[validator] second-model cross-check via "
                  f"{cfg['provider']}/{cfg['model']}{same}...")
            validation_results = validate_scan(scan_id)

    # 8. Optional grounded writer summary (LLM disabled by default)
    if not args.dry_run and not args.no_report:
        try:
            from engine.writer import generate_summary
            written = generate_summary(scan_id)
            if written:
                print(f"\n[writer] summary via "
                      f"{written['provider']}/{written['model']}")
        except Exception as e:
            print(f"\n[writer] skipped: {e}")

    # 9. Save full JSON report (path overridable for eval harnesses)
    report_path = (Path(args.json_report) if args.json_report
                   else Path("data") / f"report_{scan_id}.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({
        "scan_id": scan_id,
        "target": target,
        "profile": models.active_profile(),
        "dry_run": args.dry_run,
        "raw": all_findings,
        "triage": triage_report,
        "decisions": decisions,
        "validations": db.validations_for_scan(scan_id),
        "llm_summary": db.summary_for_scan(scan_id),
    }, indent=2))
    print(f"\n[db] full report saved → {report_path}")

    # 10. Markdown + HTML report from the audit trail
    if not args.no_report:
        paths = reporter.write_reports(scan_id)
        print(f"[report] markdown → {paths['markdown']}")
        print(f"[report] html     → {paths['html']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
