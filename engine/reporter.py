"""Report writer — builds a Markdown + self-contained HTML report purely from
the SQLite audit trail (scans, findings, triage, decisions, validations,
scope events). Nothing is invented: every claim in the report is traceable to
a logged row.

Usage:
    python main.py --report 6
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from engine import db

ROOT = Path(__file__).resolve().parents[1]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
VERDICT_ORDER = ["confirmed", "likely", "needs_review", "false_positive"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report_data(scan_id: int) -> dict:
    scan = db.scan_row(scan_id)
    if not scan:
        raise ValueError(f"scan {scan_id} not found")
    triage = db.triage_for_scan(scan_id)
    decisions = db.decisions_for_scan(scan_id)
    validations = db.validations_for_scan(scan_id)

    by_finding = {}
    for d in decisions:
        by_finding.setdefault(d["finding_id"], d)
    validation_by_finding = {}
    for v in validations:
        validation_by_finding.setdefault(v["finding_id"], v)

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for t in triage:
        sev = (t.get("severity") or "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    verdict_counts = {v: 0 for v in VERDICT_ORDER}
    for v in validations:
        if v.get("verdict") in verdict_counts:
            verdict_counts[v["verdict"]] += 1

    return {
        "scan": scan,
        "findings": db.findings_for_scan(scan_id),
        "triage": triage,
        "decisions": decisions,
        "validations": validations,
        "actions": db.actions_for_scan(scan_id),
        "scope_events": db.scope_events_for_target(scan["target"]),
        "by_finding": by_finding,
        "validation_by_finding": validation_by_finding,
        "severity_counts": severity_counts,
        "verdict_counts": verdict_counts,
        "executed_count": sum(1 for d in decisions if d.get("executed")),
        "llm_summary": db.summary_for_scan(scan_id),
        "generated_at": _now(),
    }


def _truncate(value, limit: int) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _validator_line(v: dict | None) -> str:
    if not v:
        return "Not validated (validator disabled or no model available)."
    same = " (same-family fallback)" if v.get("same_family") else ""
    return (f"`{v.get('verdict')}` — severity `{v.get('severity')}`, "
            f"confidence {float(v.get('confidence') or 0):.0%}{same} — "
            f"{v.get('rationale') or ''}")


def render_markdown(data: dict) -> str:
    scan = data["scan"]
    lines: list[str] = []
    add = lines.append

    add(f"# HydraMind — Penetration Test Report")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add(f"| Target | `{scan['target']}` |")
    add(f"| Scan ID | {scan['id']} |")
    add(f"| Started (UTC) | {scan.get('started_at', '')} |")
    add(f"| Report generated (UTC) | {data['generated_at']} |")
    add("")

    add("## Executive summary")
    add("")
    add(f"- Tool findings recorded: **{len(data['findings'])}**")
    add(f"- Triage findings: **{len(data['triage'])}**")
    add(f"- Human-approved executed actions: **{data['executed_count']}**")
    if data["validations"]:
        vc = data["verdict_counts"]
        add(f"- Validated: **{len(data['validations'])}** "
            f"(confirmed {vc['confirmed']}, likely {vc['likely']}, "
            f"needs review {vc['needs_review']}, "
            f"false positive {vc['false_positive']})")
    else:
        add("- Validated: **0** (validator disabled or no API key)")
    add("")
    if data.get("llm_summary"):
        ws = data["llm_summary"]
        add(f"**Writer summary** (LLM-assisted, grounded in [F#] IDs; "
            f"`{ws.get('provider')}/{ws.get('model')}`):")
        add("")
        add(ws.get("summary") or "")
        add("")

    confirmed = [v for v in data["validations"]
                 if v.get("verdict") in ("confirmed", "likely")]
    if confirmed:
        add("### Validated vulnerabilities")
        add("")
        for v in confirmed:
            add(f"- **[{v.get('severity')}]** {v.get('title')} — "
                f"`{v.get('verdict')}` "
                f"({float(v.get('confidence') or 0):.0%}) — {v.get('rationale')}")
        add("")

    add("### Severity breakdown")
    add("")
    add("| Severity | Findings |")
    add("|---|---|")
    for sev in SEVERITY_ORDER:
        add(f"| {sev} | {data['severity_counts'][sev]} |")
    add("")

    add("## Scope & methodology")
    add("")
    add(f"Target `{scan['target']}` was checked by the scope firewall before any "
        f"tool ran; every allow/deny decision is logged (`scope_events`).")
    add("")
    add("Pipeline: nmap → gobuster → nikto → AI triage → per-finding Reasoner "
        "→ **human approval gate (one y/n per action)** → execution → "
        "independent second-model validator. Only human-approved commands were "
        "executed; all output below comes from logged tool runs.")
    add("")

    add("## Findings")
    add("")
    if not data["triage"]:
        add("_No triage findings recorded._")
        add("")
    for t in data["triage"]:
        d = data["by_finding"].get(t["id"]) or {}
        v = data["validation_by_finding"].get(t["id"])
        add(f"### #{t.get('rank')} [{t.get('severity')}] {t.get('description')}")
        add("")
        add(f"- Source/tool: `{t.get('source')}`")
        if t.get("why"):
            add(f"- Why it matters: {t['why']}")
        if t.get("next_step"):
            add(f"- Suggested next step: {t['next_step']}")
        add(f"- Validator: {_validator_line(v)}")
        if v and v.get("remediation"):
            add(f"- Remediation: {v['remediation']}")
        add("")
        if d.get("human_decision"):
            add(f"- Human decision: **{d['human_decision']}** "
                f"(risk: {d.get('risk_level')}, "
                f"executed: {'yes' if d.get('executed') else 'no'})")
            if d.get("rejection_reason"):
                add(f"- Rejection reason: {d['rejection_reason']}")
        if d.get("proposed_command"):
            add("")
            add("Approved command:")
            add("```")
            add(_truncate(d["proposed_command"], 500))
            add("```")
        if d.get("result"):
            add("")
            add(f"Result: {_truncate(d['result'], 1200)}")
        add("")

    add("## Decision log")
    add("")
    add("| Rank | Risk | Decision | Executed | Command | Result |")
    add("|---|---|---|---|---|---|")
    if not data["decisions"]:
        add("| — | — | — | — | _none_ | |")
    for d in data["decisions"]:
        cmd = _truncate(d.get("proposed_command"), 80).replace("|", "\\|")
        res = _truncate(d.get("result"), 80).replace("|", "\\|")
        add(f"| {d.get('rank')} | {d.get('risk_level')} | "
            f"{d.get('human_decision')} | "
            f"{'yes' if d.get('executed') else 'no'} | `{cmd}` | {res} |")
    add("")

    add("## Appendix A — raw tool findings")
    add("")
    add("| Tool | Port/Path | Detail |")
    add("|---|---|---|")
    if not data["findings"]:
        add("| — | — | _none_ |")
    for f in data["findings"]:
        where = f.get("path") or (f"port {f.get('port')}" if f.get("port") else "")
        detail = _truncate(f.get("detail") or f.get("service") or "", 120)
        detail = detail.replace("|", "\\|").replace("\n", " ")
        add(f"| {f.get('tool')} | {where} | {detail} |")
    add("")

    add("## Appendix B — scope firewall events")
    add("")
    add("| Time (UTC) | Tool | Allowed | Reason |")
    add("|---|---|---|---|")
    if not data["scope_events"]:
        add("| — | — | — | _none_ |")
    for e in data["scope_events"][:20]:
        reason = _truncate(e.get("reason") or "", 100).replace("|", "\\|")
        add(f"| {e.get('created_at')} | {e.get('tool')} | "
            f"{'yes' if e.get('allowed') else 'no'} | {reason} |")
    add("")

    add("---")
    add("")
    add("_Generated by HydraMind from the SQLite audit trail. Evidence is "
        "reproduced from logged tool output only; no result was fabricated._")
    add("")
    return "\n".join(lines)


HTML_CSS = """
:root{--bg:#0f1419;--panel:#161d26;--text:#e6edf3;--muted:#8b98a5;
--border:#243040;--accent:#7ee787;--crit:#ff6b6b;--high:#ffa657;
--med:#e3b341;--low:#79c0ff;--info:#8b98a5}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:28px;margin:0 0 4px}
h2{margin-top:36px;border-bottom:1px solid var(--border);padding-bottom:6px}
h3{margin-top:28px}
.sub{color:var(--muted);margin-bottom:24px}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}
th,td{border:1px solid var(--border);padding:8px 10px;text-align:left;
vertical-align:top}
th{background:var(--panel);color:var(--muted);font-weight:600}
code{background:#1b2430;padding:1px 5px;border-radius:4px;font-size:13px}
pre{background:#0b1016;border:1px solid var(--border);border-radius:8px;
padding:12px;overflow:auto;font-size:13px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;
font-size:12px;font-weight:700;letter-spacing:.3px}
.sev-CRITICAL{background:rgba(255,107,107,.15);color:var(--crit)}
.sev-HIGH{background:rgba(255,166,87,.15);color:var(--high)}
.sev-MEDIUM{background:rgba(227,179,65,.15);color:var(--med)}
.sev-LOW{background:rgba(121,192,255,.15);color:var(--low)}
.sev-INFO{background:rgba(139,152,165,.15);color:var(--info)}
.verdict-confirmed{color:var(--accent);font-weight:700}
.verdict-likely{color:var(--low);font-weight:700}
.verdict-false_positive{color:var(--crit);font-weight:700}
.verdict-needs_review{color:var(--med);font-weight:700}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:16px 18px;margin:14px 0}
.muted{color:var(--muted)}
.footer{margin-top:40px;color:var(--muted);font-size:13px}
"""


def _e(value) -> str:
    return html.escape(str(value or ""))


def render_html(data: dict) -> str:
    scan = data["scan"]
    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    add(f"<title>HydraMind report — scan {scan['id']} — {_e(scan['target'])}</title>")
    add(f"<style>{HTML_CSS}</style></head><body><main>")

    add("<h1>HydraMind — Penetration Test Report</h1>")
    add(f"<div class='sub'>Target <code>{_e(scan['target'])}</code> · "
        f"scan #{scan['id']} · started {_e(scan.get('started_at'))} · "
        f"generated {_e(data['generated_at'])}</div>")

    add("<h2>Executive summary</h2>")
    add("<table><tbody>")
    add(f"<tr><th>Tool findings recorded</th><td>{len(data['findings'])}</td></tr>")
    add(f"<tr><th>Triage findings</th><td>{len(data['triage'])}</td></tr>")
    add(f"<tr><th>Human-approved executed actions</th><td>{data['executed_count']}</td></tr>")
    if data["validations"]:
        vc = data["verdict_counts"]
        add(f"<tr><th>Validated</th><td>{len(data['validations'])} "
            f"(confirmed {vc['confirmed']}, likely {vc['likely']}, "
            f"needs review {vc['needs_review']}, "
            f"false positive {vc['false_positive']})</td></tr>")
    else:
        add("<tr><th>Validated</th><td>0 (validator disabled or no API key)</td></tr>")
    add("</tbody></table>")
    if data.get("llm_summary"):
        ws = data["llm_summary"]
        add(f"<p class='sub'>Writer summary — LLM-assisted, grounded in [F#] IDs "
            f"(<code>{_e(ws.get('provider'))}/{_e(ws.get('model'))}</code>)</p>")
        add(f"<p>{_e(ws.get('summary'))}</p>")

    confirmed = [v for v in data["validations"]
                 if v.get("verdict") in ("confirmed", "likely")]
    if confirmed:
        add("<h3>Validated vulnerabilities</h3>")
        for v in confirmed:
            add(f"<div class='card'><span class='badge sev-{_e(v.get('severity'))}'>"
                f"{_e(v.get('severity'))}</span> {_e(v.get('title'))}<br>"
                f"<span class='verdict-{_e(v.get('verdict'))}'>"
                f"{_e(v.get('verdict'))}</span> "
                f"({float(v.get('confidence') or 0):.0%}) — "
                f"{_e(v.get('rationale'))}</div>")

    add("<h3>Severity breakdown</h3><table><thead><tr><th>Severity</th>"
        "<th>Findings</th></tr></thead><tbody>")
    for sev in SEVERITY_ORDER:
        add(f"<tr><td><span class='badge sev-{sev}'>{sev}</span></td>"
            f"<td>{data['severity_counts'][sev]}</td></tr>")
    add("</tbody></table>")

    add("<h2>Scope &amp; methodology</h2>")
    add(f"<p>Target <code>{_e(scan['target'])}</code> was checked by the scope "
        "firewall before any tool ran; every allow/deny decision is logged. "
        "Pipeline: nmap → gobuster → nikto → AI triage → per-finding Reasoner → "
        "<b>human approval gate (one y/n per action)</b> → execution → "
        "independent second-model validator. Only human-approved commands were "
        "executed.</p>")

    add("<h2>Findings</h2>")
    if not data["triage"]:
        add("<p class='muted'>No triage findings recorded.</p>")
    for t in data["triage"]:
        d = data["by_finding"].get(t["id"]) or {}
        v = data["validation_by_finding"].get(t["id"])
        add("<div class='card'>")
        add(f"<h3>#{_e(t.get('rank'))} "
            f"<span class='badge sev-{_e(t.get('severity'))}'>{_e(t.get('severity'))}</span> "
            f"{_e(t.get('description'))}</h3>")
        add(f"<p class='muted'>Source/tool: <code>{_e(t.get('source'))}</code></p>")
        if t.get("why"):
            add(f"<p><b>Why it matters:</b> {_e(t['why'])}</p>")
        if t.get("next_step"):
            add(f"<p><b>Suggested next step:</b> {_e(t['next_step'])}</p>")
        if v:
            add(f"<p><b>Validator:</b> <span class='verdict-{_e(v.get('verdict'))}'>"
                f"{_e(v.get('verdict'))}</span> — severity {_e(v.get('severity'))}, "
                f"confidence {float(v.get('confidence') or 0):.0%}"
                f"{' (same-family fallback)' if v.get('same_family') else ''} — "
                f"{_e(v.get('rationale'))}</p>")
            if v.get("remediation"):
                add(f"<p><b>Remediation:</b> {_e(v['remediation'])}</p>")
        else:
            add("<p class='muted'>Not validated (validator disabled or no model available).</p>")
        if d.get("human_decision"):
            add(f"<p><b>Human decision:</b> {_e(d['human_decision'])} "
                f"(risk {_e(d.get('risk_level'))}, executed "
                f"{'yes' if d.get('executed') else 'no'})</p>")
            if d.get("rejection_reason"):
                add(f"<p><b>Rejection reason:</b> {_e(d['rejection_reason'])}</p>")
        if d.get("proposed_command"):
            add(f"<pre>{_e(d['proposed_command'])}</pre>")
        if d.get("result"):
            add(f"<p><b>Result:</b> {_e(_truncate(d['result'], 1200))}</p>")
        add("</div>")

    add("<h2>Decision log</h2>")
    add("<table><thead><tr><th>Rank</th><th>Risk</th><th>Decision</th>"
        "<th>Executed</th><th>Command</th><th>Result</th></tr></thead><tbody>")
    if not data["decisions"]:
        add("<tr><td colspan='6' class='muted'>none</td></tr>")
    for d in data["decisions"]:
        add(f"<tr><td>{_e(d.get('rank'))}</td><td>{_e(d.get('risk_level'))}</td>"
            f"<td>{_e(d.get('human_decision'))}</td>"
            f"<td>{'yes' if d.get('executed') else 'no'}</td>"
            f"<td><code>{_e(_truncate(d.get('proposed_command'), 100))}</code></td>"
            f"<td>{_e(_truncate(d.get('result'), 100))}</td></tr>")
    add("</tbody></table>")

    add("<h2>Appendix A — raw tool findings</h2>")
    add("<table><thead><tr><th>Tool</th><th>Port/Path</th><th>Detail</th>"
        "</tr></thead><tbody>")
    if not data["findings"]:
        add("<tr><td colspan='3' class='muted'>none</td></tr>")
    for f in data["findings"]:
        where = f.get("path") or (f"port {f.get('port')}" if f.get("port") else "")
        add(f"<tr><td>{_e(f.get('tool'))}</td><td>{_e(where)}</td>"
            f"<td>{_e(_truncate(f.get('detail') or f.get('service') or '', 160))}</td></tr>")
    add("</tbody></table>")

    add("<h2>Appendix B — scope firewall events</h2>")
    add("<table><thead><tr><th>Time (UTC)</th><th>Tool</th><th>Allowed</th>"
        "<th>Reason</th></tr></thead><tbody>")
    if not data["scope_events"]:
        add("<tr><td colspan='4' class='muted'>none</td></tr>")
    for e in data["scope_events"][:20]:
        add(f"<tr><td>{_e(e.get('created_at'))}</td><td>{_e(e.get('tool'))}</td>"
            f"<td>{'yes' if e.get('allowed') else 'no'}</td>"
            f"<td>{_e(_truncate(e.get('reason') or '', 120))}</td></tr>")
    add("</tbody></table>")

    add("<p class='footer'>Generated by HydraMind from the SQLite audit trail. "
        "Evidence is reproduced from logged tool output only; no result was "
        "fabricated.</p>")
    add("</main></body></html>")
    return "\n".join(parts)


def write_reports(scan_id: int, out_dir: Path | str | None = None) -> dict:
    """Render Markdown + HTML for a scan. Returns {'markdown': path, 'html': path}."""
    data = build_report_data(scan_id)
    target_dir = Path(out_dir) if out_dir else ROOT / "reports"
    target_dir.mkdir(parents=True, exist_ok=True)
    md_path = target_dir / f"report_{scan_id}.md"
    html_path = target_dir / f"report_{scan_id}.html"
    md_path.write_text(render_markdown(data))
    html_path.write_text(render_html(data))
    return {"markdown": md_path, "html": html_path}
