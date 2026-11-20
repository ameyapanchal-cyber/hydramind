#!/usr/bin/env python3
"""HydraMind dashboard — read-only local web view of the audit trail.

    python3 dashboard.py                 # http://127.0.0.1:8765
    python3 dashboard.py --port 9000

Serves scan summaries, triage/decisions/validations, model-call logs, scope
events and the generated Markdown/HTML reports straight from SQLite. Bind is
localhost-only by default and there is no authentication: do not expose it to
an untrusted network.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from engine import dashboard as dash
from engine import db

INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HydraMind Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{display:flex;align-items:baseline;gap:12px;padding:18px 24px;
border-bottom:1px solid var(--line)}h1{font-size:18px;margin:0;color:#fff}
h2{font-size:14px;margin:24px 24px 8px;color:var(--acc);text-transform:uppercase;
letter-spacing:.08em}.sub{color:var(--mut);font-size:12px}
main{padding:0 24px 40px}.cards{display:grid;grid-template-columns:repeat(auto-fit,
minmax(150px,1fr));gap:12px;margin:18px 0}.card{background:var(--panel);
border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:22px;color:#fff}.card .l{color:var(--mut);font-size:11px;
text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;
white-space:nowrap;font-size:12.5px}th{color:var(--mut);font-weight:600;
font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:0}tbody tr:hover{background:#1f2630;cursor:pointer}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.pill{padding:1px 7px;border-radius:99px;border:1px solid var(--line);font-size:11px}
.confirmed{color:var(--ok);border-color:var(--ok)}.false_positive{color:var(--bad);
border-color:var(--bad)}.needs_review,.likely{color:var(--warn);border-color:var(--warn)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}@media(max-width:900px){
.grid{grid-template-columns:1fr}}#detail{margin-top:8px;padding:16px;
background:var(--panel);border:1px solid var(--line);border-radius:8px;display:none}
#status{color:var(--mut);font-size:12px}.err{color:var(--bad)}
.wrap{overflow-x:auto}
</style></head><body>
<header><h1>HydraMind</h1><span class="sub">read-only audit dashboard</span>
<span id="status" style="margin-left:auto"></span></header>
<main>
<div class="cards" id="cards"></div>
<h2>Scans</h2><div class="wrap"><table id="scans"><thead><tr>
<th>ID</th><th>Target</th><th>Started</th><th>Profile</th><th>Raw</th><th>Triage</th>
<th>Executed</th><th>Confirmed</th><th>FP</th><th>Reports</th></tr></thead>
<tbody></tbody></table></div>
<div id="detail"></div>
<div class="grid">
<div><h2>Model calls (recent)</h2><div class="wrap"><table id="calls"><thead><tr>
<th>Scan</th><th>Role</th><th>Model</th><th>Latency</th></tr></thead><tbody></tbody>
</table></div></div>
<div><h2>Scope events (recent)</h2><div class="wrap"><table id="scope"><thead><tr>
<th>Target</th><th>Tool</th><th>Allowed</th><th>When</th></tr></thead><tbody></tbody>
</table></div></div>
</div>
</main>
<script>
const $=id=>document.getElementById(id);
function el(tag,text,cls){const e=document.createElement(tag);
if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function row(cells,onclick){const tr=document.createElement("tr");
for(const c of cells){const td=document.createElement("td");
if(c instanceof Node)td.appendChild(c);else td.textContent=c===null?"":c;
tr.appendChild(td)}if(onclick)tr.onclick=onclick;return tr}
function pill(v){return el("span",v,"pill "+v)}
function reportLinks(s){const box=document.createDocumentFragment();
if(s.report_md){const a=el("a","md");a.href="/reports/report_"+s.id+".md";
a.target="_blank";box.appendChild(a);box.appendChild(document.createTextNode(" "))}
if(s.report_html){const a=el("a","html");a.href="/reports/report_"+s.id+".html";
a.target="_blank";box.appendChild(a)}return box}
function cards(t){$("cards").replaceChildren(...[
["Scans",t.scans],["Raw findings",t.raw_findings],["Executed actions",t.executed_actions],
["Confirmed",t.confirmed],["False positives",t.false_positive],
["Model calls",t.model_calls]].map(([l,n])=>{const d=el("div",undefined,"card");
d.appendChild(el("div",n,"n"));d.appendChild(el("div",l,"l"));return d}))}
function renderOverview(d){
if(!d.ok){$("status").textContent="DB: "+(d.error||"unavailable");
$("status").className="err";return}
$("status").textContent="updated "+new Date().toLocaleTimeString();
cards(d.totals);
const tb=$("scans").querySelector("tbody");tb.replaceChildren(...d.scans.map(s=>
row([s.id,s.target,s.started_at,s.profile||"-",s.raw_findings,s.triage_findings,
s.executed_actions,s.confirmed,s.false_positive,reportLinks(s)],
()=>loadDetail(s.id))));
const cb=$("calls").querySelector("tbody");cb.replaceChildren(...d.recent_calls.map(c=>
row([c.scan_id,c.role,c.provider+"/"+c.model,(c.latency_ms/1000).toFixed(1)+"s"])));
const sb=$("scope").querySelector("tbody");sb.replaceChildren(...d.scope_events.map(e=>
row([e.target,e.tool,e.allowed?"yes":"no",e.created_at])));
}
async function loadDetail(id){
const d=await fetch("/api/scan/"+id).then(r=>r.json()).catch(e=>({ok:false,error:String(e)}));
const box=$("detail");box.style.display="block";box.replaceChildren();
if(!d.ok){box.appendChild(el("div",d.error||"error","err"));return}
const s=d.scan;box.appendChild(el("h2","Scan #"+s.id+" — "+s.target));
const v=el("div",undefined,"cards");
const counts={};for(const x of d.validations)counts[x.verdict]=(counts[x.verdict]||0)+1;
for(const [k,n] of Object.entries(counts)){const c=el("div",undefined,"card");
c.appendChild(el("div",n,"n"));c.appendChild(el("div",k,"l"));v.appendChild(c)}
box.appendChild(v);
if(d.summary){const p=el("p",d.summary.summary);p.style.color="#c9d1d9";
box.appendChild(el("div","Writer summary ("+d.summary.provider+"/"+d.summary.model+")",
"sub"));box.appendChild(p)}
box.appendChild(el("h2","Validations"));const vt=el("table");const vh=el("thead");
const hr=el("tr");for(const h of["Title","Verdict","Severity","Confidence","Rationale"])
hr.appendChild(el("th",h));vh.appendChild(hr);vt.appendChild(vh);
const vb=el("tbody");for(const x of d.validations){const tr=el("tr");
tr.appendChild(el("td",x.title));tr.appendChild(el("td")).appendChild(pill(x.verdict));
tr.appendChild(el("td",x.severity));
tr.appendChild(el("td",Math.round((x.confidence||0)*100)+"%"));
tr.appendChild(el("td",x.rationale||""));vb.appendChild(tr)}vt.appendChild(vb);
box.appendChild(vt);
box.appendChild(el("h2","Decisions"));const dt=el("table");const dh=el("thead");
const dhr=el("tr");for(const h of["#","Risk","Command","Human","Executed"])
dhr.appendChild(el("th",h));dh.appendChild(dhr);dt.appendChild(dh);
const db=el("tbody");for(const x of d.decisions){db.appendChild(row([
x.rank,x.risk_level,x.proposed_command,x.human_decision,x.executed?"yes":"no"]))}
dt.appendChild(db);box.appendChild(dt);
}
async function refresh(){try{const d=await fetch("/api/overview").then(r=>r.json());
renderOverview(d)}catch(e){$("status").textContent="offline";$("status").className="err"}}
refresh();setInterval(refresh,10000);
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HydraMindDashboard/1.0"

    def log_message(self, fmt: str, *args) -> None:
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, data: dict) -> None:
        self._send(code, json.dumps(data, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(200, dash.health())
            return
        if path == "/api/overview":
            self._json(200, dash.overview())
            return
        if path.startswith("/api/scan/"):
            try:
                scan_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._json(400, {"ok": False, "error": "bad scan id"})
                return
            data = dash.scan_detail(scan_id)
            self._json(200 if data.get("ok") else 404, data)
            return
        if path.startswith("/reports/"):
            name = unquote(path[len("/reports/"):])
            report = dash.safe_report(name)
            if not report:
                self._json(404, {"ok": False, "error": "report not found"})
                return
            ctype = ("text/html; charset=utf-8" if report.suffix == ".html"
                     else "text/markdown; charset=utf-8")
            self._send(200, report.read_bytes(), ctype)
            return
        self._json(404, {"ok": False, "error": "not found"})


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind read-only dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", help="override database path (default data/pipeline.db)")
    ap.add_argument("--verbose", action="store_true", help="log every request")
    args = ap.parse_args()
    if args.db:
        db.DB_PATH = Path(args.db).resolve()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.verbose = args.verbose
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[dashboard] WARNING: bound to a non-loopback address and has no "
              "authentication — do not expose this to an untrusted network.")
    print(f"[dashboard] http://{args.host}:{args.port}  (db: {db.DB_PATH})")
    print("[dashboard] read-only; Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopped")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
