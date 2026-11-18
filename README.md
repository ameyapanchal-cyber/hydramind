# HydraMind — Multi-Model AI Orchestrator for Offensive Security

HydraMind automates an authorized web pentest workflow:
recon → AI triage → vuln scan → AI reasoning → (human approval) → exploit (lab only) → AI report.
Many models (the heads), one reasoning core (the mind).

**Ethics:** runs ONLY against targets in `config/scope.yaml` — labs, owned systems, or in-scope bug bounty. Nothing else.

## Requirements
- Kali Linux, Python 3.11+, nmap, gobuster, nikto

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...   # required for the AI heads
```

## Run (Phase 2)
```bash
python3 main.py --target scanme.nmap.org --skip-nikto
```
Out-of-scope targets are refused by the Scope Firewall before any subprocess runs.

Pipeline: scope check → recon (nmap → gobuster → nikto, all saved to SQLite) →
GPT-4o-mini triage → **per-finding GPT-4o Reasoner** → **human approval gate** →
approved passive actions execute via `engine/runner.py`; exploitation-class tools
are logged + queued for Phase 3 → `data/report_N.json`.

### Scope firewall — two-stage authorization
`config/scope.yaml` supports two forms side by side:
- legacy `allowed_hosts` — recon only; exploitation-class tools always refused
- rich `targets:` entries — per-target policy:
  `host`, `authorized`, `environment: lab | live_authorized`,
  `allowed_tools`, `forbidden_tools`, `program_rules_url`, `rate_limit`

Check 1: is the host authorized at all? Check 2: is the specific tool allowed
for this target (`check_tool`)? Exploitation-class tools (sqlmap/hydra/wpscan/
commix/metasploit) require `environment: lab` regardless of `allowed_tools`.
Every allow/deny decision is logged to the `scope_events` table.

### Reasoner + approval gate
- Reasons about ONE finding at a time. Context includes sibling findings and
  the history of already-approved/executed actions for the target, so attack
  chains build step by step — each step human-approved.
- The proposed command must survive `validate_action()`: tool whitelist,
  fail-closed argument validation, no shell metacharacters, no file I/O args,
  and it must reference the scoped target. One bad token rejects the action.
- `passive` proposals default to **yes**; `active`/`exploit` default to **NO**
  — you must type `y` explicitly. No input / EOF = never runs.
- On `n`: a one-line rejection reason is required and logged.
- Every decision lands in `reasoner_decisions` (FK to `triage_findings`) with
  hypothesis, proposed command, confidence, risk level, human decision,
  rejection reason, execution result.
- Approved exploitation-class proposals are logged and stop the pipeline —
  Phase 3 wires actual execution behind the same gate.
- Model override: `HYDRAMIND_REASONER_MODEL=gpt-4o`

Demo transcript: see below. First full live run: DVWA lab (Docker container on
this Kali VM, `http://127.0.0.1:8081`), 2026-11-18.

### Demo run — DVWA lab (real terminal output, trimmed)

```text
[scope] '127.0.0.1' authorized.

[nmap] scanning ports + services...
       3 open port(s) found.            # 3000, 8080 (Apache 2.4.49), 8081 (DVWA / Apache 2.4.25)
[gobuster] brute-forcing http://127.0.0.1:8080...
           5 path(s) found.
[gobuster] brute-forcing http://127.0.0.1:8081...
           12 path(s) found.            # /config, /docs, /external, /php.ini, ...
[nikto] scanning http://127.0.0.1:8080 ... 0 finding(s).
[nikto] scanning http://127.0.0.1:8081 ... 0 finding(s).   # DVWA needs auth; nikto sees little

[triager] sending 20 finding(s) to GPT-4o-mini for analysis...
  [HIGH]   #1 Apache httpd 2.4.49 detected
  [MEDIUM] #2 Apache httpd 2.4.25 detected
  [MEDIUM] #3 php.ini file accessible at /php.ini
  [LOW]    #4 sensitive paths: /config, /docs, /external

--- Finding #1 [HIGH] Apache httpd version 2.4.49 detected
  hypothesis : ...CVE-2021-41773 path traversal...
  command    : nikto -h http://127.0.0.1
  expected   : confirm known vulns/misconfigs
  confidence : 70%   risk: passive
    Approve action for finding #1? [Y/n]   → running...
  → done: rc=0, 1 finding(s) @ http://127.0.0.1

--- Finding #2 [MEDIUM] Apache httpd version 2.4.25 detected
  command    : nikto -h http://127.0.0.1
    Approve action for finding #2? [Y/n]   rejection reason (one line):
      → "Duplicate of #1; port 80 closed — use :8081/:8080"

--- Finding #3 [MEDIUM] php.ini file accessible at /php.ini
  command    : nikto -h http://127.0.0.1:8080
    Approve action for finding #3? [Y/n]   rejection reason (one line):
      → "Duplicate of recon nikto on :8080; php.ini lives on :8081"

--- Finding #4 [LOW] Potential sensitive paths found: /config, /docs, /external
  command    : nikto -h http://127.0.0.1:8080 -C all
    Approve action for finding #4? [Y/n]   rejection reason (one line):
      → "Paths discovered on :8081; :8080 already nikto-scanned"

[db] full report saved → data/report_2.json
```

All four decisions are queryable in `reasoner_decisions` (finding FK, command,
confidence, decision, rejection reason, result). The full report is
`data/report_2.json`.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1 (done): gobuster + nikto + AI triage
- Phase 2 (done): per-finding AI reasoner + human approval gate + two-stage scope policy
- Phase 3: sqlmap/hydra/wpscan/commix (labs only, extra-gated) + execution wiring
- Phase 4: validator + report writer + PortSwigger eval
- Phase 5: n8n trigger/notify + dashboard
