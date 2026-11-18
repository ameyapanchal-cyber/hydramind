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

Demo transcript: pending — will be added after the first full run against the
lab VM (Metasploitable2/DVWA) once it is reachable and scope-listed.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1 (done): gobuster + nikto + AI triage
- Phase 2 (done): per-finding AI reasoner + human approval gate + two-stage scope policy
- Phase 3: sqlmap/hydra/wpscan/commix (labs only, extra-gated) + execution wiring
- Phase 4: validator + report writer + PortSwigger eval
- Phase 5: n8n trigger/notify + dashboard
