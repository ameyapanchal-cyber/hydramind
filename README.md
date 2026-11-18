# HydraMind — Multi-Model AI Orchestrator for Offensive Security

HydraMind automates an authorized web pentest workflow:
recon → AI triage → vuln scan → AI reasoning → (human approval) → exploit (lab only) → AI report.
Many models (the heads), one reasoning core (the mind).

**Ethics:** runs ONLY against targets in `config/scope.yaml` — labs, owned systems, or in-scope bug bounty. Nothing else.

## Requirements
- Kali Linux, Python 3.11+, nmap

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
Out-of-scope targets are refused by the Scope Firewall.

Pipeline: recon (nmap → gobuster → nikto, all saved to SQLite) →
GPT-4o-mini triage → **GPT-4o reasoner** (attack paths + proposed actions) →
**human approval gate** → approved actions run through `engine/runner.py` →
`data/report_N.json`.

The approval gate:
- `passive` actions (safe recon re-runs) — prompt defaults to **yes**
- `active` actions (brute force / injection / anything risky) — prompt defaults
  to **NO**; you must type `y` explicitly. No input = never runs.
- Non-implemented tools (sqlmap/hydra/wpscan) are logged as approved + queued
  for Phase 3, executed then.
- Reasoner model is overrideable: `HYDRAMIND_REASONER_MODEL=gpt-4o`
- Every proposed action is audited in the `actions` table — approved or not.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1 (done): gobuster + nikto + AI triage
- Phase 2 (done): AI reasoner + human approval gate
- Phase 3: sqlmap (labs only)
- Phase 4: validator + report writer + PortSwigger eval
- Phase 5: n8n trigger/notify + dashboard
