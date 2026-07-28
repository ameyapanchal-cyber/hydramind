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
```

## Run (Phase 0)
```bash
python3 main.py --target scanme.nmap.org
```
Out-of-scope targets are refused by the Scope Firewall.

## Roadmap
- Phase 0 (done): scope firewall + nmap engine + SQLite store
- Phase 1: gobuster + nikto + AI triage
- Phase 2: AI reasoner + human approval gate
- Phase 3: sqlmap (labs only)
- Phase 4: validator + report writer + PortSwigger eval
- Phase 5: n8n trigger/notify + dashboard
