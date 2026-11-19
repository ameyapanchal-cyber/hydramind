"""PortSwigger Web Security Academy eval harness.

Runs the HydraMind pipeline in --dry-run mode against Academy labs and scores
whether the Reasoner proposed the expected tool/approach for each lab. Nothing
is executed: this measures recon → triage → reasoning quality only. Live
exploitation stays behind the normal human approval gate.

Setup:
  1. cp eval/labs.example.yaml eval/labs.yaml   (gitignored)
  2. launch labs on https://portswigger.net/web-security/all-labs
  3. fill in each lab's host + seed URL in eval/labs.yaml
  4. add every lab host to config/scope.yaml, e.g.:

       targets:
         - host: <lab-host>
           authorized: true
           environment: lab
           allowed_tools: [nmap, gobuster, nikto, curl, sqlmap, commix,
                           wpscan, hydra]

  5. python eval/run_eval.py            (uses the venv's python + API key)

Outputs: eval/results/eval_<timestamp>.json + a summary table.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import models  # noqa: E402
from engine.scope_firewall import ScopeFirewall, ScopeError  # noqa: E402

SCOPE_FILE = ROOT / "config" / "scope.yaml"
DEFAULT_LABS = Path(__file__).resolve().parent / "labs.yaml"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60]


def _score(lab: dict, decisions: list[dict]) -> dict:
    expected_tools = {t.lower() for t in (lab.get("expect", {}).get("tools") or [])}
    keywords = [k.lower() for k in (lab.get("expect", {}).get("keywords") or [])]
    commands = [d.get("exact_tool_and_command") or "" for d in decisions]
    texts = " ".join(
        f"{d.get('attack_hypothesis', '')} {d.get('exact_tool_and_command', '')} "
        f"{d.get('expected_outcome', '')}" for d in decisions).lower()

    proposed_tools = []
    for cmd in commands:
        first = cmd.strip().split()[0].strip("'\"") if cmd.strip() else ""
        if first:
            proposed_tools.append(first.lower())
    tool_hits = sorted(expected_tools & set(proposed_tools))
    keyword_hits = [k for k in keywords if k in texts]

    tool_ok = bool(tool_hits)
    keyword_ok = bool(keyword_hits) if keywords else None
    if tool_ok and (keyword_ok or keyword_ok is None):
        score = 1.0
    elif tool_ok:
        score = 0.5
    else:
        score = 0.0
    return {
        "score": score,
        "tool_hits": tool_hits,
        "keyword_hits": keyword_hits,
        "proposed_tools": sorted(set(proposed_tools)),
        "proposals": len(decisions),
    }


def run_lab(lab: dict, fw: ScopeFirewall, args) -> dict:
    name = lab.get("name") or "(unnamed lab)"
    target = str(lab.get("target") or "").strip().lower()
    seed_url = str(lab.get("seed_url") or "").strip()
    result = {"name": name, "target": target, "status": "error", "score": 0.0}
    if not target or not seed_url:
        result["error"] = "lab entry needs 'target' and 'seed_url'"
        return result

    try:
        fw.check(target)
    except ScopeError as e:
        result["status"] = "scope_missing"
        result["error"] = str(e)
        return result

    slug = _slug(name)
    artifact = ROOT / "eval" / "artifacts" / f"{slug}.json"
    log_path = ROOT / "eval" / "artifacts" / f"{slug}.log"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        args.python, "-u", str(ROOT / "main.py"),
        "--target", target,
        "--seed-url", seed_url,
        "--dry-run", "--skip-nikto", "--no-report", "--no-validate",
        "--ports", args.ports,
        "--json-report", str(artifact),
    ]
    if args.profile:
        cmd += ["--profile", args.profile]
    started = datetime.now(timezone.utc).isoformat()
    with log_path.open("w") as log:
        log.write(f"$ {' '.join(cmd)}\n\n")
        log.flush()
        try:
            proc = subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=args.timeout)
        except subprocess.TimeoutExpired:
            result.update(status="timeout", error=f"pipeline exceeded {args.timeout}s")
            return result

    result["returncode"] = proc.returncode
    result["artifact"] = str(artifact)
    result["log"] = str(log_path)
    if not artifact.exists():
        result["error"] = "pipeline produced no JSON report (see log)"
        return result
    data = json.loads(artifact.read_text())
    decisions = data.get("decisions") or []
    result.update(_score(lab, decisions))
    result["status"] = "ok" if proc.returncode == 0 else "pipeline_error"
    result["started"] = started
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind PortSwigger eval harness")
    ap.add_argument("--labs", default=str(DEFAULT_LABS), help="lab manifest YAML")
    ap.add_argument("--only", help="run only labs whose name contains this text")
    ap.add_argument("--limit", type=int, help="max number of labs to run")
    ap.add_argument("--ports", default="80,443", help="nmap ports for labs")
    ap.add_argument("--timeout", type=int, default=600, help="per-lab timeout (s)")
    ap.add_argument("--python", default=os.environ.get("HYDRAMIND_PYTHON", sys.executable),
                    help="python interpreter for main.py (default: this venv)")
    ap.add_argument("--out-dir", default=str(ROOT / "eval" / "results"))
    ap.add_argument("--profile", help="model profile for the pipeline "
                                      "(hybrid/free/quality/local)")
    args = ap.parse_args()
    models.configure(args.profile)

    labs_path = Path(args.labs)
    if not labs_path.exists():
        print(f"[eval] manifest not found: {labs_path}")
        print("[eval] cp eval/labs.example.yaml eval/labs.yaml and fill in lab hosts")
        return 1
    manifest = yaml.safe_load(labs_path.read_text()) or {}
    labs = manifest.get("labs") or []
    if args.only:
        labs = [l for l in labs if args.only.lower() in (l.get("name") or "").lower()]
    if args.limit:
        labs = labs[: args.limit]
    if not labs:
        print("[eval] no labs to run")
        return 1

    fw = ScopeFirewall(SCOPE_FILE)
    results = []
    rcfg = models.resolve_role("reasoner")
    print(f"[eval] {len(labs)} lab(s) · profile {models.active_profile()} · "
          f"reasoner {rcfg['provider']}/{rcfg['model']}")
    for lab in labs:
        print(f"\n[eval] {lab.get('name')} ({lab.get('category', '?')})")
        r = run_lab(lab, fw, args)
        results.append(r)
        if r["status"] == "scope_missing":
            print(f"       SCOPE MISSING: {r.get('error')}")
            print("       add the lab host to config/scope.yaml (environment: lab)")
        elif r["status"] != "ok":
            print(f"       {r['status'].upper()}: {r.get('error', '')}")
        else:
            print(f"       score {r['score']:.1f} · tools {r['tool_hits']} "
                  f"· keywords {r['keyword_hits']} · proposals {r['proposals']}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"eval_{stamp}.json"
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": models.active_profile(),
        "reasoner_model": f"{rcfg['provider']}/{rcfg['model']}",
        "labs": results,
        "summary": {
            "labs": len(results),
            "ok": sum(1 for r in results if r["status"] == "ok"),
            "avg_score": round(sum(r["score"] for r in results) / len(results), 3),
            "tool_hit_labs": sum(1 for r in results if r.get("tool_hits")),
        },
    }
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"\n[eval] results → {out_path}")
    print(f"[eval] ok {summary['summary']['ok']}/{len(results)} · "
          f"avg score {summary['summary']['avg_score']} · "
          f"tool-hit labs {summary['summary']['tool_hit_labs']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
