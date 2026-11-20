#!/usr/bin/env python3
"""LangGraph review agent — plan next steps for an existing scan without
executing anything.

    python3 agent.py --scan 16
    python3 agent.py --scan 16 --routing --max-deep 3
    python3 agent.py --scan 16 --no-rag --json /tmp/plan.json

Reads SQLite only (and logs model calls for audit), retrieves CVE/ExploitDB
references, routes high-signal findings to the reasoner, validates every
proposed command with the fail-closed safety boundary, and writes
data/agent_scan_<id>.json. Execution always remains behind main.py's human
approval gate.
"""
from __future__ import annotations

import argparse
import os
import sys

from engine import agent, rag, routing


def main() -> int:
    ap = argparse.ArgumentParser(description="HydraMind LangGraph review agent")
    ap.add_argument("--scan", type=int, required=True, help="existing scan id")
    ap.add_argument("--max-findings", type=int, default=10,
                    help="max triage findings to review (default 10)")
    ap.add_argument("--max-deep", type=int, default=4,
                    help="max reasoner calls (default 4)")
    ap.add_argument("--profile", help="model profile (hybrid/free/quality/local)")
    ap.add_argument("--routing", action="store_true",
                    help="enable context-aware routing from config/routing.yaml")
    ap.add_argument("--no-rag", action="store_true", help="disable CVE/ExploitDB retrieval")
    ap.add_argument("--json", help="output path (default data/agent_scan_<id>.json)")
    args = ap.parse_args()
    if args.routing:
        os.environ["HYDRAMIND_ROUTING"] = "1"

    print(f"[agent] LangGraph review · scan {args.scan} · "
          f"profile {args.profile or 'default'} · RAG "
          f"{'off' if args.no_rag else rag.stats()['documents']} docs · routing "
          f"{'on' if routing.enabled() else 'off'}")
    state = agent.run(args.scan, max_findings=args.max_findings,
                      max_deep=args.max_deep, use_rag=not args.no_rag,
                      output=args.json, profile=args.profile)
    if state.get("error"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
