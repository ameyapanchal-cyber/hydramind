"""LangGraph review agent — non-executing second opinion over an existing scan.

The agent fans out from a persisted scan into a planning graph:

    load -> route -> (deep_review | assemble) -> assemble -> END

``route`` retrieves CVE/ExploitDB references and applies the routing policy per
finding (severity + RAG score). High-signal findings get a reasoner call that
proposes ONE next command; everything else is reported as "keep existing
triage". Every proposed command is checked by ``validate_action`` (the same
fail-closed safety boundary the executor uses) and **never executed**. The
agent does not modify findings, triage, decisions or validations; model calls
are logged for audit and the plan is written to data/agent_scan_<id>.json.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from engine import db, models, notifier, rag, routing
from engine.findings import finding_from_triage
from engine.reasoner import reason_about_finding, validate_action

ROOT = Path(__file__).resolve().parents[1]
DEEP_SEVERITIES = ("critical", "high")
DEFAULT_RAG_DEEP = 4.0


class AgentState(TypedDict, total=False):
    scan_id: int
    target: str
    profile: str
    max_findings: int
    max_deep: int
    use_rag: bool
    output: str
    findings: list
    history: list
    plans: list
    reviews: list
    result: dict
    error: str


def _can_reason(cfg: dict) -> bool:
    provider = cfg.get("provider")
    return provider not in (None, "", "none") and models.available(provider)


def _rag_retrieve(item: dict, use_rag: bool) -> list[dict]:
    return rag.retrieve_for_finding(item, k=3) if use_rag else []


def load_node(state: AgentState) -> dict:
    scan = db.scan_row(state["scan_id"])
    if not scan:
        return {"error": f"scan {state['scan_id']} not found"}
    triage = db.triage_for_scan(state["scan_id"])
    if not triage:
        return {"error": f"scan {state['scan_id']} has no triage findings"}
    validations = {v.get("finding_id"): v
                   for v in db.validations_for_scan(state["scan_id"])}
    decisions = {d.get("finding_id"): d
                 for d in db.decisions_for_scan(state["scan_id"])}
    findings = []
    for row in triage[: max(1, int(state.get("max_findings") or 10))]:
        item = dict(row)
        val = validations.get(item["id"]) or {}
        dec = decisions.get(item["id"]) or {}
        item["existing_verdict"] = val.get("verdict") or ""
        item["existing_command"] = (dec.get("proposed_command") or "")[:300]
        item["executed"] = bool(dec.get("executed"))
        findings.append(item)
    history = [{
        "tool": d.get("source") or "", "risk": d.get("risk_level") or "",
        "description": (d.get("proposed_command") or "")[:200],
        "result": (d.get("result") or "")[:200],
        "executed": bool(d.get("executed")),
    } for d in db.decisions_for_scan(state["scan_id"])][:10]
    return {"target": scan["target"], "profile": models.active_profile(),
            "findings": findings, "history": history}


def route_node(state: AgentState) -> dict:
    if state.get("error"):
        return {"plans": []}
    use_rag = bool(state.get("use_rag", True))
    deep_score = float(os.environ.get("HYDRAMIND_AGENT_RAG_DEEP", DEFAULT_RAG_DEEP))
    plans = []
    for item in state.get("findings") or []:
        docs = _rag_retrieve(item, use_rag)
        score = float(docs[0]["score"]) if docs else 0.0
        cfg, decision = routing.resolve("reasoner", {
            "severity": item.get("severity"), "source": item.get("source"),
            "rag_score": score})
        deep = (str(item.get("severity") or "").lower() in DEEP_SEVERITIES
                or score >= deep_score or decision.get("tier") == "deep")
        plans.append({
            "finding_id": item["id"],
            "rank": item.get("rank"),
            "title": (item.get("description") or "")[:200],
            "severity": item.get("severity") or "",
            "source": item.get("source") or "",
            "existing_verdict": item.get("existing_verdict") or "",
            "executed": item.get("executed") or False,
            "row": item,
            "refs": [{"id": d["id"], "title": d["title"], "score": d["score"]}
                     for d in docs],
            "mode": "deep" if deep else "quick",
            "quick_reason": "" if deep else "no high-severity or high-signal RAG match",
            "cfg": cfg,
            "routing": decision,
        })
    deep_used = 0
    raw_deep = state.get("max_deep")
    max_deep = 4 if raw_deep is None else max(0, int(raw_deep))
    for plan in plans:
        if plan["mode"] != "deep":
            continue
        if deep_used >= max_deep:
            plan["mode"], plan["quick_reason"] = "quick", "deep-review cap reached"
        elif not _can_reason(plan["cfg"]):
            plan["mode"], plan["quick_reason"] = "quick", "reasoner provider unavailable"
        else:
            deep_used += 1
    return {"plans": plans}


def _route_after_route(state: AgentState) -> str:
    if state.get("error"):
        return "assemble"
    return "deep_review" if any(p["mode"] == "deep"
                                for p in state.get("plans") or []) else "assemble"


def deep_review_node(state: AgentState) -> dict:
    target = state["target"]
    siblings = [{"title": (p.get("title") or "")[:120],
                 "severity": p.get("severity") or "",
                 "source": p.get("source") or ""}
                for p in state.get("plans") or []]
    reviews = []
    for plan in state.get("plans") or []:
        if plan["mode"] != "deep":
            continue
        row = plan["row"]
        finding = finding_from_triage({
            "rank": row.get("rank"), "severity": row.get("severity"),
            "source": row.get("source"), "finding": row.get("description"),
            "why": row.get("why"), "next_step": row.get("next_step"),
        }, target)
        context = {"target": target, "sibling_findings": siblings,
                   "action_history": state.get("history") or []}
        try:
            out = reason_about_finding(finding, context,
                                       scan_id=state["scan_id"],
                                       role_cfg=plan["cfg"])
        except Exception as e:
            reviews.append({"finding_id": plan["finding_id"], "mode": "deep",
                            "error": models.redact(e)[:300]})
            continue
        safety = validate_action(out.exact_tool_and_command, target)
        reviews.append({
            "finding_id": plan["finding_id"],
            "mode": "deep",
            "proposal": out.to_dict(),
            "command_safe": bool(safety),
            "safety_note": ("passed validate_action; NOT executed" if safety
                            else "rejected by validate_action"),
        })
    return {"reviews": reviews}


def assemble_node(state: AgentState) -> dict:
    if state.get("error"):
        print(f"[agent] {state['error']}")
        return {"result": {"error": state["error"]}}
    by_id = {r["finding_id"]: r for r in state.get("reviews") or []}
    entries = []
    deep = quick = failed = unsafe = 0
    for plan in state.get("plans") or []:
        review = by_id.get(plan["finding_id"])
        entry = {
            "finding_id": plan["finding_id"], "rank": plan["rank"],
            "title": plan["title"], "severity": plan["severity"],
            "source": plan["source"], "existing_verdict": plan["existing_verdict"],
            "executed": plan["executed"], "mode": plan["mode"],
            "routing": plan["routing"], "references": plan["refs"],
            "proposal": None, "command_safe": None, "note": "",
        }
        if plan["mode"] == "deep" and review:
            if review.get("error"):
                entry["note"] = f"reasoner error: {review['error']}"
                failed += 1
            else:
                entry.update(review)
                entry["mode"] = "deep"
                deep += 1
                if not review.get("command_safe"):
                    unsafe += 1
        else:
            entry["note"] = plan.get("quick_reason") or "quick review"
            quick += 1
        entries.append(entry)
    references = {}
    for entry in entries:
        for ref in entry["references"]:
            references[ref["id"]] = ref
    result = {
        "scan_id": state["scan_id"],
        "target": state["target"],
        "profile": state.get("profile") or models.active_profile(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executes": False,
        "rag": rag.stats() if state.get("use_rag", True) else {"enabled": False},
        "counts": {"findings": len(entries), "deep_reviews": deep,
                   "quick": quick, "failed": failed, "unsafe_commands": unsafe},
        "references": list(references.values()),
        "findings": entries,
        "note": ("Review only — not executed. Proposed commands passed "
                 "through validate_action but still require the normal human "
                 "approval gate in main.py."),
    }
    out = Path(state.get("output") or (ROOT / "data" / f"agent_scan_{state['scan_id']}.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"[agent] {len(entries)} finding(s): {deep} deep, {quick} quick, "
          f"{failed} failed, {unsafe} unsafe command(s)")
    for entry in entries:
        refs = ", ".join(r["id"] for r in entry["references"][:3]) or "-"
        if entry.get("proposal"):
            cmd = entry["proposal"].get("exact_tool_and_command") or ""
            flag = "OK" if entry.get("command_safe") else "REJECTED"
            print(f"  #{entry['rank']} [{entry['severity']}] {entry['title'][:70]}")
            print(f"      refs: {refs}")
            print(f"      next: {cmd[:120]}  ({flag}, not executed)")
        else:
            print(f"  #{entry['rank']} [{entry['severity']}] "
                  f"{entry['title'][:70]} — {entry['note']}")
    print(f"[agent] plan → {out}")
    notifier.emit("agent_plan", {
            "scan_id": state["scan_id"], "target": state["target"],
        "profile": result["profile"], "counts": result["counts"],
        "output": str(out)})
    return {"result": result, "output": str(out)}


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("load", load_node)
    graph.add_node("route", route_node)
    graph.add_node("deep_review", deep_review_node)
    graph.add_node("assemble", assemble_node)
    graph.add_edge(START, "load")
    graph.add_edge("load", "route")
    graph.add_conditional_edges("route", _route_after_route,
                                {"deep_review": "deep_review",
                                 "assemble": "assemble"})
    graph.add_edge("deep_review", "assemble")
    graph.add_edge("assemble", END)
    return graph.compile()


def run(scan_id: int, *, max_findings: int = 10, max_deep: int = 4,
        use_rag: bool = True, output: str | None = None,
        profile: str | None = None) -> dict:
    models.configure(profile)
    app = build_graph()
    return app.invoke({
        "scan_id": int(scan_id), "max_findings": int(max_findings),
        "max_deep": int(max_deep), "use_rag": bool(use_rag),
        "output": output,
    })
