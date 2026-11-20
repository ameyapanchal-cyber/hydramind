"""Offline CVE / ExploitDB retrieval (RAG) for the triager and reasoner.

A small curated corpus (``knowledge/cve_exploits.jsonl``) is ranked with BM25
plus exact boosts for CVE IDs, product names and affected versions. ExploitDB
can be queried through the local ``searchsploit`` binary (opt-in with
``HYDRAMIND_RAG_SEARCHSPLOIT=1``), and extra JSONL corpora can be layered in
with ``HYDRAMIND_RAG_EXTRA`` (os.pathsep-separated paths).

Disable retrieval with ``HYDRAMIND_RAG=0``. Everything runs offline and
deterministically; retrieved references are untrusted context, not commands.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "knowledge" / "cve_exploits.jsonl"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]+")

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "by",
    "from", "is", "are", "was", "were", "be", "as", "at", "this", "that", "it",
    "its", "into", "via", "when", "which", "can", "could", "may", "allow",
    "allows", "allowing", "attacker", "attackers", "host", "hosts", "port",
    "ports", "http", "https", "the", "use", "used", "using", "user", "users",
}

_docs: list[dict] | None = None
_index: tuple | None = None
_index_key: tuple = ()
_sploit_cache: dict[str, list[dict]] = {}


def enabled() -> bool:
    return os.environ.get("HYDRAMIND_RAG", "1").strip().lower() not in (
        "0", "false", "no", "off")


def reload() -> None:
    global _docs, _index, _index_key
    _docs = _index = None
    _index_key = ()


def _extra_paths() -> list[Path]:
    raw = os.environ.get("HYDRAMIND_RAG_EXTRA", "")
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]


def _tokenize(text: str) -> list[str]:
    tokens = []
    for raw in TOKEN_RE.findall(str(text or "").lower()):
        token = raw.strip("._-")
        if token and token not in STOPWORDS and (len(token) > 1 or token.isdigit()):
            tokens.append(token)
    return tokens


def _doc_text(doc: dict) -> str:
    fields = ("id", "title", "description", "exploitation", "severity")
    parts = [str(doc.get(f) or "") for f in fields]
    for field in ("aliases", "products", "versions", "tags"):
        parts.extend(str(x) for x in (doc.get(field) or []))
    return " ".join(parts)


def _load_docs() -> list[dict]:
    global _docs
    paths = [CORPUS_PATH, *_extra_paths()]
    key = tuple((str(p), p.stat().st_mtime if p.exists() else 0) for p in paths)
    if _docs is not None and key == _index_key:
        return _docs
    seen, docs = set(), []
    for path in paths:
        if not path.is_file():
            continue
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(doc, dict) or not doc.get("id") or doc["id"] in seen:
                continue
            seen.add(doc["id"])
            docs.append(doc)
    _docs = docs
    return docs


def _build_index() -> tuple:
    global _index, _index_key
    docs = _load_docs()
    key = ((str(CORPUS_PATH),
            CORPUS_PATH.stat().st_mtime if CORPUS_PATH.exists() else 0),
           *[(str(p), p.stat().st_mtime if p.exists() else 0)
             for p in _extra_paths()])
    if _index is not None and key == _index_key:
        return _index
    tokenized = [_tokenize(_doc_text(d)) for d in docs]
    tfs = [Counter(tokens) for tokens in tokenized]
    df: Counter = Counter()
    for tokens in tokenized:
        df.update(set(tokens))
    avgdl = (sum(len(t) for t in tokenized) / len(tokenized)) if tokenized else 0.0
    _index = (docs, tfs, df, avgdl, len(docs))
    _index_key = key
    return _index


def _query_text(query) -> str:
    if isinstance(query, str):
        return query[:6000]
    try:
        return json.dumps(query, default=str)[:6000]
    except Exception:
        return str(query)[:6000]


def _bm25(query_tokens: list[str], tf: Counter, df: Counter, avgdl: float,
          n_docs: int, k1: float = 1.5, b: float = 0.75) -> float:
    score = 0.0
    dl = sum(tf.values()) or 1
    for token in set(query_tokens):
        freq = tf.get(token)
        if not freq:
            continue
        idf = math.log(1 + (n_docs - df[token] + 0.5) / (df[token] + 0.5))
        score += idf * freq * (k1 + 1) / (
            freq + k1 * (1 - b + b * dl / avgdl))
    return score


def _score_doc(doc: dict, base: float, query_tokens: set[str],
               query_lower: str) -> tuple[float, list[str]]:
    score, why = base, []
    doc_ids = {str(doc.get("id", "")).upper()}
    doc_ids.update(str(a).upper() for a in (doc.get("aliases") or []))
    for cve in set(c.upper() for c in CVE_RE.findall(query_lower)):
        if cve in doc_ids:
            score += 6.0
            why.append(cve)
    for version in doc.get("versions") or []:
        v = str(version).lower()
        if v and (v in query_tokens or v in query_lower):
            score += 1.6
            why.append(v)
    for product in doc.get("products") or []:
        parts = [t for t in _tokenize(product) if t not in STOPWORDS]
        if parts and sum(1 for t in parts if t in query_tokens) / len(parts) >= 0.6:
            score += 1.2
            why.append(str(product))
    matched = [t for t in _tokenize(query_lower) if t in _tokenize(_doc_text(doc))]
    why.extend(t for t in matched if t not in why)
    return score, why[:6]


def _searchsploit(query: str, limit: int = 3) -> list[dict]:
    if os.environ.get("HYDRAMIND_RAG_SEARCHSPLOIT", "").lower() not in (
            "1", "true", "yes", "on"):
        return []
    exe = shutil.which("searchsploit")
    terms = " ".join(re.findall(r"[A-Za-z0-9_.-]{3,}", query)[:6])
    if not exe or not terms:
        return []
    if terms in _sploit_cache:
        return _sploit_cache[terms]
    results: list[dict] = []
    try:
        proc = subprocess.run([exe, "--json", terms], capture_output=True,
                              text=True, timeout=8)
        data = json.loads(proc.stdout or "{}")
        for item in (data.get("RESULTS_EXPLOIT") or [])[:limit]:
            edb = str(item.get("EDB-ID") or "").strip()
            if not edb:
                continue
            results.append({
                "id": f"EDB-{edb}",
                "title": item.get("Title") or f"ExploitDB {edb}",
                "aliases": [], "products": [], "versions": [],
                "severity": "unknown", "cvss": None,
                "tags": ["exploitdb", "exploit"],
                "description": f"ExploitDB entry {edb} — {item.get('Path') or ''}".strip(),
                "exploitation": item.get("Title") or "",
                "references": [f"https://www.exploit-db.com/exploits/{edb}"],
            })
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        results = []
    _sploit_cache[terms] = results
    return results


def retrieve(query, k: int = 3, min_score: float = 0.8) -> list[dict]:
    """Return up to k ranked references for a query (str/dict/list)."""
    if not enabled():
        return []
    text = _query_text(query)
    query_tokens = _tokenize(text)
    if not query_tokens:
        return []
    docs, tfs, df, avgdl, n_docs = _build_index()
    if not docs:
        return []
    scored = []
    qset = set(query_tokens)
    for doc, tf in zip(docs, tfs):
        base = _bm25(query_tokens, tf, df, avgdl, n_docs)
        score, why = _score_doc(doc, base, qset, text.lower())
        if score >= min_score:
            scored.append((score, doc, why))
    scored.sort(key=lambda item: item[0], reverse=True)
    if scored:
        cutoff = max(min_score, scored[0][0] * 0.6)
        scored = [item for item in scored if item[0] >= cutoff]
    results = []
    for score, doc, why in scored[:k]:
        results.append({
            "id": doc.get("id"), "title": doc.get("title"),
            "severity": doc.get("severity"), "cvss": doc.get("cvss"),
            "score": round(score, 2), "why": why,
            "description": doc.get("description") or "",
            "exploitation": doc.get("exploitation") or "",
            "references": doc.get("references") or [],
        })
    if len(results) < k:
        for extra in _searchsploit(text, k - len(results)):
            if any(r["id"] == extra["id"] for r in results):
                continue
            results.append({**extra, "score": round(min_score, 2),
                            "why": ["exploitdb"]})
    return results[:k]


def retrieve_for_finding(finding: dict, k: int = 3) -> list[dict]:
    fields = ("title", "description", "detail", "finding", "product", "version",
              "service", "why", "next_step", "raw_evidence", "url", "path")
    text = " ".join(str(finding.get(f) or "") for f in fields)
    return retrieve(text, k=k)


def context_block(docs: list[dict]) -> str:
    if not docs:
        return ""
    lines = ["Retrieved reference material (local CVE/ExploitDB corpus). Use it "
             "only when relevant, cite entries as [R#], and never invent CVE IDs "
             "or exploit details."]
    for index, doc in enumerate(docs, 1):
        meta = [str(doc.get("id") or "")]
        if doc.get("severity"):
            meta.append(str(doc["severity"]))
        if doc.get("cvss") is not None:
            meta.append(f"CVSS {doc['cvss']}")
        lines.append(f"[R{index}] {' · '.join(meta)} — {doc.get('title', '')}")
        if doc.get("description"):
            lines.append(f"     {str(doc['description'])[:350]}")
        if doc.get("exploitation"):
            lines.append(f"     Known exploitation: {str(doc['exploitation'])[:350]}")
        refs = [r for r in (doc.get("references") or []) if r]
        if refs:
            lines.append(f"     Reference: {refs[0]}")
    return "\n".join(lines)


def stats() -> dict:
    docs = _load_docs()
    return {"corpus": str(CORPUS_PATH), "documents": len(docs),
            "extra": [str(p) for p in _extra_paths()],
            "searchsploit": os.environ.get("HYDRAMIND_RAG_SEARCHSPLOIT", "").lower()
            in ("1", "true", "yes", "on")}
