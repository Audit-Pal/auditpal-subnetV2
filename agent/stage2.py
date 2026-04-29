"""
Stage 2 — Prioritize & Group (~1s, no LLM)
============================================
Components:
  - Risk scoring engine   : weighted points from Stage 1 patterns
  - Contract clusterer    : groups by import/call edges
  - Context summarizer    : compact summary per session
  - Dispatch planner      : assigns clusters to LLM sessions by token budget

Input  : Stage1Result from stage1_static.run_stage1()
Output : list[Session] — each session is one LLM call in Stage 3
"""

from __future__ import annotations

import sys
from collections import defaultdict
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────

MAX_SESSIONS          = 4      # max parallel LLM calls in Stage 3
TOKEN_BUDGET_PER_SESSION = 8_000   # chars per session context (not real tokens)
MIN_RISK_TO_AUDIT     = 0      # always audit, even low-risk files

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[stage2] {msg}", file=sys.stderr, flush=True)


# ════════════════════════════════════════════════════════════════════════════════
# A — Risk Scoring Engine
# ════════════════════════════════════════════════════════════════════════════════

def score_contracts(stage1: dict[str, Any]) -> dict[str, int]:
    """
    Compute final risk score per contract file.
    Combines: pattern weights + money flow weights + edge risk + reentrancy suspects.
    Returns {filename: score} sorted descending.
    """
    # Start from Stage 1 pre-computed scores
    scores: dict[str, int] = dict(stage1.get("risk_scores", {}))

    # Bonus: reentrancy suspects get extra weight
    for suspect in stage1.get("reentrancy_suspects", []):
        fname = suspect["contract"] + ".sol"
        for key in scores:
            if suspect["contract"].lower() in key.lower():
                scores[key] += 50   # reentrancy is highest priority
                break

    # Bonus: contracts with external call map entries (more attack surface)
    ext_map = stage1.get("external_calls", {})
    for caller, callees in ext_map.items():
        contract = caller.split(".")[0]
        for key in scores:
            if contract.lower() in key.lower():
                scores[key] += len(callees) * 5
                break

    sorted_scores = dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))
    _log(f"Risk scores: {sorted_scores}")
    return sorted_scores


# ════════════════════════════════════════════════════════════════════════════════
# B — Contract Clusterer
# ════════════════════════════════════════════════════════════════════════════════

def cluster_contracts(
    stage1:        dict[str, Any],
    risk_scores:   dict[str, int],
    contracts:     dict[str, str],
) -> list[list[str]]:
    """
    Group related contracts into clusters using import/call edges.
    Uses connected-component analysis on the call graph.

    Returns list of clusters, each cluster = [filename, ...], sorted by total risk desc.
    """
    # Build adjacency from call edges
    adjacency: dict[str, set[str]] = defaultdict(set)

    for edge in stage1.get("edges", []):
        caller   = edge["caller"].split(".")[0]
        callee   = edge["callee"].split(".")[0] if "." in edge["callee"] else ""

        if not callee or callee == caller:
            continue

        # Find matching filenames
        caller_file = _find_file(caller, contracts)
        callee_file = _find_file(callee, contracts)

        if caller_file and callee_file and caller_file != callee_file:
            adjacency[caller_file].add(callee_file)
            adjacency[callee_file].add(caller_file)

    # Also link via AST imports
    for contract_data in stage1.get("ast", []):
        source_file = _normalize_filename(contract_data.get("source_file", ""))
        for imp in contract_data.get("imports", []):
            imp_file = _normalize_filename(imp)
            imp_match = _find_file(imp_file.replace(".sol", ""), contracts)
            if imp_match and imp_match != source_file and source_file in contracts:
                adjacency[source_file].add(imp_match)
                adjacency[imp_match].add(source_file)

    # Connected components DFS
    all_files = list(contracts.keys())
    visited:  set[str] = set()
    clusters: list[list[str]] = []

    def _dfs(node: str, cluster: list[str]) -> None:
        visited.add(node)
        cluster.append(node)
        for neighbor in adjacency.get(node, []):
            if neighbor not in visited and neighbor in contracts:
                _dfs(neighbor, cluster)

    for fname in all_files:
        if fname not in visited:
            cluster: list[str] = []
            _dfs(fname, cluster)
            clusters.append(cluster)

    # Sort clusters by total risk (highest first)
    clusters.sort(
        key=lambda c: sum(risk_scores.get(f, 0) for f in c),
        reverse=True,
    )

    _log(f"Clustered {len(all_files)} file(s) into {len(clusters)} cluster(s)")
    for i, c in enumerate(clusters):
        total = sum(risk_scores.get(f, 0) for f in c)
        _log(f"  Cluster {i+1}: {c}  total_risk={total}")

    return clusters


def _find_file(name: str, contracts: dict[str, str]) -> str | None:
    """Find a filename in contracts dict by contract name (case-insensitive)."""
    name_lower = name.lower().replace(".sol", "")
    for fname in contracts:
        if name_lower in fname.lower().replace(".sol", ""):
            return fname
    return None


def _normalize_filename(path: str) -> str:
    from pathlib import Path
    return Path(path).name


# ════════════════════════════════════════════════════════════════════════════════
# C — Context Summarizer
# ════════════════════════════════════════════════════════════════════════════════

def summarize_cluster(
    cluster:     list[str],
    stage1:      dict[str, Any],
    risk_scores: dict[str, int],
) -> str:
    """
    Generate a compact text summary of a cluster for the LLM session prompt.
    Tells the LLM what to focus on before it sees the raw source.
    """
    lines = ["## Codebase Intelligence (pre-computed by static analysis)\n"]

    # Per-file risk overview
    lines.append("### File Risk Summary")
    for fname in cluster:
        score    = risk_scores.get(fname, 0)
        priority = "⚠ HIGH" if score >= 60 else "▲ MED" if score >= 30 else "● LOW"
        lines.append(f"  {priority}  {fname}  (risk={score})")
    lines.append("")

    # Reentrancy suspects
    suspects = [
        s for s in stage1.get("reentrancy_suspects", [])
        if any(s["contract"].lower() in f.lower() for f in cluster)
    ]
    if suspects:
        lines.append("### ⚠ Reentrancy Suspects (audit FIRST)")
        for s in suspects:
            lines.append(f"  - {s['contract']}.{s['function']}")
            lines.append(f"    reason: {s['reason']}")
        lines.append("")

    # Patterns per file
    lines.append("### Detected Patterns")
    pattern_map: dict[str, list[str]] = defaultdict(list)
    for p in stage1.get("patterns", []):
        fname = p["contract"] + ".sol"
        if any(p["contract"].lower() in f.lower() for f in cluster):
            pattern_map[fname].append(f"{p['type']} in {p['function']}()")

    for fname, pats in pattern_map.items():
        lines.append(f"  {fname}:")
        for pat in pats:
            lines.append(f"    - {pat}")
    if not pattern_map:
        lines.append("  none detected")
    lines.append("")

    # Money flows
    flows = [
        f for f in stage1.get("money_flows", [])
        if any(f["contract"].lower() in fname.lower() for fname in cluster)
    ]
    if flows:
        lines.append("### Money Flow Functions (handle ETH/tokens)")
        seen_fns: set[str] = set()
        for flow in flows:
            key = f"{flow['contract']}.{flow['function']}"
            if key not in seen_fns:
                seen_fns.add(key)
                lines.append(f"  - {key}  [{flow['type']}]")
        lines.append("")

    # External calls
    ext_map = stage1.get("external_calls", {})
    cluster_ext = {
        caller: callees
        for caller, callees in ext_map.items()
        if any(caller.split(".")[0].lower() in f.lower() for f in cluster)
    }
    if cluster_ext:
        lines.append("### External Calls (potential attack surface)")
        for caller, callees in list(cluster_ext.items())[:8]:
            lines.append(f"  - {caller} → {callees}")
        lines.append("")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════════
# D — Dispatch Planner
# ════════════════════════════════════════════════════════════════════════════════

def plan_sessions(
    clusters:    list[list[str]],
    contracts:   dict[str, str],
    stage1:      dict[str, Any],
    risk_scores: dict[str, int],
) -> list[dict[str, Any]]:
    """
    Assign clusters to LLM sessions respecting token budget.
    Returns list of session dicts ready for Stage 3.
    """
    sessions: list[dict] = []

    for i, cluster in enumerate(clusters[:MAX_SESSIONS]):
        summary = summarize_cluster(cluster, stage1, risk_scores)
        context, truncated = _pack_context(cluster, contracts, TOKEN_BUDGET_PER_SESSION)

        session_risk = sum(risk_scores.get(f, 0) for f in cluster)

        session = {
            "session_id":    f"session-{i+1:02d}",
            "cluster":       cluster,
            "risk_score":    session_risk,
            "summary":       summary,
            "context":       context,
            "truncated":     truncated,
            "suspects":      [
                s for s in stage1.get("reentrancy_suspects", [])
                if any(s["contract"].lower() in f.lower() for f in cluster)
            ],
            "char_count":    len(context),
        }
        sessions.append(session)
        _log(f"  {session['session_id']}: files={cluster} risk={session_risk} "
             f"chars={len(context)} truncated={truncated}")

    # Handle overflow: if more clusters than MAX_SESSIONS, 
    # append remaining files to last session
    if len(clusters) > MAX_SESSIONS:
        overflow = []
        for cluster in clusters[MAX_SESSIONS:]:
            overflow.extend(cluster)
        if overflow and sessions:
            _log(f"  Overflow: {len(overflow)} file(s) appended to last session")
            extra_ctx, _ = _pack_context(
                overflow, contracts,
                max(0, TOKEN_BUDGET_PER_SESSION - sessions[-1]["char_count"])
            )
            sessions[-1]["context"] += f"\n\n// --- Additional files ---\n{extra_ctx}"
            sessions[-1]["cluster"].extend(overflow)

    _log(f"Dispatch plan: {len(sessions)} session(s)")
    return sessions


def _pack_context(
    cluster:      list[str],
    contracts:    dict[str, str],
    budget:       int,
) -> tuple[str, bool]:
    """
    Pack source files into context string within char budget.
    Returns (context_string, was_truncated).
    """
    blocks: list[str] = []
    used      = 0
    truncated = False

    for fname in cluster:
        source    = contracts.get(fname, "")
        available = budget - used

        if available <= 200:
            truncated = True
            break

        if len(source) > available:
            source    = source[:available] + "\n// [TRUNCATED — token budget reached]\n"
            truncated = True

        blocks.append(f"=== {fname} ===\n```solidity\n{source}\n```")
        used += len(source)

        if truncated:
            break

    return "\n\n".join(blocks), truncated


# ════════════════════════════════════════════════════════════════════════════════
# MAIN — run_stage2()
# ════════════════════════════════════════════════════════════════════════════════

def run_stage2(
    stage1:    dict[str, Any],
    contracts: dict[str, str],
) -> list[dict[str, Any]]:
    """
    Full Stage 2 pipeline.

    Input : stage1 result + original contracts dict
    Output: list of session dicts for Stage 3
    """
    import time
    t0 = time.time()
    _log(f"Starting Stage 2 on {len(contracts)} contract(s)")

    # A: Final risk scores
    risk_scores = score_contracts(stage1)

    # B: Cluster by call/import graph
    clusters = cluster_contracts(stage1, risk_scores, contracts)

    # C+D: Summarize + dispatch
    sessions = plan_sessions(clusters, contracts, stage1, risk_scores)

    elapsed = time.time() - t0
    _log(f"Stage 2 complete in {elapsed:.2f}s | {len(sessions)} session(s) planned")

    return sessions