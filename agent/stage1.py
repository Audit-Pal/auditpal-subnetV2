"""
Stage 1 — Static Analysis (~3s, no LLM)
========================================
Components:
  - Solidity AST parser      (parse_contracts)
  - Call graph builder       (build_call_graph)
  - Pattern detector         (detect_patterns)
  - Money flow tracker       (track_money_flow)

Input  : {filename: source} dict  OR  path to directory
Output : Stage1Result dict — fully JSON-serializable, feeds Stage 2
"""

from __future__ import annotations

import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import networkx as nx

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[stage1] {msg}", file=sys.stderr, flush=True)


# ── Risk weights per pattern ──────────────────────────────────────────────────

PATTERN_WEIGHTS: dict[str, int] = {
    "reentrancy-risk": 40,
    "delegatecall":    35,
    "assembly":        20,
    "low-level-call":  35,
    "flash-loan":      30,
    "oracle-usage":    25,
    "selfdestruct":    25,
    "tx-origin":       20,
    "unchecked-block": 15,
    "signature":       15,
    "proxy-pattern":   15,
    "eth-transfer":    20,
    "value-transfer":  25,
}

# ── Regex fallbacks (used when Slither is unavailable) ────────────────────────

REGEX_PATTERNS: dict[str, re.Pattern] = {
    "reentrancy-risk":  re.compile(r'\.call\s*[({]|\.send\s*\(|\.transfer\s*\(', re.I),
    "delegatecall":     re.compile(r'\.delegatecall\s*[({]', re.I),
    "assembly":         re.compile(r'\bassembly\s*\{', re.I),
    "selfdestruct":     re.compile(r'\bselfdestruct\s*\(', re.I),
    "tx-origin":        re.compile(r'\btx\.origin\b', re.I),
    "unchecked-block":  re.compile(r'\bunchecked\s*\{', re.I),
    "low-level-call":   re.compile(r'\b(\.call|\.staticcall)\s*\(', re.I),
    "flash-loan":       re.compile(r'flashLoan|flashSwap|uniswapV\dCallback', re.I),
    "oracle-usage":     re.compile(r'getPrice|latestAnswer|slot0\b|\.observe\(', re.I),
    "signature":        re.compile(r'ecrecover|ECDSA\.|SignatureChecker', re.I),
    "proxy-pattern":    re.compile(r'_implementation|ERC1967|upgradeTo', re.I),
    "eth-transfer":     re.compile(r'transfer\(|\.send\(|\.call\{value', re.I),
}

MONEY_REGEX = re.compile(
    r'function\s+(\w+)[^{]*(?:payable|msg\.value|\.balance\b|balances?\[)',
    re.I,
)

VALUE_KEYWORDS = re.compile(
    r'(pay|transfer|withdraw|send|mint|burn|swap|redeem|claim|deposit)',
    re.I,
)


# ════════════════════════════════════════════════════════════════════════════════
# A — AST Parser
# ════════════════════════════════════════════════════════════════════════════════

def parse_contracts(slither_or_path) -> list[dict[str, Any]]:
    """
    Extract per-contract AST data: name, source file, functions, imports.
    Accepts a Slither instance or a path string.
    """
    from slither.slither import Slither
    sl = slither_or_path if isinstance(slither_or_path, Slither) else Slither(slither_or_path)

    source_files: set[str] = set()
    for cu in sl.compilation_units:
        for f in cu.source_units:
            source_files.add(f)

    parsed: list[dict] = []
    for contract in sl.contracts:
        functions = []
        for func in contract.functions:
            functions.append({
                "name":           func.name,
                "visibility":     func.visibility,
                "is_payable":     func.payable,
                "can_reenter":    func.can_reenter(),
                "contains_asm":   func.contains_assembly,
                "internal_calls": [c.name for c in func.internal_calls
                                   if hasattr(c, "name")],
                "external_calls": [str(c) for c in func.high_level_calls],
                "params":         [str(p.type) for p in func.parameters],
                "returns":        [str(r.type) for r in func.return_type]
                                  if func.return_type else [],
            })

        parsed.append({
            "name":         contract.name,
            "source_file":  str(contract.source_mapping.filename),
            "is_interface": contract.is_interface,
            "is_library":   contract.is_library,
            "functions":    functions,
            "imports":      list(source_files),
        })

    _log(f"AST: parsed {len(parsed)} contract(s)")
    return parsed


def _regex_ast(contracts: dict[str, str]) -> list[dict]:
    """Fallback AST using regex when Slither unavailable."""
    parsed = []
    fn_regex  = re.compile(r'\bfunction\s+(\w+)\s*\(([^)]*)\)\s*([\w\s]*)', re.I)
    imp_regex = re.compile(r'import\s+["\']([^"\']+)["\']', re.I)

    for filename, source in contracts.items():
        functions = []
        for m in fn_regex.finditer(source):
            name       = m.group(1)
            modifiers  = m.group(3)
            functions.append({
                "name":           name,
                "visibility":     _extract_visibility(modifiers),
                "is_payable":     "payable" in modifiers,
                "can_reenter":    False,   # cannot determine without Slither
                "contains_asm":   False,
                "internal_calls": [],
                "external_calls": [],
                "params":         [],
                "returns":        [],
            })
        parsed.append({
            "name":         filename.replace(".sol", ""),
            "source_file":  filename,
            "is_interface": False,
            "is_library":   False,
            "functions":    functions,
            "imports":      imp_regex.findall(source),
        })
    return parsed


def _extract_visibility(modifiers: str) -> str:
    for vis in ("public", "private", "internal", "external"):
        if vis in modifiers:
            return vis
    return "internal"


# ════════════════════════════════════════════════════════════════════════════════
# B — Call Graph Builder
# ════════════════════════════════════════════════════════════════════════════════

def build_call_graph(slither_or_path) -> nx.DiGraph:
    """Build a directed call graph from Slither analysis."""
    from slither.slither import Slither
    sl = slither_or_path if isinstance(slither_or_path, Slither) else Slither(slither_or_path)

    graph = nx.DiGraph()
    for contract in sl.contracts:
        for func in contract.functions:
            caller = f"{contract.name}.{func.name}"
            for callee in func.internal_calls:
                graph.add_edge(caller, f"{contract.name},{getattr(callee, 'name', str(callee))}")
            for (_, callee) in func.high_level_calls:
                graph.add_edge(caller, str(callee))
    return graph


def clean_edges(edges: list[tuple]) -> list[dict[str, Any]]:
    """
    Convert raw NetworkX edge tuples into structured, JSON-serializable dicts.
    Classifies each edge: HIGH_LEVEL | LIBRARY | INTERNAL | LOW_LEVEL
    Filters TMP_ noise.
    """
    cleaned: list[dict] = []

    for src, dst in edges:
        dst_str = str(dst)
        src_str = str(src)

        # Filter IR noise
        if any(noise in dst_str for noise in ("TMP_", "REF_", "None")):
            continue

        call_type = _classify_edge(src_str, dst_str)
        risk      = _edge_risk(call_type, src_str)

        cleaned.append({
            "caller":      src_str,
            "callee":      dst_str,
            "call_type":   call_type,
            "risk_score":  risk,
            "is_suspect":  bool(VALUE_KEYWORDS.search(src_str))
                           and call_type in ("HIGH_LEVEL", "LOW_LEVEL"),
        })

    _log(f"Call graph: {len(cleaned)} cleaned edges")
    return cleaned


def _classify_edge(src: str, dst: str) -> str:
    if "HIGH_LEVEL_CALL" in dst:  return "HIGH_LEVEL"
    if "LOW_LEVEL_CALL"  in dst:  return "LOW_LEVEL"
    if "LIBRARY_CALL"    in dst:  return "LIBRARY"
    if "," in dst:                return "INTERNAL"
    return "EXTERNAL"


def _edge_risk(call_type: str, caller: str) -> int:
    base = {"HIGH_LEVEL": 30, "LOW_LEVEL": 40, "LIBRARY": 10,
            "INTERNAL": 0, "EXTERNAL": 20}.get(call_type, 5)
    # Bonus if caller touches value
    return base + (15 if VALUE_KEYWORDS.search(caller) else 0)


def _regex_call_graph(contracts: dict[str, str]) -> list[dict]:
    """Fallback call graph using regex."""
    edges = []
    fn_re   = re.compile(r'\bfunction\s+(\w+)', re.I)
    call_re = re.compile(r'(\w+)\.(\w+)\s*\(', re.I)

    for filename, source in contracts.items():
        contract = filename.replace(".sol", "")
        lines    = source.splitlines()
        current_fn = None

        for line in lines:
            fn_match = fn_re.search(line)
            if fn_match:
                current_fn = fn_match.group(1)

            if current_fn:
                for cm in call_re.finditer(line):
                    dest_contract = cm.group(1)
                    dest_fn       = cm.group(2)
                    if dest_contract != contract:
                        edges.append({
                            "caller":     f"{contract}.{current_fn}",
                            "callee":     f"{dest_contract}.{dest_fn}",
                            "call_type":  "HIGH_LEVEL",
                            "risk_score": 30,
                            "is_suspect": bool(VALUE_KEYWORDS.search(current_fn)),
                        })
    return edges


# ════════════════════════════════════════════════════════════════════════════════
# C — Pattern Detector
# ════════════════════════════════════════════════════════════════════════════════

def detect_patterns(slither_or_path) -> list[dict[str, Any]]:
    """
    Detect security-relevant code patterns using Slither IR.
    Returns list of {type, contract, function, severity, weight}.
    """
    from slither.slither import Slither
    sl = slither_or_path if isinstance(slither_or_path, Slither) else Slither(slither_or_path)

    findings: list[dict] = []

    for contract in sl.contracts:
        for func in contract.functions:
            ops = list(func.all_slithir_operations())

            # Reentrancy
            if func.can_reenter():
                findings.append(_pattern("reentrancy-risk", contract.name, func.name))

            # Delegatecall
            if any("delegatecall" in str(ir).lower() for ir in ops):
                findings.append(_pattern("delegatecall", contract.name, func.name))

            # Assembly
            if func.contains_assembly:
                findings.append(_pattern("assembly", contract.name, func.name))

            # Low-level call
            if any(".call(" in str(ir) or ".staticcall(" in str(ir) for ir in ops):
                findings.append(_pattern("low-level-call", contract.name, func.name))

            # tx.origin
            if any("tx.origin" in str(ir) for ir in ops):
                findings.append(_pattern("tx-origin", contract.name, func.name))

            # Selfdestruct
            if any("selfdestruct" in str(ir).lower() for ir in ops):
                findings.append(_pattern("selfdestruct", contract.name, func.name))

    _log(f"Patterns: {len(findings)} finding(s)")
    return findings


def _pattern(ptype: str, contract: str, function: str) -> dict:
    return {
        "type":     ptype,
        "contract": contract,
        "function": function,
        "weight":   PATTERN_WEIGHTS.get(ptype, 5),
    }


def _regex_detect_patterns(contracts: dict[str, str]) -> list[dict]:
    """Fallback pattern detection using regex."""
    findings = []
    for filename, source in contracts.items():
        contract = filename.replace(".sol", "")
        lines    = source.splitlines()
        current_fn = None
        fn_re      = re.compile(r'\bfunction\s+(\w+)')

        for line in lines:
            fn_match = fn_re.search(line)
            if fn_match:
                current_fn = fn_match.group(1)

            for pat_name, regex in REGEX_PATTERNS.items():
                if regex.search(line) and current_fn:
                    findings.append(_pattern(pat_name, contract, current_fn))

    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        key = (f["type"], f["contract"], f["function"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    _log(f"Patterns (regex): {len(deduped)} finding(s)")
    return deduped


# ════════════════════════════════════════════════════════════════════════════════
# D — Money Flow Tracker
# ════════════════════════════════════════════════════════════════════════════════

def track_money_flow(slither_or_path) -> list[dict[str, Any]]:
    """
    Track ETH and token transfers through the contract IR.
    """
    from slither.slither import Slither
    sl = slither_or_path if isinstance(slither_or_path, Slither) else Slither(slither_or_path)

    flows: list[dict] = []

    for contract in sl.contracts:
        for func in contract.functions:
            for node in func.nodes:
                for ir in node.irs:
                    ir_str = str(ir)

                    if hasattr(ir, "call_value") and ir.call_value:
                        flows.append({
                            "type":     "value-transfer",
                            "contract": contract.name,
                            "function": func.name,
                            "value":    str(ir.call_value),
                            "detail":   ir_str,
                            "weight":   PATTERN_WEIGHTS["value-transfer"],
                        })
                    elif "transfer" in ir_str or "send" in ir_str:
                        flows.append({
                            "type":     "eth-transfer",
                            "contract": contract.name,
                            "function": func.name,
                            "detail":   ir_str,
                            "weight":   PATTERN_WEIGHTS["eth-transfer"],
                        })

    _log(f"Money flows: {len(flows)} flow(s)")
    return flows


def _regex_money_flow(contracts: dict[str, str]) -> list[dict]:
    """Fallback money flow using regex."""
    flows = []
    for filename, source in contracts.items():
        contract = filename.replace(".sol", "")
        for fn_name in MONEY_REGEX.findall(source):
            flows.append({
                "type":     "eth-transfer",
                "contract": contract,
                "function": fn_name,
                "detail":   "detected via regex",
                "weight":   PATTERN_WEIGHTS["eth-transfer"],
            })
    return flows


# ════════════════════════════════════════════════════════════════════════════════
# MAIN — run_stage1()
# ════════════════════════════════════════════════════════════════════════════════

def run_stage1(contracts: dict[str, str]) -> dict[str, Any]:
    """
    Full Stage 1 pipeline.

    Input : {filename: solidity_source}
    Output: {
        ast, patterns, money_flows, edges,
        risk_scores, reentrancy_suspects,
        slither_ok, summary
    }
    """
    import time
    t0 = time.time()
    _log(f"Starting Stage 1 on {len(contracts)} contract(s)")

    # Write to /tmp so Slither can compile
    tmp_dir = Path(tempfile.mkdtemp(dir="/tmp", prefix="s1_"))
    for fname, src in contracts.items():
        (tmp_dir / fname).write_text(src, encoding="utf-8")

    slither_ok = False
    sl         = None

    try:
        from slither.slither import Slither
        sl         = Slither(str(tmp_dir))
        slither_ok = True
        _log("Slither initialized ✓")
    except Exception as exc:
        _log(f"Slither unavailable: {exc} — using regex fallback")

    # ── A: AST ───────────────────────────────────────────────────────────────
    ast_data = parse_contracts(sl) if slither_ok else _regex_ast(contracts)

    # ── B: Call graph ─────────────────────────────────────────────────────────
    if slither_ok:
        raw_graph = build_call_graph(sl)
        edges     = clean_edges(list(raw_graph.edges))
    else:
        edges = _regex_call_graph(contracts)

    # ── C: Patterns ───────────────────────────────────────────────────────────
    patterns = detect_patterns(sl) if slither_ok else _regex_detect_patterns(contracts)

    # ── D: Money flows ────────────────────────────────────────────────────────
    money_flows = track_money_flow(sl) if slither_ok else _regex_money_flow(contracts)

    # ── Risk scoring per file ─────────────────────────────────────────────────
    risk_scores = _compute_risk_scores(contracts, patterns, money_flows, edges)

    # ── Reentrancy suspects ───────────────────────────────────────────────────
    reentrancy_suspects = _find_reentrancy_suspects(patterns, edges)

    # ── External call map ─────────────────────────────────────────────────────
    external_calls = _build_external_call_map(edges)

    elapsed = time.time() - t0
    _log(f"Stage 1 complete in {elapsed:.2f}s | slither={slither_ok} | "
         f"patterns={len(patterns)} | flows={len(money_flows)} | edges={len(edges)}")

    return {
        "ast":                  ast_data,
        "patterns":             patterns,
        "money_flows":          money_flows,
        "edges":                edges,
        "risk_scores":          risk_scores,        # {filename: int} sorted desc
        "reentrancy_suspects":  reentrancy_suspects, # [{contract, function, reason}]
        "external_calls":       external_calls,      # {caller: [callee, ...]}
        "slither_ok":           slither_ok,
        "elapsed_s":            round(elapsed, 2),
        "summary": {
            "contracts":        len(contracts),
            "total_patterns":   len(patterns),
            "total_flows":      len(money_flows),
            "total_edges":      len(edges),
            "high_risk_files":  [f for f, s in risk_scores.items() if s >= 50],
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_risk_scores(
    contracts:   dict[str, str],
    patterns:    list[dict],
    money_flows: list[dict],
    edges:       list[dict],
) -> dict[str, int]:
    scores: dict[str, int] = {f: 0 for f in contracts}

    for p in patterns:
        fname = p["contract"] + ".sol"
        if fname in scores:
            scores[fname] += p.get("weight", 5)
        else:
            # Try partial match
            for key in scores:
                if p["contract"].lower() in key.lower():
                    scores[key] += p.get("weight", 5)
                    break

    for flow in money_flows:
        fname = flow["contract"] + ".sol"
        for key in scores:
            if flow["contract"].lower() in key.lower():
                scores[key] += flow.get("weight", 10)
                break

    for edge in edges:
        if not edge.get("is_suspect"):
            continue
        caller = edge["caller"].split(".")[0]
        for key in scores:
            if caller.lower() in key.lower():
                scores[key] += edge.get("risk_score", 0)
                break

    return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))


def _find_reentrancy_suspects(
    patterns: list[dict],
    edges:    list[dict],
) -> list[dict]:
    suspects = []

    # From Slither: direct can_reenter() flag
    for p in patterns:
        if p["type"] == "reentrancy-risk":
            suspects.append({
                "contract": p["contract"],
                "function": p["function"],
                "reason":   "Slither: can_reenter() = True",
            })

    # From call graph: external call + value keyword in function name
    for edge in edges:
        if edge.get("is_suspect") and edge["call_type"] in ("HIGH_LEVEL", "LOW_LEVEL"):
            contract, fn = (edge["caller"].split(".", 1) + ["?"])[:2]
            suspects.append({
                "contract": contract,
                "function": fn,
                "reason":   f"External call from value-related function → {edge['callee']}",
            })

    # Deduplicate
    seen  = set()
    dedup = []
    for s in suspects:
        key = (s["contract"], s["function"])
        if key not in seen:
            seen.add(key)
            dedup.append(s)

    return dedup


def _build_external_call_map(edges: list[dict]) -> dict[str, list[str]]:
    call_map: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if edge["call_type"] in ("HIGH_LEVEL", "LOW_LEVEL", "EXTERNAL"):
            call_map[edge["caller"]].append(edge["callee"])
    return dict(call_map)