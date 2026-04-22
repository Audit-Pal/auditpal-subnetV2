#!/usr/bin/env python3
"""
Bittensor Smart Contract Audit Agent
Pass 0 : Slither static analysis
Pass 1 : Gemini contract overview & attack-surface mapping
Pass 2 : Gemini deep per-function vulnerability analysis
"""
import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import google.generativeai as genai
from google.generativeai import types

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

GEMINI_MODEL = "gemini-2.5-flash"
MAX_RETRIES  = 3
RETRY_DELAY  = 2  # seconds

# Slither impact level → subnet severity
_SLITHER_SEVERITY: Dict[str, str] = {
    "High":          "high",
    "Medium":        "medium",
    "Low":           "low",
    "Informational": "info",
    "Optimization":  "info",
}

# Slither detector → normalized vulnerability_type
_SLITHER_TYPE: Dict[str, str] = {
    "reentrancy-eth":            "reentrancy",
    "reentrancy-no-eth":         "reentrancy",
    "reentrancy-benign":         "reentrancy",
    "reentrancy-events":         "reentrancy",
    "reentrancy-unlimited-gas":  "reentrancy",
    "controlled-delegatecall":   "delegatecall",
    "delegatecall-loop":         "delegatecall",
    "unprotected-upgrade":       "access-control",
    "suicidal":                  "selfdestruct",
    "arbitrary-send-eth":        "arbitrary-send",
    "arbitrary-send-erc20":      "arbitrary-send",
    "tx-origin":                 "tx-origin",
    "integer-overflow":          "integer-overflow",
    "tautology":                 "logic-error",
    "incorrect-equality":        "logic-error",
    "divide-before-multiply":    "precision-loss",
    "weak-prng":                 "randomness",
    "timestamp":                 "timestamp-dependency",
    "locked-ether":              "locked-ether",
    "unchecked-lowlevel":        "unchecked-return",
    "unchecked-send":            "unchecked-return",
    "unchecked-transfer":        "unchecked-return",
    "unused-return":             "unchecked-return",
    "missing-zero-check":        "missing-validation",
    "uninitialized-local":       "uninitialized-variable",
    "uninitialized-state":       "uninitialized-variable",
    "uninitialized-storage":     "uninitialized-variable",
    "shadowing-local":           "shadowing",
    "shadowing-state":           "shadowing",
    "shadowing-builtin":         "shadowing",
    "shadowing-abstract":        "shadowing",
    "msg-value-loop":            "denial-of-service",
    "calls-loop":                "denial-of-service",
    "costly-loop":               "denial-of-service",
    "incorrect-modifier":        "logic-error",
    "events-maths":              "missing-event",
    "events-access":             "missing-event",
    "reentrancy-unlimited-gas":  "reentrancy",
    "variable-scope":            "logic-error",
    "protected-vars":            "access-control",
    "modifier-defaultrevert":    "logic-error",
    "incorrect-exp":             "logic-error",
    "storage-array":             "logic-error",
    "write-after-write":         "logic-error",
    "msg-value-loop":            "logic-error",
    "controlled-array-length":   "access-control",
    "rtlo":                      "code-quality",
    "name-reuse":                "code-quality",
    "abiencoderv2-array":        "encoding-bug",
    "erc20-interface":           "interface-violation",
    "erc721-interface":          "interface-violation",
    "locked-ether":              "locked-ether",
    "constant-function-changing-state": "logic-error",
    "constant-function-asm":     "logic-error",
    "boolean-equality":          "logic-error",
    "low-level-calls":           "low-level-call",
    "assembly":                  "assembly-usage",
    "dead-code":                 "dead-code",
}


# ─────────────────────────────────────────────────────────────────────────────
# Gemini tool schemas  (no additionalProperties — unsupported by proto backend)
# ─────────────────────────────────────────────────────────────────────────────

OVERVIEW_TOOL = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="submit_contract_overview",
            description="Submit the contract overview and attack surface mapping results.",
            parameters={
                "type": "object",
                "properties": {
                    "contracts": {
                        "type": "array",
                        "description": "One entry per contract file.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "contract_name": {
                                    "type": "string",
                                    "description": "Filename, e.g. Token.sol",
                                },
                                "purpose": {
                                    "type": "string",
                                    "description": "1-2 sentence purpose.",
                                },
                                "privileged_roles": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Access-control roles/owners.",
                                },
                                "external_calls": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "External contract/token calls.",
                                },
                                "critical_state_vars": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Critical state variables.",
                                },
                                "risk_areas": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "High-risk functions or patterns.",
                                },
                            },
                            "required": [
                                "contract_name", "purpose", "privileged_roles",
                                "external_calls", "critical_state_vars", "risk_areas",
                            ],
                        },
                    },
                    "global_risks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Cross-contract risks.",
                    },
                },
                "required": ["contracts", "global_risks"],
            },
        )
    ]
)

FINDINGS_TOOL = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="submit_vulnerability_findings",
            description="Submit all vulnerability findings for a contract.",
            parameters={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "List of vulnerability findings.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "description": "Short title.",
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Detailed explanation.",
                                },
                                "vulnerability_type": {
                                    "type": "string",
                                    "description": (
                                        "Canonical type — use one of: reentrancy, "
                                        "access-control, integer-overflow, unchecked-return, "
                                        "timestamp-dependency, front-running, denial-of-service, "
                                        "logic-error, tx-origin, flash-loan, arbitrary-send, "
                                        "selfdestruct, delegatecall, precision-loss, randomness, "
                                        "missing-validation, uninitialized-variable, shadowing, "
                                        "locked-ether, low-level-call"
                                    ),
                                },
                                "severity": {
                                    "type": "string",
                                    "enum": ["high", "medium", "low", "info"],
                                },
                                "line_number": {
                                    "type": "integer",
                                    "description": "Approximate line number.",
                                },
                                "function_name": {
                                    "type": "string",
                                    "description": "Affected function name.",
                                },
                                "exploit_scenario": {
                                    "type": "string",
                                    "description": "Brief concrete exploit scenario.",
                                },
                                "recommendation": {
                                    "type": "string",
                                    "description": "Fix recommendation.",
                                },
                            },
                            "required": [
                                "title", "description", "vulnerability_type", "severity",
                                "line_number", "function_name", "exploit_scenario", "recommendation",
                            ],
                        },
                    },
                },
                "required": ["findings"],
            },
        )
    ]
)


# ─────────────────────────────────────────────────────────────────────────────
# Pass 0 — Slither static analysis
# ─────────────────────────────────────────────────────────────────────────────

def _run_slither(sol_path: Path) -> List[Dict[str, Any]]:
    """Run slither on a single .sol file, return normalised finding dicts."""
    try:
        result = subprocess.run(
            ["slither", str(sol_path), "--json", "-", "--no-fail-pedantic"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = result.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
    except Exception as exc:
        logger.warning("[Slither] %s: %s", sol_path.name, exc)
        return []

    findings: List[Dict[str, Any]] = []
    for det in data.get("results", {}).get("detectors", []):
        check    = det.get("check", "unknown")
        impact   = det.get("impact", "Informational")
        severity = _SLITHER_SEVERITY.get(impact, "info")
        vuln_type = _SLITHER_TYPE.get(check, check.replace("-", "-"))

        # Extract primary source location
        elements = det.get("elements", [])
        line_no  = 1
        func_name = "unknown"
        for el in elements:
            sm = el.get("source_mapping", {})
            lines = sm.get("lines", [])
            if lines:
                line_no = lines[0]
            if el.get("type") == "function":
                func_name = el.get("name", func_name)
            if line_no and func_name != "unknown":
                break

        description = det.get("description", "").strip()
        title = f"{check}: {func_name}" if func_name != "unknown" else check

        findings.append({
            "file":               sol_path.name,
            "severity":           severity,
            "vulnerability_type": vuln_type,
            "title":              title,
            "description":        description,
            "location":           f"{sol_path.name}:{line_no}",
            "line_number":        line_no,
            "function_name":      func_name,
            "_source":            "slither",
        })

    logger.info("[Slither] %s → %d finding(s)", sol_path.name, len(findings))
    return findings


def slither_pass(contracts: Dict[str, str]) -> List[Dict[str, Any]]:
    """Write contracts to a temp dir, run Slither on each, collect findings."""
    all_findings: List[Dict[str, Any]] = []
    tmp = tempfile.mkdtemp()

    for filename, source in contracts.items():
        sol_path = Path(tmp) / Path(filename).name
        sol_path.write_text(source, encoding="utf-8")
        all_findings.extend(_run_slither(sol_path))

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Gemini client
# ─────────────────────────────────────────────────────────────────────────────

class GeminiClient:
    def __init__(self, api_key: str):
        if api_key:
            genai.configure(api_key=api_key)
            self.available = True
        else:
            logger.warning("[Gemini] No API key — LLM passes disabled.")
            self.available = False

    def call_with_tool(
        self,
        prompt: str,
        tool: types.Tool,
        function_name: str,
    ) -> Dict[str, Any]:
        if not self.available:
            return {}

        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            tools=[tool],
            tool_config={
                "function_calling_config": {
                    "mode": "ANY",
                    "allowed_function_names": [function_name],
                }
            },
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = model.generate_content(prompt)
                for part in response.candidates[0].content.parts:
                    if (
                        hasattr(part, "function_call")
                        and part.function_call
                        and part.function_call.name == function_name
                    ):
                        return dict(part.function_call.args)

                logger.warning(
                    "[Gemini] No '%s' call in response (attempt %d/%d)",
                    function_name, attempt, MAX_RETRIES,
                )
            except Exception as exc:
                logger.warning("[Gemini] Attempt %d/%d: %s", attempt, MAX_RETRIES, exc)
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)

        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Pass 1 — LLM contract overview
# ─────────────────────────────────────────────────────────────────────────────

def llm_pass1_overview(
    contracts: Dict[str, str],
    gemini: GeminiClient,
) -> Dict[str, Any]:
    logger.info("[Pass 1] Contract overview & attack-surface mapping")

    combined = "\n\n".join(
        f"// === FILE: {Path(fp).name} ===\n{src}"
        for fp, src in contracts.items()
    )

    prompt = f"""You are a senior smart-contract security auditor doing initial triage.

Contracts under review:

{combined}

For EACH contract identify:
1. Purpose (1-2 sentences)
2. Privileged roles / access-control owners
3. All external calls (other contracts, tokens, oracles)
4. Critical state variables (balances, ownership, flags, counters)
5. High-risk functions warranting deep analysis

Call submit_contract_overview with your complete analysis."""

    data = gemini.call_with_tool(prompt, OVERVIEW_TOOL, "submit_contract_overview")
    logger.info("[Pass 1] Overview for %d contract(s)", len(data.get("contracts", [])))
    return data


# ─────────────────────────────────────────────────────────────────────────────
# Pass 2 — LLM deep per-contract analysis
# ─────────────────────────────────────────────────────────────────────────────

def llm_pass2_findings(
    contracts: Dict[str, str],
    overview: Dict[str, Any],
    slither_findings: List[Dict[str, Any]],
    gemini: GeminiClient,
) -> List[Dict[str, Any]]:
    logger.info("[Pass 2] Deep per-function vulnerability analysis")

    # Build contract_name → overview lookup
    raw_ov = overview.get("contracts", [])
    ov_map: Dict[str, Any] = {}
    for ov in (raw_ov if isinstance(raw_ov, list) else []):
        name = ov.get("contract_name", "")
        ov_map[name] = ov
        ov_map[Path(name).stem] = ov

    # Index Slither findings per file for context
    slither_by_file: Dict[str, List[str]] = {}
    for sf in slither_findings:
        fname = sf["file"]
        slither_by_file.setdefault(fname, [])
        slither_by_file[fname].append(
            f"  [{sf['severity'].upper()}] {sf['vulnerability_type']} @ line {sf['line_number']}: {sf['title']}"
        )

    all_findings: List[Dict[str, Any]] = []

    for file_path, source in contracts.items():
        name = Path(file_path).name
        stem = Path(file_path).stem
        ov   = ov_map.get(name) or ov_map.get(stem) or {}

        risk_areas = list(ov.get("risk_areas", []))
        ext_calls  = list(ov.get("external_calls", []))
        roles      = list(ov.get("privileged_roles", []))
        slither_ctx = slither_by_file.get(name, [])

        triage = ""
        if ov:
            triage = (
                f"High-risk areas: {', '.join(risk_areas)}\n"
                f"External calls: {', '.join(ext_calls)}\n"
                f"Privileged roles: {', '.join(roles)}"
            )
        if slither_ctx:
            triage += "\n\nSlither pre-scan findings (verify and enrich these):\n" + "\n".join(slither_ctx)
        if not triage:
            triage = "No prior triage — analyse all functions thoroughly."

        prompt = f"""You are a senior smart-contract security auditor doing deep vulnerability analysis.

FILE: {name}
{triage}

```solidity
{source}
```

Analyse EVERY function for:
- Reentrancy (cross-function, cross-contract, read-only)
- Access control bypass / missing modifiers
- Integer overflow / underflow (pre/post Solidity 0.8)
- Unchecked return values / low-level calls
- Timestamp / block.number dependency
- Front-running / MEV / sandwich attacks
- Checks-Effects-Interactions violations
- Denial-of-service vectors (gas, loops, revert)
- Logic errors / invariant violations
- tx.origin misuse
- Flash-loan attack vectors
- Precision loss / division-before-multiplication

Use CANONICAL vulnerability_type values: reentrancy, access-control, integer-overflow,
unchecked-return, timestamp-dependency, front-running, denial-of-service, logic-error,
tx-origin, flash-loan, arbitrary-send, selfdestruct, delegatecall, precision-loss,
randomness, missing-validation, uninitialized-variable, shadowing, locked-ether, low-level-call.

For each finding: exact line number, severity justification, concrete exploit scenario.
Call submit_vulnerability_findings with ALL findings (including confirmed Slither items)."""

        data     = gemini.call_with_tool(prompt, FINDINGS_TOOL, "submit_vulnerability_findings")
        findings = list(data.get("findings", []))
        for f in findings:
            f["file"] = name
        all_findings.extend(findings)
        logger.info("[Pass 2] %s → %d finding(s)", name, len(findings))

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Normalise & deduplicate to MinerFinding schema
# ─────────────────────────────────────────────────────────────────────────────

def _normalise(
    slither: List[Dict[str, Any]],
    llm: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Merge Slither + LLM findings, deduplicate by (file, vulnerability_type, severity),
    and emit the MinerFinding-compatible schema.
    """
    out: List[Dict[str, Any]] = []
    seen: set = set()

    def _emit(f: Dict[str, Any]) -> None:
        if not isinstance(f, dict):
            try:
                f = dict(f)
            except Exception:
                return

        severity = str(f.get("severity", "info")).lower()
        if severity not in ("high", "medium", "low", "info"):
            severity = "info"

        file_name = Path(str(f.get("file", "unknown.sol"))).name
        vuln_type = str(f.get("vulnerability_type", "unknown")).lower().strip()
        title     = str(f.get("title", "Untitled"))
        line_no   = max(1, int(f.get("line_number", 1) or 1))

        # Deduplicate: same file + normalised type + severity
        import re
        norm_type = re.sub(r"[\W_]+", "", vuln_type)
        key = (file_name.lower(), norm_type, severity)
        if key in seen:
            return
        seen.add(key)

        out.append({
            "file":               file_name,
            "severity":           severity,
            "vulnerability_type": vuln_type,
            "title":              title,
            "description":        str(f.get("description", "")),
            "location":           f.get("location") or f"{file_name}:{line_no}",
        })

    # Slither findings first (higher confidence)
    for f in slither:
        _emit(f)

    # LLM findings fill gaps
    for f in llm:
        _emit(f)

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda x: order.get(x["severity"], 4))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def agent_main(task: Dict[str, Any]) -> Dict[str, Any]:
    challenge_id = task.get("challenge_id") or task.get("_id", "")
    project_id   = task.get("project_id", "")
    contracts: Dict[str, str] = task.get("contracts", {})

    if not contracts:
        logger.warning("[agent_main] No contracts — returning empty report.")
        return {"challenge_id": challenge_id, "project_id": project_id, "findings": []}

    logger.info("[agent_main] Analysing %d contract(s)", len(contracts))

    # Pass 0: Slither static analysis
    slither_findings = slither_pass(contracts)

    # Pass 1 + 2: LLM (skipped gracefully if no API key)
    api_key = os.environ.get("GEMINI_API_KEY", "")
    gemini  = GeminiClient(api_key)

    overview     = llm_pass1_overview(contracts, gemini)
    llm_findings = llm_pass2_findings(contracts, overview, slither_findings, gemini)

    findings = _normalise(slither_findings, llm_findings)

    logger.info(
        "[agent_main] Done — %d finding(s) [H:%d M:%d L:%d I:%d]",
        len(findings),
        sum(1 for f in findings if f["severity"] == "high"),
        sum(1 for f in findings if f["severity"] == "medium"),
        sum(1 for f in findings if f["severity"] == "low"),
        sum(1 for f in findings if f["severity"] == "info"),
    )

    return {"challenge_id": challenge_id, "project_id": project_id, "findings": findings}


# ─────────────────────────────────────────────────────────────────────────────
# Local test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess as _sp
    task = {
        "_id": "695827d811998fe379983ccf",
        "project_id": "sherlock_crestal-network_2025_03",
        "contracts": {},
    }
    result = agent_main(task)
    print(json.dumps(result, indent=2))
