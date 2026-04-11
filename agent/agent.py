#!/usr/bin/env python3
"""
Bittensor Smart Contract Audit Agent — 2-Pass Analysis
Pass 1 : Contract overview & attack surface mapping
Pass 2 : Deep per-function vulnerability analysis
Model  : gemini-2.5-flash
"""
import subprocess
import tempfile
from pathlib import Path
import re
import json
import logging
import os
import time
from typing import Any, Dict, List

from google import genai
from google.genai import types




logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

GEMINI_MODEL = "gemini-2.5-flash"
MAX_RETRIES  = 3
RETRY_DELAY  = 2  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# Gemini wrapper with retry
# ─────────────────────────────────────────────────────────────────────────────
class GeminiClient:
    def __init__(self, api_key: str):
        if api_key:
            self._client = genai.Client(api_key=api_key)
            self.available = True
            logger.info("Gemini ready: %s", GEMINI_MODEL)
        else:
            self._client = None
            self.available = False
            logger.warning("Gemini unavailable — no API key")

    def call(self, prompt: str, json_mode: bool = True) -> str:
        if not self.available:
            return "{}"

        config = types.GenerateContentConfig(
            response_mime_type="application/json" if json_mode else "text/plain"
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self._client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=prompt,
                    config=config,
                )
                return response.text
            except Exception as exc:
                logger.warning("Gemini attempt %d/%d failed: %s", attempt, MAX_RETRIES, exc)
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
        return "{}"


# ─────────────────────────────────────────────────────────────────────────────
# 2-Pass analyser
# ─────────────────────────────────────────────────────────────────────────────

class TwoPassAnalyser:

    def __init__(self, gemini: GeminiClient):
        self.gemini = gemini

    # ── Pass 1: Overview & attack surface ────────────────────────────────────

    def pass1_overview(self, contracts: Dict[str, str]) -> Dict[str, Any]:
        logger.info("[Pass 1] Contract overview & attack surface mapping")

        combined = "\n\n".join(
            f"// === FILE: {Path(fp).name} ===\n{src}"
            for fp, src in contracts.items()
        )

        prompt = f"""You are a senior smart-contract auditor performing initial triage.

Below are all Solidity contracts in this project:

{combined}

For each contract identify:
1. Its purpose (1-2 sentences)
2. Privileged roles / access control owners
3. All external calls (to other contracts or tokens)
4. Critical state variables (balances, ownership, flags)
5. High-risk functions that warrant deeper analysis

Respond ONLY with valid JSON:
{{
  "contracts": {{
    "<ContractName>": {{
      "purpose": "str",
      "privileged_roles": ["str"],
      "external_calls": ["str"],
      "critical_state_vars": ["str"],
      "risk_areas": ["functionName or pattern"]
    }}
  }},
  "global_risks": ["any cross-contract risk worth noting"]
}}"""

        raw  = self.gemini.call(prompt)
        data = _parse_json(raw)
        logger.info("[Pass 1] Mapped %d contract(s)", len(data.get("contracts", {})))
        return data

    # ── Pass 2: Deep per-function vulnerability analysis ─────────────────────

    def pass2_deep_analysis(
        self,
        contracts: Dict[str, str],
        overview: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        logger.info("[Pass 2] Deep per-function vulnerability analysis")
        all_findings: List[Dict[str, Any]] = []
        contract_overviews = overview.get("contracts", {})

        for file_path, source in contracts.items():
            name = Path(file_path).name
            stem = Path(file_path).stem
            ov   = contract_overviews.get(stem) or contract_overviews.get(name) or {}

            risk_areas = ov.get("risk_areas", [])
            ext_calls  = ov.get("external_calls", [])
            roles      = ov.get("privileged_roles", [])

            risk_hint = (
                f"High-risk areas from Pass 1: {', '.join(risk_areas)}\n"
                f"External calls: {', '.join(ext_calls)}\n"
                f"Privileged roles: {', '.join(roles)}"
                if ov else "No prior triage — analyse all functions."
            )

            prompt = f"""You are a senior smart-contract auditor performing deep vulnerability analysis.

FILE: {name}
{risk_hint}

```solidity
{source}
```

Analyse EVERY function for:
- Reentrancy (cross-function, cross-contract, read-only)
- Access control bypass
- Integer overflow / underflow
- Unchecked return values
- Timestamp / block dependency
- Front-running / MEV exposure
- Checks-effects-interactions violations
- Denial of service vectors
- Logic errors / invariant violations
- tx.origin misuse

For each finding provide exact line reference, severity justification, and a brief exploit scenario.

Respond ONLY with valid JSON:
{{
  "findings": [
    {{
      "title": "str",
      "description": "str (detailed — why is it exploitable?)",
      "vulnerability_type": "str",
      "severity": "high|medium|low|info",
      "confidence": 0.0,
      "line_number": 1,
      "function_name": "str",
      "exploit_scenario": "str",
      "recommendation": "str"
    }}
  ]
}}"""

            raw      = self.gemini.call(prompt)
            data     = _parse_json(raw)
            findings = data.get("findings", []) if isinstance(data, dict) else []
            for f in findings:
                f["file"] = name
            all_findings.extend(findings)
            logger.info("[Pass 2] %s → %d finding(s)", name, len(findings))

        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Normalise to AuditReport schema
# ─────────────────────────────────────────────────────────────────────────────

def _normalise(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out  = []
    seen = set()
    for f in findings:
        severity = f.get("severity", "info").lower()
        if severity not in ("high", "medium", "low", "info"):
            severity = "info"

        file_name = f.get("file", "unknown.sol")
        line_no   = max(1, int(f.get("line_number", 1)))
        title     = f.get("title", "Untitled finding")

        key = (file_name, line_no, title.lower()[:60])
        if key in seen:
            continue
        seen.add(key)

        out.append({
            "file":               file_name,
            "line":               line_no,
            "severity":           severity,
            "vulnerability_type": f.get("vulnerability_type", "unknown"),
            "title":              title,
            "description":        f.get("description", ""),
            "location":           f"{file_name}:{line_no}",
        })

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda x: order.get(x["severity"], 4))
    return out


def build_contracts_from_codebase(codebase: Dict[str, Any]) -> Dict[str, str]:
    repo_url = codebase["repo_url"]
    tmp_dir  = tempfile.mkdtemp()

    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, tmp_dir],
        check=True
    )

    contracts = {}
    for path in Path(tmp_dir).rglob("*.sol"):
        try:
            contracts[str(path)] = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    return contracts


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def agent_main(task: Dict[str, Any]) -> Dict[str, Any]:
    challenge_id = task.get("_id") or task.get("challenge_id", "")
    project_id   = task.get("project_id", "")

    api_key = os.environ.get("GEMINI_API_KEY", "")
    gemini  = GeminiClient(api_key)
    analyser = TwoPassAnalyser(gemini)

    # Runner already read /challenge and passed contracts directly
    contracts = task.get("contracts", {})

    if not contracts:
        logger.error("No contracts in task — /challenge may be empty")
        return {"challenge_id": challenge_id, "project_id": project_id, "findings": []}

    logger.info("Loaded %d contract(s) from task", len(contracts))
    for path in contracts:
        logger.info("  → %s", path)

    # Pass 1
    overview = analyser.pass1_overview(contracts)

    # Pass 2
    raw_findings = analyser.pass2_deep_analysis(contracts, overview)

    findings = _normalise(raw_findings)

    logger.info(
        "Analysis complete — %d finding(s) [H:%d M:%d L:%d I:%d]",
        len(findings),
        sum(1 for f in findings if f["severity"] == "high"),
        sum(1 for f in findings if f["severity"] == "medium"),
        sum(1 for f in findings if f["severity"] == "low"),
        sum(1 for f in findings if f["severity"] == "info"),
    )

    return {
        "challenge_id": challenge_id,
        "project_id":   project_id,
        "findings":     findings,
    }
if __name__ == "__main__":
    task = {
        "_id": "695827d811998fe379983ccf",
        "project_id": "sherlock_crestal-network_2025_03",
        "__v": 0,
        "codebases": [
            {
                "codebase_id": "Crestal Network_dc45e9",
                "repo_url": "https://github.com/crestalnetwork/crestal-omni-contracts",
                "commit": "dc45e98af5e247dce5bbe53b0bd5b1f256884f84",
                "tree_url": "https://github.com/crestalnetwork/crestal-omni-contracts/tree/dc45e98af5e247dce5bbe53b0bd5b1f256884f84",
                "tarball_url": "https://github.com/crestalnetwork/crestal-omni-contracts/archive/dc45e98af5e247dce5bbe53b0bd5b1f256884f84.tar.gz",
                "_id": "695838db16c9f665c010f695"
            }
        ],
        "created_at": "2026-01-02T20:17:28.090Z",
        "name": "Crestal Network",
        "platform": "sherlock",
        "updated_at": "2026-01-02T21:30:03.141Z"
    }

    result = agent_main(task)
    print(json.dumps(result, indent=2))