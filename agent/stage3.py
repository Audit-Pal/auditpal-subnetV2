"""
Stage 3 — Parallel LLM Sessions (~70s)
========================================
Components:
  - Parallel session runner   : ThreadPoolExecutor
  - Tool-calling loop         : ReAct loop per session
  - Prompt engineering        : auditor role + CoT + structured JSON
  - Context window management : fits cluster + summary within token limits
  - Structured output schema  : typed JSON findings per session
  - Error handling + retry    : timeouts, malformed JSON, rate limits

Input  : list[Session] from stage2_prioritize.run_stage2()
Output : list[dict] raw findings — feeds Stage 4
"""

from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────

MAX_WORKERS       = 4      # parallel Gemini calls
SESSION_TIMEOUT_S = 60     # per-session timeout
WALL_TIMEOUT_S    = 75     # total Stage 3 wall time
MAX_RETRIES       = 2      # retries per session on failure

CANDIDATE_MODELS = [
    "gemini-2.5-pro",
]

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[stage3] {msg}", file=sys.stderr, flush=True)


# ════════════════════════════════════════════════════════════════════════════════
# SDK + Model Setup
# ════════════════════════════════════════════════════════════════════════════════

def get_generate_fn(api_key: str):
    """
    Return generate(model, prompt) -> str.
    Supports both google-generativeai and google-genai SDKs.
    """
    if not api_key:
        raise ValueError("GEMINI_API_KEY is empty — cannot call LLM")

    # Try old SDK: google-generativeai
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _log("SDK: google-generativeai")

        def _gen(model: str, prompt: str) -> str:
            m = genai.GenerativeModel(model_name=model)
            return m.generate_content(prompt).text

        return _gen
    except ImportError:
        pass

    # Try new SDK: google-genai
    try:
        from google import genai as new_genai
        client = new_genai.Client(api_key=api_key)
        _log("SDK: google-genai (new)")

        def _gen_new(model: str, prompt: str) -> str:
            return client.models.generate_content(
                model=model, contents=prompt
            ).text

        return _gen_new
    except ImportError:
        pass

    raise ImportError(
        "Install google-generativeai or google-genai in requirements.txt"
    )


def pick_model(generate_fn) -> str:
    """Probe candidate models and return the first working one."""
    for model in CANDIDATE_MODELS:
        try:
            result = generate_fn(model, "Reply with the single word: ok")
            _log(f"Model selected: {model}  (probe: {result.strip()[:15]})")
            return model
        except Exception as exc:
            _log(f"  {model} unavailable: {exc}")
    raise RuntimeError(f"No working model among: {CANDIDATE_MODELS}")


# ════════════════════════════════════════════════════════════════════════════════
# Prompt Engineering
# ════════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """\
You are a senior smart-contract security researcher with deep expertise in:
- EVM internals and Solidity edge cases
- DeFi protocol attack patterns (flash loans, oracle manipulation, MEV)
- Common vulnerability classes: reentrancy, access control, integer issues,
  signature replay, storage collisions, proxy pitfalls, DoS vectors

Your job: find REAL, EXPLOITABLE vulnerabilities. Be precise and thorough.
Do NOT hallucinate issues that aren't present in the code.
"""

AUDIT_PROMPT_TEMPLATE = """\
{system}

{summary}

## Your Task
Perform a thorough security audit of the Solidity source below.
The static analysis above has pre-identified high-risk areas — start there,
then audit the rest of the code systematically.

Check for ALL of:
- Reentrancy (cross-function, read-only, cross-contract)
- Access control flaws (missing modifiers, wrong msg.sender checks)
- Integer overflow/underflow (especially in unchecked blocks)
- Oracle / price manipulation
- Flash loan attack vectors
- Front-running / MEV exposure
- Unchecked external call return values
- Denial of service (gas limit, push-over-pull)
- Logic errors / incorrect accounting
- Unsafe delegatecall / storage collision
- Signature replay / missing nonce
- Centralization risks / admin key abuse
- Proxy upgrade pitfalls
- Missing event emissions on critical state changes

## Output Format
Respond ONLY with a valid JSON array — no markdown fences, no explanation, no preamble.
If no vulnerabilities exist, return: []

Each finding object MUST have exactly these fields:
{{
  "title":              "<short title ≤ 80 chars>",
  "vulnerability_type": "<canonical category e.g. Reentrancy>",
  "severity":           "<critical|high|medium|low|info>",
  "file":               "<filename.sol>",
  "line_start":         <integer>,
  "line_end":           <integer>,
  "description":        "<what, why dangerous, concrete attack scenario — 2-5 sentences>",
  "recommendation":     "<concrete fix — 1-3 sentences>"
}}

## Source Files
{context}

BEGIN AUDIT:
"""


def build_prompt(session: dict[str, Any]) -> str:
    return AUDIT_PROMPT_TEMPLATE.format(
        system=SYSTEM_PROMPT,
        summary=session.get("summary", ""),
        context=session.get("context", ""),
    )


# ════════════════════════════════════════════════════════════════════════════════
# JSON Parser — robust extraction from LLM output
# ════════════════════════════════════════════════════════════════════════════════

def parse_llm_json(raw: str, session_id: str) -> list[dict]:
    """Robustly extract a JSON array from LLM output."""
    if not raw or not raw.strip():
        _log(f"  {session_id}: empty response from LLM")
        return []

    cleaned = raw.strip()

    # Strip markdown fences
    if cleaned.startswith("```"):
        parts   = cleaned.split("```")
        cleaned = parts[1] if len(parts) > 1 else cleaned
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()

    # Direct parse
    try:
        result = json.loads(cleaned)
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        pass

    # Find first [...] block
    match = re.search(r'\[.*?\]', cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            return result if isinstance(result, list) else [result]
        except json.JSONDecodeError:
            pass

    # Find first {...} block (single finding)
    match = re.search(r'\{.*?\}', cleaned, re.DOTALL)
    if match:
        try:
            return [json.loads(match.group())]
        except json.JSONDecodeError:
            pass

    _log(f"  {session_id}: could not parse JSON. Raw (first 200): {raw[:200]}")
    return []


# ════════════════════════════════════════════════════════════════════════════════
# Single Session Runner (with retry)
# ════════════════════════════════════════════════════════════════════════════════

def run_session(
    session:     dict[str, Any],
    generate_fn,
    model:       str,
) -> list[dict]:
    """
    Run one LLM audit session with retry on failure.
    Tags each finding with session metadata.
    """
    sid    = session["session_id"]
    prompt = build_prompt(session)

    _log(f"  {sid}: starting | cluster={session['cluster']} "
         f"| chars={len(prompt):,} | suspects={len(session.get('suspects', []))}")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            t0  = time.time()
            raw = generate_fn(model, prompt)
            elapsed = time.time() - t0

            _log(f"  {sid}: attempt {attempt} response in {elapsed:.1f}s ({len(raw)} chars)")

            findings = parse_llm_json(raw, sid)

            # Tag findings with session info
            for f in findings:
                f["_session"] = sid
                f["_cluster"] = session["cluster"]

            _log(f"  {sid}: {len(findings)} finding(s) parsed")
            return findings

        except Exception as exc:
            _log(f"  {sid}: attempt {attempt}/{MAX_RETRIES} failed: "
                 f"{type(exc).__name__}: {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)   # exponential backoff

    _log(f"  {sid}: all retries exhausted — returning empty")
    return []


# ════════════════════════════════════════════════════════════════════════════════
# Parallel Session Runner
# ════════════════════════════════════════════════════════════════════════════════

def run_parallel_sessions(
    sessions:    list[dict[str, Any]],
    generate_fn,
    model:       str,
) -> list[dict]:
    """
    Run all sessions in parallel using ThreadPoolExecutor.
    Respects WALL_TIMEOUT_S — returns partial results on timeout.
    """
    all_findings: list[dict] = []
    n_workers = min(len(sessions), MAX_WORKERS)

    _log(f"Launching {len(sessions)} session(s) with {n_workers} worker(s) "
         f"| wall_timeout={WALL_TIMEOUT_S}s")

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        future_to_sid = {
            pool.submit(run_session, s, generate_fn, model): s["session_id"]
            for s in sessions
        }

        try:
            for future in as_completed(future_to_sid):
                sid = future_to_sid[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    _log(f"  {sid}: collected {len(findings)} finding(s)")
                except Exception as exc:
                    _log(f"  {sid}: future raised {type(exc).__name__}: {exc}")

        except FuturesTimeout:
            _log(f"Wall-clock timeout after {WALL_TIMEOUT_S}s — "
                 f"returning {len(all_findings)} partial finding(s)")

    return all_findings


# ════════════════════════════════════════════════════════════════════════════════
# MAIN — run_stage3()
# ════════════════════════════════════════════════════════════════════════════════

def run_stage3(
    sessions:    list[dict[str, Any]],
    api_key:     str,
) -> list[dict]:
    """
    Full Stage 3 pipeline.

    Input : sessions from stage2_prioritize.run_stage2()
    Output: list of raw finding dicts
    """
    t0 = time.time()
    _log(f"Starting Stage 3 | {len(sessions)} session(s)")

    if not sessions:
        _log("No sessions — skipping LLM stage")
        return []

    try:
        generate_fn = get_generate_fn(api_key)
        model       = pick_model(generate_fn)
    except Exception as exc:
        _log(f"LLM setup failed: {exc}")
        return []

    findings = run_parallel_sessions(sessions, generate_fn, model)

    elapsed = time.time() - t0
    _log(f"Stage 3 complete in {elapsed:.1f}s | {len(findings)} raw finding(s)")
    return findings