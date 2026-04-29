"""
Stage 4 — Deduplicate & Verify (~10s)
=======================================
Components:
  - Deduplication engine    : merge near-duplicate findings across sessions
  - Cross-contract verifier : one LLM call — do findings combine into larger attacks?
  - Severity ranker         : CVSS-style ranking of deduplicated findings
  - Report generator        : formats ranked findings into final AuditReport

Input  : list[dict] raw findings from stage3_llm.run_stage3()
Output : final AuditReport dict matching validator schema
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import defaultdict
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}
VALID_SEVERITIES = set(SEVERITY_ORDER.keys())

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[stage4] {msg}", file=sys.stderr, flush=True)


# ════════════════════════════════════════════════════════════════════════════════
# A — Deduplication Engine
# ════════════════════════════════════════════════════════════════════════════════

def deduplicate(findings: list[dict]) -> list[dict]:
    """
    Merge near-duplicate findings across sessions.

    Two findings are duplicates if they share:
      - same file (normalized)
      - similar title (normalized, first 30 chars)
      - close line numbers (within 10 lines)

    Keeps the finding with the most complete description.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)

    for f in findings:
        key = _dedup_key(f)
        buckets[key].append(f)

    merged: list[dict] = []
    for key, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            # Keep the one with longest description (most detailed)
            best = max(group, key=lambda x: len(x.get("description", "")))
            # Merge any extra detail from others
            all_recs = set(
                x.get("recommendation", "") for x in group
                if x.get("recommendation")
            )
            if len(all_recs) > 1:
                best["recommendation"] = " | ".join(sorted(all_recs))
            merged.append(best)

    _log(f"Dedup: {len(findings)} → {len(merged)} findings "
         f"({len(findings) - len(merged)} duplicates removed)")
    return merged


def _dedup_key(f: dict) -> str:
    """Generate a deduplication bucket key."""
    file_norm  = str(f.get("file", "")).lower().replace(".sol", "")
    title_norm = re.sub(r'\W+', '', str(f.get("title", ""))).lower()[:30]
    line_bucket = int(f.get("line_start", 0)) // 10   # bucket by 10-line windows
    return f"{file_norm}|{title_norm}|{line_bucket}"


# ════════════════════════════════════════════════════════════════════════════════
# B — Cross-Contract Verifier
# ════════════════════════════════════════════════════════════════════════════════

VERIFY_PROMPT = """\
You are a senior smart-contract security researcher.

Below is a list of individual findings from a multi-contract audit.
Your task: identify if ANY TWO OR MORE findings together enable a LARGER attack chain
that wasn't reported individually (e.g. reentrancy + oracle manipulation = flash loan exploit).

Only report NEW combined findings not already in the list.
If no combinations exist, return: []

Respond ONLY with a JSON array — no markdown, no explanation.
Same schema as findings:
  title, vulnerability_type, severity (critical|high|medium|low|info),
  file, line_start, line_end, description, recommendation

Individual findings:
{findings_summary}

BEGIN:
"""


def cross_contract_verify(
    findings:    list[dict],
    generate_fn,
    model:       str,
) -> list[dict]:
    """
    One LLM call to find combined cross-contract attack vectors.
    Appends any new combined findings to the list.
    """
    if len(findings) < 2:
        _log("Cross-verify: skipped (fewer than 2 findings)")
        return findings

    # Build compact summary for the prompt
    summary_lines = []
    for f in findings[:20]:   # cap to avoid prompt bloat
        summary_lines.append(
            f"- [{f.get('severity','?').upper()}] {f.get('title','')} "
            f"in {f.get('file','')} line {f.get('line_start', '?')}"
        )
    summary = "\n".join(summary_lines)

    prompt = VERIFY_PROMPT.format(findings_summary=summary)

    try:
        _log("Cross-verify: calling LLM...")
        t0  = time.time()
        raw = generate_fn(model, prompt)
        _log(f"Cross-verify: response in {time.time()-t0:.1f}s ({len(raw)} chars)")

        combined = _parse_json_safe(raw)
        if combined:
            _log(f"Cross-verify: {len(combined)} combined attack(s) found")
            for c in combined:
                c["_combined"]          = True
                c["vulnerability_type"] = c.get("vulnerability_type", "Combined Attack")
            findings.extend(combined)
        else:
            _log("Cross-verify: no combined attacks found")

    except Exception as exc:
        _log(f"Cross-verify: failed — {type(exc).__name__}: {exc}")

    return findings


def _parse_json_safe(raw: str) -> list[dict]:
    """Safe JSON extraction from LLM output."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        parts   = cleaned.split("```")
        cleaned = parts[1] if len(parts) > 1 else cleaned
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()

    try:
        result = json.loads(cleaned)
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        pass

    match = re.search(r'\[.*?\]', cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return []


# ════════════════════════════════════════════════════════════════════════════════
# C — Severity Ranker
# ════════════════════════════════════════════════════════════════════════════════

def rank_findings(findings: list[dict]) -> list[dict]:
    """
    CVSS-style ranking:
      Primary   : severity (critical → info)
      Secondary : combined (cross-contract) findings ranked higher within tier
      Tertiary  : file name alphabetical for determinism
    """
    def _sort_key(f: dict) -> tuple:
        sev   = f.get("severity", "info").lower()
        sev_n = SEVERITY_ORDER.get(sev, 5)
        is_combined = 0 if f.get("_combined") else 1   # combined first within tier
        fname = str(f.get("file", ""))
        return (sev_n, is_combined, fname)

    ranked = sorted(findings, key=_sort_key)

    # Log severity breakdown
    counts: dict[str, int] = defaultdict(int)
    for f in ranked:
        counts[f.get("severity", "info")] += 1
    _log(f"Ranked {len(ranked)} findings: {dict(counts)}")

    return ranked


# ════════════════════════════════════════════════════════════════════════════════
# D — Report Generator
# ════════════════════════════════════════════════════════════════════════════════

def generate_report(
    findings:     list[dict],
    challenge_id: str,
    project_id:   str,
) -> dict[str, Any]:
    """
    Format ranked findings into the final AuditReport matching validator schema.
    Validates and sanitizes all fields.
    """
    formatted: list[dict] = []

    for i, f in enumerate(findings):
        sev = str(f.get("severity", "info")).lower()
        if sev not in VALID_SEVERITIES:
            sev = "info"

        formatted.append({
            "id":                 f"finding-{i+1:03d}",
            "title":              str(f.get("title", "Untitled"))[:80],
            "vulnerability_type": str(f.get("vulnerability_type", "Unknown")),
            "severity":           sev,
            "file":               str(f.get("file", "unknown.sol")),
            "line_start":         _safe_int(f.get("line_start", 0)),
            "line_end":           _safe_int(f.get("line_end", 0)),
            "description":        str(f.get("description", "")),
            "recommendation":     str(f.get("recommendation", "")),
        })

    report = {
        "challenge_id": challenge_id,
        "project_id":   project_id,
        "findings":     formatted,
    }

    # Summary stats (stripped before returning — for logging only)
    counts: dict[str, int] = defaultdict(int)
    for f in formatted:
        counts[f["severity"]] += 1

    _log(f"Report generated: {len(formatted)} findings | "
         f"critical={counts.get('critical',0)} "
         f"high={counts.get('high',0)} "
         f"medium={counts.get('medium',0)} "
         f"low={counts.get('low',0)} "
         f"info={counts.get('info',0)}")

    return report


def _safe_int(val: Any) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


# ════════════════════════════════════════════════════════════════════════════════
# MAIN — run_stage4()
# ════════════════════════════════════════════════════════════════════════════════

def run_stage4(
    findings:     list[dict],
    challenge_id: str,
    project_id:   str,
    generate_fn   = None,
    model:        str = "",
) -> dict[str, Any]:
    """
    Full Stage 4 pipeline.

    Input : raw findings from stage3_llm.run_stage3()
    Output: final AuditReport dict
    """
    t0 = time.time()
    _log(f"Starting Stage 4 | {len(findings)} raw finding(s)")

    if not findings:
        _log("No findings — returning empty report")
        return generate_report([], challenge_id, project_id)

    # A: Deduplicate
    deduped = deduplicate(findings)

    # B: Cross-contract verify (only if LLM available)
    if generate_fn and model:
        verified = cross_contract_verify(deduped, generate_fn, model)
    else:
        _log("Cross-verify: skipped (no LLM available)")
        verified = deduped

    # C: Rank
    ranked = rank_findings(verified)

    # D: Generate report
    report = generate_report(ranked, challenge_id, project_id)

    elapsed = time.time() - t0
    _log(f"Stage 4 complete in {elapsed:.1f}s | {len(report['findings'])} final finding(s)")

    return report