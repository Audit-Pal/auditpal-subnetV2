from __future__ import annotations
 
import re
from pathlib import Path
from typing import Optional
 
import bittensor as bt
 
from auditing.models import AuditReport, ChallengeReport, GroundTruthFinding, MinerFinding
 
 
# ── tuneable constants ────────────────────────────────────────────────────────
 
SEVERITY_WEIGHTS: dict[str, float] = {
    "high":   4.0,
    "medium": 2.0,
    "low":    1.0,
    "info":   0.5,
}
 
FP_PENALTY = 0.02          # deducted per false-positive finding
MIN_SCORE  = 0.0
MAX_SCORE  = 1.0
 
 
# ── terminal colours (mirrors sandbox.py) ────────────────────────────────────
 
_R = "\033[0m";  _B = "\033[1m";  _G = "\033[92m"
_Y = "\033[93m"; _E = "\033[91m"; _C = "\033[96m"; _D = "\033[2m"
 
def _ok(m):   print(f"{_G}  ✓  {m}{_R}")
def _info(m): print(f"{_C}  →  {m}{_R}")
def _warn(m): print(f"{_Y}  ⚠  {m}{_R}")
def _err(m):  print(f"{_E}  ✗  {m}{_R}")
def _dim(m):  print(f"{_D}      {m}{_R}")
def _step(m): print(f"\n{_B}{_C}{'─'*60}{_R}\n{_B}  {m}{_R}")
 
 
# ── normalisation helpers ─────────────────────────────────────────────────────
 
def _norm_file(path: str) -> str:
    """Return the lowercased basename of a file path."""
    return Path(path).name.lower()
 
 
def _norm_type(vuln_type: str) -> str:
    """Lowercase + remove punctuation/whitespace for fuzzy type matching."""
    return re.sub(r"[\W_]+", "", vuln_type.lower())
 
 
def _severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity.lower(), 0.5)
 
 
# ── key builders ─────────────────────────────────────────────────────────────
 
def _gt_key(finding: GroundTruthFinding) -> tuple[str, str, str]:
    """Canonical lookup key for a ground-truth finding."""
    return (
        _norm_file(finding.file),
        _norm_type(finding.vulnerability_type),
        finding.severity.lower(),
    )
 
 
def _miner_key(finding: MinerFinding) -> tuple[str, str, str]:
    """Same key shape for a miner finding."""
    return (
        _norm_file(finding.file),
        _norm_type(finding.vulnerability_type),
        finding.severity.lower(),
    )
 
 
# ── per-miner scoring ─────────────────────────────────────────────────────────
 
def score_one(
    report: Optional[AuditReport],
    ground_truth: ChallengeReport,
) -> float:
    """
    Score a single miner report against the ground-truth ChallengeReport.
 
    Returns a float in [0.0, 1.0].
    """
    # No report at all → zero
    if report is None:
        return 0.0
 
    # Build a lookup: key → list[GroundTruthFinding]
    # (multiple GT findings can share the same key — each is worth its own weight)
    gt_by_key: dict[tuple, list[GroundTruthFinding]] = {}
    for gt in ground_truth.findings:
        k = _gt_key(gt)
        gt_by_key.setdefault(k, []).append(gt)
 
    # Total achievable weighted score
    total_weight = sum(_severity_weight(gt.severity) for gt in ground_truth.findings)
    if total_weight == 0.0:
        return 0.0
 
    # Track which GT findings have already been credited (avoid double-counting)
    credited_ids: set[str] = set()
    weighted_hits = 0.0
    false_positives = 0
 
    for mf in report.findings:
        key = _miner_key(mf)
        candidates = gt_by_key.get(key, [])
 
        # Credit the first un-credited GT match
        matched = False
        for gt in candidates:
            if gt.id not in credited_ids:
                credited_ids.add(gt.id)
                weighted_hits += _severity_weight(gt.severity)
                matched = True
                break
 
        if not matched:
            false_positives += 1
 
    # Raw score before penalty
    raw = weighted_hits / total_weight
 
    # False-positive penalty
    penalty = false_positives * FP_PENALTY
    final   = max(MIN_SCORE, min(MAX_SCORE, raw - penalty))
 
    return final
 
 
# ── batch scoring (one call per validation round) ────────────────────────────
 
def score_miners(
    reports: list[Optional[AuditReport]],
    ground_truth: ChallengeReport,
) -> list[float]:
    """
    Score every miner in a validation round.
 
    Parameters
    ----------
    reports      : one AuditReport (or None) per miner, in miner-index order.
    ground_truth : the ChallengeReport fetched from the challenge API.
 
    Returns
    -------
    List of floats in [0.0, 1.0], same length as `reports`.
    """
    _step("Scoring miners")
    _info(f"Ground-truth findings : {len(ground_truth.findings)}")
    _info(f"Miners to score       : {len(reports)}")
 
    # Pre-compute total achievable weight once for the log line
    total_weight = sum(_severity_weight(gt.severity) for gt in ground_truth.findings)
    _info(f"Total achievable weight: {total_weight:.1f}")
 
    sev_map = {"high": _E, "medium": _Y, "low": _C, "info": _D}
    print()
    _dim("Ground-truth breakdown:")
    from collections import Counter
    sev_counts = Counter(gt.severity.lower() for gt in ground_truth.findings)
    for sev, cnt in sorted(sev_counts.items()):
        colour = sev_map.get(sev, _D)
        _dim(f"  {colour}[{sev.upper():6}]{_R}  {cnt} finding(s)")
 
    scores: list[float] = []
    for idx, report in enumerate(reports):
        score = score_one(report, ground_truth)
        scores.append(score)
 
        if report is None:
            _warn(f"  miner {idx:>3}  →  no report  →  score = 0.000")
        else:
            findings_n = len(report.findings)
            bar_filled = int(score * 20)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            colour = _G if score >= 0.7 else (_Y if score >= 0.3 else _E)
            print(
                f"  miner {idx:>3}  "
                f"findings={findings_n:>3}  "
                f"[{colour}{bar}{_R}]  "
                f"{colour}{score:.3f}{_R}"
            )
 
    print()
    valid_scores = [s for s, r in zip(scores, reports) if r is not None]
    if valid_scores:
        _info(f"Mean score (responded) : {sum(valid_scores)/len(valid_scores):.3f}")
        _info(f"Max score              : {max(valid_scores):.3f}")
        _info(f"Min score              : {min(valid_scores):.3f}")
    _ok(f"Scoring complete — {len(scores)} miners processed")
 
    return scores
 
 
# ── debug helper ─────────────────────────────────────────────────────────────
 
def explain_score(
    report: AuditReport,
    ground_truth: ChallengeReport,
) -> None:
    """
    Pretty-print a per-finding breakdown for a single miner (debugging).
    """
    _step("Score explanation")
    gt_by_key: dict[tuple, list[GroundTruthFinding]] = {}
    for gt in ground_truth.findings:
        k = _gt_key(gt)
        gt_by_key.setdefault(k, []).append(gt)
 
    credited_ids: set[str] = set()
    total_weight = sum(_severity_weight(gt.severity) for gt in ground_truth.findings)
    weighted_hits = 0.0
    fp = 0
 
    for mf in report.findings:
        key = _miner_key(mf)
        candidates = gt_by_key.get(key, [])
        matched_gt = None
        for gt in candidates:
            if gt.id not in credited_ids:
                credited_ids.add(gt.id)
                matched_gt = gt
                weighted_hits += _severity_weight(gt.severity)
                break
 
        if matched_gt:
            _ok(
                f"HIT   [{mf.severity.upper():6}]  {mf.file}  "
                f"| {mf.vulnerability_type}  "
                f"+{_severity_weight(matched_gt.severity):.1f}"
            )
        else:
            fp += 1
            _warn(
                f"FP    [{mf.severity.upper():6}]  {mf.file}  "
                f"| {mf.vulnerability_type}  "
                f"-{FP_PENALTY:.3f}"
            )
 
    raw     = weighted_hits / total_weight if total_weight else 0.0
    penalty = fp * FP_PENALTY
    final   = max(MIN_SCORE, min(MAX_SCORE, raw - penalty))
 
    print()
    _info(f"Weighted hits : {weighted_hits:.1f} / {total_weight:.1f}")
    _info(f"Raw score     : {raw:.3f}")
    _info(f"FP penalty    : -{penalty:.3f}  ({fp} false positive(s))")
    _ok  (f"Final score   : {final:.3f}")