# auditing/scorer.py  — replace score_one() with this

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional
from auditing.models import AuditReport, ChallengeReport, GroundTruthFinding, MinerFinding

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 5.0,
    "high":     4.0,
    "medium":   2.0,
    "low":      1.0,
    "info":     0.5,
}

# How much credit for each matching dimension (must sum ≤ 1.0)
FILE_WEIGHT     = 0.35   # correct file identified
TYPE_WEIGHT     = 0.45   # correct vulnerability class
SEVERITY_WEIGHT = 0.20   # correct severity

# Adjacent severities still get partial credit
SEVERITY_ADJACENCY: dict[str, set[str]] = {
    "critical": {"high"},
    "high":     {"critical", "medium"},
    "medium":   {"high", "low"},
    "low":      {"medium", "info"},
    "info":     {"low"},
}
ADJACENT_SEVERITY_CREDIT = 0.5   # 50 % credit for off-by-one severity

FP_PENALTY = 0.02
MIN_SCORE  = 0.0
MAX_SCORE  = 1.0

_R = "\033[0m"; _B = "\033[1m"; _G = "\033[92m"
_Y = "\033[93m"; _E = "\033[91m"; _C = "\033[96m"; _D = "\033[2m"
def _ok(m):   print(f"{_G}  ✓  {m}{_R}")
def _info(m): print(f"{_C}  →  {m}{_R}")
def _warn(m): print(f"{_Y}  ⚠  {m}{_R}")


def _norm_file(path: str) -> str:
    return Path(path).name.lower()

def _norm_type(vuln_type: str) -> str:
    return re.sub(r"[\W_]+", "", vuln_type.lower())

def _severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity.lower(), 0.5)


def _finding_match_score(mf: MinerFinding, gt: GroundTruthFinding) -> float:
    """
    Returns a match score in [0.0, 1.0] between a miner finding and a GT finding.
    Exact match = 1.0. Partial credit for file + type match with wrong severity.
    Zero if file or type don't match at all.
    """
    mf_file = _norm_file(mf.file)
    gt_file = _norm_file(gt.file)
    mf_type = _norm_type(mf.vulnerability_type)
    gt_type = _norm_type(gt.vulnerability_type)
    mf_sev  = mf.severity.lower()
    gt_sev  = gt.severity.lower()

    # ── File match ───────────────────────────────────────────────────────────
    if mf_file == gt_file:
        file_score = 1.0
    else:
        return 0.0   # wrong file → no credit at all

    # ── Vulnerability type match (substring counts as partial) ───────────────
    if mf_type == gt_type:
        type_score = 1.0
    elif gt_type in mf_type or mf_type in gt_type:
        # e.g. miner says "reentrancyandoraclemanipulation", GT has "reentrancy"
        type_score = 0.6
    else:
        return 0.0   # completely wrong type → no credit

    # ── Severity match ───────────────────────────────────────────────────────
    if mf_sev == gt_sev:
        sev_score = 1.0
    elif mf_sev in SEVERITY_ADJACENCY.get(gt_sev, set()):
        sev_score = ADJACENT_SEVERITY_CREDIT
    else:
        sev_score = 0.0

    return (
        file_score * FILE_WEIGHT
        + type_score * TYPE_WEIGHT
        + sev_score * SEVERITY_WEIGHT
    )


def score_one(
    report: Optional[AuditReport],
    ground_truth: ChallengeReport,
) -> float:
    if report is None:
        return 0.0

    total_weight = sum(_severity_weight(gt.severity) for gt in ground_truth.findings)
    if total_weight == 0.0:
        return 0.0

    # For each GT finding, track the best partial match score given by the miner
    gt_findings = list(ground_truth.findings)
    gt_credited  = [False] * len(gt_findings)   # prevent double-crediting same GT
    mf_matched   = [False] * len(report.findings)

    weighted_hits = 0.0
    false_positives = 0

    for mf_idx, mf in enumerate(report.findings):
        best_score = 0.0
        best_gt_idx = -1

        for gt_idx, gt in enumerate(gt_findings):
            if gt_credited[gt_idx]:
                continue
            match = _finding_match_score(mf, gt)
            if match > best_score:
                best_score   = match
                best_gt_idx  = gt_idx

        if best_score > 0.0 and best_gt_idx >= 0:
            gt_credited[best_gt_idx] = True
            mf_matched[mf_idx]       = True
            gt = gt_findings[best_gt_idx]
            # Credit is proportional to how well it matched × GT severity weight
            weighted_hits += best_score * _severity_weight(gt.severity)
            _info(
                f"  MATCH  [{mf.severity.upper():8}] {mf.file} | {mf.vulnerability_type}"
                f"  →  GT [{gt.severity.upper():8}] {gt.file} | {gt.vulnerability_type}"
                f"  match={best_score:.2f}  weight={_severity_weight(gt.severity):.1f}"
            )
        else:
            false_positives += 1

    raw     = weighted_hits / total_weight
    penalty = false_positives * FP_PENALTY
    final   = max(MIN_SCORE, min(MAX_SCORE, raw - penalty))

    _info(f"  weighted_hits={weighted_hits:.2f}  total={total_weight:.2f}"
          f"  raw={raw:.3f}  fp={false_positives}  penalty={penalty:.3f}"
          f"  final={final:.3f}")
    return final