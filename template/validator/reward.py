import numpy as np
from typing import List, Optional

import bittensor as bt

from auditing.models import AuditReport, ChallengeReport
from auditing.scorer import score_one


def reward(
    report: Optional[AuditReport],
    ground_truth: ChallengeReport,
) -> float:
    """
    Reward a single miner's AuditReport against the ground-truth ChallengeReport.

    Args:
    - report       : The miner's AuditReport, or None if the miner did not respond.
    - ground_truth : The ChallengeReport fetched from the challenge API.

    Returns:
    - float in [0.0, 1.0]
    """
    score = score_one(report, ground_truth)
    bt.logging.info(
        f"reward → findings={len(report.findings) if report else 'N/A'}  "
        f"score={score:.4f}"
    )
    return score


def get_rewards(
    self,
    reports: List[Optional[AuditReport]],
    ground_truth: ChallengeReport,
) -> np.ndarray:
    """
    Returns an array of rewards for all miner reports in a validation round.

    Args:
    - reports      : One AuditReport (or None) per miner, in miner-index order.
    - ground_truth : The ChallengeReport fetched from the challenge API.

    Returns:
    - np.ndarray of float32, shape (len(reports),), values in [0.0, 1.0].
    """
    scores = [reward(report, ground_truth) for report in reports]
    bt.logging.info(
        f"get_rewards → miners={len(scores)}  "
        f"mean={np.mean(scores):.4f}  max={np.max(scores):.4f}"
    )
    return np.array(scores, dtype=np.float32)