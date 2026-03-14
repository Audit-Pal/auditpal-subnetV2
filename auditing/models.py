from pydantic import BaseModel, Field
from typing import Optional

# --- Challenge API models ---

class Codebase(BaseModel):
    codebase_id: str
    repo_url: str
    commit: str                          # may be "" or "main" — handle both
    tarball_url: str                     # prefer this over git clone — faster
    tree_url: str = ""

class Challenge(BaseModel):
    id: str = Field(alias="_id")
    project_id: str                      # KEY — used to fetch report
    name: str
    platform: str                        # "code4rena" | "sherlock" | "cantina"
    codebases: list[Codebase]
    created_at: str
    updated_at: str

    model_config = {"populate_by_name": True}

# --- Report API models (ground truth) ---

class GroundTruthFinding(BaseModel):
    id: str
    title: str
    description: str
    vulnerability_type: str
    severity: str                        # "high" | "medium" | "low" | "info"
    confidence: float                    # 0.0–1.0
    file: str                            # "AaveV3FiatReserve.sol"
    location: str
    reported_by_model: str
    status: str                          # "proposed"

class ChallengeReport(BaseModel):
    id: str = Field(alias="_id")
    project_id: str
    files_analyzed: int
    total_findings: int
    findings: list[GroundTruthFinding]
    timestamp: str

    model_config = {"populate_by_name": True}

# --- Miner output models ---

class MinerFinding(BaseModel):
    file: str                            # must match a .sol file in the repo
    severity: str                        # "high" | "medium" | "low" | "info"
    vulnerability_type: str
    title: str
    description: str
    location: Optional[str] = None

class AuditReport(BaseModel):
    challenge_id: str
    project_id: str
    findings: list[MinerFinding]