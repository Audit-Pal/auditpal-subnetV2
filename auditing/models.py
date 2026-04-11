from pydantic import BaseModel, Field, field_validator
from typing import Optional

class Codebase(BaseModel):
    codebase_id: str
    repo_url: str
    commit: str                         
    tarball_url: str                    
    tree_url: str = ""

class Challenge(BaseModel):
    id: str = Field(alias="_id")
    project_id: str                      
    name: str
    platform: str                       
    codebases: list[Codebase]
    created_at: str
    updated_at: str
    model_config = {"populate_by_name": True}



class GroundTruthFinding(BaseModel):
    id: str
    title: str
    description: str
    vulnerability_type: str
    severity: str
    confidence: float
    file: str
    location: str
    reported_by_model: str
    status: str

    @field_validator(
        "title",
        "description",
        "vulnerability_type",
        "severity",
        "file",
        "location",
        "reported_by_model",
        "status",
        mode="before"
    )
    @classmethod
    def fix_strings(cls, v):
        if isinstance(v, list):
            return " ".join(map(str, v))
        return v                    

class ChallengeReport(BaseModel):
    id: str = Field(alias="_id")
    project_id: str
    files_analyzed: int
    total_findings: int
    findings: list[GroundTruthFinding]
    timestamp: str

    model_config = {"populate_by_name": True}



class MinerFinding(BaseModel):
    file: str
    severity: str
    vulnerability_type: str
    title: str
    description: str
    location: Optional[str] = None

    @field_validator(
        "file",
        "severity",
        "vulnerability_type",
        "title",
        "description",
        "location",
        mode="before"
    )
    @classmethod
    def fix_strings(cls, v):
        if isinstance(v, list):
            return " ".join(map(str, v))
        return v

class AuditReport(BaseModel):
    challenge_id: str
    project_id: str
    findings: list[MinerFinding]