from pydantic import BaseModel, Field
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

class AuditReport(BaseModel):
    challenge_id: str
    project_id: str
    findings: list[MinerFinding]