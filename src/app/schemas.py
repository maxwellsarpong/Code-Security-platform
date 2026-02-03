from pydantic import BaseModel, HttpUrl, ConfigDict
from typing import Optional, List
from uuid import UUID
from datetime import datetime


class ScanCreate(BaseModel):
    repo_url: HttpUrl
    git_token: Optional[str] = None


class FindingRead(BaseModel):
    id: UUID
    title: str
    severity: str
    description: Optional[str]
    remediation: Optional[str]
    # Scanner metadata
    scanner_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    confidence: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanRead(BaseModel):
    id: UUID
    repo_url: HttpUrl
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    risk_score: Optional[float]
    findings: Optional[List[FindingRead]] = []

    model_config = ConfigDict(from_attributes=True)
