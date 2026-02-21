from pydantic import BaseModel, HttpUrl, ConfigDict
from typing import Optional, List
from uuid import UUID
from datetime import datetime


class UserCreate(BaseModel):
    email: str
    password: str
    tenant_name: str  # Creating a user also creates a tenant for simplicity in this flow


class LoginRequest(BaseModel):
    email: str
    password: str


class UserRead(BaseModel):
    id: UUID
    email: str
    tenant_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TenantRead(BaseModel):
    id: UUID
    name: str
    plan: str
    slack_webhook_url: Optional[str] = None
    jira_url: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class ScanCreate(BaseModel):
    repo_url: HttpUrl
    git_token: Optional[str] = None


class FindingRead(BaseModel):
    id: UUID
    scan_id: UUID
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
    is_fixed: bool = False
    pr_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanRead(BaseModel):
    id: UUID
    tenant_id: UUID
    repo_url: HttpUrl
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    risk_score: Optional[float]
    findings: Optional[List[FindingRead]] = []

    model_config = ConfigDict(from_attributes=True)


class ResolutionRequest(BaseModel):
    github_token: Optional[str] = None


class ResolutionResponse(BaseModel):
    status: str
    pr_url: Optional[str] = None
    finding_id: UUID
    message: str

