from pydantic import BaseModel, HttpUrl, ConfigDict, model_validator
from typing import Optional, List
from uuid import UUID
from datetime import datetime, date


class UserCreate(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class PasswordRecoveryRequest(BaseModel):
    email: str


class PasswordResetRequest(BaseModel):
    token: str
    new_password: str


class UserRead(BaseModel):
    id: UUID
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserProfileRead(BaseModel):
    id: UUID
    email: str
    plan: str
    scan_quota_per_month: Optional[int] = None
    resolve_quota_per_month: Optional[int] = None
    slack_webhook_url: Optional[str] = None
    jira_url: Optional[str] = None
    is_superuser: bool = False
    created_at: datetime

    @model_validator(mode='after')
    def backfill_quotas(self) -> "UserProfileRead":
        from .core.billing_plans import get_plan
        plan_config = get_plan(self.plan)
        if self.scan_quota_per_month is None:
            self.scan_quota_per_month = plan_config["scan_quota"]
        if self.resolve_quota_per_month is None:
            self.resolve_quota_per_month = plan_config["resolve_quota"]
        return self

    model_config = ConfigDict(from_attributes=True)


class UserProfileUpdate(BaseModel):
    slack_webhook_url: Optional[str] = None
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    bitbucket_token: Optional[str] = None


class AdminUserUpdate(BaseModel):
    plan: Optional[str] = None
    is_superuser: Optional[bool] = None
    scan_quota_per_month: Optional[int] = None
    resolve_quota_per_month: Optional[int] = None


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
    user_id: UUID
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


class UsageRead(BaseModel):
    date: date
    scans_count: int
    resolutions_count: int
    billable_units: int

    model_config = ConfigDict(from_attributes=True)


class UserUsageResponse(BaseModel):
    usage: List[UsageRead]
    percentage_credit_left: float
    scan_quota_limit: int
    resolve_quota_limit: int
    current_month_usage: int


class AdminHealthStats(BaseModel):
    system_health_percentage: float
    total_scans: int
    total_findings: int
    total_fixed_findings: int
    average_risk_score: float


class EventRead(BaseModel):
    id: UUID
    user_id: UUID
    event_type: str
    amount: float
    meta: Optional[dict] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
