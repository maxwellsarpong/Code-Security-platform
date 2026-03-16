from sqlmodel import SQLModel, Field, Column, JSON, Relationship
from typing import Optional, List, Any, Dict
from uuid import UUID, uuid4
from datetime import datetime, date


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = Field(default=False)
    
    # Quota and Plan
    plan: str = "starter"
    rate_limit_per_minute: int = 10
    scan_quota_per_month: Optional[int] = 2
    resolve_quota_per_month: Optional[int] = 2
    
    # Integration Config
    slack_webhook_url: Optional[str] = None
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None
    
    # Git Tokens
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    bitbucket_token: Optional[str] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    scans: List["Scan"] = Relationship(back_populates="user")
    findings: List["Finding"] = Relationship(back_populates="user")


class Scan(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True)
    repo_url: Optional[str] = None
    is_local: bool = Field(default=False)
    zip_path: Optional[str] = None
    status: str = "queued"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    risk_score: Optional[float] = None
    git_token: Optional[str] = None

    # Relationships
    findings: List["Finding"] = Relationship(back_populates="scan")
    user: "User" = Relationship(back_populates="scans")


class Finding(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(foreign_key="scan.id")
    user_id: UUID = Field(foreign_key="user.id", index=True)
    title: str
    severity: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    # Scanner metadata
    scanner_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    confidence: Optional[str] = None
    is_fixed: bool = Field(default=False)
    pr_url: Optional[str] = None

    # Relationships
    scan: Optional[Scan] = Relationship(back_populates="findings")
    user: "User" = Relationship(back_populates="findings")





class APIKey(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id")
    key: str
    revoked: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Usage(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id")
    date: date
    scans_count: int = 0
    resolutions_count: int = 0
    billable_units: int = 0


class BillingEvent(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id")
    event_type: str
    amount: float = 0.0
    # annotate with a normal Python type for Pydantic validation and attach a SQL JSON column
    meta: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON), alias="metadata")
    created_at: datetime = Field(default_factory=datetime.utcnow)
