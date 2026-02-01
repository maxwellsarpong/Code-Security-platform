from sqlmodel import SQLModel, Field, Column, JSON, Relationship
from typing import Optional, List, Any, Dict
from uuid import UUID, uuid4
from datetime import datetime, date


class Scan(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    repo_url: str
    status: str = "queued"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    risk_score: Optional[float] = None

    # Relationships
    findings: List["Finding"] = Relationship(back_populates="scan")


class Finding(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(foreign_key="scan.id")
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

    # Relationships
    scan: Optional[Scan] = Relationship(back_populates="findings")


class Tenant(SQLModel, table=True):
    """Represents a customer / tenant with quota and rate limits."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str
    plan: str = "free"
    rate_limit_per_minute: int = 10
    quota_per_month: int = 100
    created_at: datetime = Field(default_factory=datetime.utcnow)


class APIKey(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID
    key: str
    revoked: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Usage(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID
    date: date
    scans_count: int = 0
    billable_units: int = 0


class BillingEvent(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID
    event_type: str
    amount: float = 0.0
    # annotate with a normal Python type for Pydantic validation and attach a SQL JSON column
    meta: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON), alias="metadata")
    created_at: datetime = Field(default_factory=datetime.utcnow)
