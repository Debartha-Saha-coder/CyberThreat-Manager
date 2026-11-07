"""
Pydantic v2 schemas for auth, scanning, community, and dashboard.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# ------------------------------------------------------------------ #
# Auth schemas
# ------------------------------------------------------------------ #
class UserRegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (underscores and hyphens allowed).")
        return v.lower()


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Scan schemas
# ------------------------------------------------------------------ #
class ScanCreateRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


class ScanListItem(BaseModel):
    id: int
    url: str
    status: str
    overall_risk_score: Optional[float]
    risk_classification: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    id: int
    url: str
    normalized_url: str
    domain: str
    status: str
    overall_risk_score: Optional[float]
    risk_classification: Optional[str]
    threat_score: Optional[float]
    web_score: Optional[float]
    certificate_score: Optional[float]
    community_score: Optional[float]
    threat_engine_ran: bool
    web_engine_ran: bool
    cert_engine_ran: bool
    community_engine_ran: bool
    error_message: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class ScanReportResponse(BaseModel):
    scan: ScanDetailResponse
    scoring: Optional[dict]
    threat: Optional[dict]
    web: Optional[dict]
    certificate: Optional[dict]
    community: Optional[dict]


# ------------------------------------------------------------------ #
# Community schemas
# ------------------------------------------------------------------ #
class ReportCreateRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    category: str
    title: str = Field(min_length=5, max_length=255)
    description: str = Field(min_length=20)
    evidence: Optional[list[dict[str, str]]] = None


class ReportVoteRequest(BaseModel):
    vote_type: str  # support | dispute

    @field_validator("vote_type")
    @classmethod
    def valid_vote(cls, v: str) -> str:
        if v not in ("support", "dispute"):
            raise ValueError("vote_type must be 'support' or 'dispute'.")
        return v


class ReportListItem(BaseModel):
    id: int
    url: str
    domain: str
    category: str
    title: str
    status: str
    support_count: int
    dispute_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportDetailResponse(BaseModel):
    id: int
    url: str
    domain: str
    category: str
    title: str
    description: str
    status: str
    support_count: int
    dispute_count: int
    analyst_notes: Optional[str]
    verified_at: Optional[datetime]
    evidence: list[dict]
    created_at: datetime

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Dashboard schemas
# ------------------------------------------------------------------ #
class DashboardStats(BaseModel):
    total_scans: int
    scans_today: int
    threats_detected: int
    high_risk_domains: int
    critical_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    recent_scans: list[ScanListItem]
    risk_distribution: list[dict[str, Any]]


# ------------------------------------------------------------------ #
# Domain intelligence schemas
# ------------------------------------------------------------------ #
class DomainReputationResponse(BaseModel):
    domain: str
    reputation_score: Optional[float]
    total_scans: int
    confirmed_malicious: bool
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Error schema
# ------------------------------------------------------------------ #
class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
