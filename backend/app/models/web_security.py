"""
SQLAlchemy models — Web security assessment.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WebAssessment(Base):
    """Overall web security posture per scan."""
    __tablename__ = "web_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    final_url: Mapped[str | None] = mapped_column(Text)
    http_status_code: Mapped[int | None] = mapped_column(Integer)
    enforces_https: Mapped[bool] = mapped_column(Boolean, default=False)
    redirect_count: Mapped[int] = mapped_column(Integer, default=0)
    redirect_chain: Mapped[list | None] = mapped_column(JSON)
    has_mixed_content: Mapped[bool] = mapped_column(Boolean, default=False)
    has_csp: Mapped[bool] = mapped_column(Boolean, default=False)
    has_hsts: Mapped[bool] = mapped_column(Boolean, default=False)
    has_x_content_type: Mapped[bool] = mapped_column(Boolean, default=False)
    has_referrer_policy: Mapped[bool] = mapped_column(Boolean, default=False)
    has_x_frame_options: Mapped[bool] = mapped_column(Boolean, default=False)
    has_permissions_policy: Mapped[bool] = mapped_column(Boolean, default=False)
    cookie_issues: Mapped[list | None] = mapped_column(JSON)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    server_header: Mapped[str | None] = mapped_column(String(255))
    powered_by: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    findings: Mapped[list["SecurityFinding"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    headers: Mapped["HTTPHeaders"] = relationship(
        back_populates="assessment", uselist=False, cascade="all, delete-orphan"
    )


class SecurityFinding(Base):
    """Individual security finding from web assessment."""
    __tablename__ = "security_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    assessment_id: Mapped[int] = mapped_column(Integer, ForeignKey("web_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), nullable=False, index=True)
    evidence: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(100))  # header, cookie, redirect, etc.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assessment: Mapped["WebAssessment"] = relationship(back_populates="findings")


class HTTPHeaders(Base):
    """Raw HTTP response headers per scan."""
    __tablename__ = "http_headers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    assessment_id: Mapped[int] = mapped_column(Integer, ForeignKey("web_assessments.id", ondelete="CASCADE"), unique=True, nullable=False)
    content_security_policy: Mapped[str | None] = mapped_column(Text)
    strict_transport_security: Mapped[str | None] = mapped_column(Text)
    x_content_type_options: Mapped[str | None] = mapped_column(String(100))
    x_frame_options: Mapped[str | None] = mapped_column(String(100))
    referrer_policy: Mapped[str | None] = mapped_column(String(255))
    permissions_policy: Mapped[str | None] = mapped_column(Text)
    x_xss_protection: Mapped[str | None] = mapped_column(String(100))
    server: Mapped[str | None] = mapped_column(String(255))
    x_powered_by: Mapped[str | None] = mapped_column(String(255))
    all_headers: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assessment: Mapped["WebAssessment"] = relationship(back_populates="headers")
