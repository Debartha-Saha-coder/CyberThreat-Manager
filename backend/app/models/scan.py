"""
SQLAlchemy models — Website scanning core.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class RiskClassification(str, enum.Enum):
    LOW_RISK = "LOW_RISK"
    GUARDED = "GUARDED"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    registered_domain: Mapped[str | None] = mapped_column(String(255), index=True)
    tld: Mapped[str | None] = mapped_column(String(50))
    subdomain: Mapped[str | None] = mapped_column(String(255))
    is_ip_address: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_address: Mapped[str | None] = mapped_column(String(50))
    # Risk summary (updated after each scan)
    reputation_score: Mapped[float | None] = mapped_column(Float)
    total_scans: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    urls: Mapped[list["URL"]] = relationship(back_populates="domain", cascade="all, delete-orphan")


class URL(Base):
    __tablename__ = "urls"
    __table_args__ = (
        Index("ix_urls_normalized", "normalized_url"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int] = mapped_column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    raw_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(10))
    path: Mapped[str | None] = mapped_column(Text)
    query_string: Mapped[str | None] = mapped_column(Text)
    fragment: Mapped[str | None] = mapped_column(Text)
    url_length: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    domain: Mapped["Domain"] = relationship(back_populates="urls")
    scans: Mapped[list["Scan"]] = relationship(back_populates="url", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    url_id: Mapped[int] = mapped_column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    # Unified risk scoring
    overall_risk_score: Mapped[float | None] = mapped_column(Float)
    risk_classification: Mapped[RiskClassification | None] = mapped_column(Enum(RiskClassification))
    threat_score: Mapped[float | None] = mapped_column(Float)
    web_score: Mapped[float | None] = mapped_column(Float)
    certificate_score: Mapped[float | None] = mapped_column(Float)
    community_score: Mapped[float | None] = mapped_column(Float)
    # Engine availability flags
    threat_engine_ran: Mapped[bool] = mapped_column(Boolean, default=False)
    web_engine_ran: Mapped[bool] = mapped_column(Boolean, default=False)
    cert_engine_ran: Mapped[bool] = mapped_column(Boolean, default=False)
    community_engine_ran: Mapped[bool] = mapped_column(Boolean, default=False)
    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    url: Mapped["URL"] = relationship(back_populates="scans")
    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanResult(Base):
    """Stores the raw JSON result from each detection engine."""
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    engine_name: Mapped[str] = mapped_column(String(50), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    raw_result: Mapped[dict | None] = mapped_column(JSON)
    ran_successfully: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str | None] = mapped_column(Text)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["Scan"] = relationship(back_populates="scan_results")
