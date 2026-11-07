"""
SQLAlchemy models — Community threat intelligence.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class ThreatCategory(str, enum.Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SCAM = "scam"
    FAKE_BRAND = "fake_brand"
    FAKE_RECRUITMENT = "fake_recruitment"
    FRAUDULENT_PAYMENT = "fraudulent_payment"
    IMPERSONATION = "impersonation"
    RANSOMWARE = "ransomware"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    OTHER = "other"


class VoteType(str, enum.Enum):
    SUPPORT = "support"
    DISPUTE = "dispute"


class CommunityReport(Base):
    __tablename__ = "community_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    reporter_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    category: Mapped[ThreatCategory] = mapped_column(Enum(ThreatCategory), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ReportStatus] = mapped_column(Enum(ReportStatus), default=ReportStatus.PENDING, index=True)
    # Vote tallies (denormalised for quick reads)
    support_count: Mapped[int] = mapped_column(Integer, default=0)
    dispute_count: Mapped[int] = mapped_column(Integer, default=0)
    # Analyst verification
    verified_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    # Duplicate detection
    duplicate_of_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("community_reports.id", ondelete="SET NULL"))
    # Campaign linkage
    campaign_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("threat_campaigns.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    reporter: Mapped["User"] = relationship(back_populates="reports", foreign_keys=[reporter_id])
    evidence: Mapped[list["ReportEvidence"]] = relationship(back_populates="report", cascade="all, delete-orphan")
    votes: Mapped[list["ReportVote"]] = relationship(back_populates="report", cascade="all, delete-orphan")
    moderation_logs: Mapped[list["ModerationLog"]] = relationship(back_populates="report", cascade="all, delete-orphan")
    campaign: Mapped["ThreatCampaign | None"] = relationship(back_populates="reports", foreign_keys=[campaign_id])
    duplicate_of: Mapped["CommunityReport | None"] = relationship(foreign_keys=[duplicate_of_id], remote_side="CommunityReport.id")


class ReportEvidence(Base):
    __tablename__ = "report_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(50))  # screenshot_url, text, email_header, etc.
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report: Mapped["CommunityReport"] = relationship(back_populates="evidence")


class ReportVote(Base):
    __tablename__ = "report_votes"
    __table_args__ = (UniqueConstraint("report_id", "voter_id", name="uq_vote_per_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    voter_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    vote_type: Mapped[VoteType] = mapped_column(Enum(VoteType), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report: Mapped["CommunityReport"] = relationship(back_populates="votes")


class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[ThreatCategory] = mapped_column(Enum(ThreatCategory))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    reports: Mapped[list["CommunityReport"]] = relationship(back_populates="campaign", foreign_keys="CommunityReport.campaign_id")
    indicators: Mapped[list["CampaignIndicator"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")


class CampaignIndicator(Base):
    __tablename__ = "campaign_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(50))  # domain, ip, email, hash
    value: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    campaign: Mapped["ThreatCampaign"] = relationship(back_populates="indicators")


class ModerationLog(Base):
    __tablename__ = "moderation_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    moderator_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # approved, rejected, escalated, etc.
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report: Mapped["CommunityReport"] = relationship(back_populates="moderation_logs")


# Resolve forward references
from app.models.user import User  # noqa: E402, F401
