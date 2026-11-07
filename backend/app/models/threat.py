"""
SQLAlchemy models — Threat analysis.
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


class ThreatCategory(str, enum.Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SCAM = "scam"
    RANSOMWARE = "ransomware"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    FAKE_BRAND = "fake_brand"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class ThreatSource(str, enum.Enum):
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    VIRUSTOTAL = "virustotal"
    PHISHTANK = "phishtank"
    URLHAUS = "urlhaus"
    INTERNAL_HEURISTIC = "internal_heuristic"
    COMMUNITY = "community"
    MANUAL = "manual"


class ThreatIndicator(Base):
    """Known threat indicators — domains, IPs, URL patterns."""
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # domain, ip, url, pattern
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    category: Mapped[ThreatCategory] = mapped_column(Enum(ThreatCategory), nullable=False, index=True)
    source: Mapped[ThreatSource] = mapped_column(Enum(ThreatSource), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)  # 0.0–1.0
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_data: Mapped[dict | None] = mapped_column(JSON)


class URLFeatures(Base):
    """Extracted heuristic features from a URL."""
    __tablename__ = "url_features"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    url_length: Mapped[int] = mapped_column(Integer, default=0)
    subdomain_count: Mapped[int] = mapped_column(Integer, default=0)
    has_ip_address: Mapped[bool] = mapped_column(Boolean, default=False)
    has_at_symbol: Mapped[bool] = mapped_column(Boolean, default=False)
    has_double_slash_redirect: Mapped[bool] = mapped_column(Boolean, default=False)
    has_hyphen_in_domain: Mapped[bool] = mapped_column(Boolean, default=False)
    has_excessive_dots: Mapped[bool] = mapped_column(Boolean, default=False)
    uses_https: Mapped[bool] = mapped_column(Boolean, default=False)
    has_suspicious_tld: Mapped[bool] = mapped_column(Boolean, default=False)
    has_brand_in_subdomain: Mapped[bool] = mapped_column(Boolean, default=False)
    suspicious_keywords: Mapped[list | None] = mapped_column(JSON)
    lookalike_brand: Mapped[str | None] = mapped_column(String(100))
    entropy_score: Mapped[float | None] = mapped_column(Float)
    digit_ratio: Mapped[float | None] = mapped_column(Float)
    special_char_ratio: Mapped[float | None] = mapped_column(Float)
    heuristic_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatMatch(Base):
    """Records when a URL matched a known threat indicator."""
    __tablename__ = "threat_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("threat_indicators.id", ondelete="SET NULL"))
    source: Mapped[ThreatSource] = mapped_column(Enum(ThreatSource), nullable=False)
    match_type: Mapped[str] = mapped_column(String(50))  # exact, pattern, heuristic
    matched_value: Mapped[str | None] = mapped_column(Text)
    category: Mapped[ThreatCategory] = mapped_column(Enum(ThreatCategory))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    indicator: Mapped["ThreatIndicator | None"] = relationship()
