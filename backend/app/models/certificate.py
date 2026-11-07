"""
SQLAlchemy models — TLS/SSL certificate intelligence.
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


class CertificateStatus(str, enum.Enum):
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    SELF_SIGNED = "self_signed"
    UNTRUSTED_CHAIN = "untrusted_chain"
    WEAK_CRYPTO = "weak_crypto"
    ERROR = "error"
    UNKNOWN = "unknown"


class Certificate(Base):
    """Unique TLS certificate by fingerprint."""
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    sha256_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sha1_fingerprint: Mapped[str | None] = mapped_column(String(40), index=True)
    subject_cn: Mapped[str | None] = mapped_column(String(255))
    subject_org: Mapped[str | None] = mapped_column(String(255))
    issuer_cn: Mapped[str | None] = mapped_column(String(255))
    issuer_org: Mapped[str | None] = mapped_column(String(255))
    issuer_country: Mapped[str | None] = mapped_column(String(5))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    serial_number: Mapped[str | None] = mapped_column(String(100))
    signature_algorithm: Mapped[str | None] = mapped_column(String(100))
    key_algorithm: Mapped[str | None] = mapped_column(String(50))
    key_size: Mapped[int | None] = mapped_column(Integer)
    san_domains: Mapped[list | None] = mapped_column(JSON)  # Subject Alternative Names
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ev: Mapped[bool] = mapped_column(Boolean, default=False)  # Extended Validation
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    in_ct_log: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    raw_pem: Mapped[str | None] = mapped_column(Text)

    observations: Mapped[list["CertificateObservation"]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )


class CertificateObservation(Base):
    """Each time a certificate is seen on a domain during a scan."""
    __tablename__ = "certificate_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    certificate_id: Mapped[int] = mapped_column(Integer, ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_observed: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tls_version: Mapped[str | None] = mapped_column(String(20))
    cipher_suite: Mapped[str | None] = mapped_column(String(100))
    chain_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname_matches: Mapped[bool] = mapped_column(Boolean, default=False)
    is_expired: Mapped[bool] = mapped_column(Boolean, default=False)
    days_until_expiry: Mapped[int | None] = mapped_column(Integer)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    certificate: Mapped["Certificate"] = relationship(back_populates="observations")


class CertificateCheck(Base):
    """Per-scan certificate analysis results and findings."""
    __tablename__ = "certificate_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    certificate_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"))
    status: Mapped[CertificateStatus] = mapped_column(Enum(CertificateStatus), default=CertificateStatus.UNKNOWN)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    findings: Mapped[list | None] = mapped_column(JSON)  # List of finding dicts
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CTObservation(Base):
    """Certificate Transparency log observations (from crt.sh etc.)."""
    __tablename__ = "ct_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    common_name: Mapped[str | None] = mapped_column(String(255))
    issuer: Mapped[str | None] = mapped_column(String(255))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sha256_fingerprint: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(100), default="crt.sh")
    raw_entry: Mapped[dict | None] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
