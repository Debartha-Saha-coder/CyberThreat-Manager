"""
Models package — imports all models so SQLAlchemy registers them.
"""

from app.models.user import User, UserSession, UserReputation
from app.models.scan import Domain, URL, Scan, ScanResult, ScanStatus, RiskClassification
from app.models.threat import ThreatIndicator, URLFeatures, ThreatMatch, ThreatCategory, ThreatSource
from app.models.certificate import Certificate, CertificateObservation, CertificateCheck, CTObservation, CertificateStatus
from app.models.web_security import WebAssessment, SecurityFinding, HTTPHeaders, FindingSeverity
from app.models.community import (
    CommunityReport, ReportEvidence, ReportVote, ThreatCampaign,
    CampaignIndicator, ModerationLog, ReportStatus, VoteType,
)

__all__ = [
    "User", "UserSession", "UserReputation",
    "Domain", "URL", "Scan", "ScanResult", "ScanStatus", "RiskClassification",
    "ThreatIndicator", "URLFeatures", "ThreatMatch", "ThreatCategory", "ThreatSource",
    "Certificate", "CertificateObservation", "CertificateCheck", "CTObservation", "CertificateStatus",
    "WebAssessment", "SecurityFinding", "HTTPHeaders", "FindingSeverity",
    "CommunityReport", "ReportEvidence", "ReportVote", "ThreatCampaign",
    "CampaignIndicator", "ModerationLog", "ReportStatus", "VoteType",
]
