"""Initial demonstration data for populated platform views."""

from sqlalchemy.orm import Session

from app.models.community import (
    CampaignIndicator,
    CommunityReport,
    ReportEvidence,
    ReportStatus,
    ThreatCampaign,
    ThreatCategory,
)
from app.models.user import User


CAMPAIGNS = [
    {
        "name": "Operation Velvet Relay",
        "description": "Credential phishing campaign targeting cloud workspace sign-in flows.",
        "category": ThreatCategory.PHISHING,
        "indicators": [
            ("domain", "secure-workspace.example", "Login mimicry domain"),
            ("url", "https://secure-workspace.example/auth/verify", "Credential collection endpoint"),
            ("email", "security-alerts@example.net", "Campaign notification sender"),
        ],
    },
    {
        "name": "Invoice Shadow",
        "description": "Business email compromise cluster distributing fraudulent payment requests.",
        "category": ThreatCategory.FRAUDULENT_PAYMENT,
        "indicators": [
            ("domain", "invoice-review.example", "Payment redirection domain"),
            ("email", "accounts-payable@example.net", "Impersonation sender pattern"),
            ("pattern", "urgent invoice settlement required", "Observed message phrase"),
        ],
    },
    {
        "name": "Glass Runner",
        "description": "Malware delivery operation using archived executables and document lures.",
        "category": ThreatCategory.MALWARE,
        "indicators": [
            ("domain", "delivery-files.example", "Payload hosting domain"),
            ("hash", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Observed archive payload hash"),
            ("pattern", "quarterly-review-update.zip", "Recurring lure filename"),
        ],
    },
    {
        "name": "Recruitment Ghost",
        "description": "Employment impersonation campaign distributing fake interview and onboarding forms.",
        "category": ThreatCategory.FAKE_RECRUITMENT,
        "indicators": [
            ("domain", "careers-portal.example", "Recruitment impersonation domain"),
            ("email", "talent-team@example.net", "Impersonation recruiter address"),
            ("pattern", "verified onboarding fee", "Payment solicitation phrase"),
        ],
    },
]


def seed_threat_campaigns(db: Session) -> int:
    """Insert campaign seed records only when their names are absent."""
    inserted = 0
    for campaign_data in CAMPAIGNS:
        existing = db.query(ThreatCampaign).filter(ThreatCampaign.name == campaign_data["name"]).first()
        if existing:
            continue

        campaign = ThreatCampaign(
            name=campaign_data["name"],
            description=campaign_data["description"],
            category=campaign_data["category"],
            is_active=True,
        )
        db.add(campaign)
        db.flush()

        for indicator_type, value, notes in campaign_data["indicators"]:
            db.add(CampaignIndicator(
                campaign_id=campaign.id,
                indicator_type=indicator_type,
                value=value,
                notes=notes,
            ))
        inserted += 1

    if inserted:
        db.commit()
    return inserted


COMMUNITY_REPORTS = [
    {
        "url": "https://secure-workspace.example/auth/verify",
        "domain": "secure-workspace.example",
        "category": ThreatCategory.PHISHING,
        "title": "Microsoft 365 credential verification clone",
        "description": "The page closely imitates a workspace sign-in portal and immediately requests account verification. The form destination is external to the organization's domain.",
        "status": ReportStatus.VERIFIED,
        "support_count": 18,
        "dispute_count": 1,
        "campaign_name": "Operation Velvet Relay",
        "evidence": ("text", "Brand copy and form layout match a known workspace login template."),
    },
    {
        "url": "https://invoice-review.example/pay/48127",
        "domain": "invoice-review.example",
        "category": ThreatCategory.FRAUDULENT_PAYMENT,
        "title": "Urgent invoice payment redirection",
        "description": "Recipients report an invoice document directing them to update bank details through a newly registered payment portal.",
        "status": ReportStatus.UNDER_REVIEW,
        "support_count": 11,
        "dispute_count": 2,
        "campaign_name": "Invoice Shadow",
        "evidence": ("text", "Sender uses a display-name impersonation pattern and a recently registered domain."),
    },
    {
        "url": "https://delivery-files.example/quarterly-review-update.zip",
        "domain": "delivery-files.example",
        "category": ThreatCategory.MALWARE,
        "title": "Archive carrying unsolicited macro document",
        "description": "The archive is offered as a routine quarterly review attachment and prompts the recipient to enable document content.",
        "status": ReportStatus.VERIFIED,
        "support_count": 27,
        "dispute_count": 0,
        "campaign_name": "Glass Runner",
        "evidence": ("text", "ZIP filename and lure language recur across multiple unrelated reports."),
    },
    {
        "url": "https://careers-portal.example/application/onboarding",
        "domain": "careers-portal.example",
        "category": ThreatCategory.FAKE_RECRUITMENT,
        "title": "Fake recruitment onboarding fee request",
        "description": "An impersonated recruiter asks applicants to complete an onboarding form and pay a background-check fee through an external processor.",
        "status": ReportStatus.PENDING,
        "support_count": 9,
        "dispute_count": 3,
        "campaign_name": "Recruitment Ghost",
        "evidence": ("text", "Recruitment message requests payment before an interview or employment agreement."),
    },
    {
        "url": "https://account-recovery.example/confirm-device",
        "domain": "account-recovery.example",
        "category": ThreatCategory.CREDENTIAL_HARVESTING,
        "title": "Account recovery portal harvesting MFA codes",
        "description": "A recovery page requests both a password and a time-based authentication code after showing an account lockout warning.",
        "status": ReportStatus.VERIFIED,
        "support_count": 14,
        "dispute_count": 1,
        "campaign_name": None,
        "evidence": ("text", "Page requests an MFA code even though the normal recovery workflow does not require one."),
    },
]


def seed_community_reports(db: Session) -> int:
    """Insert representative community reports without duplicating existing URLs."""
    reporter = db.query(User).filter(User.role == "admin").first()
    if reporter is None:
        reporter = db.query(User).filter(User.email.like("%@%")).first()
    if reporter is None:
        return 0

    inserted = 0
    for report_data in COMMUNITY_REPORTS:
        existing = db.query(CommunityReport).filter(
            CommunityReport.url == report_data["url"],
            CommunityReport.category == report_data["category"],
        ).first()
        if existing:
            continue

        campaign = None
        if report_data["campaign_name"]:
            campaign = db.query(ThreatCampaign).filter(ThreatCampaign.name == report_data["campaign_name"]).first()

        report = CommunityReport(
            reporter_id=reporter.id,
            url=report_data["url"],
            domain=report_data["domain"],
            category=report_data["category"],
            title=report_data["title"],
            description=report_data["description"],
            status=report_data["status"],
            support_count=report_data["support_count"],
            dispute_count=report_data["dispute_count"],
            campaign_id=campaign.id if campaign else None,
        )
        db.add(report)
        db.flush()

        evidence_type, content = report_data["evidence"]
        db.add(ReportEvidence(
            report_id=report.id,
            evidence_type=evidence_type,
            content=content,
        ))
        inserted += 1

    if inserted:
        db.commit()
    return inserted
