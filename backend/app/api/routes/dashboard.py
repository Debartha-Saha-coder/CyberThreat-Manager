"""
Dashboard and intelligence API routes.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.database.connection import get_db
from app.models.scan import Scan, ScanStatus, RiskClassification, Domain
from app.models.community import CommunityReport, ThreatCampaign
from app.models.user import User
from app.schemas.schemas import DashboardStats, DomainReputationResponse, ScanListItem

router = APIRouter(tags=["Dashboard & Intelligence"])


@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    scans_today = db.query(func.count(Scan.id)).filter(Scan.created_at >= today_start).scalar() or 0
    threats_detected = (
        db.query(func.count(Scan.id))
        .filter(Scan.risk_classification.in_([
            RiskClassification.HIGH_RISK, RiskClassification.CRITICAL
        ]))
        .scalar() or 0
    )
    high_risk_domains = db.query(func.count(Domain.id)).filter(Domain.confirmed_malicious == True).scalar() or 0

    critical_count = db.query(func.count(Scan.id)).filter(Scan.risk_classification == RiskClassification.CRITICAL).scalar() or 0
    high_risk_count = db.query(func.count(Scan.id)).filter(Scan.risk_classification == RiskClassification.HIGH_RISK).scalar() or 0
    medium_risk_count = db.query(func.count(Scan.id)).filter(Scan.risk_classification == RiskClassification.MEDIUM_RISK).scalar() or 0
    low_risk_count = db.query(func.count(Scan.id)).filter(
        Scan.risk_classification.in_([RiskClassification.LOW_RISK, RiskClassification.GUARDED])
    ).scalar() or 0

    recent_scans_raw = (
        db.query(Scan)
        .filter(Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED]))
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    recent_scans = [
        ScanListItem(
            id=s.id,
            url=s.url.normalized_url if s.url else "",
            status=s.status.value,
            overall_risk_score=s.overall_risk_score,
            risk_classification=s.risk_classification.value if s.risk_classification else None,
            created_at=s.created_at,
            completed_at=s.completed_at,
        )
        for s in recent_scans_raw
    ]

    risk_distribution = [
        {"classification": "CRITICAL", "count": critical_count},
        {"classification": "HIGH_RISK", "count": high_risk_count},
        {"classification": "MEDIUM_RISK", "count": medium_risk_count},
        {"classification": "GUARDED/LOW", "count": low_risk_count},
    ]

    return DashboardStats(
        total_scans=total_scans,
        scans_today=scans_today,
        threats_detected=threats_detected,
        high_risk_domains=high_risk_domains,
        critical_count=critical_count,
        high_risk_count=high_risk_count,
        medium_risk_count=medium_risk_count,
        low_risk_count=low_risk_count,
        recent_scans=recent_scans,
        risk_distribution=risk_distribution,
    )


@router.get("/domains/{domain}/reputation", response_model=DomainReputationResponse)
def get_domain_reputation(domain: str, db: Session = Depends(get_db)):
    domain_record = db.query(Domain).filter(Domain.domain == domain).first()
    if not domain_record:
        raise HTTPException(status_code=404, detail="Domain not found.")
    return DomainReputationResponse(
        domain=domain_record.domain,
        reputation_score=domain_record.reputation_score,
        total_scans=domain_record.total_scans,
        confirmed_malicious=domain_record.confirmed_malicious,
        first_seen=domain_record.first_seen,
        last_seen=domain_record.last_seen,
    )


@router.get("/intelligence/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(ThreatCampaign).filter(ThreatCampaign.is_active == True).order_by(ThreatCampaign.created_at.desc()).limit(50).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "category": c.category.value if c.category else None,
            "report_count": len(c.reports),
            "indicator_count": len(c.indicators),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in campaigns
    ]


@router.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "username": u.username,
            "role": u.role.value,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]
