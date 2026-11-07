"""
Community report API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_analyst
from app.database.connection import get_db
from app.models.community import (
    CommunityReport, ReportEvidence, ReportVote, ReportStatus, VoteType, ThreatCategory,
)
from app.models.user import User
from app.schemas.schemas import (
    ReportCreateRequest, ReportVoteRequest, ReportListItem, ReportDetailResponse,
)

import tldextract

router = APIRouter(prefix="/reports", tags=["Community Intelligence"])


@router.post("", status_code=201)
def submit_report(
    body: ReportCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Validate category
    try:
        category = ThreatCategory(body.category)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid category. Valid options: {[c.value for c in ThreatCategory]}")

    # Extract domain (lightweight parse — no DNS resolution needed for report submission)
    from urllib.parse import urlparse
    try:
        parsed = urlparse(body.url if body.url.lower().startswith(("http://", "https://")) else f"https://{body.url}")
        if not parsed.hostname:
            raise ValueError("No hostname")
        domain = parsed.hostname.lower()
        normalized_url = body.url
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {exc}")

    # Duplicate detection — same domain + category + reporter
    existing = db.query(CommunityReport).filter(
        CommunityReport.domain == domain,
        CommunityReport.reporter_id == current_user.id,
        CommunityReport.status.in_([ReportStatus.PENDING, ReportStatus.VERIFIED]),
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"You already have an active report for this domain (ID: {existing.id}).")

    report = CommunityReport(
        reporter_id=current_user.id,
        url=normalized_url,
        domain=domain,
        category=category,
        title=body.title,
        description=body.description,
        status=ReportStatus.PENDING,
    )
    db.add(report)
    db.flush()

    if body.evidence:
        for ev in body.evidence:
            db.add(ReportEvidence(
                report_id=report.id,
                evidence_type=ev.get("type", "text"),
                content=ev.get("content", ""),
            ))

    # Update reporter reputation
    from app.models.user import UserReputation
    rep = db.query(UserReputation).filter(UserReputation.user_id == current_user.id).first()
    if rep:
        rep.total_reports += 1

    db.commit()
    return {"report_id": report.id, "status": "pending"}


@router.get("", response_model=list[ReportListItem])
def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, le=100),
    category: str = Query(None),
    status_filter: str = Query(None, alias="status"),
    db: Session = Depends(get_db),
):
    q = db.query(CommunityReport).order_by(CommunityReport.created_at.desc())
    if category:
        try:
            q = q.filter(CommunityReport.category == ThreatCategory(category))
        except ValueError:
            pass
    if status_filter:
        try:
            q = q.filter(CommunityReport.status == ReportStatus(status_filter))
        except ValueError:
            pass
    reports = q.offset(skip).limit(limit).all()
    return [
        ReportListItem(
            id=r.id,
            url=r.url,
            domain=r.domain,
            category=r.category.value,
            title=r.title,
            status=r.status.value,
            support_count=r.support_count,
            dispute_count=r.dispute_count,
            created_at=r.created_at,
        )
        for r in reports
    ]


@router.get("/{report_id}", response_model=ReportDetailResponse)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(CommunityReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return ReportDetailResponse(
        id=report.id,
        url=report.url,
        domain=report.domain,
        category=report.category.value,
        title=report.title,
        description=report.description,
        status=report.status.value,
        support_count=report.support_count,
        dispute_count=report.dispute_count,
        analyst_notes=report.analyst_notes,
        verified_at=report.verified_at,
        evidence=[{"type": e.evidence_type, "content": e.content} for e in report.evidence],
        created_at=report.created_at,
    )


@router.post("/{report_id}/vote", status_code=200)
def vote_on_report(
    report_id: int,
    body: ReportVoteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = db.get(CommunityReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    # Prevent voting on own report
    if report.reporter_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot vote on your own report.")

    existing_vote = db.query(ReportVote).filter(
        ReportVote.report_id == report_id,
        ReportVote.voter_id == current_user.id,
    ).first()

    if existing_vote:
        # Update existing vote
        old_type = existing_vote.vote_type
        if old_type == VoteType.SUPPORT:
            report.support_count = max(report.support_count - 1, 0)
        else:
            report.dispute_count = max(report.dispute_count - 1, 0)
        existing_vote.vote_type = VoteType(body.vote_type)
    else:
        db.add(ReportVote(
            report_id=report_id,
            voter_id=current_user.id,
            vote_type=VoteType(body.vote_type),
        ))

    if body.vote_type == "support":
        report.support_count += 1
    else:
        report.dispute_count += 1

    db.commit()
    return {"support": report.support_count, "dispute": report.dispute_count}


@router.patch("/{report_id}/verify", status_code=200)
def verify_report(
    report_id: int,
    action: str = Query(..., description="approve | reject | duplicate"),
    notes: str = Query(None),
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst),
):
    from datetime import datetime, timezone
    from app.models.community import ModerationLog

    report = db.get(CommunityReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    action_map = {
        "approve": ReportStatus.VERIFIED,
        "reject": ReportStatus.REJECTED,
        "duplicate": ReportStatus.DUPLICATE,
        "review": ReportStatus.UNDER_REVIEW,
    }
    if action not in action_map:
        raise HTTPException(status_code=400, detail=f"Invalid action. Options: {list(action_map.keys())}")

    report.status = action_map[action]
    if action == "approve":
        report.verified_by_id = analyst.id
        report.verified_at = datetime.now(timezone.utc)
    if notes:
        report.analyst_notes = notes

    db.add(ModerationLog(
        report_id=report.id,
        moderator_id=analyst.id,
        action=action,
        notes=notes,
    ))
    db.commit()
    return {"status": report.status.value}
