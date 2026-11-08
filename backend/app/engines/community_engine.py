"""
Community Intelligence Engine.

Reads community reports from the database to compute a community risk score.
Does not modify data — that is handled by the community API routes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Data structures
# ------------------------------------------------------------------ #
@dataclass
class CommunityEngineResult:
    domain: str
    total_reports: int
    verified_reports: int
    pending_reports: int
    rejected_reports: int
    top_categories: list[str]
    support_votes: int
    dispute_votes: int
    community_score: float
    is_community_flagged: bool
    recent_reports: list[dict]
    execution_time_ms: int

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "total_reports": self.total_reports,
            "verified_reports": self.verified_reports,
            "pending_reports": self.pending_reports,
            "rejected_reports": self.rejected_reports,
            "top_categories": self.top_categories,
            "support_votes": self.support_votes,
            "dispute_votes": self.dispute_votes,
            "community_score": self.community_score,
            "is_community_flagged": self.is_community_flagged,
            "recent_reports": self.recent_reports,
            "execution_time_ms": self.execution_time_ms,
        }


# ------------------------------------------------------------------ #
# Engine
# ------------------------------------------------------------------ #
def run_community_engine(domain: str, db: Session) -> CommunityEngineResult:
    """
    Compute community intelligence score for a domain.
    Uses database reports synchronously (called inside an async context via run_in_executor).
    """
    start = time.monotonic()

    from app.models.community import CommunityReport, ReportStatus, ReportVote, VoteType

    reports = (
        db.query(CommunityReport)
        .filter(CommunityReport.domain == domain)
        .order_by(CommunityReport.created_at.desc())
        .limit(100)
        .all()
    )

    total = len(reports)
    verified = sum(1 for r in reports if r.status == ReportStatus.VERIFIED)
    pending = sum(1 for r in reports if r.status == ReportStatus.PENDING)
    rejected = sum(1 for r in reports if r.status == ReportStatus.REJECTED)
    support_votes = sum(r.support_count for r in reports)
    dispute_votes = sum(r.dispute_count for r in reports)

    # Category frequency
    cat_counts: dict[str, int] = {}
    for r in reports:
        if r.status != ReportStatus.REJECTED:
            c = r.category.value if hasattr(r.category, "value") else str(r.category)
            cat_counts[c] = cat_counts.get(c, 0) + 1
    top_categories = sorted(cat_counts, key=lambda k: cat_counts[k], reverse=True)[:3]

    # Score computation:
    # Verified reports heavily penalise the domain.
    # Unverified reports contribute lightly.
    # Disputes reduce the score.
    score = 0.0
    if total > 0:
        verified_score = min(verified * 25.0, 80.0)   # max 80 from verified
        pending_score = min(pending * 5.0, 20.0)       # max 20 from pending
        dispute_reduction = min(dispute_votes * 3.0, 20.0)
        score = max(verified_score + pending_score - dispute_reduction, 0.0)
        score = min(score, 100.0)

    is_flagged = verified >= 1 or (pending >= 3 and dispute_votes < pending)

    # Recent reports for display
    recent = []
    for r in reports[:5]:
        recent.append({
            "id": r.id,
            "title": r.title,
            "category": r.category.value if hasattr(r.category, "value") else str(r.category),
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "support_count": r.support_count,
            "dispute_count": r.dispute_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return CommunityEngineResult(
        domain=domain,
        total_reports=total,
        verified_reports=verified,
        pending_reports=pending,
        rejected_reports=rejected,
        top_categories=top_categories,
        support_votes=support_votes,
        dispute_votes=dispute_votes,
        community_score=score,
        is_community_flagged=is_flagged,
        recent_reports=recent,
        execution_time_ms=elapsed_ms,
    )
