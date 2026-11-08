"""
Scan API routes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_optional_user
from app.database.connection import get_db
from app.models.scan import Scan, ScanStatus, RiskClassification
from app.models.user import User
from app.schemas.schemas import ScanCreateRequest, ScanDetailResponse, ScanListItem, ScanReportResponse
from app.services.scan_service import (
    execute_scan, get_or_create_domain, get_or_create_url, create_scan_record,
)
from app.services.url_validator import validate_and_normalize

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scanning"])


@router.post("", status_code=202)
async def submit_scan(
    body: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Submit a URL for scanning. Returns a scan ID immediately; processing is async."""
    validated = validate_and_normalize(body.url)
    if not validated.is_valid:
        raise HTTPException(status_code=400, detail=validated.error)

    from app.services.url_validator import extract_url_features
    features = extract_url_features(validated)

    domain = get_or_create_domain(validated.hostname, db)
    url_record = get_or_create_url(validated.normalized_url, domain, validated, db)
    scan = create_scan_record(url_record, current_user.id if current_user else None, db)
    db.commit()

    # Run scan in background
    scan_id = scan.id
    background_tasks.add_task(_run_scan_background, scan_id)

    return {"scan_id": scan_id, "status": "pending", "message": "Scan queued."}


async def _run_scan_background(scan_id: int) -> None:
    from app.database.connection import SessionLocal
    db = SessionLocal()
    try:
        await execute_scan(scan_id, db)
    except Exception as exc:
        logger.exception("Background scan %d failed: %s", scan_id, exc)
    finally:
        db.close()


@router.get("", response_model=list[ScanListItem])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
):
    scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [_scan_to_list_item(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _scan_to_detail(scan)


@router.get("/{scan_id}/report", response_model=ScanReportResponse)
def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if scan.status == ScanStatus.PENDING or scan.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=202, detail="Scan is still in progress.")

    # Collect engine results
    from app.models.scan import ScanResult
    results = {r.engine_name: r for r in scan.scan_results}

    def _result_dict(name: str) -> Optional[dict]:
        r = results.get(name)
        if r and r.raw_result:
            return r.raw_result
        return None

    return ScanReportResponse(
        scan=_scan_to_detail(scan),
        scoring={
            "overall_score": scan.overall_risk_score,
            "classification": scan.risk_classification.value if scan.risk_classification else None,
            "threat_score": scan.threat_score,
            "web_score": scan.web_score,
            "certificate_score": scan.certificate_score,
            "community_score": scan.community_score,
        },
        threat=_result_dict("threat"),
        web=_result_dict("web"),
        certificate=_result_dict("certificate"),
        community=_result_dict("community"),
    )


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #
def _scan_to_list_item(scan: Scan) -> ScanListItem:
    return ScanListItem(
        id=scan.id,
        url=scan.url.normalized_url if scan.url else "",
        status=scan.status.value,
        overall_risk_score=scan.overall_risk_score,
        risk_classification=scan.risk_classification.value if scan.risk_classification else None,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


def _scan_to_detail(scan: Scan) -> ScanDetailResponse:
    return ScanDetailResponse(
        id=scan.id,
        url=scan.url.raw_url if scan.url else "",
        normalized_url=scan.url.normalized_url if scan.url else "",
        domain=scan.url.domain.domain if scan.url and scan.url.domain else "",
        status=scan.status.value,
        overall_risk_score=scan.overall_risk_score,
        risk_classification=scan.risk_classification.value if scan.risk_classification else None,
        threat_score=scan.threat_score,
        web_score=scan.web_score,
        certificate_score=scan.certificate_score,
        community_score=scan.community_score,
        threat_engine_ran=scan.threat_engine_ran,
        web_engine_ran=scan.web_engine_ran,
        cert_engine_ran=scan.cert_engine_ran,
        community_engine_ran=scan.community_engine_ran,
        error_message=scan.error_message,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )
