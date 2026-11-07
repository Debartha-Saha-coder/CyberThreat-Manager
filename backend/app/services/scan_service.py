"""
Scan orchestration service.
Coordinates all four detection engines for a given URL scan.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.services.url_validator import validate_and_normalize, extract_url_features
from app.engines.threat_engine import run_threat_engine
from app.engines.web_assessment import run_web_assessment
from app.engines.certificate_engine import run_certificate_engine
from app.engines.community_engine import run_community_engine
from app.engines.scoring_engine import compute_risk_score, ScoringInput
from app.models.scan import Scan, ScanResult, ScanStatus, Domain, URL, RiskClassification
from app.models.threat import URLFeatures, ThreatMatch, ThreatSource, ThreatCategory
from app.models.web_security import WebAssessment, SecurityFinding, HTTPHeaders, FindingSeverity
from app.models.certificate import Certificate, CertificateObservation, CertificateCheck, CertificateStatus

import tldextract

logger = logging.getLogger(__name__)
settings = get_settings()


# ------------------------------------------------------------------ #
# Main orchestrator
# ------------------------------------------------------------------ #
async def execute_scan(scan_id: int, db: Session) -> Scan:
    """
    Execute a full scan for a given scan_id.
    The scan record must already exist in the database.
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found.")

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    db.commit()

    try:
        url_record = scan.url
        raw_url = url_record.normalized_url

        # 1. Validate and extract features
        validated = validate_and_normalize(raw_url)
        if not validated.is_valid:
            scan.status = ScanStatus.FAILED
            scan.error_message = validated.error
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return scan

        features = extract_url_features(validated)

        # 2. Run engines concurrently (except community which uses the DB synchronously)
        threat_task = asyncio.create_task(run_threat_engine(validated, features))
        web_task = asyncio.create_task(run_web_assessment(validated))
        cert_task = asyncio.create_task(run_certificate_engine(validated.hostname))

        # Community engine is synchronous (DB access)
        community_result = await asyncio.get_event_loop().run_in_executor(
            None, run_community_engine, validated.hostname, db
        )

        # Await async tasks
        threat_result, web_result, cert_result = await asyncio.gather(
            threat_task, web_task, cert_task, return_exceptions=True
        )

        # 3. Persist engine results
        threat_score = _save_threat_result(scan, features, threat_result, db)
        web_score = _save_web_result(scan, web_result, db)
        cert_score = _save_cert_result(scan, cert_result, validated.hostname, db)
        community_score = community_result.community_score

        # Mark which engines ran
        scan.threat_engine_ran = not isinstance(threat_result, Exception)
        scan.web_engine_ran = not isinstance(web_result, Exception)
        scan.cert_engine_ran = not isinstance(cert_result, Exception)
        scan.community_engine_ran = True

        # 4. Compute unified score
        scoring_input = ScoringInput(
            threat_score=threat_score,
            web_score=web_score,
            certificate_score=cert_score,
            community_score=community_score,
            threat_confirmed_malicious=(
                not isinstance(threat_result, Exception) and
                getattr(threat_result, "is_confirmed_malicious", False)
            ),
        )
        scoring_result = compute_risk_score(scoring_input)

        # 5. Update scan record
        scan.overall_risk_score = scoring_result.overall_score
        scan.risk_classification = RiskClassification(scoring_result.classification)
        scan.threat_score = threat_score
        scan.web_score = web_score
        scan.certificate_score = cert_score
        scan.community_score = community_score
        scan.status = ScanStatus.PARTIAL if scoring_result.is_incomplete else ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)

        # Update domain reputation
        domain = scan.url.domain
        domain.total_scans += 1
        if scoring_result.overall_score >= 80:
            domain.confirmed_malicious = True
        domain.reputation_score = scoring_result.overall_score

        # Update URL last_scanned
        scan.url.last_scanned = datetime.now(timezone.utc)

        db.commit()
        logger.info("Scan %d completed: score=%.1f classification=%s", scan_id, scoring_result.overall_score, scoring_result.classification)

    except Exception as exc:
        logger.exception("Scan %d failed with unexpected error", scan_id)
        scan.status = ScanStatus.FAILED
        scan.error_message = f"{type(exc).__name__}: {exc}"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

    return scan


# ------------------------------------------------------------------ #
# Domain and URL resolution
# ------------------------------------------------------------------ #
def get_or_create_domain(hostname: str, db: Session) -> Domain:
    domain = db.query(Domain).filter(Domain.domain == hostname).first()
    if domain:
        return domain
    extracted = tldextract.extract(hostname)
    domain = Domain(
        domain=hostname,
        registered_domain=extracted.registered_domain or hostname,
        tld=extracted.suffix,
        subdomain=extracted.subdomain or None,
        is_ip_address=False,
    )
    db.add(domain)
    db.flush()
    return domain


def get_or_create_url(normalized_url: str, domain: Domain, validated, db: Session) -> URL:
    url_record = db.query(URL).filter(URL.normalized_url == normalized_url).first()
    if url_record:
        return url_record
    url_record = URL(
        domain_id=domain.id,
        raw_url=normalized_url,
        normalized_url=normalized_url,
        scheme=validated.scheme,
        path=validated.path,
        query_string=validated.query,
        url_length=len(normalized_url),
    )
    db.add(url_record)
    db.flush()
    return url_record


def create_scan_record(url_record: URL, user_id: Optional[int], db: Session) -> Scan:
    scan = Scan(
        url_id=url_record.id,
        requested_by_id=user_id,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.flush()
    return scan


# ------------------------------------------------------------------ #
# Engine result persistence helpers
# ------------------------------------------------------------------ #
def _save_threat_result(scan: Scan, features, result, db: Session) -> Optional[float]:
    if isinstance(result, Exception):
        logger.error("Threat engine exception for scan %d: %s", scan.id, result)
        db.add(ScanResult(
            scan_id=scan.id,
            engine_name="threat",
            ran_successfully=False,
            error_message=str(result),
        ))
        db.flush()
        return None

    # Save URL features
    url_feats = URLFeatures(
        scan_id=scan.id,
        url_length=features.url_length,
        subdomain_count=features.subdomain_count,
        has_ip_address=features.has_ip_address,
        has_at_symbol=features.has_at_symbol,
        has_double_slash_redirect=features.has_double_slash_redirect,
        has_hyphen_in_domain=features.has_hyphen_in_domain,
        has_excessive_dots=features.has_excessive_dots,
        uses_https=features.uses_https,
        has_suspicious_tld=features.has_suspicious_tld,
        has_brand_in_subdomain=features.has_brand_in_subdomain,
        suspicious_keywords=features.suspicious_keywords,
        lookalike_brand=features.lookalike_brand,
        entropy_score=features.entropy_score,
        digit_ratio=features.digit_ratio,
        special_char_ratio=features.special_char_ratio,
        heuristic_score=features.heuristic_score,
    )
    db.add(url_feats)

    # Save threat matches
    for match in result.matches:
        db.add(ThreatMatch(
            scan_id=scan.id,
            source=ThreatSource(match["source"].lower().replace(" ", "_")) if match["source"].lower().replace(" ", "_") in ThreatSource.__members__.values() else ThreatSource.INTERNAL_HEURISTIC,
            match_type="confirmed" if match.get("is_confirmed") else "heuristic",
            matched_value=result.url,
            category=ThreatCategory.PHISHING,
            confidence=match.get("confidence", 0.5),
            is_confirmed=match.get("is_confirmed", False),
            description=f"Detected by {match['source']}",
        ))

    # Save raw engine result
    db.add(ScanResult(
        scan_id=scan.id,
        engine_name="threat",
        score=result.combined_score,
        raw_result=result.to_dict(),
        ran_successfully=True,
        execution_time_ms=result.execution_time_ms,
    ))
    db.flush()
    return result.combined_score


def _save_web_result(scan: Scan, result, db: Session) -> Optional[float]:
    if isinstance(result, Exception):
        logger.error("Web engine exception for scan %d: %s", scan.id, result)
        db.add(ScanResult(
            scan_id=scan.id,
            engine_name="web",
            ran_successfully=False,
            error_message=str(result),
        ))
        db.flush()
        return None

    assessment = WebAssessment(
        scan_id=scan.id,
        final_url=result.final_url,
        http_status_code=result.http_status,
        enforces_https=result.enforces_https,
        redirect_count=result.redirect_count,
        redirect_chain=result.redirect_chain,
        has_mixed_content=result.has_mixed_content,
        has_csp=bool(result.headers_snapshot.get("content-security-policy")),
        has_hsts=bool(result.headers_snapshot.get("strict-transport-security")),
        has_x_content_type=bool(result.headers_snapshot.get("x-content-type-options")),
        has_referrer_policy=bool(result.headers_snapshot.get("referrer-policy")),
        has_x_frame_options=bool(result.headers_snapshot.get("x-frame-options")),
        has_permissions_policy=bool(result.headers_snapshot.get("permissions-policy")),
        risk_score=result.risk_score,
        server_header=result.server_header,
        powered_by=result.powered_by,
        error_message=result.error_message,
    )
    db.add(assessment)
    db.flush()

    # Security findings
    sev_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO,
    }
    for f in result.findings:
        db.add(SecurityFinding(
            assessment_id=assessment.id,
            title=f.title,
            description=f.description,
            severity=sev_map.get(f.severity, FindingSeverity.INFO),
            evidence=f.evidence,
            recommendation=f.recommendation,
            category=f.category,
        ))

    # HTTP headers snapshot
    h = result.headers_snapshot
    db.add(HTTPHeaders(
        assessment_id=assessment.id,
        content_security_policy=h.get("content-security-policy"),
        strict_transport_security=h.get("strict-transport-security"),
        x_content_type_options=h.get("x-content-type-options"),
        x_frame_options=h.get("x-frame-options"),
        referrer_policy=h.get("referrer-policy"),
        permissions_policy=h.get("permissions-policy"),
        x_xss_protection=h.get("x-xss-protection"),
        server=h.get("server"),
        x_powered_by=h.get("x-powered-by"),
        all_headers=h,
    ))

    db.add(ScanResult(
        scan_id=scan.id,
        engine_name="web",
        score=result.risk_score,
        raw_result=result.to_dict(),
        ran_successfully=True,
        execution_time_ms=result.execution_time_ms,
    ))
    db.flush()
    return result.risk_score


def _save_cert_result(scan: Scan, result, hostname: str, db: Session) -> Optional[float]:
    if isinstance(result, Exception):
        logger.error("Certificate engine exception for scan %d: %s", scan.id, result)
        db.add(ScanResult(
            scan_id=scan.id,
            engine_name="certificate",
            ran_successfully=False,
            error_message=str(result),
        ))
        db.flush()
        return None

    cert_record = None
    if result.certificate:
        # Upsert certificate by fingerprint
        cert_record = db.query(Certificate).filter(
            Certificate.sha256_fingerprint == result.certificate.sha256_fingerprint
        ).first()
        if not cert_record:
            cert_record = Certificate(
                sha256_fingerprint=result.certificate.sha256_fingerprint,
                sha1_fingerprint=result.certificate.sha1_fingerprint,
                subject_cn=result.certificate.subject_cn,
                subject_org=result.certificate.subject_org,
                issuer_cn=result.certificate.issuer_cn,
                issuer_org=result.certificate.issuer_org,
                issuer_country=result.certificate.issuer_country,
                not_before=result.certificate.not_before,
                not_after=result.certificate.not_after,
                serial_number=result.certificate.serial_number,
                signature_algorithm=result.certificate.signature_algorithm,
                key_algorithm=result.certificate.key_algorithm,
                key_size=result.certificate.key_size,
                san_domains=result.certificate.san_domains,
                is_wildcard=result.certificate.is_wildcard,
                is_ev=result.certificate.is_ev,
                is_self_signed=result.certificate.is_self_signed,
                raw_pem=result.certificate.raw_pem,
            )
            db.add(cert_record)
            db.flush()

        # Certificate observation for this scan
        db.add(CertificateObservation(
            certificate_id=cert_record.id,
            scan_id=scan.id,
            domain_observed=hostname,
            tls_version=result.tls_version,
            cipher_suite=result.cipher_suite,
            chain_valid=result.chain_valid,
            hostname_matches=result.hostname_matches,
            is_expired=result.is_expired,
            days_until_expiry=result.certificate.days_until_expiry,
        ))

    # Certificate check record
    status_map = {
        "valid": CertificateStatus.VALID,
        "expired": CertificateStatus.EXPIRED,
        "self_signed": CertificateStatus.SELF_SIGNED,
        "untrusted_chain": CertificateStatus.UNTRUSTED_CHAIN,
        "hostname_mismatch": CertificateStatus.HOSTNAME_MISMATCH,
        "weak_crypto": CertificateStatus.WEAK_CRYPTO,
        "error": CertificateStatus.ERROR,
    }
    db.add(CertificateCheck(
        scan_id=scan.id,
        certificate_id=cert_record.id if cert_record else None,
        status=status_map.get(result.status, CertificateStatus.UNKNOWN),
        risk_score=result.risk_score,
        findings=[
            {"title": f.title, "severity": f.severity, "evidence": f.evidence}
            for f in result.findings
        ],
        error_message=result.error_message,
    ))

    db.add(ScanResult(
        scan_id=scan.id,
        engine_name="certificate",
        score=result.risk_score,
        raw_result=result.to_dict(),
        ran_successfully=True,
        execution_time_ms=result.execution_time_ms,
    ))
    db.flush()
    return result.risk_score
