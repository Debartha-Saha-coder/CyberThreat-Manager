"""
Web Security Assessment Engine.

Performs passive HTTP security checks — no exploit attempts, no form submissions,
no intrusive actions. Checks headers, redirect behaviour, HTTPS enforcement, cookies.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import get_settings
from app.services.url_validator import URLValidationResult

logger = logging.getLogger(__name__)
settings = get_settings()


# ------------------------------------------------------------------ #
# Data structures
# ------------------------------------------------------------------ #
@dataclass
class SecurityFindingData:
    title: str
    description: str
    severity: str  # critical | high | medium | low | info
    evidence: str
    recommendation: str
    category: str


@dataclass
class WebAssessmentResult:
    url: str
    final_url: str
    http_status: Optional[int]
    enforces_https: bool
    redirect_count: int
    redirect_chain: list[str]
    has_mixed_content: bool
    findings: list[SecurityFindingData]
    headers_snapshot: dict
    risk_score: float
    server_header: Optional[str]
    powered_by: Optional[str]
    error_message: Optional[str]
    execution_time_ms: int

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "enforces_https": self.enforces_https,
            "redirect_count": self.redirect_count,
            "redirect_chain": self.redirect_chain,
            "has_mixed_content": self.has_mixed_content,
            "risk_score": self.risk_score,
            "server_header": self.server_header,
            "powered_by": self.powered_by,
            "error_message": self.error_message,
            "execution_time_ms": self.execution_time_ms,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "category": f.category,
                }
                for f in self.findings
            ],
            "headers": self.headers_snapshot,
        }


# ------------------------------------------------------------------ #
# Engine implementation
# ------------------------------------------------------------------ #
async def run_web_assessment(validated_url: URLValidationResult) -> WebAssessmentResult:
    start = time.monotonic()
    url = validated_url.normalized_url
    findings: list[SecurityFindingData] = []
    redirect_chain: list[str] = []
    headers_snapshot: dict = {}
    final_url = url
    http_status: Optional[int] = None
    error_message: Optional[str] = None

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=settings.max_redirects,
            timeout=settings.scan_timeout_seconds,
            verify=False,  # Certificate errors handled by cert engine
            headers={"User-Agent": "Hackmetrix-Scanner/1.0"},
            limits=httpx.Limits(max_connections=1),
        ) as client:
            response = await client.get(
                url,
                extensions={"max_read": settings.max_response_size_bytes},
            )

        http_status = response.status_code
        final_url = str(response.url)
        headers = dict(response.headers)
        headers_snapshot = {k.lower(): v for k, v in headers.items()}

        # Rebuild redirect chain
        for hist in response.history:
            redirect_chain.append(str(hist.url))
        redirect_chain.append(final_url)

        # --- HTTPS enforcement ---
        enforces_https = _check_https_enforcement(url, response, redirect_chain, findings)

        # --- Security headers ---
        _check_security_headers(headers_snapshot, findings)

        # --- Cookie security ---
        _check_cookies(response, findings)

        # --- Redirect safety ---
        _check_redirects(url, redirect_chain, findings)

        # --- Information leakage ---
        server_header = headers_snapshot.get("server")
        powered_by = headers_snapshot.get("x-powered-by")
        _check_information_disclosure(server_header, powered_by, findings)

        # Mixed content check (basic — from meta tags / inline HTML is not fetched)
        has_mixed_content = _detect_mixed_content_headers(headers_snapshot)

    except httpx.TooManyRedirects:
        error_message = f"Too many redirects (limit: {settings.max_redirects})."
        enforces_https = False
        server_header = None
        powered_by = None
        has_mixed_content = False
        findings.append(SecurityFindingData(
            title="Excessive Redirects",
            description="The server returned more redirects than the permitted limit.",
            severity="medium",
            evidence=f"Redirect limit exceeded: {settings.max_redirects}",
            recommendation="Investigate the redirect chain. Phishing sites sometimes redirect through multiple hops.",
            category="redirect",
        ))
    except httpx.ConnectError as exc:
        error_message = f"Connection failed: {exc}"
        enforces_https = False
        server_header = None
        powered_by = None
        has_mixed_content = False
    except httpx.TimeoutException:
        error_message = "Request timed out."
        enforces_https = False
        server_header = None
        powered_by = None
        has_mixed_content = False
    except Exception as exc:
        logger.exception("Unexpected error in web assessment for %s", url)
        error_message = f"Assessment error: {type(exc).__name__}: {exc}"
        enforces_https = False
        server_header = None
        powered_by = None
        has_mixed_content = False

    risk_score = _compute_web_risk_score(findings, enforces_https, has_mixed_content, http_status, error_message)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return WebAssessmentResult(
        url=url,
        final_url=final_url,
        http_status=http_status,
        enforces_https=enforces_https,
        redirect_count=max(len(redirect_chain) - 1, 0),
        redirect_chain=redirect_chain,
        has_mixed_content=has_mixed_content,
        findings=findings,
        headers_snapshot=headers_snapshot,
        risk_score=risk_score,
        server_header=server_header,
        powered_by=powered_by,
        error_message=error_message,
        execution_time_ms=elapsed_ms,
    )


# ------------------------------------------------------------------ #
# Individual security checks
# ------------------------------------------------------------------ #
def _check_https_enforcement(
    original_url: str,
    response: httpx.Response,
    redirect_chain: list[str],
    findings: list[SecurityFindingData],
) -> bool:
    final = str(response.url)
    started_https = original_url.startswith("https://")
    final_https = final.startswith("https://")

    if not final_https:
        findings.append(SecurityFindingData(
            title="HTTPS Not Enforced",
            description="The website does not use HTTPS. Data transmitted to this site is not encrypted.",
            severity="high",
            evidence=f"Final URL: {final}",
            recommendation="Deploy a valid TLS certificate and redirect all HTTP traffic to HTTPS.",
            category="https",
        ))
        return False

    if not started_https and final_https:
        # Redirects to HTTPS — acceptable but note it
        pass

    return True


def _check_security_headers(headers: dict, findings: list[SecurityFindingData]) -> None:
    """Check for presence and basic quality of security headers."""

    # HSTS
    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append(SecurityFindingData(
            title="Missing Strict-Transport-Security Header",
            description="HSTS is not set. Browsers will not enforce HTTPS connections.",
            severity="medium",
            evidence="Header 'Strict-Transport-Security' is absent.",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            category="header",
        ))
    else:
        if "max-age=0" in hsts.lower():
            findings.append(SecurityFindingData(
                title="HSTS max-age Is Zero",
                description="HSTS is configured with max-age=0, which disables HSTS protection.",
                severity="medium",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Set max-age to at least 31536000 (1 year).",
                category="header",
            ))

    # CSP
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(SecurityFindingData(
            title="Missing Content-Security-Policy Header",
            description="No CSP is defined. This increases exposure to XSS and data injection attacks.",
            severity="medium",
            evidence="Header 'Content-Security-Policy' is absent.",
            recommendation="Define a Content-Security-Policy appropriate for your application.",
            category="header",
        ))

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if not xcto:
        findings.append(SecurityFindingData(
            title="Missing X-Content-Type-Options Header",
            description="Without this header, browsers may MIME-sniff content, enabling attacks.",
            severity="low",
            evidence="Header 'X-Content-Type-Options' is absent.",
            recommendation="Add: X-Content-Type-Options: nosniff",
            category="header",
        ))

    # Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        findings.append(SecurityFindingData(
            title="Missing Referrer-Policy Header",
            description="No Referrer-Policy is set. This may leak sensitive URL data to third parties.",
            severity="low",
            evidence="Header 'Referrer-Policy' is absent.",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            category="header",
        ))

    # X-Frame-Options
    xfo = headers.get("x-frame-options")
    if not xfo:
        findings.append(SecurityFindingData(
            title="Missing X-Frame-Options Header",
            description="Without X-Frame-Options or frame-ancestors in CSP, the page may be embedded in an iframe (clickjacking).",
            severity="low",
            evidence="Header 'X-Frame-Options' is absent.",
            recommendation="Add: X-Frame-Options: DENY or SAMEORIGIN",
            category="header",
        ))


def _check_cookies(response: httpx.Response, findings: list[SecurityFindingData]) -> None:
    issues = []
    for cookie in response.cookies.jar:
        problems = []
        if not cookie.secure:
            problems.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            problems.append("missing HttpOnly flag")
        samesite = cookie.get_nonstandard_attr("SameSite", "")
        if not samesite:
            problems.append("missing SameSite attribute")
        if problems:
            issues.append(f"Cookie '{cookie.name}': {', '.join(problems)}")

    if issues:
        findings.append(SecurityFindingData(
            title="Insecure Cookie Configuration",
            description=f"{len(issues)} cookie(s) are missing important security attributes.",
            severity="medium",
            evidence="\n".join(issues[:5]),
            recommendation="Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all cookies.",
            category="cookie",
        ))


def _check_redirects(
    original_url: str,
    redirect_chain: list[str],
    findings: list[SecurityFindingData],
) -> None:
    if len(redirect_chain) > 3:
        findings.append(SecurityFindingData(
            title="Long Redirect Chain",
            description=f"The URL redirected {len(redirect_chain) - 1} time(s). Long chains are common in phishing.",
            severity="low",
            evidence=" → ".join(redirect_chain[:6]),
            recommendation="Investigate each redirect destination for legitimacy.",
            category="redirect",
        ))

    # Check for redirect to completely different domain
    if len(redirect_chain) >= 2:
        try:
            import tldextract
            orig_ext = tldextract.extract(original_url)
            final_ext = tldextract.extract(redirect_chain[-1])
            if orig_ext.registered_domain and final_ext.registered_domain:
                if orig_ext.registered_domain != final_ext.registered_domain:
                    findings.append(SecurityFindingData(
                        title="Cross-Domain Redirect",
                        description="The URL redirects to a different registered domain.",
                        severity="medium",
                        evidence=f"{original_url} → {redirect_chain[-1]}",
                        recommendation="Verify the redirect destination is the legitimate site.",
                        category="redirect",
                    ))
        except Exception:
            pass


def _check_information_disclosure(
    server: Optional[str],
    powered_by: Optional[str],
    findings: list[SecurityFindingData],
) -> None:
    if server:
        findings.append(SecurityFindingData(
            title="Server Banner Disclosure",
            description=f"The server reveals its software version: '{server}'",
            severity="info",
            evidence=f"Server: {server}",
            recommendation="Remove or obscure the Server header to reduce attack surface.",
            category="information_disclosure",
        ))
    if powered_by:
        findings.append(SecurityFindingData(
            title="Technology Stack Disclosure",
            description=f"X-Powered-By header reveals technology: '{powered_by}'",
            severity="info",
            evidence=f"X-Powered-By: {powered_by}",
            recommendation="Remove the X-Powered-By header.",
            category="information_disclosure",
        ))


def _detect_mixed_content_headers(headers: dict) -> bool:
    """
    Check for CSP upgrade-insecure-requests absence as a proxy for mixed content risk.
    Real mixed content detection requires full page parsing.
    """
    csp = headers.get("content-security-policy", "").lower()
    return "upgrade-insecure-requests" not in csp and not headers.get("strict-transport-security")


# ------------------------------------------------------------------ #
# Risk scoring
# ------------------------------------------------------------------ #
def _compute_web_risk_score(
    findings: list[SecurityFindingData],
    enforces_https: bool,
    has_mixed_content: bool,
    http_status: Optional[int],
    error_message: Optional[str],
) -> float:
    """
    Compute a 0–100 risk score from web assessment findings.
    Missing security headers are contributing signals but not treated as proof of phishing.
    """
    score = 0.0

    severity_weights = {
        "critical": 30.0,
        "high": 20.0,
        "medium": 10.0,
        "low": 5.0,
        "info": 0.0,
    }

    for finding in findings:
        score += severity_weights.get(finding.severity, 0.0)

    if has_mixed_content:
        score += 10.0

    if error_message:
        score += 15.0

    return min(score, 100.0)
