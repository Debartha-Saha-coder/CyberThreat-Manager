"""
Threat Intelligence Engine — integrates heuristic analysis and external threat feeds.

Each external adapter independently queries its provider.
If a provider is not configured (no API key), it returns NOT_CONFIGURED.
If a provider request fails, it returns a graceful error result — the engine continues.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

from app.config import get_settings
from app.services.url_validator import URLValidationResult, URLFeatureSet

logger = logging.getLogger(__name__)
settings = get_settings()


# ------------------------------------------------------------------ #
# Data structures
# ------------------------------------------------------------------ #
class AdapterStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    NOT_CONFIGURED = "not_configured"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class AdapterResult:
    adapter_name: str
    status: AdapterStatus
    score: float = 0.0         # 0–100
    confidence: float = 0.0    # 0–1
    categories: list[str] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)
    error_message: Optional[str] = None
    is_confirmed: bool = False


@dataclass
class ThreatEngineResult:
    url: str
    heuristic_score: float
    adapter_results: list[AdapterResult] = field(default_factory=list)
    combined_score: float = 0.0
    is_confirmed_malicious: bool = False
    dominant_category: Optional[str] = None
    matches: list[dict] = field(default_factory=list)
    execution_time_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "heuristic_score": self.heuristic_score,
            "combined_score": self.combined_score,
            "is_confirmed_malicious": self.is_confirmed_malicious,
            "dominant_category": self.dominant_category,
            "matches": self.matches,
            "execution_time_ms": self.execution_time_ms,
            "adapters": [
                {
                    "name": r.adapter_name,
                    "status": r.status,
                    "score": r.score,
                    "confidence": r.confidence,
                    "categories": r.categories,
                    "error": r.error_message,
                    "is_confirmed": r.is_confirmed,
                }
                for r in self.adapter_results
            ],
        }


# ------------------------------------------------------------------ #
# Google Safe Browsing Adapter
# ------------------------------------------------------------------ #
async def _check_google_safe_browsing(url: str, client: httpx.AsyncClient) -> AdapterResult:
    if not settings.google_safe_browsing_configured:
        return AdapterResult(
            adapter_name="Google Safe Browsing",
            status=AdapterStatus.NOT_CONFIGURED,
            error_message="API key not configured.",
        )

    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "hackmetrix", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = await client.post(
            api_url,
            params={"key": settings.google_safe_browsing_api_key},
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            categories = list({m.get("threatType", "UNKNOWN") for m in matches})
            return AdapterResult(
                adapter_name="Google Safe Browsing",
                status=AdapterStatus.MALICIOUS,
                score=95.0,
                confidence=0.95,
                categories=categories,
                raw_response=data,
                is_confirmed=True,
            )
        return AdapterResult(
            adapter_name="Google Safe Browsing",
            status=AdapterStatus.CLEAN,
            score=0.0,
            confidence=0.9,
            raw_response=data,
        )
    except httpx.HTTPStatusError as exc:
        return AdapterResult(
            adapter_name="Google Safe Browsing",
            status=AdapterStatus.ERROR,
            error_message=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        )
    except Exception as exc:
        return AdapterResult(
            adapter_name="Google Safe Browsing",
            status=AdapterStatus.ERROR,
            error_message=str(exc),
        )


# ------------------------------------------------------------------ #
# VirusTotal Adapter
# ------------------------------------------------------------------ #
async def _check_virustotal(url: str, client: httpx.AsyncClient) -> AdapterResult:
    if not settings.virustotal_configured:
        return AdapterResult(
            adapter_name="VirusTotal",
            status=AdapterStatus.NOT_CONFIGURED,
            error_message="API key not configured.",
        )

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        resp = await client.get(
            api_url,
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            # URL not yet in VT database
            return AdapterResult(
                adapter_name="VirusTotal",
                status=AdapterStatus.UNKNOWN,
                score=0.0,
                error_message="URL not found in VirusTotal database.",
            )
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = ((malicious * 1.0 + suspicious * 0.5) / total) * 100
        is_confirmed = malicious >= 3

        categories_raw = data.get("data", {}).get("attributes", {}).get("categories", {})
        categories = list(set(categories_raw.values())) if categories_raw else []

        return AdapterResult(
            adapter_name="VirusTotal",
            status=AdapterStatus.MALICIOUS if malicious > 0 else (
                AdapterStatus.SUSPICIOUS if suspicious > 0 else AdapterStatus.CLEAN
            ),
            score=min(score, 100.0),
            confidence=min(malicious / max(total, 10), 1.0),
            categories=categories,
            raw_response={"stats": stats},
            is_confirmed=is_confirmed,
        )
    except httpx.HTTPStatusError as exc:
        return AdapterResult(
            adapter_name="VirusTotal",
            status=AdapterStatus.ERROR,
            error_message=f"HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        return AdapterResult(
            adapter_name="VirusTotal",
            status=AdapterStatus.ERROR,
            error_message=str(exc),
        )


# ------------------------------------------------------------------ #
# PhishTank Adapter
# ------------------------------------------------------------------ #
async def _check_phishtank(url: str, client: httpx.AsyncClient) -> AdapterResult:
    if not settings.phishtank_configured:
        return AdapterResult(
            adapter_name="PhishTank",
            status=AdapterStatus.NOT_CONFIGURED,
            error_message="API key not configured.",
        )

    try:
        resp = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": settings.phishtank_api_key},
            headers={"User-Agent": "hackmetrix/1.0"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        valid = results.get("valid", False)

        if in_database and valid:
            return AdapterResult(
                adapter_name="PhishTank",
                status=AdapterStatus.MALICIOUS,
                score=90.0,
                confidence=0.9,
                categories=["phishing"],
                raw_response=results,
                is_confirmed=True,
            )
        return AdapterResult(
            adapter_name="PhishTank",
            status=AdapterStatus.CLEAN,
            score=0.0,
            confidence=0.7,
            raw_response=results,
        )
    except Exception as exc:
        return AdapterResult(
            adapter_name="PhishTank",
            status=AdapterStatus.ERROR,
            error_message=str(exc),
        )


# ------------------------------------------------------------------ #
# URLhaus Adapter (public, no API key required)
# ------------------------------------------------------------------ #
async def _check_urlhaus(url: str, client: httpx.AsyncClient) -> AdapterResult:
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "is_blacklisted":
            tags = data.get("tags") or []
            return AdapterResult(
                adapter_name="URLhaus",
                status=AdapterStatus.MALICIOUS,
                score=85.0,
                confidence=0.85,
                categories=tags if tags else ["malware"],
                raw_response=data,
                is_confirmed=True,
            )
        return AdapterResult(
            adapter_name="URLhaus",
            status=AdapterStatus.CLEAN,
            score=0.0,
            confidence=0.7,
            raw_response={"query_status": query_status},
        )
    except Exception as exc:
        return AdapterResult(
            adapter_name="URLhaus",
            status=AdapterStatus.ERROR,
            error_message=str(exc),
        )


# ------------------------------------------------------------------ #
# Main Threat Engine
# ------------------------------------------------------------------ #
async def run_threat_engine(
    validated_url: URLValidationResult,
    features: URLFeatureSet,
) -> ThreatEngineResult:
    """
    Run all threat intelligence adapters and combine scores.
    A single adapter failure never crashes the entire engine.
    """
    start = time.monotonic()
    url = validated_url.normalized_url

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=15,
    ) as client:
        tasks = [
            _check_google_safe_browsing(url, client),
            _check_virustotal(url, client),
            _check_phishtank(url, client),
            _check_urlhaus(url, client),
        ]
        adapter_results: list[AdapterResult] = await asyncio.gather(*tasks, return_exceptions=False)

    # Build matches list
    matches = []
    for r in adapter_results:
        if r.status in (AdapterStatus.MALICIOUS, AdapterStatus.SUSPICIOUS):
            for cat in (r.categories or ["unknown"]):
                matches.append({
                    "source": r.adapter_name,
                    "category": cat,
                    "confidence": r.confidence,
                    "is_confirmed": r.is_confirmed,
                })

    # Determine confirmed malicious
    is_confirmed = any(r.is_confirmed for r in adapter_results)

    # Compute combined score:
    # Confirmed matches carry full weight; heuristic is a fallback.
    active_adapters = [r for r in adapter_results if r.status not in (AdapterStatus.NOT_CONFIGURED, AdapterStatus.ERROR, AdapterStatus.UNKNOWN)]

    if active_adapters:
        adapter_score = max((r.score for r in active_adapters), default=0.0)
        # If any confirmed match, boost to at least 80
        if is_confirmed:
            adapter_score = max(adapter_score, 80.0)
        combined = (adapter_score * 0.7) + (features.heuristic_score * 0.3)
    else:
        # All adapters unavailable — rely on heuristics alone
        combined = features.heuristic_score

    combined = min(combined, 100.0)

    # Determine dominant category
    cat_counts: dict[str, int] = {}
    for m in matches:
        cat_counts[m["category"]] = cat_counts.get(m["category"], 0) + 1
    dominant = max(cat_counts, key=lambda k: cat_counts[k]) if cat_counts else None

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return ThreatEngineResult(
        url=url,
        heuristic_score=features.heuristic_score,
        adapter_results=adapter_results,
        combined_score=combined,
        is_confirmed_malicious=is_confirmed,
        dominant_category=dominant,
        matches=matches,
        execution_time_ms=elapsed_ms,
    )
