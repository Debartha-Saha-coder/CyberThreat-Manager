"""
URL validation and normalization utilities.
Includes SSRF protection — blocks private IPs, localhost, cloud metadata endpoints.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse, quote, unquote

import tldextract


# ------------------------------------------------------------------ #
# SSRF block-lists
# ------------------------------------------------------------------ #
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space
]

_METADATA_HOSTNAMES = {
    "169.254.169.254",  # AWS / Azure / GCP metadata
    "metadata.google.internal",
    "169.254.170.2",    # ECS task metadata
}

_ALLOWED_SCHEMES = {"http", "https"}

_MAX_URL_LENGTH = 2048


# ------------------------------------------------------------------ #
# Result dataclass
# ------------------------------------------------------------------ #
@dataclass
class URLValidationResult:
    is_valid: bool
    normalized_url: str = ""
    scheme: str = ""
    hostname: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    error: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    resolved_ip: Optional[str] = None


# ------------------------------------------------------------------ #
# Public API
# ------------------------------------------------------------------ #
def validate_and_normalize(raw_url: str) -> URLValidationResult:
    """
    Validate and normalise a user-submitted URL.
    Returns a URLValidationResult; is_valid=False means the URL must not be scanned.
    """
    if not raw_url or not raw_url.strip():
        return URLValidationResult(is_valid=False, error="URL is empty.")

    url = raw_url.strip()

    # Inject scheme if missing (case-insensitive check)
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    if len(url) > _MAX_URL_LENGTH:
        return URLValidationResult(is_valid=False, error=f"URL exceeds maximum allowed length of {_MAX_URL_LENGTH} characters.")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return URLValidationResult(is_valid=False, error=f"URL parse error: {exc}")

    # Scheme check
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return URLValidationResult(is_valid=False, error=f"Scheme '{parsed.scheme}' is not allowed. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return URLValidationResult(is_valid=False, error="URL has no hostname.")

    # SSRF — block cloud metadata hostnames
    if hostname in _METADATA_HOSTNAMES:
        return URLValidationResult(is_valid=False, error="Access to cloud metadata endpoints is not allowed.")

    # SSRF — resolve DNS and check resulting IP
    resolved_ip = _resolve_hostname(hostname)
    if resolved_ip is None:
        return URLValidationResult(is_valid=False, error=f"Could not resolve hostname '{hostname}'.")

    if _is_ssrf_ip(resolved_ip):
        return URLValidationResult(is_valid=False, error=f"Resolved IP {resolved_ip} is within a private/reserved address range.")

    # Normalise
    normalized = _normalize(parsed)

    return URLValidationResult(
        is_valid=True,
        normalized_url=normalized,
        scheme=parsed.scheme,
        hostname=hostname,
        path=parsed.path or "/",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        resolved_ip=resolved_ip,
    )


def _resolve_hostname(hostname: str) -> Optional[str]:
    try:
        # Check if it's already an IP
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        for result in results:
            return result[4][0]
        return None
    except (socket.gaierror, OSError):
        return None


def _is_ssrf_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
        for network in _PRIVATE_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def _normalize(parsed) -> str:
    """Produce a consistent, lowercase, normalised URL."""
    scheme = parsed.scheme.lower()
    netloc = (parsed.netloc or "").lower()
    # Remove default ports
    if scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


# ------------------------------------------------------------------ #
# URL feature extraction (for heuristic analysis)
# ------------------------------------------------------------------ #
_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "apple", "microsoft", "google",
    "amazon", "netflix", "wallet", "password", "credential",
    "suspended", "unlock", "alert", "notice",
]

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".download", ".zip", ".review", ".country",
    ".kim", ".science", ".party", ".gdn", ".stream",
}

_BRAND_NAMES = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "wellsfargo", "bankofamerica", "chase", "citibank", "hsbc",
    "barclays", "natwest", "lloyds", "santander", "halifax",
]


@dataclass
class URLFeatureSet:
    url_length: int = 0
    subdomain_count: int = 0
    has_ip_address: bool = False
    has_at_symbol: bool = False
    has_double_slash_redirect: bool = False
    has_hyphen_in_domain: bool = False
    has_excessive_dots: bool = False
    uses_https: bool = False
    has_suspicious_tld: bool = False
    has_brand_in_subdomain: bool = False
    suspicious_keywords: list[str] = field(default_factory=list)
    lookalike_brand: Optional[str] = None
    entropy_score: float = 0.0
    digit_ratio: float = 0.0
    special_char_ratio: float = 0.0
    heuristic_score: float = 0.0


def extract_url_features(validated: URLValidationResult) -> URLFeatureSet:
    """Extract heuristic features from a validated URL."""
    url = validated.normalized_url
    hostname = validated.hostname
    extracted = tldextract.extract(hostname)

    features = URLFeatureSet()
    features.url_length = len(url)
    features.uses_https = validated.scheme == "https"

    # IP address in host
    try:
        ipaddress.ip_address(hostname)
        features.has_ip_address = True
    except ValueError:
        pass

    # Subdomain depth
    if extracted.subdomain:
        features.subdomain_count = len(extracted.subdomain.split("."))

    # At symbol in URL
    features.has_at_symbol = "@" in url

    # Double-slash redirect trick
    features.has_double_slash_redirect = "//" in (validated.path or "")

    # Hyphen in registered domain
    features.has_hyphen_in_domain = "-" in (extracted.domain or "")

    # Excessive dots (more than 4 in full hostname)
    dot_count = hostname.count(".")
    features.has_excessive_dots = dot_count > 4

    # Suspicious TLD
    tld = f".{extracted.suffix}" if extracted.suffix else ""
    features.has_suspicious_tld = tld.lower() in _SUSPICIOUS_TLDS

    # Suspicious keywords in full URL
    url_lower = url.lower()
    features.suspicious_keywords = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in url_lower]

    # Brand name in subdomain (but not as the registered domain itself)
    if extracted.subdomain:
        sub_lower = extracted.subdomain.lower()
        for brand in _BRAND_NAMES:
            if brand in sub_lower and brand not in (extracted.domain or "").lower():
                features.has_brand_in_subdomain = True
                features.lookalike_brand = brand
                break

    # Lookalike domain (brand name in registered domain but not exact)
    if not features.lookalike_brand and extracted.domain:
        domain_lower = extracted.domain.lower()
        for brand in _BRAND_NAMES:
            if brand in domain_lower and brand != domain_lower:
                features.lookalike_brand = brand
                break

    # Entropy of hostname
    features.entropy_score = _shannon_entropy(hostname)

    # Digit ratio in hostname
    digits = sum(1 for c in hostname if c.isdigit())
    features.digit_ratio = digits / max(len(hostname), 1)

    # Special char ratio in full URL path+query
    path_query = (validated.path or "") + (validated.query or "")
    special = sum(1 for c in path_query if not c.isalnum() and c not in "/.-_")
    features.special_char_ratio = special / max(len(path_query), 1)

    # Compute heuristic score (0–100)
    features.heuristic_score = _compute_heuristic_score(features)

    return features


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _compute_heuristic_score(f: URLFeatureSet) -> float:
    score = 0.0
    if f.has_ip_address:
        score += 25.0
    if f.has_at_symbol:
        score += 20.0
    if f.has_brand_in_subdomain:
        score += 30.0
    elif f.lookalike_brand:
        score += 20.0
    if len(f.suspicious_keywords) >= 3:
        score += 20.0
    elif len(f.suspicious_keywords) >= 1:
        score += 10.0
    if f.has_suspicious_tld:
        score += 15.0
    if f.subdomain_count >= 3:
        score += 15.0
    elif f.subdomain_count >= 2:
        score += 5.0
    if f.url_length > 100:
        score += 10.0
    if f.has_excessive_dots:
        score += 10.0
    if f.has_hyphen_in_domain:
        score += 5.0
    if not f.uses_https:
        score += 10.0
    return min(score, 100.0)
