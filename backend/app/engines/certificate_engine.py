"""
TLS/SSL Certificate Intelligence Engine.

Analyses the TLS certificate of a target hostname.
Checks expiry, hostname matching, chain validity, key strength,
signature algorithms, and queries Certificate Transparency logs.

IMPORTANT: A valid certificate does NOT imply the site is legitimate.
Phishing sites routinely obtain valid DV certificates.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Data structures
# ------------------------------------------------------------------ #
@dataclass
class CertFinding:
    title: str
    description: str
    severity: str
    evidence: str
    recommendation: str


@dataclass
class CertificateData:
    subject_cn: Optional[str]
    subject_org: Optional[str]
    issuer_cn: Optional[str]
    issuer_org: Optional[str]
    issuer_country: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    serial_number: Optional[str]
    signature_algorithm: Optional[str]
    key_algorithm: Optional[str]
    key_size: Optional[int]
    san_domains: list[str]
    is_wildcard: bool
    is_ev: bool
    is_self_signed: bool
    sha256_fingerprint: str
    sha1_fingerprint: str
    raw_pem: Optional[str]
    days_until_expiry: Optional[int]


@dataclass
class CTEntry:
    common_name: str
    issuer: str
    not_before: Optional[str]
    not_after: Optional[str]
    id: int


@dataclass
class CertEngineResult:
    hostname: str
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    certificate: Optional[CertificateData]
    chain_valid: bool
    hostname_matches: bool
    is_expired: bool
    findings: list[CertFinding]
    ct_entries: list[CTEntry]
    risk_score: float
    status: str
    error_message: Optional[str]
    execution_time_ms: int

    def to_dict(self) -> dict:
        cert = self.certificate
        return {
            "hostname": self.hostname,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "chain_valid": self.chain_valid,
            "hostname_matches": self.hostname_matches,
            "is_expired": self.is_expired,
            "risk_score": self.risk_score,
            "status": self.status,
            "error_message": self.error_message,
            "execution_time_ms": self.execution_time_ms,
            "certificate": {
                "subject_cn": cert.subject_cn,
                "subject_org": cert.subject_org,
                "issuer_cn": cert.issuer_cn,
                "issuer_org": cert.issuer_org,
                "not_before": cert.not_before.isoformat() if cert.not_before else None,
                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                "days_until_expiry": cert.days_until_expiry,
                "serial_number": cert.serial_number,
                "signature_algorithm": cert.signature_algorithm,
                "key_algorithm": cert.key_algorithm,
                "key_size": cert.key_size,
                "san_domains": cert.san_domains,
                "is_wildcard": cert.is_wildcard,
                "is_ev": cert.is_ev,
                "is_self_signed": cert.is_self_signed,
                "sha256_fingerprint": cert.sha256_fingerprint,
                "sha1_fingerprint": cert.sha1_fingerprint,
            } if cert else None,
            "ct_entries_count": len(self.ct_entries),
            "ct_entries": [
                {
                    "common_name": e.common_name,
                    "issuer": e.issuer,
                    "not_before": e.not_before,
                    "not_after": e.not_after,
                }
                for e in self.ct_entries[:10]  # limit to 10 for response size
            ],
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }


# ------------------------------------------------------------------ #
# Main engine
# ------------------------------------------------------------------ #
async def run_certificate_engine(hostname: str, port: int = 443) -> CertEngineResult:
    start = time.monotonic()
    findings: list[CertFinding] = []

    # Fetch certificate using ssl module
    cert_data, tls_version, cipher_suite, chain_valid, error_message = await _fetch_certificate(hostname, port)

    hostname_matches = False
    is_expired = False
    status = "unknown"

    if cert_data:
        hostname_matches = _check_hostname(hostname, cert_data)
        is_expired = _check_expiry(cert_data, findings)
        _check_key_strength(cert_data, findings)
        _check_signature_algorithm(cert_data, findings)
        if cert_data.is_self_signed:
            findings.append(CertFinding(
                title="Self-Signed Certificate",
                description="The certificate is self-signed and not trusted by browsers.",
                severity="high",
                evidence=f"Issuer = Subject: {cert_data.issuer_cn}",
                recommendation="Replace with a certificate from a trusted Certificate Authority.",
            ))
        if not chain_valid:
            findings.append(CertFinding(
                title="Invalid Certificate Chain",
                description="The certificate chain could not be validated against trusted root CAs.",
                severity="critical",
                evidence="TLS handshake validation failed.",
                recommendation="Ensure intermediate certificates are installed and the chain is complete.",
            ))
        if not hostname_matches:
            findings.append(CertFinding(
                title="Certificate Hostname Mismatch",
                description=f"The certificate is not valid for hostname '{hostname}'.",
                severity="critical",
                evidence=f"SANs: {cert_data.san_domains}",
                recommendation="Obtain a certificate valid for this hostname.",
            ))
        status = _determine_status(cert_data, chain_valid, hostname_matches, findings)
    else:
        status = "error"
        findings.append(CertFinding(
            title="TLS Connection Failed",
            description="Could not establish a TLS connection to the target.",
            severity="high",
            evidence=error_message or "Unknown error",
            recommendation="Verify the server has TLS properly configured on the expected port.",
        ))

    # Fetch CT log entries from crt.sh
    ct_entries = await _fetch_ct_entries(hostname)

    risk_score = _compute_cert_risk_score(findings, cert_data, chain_valid, hostname_matches, is_expired)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return CertEngineResult(
        hostname=hostname,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        certificate=cert_data,
        chain_valid=chain_valid,
        hostname_matches=hostname_matches,
        is_expired=is_expired,
        findings=findings,
        ct_entries=ct_entries,
        risk_score=risk_score,
        status=status,
        error_message=error_message,
        execution_time_ms=elapsed_ms,
    )


# ------------------------------------------------------------------ #
# Certificate fetch
# ------------------------------------------------------------------ #
async def _fetch_certificate(
    hostname: str,
    port: int,
) -> tuple[Optional[CertificateData], Optional[str], Optional[str], bool, Optional[str]]:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, _fetch_cert_sync, hostname, port)
        return result
    except Exception as exc:
        logger.warning("Certificate fetch error for %s:%s — %s", hostname, port, exc)
        return None, None, None, False, str(exc)


def _fetch_cert_sync(
    hostname: str,
    port: int,
) -> tuple[Optional[CertificateData], Optional[str], Optional[str], bool, Optional[str]]:
    """Synchronous TLS connect + certificate extraction."""
    context = ssl.create_default_context()

    # First attempt with full chain validation
    chain_valid = True
    tls_version = None
    cipher_suite = None
    error_message = None

    try:
        with socket.create_connection((hostname, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                cipher_suite = f"{cipher_info[0]} ({cipher_info[1]})" if cipher_info else None
                der_cert = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        chain_valid = False
        error_message = str(exc)
        # Try again without verification to extract the cert anyway
        try:
            no_verify_ctx = ssl.create_default_context()
            no_verify_ctx.check_hostname = False
            no_verify_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=15) as sock:
                with no_verify_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_suite = f"{cipher_info[0]} ({cipher_info[1]})" if cipher_info else None
                    der_cert = ssock.getpeercert(binary_form=True)
        except Exception as inner:
            return None, None, None, False, f"SSL verification failed: {error_message}. Recovery failed: {inner}"
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return None, None, None, False, f"Connection error: {exc}"

    try:
        cert = x509.load_der_x509_certificate(der_cert)
        cert_data = _parse_certificate(cert)
    except Exception as exc:
        return None, tls_version, cipher_suite, chain_valid, f"Certificate parse error: {exc}"

    return cert_data, tls_version, cipher_suite, chain_valid, error_message


def _parse_certificate(cert: x509.Certificate) -> CertificateData:
    now = datetime.now(timezone.utc)

    # Subject
    subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
    subject_org = _get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)

    # Issuer
    issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_country = _get_name_attr(cert.issuer, NameOID.COUNTRY_NAME)

    # Validity
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_until_expiry = (not_after - now).days

    # SANs
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_domains = [dns.value for dns in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    # Key info
    pub_key = cert.public_key()
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algorithm = f"EC ({pub_key.curve.name})"
        key_size = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algorithm = "DSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_algorithm = type(pub_key).__name__.replace("PublicKey", "")
        key_size = None

    # Fingerprints
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex()
    sha1_fp = cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303 — display only

    # Self-signed check
    is_self_signed = cert.issuer == cert.subject

    # EV check (OID presence is not foolproof, but a reasonable heuristic)
    is_ev = False
    try:
        pol_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        ev_oids = {
            "2.23.140.1.1",  # EV TLS
            "2.23.140.1.3",  # EV Code Signing
        }
        for policy in pol_ext.value:
            if policy.policy_identifier.dotted_string in ev_oids:
                is_ev = True
                break
    except x509.ExtensionNotFound:
        pass

    is_wildcard = any(d.startswith("*.") for d in san_domains) or (subject_cn or "").startswith("*.")

    # PEM
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    return CertificateData(
        subject_cn=subject_cn,
        subject_org=subject_org,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        issuer_country=issuer_country,
        not_before=not_before,
        not_after=not_after,
        serial_number=str(cert.serial_number),
        signature_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        key_algorithm=key_algorithm,
        key_size=key_size,
        san_domains=san_domains,
        is_wildcard=is_wildcard,
        is_ev=is_ev,
        is_self_signed=is_self_signed,
        sha256_fingerprint=sha256_fp,
        sha1_fingerprint=sha1_fp,
        raw_pem=pem,
        days_until_expiry=days_until_expiry,
    )


def _get_name_attr(name: x509.Name, oid) -> Optional[str]:
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except IndexError:
        return None


# ------------------------------------------------------------------ #
# Individual cert checks
# ------------------------------------------------------------------ #
def _check_hostname(hostname: str, cert: CertificateData) -> bool:
    """Check if hostname matches any SAN or the subject CN."""
    hostname = hostname.lower()

    for san in cert.san_domains:
        san_lower = san.lower()
        if san_lower == hostname:
            return True
        if san_lower.startswith("*."):
            wildcard_base = san_lower[2:]
            # Only one level of wildcard
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]) == wildcard_base:
                return True

    # Fall back to CN if no SANs
    if not cert.san_domains and cert.subject_cn:
        cn = cert.subject_cn.lower()
        if cn == hostname:
            return True
        if cn.startswith("*."):
            wildcard_base = cn[2:]
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]) == wildcard_base:
                return True

    return False


def _check_expiry(cert: CertificateData, findings: list[CertFinding]) -> bool:
    if cert.days_until_expiry is None:
        return False
    if cert.days_until_expiry < 0:
        findings.append(CertFinding(
            title="Certificate Expired",
            description=f"The certificate expired {abs(cert.days_until_expiry)} day(s) ago.",
            severity="critical",
            evidence=f"Not After: {cert.not_after}",
            recommendation="Renew the certificate immediately.",
        ))
        return True
    if cert.days_until_expiry < 14:
        findings.append(CertFinding(
            title="Certificate Expiring Soon",
            description=f"The certificate will expire in {cert.days_until_expiry} day(s).",
            severity="high",
            evidence=f"Not After: {cert.not_after}",
            recommendation="Renew the certificate before it expires.",
        ))
    elif cert.days_until_expiry < 30:
        findings.append(CertFinding(
            title="Certificate Expiring Within 30 Days",
            description=f"The certificate will expire in {cert.days_until_expiry} day(s).",
            severity="medium",
            evidence=f"Not After: {cert.not_after}",
            recommendation="Plan certificate renewal soon.",
        ))
    return False


def _check_key_strength(cert: CertificateData, findings: list[CertFinding]) -> None:
    if cert.key_algorithm == "RSA" and cert.key_size and cert.key_size < 2048:
        findings.append(CertFinding(
            title="Weak RSA Key Size",
            description=f"RSA key size is {cert.key_size} bits, below the recommended 2048 bits.",
            severity="high",
            evidence=f"Key: RSA-{cert.key_size}",
            recommendation="Use RSA-2048 or higher, or switch to ECDSA P-256.",
        ))
    if cert.key_algorithm == "DSA":
        findings.append(CertFinding(
            title="DSA Key Detected",
            description="DSA keys are deprecated and should not be used for TLS.",
            severity="medium",
            evidence=f"Key algorithm: {cert.key_algorithm}",
            recommendation="Replace with RSA-2048+ or ECDSA P-256.",
        ))


def _check_signature_algorithm(cert: CertificateData, findings: list[CertFinding]) -> None:
    algo = (cert.signature_algorithm or "").lower()
    if "md5" in algo or "md2" in algo:
        findings.append(CertFinding(
            title="Critically Weak Signature Algorithm",
            description=f"Certificate uses {cert.signature_algorithm}, which is cryptographically broken.",
            severity="critical",
            evidence=f"Signature algorithm: {cert.signature_algorithm}",
            recommendation="Replace the certificate immediately with one using SHA-256 or stronger.",
        ))
    elif "sha1" in algo:
        findings.append(CertFinding(
            title="Deprecated SHA-1 Signature Algorithm",
            description="SHA-1 signatures are deprecated and not accepted by modern browsers.",
            severity="high",
            evidence=f"Signature algorithm: {cert.signature_algorithm}",
            recommendation="Replace with a SHA-256 signed certificate.",
        ))


def _determine_status(
    cert: CertificateData,
    chain_valid: bool,
    hostname_matches: bool,
    findings: list[CertFinding],
) -> str:
    if cert.days_until_expiry is not None and cert.days_until_expiry < 0:
        return "expired"
    if cert.is_self_signed:
        return "self_signed"
    if not chain_valid:
        return "untrusted_chain"
    if not hostname_matches:
        return "hostname_mismatch"
    weak = any(f.severity in ("critical", "high") for f in findings)
    if weak:
        return "weak_crypto"
    return "valid"


# ------------------------------------------------------------------ #
# Certificate Transparency (crt.sh)
# ------------------------------------------------------------------ #
async def _fetch_ct_entries(hostname: str) -> list[CTEntry]:
    """Query crt.sh for Certificate Transparency log entries."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": hostname, "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            entries = []
            seen_ids = set()
            for entry in data[:50]:  # cap at 50
                entry_id = entry.get("id")
                if entry_id in seen_ids:
                    continue
                seen_ids.add(entry_id)
                entries.append(CTEntry(
                    common_name=entry.get("common_name", ""),
                    issuer=entry.get("issuer_name", ""),
                    not_before=entry.get("not_before"),
                    not_after=entry.get("not_after"),
                    id=entry_id or 0,
                ))
            return entries
    except Exception as exc:
        logger.warning("CT log fetch error for %s: %s", hostname, exc)
        return []


# ------------------------------------------------------------------ #
# Risk scoring
# ------------------------------------------------------------------ #
def _compute_cert_risk_score(
    findings: list[CertFinding],
    cert: Optional[CertificateData],
    chain_valid: bool,
    hostname_matches: bool,
    is_expired: bool,
) -> float:
    score = 0.0

    severity_weights = {
        "critical": 35.0,
        "high": 20.0,
        "medium": 10.0,
        "low": 5.0,
        "info": 0.0,
    }

    for finding in findings:
        score += severity_weights.get(finding.severity, 0.0)

    if cert is None:
        score += 20.0  # Can't connect

    return min(score, 100.0)
