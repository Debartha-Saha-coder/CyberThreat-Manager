"""
Tests for certificate engine analysis helpers (pure functions — no network calls).
"""

import pytest
from datetime import datetime, timezone, timedelta
from app.engines.certificate_engine import (
    _check_hostname, _check_expiry, _check_key_strength,
    _check_signature_algorithm, CertificateData, CertFinding,
)


def make_cert(**kwargs) -> CertificateData:
    defaults = dict(
        subject_cn="example.com",
        subject_org=None,
        issuer_cn="Let's Encrypt",
        issuer_org=None,
        issuer_country="US",
        not_before=datetime.now(timezone.utc) - timedelta(days=30),
        not_after=datetime.now(timezone.utc) + timedelta(days=60),
        serial_number="12345",
        signature_algorithm="sha256",
        key_algorithm="RSA",
        key_size=2048,
        san_domains=["example.com", "www.example.com"],
        is_wildcard=False,
        is_ev=False,
        is_self_signed=False,
        sha256_fingerprint="abc123",
        sha1_fingerprint="def456",
        raw_pem=None,
        days_until_expiry=60,
    )
    defaults.update(kwargs)
    return CertificateData(**defaults)


class TestHostnameMatching:
    def test_exact_match(self):
        cert = make_cert(san_domains=["example.com"])
        assert _check_hostname("example.com", cert) is True

    def test_wildcard_match(self):
        cert = make_cert(san_domains=["*.example.com"])
        assert _check_hostname("www.example.com", cert) is True
        assert _check_hostname("sub.example.com", cert) is True

    def test_wildcard_does_not_match_parent(self):
        cert = make_cert(san_domains=["*.example.com"])
        assert _check_hostname("example.com", cert) is False

    def test_no_match(self):
        cert = make_cert(san_domains=["evil.com"])
        assert _check_hostname("example.com", cert) is False

    def test_case_insensitive(self):
        cert = make_cert(san_domains=["Example.COM"])
        assert _check_hostname("example.com", cert) is True


class TestExpiryChecks:
    def test_expired_certificate(self):
        findings: list[CertFinding] = []
        cert = make_cert(
            not_after=datetime.now(timezone.utc) - timedelta(days=5),
            days_until_expiry=-5,
        )
        is_expired = _check_expiry(cert, findings)
        assert is_expired is True
        assert any("Expired" in f.title for f in findings)
        assert findings[0].severity == "critical"

    def test_expiry_warning_14_days(self):
        findings: list[CertFinding] = []
        cert = make_cert(days_until_expiry=7)
        is_expired = _check_expiry(cert, findings)
        assert is_expired is False
        assert any("Expiring" in f.title for f in findings)
        assert findings[0].severity == "high"

    def test_expiry_30_day_warning(self):
        findings: list[CertFinding] = []
        cert = make_cert(days_until_expiry=20)
        _check_expiry(cert, findings)
        assert any("30" in f.title or "Expiring" in f.title for f in findings)

    def test_valid_certificate_no_findings(self):
        findings: list[CertFinding] = []
        cert = make_cert(days_until_expiry=180)
        _check_expiry(cert, findings)
        assert len(findings) == 0


class TestKeyStrength:
    def test_weak_rsa_key(self):
        findings: list[CertFinding] = []
        cert = make_cert(key_algorithm="RSA", key_size=1024)
        _check_key_strength(cert, findings)
        assert any("Weak" in f.title for f in findings)

    def test_strong_rsa_key_no_finding(self):
        findings: list[CertFinding] = []
        cert = make_cert(key_algorithm="RSA", key_size=2048)
        _check_key_strength(cert, findings)
        assert len(findings) == 0

    def test_dsa_key_flagged(self):
        findings: list[CertFinding] = []
        cert = make_cert(key_algorithm="DSA")
        _check_key_strength(cert, findings)
        assert any("DSA" in f.title for f in findings)


class TestSignatureAlgorithm:
    def test_md5_critical(self):
        findings: list[CertFinding] = []
        cert = make_cert(signature_algorithm="md5WithRSAEncryption")
        _check_signature_algorithm(cert, findings)
        assert findings[0].severity == "critical"

    def test_sha1_high(self):
        findings: list[CertFinding] = []
        cert = make_cert(signature_algorithm="sha1WithRSAEncryption")
        _check_signature_algorithm(cert, findings)
        assert findings[0].severity == "high"

    def test_sha256_clean(self):
        findings: list[CertFinding] = []
        cert = make_cert(signature_algorithm="sha256WithRSAEncryption")
        _check_signature_algorithm(cert, findings)
        assert len(findings) == 0
