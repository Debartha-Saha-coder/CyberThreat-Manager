"""
Tests for URL validation, SSRF protection, and feature extraction.
"""

import pytest
from app.services.url_validator import validate_and_normalize, extract_url_features


class TestURLValidation:
    def test_valid_https_url(self):
        r = validate_and_normalize("https://example.com")
        assert r.is_valid is True
        assert r.scheme == "https"
        assert r.hostname == "example.com"

    def test_http_scheme_injected(self):
        """Missing scheme should default to https://"""
        r = validate_and_normalize("google.com")
        assert r.is_valid is True
        assert r.scheme == "https"

    def test_localhost_blocked(self):
        r = validate_and_normalize("http://localhost/admin")
        assert r.is_valid is False

    def test_private_ip_blocked_10(self):
        r = validate_and_normalize("http://10.0.0.1/secret")
        assert r.is_valid is False

    def test_private_ip_blocked_192(self):
        r = validate_and_normalize("http://192.168.1.1/")
        assert r.is_valid is False

    def test_cloud_metadata_blocked(self):
        r = validate_and_normalize("http://169.254.169.254/latest/meta-data/")
        assert r.is_valid is False

    def test_ftp_scheme_rejected(self):
        r = validate_and_normalize("ftp://example.com/file")
        assert r.is_valid is False

    def test_empty_url_rejected(self):
        r = validate_and_normalize("")
        assert r.is_valid is False

    def test_url_too_long_rejected(self):
        r = validate_and_normalize("https://example.com/" + "a" * 2100)
        assert r.is_valid is False

    def test_normalized_url_lowercase(self):
        r = validate_and_normalize("HTTPS://Example.COM/Path")
        assert r.is_valid is True
        assert r.hostname == "example.com"

    def test_default_port_stripped(self):
        r = validate_and_normalize("https://example.com:443/path")
        assert r.is_valid is True
        assert ":443" not in r.normalized_url


class TestURLFeatureExtraction:
    def test_ip_address_detected(self):
        r = validate_and_normalize("http://93.184.216.34/")
        if r.is_valid:
            f = extract_url_features(r)
            assert f.has_ip_address is True

    def test_at_symbol_detected(self):
        r = validate_and_normalize("https://example.com@evil.com/")
        if r.is_valid:
            f = extract_url_features(r)
            assert f.has_at_symbol is True

    def test_suspicious_keywords_phishing(self):
        r = validate_and_normalize("https://secure-login-verify-paypal.com/signin")
        if r.is_valid:
            f = extract_url_features(r)
            assert len(f.suspicious_keywords) > 0

    def test_brand_in_subdomain(self):
        r = validate_and_normalize("https://paypal.evil.com/")
        if r.is_valid:
            f = extract_url_features(r)
            assert f.has_brand_in_subdomain is True
            assert f.lookalike_brand == "paypal"

    def test_heuristic_score_range(self):
        r = validate_and_normalize("https://example.com")
        if r.is_valid:
            f = extract_url_features(r)
            assert 0.0 <= f.heuristic_score <= 100.0

    def test_legitimate_url_low_score(self):
        r = validate_and_normalize("https://github.com/login")
        if r.is_valid:
            f = extract_url_features(r)
            # github.com should not trigger many signals
            assert f.heuristic_score < 40.0
