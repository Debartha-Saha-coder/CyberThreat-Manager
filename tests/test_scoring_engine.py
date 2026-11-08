"""
Tests for the unified risk scoring engine.
"""

import pytest
from app.engines.scoring_engine import compute_risk_score, ScoringInput


class TestScoringEngine:
    def test_all_modules_available(self):
        inputs = ScoringInput(threat_score=80, web_score=40, certificate_score=20, community_score=10)
        result = compute_risk_score(inputs)
        # Expected = 80*0.35 + 40*0.20 + 20*0.25 + 10*0.20 = 28+8+5+2 = 43
        assert 40.0 < result.overall_score < 50.0
        assert result.classification == "MEDIUM_RISK"
        assert result.is_incomplete is False

    def test_missing_module_weight_redistribution(self):
        inputs = ScoringInput(threat_score=100, web_score=None, certificate_score=None, community_score=None)
        result = compute_risk_score(inputs)
        # Only threat module — 100% weight
        assert result.overall_score == pytest.approx(100.0)
        assert result.is_incomplete is True
        assert "web" in result.modules_unavailable

    def test_confirmed_malicious_floor(self):
        inputs = ScoringInput(
            threat_score=50, web_score=10, certificate_score=0, community_score=0,
            threat_confirmed_malicious=True,
        )
        result = compute_risk_score(inputs)
        assert result.overall_score >= 70.0

    def test_all_zero_scores(self):
        inputs = ScoringInput(threat_score=0, web_score=0, certificate_score=0, community_score=0)
        result = compute_risk_score(inputs)
        assert result.overall_score == 0.0
        assert result.classification == "LOW_RISK"

    def test_all_critical(self):
        inputs = ScoringInput(threat_score=100, web_score=100, certificate_score=100, community_score=100)
        result = compute_risk_score(inputs)
        assert result.overall_score == pytest.approx(100.0)
        assert result.classification == "CRITICAL"

    def test_no_modules_available(self):
        inputs = ScoringInput(threat_score=None, web_score=None, certificate_score=None, community_score=None)
        result = compute_risk_score(inputs)
        assert result.classification == "UNKNOWN"
        assert result.is_incomplete is True

    def test_classification_boundaries(self):
        for score, expected in [
            (0, "LOW_RISK"), (19, "LOW_RISK"),
            (20, "GUARDED"), (39, "GUARDED"),
            (40, "MEDIUM_RISK"), (59, "MEDIUM_RISK"),
            (60, "HIGH_RISK"), (79, "HIGH_RISK"),
            (80, "CRITICAL"), (100, "CRITICAL"),
        ]:
            inputs = ScoringInput(threat_score=float(score), web_score=None, certificate_score=None, community_score=None)
            result = compute_risk_score(inputs)
            assert result.classification == expected, f"score={score} → expected {expected}, got {result.classification}"

    def test_custom_weights(self):
        # All 4 modules have scores (0 is a valid score, not None = unavailable).
        # threat=100 with weight 0.10 out of total weight 1.0 → 100*0.10 = 10.0
        inputs = ScoringInput(threat_score=100, web_score=0, certificate_score=0, community_score=0)
        custom = {"threat": 0.10, "web": 0.30, "certificate": 0.30, "community": 0.30}
        result = compute_risk_score(inputs, weights=custom)
        assert result.overall_score == pytest.approx(10.0)

    def test_custom_weights_single_module(self):
        # With only threat available (others None), threat gets full weight → 100.0
        inputs = ScoringInput(threat_score=100, web_score=None, certificate_score=None, community_score=None)
        custom = {"threat": 0.10, "web": 0.30, "certificate": 0.30, "community": 0.30}
        result = compute_risk_score(inputs, weights=custom)
        assert result.overall_score == pytest.approx(100.0)
