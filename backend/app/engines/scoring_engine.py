"""
Unified Risk Scoring Engine.

Combines individual engine scores using a configurable weighted formula:

  Risk Score =
    (Threat Score × 0.35) +
    (Web Score   × 0.20) +
    (Cert Score  × 0.25) +
    (Community   × 0.20)

If a module did not run or failed, its weight is redistributed proportionally
among the modules that did run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Configuration
# ------------------------------------------------------------------ #
DEFAULT_WEIGHTS = {
    "threat": 0.35,
    "web": 0.20,
    "certificate": 0.25,
    "community": 0.20,
}

RISK_THRESHOLDS = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH_RISK"),
    (40.0, "MEDIUM_RISK"),
    (20.0, "GUARDED"),
    (0.0,  "LOW_RISK"),
]


# ------------------------------------------------------------------ #
# Data structures
# ------------------------------------------------------------------ #
@dataclass
class ScoringInput:
    threat_score: Optional[float]
    web_score: Optional[float]
    certificate_score: Optional[float]
    community_score: Optional[float]
    # Confidence that confirmed-malicious match from threat engine
    threat_confirmed_malicious: bool = False


@dataclass
class ScoringResult:
    overall_score: float
    classification: str
    threat_score: Optional[float]
    web_score: Optional[float]
    certificate_score: Optional[float]
    community_score: Optional[float]
    applied_weights: dict[str, float]
    modules_used: list[str]
    modules_unavailable: list[str]
    is_incomplete: bool
    verdict_explanation: str

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 2),
            "classification": self.classification,
            "scores": {
                "threat": self.threat_score,
                "web": self.web_score,
                "certificate": self.certificate_score,
                "community": self.community_score,
            },
            "applied_weights": {k: round(v, 4) for k, v in self.applied_weights.items()},
            "modules_used": self.modules_used,
            "modules_unavailable": self.modules_unavailable,
            "is_incomplete": self.is_incomplete,
            "verdict_explanation": self.verdict_explanation,
        }


# ------------------------------------------------------------------ #
# Scoring engine
# ------------------------------------------------------------------ #
def compute_risk_score(
    inputs: ScoringInput,
    weights: Optional[dict[str, float]] = None,
) -> ScoringResult:
    """
    Compute unified risk score from individual engine outputs.

    Rules:
    - Only modules with a score are included (None = unavailable).
    - Weights are renormalized when modules are missing.
    - A confirmed-malicious threat match applies a minimum floor of 70.
    - Double-counting is avoided: each evidence source is consumed once.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}

    # Determine available modules
    module_data = {
        "threat": inputs.threat_score,
        "web": inputs.web_score,
        "certificate": inputs.certificate_score,
        "community": inputs.community_score,
    }

    available = {k: v for k, v in module_data.items() if v is not None}
    unavailable = [k for k, v in module_data.items() if v is None]

    if not available:
        return ScoringResult(
            overall_score=0.0,
            classification="UNKNOWN",
            threat_score=None,
            web_score=None,
            certificate_score=None,
            community_score=None,
            applied_weights={},
            modules_used=[],
            modules_unavailable=list(module_data.keys()),
            is_incomplete=True,
            verdict_explanation="No engines produced results. Assessment could not be completed.",
        )

    # Renormalize weights
    total_weight = sum(w[k] for k in available)
    normalized_weights = {k: w[k] / total_weight for k in available}

    # Weighted sum
    score = sum(available[k] * normalized_weights[k] for k in available)

    # Apply confirmed-malicious floor
    if inputs.threat_confirmed_malicious:
        score = max(score, 70.0)
        logger.info("Confirmed-malicious floor applied: score raised to %.1f", score)

    score = min(max(score, 0.0), 100.0)

    classification = _classify(score)
    explanation = _build_explanation(
        score, classification, available, normalized_weights,
        inputs.threat_confirmed_malicious, unavailable,
    )

    return ScoringResult(
        overall_score=round(score, 2),
        classification=classification,
        threat_score=inputs.threat_score,
        web_score=inputs.web_score,
        certificate_score=inputs.certificate_score,
        community_score=inputs.community_score,
        applied_weights=normalized_weights,
        modules_used=list(available.keys()),
        modules_unavailable=unavailable,
        is_incomplete=len(unavailable) > 0,
        verdict_explanation=explanation,
    )


def _classify(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW_RISK"


def _build_explanation(
    score: float,
    classification: str,
    available: dict[str, float],
    weights: dict[str, float],
    confirmed_malicious: bool,
    unavailable: list[str],
) -> str:
    parts = []

    if confirmed_malicious:
        parts.append("⚠ At least one threat intelligence provider confirmed this URL as malicious.")

    for module, mod_score in available.items():
        w = weights.get(module, 0)
        contribution = mod_score * w
        if mod_score >= 60:
            parts.append(f"{module.title()} engine scored {mod_score:.0f}/100 (high risk, contributing {contribution:.1f} points).")
        elif mod_score >= 30:
            parts.append(f"{module.title()} engine scored {mod_score:.0f}/100 (moderate risk, contributing {contribution:.1f} points).")

    if unavailable:
        parts.append(f"Note: The following engines were unavailable: {', '.join(unavailable)}. Weights were redistributed.")

    classification_text = {
        "CRITICAL": "CRITICAL risk — strong evidence of malicious activity.",
        "HIGH_RISK": "HIGH risk — significant threat indicators detected.",
        "MEDIUM_RISK": "MEDIUM risk — notable security concerns present.",
        "GUARDED": "GUARDED — minor concerns, investigate further.",
        "LOW_RISK": "LOW risk — no significant threats detected.",
        "UNKNOWN": "Assessment could not be completed.",
    }.get(classification, "")

    parts.insert(0, classification_text)
    return " ".join(parts)
