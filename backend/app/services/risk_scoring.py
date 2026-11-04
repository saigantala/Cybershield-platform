from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class CalculatedRiskScores:
    cvss_score: float
    cvss_version: str
    official_severity: str
    is_kev: bool
    prioritization_score: float
    scoring_rationale: str


class RiskScoringEngine:
    """
    Centralized CyberShield Vulnerability Prioritization & Risk Engine.

    AUDITABLE PRIORITIZATION FORMULA:
    Range: 0.0 to 100.0
    1. Base CVSS Weight: cvss_score * 7.0 (max 70.0 points).
    2. Weaponization Context (CISA KEV): +25.0 points if actively exploited in the wild.
    3. Asset Criticality Boost: +5.0 points if asset risk level is 'Critical'.
    Final: min(100.0, round(base_cvss + kev_boost + asset_criticality, 1))

    All official metrics (CVSS, severity, KEV) remain immutable and distinct.
    """

    @staticmethod
    def get_official_severity(cvss_score: float) -> str:
        """Map CVSS v3.1 score to standardized official severity rating."""
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        if cvss_score >= 0.1:
            return "Low"
        return "Informational"

    @classmethod
    def calculate_scores(
        cls,
        cvss_score: float,
        is_kev: bool = False,
        asset_risk_level: Optional[str] = None,
        cvss_version: str = "3.1",
    ) -> CalculatedRiskScores:
        clamped_cvss = max(0.0, min(10.0, round(float(cvss_score or 0.0), 1)))
        severity = cls.get_official_severity(clamped_cvss)

        base_points = clamped_cvss * 7.0
        kev_boost = 25.0 if is_kev else 0.0
        asset_boost = 5.0 if (asset_risk_level or "").strip().lower() == "critical" else 0.0

        prioritization = min(100.0, round(base_points + kev_boost + asset_boost, 1))

        rationale = (
            f"Base CVSS {clamped_cvss} ({round(base_points, 1)} pts)"
            + (f" + CISA KEV Exploitation (+{kev_boost} pts)" if is_kev else "")
            + (f" + Critical Asset Context (+{asset_boost} pts)" if asset_boost > 0 else "")
            + f" = {prioritization}/100"
        )

        return CalculatedRiskScores(
            cvss_score=clamped_cvss,
            cvss_version=cvss_version,
            official_severity=severity,
            is_kev=is_kev,
            prioritization_score=prioritization,
            scoring_rationale=rationale,
        )


risk_scoring_engine = RiskScoringEngine()
