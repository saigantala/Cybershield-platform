from typing import Any, Dict


class DeterministicRiskAnalyzer:
    """
    Transparent, auditable risk scoring engine that computes deterministic priority
    scores without relying on probabilistic LLM hallucinations.
    """

    @staticmethod
    def calculate_vulnerability_risk(
        cvss_score: float,
        is_kev: bool,
        is_perimeter: bool = False,
        confidence: int = 100,
    ) -> Dict[str, Any]:
        """
        Formulated scoring:
        - Base CVSS component: (CVSS / 10.0) * 65.0  (Max 65 pts)
        - CISA KEV weaponization: +25.0 pts if in CISA KEV catalog
        - Exposure factor: +10.0 pts if perimeter-facing asset
        - Confidence scaling: adjusted slightly if confidence < 70%
        """
        cvss_clean = max(0.0, min(10.0, float(cvss_score or 0.0)))
        cvss_contribution = (cvss_clean / 10.0) * 65.0

        kev_contribution = 25.0 if is_kev else 0.0
        exposure_contribution = 10.0 if is_perimeter else 0.0

        raw_score = cvss_contribution + kev_contribution + exposure_contribution
        confidence_factor = max(0.5, min(1.0, float(confidence or 100) / 100.0))

        final_score = int(round(raw_score * confidence_factor))
        final_score = max(1, min(100, final_score))

        # Risk level categorization
        if final_score >= 85:
            tier = "Critical Priority"
            urgency = "Immediate Remediation (Within 24 Hours)"
        elif final_score >= 70:
            tier = "High Priority"
            urgency = "Remediate Within 7 Days"
        elif final_score >= 40:
            tier = "Medium Priority"
            urgency = "Remediate in Next Maintenance Window"
        else:
            tier = "Low Priority"
            urgency = "Routine Patching Cycle"

        return {
            "cybershield_risk_score": final_score,
            "risk_tier": tier,
            "recommended_sla": urgency,
            "factor_contributions": {
                "cvss_base_score": cvss_clean,
                "cvss_points": round(cvss_contribution, 1),
                "cisa_kev_active_exploit": is_kev,
                "cisa_kev_points": kev_contribution,
                "perimeter_exposure": is_perimeter,
                "exposure_points": exposure_contribution,
                "evidence_confidence_percent": confidence,
            },
            "formula_documentation": "CyberShield Risk = ((CVSS/10 * 65) + KEV(25) + Perimeter(10)) * Confidence",
        }
