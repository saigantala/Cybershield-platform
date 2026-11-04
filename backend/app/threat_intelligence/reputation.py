from typing import Any, Dict, List, Optional

from app.threat_intelligence.indicators import IndicatorValidator


class ReputationService:
    """
    Evaluates reputation and threat attribution for observable entity values
    (IPs, hostnames, URLs, and file hashes) against stored Threat Intelligence indicators.
    """

    @classmethod
    def lookup(
        cls, value: str, indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Check if an observable artifact matches any known malicious indicator.
        Returns match metadata, threat severity, and attribution source.
        """
        if not value or not value.strip():
            return {"is_malicious": False, "match": None}

        cleaned = value.strip().lower()

        for ind in indicators:
            ind_val = str(ind.get("indicator_value", "")).strip().lower()
            ind_type = ind.get("indicator_type", "")

            # Match logic per type
            is_match = False
            if ind_type in ("sha256", "sha1", "md5", "ipv4", "ipv6"):
                is_match = cleaned == ind_val
            elif ind_type == "domain":
                # Matches exact domain or subdomain (e.g. host.malicious.com matches malicious.com)
                is_match = cleaned == ind_val or cleaned.endswith("." + ind_val)
            elif ind_type == "url":
                is_match = cleaned == ind_val or ind_val in cleaned

            if is_match:
                return {
                    "is_malicious": True,
                    "indicator_id": ind.get("id"),
                    "indicator_type": ind_type,
                    "indicator_value": ind.get("indicator_value"),
                    "source": ind.get("source"),
                    "threat_category": ind.get("threat_category"),
                    "severity": ind.get("severity", "High"),
                    "confidence": ind.get("confidence", 80),
                    "description": ind.get("description"),
                    "reference_url": ind.get("reference_url"),
                }

        return {"is_malicious": False, "match": None}


reputation_service = ReputationService()
