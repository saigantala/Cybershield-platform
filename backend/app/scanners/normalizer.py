import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.scanners.base import RawFinding


@dataclass
class NormalizedFinding:
    asset_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_version: str
    prioritization_score: float = 0.0
    cve_id: Optional[str] = None
    affected_service: Optional[str] = None
    affected_version: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    evidence: str = ""
    remediation: str = ""
    reference_urls: List[str] = field(default_factory=list)
    is_kev: bool = False
    kev_metadata: Optional[Dict[str, Any]] = None
    scanner_name: str = "CyberShield Engine"


class FindingNormalizer:
    """Normalizes raw scanner outputs into consistent CyberShield findings."""

    @staticmethod
    def map_cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "Critical"
        if cvss >= 7.0:
            return "High"
        if cvss >= 4.0:
            return "Medium"
        if cvss > 0.0:
            return "Low"
        return "Informational"

    @staticmethod
    def normalize_severity(severity_str: str, cvss: float = 0.0) -> str:
        s = (severity_str or "").strip().lower()
        if "crit" in s:
            return "Critical"
        if "high" in s:
            return "High"
        if "med" in s:
            return "Medium"
        if "low" in s:
            return "Low"
        if "info" in s or "log" in s or "none" in s:
            return "Informational"
        return FindingNormalizer.map_cvss_to_severity(cvss)

    @classmethod
    def normalize(
        cls,
        raw: RawFinding,
        asset_id: str,
        asset_context: Optional[Dict[str, Any]] = None,
    ) -> NormalizedFinding:
        cvss = max(0.0, min(10.0, float(raw.cvss_score or 0.0)))
        severity = cls.normalize_severity(raw.severity, cvss)

        # Standardize CVE format if present
        cve = None
        if raw.cve_id:
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", raw.cve_id, re.IGNORECASE)
            if cve_match:
                cve = cve_match.group(0).upper()

        # Clean reference links
        clean_refs = []
        for ref in raw.reference_urls:
            if ref and isinstance(ref, str) and (ref.startswith("http://") or ref.startswith("https://")):
                if ref not in clean_refs:
                    clean_refs.append(ref)

        return NormalizedFinding(
            asset_id=str(asset_id),
            title=raw.title.strip(),
            description=(raw.description or "No description provided.").strip(),
            severity=severity,
            cvss_score=round(cvss, 1),
            cvss_version=raw.cvss_version or "3.1",
            cve_id=cve,
            affected_service=raw.affected_service or "Unknown",
            affected_version=raw.affected_version,
            port=raw.port,
            protocol=raw.protocol or "tcp",
            evidence=(raw.evidence or "Observed during non-intrusive banner audit.").strip(),
            remediation=(raw.remediation or "Upgrade the affected component to the latest vendor security release.").strip(),
            reference_urls=clean_refs,
            scanner_name=raw.scanner_name,
        )
