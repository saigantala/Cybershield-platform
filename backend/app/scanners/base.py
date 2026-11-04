from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class RawFinding:
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Informational
    cvss_score: float = 0.0
    cvss_version: str = "3.1"
    cve_id: Optional[str] = None
    affected_service: Optional[str] = None
    affected_version: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    reference_urls: List[str] = field(default_factory=list)
    scanner_name: str = "Scanner"
    raw_payload: Optional[Dict[str, Any]] = None


class BaseScanner(ABC):
    """
    Common abstraction layer for all CyberShield vulnerability engines.
    Enforces non-destructive, safe vulnerability scanning principles.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def check_health(self) -> Dict[str, Any]:
        """Verify scanner daemon connectivity, authentication, and readiness."""
        pass

    @abstractmethod
    async def run_assessment(
        self,
        targets: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[RawFinding]:
        """
        Execute safe, authorized vulnerability assessment against approved targets.
        Strictly forbids brute-force, exploits, or denial of service actions.
        """
        pass

    @abstractmethod
    async def cancel_assessment(self, task_id: str) -> bool:
        """Cancel an ongoing assessment job in the underlying scanner engine."""
        pass
